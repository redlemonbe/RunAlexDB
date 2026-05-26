//! MySQL wire protocol server — TCP listener, session handler.

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::Semaphore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use anyhow::Result;
use bytes::BytesMut;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::auth::{generate_scramble, verify_native_password};
use crate::config::Config;
use crate::engine::{Engine, QueryResult};
use crate::protocol::{
    self, column_def, eof_packet, encode_packet, err_packet, ok_packet, parse_command,
    server_greeting, server_greeting_tls, text_row, Command, CAPABILITY_SSL,
};

const MAX_CONNECTIONS: usize = 256;

// ── TLS acceptor setup ─────────────────────────────────────────────────────

#[cfg(feature = "tls")]
fn make_tls_acceptor(cfg: &Config) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let (cert, key): (CertificateDer<'static>, PrivateKeyDer<'static>) =
        if cfg.tls.cert.is_some() && cfg.tls.key.is_some() {
            let cert_pem = std::fs::read_to_string(cfg.tls.cert.as_ref().unwrap())?;
            let key_pem  = std::fs::read_to_string(cfg.tls.key.as_ref().unwrap())?;
            let cert = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .next().ok_or_else(|| anyhow::anyhow!("no cert in file"))??;
            let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("no key in file"))?;
            (cert, key)
        } else {
            // Auto-generate ephemeral self-signed cert
            let ck = rcgen::generate_simple_self_signed(vec![
                "localhost".to_owned(),
                "runalexdb".to_owned(),
            ])?;
            let cert_bytes = ck.cert.der().to_vec();
            let key_bytes  = ck.key_pair.serialize_der();
            (
                CertificateDer::from(cert_bytes),
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_bytes).into(),
            )
        };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

// ── Listener ───────────────────────────────────────────────────────────────

pub async fn run(cfg: Config, db: Arc<Engine>) -> Result<()> {
    let addr = format!("{}:{}", cfg.bind, cfg.mysql_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("MySQL listener on {addr} (max {} concurrent connections)", MAX_CONNECTIONS);

    #[cfg(feature = "tls")]
    let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> = if cfg.tls.enabled {
        match make_tls_acceptor(&cfg) {
            Ok(a) => {
                info!("TLS enabled on MySQL port {} ({})",
                    cfg.mysql_port,
                    if cfg.tls.cert.is_some() { "custom cert" } else { "auto self-signed" });
                Some(Arc::new(a))
            }
            Err(e) => {
                tracing::error!("TLS setup failed: {e} — plaintext only");
                None
            }
        }
    } else {
        None
    };

    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let permit = match Arc::clone(&sem).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("connection limit reached ({MAX_CONNECTIONS}), rejecting {peer}");
                        continue;
                    }
                };
                let db  = Arc::clone(&db);
                let cfg = cfg.clone();
                #[cfg(feature = "tls")]
                let tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    #[cfg(feature = "tls")]
                    let r = handle_connection(stream, peer, db, cfg, tls_acceptor).await;
                    #[cfg(not(feature = "tls"))]
                    let r = {
                        let scramble = generate_scramble();
                        let greeting = server_greeting(1, &scramble);
                        let mut s = stream;
                        let _ = s.write_all(&encode_packet(&greeting, 0)).await;
                        let mut buf = BytesMut::with_capacity(4096);
                        match s.read_buf(&mut buf).await {
                            Ok(0) | Err(_) => Ok(()),
                            Ok(_) => run_authenticated_session(s, peer, db, cfg, scramble, buf).await,
                        }
                    };
                    if let Err(e) = r { debug!("session {peer} closed: {e}"); }
                });
            }
            Err(e) => error!("accept error: {e}"),
        }
    }
}

// ── TLS upgrade ────────────────────────────────────────────────────────────

#[cfg(feature = "tls")]
async fn handle_connection(
    mut stream: TcpStream,
    peer:       SocketAddr,
    db:         Arc<Engine>,
    cfg:        Config,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
) -> Result<()> {
    debug!("new connection from {peer}");
    let scramble = generate_scramble();

    // Announce TLS capability if acceptor is ready
    let greeting = if tls_acceptor.is_some() {
        server_greeting_tls(1, &scramble)
    } else {
        server_greeting(1, &scramble)
    };
    stream.write_all(&encode_packet(&greeting, 0)).await?;

    // Read first client packet
    let mut buf = BytesMut::with_capacity(4096);
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 { return Ok(()); }

    // Detect SSLRequest: payload is exactly 32 bytes with CLIENT_SSL cap bit set
    if let Some(acceptor) = tls_acceptor {
        let is_ssl = {
            let mut tmp = buf.clone();
            protocol::decode_packet(&mut tmp)
                .map(|(p, _)| p.len() == 32 && u32::from_le_bytes([p[0],p[1],p[2],p[3]]) & CAPABILITY_SSL != 0)
                .unwrap_or(false)
        };
        if is_ssl {
            protocol::decode_packet(&mut buf); // consume SSLRequest
            let tls_stream = acceptor.accept(stream).await?;
            return run_authenticated_session(tls_stream, peer, db, cfg, scramble, BytesMut::new()).await;
        }
    }

    // Plain connection — buf already contains HandshakeResponse41
    run_authenticated_session(stream, peer, db, cfg, scramble, buf).await
}

// ── Session (auth + command loop) ─────────────────────────────────────────

async fn run_authenticated_session<S>(
    mut stream: S,
    peer:       SocketAddr,
    db:         Arc<Engine>,
    cfg:        Config,
    scramble:   [u8; 20],
    mut buf:    BytesMut,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // ── Handshake loop ──
    let mut current_db: Option<String> = None;
    loop {
        let n = stream.read_buf(&mut buf).await?;
        if n == 0 { return Ok(()); }
        if let Some((payload, _seq)) = protocol::decode_packet(&mut buf) {
            if payload.len() < 32 { break; }
            let caps = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            if payload.len() < 33 { break; }
            let rest = &payload[32..];
            let user_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let _username = String::from_utf8_lossy(&rest[..user_end]);
            let rest = &rest[user_end + 1..];
            let (auth_resp, _) = if rest.is_empty() {
                (&[][..], &[][..])
            } else {
                let len = rest[0] as usize;
                (&rest[1..1 + len.min(rest.len() - 1)], &rest[1 + len.min(rest.len() - 1)..])
            };
            if !verify_native_password(&cfg.auth.root_password, &scramble, auth_resp) {
                warn!("auth failed from {peer}");
                stream.write_all(&encode_packet(&err_packet(1045, "Access denied"), 2)).await?;
                return Ok(());
            }
            let connect_with_db: u32 = 1 << 3;
            let db_from_handshake: Option<String> = if caps & connect_with_db != 0 {
                let auth_len = if rest.is_empty() { 0 } else { rest[0] as usize };
                let db_offset = 1 + auth_len;
                let rest2 = if db_offset <= rest.len() { &rest[db_offset..] } else { &[][..] };
                if let Some(end) = rest2.iter().position(|&b| b == 0) {
                    let name = String::from_utf8_lossy(&rest2[..end]).trim().to_owned();
                    if !name.is_empty() { Some(name) } else { None }
                } else if !rest2.is_empty() {
                    let name = String::from_utf8_lossy(rest2).trim().trim_matches('\0').to_owned();
                    if !name.is_empty() { Some(name) } else { None }
                } else {
                    None
                }
            } else { None };
            debug!("handshake: caps={:#010x}, connect_with_db={}, db={:?}",
                caps, caps & connect_with_db != 0, db_from_handshake);
            if let Some(ref db_name) = db_from_handshake {
                db.ensure_database(db_name);
            }
            current_db = db_from_handshake;
            stream.write_all(&encode_packet(&ok_packet(0, 0), 2)).await?;
            break;
        }
        // If buf had data but no complete packet: the loop will read more
    }

    // ── Command loop ──
    loop {
        if buf.is_empty() {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 { return Ok(()); }
        } else {
            // Try to read more without blocking, then fall back
            match stream.read_buf(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }

        while let Some((payload, _seq)) = protocol::decode_packet(&mut buf) {
            let cmd = parse_command(&payload);
            debug!("cmd from {peer}: {cmd:?}");
            debug!("current_db for cmd: {:?}", current_db);

            match cmd {
                Command::Quit => return Ok(()),
                Command::Ping => {
                    stream.write_all(&encode_packet(&ok_packet(0, 0), 1)).await?;
                }
                Command::InitDb(db_name) => {
                    current_db = Some(db_name);
                    stream.write_all(&encode_packet(&ok_packet(0, 0), 1)).await?;
                }
                Command::Query(sql) => {
                    let result = db.execute(&sql, &current_db);
                    let sql_trimmed = sql.trim().to_uppercase();
                    if sql_trimmed.starts_with("USE ") {
                        let db_name = sql.trim()[4..].trim().trim_matches(';').trim_matches('`').to_owned();
                        current_db = Some(db_name);
                    }
                    send_result(&mut stream, result, 1).await?;
                }
                Command::FieldList(_) => {
                    stream.write_all(&encode_packet(&eof_packet(), 1)).await?;
                }
                Command::Unknown(c) => {
                    let msg = format!("Unknown command 0x{c:02x}");
                    stream.write_all(&encode_packet(&err_packet(1047, &msg), 1)).await?;
                }
            }
        }

        let n = stream.read_buf(&mut buf).await?;
        if n == 0 { return Ok(()); }
    }
}

async fn send_result<S>(stream: &mut S, result: QueryResult, mut seq: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    match result {
        QueryResult::Ok { affected, last_insert_id } => {
            stream.write_all(&encode_packet(&ok_packet(affected, last_insert_id), seq)).await?;
        }
        QueryResult::Err { code, message } => {
            stream.write_all(&encode_packet(&err_packet(code, &message), seq)).await?;
        }
        QueryResult::Rows { columns, rows } => {
            let mut count_pkt = BytesMut::new();
            count_pkt.extend_from_slice(&[columns.len() as u8]);
            stream.write_all(&encode_packet(&count_pkt, seq)).await?;
            seq += 1;
            for col in &columns {
                let def = column_def("", "", col, 0xfd, 0);
                stream.write_all(&encode_packet(&def, seq)).await?;
                seq += 1;
            }
            stream.write_all(&encode_packet(&eof_packet(), seq)).await?;
            seq += 1;
            for row in &rows {
                let vals: Vec<Option<&str>> = row.iter().map(|v| v.as_deref()).collect();
                stream.write_all(&encode_packet(&text_row(&vals), seq)).await?;
                seq += 1;
            }
            stream.write_all(&encode_packet(&eof_packet(), seq)).await?;
        }
    }
    Ok(())
}
