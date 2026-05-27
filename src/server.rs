//! MySQL wire protocol server — TCP listener, session handler.

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::Semaphore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use anyhow::Result;
use tokio::time::timeout;
use bytes::BytesMut;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::auth::{generate_scramble, verify_native_password};
use crate::config::Config;
use crate::engine::{Engine, QueryResult};
use crate::protocol::{
    self, binary_row, column_def, eof_packet, encode_packet, err_packet, ok_packet, parse_command,
    parse_execute_params, stmt_prepare_ok, server_greeting, server_greeting_tls, text_row, Command, CAPABILITY_SSL,
};


// Pre-computed wire bytes for "SELECT 1" — skips parsing and encoding entirely.
// Packet sequence always starts at 1 for a fresh command response.
const SELECT_1_RESPONSE: &[u8] = &[
    // column count = 1 (seq=1)
    0x01, 0x00, 0x00, 0x01, 0x01,
    // column def name="1", type=0xfd (seq=2)
    0x18, 0x00, 0x00, 0x02,
    0x03, 0x64, 0x65, 0x66, // "def"
    0x00,                    // schema ""
    0x00,                    // table ""
    0x00,                    // org_table ""
    0x01, 0x31,              // name "1"
    0x01, 0x31,              // org_name "1"
    0x0c, 0x21, 0x00, 0xff, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00,
    // EOF (seq=3)
    0x05, 0x00, 0x00, 0x03, 0xfe, 0x00, 0x00, 0x02, 0x00,
    // row "1" (seq=4)
    0x02, 0x00, 0x00, 0x04, 0x01, 0x31,
    // EOF (seq=5)
    0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, 0x02, 0x00,
];

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

#[derive(Clone)]
struct PreparedStmt {
    sql: String,
    num_params: u16,
}

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
                let _ = stream.set_nodelay(true);
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
        let mut txn_snapshot: Option<std::collections::HashMap<String, std::collections::HashMap<String, crate::engine::Table>>> = None;
    let mut stmt_cache: std::collections::HashMap<u32, PreparedStmt> = std::collections::HashMap::new();
    let mut next_stmt_id: u32 = 1;
    let mut effective_user = String::from("root");
    loop {
        // If buf already has data (pre-read before calling us), skip the network read.
        if buf.is_empty() {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 { return Ok(()); }
        }
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
            // Multi-user auth: check username against user table
            let username_str = _username.trim_matches('`').to_owned();
            effective_user = if username_str.is_empty() { "root".to_owned() } else { username_str.clone() };
            let auth_ok = {
                // Try user table first
                if let Some((stored_hash2, _is_root)) = db.lookup_user(&effective_user) {
                    // verify_native_password_hash takes SHA1(SHA1(pw)) directly
                    crate::auth::verify_native_password_hash(&stored_hash2, &scramble, auth_resp)
                } else if effective_user == "root" {
                    // Fallback to config root password
                    verify_native_password(&cfg.auth.root_password, &scramble, auth_resp)
                } else {
                    false
                }
            };
            if !auth_ok {
                warn!(user = %effective_user, "auth failed from {peer}");
                stream.write_all(&encode_packet(&err_packet(1045, "Access denied"), 2)).await?;
                return Ok(());
            }
            let connect_with_db: u32 = 1 << 3;
            let db_from_handshake: Option<String> = if caps & connect_with_db != 0 {
                let auth_len = if rest.is_empty() { 0 } else { rest[0] as usize };
                let db_offset = 1 + auth_len;
                let rest2 = if db_offset <= rest.len() { &rest[db_offset..] } else { &[][..] };
                // MySQL auth plugin names are not valid database names — filter them out.
                // Some clients (pymysql) omit the database field and put the plugin name here.
                const AUTH_PLUGINS: &[&str] = &["mysql_native_password", "sha256_password",
                    "caching_sha2_password", "mysql_clear_password", "authentication_windows_client"];
                if let Some(end) = rest2.iter().position(|&b| b == 0) {
                    let name = String::from_utf8_lossy(&rest2[..end]).trim().to_owned();
                    if !name.is_empty() && !AUTH_PLUGINS.iter().any(|p| name.eq_ignore_ascii_case(p)) {
                        Some(name)
                    } else { None }
                } else if !rest2.is_empty() {
                    let name = String::from_utf8_lossy(rest2).trim().trim_matches('\0').to_owned();
                    if !name.is_empty() && !AUTH_PLUGINS.iter().any(|p| name.eq_ignore_ascii_case(p)) {
                        Some(name)
                    } else { None }
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
    // Per-connection write buffer: cleared and reused for each response.
    // Eliminates per-packet allocation and reduces to 1 write_all() per query.
    let mut write_buf = BytesMut::with_capacity(65536);
    // L0 result cache: same query on same connection → return pre-serialized bytes.
    // write_gen from Engine detects cross-connection writes (INSERT/UPDATE/DELETE).
    let mut l0_hash: u64 = 0;
    let mut l0_gen:  u64 = u64::MAX; // initialise to invalid
    let mut l0_bytes: Option<bytes::Bytes> = None;
    let idle_timeout = std::time::Duration::from_secs(cfg.connection_timeout_secs);
    loop {
        if buf.is_empty() {
            let n = match timeout(idle_timeout, stream.read_buf(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(()), // idle timeout — close connection silently
            };
            if n == 0 { return Ok(()); }
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
                    l0_hash = 0; // invalidate L0 cache: current_db changed
                    stream.write_all(&encode_packet(&ok_packet(0, 0), 1)).await?;
                }
                Command::Query(sql) => {
                    // SELECT 1 — pre-computed static bytes (health-check / overhead probe)
                    let sql_up = sql.trim().to_uppercase();
                    if sql_up == "SELECT 1" || sql_up == "SELECT 1;" {
                        stream.write_all(SELECT_1_RESPONSE).await?;
                        continue;
                    }
                    if sql_up.starts_with("USE ") {
                        let rest = sql.trim()[4..].trim();
                        if !rest.contains(';') {
                            let db_name = rest.trim_matches('`').to_owned();
                            current_db = Some(db_name);
                        }
                    }
                    // L0 result cache: CRC32 hash query, check write_gen for staleness.
                    // Hit: return pre-serialized bytes — zero SQL parsing, zero encoding.
                    // Transaction control: handle in server, not engine
                    {
                        let sql_tc = sql.trim().trim_end_matches(';').to_uppercase();
                        if sql_tc == "BEGIN" || sql_tc == "START TRANSACTION" {
                            txn_snapshot = Some(db.take_snapshot());
                            stream.write_all(&encode_packet(&ok_packet(0, 0), 1)).await?;
                            continue;
                        }
                        if sql_tc == "COMMIT" {
                            txn_snapshot = None;
                            stream.write_all(&encode_packet(&ok_packet(0, 0), 1)).await?;
                            continue;
                        }
                        if sql_tc == "ROLLBACK" {
                            if let Some(snap) = txn_snapshot.take() {
                                db.restore_snapshot(snap);
                            }
                            stream.write_all(&encode_packet(&ok_packet(0, 0), 1)).await?;
                            continue;
                        }
                    }
                    let qhash = crate::simd_scan::hash_query(sql.as_bytes());
                    let cur_gen = db.write_gen();
                    if qhash == l0_hash && cur_gen == l0_gen {
                        if let Some(ref cached) = l0_bytes {
                            stream.write_all(cached).await?;
                            continue;
                        }
                    }
                    let result = db.execute(&sql, &current_db, &effective_user);
                    write_buf.clear();
                    protocol::build_result_into(&mut write_buf, &result, 1);
                    stream.write_all(&write_buf).await?;
                    // Cache this result (only cache non-error responses)
                    if !matches!(result, crate::engine::QueryResult::Err { .. }) {
                        l0_hash  = qhash;
                        l0_gen   = db.write_gen(); // re-read after execution
                        l0_bytes = Some(bytes::Bytes::copy_from_slice(&write_buf));
                    }
                }
                Command::FieldList(_) => {
                    stream.write_all(&encode_packet(&eof_packet(), 1)).await?;
                }
                Command::StmtPrepare(sql) => {
                    let num_params = sql.bytes().filter(|&b| b == b'?').count() as u16;
                    let stmt_id = next_stmt_id;
                    next_stmt_id += 1;
                    stmt_cache.insert(stmt_id, PreparedStmt { sql, num_params });
                    stream.write_all(&encode_packet(&stmt_prepare_ok(stmt_id, num_params, 0), 1)).await?;
                    if num_params > 0 {
                        let mut s = 2u8;
                        for _ in 0..num_params {
                            stream.write_all(&encode_packet(&column_def("", "", "?", 0xfd, 0), s)).await?;
                            s = s.wrapping_add(1);
                        }
                        stream.write_all(&encode_packet(&eof_packet(), s)).await?;
                    }
                }
                Command::StmtExecute(stmt_id) => {
                    let stmt = match stmt_cache.get(&stmt_id).cloned() {
                        Some(s) => s,
                        None => {
                            stream.write_all(&encode_packet(&err_packet(1243, "Unknown prepared statement handler"), 1)).await?;
                            continue;
                        }
                    };
                    let params = parse_execute_params(&payload, stmt.num_params);
                    let result = db.execute_prepared(&stmt.sql, &params, &current_db, &effective_user);
                    write_buf.clear();
                    protocol::build_binary_result_into(&mut write_buf, &result, 1);
                    stream.write_all(&write_buf).await?;
                }
                Command::StmtClose(stmt_id) => {
                    stmt_cache.remove(&stmt_id);
                }
                Command::StmtReset(stmt_id) => {
                    if stmt_cache.contains_key(&stmt_id) {
                        stream.write_all(&encode_packet(&ok_packet(0, 0), 1)).await?;
                    } else {
                        stream.write_all(&encode_packet(&err_packet(1243, "Unknown prepared statement handler"), 1)).await?;
                    }
                }
                Command::Unknown(c) => {
                    let msg = format!("Unknown command 0x{c:02x}");
                    stream.write_all(&encode_packet(&err_packet(1047, &msg), 1)).await?;
                }
            }
        }

        let n = match timeout(idle_timeout, stream.read_buf(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()),
        };
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
        QueryResult::ValueRows { columns, rows } => {
            // Delegate to batched encoder
            let mut tmp = bytes::BytesMut::with_capacity(256 + rows.len() * 32);
            protocol::build_value_result_into(&mut tmp, &columns, &rows, seq);
            stream.write_all(&tmp).await?;
        }
    }
    Ok(())
}

async fn send_result_binary<S>(stream: &mut S, result: crate::engine::QueryResult, mut seq: u8) -> anyhow::Result<()>
where S: tokio::io::AsyncWrite + Unpin {
    use crate::engine::QueryResult;
    match result {
        QueryResult::Ok { affected, last_insert_id } => {
            stream.write_all(&encode_packet(&ok_packet(affected, last_insert_id), seq)).await?;
        }
        QueryResult::Err { code, message } => {
            stream.write_all(&encode_packet(&err_packet(code, &message), seq)).await?;
        }
        QueryResult::Rows { columns, rows } => {
            let mut cnt = BytesMut::new();
            cnt.extend_from_slice(&[columns.len() as u8]);
            stream.write_all(&encode_packet(&cnt, seq)).await?; seq = seq.wrapping_add(1);
            for col in &columns {
                stream.write_all(&encode_packet(&column_def("", "", col, 0xfd, 0), seq)).await?;
                seq = seq.wrapping_add(1);
            }
            stream.write_all(&encode_packet(&eof_packet(), seq)).await?; seq = seq.wrapping_add(1);
            for row in &rows {
                let vals: Vec<Option<&str>> = row.iter().map(|v| v.as_deref()).collect();
                stream.write_all(&encode_packet(&binary_row(&vals), seq)).await?;
                seq = seq.wrapping_add(1);
            }
            stream.write_all(&encode_packet(&eof_packet(), seq)).await?;
        }
        QueryResult::ValueRows { columns, rows } => {
            let mut tmp = bytes::BytesMut::with_capacity(256 + rows.len() * 32);
            protocol::build_value_result_into(&mut tmp, &columns, &rows, seq);
            stream.write_all(&tmp).await?;
        }
    }
    Ok(())
}
