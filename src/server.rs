//! MySQL wire protocol server — TCP listener, session handler.

use std::sync::Arc;
use std::net::SocketAddr;

use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::auth::{generate_scramble, verify_native_password};
use crate::config::Config;
use crate::engine::{Engine, QueryResult};
use crate::protocol::{
    self, column_def, eof_packet, encode_packet, err_packet, ok_packet, parse_command,
    server_greeting, text_row, Command,
};

pub async fn run(cfg: Config, db: Arc<Engine>) -> Result<()> {
    let addr = format!("{}:{}", cfg.bind, cfg.mysql_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("MySQL listener on {addr}");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let db = Arc::clone(&db);
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer, db, cfg).await {
                        debug!("session {peer} closed: {e}");
                    }
                });
            }
            Err(e) => error!("accept error: {e}"),
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    db: Arc<Engine>,
    cfg: Config,
) -> Result<()> {
    debug!("new connection from {peer}");

    let scramble = generate_scramble();

    // Send server greeting
    let greeting = server_greeting(1, &scramble);
    stream.write_all(&encode_packet(&greeting, 0)).await?;

    // Read handshake response
    let mut buf = BytesMut::with_capacity(4096);
    let mut current_db: Option<String> = None;
    loop {
        let n = stream.read_buf(&mut buf).await?;
        if n == 0 { return Ok(()); }
        if let Some((payload, _seq)) = protocol::decode_packet(&mut buf) {
            // Parse HandshakeResponse41
            if payload.len() < 32 { break; }
            let caps = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            // username starts after: caps(4) + max_packet(4) + charset(1) + reserved(23) = offset 32
            if payload.len() < 33 { break; }
            let rest = &payload[32..];
            let user_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let _username = String::from_utf8_lossy(&rest[..user_end]);
            let rest = &rest[user_end + 1..];
            // auth response (length-prefixed)
            let (auth_resp, _) = if rest.is_empty() {
                (&[][..], &[][..])
            } else {
                let len = rest[0] as usize;
                (&rest[1..1+len.min(rest.len()-1)], &rest[1+len.min(rest.len()-1)..])
            };

            if !verify_native_password(&cfg.auth.root_password, &scramble, auth_resp) {
                warn!("auth failed from {peer}");
                stream.write_all(&encode_packet(&err_packet(1045, "Access denied"), 2)).await?;
                return Ok(());
            }
            // Extract database name from HandshakeResponse41 if CLIENT_CONNECT_WITH_DB is set
            // After auth_response, there may be a null-terminated db name
            let connect_with_db: u32 = 1 << 3; // CLIENT_CONNECT_WITH_DB
            let db_from_handshake: Option<String> = if caps & connect_with_db != 0 {
                // rest is already past username+NUL; rest[0]=auth_len, rest[1..1+len]=auth bytes
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
            debug!("handshake: caps={:#010x}, connect_with_db_flag={:?}, db_from_handshake={:?}", caps, caps & connect_with_db != 0, db_from_handshake);
            // Auto-create database if specified in handshake but not yet in engine
            if let Some(ref db_name) = db_from_handshake {
                db.ensure_database(db_name);
            }
            // Set current_db from handshake before breaking
            current_db = db_from_handshake;
            stream.write_all(&encode_packet(&ok_packet(0, 0), 2)).await?;
            break;
        }
    }

    // Command loop — current_db set from handshake (or None for no initial db)
    loop {
        if buf.is_empty() {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 { return Ok(()); }
        } else {
            match stream.try_read_buf(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            // If still no data, read blocking
            if buf.is_empty() {
                let n = stream.read_buf(&mut buf).await?;
                if n == 0 { return Ok(()); }
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
                    // Handle USE statement to track current_db
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

        // If buf had data but no complete packet yet, read more
        let n = stream.read_buf(&mut buf).await?;
        if n == 0 { return Ok(()); }
    }
}

async fn send_result(stream: &mut TcpStream, result: QueryResult, mut seq: u8) -> Result<()> {
    match result {
        QueryResult::Ok { affected, last_insert_id } => {
            stream.write_all(&encode_packet(&ok_packet(affected, last_insert_id), seq)).await?;
        }
        QueryResult::Err { code, message } => {
            stream.write_all(&encode_packet(&err_packet(code, &message), seq)).await?;
        }
        QueryResult::Rows { columns, rows } => {
            // Column count
            let mut count_pkt = BytesMut::new();
            count_pkt.extend_from_slice(&[columns.len() as u8]);
            stream.write_all(&encode_packet(&count_pkt, seq)).await?;
            seq += 1;

            // Column definitions
            for col in &columns {
                let def = column_def("", "", col, 0xfd, 0);
                stream.write_all(&encode_packet(&def, seq)).await?;
                seq += 1;
            }
            stream.write_all(&encode_packet(&eof_packet(), seq)).await?;
            seq += 1;

            // Rows
            for row in &rows {
                let vals: Vec<Option<&str>> = row.iter()
                    .map(|v| v.as_deref())
                    .collect();
                stream.write_all(&encode_packet(&text_row(&vals), seq)).await?;
                seq += 1;
            }
            stream.write_all(&encode_packet(&eof_packet(), seq)).await?;
        }
    }
    Ok(())
}
