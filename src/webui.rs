//! Embedded admin web UI — runs on webui_port.

use std::sync::Arc;

use anyhow::Result;
use serde_json::Value as JsonValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use subtle::ConstantTimeEq;
use crate::config::Config;
use crate::engine::{Engine, QueryResult};

static UI_HTML: &str = include_str!("webui.html");

pub async fn run(cfg: Config, db: Arc<Engine>) -> Result<()> {
    let addr = format!("{}:{}", cfg.bind, cfg.webui_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("Admin UI on http://{addr}");

    loop {
        if let Ok((mut stream, peer)) = listener.accept().await {
            let db = Arc::clone(&db);
            let cfg = cfg.clone();
            tokio::spawn(async move {
                debug!("webui req from {peer}");
                let mut buf = vec![0u8; 65536];
                let n = match stream.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let raw = String::from_utf8_lossy(&buf[..n]);

                // Parse HTTP request line + headers
                let mut lines = raw.lines();
                let req_line = lines.next().unwrap_or("");
                let mut parts = req_line.split_whitespace();
                let method = parts.next().unwrap_or("GET");
                let path   = parts.next().unwrap_or("/");

                // Find body (after \r\n\r\n)
                let body = if let Some(pos) = raw.find("\r\n\r\n") {
                    raw[pos+4..].to_owned()
                } else {
                    String::new()
                };

                // Extract X-API-Key or Authorization: Bearer from headers
                let req_key = raw.lines()
                    .find(|l| l.to_lowercase().starts_with("x-api-key:"))
                    .map(|l| l[10..].trim().to_owned())
                    .or_else(|| raw.lines()
                        .find(|l| l.to_lowercase().starts_with("authorization:"))
                        .and_then(|l| l.split_whitespace().nth(1).map(|s| s.trim_start_matches("Bearer ").to_owned())))
                    .unwrap_or_default();

                let resp = match (method, path) {
                    ("GET", "/" | "/ui" | "/index.html") => {
                        let html = UI_HTML.replace("{{API_KEY}}", &cfg.auth.webui_api_key);
                        http_response(200, "text/html; charset=utf-8", html.as_bytes())
                    }
                    // OPTIONS preflight
                    ("OPTIONS", _) => {
                        http_response(204, "text/plain", b"")
                    }
                    // API routes — require valid key
                    _ if path.starts_with("/api/") && !req_key.as_bytes().ct_eq(cfg.auth.webui_api_key.as_bytes()).unwrap_u8() == 0 => {
                        http_response(401, "application/json", br#"{"error":"Unauthorized"}"#)
                    }
                    ("GET", "/api/system") => {
                        let json = api_system(&db, &cfg);
                        http_response(200, "application/json", json.as_bytes())
                    }
                    ("GET", "/api/databases") => {
                        let json = api_databases(&db);
                        http_response(200, "application/json", json.as_bytes())
                    }
                    ("POST", "/api/query") => {
                        let json = api_query(&db, &body);
                        http_response(200, "application/json", json.as_bytes())
                    }
                    ("POST", "/api/backup") => {
                        let (code, json) = api_backup(&db, &cfg, &body);
                        http_response(code, "application/json", json.as_bytes())
                    }
                    ("GET", "/api/backups") => {
                        let (code, json) = api_list_backups(&cfg);
                        http_response(code, "application/json", json.as_bytes())
                    }
                    ("POST", "/api/restore") => {
                        let (code, json) = api_restore(&db, &cfg, &body);
                        http_response(code, "application/json", json.as_bytes())
                    }
                    ("DELETE", p) if p.starts_with("/api/backups/") => {
                        let id = &p["/api/backups/".len()..];
                        let (code, json) = api_delete_backup(&cfg, id);
                        http_response(code, "application/json", json.as_bytes())
                    }
                    _ => http_response(404, "text/plain", b"Not Found"),
                };

                let _ = stream.write_all(&resp).await;
            });
        }
    }
}

fn http_response(status: u16, ct: &str, body: &[u8]) -> Vec<u8> {
    let status_text = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(body);
    out
}

fn api_system(db: &Engine, cfg: &Config) -> String {
    let dbs = db.databases.read().unwrap();
    let db_count = dbs.values()
        .filter(|d| {
            let n = &d.read().unwrap().name.clone();
            !["information_schema","performance_schema","mysql","sys"].contains(&n.as_str())
        })
        .count();
    let table_count: usize = dbs.values()
        .map(|d| d.read().unwrap().tables.len())
        .sum();
    format!(
        r#"{{"version":"{}","databases":{},"tables":{},"mysql_port":{},"webui_port":{}}}"#,
        env!("CARGO_PKG_VERSION"), db_count, table_count, cfg.mysql_port, cfg.webui_port
    )
}

fn api_databases(db: &Engine) -> String {
    let dbs = db.databases.read().unwrap();
    let names: Vec<String> = dbs.keys()
        .filter(|n| !["information_schema","performance_schema","mysql","sys"].contains(&n.as_str()))
        .map(|n| format!("\"{}\"", n))
        .collect();
    format!("[{}]", names.join(","))
}

fn api_query(db: &Engine, body: &str) -> String {
    // Parse JSON body: {"db": "mydb", "sql": "SELECT 1"}
    let parsed: JsonValue = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return r#"{"error":"Invalid JSON"}"#.to_owned(),
    };
    let db_name = parsed["db"].as_str().unwrap_or("").to_owned();
    let sql = parsed["sql"].as_str().unwrap_or("").to_owned();

    if sql.is_empty() {
        return r#"{"error":"Missing sql field"}"#.to_owned();
    }

    let current_db = if db_name.is_empty() { None } else { Some(db_name) };
    let result = db.execute(&sql, &current_db);

    match result {
        QueryResult::Ok { affected, last_insert_id } => {
            format!(r#"{{"affected":{},"last_insert_id":{}}}"#, affected, last_insert_id)
        }
        QueryResult::Err { code, message } => {
            let msg = message.replace('"', "'");
            format!(r#"{{"error":true,"code":{},"message":"{}"}}"#, code, msg)
        }
        QueryResult::Rows { columns, rows } => {
            let cols_json: Vec<String> = columns.iter().map(|c| format!("\"{}\"", c)).collect();
            let rows_json: Vec<String> = rows.iter().map(|row| {
                let vals: Vec<String> = row.iter().map(|v| match v {
                    None => "null".to_owned(),
                    Some(s) => format!("\"{}\"", s.replace('"', "'")),
                }).collect();
                format!("[{}]", vals.join(","))
            }).collect();
            format!(r#"{{"columns":[{}],"rows":[{}]}}"#,
                cols_json.join(","), rows_json.join(","))
        }
        QueryResult::ValueRows { .. } => "{}".to_owned(),
    }
}

fn api_backup(db: &Engine, cfg: &Config, body: &str) -> (u16, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let label = serde_json::from_str::<JsonValue>(body)
        .ok()
        .and_then(|v| v["label"].as_str().map(|s| s.to_owned()))
        .filter(|s| !s.is_empty() && s.len() <= 32
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or_default();

    let filename = if label.is_empty() {
        format!("backup_{ts}.sql")
    } else {
        format!("backup_{ts}_{label}.sql")
    };

    let backup_dir = format!("{}/backups", cfg.data_dir);
    if let Err(e) = std::fs::create_dir_all(&backup_dir) {
        return (500, format!(r#"{{"error":"cannot create backup dir: {e}"}}"#));
    }

    let path = format!("{backup_dir}/{filename}");
    let sql = db.dump_sql();
    let size = sql.len();
    if let Err(e) = std::fs::write(&path, &sql) {
        return (500, format!(r#"{{"error":"write failed: {e}"}}"#));
    }

    (200, format!(r#"{{"id":"{filename}","size":{size},"ts":{ts}}}"#))
}

fn api_list_backups(cfg: &Config) -> (u16, String) {
    let backup_dir = format!("{}/backups", cfg.data_dir);
    let entries = match std::fs::read_dir(&backup_dir) {
        Ok(e) => e,
        Err(_) => return (200, "[]".to_owned()),
    };

    let mut items: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".sql"))
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            let ts = e.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!(r#"{{"id":"{name}","size":{size},"ts":{ts}}}"#)
        })
        .collect();

    items.sort();
    (200, format!("[{}]", items.join(",")))
}

fn api_restore(db: &Engine, cfg: &Config, body: &str) -> (u16, String) {
    let parsed: JsonValue = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return (400, r#"{"error":"Invalid JSON"}"#.to_owned()),
    };

    let id = match parsed["id"].as_str() {
        Some(s) => s.to_owned(),
        None => return (400, r#"{"error":"Missing id field"}"#.to_owned()),
    };

    if id.contains('/') || id.contains("..") || !id.ends_with(".sql") {
        return (400, r#"{"error":"Invalid backup id"}"#.to_owned());
    }

    let path = format!("{}/backups/{id}", cfg.data_dir);
    let sql = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return (404, r#"{"error":"Backup not found"}"#.to_owned()),
    };

    db.restore_sql(&sql);
    (200, format!(r#"{{"ok":true,"restored":"{id}"}}"#))
}

fn api_delete_backup(cfg: &Config, id: &str) -> (u16, String) {
    if id.contains('/') || id.contains("..") || !id.ends_with(".sql") {
        return (400, r#"{"error":"Invalid backup id"}"#.to_owned());
    }
    let path = format!("{}/backups/{id}", cfg.data_dir);
    match std::fs::remove_file(&path) {
        Ok(_) => (200, format!(r#"{{"ok":true,"deleted":"{id}"}}"#)),
        Err(_) => (404, r#"{"error":"Backup not found"}"#.to_owned()),
    }
}
