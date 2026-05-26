//! Embedded admin web UI — runs on webui_port.

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

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
                    _ if path.starts_with("/api/") && req_key != cfg.auth.webui_api_key => {
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
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
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
    let db_name = extract_json_str(body, "db");
    let sql = extract_json_str(body, "sql");

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
    }
}

/// Very simple JSON string field extractor — no external dep.
fn extract_json_str(json: &str, key: &str) -> String {
    let needle = format!("\"{}\"", key);
    let pos = match json.find(&needle) {
        Some(p) => p + needle.len(),
        None => return String::new(),
    };
    let rest = json[pos..].trim_start();
    if !rest.starts_with(':') { return String::new(); }
    let rest = rest[1..].trim_start();
    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"').unwrap_or(inner.len());
        inner[..end].to_owned()
    } else if rest.starts_with("null") {
        String::new()
    } else {
        // Non-string value
        let end = rest.find([',', '}', ']']).unwrap_or(rest.len());
        rest[..end].trim().to_owned()
    }
}
