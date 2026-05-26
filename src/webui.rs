//! Embedded admin web UI — runs on webui_port, served over HTTP.

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::config::Config;
use crate::engine::Engine;

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
                let mut buf = vec![0u8; 8192];
                let n = match stream.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.lines().next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");

                let resp = match path {
                    "/" | "/ui" | "/index.html" => {
                        let body = UI_HTML.replace("{{API_KEY}}", &cfg.auth.webui_api_key);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(), body
                        )
                    }
                    p if p.starts_with("/api/") => {
                        let json_body = handle_api(p, &db, &cfg);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json_body.len(), json_body
                        )
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found".to_owned(),
                };

                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    }
}

fn handle_api(path: &str, db: &Arc<Engine>, _cfg: &Config) -> String {
    match path {
        "/api/system" => {
            let dbs = db.databases.read().unwrap();
            let db_count = dbs.len();
            let table_count: usize = dbs.values()
                .map(|d| d.read().unwrap().tables.len())
                .sum();
            format!(
                r#"{{"version":"{}","databases":{},"tables":{}}}"#,
                env!("CARGO_PKG_VERSION"), db_count, table_count
            )
        }
        "/api/databases" => {
            let dbs = db.databases.read().unwrap();
            let names: Vec<String> = dbs.keys()
                .map(|n| format!("\"{}\"", n))
                .collect();
            format!("[{}]", names.join(","))
        }
        _ => r#"{"error":"Not found"}"#.to_owned(),
    }
}
