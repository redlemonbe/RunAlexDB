//! Embedded admin web UI — runs on webui_port.
//! Session-based auth: POST /login → session cookie (HttpOnly, 8h TTL).
//! Multi-user: webui admin from config + MySQL users via double-SHA1.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::Rng;
use serde_json::Value as JsonValue;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::config::Config;
use crate::engine::{Engine, QueryResult};

static LOGIN_HTML: &str = include_str!("login.html");
static UI_HTML:    &str = include_str!("webui.html");

const SESSION_TTL:     Duration = Duration::from_secs(8 * 3600);
const SESSION_CLEANUP: Duration = Duration::from_secs(3600);

struct SessionEntry {
    username: String,
    expires:  Instant,
}

type SessionStore = Arc<Mutex<HashMap<String, SessionEntry>>>;

fn gen_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

fn extract_cookie(raw: &str, name: &str) -> Option<String> {
    for line in raw.lines() {
        if line.to_lowercase().starts_with("cookie:") {
            for part in line[7..].split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix(&format!("{}=", name)) {
                    return Some(val.trim().to_owned());
                }
            }
        }
    }
    None
}

fn session_user(sessions: &SessionStore, token: &str) -> Option<String> {
    let mut store = sessions.lock().unwrap();
    match store.get(token) {
        Some(e) if e.expires > Instant::now() => Some(e.username.clone()),
        Some(_) => { store.remove(token); None }
        None => None,
    }
}

/// Validate webui login: config admin OR any MySQL user.
fn verify_login(username: &str, password: &str, cfg: &Config, engine: &Engine) -> bool {
    // Config admin account
    let admin_user = cfg.auth.webui_admin_user.as_str();
    let admin_pass = cfg.auth.webui_admin_password.as_str();
    if username.len() == admin_user.len()
        && username.as_bytes().ct_eq(admin_user.as_bytes()).into()
        && password.len() == admin_pass.len()
        && password.as_bytes().ct_eq(admin_pass.as_bytes()).into()
    {
        return true;
    }
    // MySQL users: compare double-SHA1
    engine.verify_webui_password(username, password)
}

pub async fn run(cfg: Config, db: Arc<Engine>) -> Result<()> {
    let addr = format!("{}:{}", cfg.bind, cfg.webui_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("Admin UI on http://{addr}");

    let sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));

    // Background task: purge expired sessions hourly
    {
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SESSION_CLEANUP).await;
                let now = Instant::now();
                sessions.lock().unwrap().retain(|_, e| e.expires > now);
            }
        });
    }

    loop {
        if let Ok((mut stream, peer)) = listener.accept().await {
            let db       = Arc::clone(&db);
            let cfg      = cfg.clone();
            let sessions = Arc::clone(&sessions);
            tokio::spawn(async move {
                debug!("webui req from {peer}");
                let mut buf = vec![0u8; 131072];
                let n = match stream.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let raw = String::from_utf8_lossy(&buf[..n]);

                let mut lines = raw.lines();
                let req_line  = lines.next().unwrap_or("");
                let mut parts = req_line.split_whitespace();
                let method    = parts.next().unwrap_or("GET");
                let path      = parts.next().unwrap_or("/").split('?').next().unwrap_or("/");

                let body = raw.find("\r\n\r\n")
                    .map(|p| raw[p+4..].to_owned())
                    .unwrap_or_default();

                let token    = extract_cookie(&raw, "session");
                let username = token.as_deref().and_then(|t| session_user(&sessions, t));

                let resp = match (method, path) {
                    // ── Login page ──────────────────────────────────────────
                    ("GET", "/login") => {
                        http_response(200, "text/html; charset=utf-8", LOGIN_HTML.as_bytes())
                    }
                    ("POST", "/login") => {
                        handle_login(&body, &cfg, &db, &sessions)
                    }
                    // ── Logout ───────────────────────────────────────────────
                    ("POST", "/logout") => {
                        if let Some(tok) = token.as_deref() {
                            sessions.lock().unwrap().remove(tok);
                        }
                        redirect("/login")
                    }
                    // ── Root / UI → redirect ─────────────────────────────────
                    ("GET", "/" | "/index.html") => redirect("/ui"),
                    ("GET", "/ui") => {
                        if username.is_some() {
                            http_response(200, "text/html; charset=utf-8", UI_HTML.as_bytes())
                        } else {
                            redirect("/login")
                        }
                    }
                    // ── OPTIONS preflight ────────────────────────────────────
                    ("OPTIONS", _) => http_response(204, "text/plain", b""),
                    // ── API routes — session required ────────────────────────
                    _ if path.starts_with("/api/") => {
                        match username {
                            None => http_response(401, "application/json",
                                        br#"{"error":"Unauthorized"}"#),
                            Some(ref user) => {
                                dispatch_api(method, path, &body, &db, &cfg, user, &raw)
                            }
                        }
                    }
                    _ => http_response(404, "text/plain", b"Not found"),
                };
                let _ = stream.write_all(&resp).await;
            });
        }
    }
}

fn handle_login(body: &str, cfg: &Config, engine: &Engine, sessions: &SessionStore) -> Vec<u8> {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return http_response(400, "application/json", br#"{"error":"Bad request"}"#),
    };
    let username = v["username"].as_str().unwrap_or("").trim();
    let password = v["password"].as_str().unwrap_or("");

    if username.is_empty() || !verify_login(username, password, cfg, engine) {
        // Fixed 300ms delay on failure to slow brute force
        std::thread::sleep(std::time::Duration::from_millis(300));
        return http_response(401, "application/json", br#"{"error":"Invalid username or password"}"#);
    }

    let token   = gen_token();
    let expires = Instant::now() + SESSION_TTL;
    sessions.lock().unwrap().insert(token.clone(), SessionEntry {
        username: username.to_owned(),
        expires,
    });

    let cookie = format!(
        "session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        token, SESSION_TTL.as_secs()
    );
    let body_json = br#"{"ok":true}"#;
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        body_json.len(), cookie, String::from_utf8_lossy(body_json)
    ).into_bytes()
}

fn dispatch_api(method: &str, path: &str, body: &str, db: &Arc<Engine>,
                cfg: &Config, user: &str, _raw: &str) -> Vec<u8> {
    match (method, path) {
        ("GET", "/api/system") => {
            let json = api_system(db, cfg, user);
            http_response(200, "application/json", json.as_bytes())
        }
        ("GET", "/api/databases") => {
            let json = api_databases(db);
            http_response(200, "application/json", json.as_bytes())
        }
        ("GET", "/api/users") => {
            let json = api_users(db);
            http_response(200, "application/json", json.as_bytes())
        }
        ("POST", "/api/query") => {
            let json = api_query(db, body, user);
            http_response(200, "application/json", json.as_bytes())
        }
        _ => http_response(404, "application/json", br#"{"error":"Not found"}"#),
    }
}

fn api_system(db: &Engine, cfg: &Config, user: &str) -> String {
    let dbs = db.databases.read().unwrap_or_else(|e| e.into_inner());
    let db_count = dbs.values()
        .filter(|_| true)
        .count();
    let table_count: usize = dbs.values()
        .map(|d| d.read().unwrap_or_else(|e| e.into_inner()).tables.len())
        .sum();
    drop(dbs);
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "databases": db_count,
        "tables": table_count,
        "mysql_port": cfg.mysql_port,
        "webui_port": cfg.webui_port,
        "logged_user": user,
    }).to_string()
}

fn api_databases(db: &Engine) -> String {
    let dbs = db.databases.read().unwrap_or_else(|e| e.into_inner());
    let names: Vec<&String> = dbs.keys()
        .filter(|n| !n.starts_with("information_schema") && !n.starts_with("performance_schema")
                 && n.as_str() != "mysql" && n.as_str() != "sys")
        .collect();
    serde_json::to_string(&names).unwrap_or_else(|_| "[]".into())
}

fn api_users(db: &Engine) -> String {
    let users = db.users.read().unwrap_or_else(|e| e.into_inner());
    let list: Vec<serde_json::Value> = users.iter().map(|(name, u)| {
        let dbs_str = match &u.allowed_dbs {
            None => "ALL".to_owned(),
            Some(s) => if s.is_empty() { "none".to_owned() } else {
                s.iter().cloned().collect::<Vec<_>>().join(", ")
            }
        };
        serde_json::json!({
            "username": name,
            "dbs": dbs_str,
            "can_write": u.can_write,
        })
    }).collect();
    serde_json::to_string(&list).unwrap_or_else(|_| "[]".into())
}

fn api_query(db: &Engine, body: &str, user: &str) -> String {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return r#"{"error":true,"code":1064,"message":"Bad JSON"}"#.into(),
    };
    let sql = v["sql"].as_str().unwrap_or("").trim();
    let db_name: Option<String> = v["db"].as_str().map(|s| s.to_owned());
    if sql.is_empty() {
        return r#"{"ok":true,"affected":0}"#.into();
    }
    let result = db.execute(sql, &db_name, user);
    result_to_json(&result)
}

fn result_to_json(result: &QueryResult) -> String {
    match result {
        QueryResult::Ok { affected, last_insert_id } => {
            serde_json::json!({"ok":true,"affected":affected,"insert_id":last_insert_id}).to_string()
        }
        QueryResult::Err { code, message } => {
            serde_json::json!({"error":true,"code":code,"message":message}).to_string()
        }
        QueryResult::Rows { columns, rows } => {
            serde_json::json!({"rows": rows, "columns": columns}).to_string()
        }
        QueryResult::ValueRows { columns, rows } => {
            let json_rows: Vec<Vec<Option<String>>> = rows.iter().map(|row| {
                row.iter().map(|v| match v {
                    crate::engine::Value::Null => None,
                    other => other.as_str().map(|s| s.to_owned()).or_else(|| Some(format!("{:?}", other))),
                }).collect()
            }).collect();
            serde_json::json!({"rows": json_rows, "columns": columns}).to_string()
        }
    }
}

fn http_response(status: u16, ct: &str, body: &[u8]) -> Vec<u8> {
    let status_text = match status {
        200 => "OK", 204 => "No Content", 301 => "Moved Permanently",
        400 => "Bad Request", 401 => "Unauthorized", 404 => "Not Found",
        _   => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut r = header.into_bytes();
    r.extend_from_slice(body);
    r
}

fn redirect(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ).into_bytes()
}
