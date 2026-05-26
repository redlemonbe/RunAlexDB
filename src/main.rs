mod config;
mod protocol;
mod engine;
mod auth;
mod server;
mod webui;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "runalexdb=info".into())
        )
        .init();

    let cfg = config::Config::load()?;
    info!("RunAlexDB v{} starting", env!("CARGO_PKG_VERSION"));
    info!("MySQL port  : {}", cfg.mysql_port);
    info!("Admin UI    : http://0.0.0.0:{}", cfg.webui_port);

    // Start MySQL listener and web UI concurrently
    let db = std::sync::Arc::new(engine::Engine::new(&cfg));
    tokio::try_join!(
        server::run(cfg.clone(), std::sync::Arc::clone(&db)),
        webui::run(cfg.clone(), std::sync::Arc::clone(&db)),
    )?;

    Ok(())
}
