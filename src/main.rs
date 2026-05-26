mod config;
mod protocol;
mod engine;
mod auth;
mod server;
mod webui;
mod firewall;

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

    // Firewall — open MySQL + WebUI ports at startup, close on shutdown.
    let fw_ports: Vec<(u16, &'static str)> = vec![
        (cfg.mysql_port, "tcp"),
        (cfg.webui_port, "tcp"),
    ];
    let fw = std::sync::Arc::new(firewall::FirewallManager::new(
        cfg.firewall_manage,
        cfg.firewall_backend.as_deref(),
        &cfg.firewall_tag,
    ));
    fw.open(&fw_ports);
    let fw_cleanup = std::sync::Arc::clone(&fw);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        fw_cleanup.close();
        std::process::exit(0);
    });

    // Start MySQL listener and web UI concurrently
    let db = std::sync::Arc::new(engine::Engine::new(&cfg));
    tokio::try_join!(
        server::run(cfg.clone(), std::sync::Arc::clone(&db)),
        webui::run(cfg.clone(), std::sync::Arc::clone(&db)),
    )?;

    Ok(())
}
