mod config;
mod protocol;
mod engine;
mod simd_scan;
mod xdp;
mod auth;
mod server;
mod webui;
mod firewall;
mod icmp_guard;
mod numa_pin;

use anyhow::Result;
use tracing::{info, warn};

fn main() -> Result<()> {
    let cfg = config::Config::load().unwrap_or_default();
    let worker_count = if cfg.worker_threads > 0 {
        cfg.worker_threads
    } else {
        numa_pin::physical_core_ids().len().max(1)
    };
    let pin_cores = if cfg.numa_pin {
        let cores = numa_pin::physical_core_ids();
        if !cores.is_empty() {
            eprintln!("NUMA pinning: {} physical cores detected", cores.len());
        }
        cores
    } else { vec![] };
    let rr = std::sync::Arc::new(numa_pin::CpuRoundRobin::new(pin_cores));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_count)
        .on_thread_start(move || rr.pin_next())
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "runalexdb=info".into())
        )
        .init();

    let cfg = config::Config::load()?;
    info!("RunAlexDB v{} starting", env!("CARGO_PKG_VERSION"));
    info!("MySQL port  : {}", cfg.mysql_port);
    info!("Admin UI    : http://0.0.0.0:{}", cfg.webui_port);

    // XDP availability — log result, fall back silently if unavailable.
    if cfg.xdp.enabled {
        if xdp::check_available() {
            info!("XDP         : available (kernel + bpf fs present)");
        } else {
            warn!("XDP         : not available on this host — falling back to standard TCP");
        }
    } else {
        info!("XDP         : disabled in config");
    }

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

    // ICMP protection — with inter-process coordination via /var/run/icmp_guard.pid
    let _icmp = icmp_guard::IcmpGuard::setup(cfg.icmp_protection);

    // Start MySQL listener and web UI concurrently
    let db = std::sync::Arc::new(engine::Engine::new(&cfg));
    let db_shutdown = std::sync::Arc::clone(&db);
    let data_dir_shutdown = cfg.data_dir.clone();

    // Periodic auto-checkpoint (configurable interval, default 300 s).
    if cfg.checkpoint_interval_secs > 0 {
        let db_ckpt = std::sync::Arc::clone(&db);
        let data_dir_ckpt = cfg.data_dir.clone();
        let interval_secs = cfg.checkpoint_interval_secs;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            tick.tick().await; // skip first tick
            loop {
                tick.tick().await;
                let sql = db_ckpt.dump_sql();
                let path = format!("{}/runalexdb.sql", data_dir_ckpt);
                let tmp = format!("{}/runalexdb.sql.tmp", data_dir_ckpt);
                if std::fs::write(&tmp, &sql).is_ok() {
                    let _ = std::fs::rename(&tmp, &path);
                    tracing::debug!("Auto-checkpoint written to {path}");
                }
            }
        });
    }
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate()
            ).expect("sigterm handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await.ok();

        fw_cleanup.close();

        // Persist all data before exit
        let sql = db_shutdown.dump_sql();
        let path = format!("{data_dir_shutdown}/runalexdb.sql");
        if let Ok(()) = std::fs::write(&path, &sql) {
            tracing::info!("Data persisted to {path}");
        }
        std::process::exit(0);
    });
    tokio::try_join!(
        server::run(cfg.clone(), std::sync::Arc::clone(&db)),
        webui::run(cfg.clone(), std::sync::Arc::clone(&db)),
    )?;

    Ok(())
}
