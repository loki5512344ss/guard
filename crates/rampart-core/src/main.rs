use rampart_core::config::Config;
use rampart_core::filter::blacklist::Blacklist;
use rampart_core::filter::rate_limit::RateLimiter;
use rampart_core::metrics;
use rampart_core::pow::difficulty::DifficultyAdjuster;
use rampart_core::proxy::listener::ProxyListener;
use rampart_core::store::clickhouse::{ClickHouseEvent, ClickHouseWriter};
use rampart_core::traffic::detector::{AttackDetector, AttackStatus};
use rampart_core::traffic::reputation::IpReputation;
use rampart_core::xdp::XdpFilter;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

fn attack_status_value(status: AttackStatus) -> i64 {
    match status {
        AttackStatus::Normal => 0,
        AttackStatus::Suspicious => 1,
        AttackStatus::UnderAttack => 2,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rampart_core=info".parse()?))
        .init();

    let config_path = std::env::var("RAMPART_CONFIG").unwrap_or_else(|_| "/etc/rampart/config.toml".to_string());
    let config = Config::from_file(&config_path)?;
    let whitelist = build_whitelist(&config)?;
    let config = Arc::new(config);

    let rate_limiter = Arc::new(RateLimiter::new(
        config.limits.rate_limit_login_pps,
        config.limits.rate_limit_burst,
    ));
    let blacklist = Arc::new(Blacklist::new());
    let reputation = Arc::new(IpReputation::new());
    let detector = Arc::new(Mutex::new(AttackDetector::new()));
    let allowed_1s = Arc::new(AtomicU64::new(0));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let sig_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received, draining connections...");
        let _ = sig_tx.send(true);
        tokio::time::sleep(Duration::from_secs(5)).await;
        tracing::info!("shutdown timeout reached, exiting");
        std::process::exit(0);
    });

    #[cfg(feature = "store-redis")]
    if let Some(redis_url) = &config.store.redis_url
        && !redis_url.is_empty()
    {
        let bl = blacklist.clone();
        let sd = shutdown_rx.clone();
        let url = redis_url.clone();
        tokio::spawn(async move {
            let client = match redis::Client::open(url.as_str()) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Invalid redis_url: {e}, blacklist sync disabled");
                    return;
                },
            };
            rampart_core::store::start_blacklist_sync(&client, bl, sd).await;
        });
    }

    if config.metrics.enabled {
        let metrics_addr = format!("0.0.0.0:{}", config.metrics.port);
        tracing::info!("Metrics server listening on {metrics_addr}");
        tokio::spawn(async move {
            metrics::run_metrics_server(&metrics_addr).await;
        });
    }

    let clickhouse: Option<Arc<tokio::sync::Mutex<ClickHouseWriter>>> = match &config.store.clickhouse_url {
        Some(url) if !url.is_empty() => {
            let writer = Arc::new(tokio::sync::Mutex::new(ClickHouseWriter::new(url)));
            rampart_core::store::clickhouse::start_flush_task(writer.clone(), shutdown_rx.clone());
            Some(writer)
        },
        _ => None,
    };

    #[cfg(feature = "xdp")]
    let xdp_filter: Option<Arc<Mutex<XdpFilter>>> = if config.xdp.enabled {
        use rampart_core::xdp::XdpMetrics;

        let filter = XdpFilter::new(&config.xdp.interface);
        let shared = Arc::new(Mutex::new(filter));
        shared.lock().expect("xdp lock poisoned").load()?;
        let xdp_metrics = XdpMetrics::register()?;

        let sd = shutdown_rx.clone();
        let shared_thread = shared.clone();
        std::thread::spawn(move || {
            while !*sd.borrow() {
                let guard = match shared_thread.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                guard.drain_events();
                if let Ok(stats) = guard.get_stats() {
                    xdp_metrics.update(&stats);
                }
                drop(guard);
                std::thread::sleep(Duration::from_secs(5));
            }
            if let Ok(mut guard) = shared_thread.lock() {
                guard.unload().ok();
            }
        });
        Some(shared)
    } else {
        None
    };

    #[cfg(not(feature = "xdp"))]
    let xdp_filter: Option<Arc<Mutex<XdpFilter>>> = None;

    let rl = rate_limiter.clone();
    let bl = blacklist.clone();
    let det = detector.clone();
    let a1s = allowed_1s.clone();
    let ch = clickhouse.clone();
    let mut sd = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut sec_tick = tokio::time::interval(Duration::from_secs(1));
        let mut min_tick = tokio::time::interval(Duration::from_secs(60));
        sec_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        min_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut was_under_attack = false;
        loop {
            tokio::select! {
                biased;
                _ = sd.changed() => {
                    if *sd.borrow() {
                        return;
                    }
                }
                _ = sec_tick.tick() => {
                    let pps = a1s.swap(0, Ordering::Relaxed) as f64;
                    let status = det.lock().expect("detector lock poisoned").analyze(pps);
                    metrics::ATTACK_STATUS.set(attack_status_value(status));
                    if status == AttackStatus::UnderAttack {
                        if !was_under_attack {
                            was_under_attack = true;
                            tracing::info!(pps, "attack detected: under attack");
                            if let Some(writer) = &ch {
                                let event = ClickHouseEvent {
                                    timestamp: chrono::Utc::now(),
                                    event_type: "attack".to_string(),
                                    ip: String::new(),
                                    data_float: pps,
                                    data_int: 0,
                                    data_string: "under_attack".to_string(),
                                };
                                if let Err(e) = writer.lock().await.push(event).await {
                                    tracing::debug!("clickhouse push error: {e}");
                                }
                            }
                        }
                    } else if was_under_attack {
                        was_under_attack = false;
                    }
                }
                _ = min_tick.tick() => {
                    rl.sweep();
                    bl.clear_expired();
                }
            }
        }
    });

    tracing::info!("Rampart edge starting on {}:{}", config.bind.address, config.bind.port);
    tracing::info!("Backend: {}:{}", config.backend.address, config.backend.port);

    let adjuster = Arc::new(Mutex::new(DifficultyAdjuster::default()));
    let listener = ProxyListener::new(
        config,
        rate_limiter,
        blacklist,
        adjuster,
        whitelist,
        reputation,
        xdp_filter,
        clickhouse,
        allowed_1s,
    );
    listener.run(shutdown_rx).await
}

fn build_whitelist(config: &Config) -> anyhow::Result<Arc<HashSet<IpAddr>>> {
    let mut set = HashSet::with_capacity(config.whitelist.len());
    for entry in &config.whitelist {
        let ip: IpAddr = match entry.parse() {
            Ok(ip) => ip,
            Err(_) => anyhow::bail!("invalid whitelist entry: {entry}"),
        };
        set.insert(ip);
    }
    Ok(Arc::new(set))
}

async fn wait_for_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => {}
        _ = term.recv() => {}
    }
}
