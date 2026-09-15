//! Runtime edge-демона: сборка компонентов, фоновые задачи и запуск listener.

use crate::config::Config;
use crate::engine::challenge::DifficultyAdjuster;
use crate::engine::listener;
use crate::engine::subnet::monitor;
use crate::engine::tunnel::Gateway;
use crate::filter::blacklist::Blacklist;
use crate::filter::rate_limit::RateLimiter;
use crate::metrics;
use crate::store::clickhouse::{ClickHouseEvent, ClickHouseWriter};
use crate::traffic::hook::TrafficHook;
use crate::traffic::intel::detector::{AttackDetector, AttackStatus};
use crate::traffic::intel::reputation::IpReputation;
use crate::traffic::profile::alert::{AlertDispatcher, send_webhook};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use super::services::{build_registry, build_whitelist, start_subnet_tracker, start_xdp};

fn attack_status_value(status: AttackStatus) -> i64 {
    match status {
        AttackStatus::Normal => 0,
        AttackStatus::Suspicious => 1,
        AttackStatus::UnderAttack => 2,
    }
}

/// Точка входа edge-демона (`rampart`): то, что делал `main` бинаря.
///
/// # Errors
/// Ошибки старта: нечитаемый конфиг, пустой реестр протоколов, сбой listener.
pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rampart=info".parse()?))
        .init();

    let config_path = std::env::var("RAMPART_CONFIG").unwrap_or_else(|_| "/etc/rampart/config.toml".to_string());
    let config = Arc::new(Config::from_file(&config_path)?);

    let registry = Arc::new(build_registry(&config));
    if registry.is_empty() {
        anyhow::bail!(
            "no protocol plugins compiled; available feature flags: protocol-http, \
             store-redis, geoip, xdp, io-uring. Build with --features protocol-http \
             or link an external ProtocolHandler implementation"
        );
    }
    let whitelist = build_whitelist(&config)?;

    let rate_limiter = Arc::new(RateLimiter::new(
        config.limits.rate_limit_pps,
        config.limits.rate_limit_burst,
    ));
    let blacklist = Arc::new(Blacklist::new());
    let reputation = Arc::new(IpReputation::new());
    let detector = Arc::new(Mutex::new(AttackDetector::new()));
    let hook = Arc::new(TrafficHook::new(
        reputation.clone(),
        blacklist.clone(),
        config.detect.autoban.clone(),
        config.ban.ban_duration_secs,
    ));
    let alert_dispatcher = AlertDispatcher::new();
    let webhook_url = config.detect.alert.webhook_url.clone();
    let allowed_1s = Arc::new(AtomicU64::new(0));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let sig_tx = shutdown_tx.clone();
    // shutdown-таймер обязан завершить процесс; в исходном коде вызов жил
    // внутри `fn main` и был освобождён от clippy::exit. Чистый перенос в
    // lib сохранил бы поведение, поэтому узкий allow — минимальная цена.
    #[allow(clippy::exit)]
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
            crate::store::start_blacklist_sync(&client, bl, sd).await;
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
            crate::store::clickhouse::start_flush_task(writer.clone(), shutdown_rx.clone());
            Some(writer)
        },
        _ => None,
    };

    let xdp_filter = start_xdp(&config, &shutdown_rx)?;
    let subnet_tracker = start_subnet_tracker(&config);
    monitor::spawn(
        &config.detect.prefix,
        subnet_tracker.clone(),
        xdp_filter.clone(),
        shutdown_rx.clone(),
    );

    let rl = rate_limiter.clone();
    let bl = blacklist.clone();
    let det = detector.clone();
    let intel = hook.clone();
    let a1s = allowed_1s.clone();
    let ch = clickhouse.clone();
    let mut sd = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut sec_tick = tokio::time::interval(Duration::from_secs(1));
        let mut min_tick = tokio::time::interval(Duration::from_secs(60));
        sec_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        min_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                    let cps = intel.take_cps() as f64;
                    metrics::INTEL_CPS.set(cps as i64);
                    let status = det.lock().expect("detector lock poisoned").analyze(pps, cps);
                    metrics::ATTACK_STATUS.set(attack_status_value(status));
                    if let Some(alert) = alert_dispatcher.on_status(status) {
                        // Дедупликация: алерт только на переходе состояния атаки.
                        metrics::INTEL_ALERTS_TOTAL.inc();
                        tracing::warn!(pps, cps, "{alert}");
                        push_attack_event(&ch, pps).await;
                        if let Some(url) = webhook_url.clone() {
                            tokio::spawn(send_webhook(url, alert.clone()));
                        }
                    }
                    if status == AttackStatus::UnderAttack {
                        let banned = intel.ban_offenders();
                        if banned > 0 {
                            tracing::info!(banned, "escalation: offenders auto-banned during attack");
                        }
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
    tracing::info!("Upstreams: {:?}", config.backend.upstreams);

    let adjuster = Arc::new(Mutex::new(DifficultyAdjuster::default()));
    let gateway = Arc::new(Gateway::new(
        config.clone(),
        rate_limiter,
        blacklist,
        adjuster,
        whitelist,
        reputation,
        xdp_filter,
        clickhouse,
        allowed_1s,
        registry,
        subnet_tracker,
    ));
    listener::run(config, gateway, hook, shutdown_rx).await
}

async fn push_attack_event(writer: &Option<Arc<tokio::sync::Mutex<ClickHouseWriter>>>, pps: f64) {
    let Some(writer) = writer else {
        return;
    };
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

async fn wait_for_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => {}
        _ = term.recv() => {}
    }
}
