use rampart_core::config::Config;
use rampart_core::filter::blacklist::Blacklist;
use rampart_core::filter::rate_limit::RateLimiter;
use rampart_core::metrics;
use rampart_core::proxy::listener::ProxyListener;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rampart_core=info".parse()?))
        .init();

    let config_path = std::env::var("RAMPART_CONFIG").unwrap_or_else(|_| "/etc/rampart/config.toml".to_string());
    let config = Config::from_file(&config_path)?;
    let config = Arc::new(config);

    let rate_limiter = Arc::new(RateLimiter::new(
        config.limits.rate_limit_login_pps,
        config.limits.rate_limit_burst,
    ));
    let blacklist = Arc::new(Blacklist::new());

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

    tracing::info!("Rampart edge starting on {}:{}", config.bind.address, config.bind.port);
    tracing::info!("Backend: {}:{}", config.backend.address, config.backend.port);

    let listener = ProxyListener::new(config, rate_limiter, blacklist);
    listener.run(shutdown_rx).await
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
