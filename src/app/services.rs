//! Сервисы edge-демона: реестр протоколов, whitelist, XDP и subnet-трекер.

use crate::config::Config;
use crate::engine::subnet::tracker::SubnetTracker;
use crate::protocol::ProtocolRegistry;
use crate::xdp::XdpFilter;
#[cfg(feature = "xdp")]
use crate::xdp::XdpGlobals;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::watch;

/// Собирает реестр протоколов из скомпилированных реализаций.
///
/// Обработчики поставляются фичами: `protocol-http` регистрирует
/// HTTP/1.1-обработчик с политикой из секции `[protocol.http]`.
/// Внешние крейты регистрируют свои обработчики в этом же месте.
pub(crate) fn build_registry(config: &Config) -> ProtocolRegistry {
    #[cfg(feature = "protocol-http")]
    {
        let mut registry = ProtocolRegistry::new();
        register_http(&mut registry, config);
        registry
    }
    #[cfg(not(feature = "protocol-http"))]
    {
        let _ = config;
        ProtocolRegistry::new()
    }
}

#[cfg(feature = "protocol-http")]
fn register_http(registry: &mut ProtocolRegistry, config: &Config) {
    registry.register(Box::new(crate::protocol::http::HttpProtocolHandler::new(
        &config.protocol.http,
        &config.backend.upstreams,
    )));
}

#[cfg(feature = "xdp")]
pub(crate) fn start_xdp(
    config: &Arc<Config>,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<Option<Arc<Mutex<XdpFilter>>>> {
    use crate::xdp::XdpMetrics;

    if !config.xdp.enabled {
        return Ok(None);
    }

    let filter = XdpFilter::new(&config.xdp.interface);
    let shared = Arc::new(Mutex::new(filter));
    {
        let mut guard = shared.lock().expect("xdp lock poisoned");
        let globals = XdpGlobals::from_config(&config.xdp)?;
        guard.set_globals(globals);
        guard.load()?;
    }
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
    Ok(Some(shared))
}

#[cfg(not(feature = "xdp"))]
pub(crate) fn start_xdp(
    _config: &Arc<Config>,
    _shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<Option<Arc<Mutex<XdpFilter>>>> {
    Ok(None)
}

/// Юзерспейс-агрегатор префиксов: активен, когда detect.prefix включён,
/// а XDP-путь не работает (не собран или выключен в конфиге).
pub(crate) fn start_subnet_tracker(config: &Config) -> Option<Arc<SubnetTracker>> {
    let xdp_active = cfg!(feature = "xdp") && config.xdp.enabled;
    if config.detect.prefix.enabled && !xdp_active {
        tracing::info!(
            window_secs = config.detect.prefix.window_secs,
            syn_threshold = config.detect.prefix.syn_threshold,
            "subnet tracker enabled (userspace prefix aggregation)"
        );
        Some(Arc::new(SubnetTracker::new()))
    } else {
        None
    }
}

pub(crate) fn build_whitelist(config: &Config) -> anyhow::Result<Arc<HashSet<IpAddr>>> {
    let mut set = HashSet::with_capacity(config.whitelist.len());
    for entry in &config.whitelist {
        let ip: IpAddr = entry
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid whitelist entry: {entry}"))?;
        set.insert(ip);
    }
    Ok(Arc::new(set))
}
