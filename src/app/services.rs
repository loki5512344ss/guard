//! Сервисы edge-демона: реестр протоколов, whitelist, XDP и subnet-трекер.

use crate::config::Config;
use crate::engine::subnet::tracker::SubnetTracker;
use crate::filter::blacklist::Blacklist;
use crate::protocol::ProtocolRegistry;
use crate::xdp::XdpFilter;
#[cfg(feature = "xdp")]
use crate::xdp::XdpGlobals;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
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
    blacklist: &Arc<Blacklist>,
) -> anyhow::Result<Option<Arc<Mutex<XdpFilter>>>> {
    use std::time::Duration;

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
        // Порядок load-bearing: `load()` захватывает blacklist и политику
        // авто-бана в ringbuf-колбэк (XdpFilter::load -> build_ringbuf),
        // поэтому set_autoban обязан отработать ДО load(), а не после.
        guard.set_autoban(blacklist.clone(), &config.xdp);
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
    _blacklist: &Arc<Blacklist>,
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

/// Store-фичи проверяются на старте edge-демона: конфиг, запрашивающий redis,
/// в бинаре без `store-redis` должен упасть сразу, а не молча потерять
/// blacklist-sync (sync-задача в runtime.rs живёт под тем же cfg).
/// Точка вызова — `build_whitelist`: ближайший `?`-хук, принимающий конфиг
/// до бинда listener'а (сам runtime.rs вне правок этой задачи).
fn ensure_store_features(config: &Config) -> anyhow::Result<()> {
    #[cfg(not(feature = "store-redis"))]
    if config.store.redis_url.as_deref().is_some_and(|url| !url.is_empty()) {
        anyhow::bail!("[store].redis_url requires a redis-backed store: built without store-redis feature");
    }
    #[cfg(feature = "store-redis")]
    let _ = config;
    Ok(())
}

pub(crate) fn build_whitelist(config: &Config) -> anyhow::Result<Arc<HashSet<IpAddr>>> {
    ensure_store_features(config)?;
    let mut set = HashSet::with_capacity(config.whitelist.len());
    for entry in &config.whitelist {
        let ip: IpAddr = entry
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid whitelist entry: {entry}"))?;
        set.insert(ip);
    }
    Ok(Arc::new(set))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_redis() -> Config {
        Config {
            store: crate::config::StoreConfig {
                redis_url: Some("redis://127.0.0.1:6379/0".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[cfg(not(feature = "store-redis"))]
    #[test]
    fn redis_config_without_feature_fails_fast() {
        let err = ensure_store_features(&config_with_redis()).expect_err("must fail without store-redis");
        assert!(err.to_string().contains("built without store-redis feature"));
    }

    #[cfg(not(feature = "store-redis"))]
    #[test]
    fn empty_store_config_passes_without_feature() {
        assert!(ensure_store_features(&Config::default()).is_ok());
    }

    #[cfg(feature = "store-redis")]
    #[test]
    fn guard_is_noop_with_feature() {
        assert!(ensure_store_features(&config_with_redis()).is_ok());
    }

    /// Wiring-тасовка XDP auto-ban: `start_xdp` обязан принимать `Arc<Blacklist>`
    /// (т.е. существовать в сигнатуре с blacklist) и при выключенном `[xdp]`
    /// не трогать ни ядро, ни blacklist. Порядок `set_autoban` -> `load()`
    /// внутри enabled-ветки без ядра непроверяем — см. комментарий на месте вызова.
    #[test]
    fn start_xdp_accepts_blacklist_and_skips_kernel_when_disabled() {
        let (_tx, rx) = watch::channel(false);
        let blacklist = Arc::new(Blacklist::new());
        let started = start_xdp(&Arc::new(Config::default()), &rx, &blacklist)
            .expect("xdp disabled: no kernel work and no error");
        assert!(started.is_none());
        assert!(blacklist.is_empty());
    }
}
