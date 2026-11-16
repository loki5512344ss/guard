//! Edge daemon services: protocol registry, whitelist, XDP and the subnet
//! tracker.

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

/// Builds the protocol registry from the compiled handlers.
///
/// Handlers are supplied by features: `protocol-http` registers the HTTP/1.1
/// handler with the policy from `[protocol.http]`. External crates register
/// their handlers at the same point.
pub(crate) fn build_registry(config: &Config) -> ProtocolRegistry {
	#[cfg(feature = "protocol-minecraft")]
	if config.protocol.minecraft.enabled {
		let mut registry = ProtocolRegistry::new();
		registry.register(Box::new(crate::protocol::minecraft::MinecraftProtocolHandler::new(
			&config.protocol.minecraft,
			&config.backend.upstreams,
		)));
		return registry;
	}
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
pub fn start_xdp(
	config: &Arc<Config>,
	shutdown_rx: &watch::Receiver<bool>,
	blacklist: &Arc<Blacklist>,
) -> anyhow::Result<Option<Arc<Mutex<XdpFilter>>>> {
	use anyhow::Context as _;
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
		// With ingress PROXY protocol, XDP sees only the provider's transport
		// address, so its events must not trigger per-player or provider bans.
		if !config.proxy_protocol.ingress_enabled {
			// load() captures the blacklist and auto-ban policy in its ringbuf
			// callback, so set_autoban must happen first.
			guard.set_autoban(blacklist.clone(), &config.xdp);
		} else if config.xdp.auto_ban_enabled {
			tracing::warn!(
				"XDP auto-ban is disabled while inbound PROXY protocol is enabled; XDP only sees transport peers"
			);
		}
		guard.load()?;
		// The kernel filter only honours its LPM whitelist, so a configured
		// `whitelist` that fails to load is a startup error: silently dropping
		// the entries would expose trusted peers to the XDP rules.
		let whitelist = build_whitelist(config)?;
		for ip in whitelist.iter() {
			guard
				.whitelist_add(*ip)
				.with_context(|| format!("failed to load XDP whitelist entry {ip}"))?;
		}
		tracing::info!(
			entries = whitelist.len(),
			"configured whitelist loaded into the XDP LPM maps"
		);
	}
	let xdp_metrics = XdpMetrics::register()?;

	let sd = shutdown_rx.clone();
	let shared_thread = shared.clone();
	std::thread::spawn(move || {
		// The loop ticks every 5 s; sweep the ban maps once a minute.
		const REAP_EVERY_TICKS: u32 = 12;
		let mut tick: u32 = 0;
		while !*sd.borrow() {
			let guard = match shared_thread.lock() {
				Ok(g) => g,
				Err(_) => break,
			};
			guard.drain_events();
			if let Ok(stats) = guard.get_stats() {
				xdp_metrics.update(&stats);
			}
			tick += 1;
			if tick >= REAP_EVERY_TICKS {
				tick = 0;
				// The packet path only expires the exact /32 or /128 key it
				// looked up, so wider prefix bans stay resident until swept.
				match guard.reap_expired_bans() {
					Ok(0) => {},
					Ok(n) => tracing::info!(reaped = n, "expired XDP prefix bans removed"),
					Err(e) => tracing::warn!(error = %e, "XDP expired-ban reaper failed"),
				}
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
pub fn start_xdp(
	_config: &Arc<Config>,
	_shutdown_rx: &watch::Receiver<bool>,
	_blacklist: &Arc<Blacklist>,
) -> anyhow::Result<Option<Arc<Mutex<XdpFilter>>>> {
	Ok(None)
}

/// Userspace prefix aggregator: active when `detect.prefix` is enabled and the
/// XDP path does not run (not compiled in or disabled in the config).
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

/// Validates store features at edge startup: a config that asks for redis in a
/// binary without `store-redis` must fail immediately instead of silently losing
/// blacklist sync (the sync task in `runtime.rs` lives behind the same cfg).
///
/// Called from `build_whitelist`, the closest `?` hook that receives the config
/// before the listener binds.
fn ensure_store_features(config: &Config) -> anyhow::Result<()> {
	#[cfg(not(feature = "store-redis"))]
	if config.store.redis_url.as_deref().is_some_and(|url| !url.is_empty()) {
		anyhow::bail!("[store].redis_url requires a redis-backed store: built without store-redis feature");
	}
	#[cfg(feature = "store-redis")]
	let _ = config;
	Ok(())
}

/// Parses `whitelist` entries into a shared address set.
///
/// # Errors
/// Fails on an invalid entry or when the config requires store features that are
/// not compiled in.
pub fn build_whitelist(config: &Config) -> anyhow::Result<Arc<HashSet<IpAddr>>> {
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
