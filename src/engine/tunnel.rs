//! Generic TCP proxy pipeline: ingress filters, protocol handshake, upstream
//! relay.

use crate::config::Config;
use crate::engine::challenge::DifficultyAdjuster;
use crate::engine::subnet_tracker::SubnetTracker;
use crate::filter::blacklist::Blacklist;
use crate::filter::connection_limit::ConnectionLimiter;
use crate::filter::rate_limit::RateLimiter;
use crate::protocol::ProtocolRegistry;
use crate::store::clickhouse::ClickHouseWriter;
use crate::traffic::reputation::IpReputation;
use crate::xdp::XdpFilter;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Semaphore;
mod gateway;
#[cfg(feature = "protocol-minecraft")]
mod proxy;
#[cfg(feature = "protocol-minecraft")]
pub use proxy::{ClientIpRejection, parse_v2_header, validate_client_ip};

/// Multiplier applied to the per-IP limit when sizing the global connection
/// budget: `4 x workers x max_connections_per_ip` in-flight connections.
const CONNECTION_BUDGET_FACTOR: usize = 4;
/// Ceiling of the global budget, so a large worker count cannot exhaust the
/// file-descriptor table of the host.
const CONNECTION_BUDGET_MAX: usize = 100_000;

/// Returns the in-flight connection budget of one gateway instance.
///
/// The budget lives on the gateway instead of in a process-wide static so an
/// embedded or test gateway gets its own limiter and configuration changes are
/// visible without restarting the process.
fn connection_budget_capacity(config: &Config) -> usize {
	let workers = config.workers.count.max(1);
	let per_ip = config.limits.max_connections_per_ip.max(1) as usize;
	workers
		.saturating_mul(per_ip)
		.saturating_mul(CONNECTION_BUDGET_FACTOR)
		.clamp(1, CONNECTION_BUDGET_MAX)
}

/// Shared edge engine state handed to every accept loop by [`Arc`].
pub struct Gateway {
	pub config: Arc<Config>,
	pub rate_limiter: Arc<RateLimiter>,
	pub connection_limiter: ConnectionLimiter,
	pub blacklist: Arc<Blacklist>,
	pub adjuster: Arc<Mutex<DifficultyAdjuster>>,
	pub whitelist: Arc<HashSet<IpAddr>>,
	pub reputation: Arc<IpReputation>,
	pub xdp: Option<Arc<Mutex<XdpFilter>>>,
	pub clickhouse: Option<Arc<TokioMutex<ClickHouseWriter>>>,
	pub allowed_1s: Arc<AtomicU64>,
	pub registry: Arc<ProtocolRegistry>,
	pub subnet_tracker: Option<Arc<SubnetTracker>>,
	budget: Arc<Semaphore>,
	budget_rejections: AtomicU64,
	upstream_cursor: AtomicUsize,
}

/// Result of a connection attempt, retaining the verified client identity for
/// post-connection traffic accounting.
pub struct GatewayOutcome {
	pub client_ip: Option<IpAddr>,
	pub result: anyhow::Result<()>,
}
