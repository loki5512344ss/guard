//! Generic TCP proxy: фильтры входа → protocol handshake → upstream.

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
mod gateway;
#[cfg(feature = "protocol-minecraft")]
mod proxy;

/// Общее состояние edge-движка, разделяемое между accept-loop'ами.
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
    upstream_cursor: AtomicUsize,
}

/// Result of a connection attempt, retaining the verified client identity for
/// post-connection traffic accounting.
pub struct GatewayOutcome {
    pub client_ip: Option<IpAddr>,
    pub result: anyhow::Result<()>,
}
