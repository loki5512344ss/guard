//! Per-connection pipeline of the edge engine: filters, PoW gate, protocol
//! handshake and upstream relay.
//!
//! The module root owns gateway construction and the entry point; the stages
//! live in `pipeline` (filters, PoW, handshake, upstream), `admission`
//! (reputation escalation, bans and events) and `relay` (idle-bounded relay).

mod admission;
mod challenge;
mod pipeline;
mod relay;

#[cfg(feature = "protocol-minecraft")]
use super::proxy;
use super::{Gateway, GatewayOutcome};
use crate::config::Config;
use crate::engine::challenge::DifficultyAdjuster;
use crate::engine::subnet::tracker::SubnetTracker;
use crate::filter::blacklist::Blacklist;
use crate::filter::connection_limit::ConnectionLimiter;
use crate::filter::rate_limit::RateLimiter;
use crate::protocol::ProtocolRegistry;
use crate::store::clickhouse::ClickHouseWriter;
use crate::traffic::reputation::IpReputation;
use crate::xdp::XdpFilter;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Semaphore;

impl Gateway {
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		config: Arc<Config>,
		rate_limiter: Arc<RateLimiter>,
		blacklist: Arc<Blacklist>,
		adjuster: Arc<Mutex<DifficultyAdjuster>>,
		whitelist: Arc<HashSet<IpAddr>>,
		reputation: Arc<IpReputation>,
		xdp: Option<Arc<Mutex<XdpFilter>>>,
		clickhouse: Option<Arc<TokioMutex<ClickHouseWriter>>>,
		allowed_1s: Arc<AtomicU64>,
		registry: Arc<ProtocolRegistry>,
		subnet_tracker: Option<Arc<SubnetTracker>>,
	) -> Self {
		let max_connections = config.limits.max_connections_per_ip as usize;
		let budget = Arc::new(Semaphore::new(super::connection_budget_capacity(&config)));
		Self {
			config,
			rate_limiter,
			connection_limiter: ConnectionLimiter::new(max_connections),
			blacklist,
			adjuster,
			whitelist,
			reputation,
			xdp,
			clickhouse,
			allowed_1s,
			registry,
			subnet_tracker,
			budget,
			budget_rejections: AtomicU64::new(0),
			upstream_cursor: std::sync::atomic::AtomicUsize::new(0),
		}
	}

	/// Runs the full pipeline for one inbound connection.
	///
	/// # Errors
	/// Only upstream I/O failures are surfaced; a connection dropped by a filter or
	/// by the challenge gate is not an error.
	#[allow(unused_mut)]
	pub async fn handle(&self, mut client: TcpStream, peer_addr: std::net::SocketAddr) -> GatewayOutcome {
		let client_addr = if self.config.proxy_protocol.ingress_enabled {
			#[cfg(feature = "protocol-minecraft")]
			{
				match proxy::resolve_client_addr(&self.config.proxy_protocol, &mut client, peer_addr).await {
					Ok(client_addr) => client_addr,
					Err(error) => {
						return GatewayOutcome {
							client_ip: None,
							result: Err(error),
						};
					},
				}
			}
			#[cfg(not(feature = "protocol-minecraft"))]
			{
				return GatewayOutcome {
					client_ip: None,
					result: Err(anyhow::anyhow!("inbound PROXY protocol requires protocol-minecraft")),
				};
			}
		} else {
			peer_addr
		};
		let client_ip = client_addr.ip();
		let result = self.handle_client(client, peer_addr, client_addr).await;
		GatewayOutcome {
			client_ip: Some(client_ip),
			result,
		}
	}
}
