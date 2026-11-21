//! Filter order and upstream establishment for one accepted connection.

use super::Gateway;
use crate::metrics;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// One in every `BUDGET_LOG_EVERY` budget rejections is logged.
const BUDGET_LOG_EVERY: u64 = 128;

impl Gateway {
	/// Runs the filter stages, PoW gate, protocol handshake and relay.
	///
	/// # Errors
	/// Only upstream I/O failures are surfaced; every filter drop is `Ok(())`.
	pub(super) async fn handle_client(
		&self,
		mut client: TcpStream,
		peer_addr: std::net::SocketAddr,
		client_addr: std::net::SocketAddr,
	) -> anyhow::Result<()> {
		let peer_ip = client_addr.ip();
		let trusted = self.whitelist.contains(&peer_ip);

		// Trusted peers bypass every ingress filter and are never auto-banned:
		// blacklist entries and XDP/Redis bans propagate across all nodes, so a
		// whitelisted address must never enter that path.
		if !trusted {
			let local_port = client.local_addr().map_or(0, |addr| addr.port());
			if self.blacklist.is_blocked_on(peer_ip, local_port) {
				metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
				return Ok(());
			}

			// Feed the subnet detector only after the ban decision: a source we
			// already block must not allocate tracker memory.
			if let Some(tracker) = &self.subnet_tracker {
				tracker.record_connection(peer_ip);
			}

			// The cheap token check runs before the expensive PoW exchange: a
			// client that never solves the challenge must still exhaust its own
			// rate budget instead of holding a task for the PoW timeout unpaid.
			if !self.rate_limiter.check(peer_ip) {
				self.block_rate_limit(peer_ip).await;
				return Ok(());
			}
		}

		// Global budget: `try_acquire` keeps an overloaded node responsive (the
		// accept loop never queues unbounded per-connection tasks) and the
		// connection is closed immediately on refusal.
		let _global_permit = if trusted {
			None
		} else {
			match self.budget.try_acquire() {
				Ok(permit) => Some(permit),
				Err(_) => {
					metrics::CONNECTIONS_TOTAL.with_label_values(&["overloaded"]).inc();
					let seen = self.budget_rejections.fetch_add(1, Ordering::Relaxed);
					if seen % BUDGET_LOG_EVERY == 0 {
						tracing::warn!(
							"global connection budget exhausted after {seen} rejections, dropping {peer_ip}"
						);
					}
					return Ok(());
				},
			}
		};

		let Some(_connection_permit) = self.connection_limiter.try_acquire(peer_ip) else {
			if trusted {
				tracing::debug!("per-IP connection limit reached for trusted {peer_ip}");
			} else {
				self.block_rate_limit(peer_ip).await;
			}
			return Ok(());
		};

		if !self.pass_pow_gate(&mut client, peer_ip).await? {
			return Ok(());
		}

		let handshake_budget = Duration::from_secs(self.config.limits.handshake_timeout_secs.max(1));
		let handler = self.registry.primary()?;
		let handshake = match tokio::time::timeout(handshake_budget, handler.handshake(&mut client)).await {
			Ok(Ok(handshake)) => handshake,
			Ok(Err(e)) => {
				tracing::debug!("handshake rejected from {peer_addr}: {e}");
				metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
				return Ok(());
			},
			Err(_) => {
				tracing::debug!("handshake timed out after {handshake_budget:?} from {peer_addr}");
				metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
				return Ok(());
			},
		};

		metrics::CONNECTIONS_TOTAL.with_label_values(&["allowed"]).inc();
		self.allowed_1s.fetch_add(1, Ordering::Relaxed);
		self.reputation.record_good(peer_ip);

		let mut backend = self
			.connect_upstream(&handshake.upstream.addr, handshake_budget)
			.await?;
		self.send_preamble(
			&mut client,
			&mut backend,
			client_addr,
			&handshake.initial_backend_data,
			handshake_budget,
		)
		.await?;
		self.relay_with_idle(client, backend, self.relay_idle_timeout()).await
	}

	/// Opens the upstream connection under the handshake timeout.
	///
	/// # Errors
	/// Fails when the connect is refused or exceeds `budget`.
	async fn connect_upstream(&self, negotiated: &str, budget: Duration) -> anyhow::Result<TcpStream> {
		let upstream = self.next_upstream(negotiated);
		match tokio::time::timeout(budget, TcpStream::connect(upstream)).await {
			Ok(Ok(stream)) => Ok(stream),
			Ok(Err(e)) => Err(anyhow::anyhow!("upstream connect to {upstream} failed: {e}")),
			Err(_) => Err(anyhow::anyhow!(
				"upstream connect to {upstream} timed out after {budget:?}"
			)),
		}
	}

	/// Writes the PROXY protocol header and the protocol's replay bytes to the
	/// backend under the handshake timeout.
	///
	/// # Errors
	/// Fails on address resolution and on a write that exceeds `budget`.
	#[allow(unused_variables)]
	async fn send_preamble(
		&self,
		client: &mut TcpStream,
		backend: &mut TcpStream,
		client_addr: std::net::SocketAddr,
		initial_data: &[u8],
		budget: Duration,
	) -> anyhow::Result<()> {
		let mut preamble = Vec::new();
		#[cfg(feature = "protocol-minecraft")]
		if self.config.protocol.minecraft.enabled && self.config.protocol.minecraft.send_proxy_protocol {
			let destination = client.local_addr()?;
			preamble.extend_from_slice(&super::super::proxy::protocol_v2(client_addr, destination)?);
		}
		preamble.extend_from_slice(initial_data);
		if preamble.is_empty() {
			return Ok(());
		}
		match tokio::time::timeout(budget, backend.write_all(&preamble)).await {
			Ok(Ok(())) => Ok(()),
			Ok(Err(e)) => Err(e.into()),
			Err(_) => Err(anyhow::anyhow!("upstream preamble write timed out after {budget:?}")),
		}
	}

	fn next_upstream<'a>(&'a self, negotiated: &'a str) -> &'a str {
		let upstreams = &self.config.backend.upstreams;
		if upstreams.len() > 1 {
			let idx = self.upstream_cursor.fetch_add(1, Ordering::Relaxed) % upstreams.len();
			return upstreams[idx].as_str();
		}
		if let Some(first) = upstreams.first() {
			return first.as_str();
		}
		negotiated
	}
}
