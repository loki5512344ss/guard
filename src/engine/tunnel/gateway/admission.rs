//! Reputation escalation, bans and telemetry for dropped connections.

use super::Gateway;
use crate::metrics;
use crate::store::clickhouse::ClickHouseEvent;
use std::net::IpAddr;
use std::time::Duration;

impl Gateway {
	/// Accounts for a connection dropped by an admission filter and escalates to
	/// a ban when the source reputation is exhausted.
	///
	/// Whitelisted peers are exempt: a ban is replicated to Redis and XDP on
	/// every node, which would lock a trusted operator out of the whole cluster.
	pub(super) async fn block_rate_limit(&self, ip: IpAddr) {
		if self.whitelist.contains(&ip) {
			metrics::RATE_LIMIT_HITS.with_label_values(&["trusted"]).inc();
			return;
		}
		metrics::RATE_LIMIT_HITS.with_label_values(&["hit"]).inc();
		metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
		self.reputation.record_bad(ip);
		if self.reputation.score(ip) < -40 {
			// Defence in depth: a trusted proxy address must never enter the ban
			// path, even when reputation escalation is reached. Bans are
			// replicated to Redis and XDP on every node, so one wrong identity
			// here could take the ingress proxy out of the whole cluster.
			if self.is_trusted_proxy(ip) {
				tracing::warn!(
					%ip,
					"suppressed ban for an address inside proxy_protocol.trusted_cidrs"
				);
				return;
			}
			let duration_secs = Duration::from_secs(self.config.ban.ban_duration_secs);
			self.blacklist.add(ip, duration_secs, "low_reputation");
			if !self.config.proxy_protocol.ingress_enabled {
				self.xdp_ban(ip, duration_secs.as_secs());
			}
			self.push_event("block", ip, "low_reputation").await;
			tracing::info!("low reputation ban {ip}: rate-limit abuse");
		}
	}

	/// Returns whether `ip` belongs to a configured trusted proxy network.
	fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
		self.config
			.proxy_protocol
			.trusted_cidrs
			.iter()
			.any(|cidr| cidr.contains(ip))
	}

	/// Mirrors a ban into the XDP map, if the kernel filter is attached.
	fn xdp_ban(&self, ip: IpAddr, duration_secs: u64) {
		let Some(xdp) = &self.xdp else {
			return;
		};
		let prefix_len = if ip.is_ipv4() { 32 } else { 128 };
		match xdp
			.lock()
			.expect("xdp lock poisoned")
			.ban_cidr(ip, prefix_len, duration_secs)
		{
			Ok(()) => tracing::debug!("xdp ban {ip} for {duration_secs}s"),
			Err(e) => tracing::warn!("xdp ban failed for {ip}: {e}"),
		}
	}

	/// Forwards an event to ClickHouse when the writer is configured.
	async fn push_event(&self, event_type: &str, ip: IpAddr, data_string: &str) {
		let Some(writer) = &self.clickhouse else {
			return;
		};
		let event = ClickHouseEvent {
			timestamp: time::OffsetDateTime::now_utc(),
			event_type: event_type.to_string(),
			ip: ip.to_string(),
			data_float: 0.0,
			data_int: 0,
			data_string: data_string.to_string(),
		};
		if let Err(e) = writer.lock().await.push(event).await {
			tracing::debug!("clickhouse push error: {e}");
		}
	}
}
