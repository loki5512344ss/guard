//! Proof-of-work gate step of the connection pipeline.

use super::Gateway;
use crate::engine::challenge::enforce as enforce_pow;
use crate::metrics;
use std::net::IpAddr;
use tokio::net::TcpStream;

impl Gateway {
	/// Runs the proof-of-work gate for `peer_ip` and reports whether the
	/// connection may continue.
	///
	/// Whitelisted peers skip the challenge but still publish the current
	/// difficulty to the metrics gauge.
	///
	/// # Errors
	/// Propagates I/O failures from the challenge exchange.
	pub(super) async fn pass_pow_gate(&self, client: &mut TcpStream, peer_ip: IpAddr) -> anyhow::Result<bool> {
		let pow_config = &self.config.pow;
		if !(pow_config.enabled && pow_config.difficulty > 0) {
			return Ok(true);
		}
		if self.whitelist.contains(&peer_ip) {
			metrics::POW_CHALLENGES_TOTAL.with_label_values(&["skipped"]).inc();
			metrics::POW_CURRENT_DIFFICULTY.set(pow_config.difficulty as i64);
			return Ok(true);
		}

		let diff = {
			let mut adjuster = self.adjuster.lock().expect("adjuster lock poisoned");
			adjuster.record_connection();
			adjuster.current_difficulty()
		};
		// The configured difficulty is a hard floor even if the adjuster was
		// constructed without it; recording the connection above still adapts
		// the value for later peers.
		let diff = diff.max(pow_config.difficulty);
		let result = enforce_pow(client, peer_ip, diff).await?;
		if !result {
			metrics::POW_CHALLENGES_TOTAL.with_label_values(&["failed"]).inc();
			tracing::debug!("pow: failed for {peer_ip}, dropping connection");
			return Ok(false);
		}
		metrics::POW_CHALLENGES_TOTAL.with_label_values(&["passed"]).inc();
		metrics::POW_CURRENT_DIFFICULTY.set(diff as i64);
		Ok(true)
	}
}
