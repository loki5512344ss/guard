//! Traffic Intelligence in the hot path: reputation, auto-ban and window metrics.
//!
//! Every call reachable from the accept path is cheap (DashMap/atomics) and
//! performs no blocking I/O.

use crate::config::DetectAutobanConfig;
use crate::filter::blacklist::Blacklist;
use crate::metrics;
use crate::traffic::reputation::IpReputation;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const BAN_REASON_LOW_REPUTATION: &str = "low_reputation";
const BAN_REASON_ATTACK: &str = "attack_detector";

/// Entry point of Traffic Intelligence on the network path.
///
/// Events: a new connection (`on_accept`), a finished connection
/// (`on_connection_end`) and attack-detector escalation (`ban_offenders`).
pub struct TrafficHook {
	reputation: Arc<IpReputation>,
	blacklist: Arc<Blacklist>,
	autoban: DetectAutobanConfig,
	ban_ttl_secs: u64,
	conn_window: AtomicU64,
}

impl TrafficHook {
	pub fn new(
		reputation: Arc<IpReputation>,
		blacklist: Arc<Blacklist>,
		autoban: DetectAutobanConfig,
		ban_ttl_secs: u64,
	) -> Self {
		Self {
			reputation,
			blacklist,
			autoban,
			ban_ttl_secs,
			conn_window: AtomicU64::new(0),
		}
	}

	/// A new connection was accepted by the accept loop.
	///
	/// Only bumps the cps window counter; the counter is drained by
	/// [`Self::take_cps`] once per second.
	pub fn on_accept(&self) {
		self.conn_window.fetch_add(1, Ordering::Relaxed);
	}

	/// A connection finished processing.
	///
	/// If the source was pushed down to the reputation threshold, it is banned
	/// with the TTL taken from the config.
	pub fn on_connection_end(&self, ip: IpAddr) {
		if !self.autoban.enabled || self.blacklist.is_blocked(ip) {
			return;
		}
		self.autoban_if_toxic(ip, BAN_REASON_LOW_REPUTATION);
	}

	/// Attack-detector escalation: bans every source below the reputation
	/// threshold and returns how many bans were issued.
	///
	/// Called once on the transition into `UnderAttack`, not on every tick.
	pub fn ban_offenders(&self) -> usize {
		if !self.autoban.enabled {
			return 0;
		}
		let offenders = self.reputation.offenders_below(self.autoban.reputation_threshold);
		let mut banned = 0;
		for ip in offenders {
			if self.blacklist.is_blocked(ip) {
				continue;
			}
			self.ban(ip, BAN_REASON_ATTACK);
			banned += 1;
		}
		banned
	}

	/// Takes the accumulated one-second window of new connections (cps).
	pub fn take_cps(&self) -> u64 {
		self.conn_window.swap(0, Ordering::Relaxed)
	}

	fn autoban_if_toxic(&self, ip: IpAddr, reason: &str) {
		if self.reputation.score(ip) > self.autoban.reputation_threshold {
			return;
		}
		self.ban(ip, reason);
	}

	fn ban(&self, ip: IpAddr, reason: &str) {
		self.blacklist.add(ip, Duration::from_secs(self.ban_ttl_secs), reason);
		metrics::AUTO_BANS_TOTAL.with_label_values(&[reason]).inc();
		tracing::warn!(%ip, reason, ttl_secs = self.ban_ttl_secs, "auto-ban issued by traffic intelligence");
	}
}
