//! Userspace aggregator of new connections per prefix (/24 for IPv4, /64 for
//! IPv6).
//!
//! Fallback path of the subnet detector when XDP is disabled: it feeds
//! [`crate::traffic::prefix::SubnetDetector`] with the same snapshot shape the
//! kernel map produces.

use crate::traffic::prefix::{PrefixSnapshot, PrefixStatsSource, prefix_of};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

struct WindowState {
	syn_count: u64,
	sources: std::collections::HashSet<IpAddr>,
	started: Instant,
}

/// Aggregates new connections per prefix.
///
/// `take_snapshot` drains the accumulated state, so every call closes exactly
/// one detection window.
pub struct SubnetTracker {
	windows: DashMap<IpAddr, WindowState>,
}

impl Default for SubnetTracker {
	fn default() -> Self {
		Self::new()
	}
}

impl SubnetTracker {
	#[must_use]
	pub fn new() -> Self {
		Self {
			windows: DashMap::new(),
		}
	}

	/// Records a new inbound connection (userspace equivalent of a SYN).
	pub fn record_connection(&self, ip: IpAddr) {
		let prefix = prefix_of(ip);
		let mut state = self.windows.entry(prefix).or_insert_with(|| WindowState {
			syn_count: 0,
			sources: std::collections::HashSet::new(),
			started: Instant::now(),
		});
		state.syn_count = state.syn_count.saturating_add(1);
		state.sources.insert(ip);
	}

	/// Takes and resets the aggregates of the current window.
	#[must_use]
	pub fn take_snapshot(&self) -> Vec<(IpAddr, PrefixSnapshot)> {
		let mut out = Vec::new();
		// Drain every key: the next window starts from an empty map, so memory does not
		// grow when an attacker spoofs many distinct prefixes.
		self.windows.retain(|prefix, state| {
			if state.syn_count == 0 {
				return false;
			}
			out.push((
				*prefix,
				PrefixSnapshot {
					// Userspace only sees established connections, so `pkt_count` mirrors the same
					// flow as `syn_count`.
					pkt_count: state.syn_count,
					syn_count: state.syn_count,
					last_seen_ns: state.started.elapsed().as_nanos() as u64,
					unique_sources: state.sources.len() as u64,
				},
			));
			false
		});
		out
	}
}

/// Adapts [`SubnetTracker`] to the [`PrefixStatsSource`] trait.
pub struct TrackerSource {
	pub tracker: Arc<SubnetTracker>,
}

impl PrefixStatsSource for TrackerSource {
	async fn snapshot(&self) -> anyhow::Result<Vec<(IpAddr, PrefixSnapshot)>> {
		Ok(self.tracker.take_snapshot())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::{Ipv4Addr, Ipv6Addr};

	fn v4(octets: [u8; 4]) -> IpAddr {
		IpAddr::V4(Ipv4Addr::from(octets))
	}

	#[test]
	fn groups_connections_by_prefix() {
		let tracker = SubnetTracker::new();
		tracker.record_connection(v4([203, 0, 113, 1]));
		tracker.record_connection(v4([203, 0, 113, 2]));
		tracker.record_connection(v4([198, 51, 100, 9]));
		let snaps = tracker.take_snapshot();
		assert_eq!(snaps.len(), 2);
		let by_prefix: std::collections::HashMap<IpAddr, PrefixSnapshot> = snaps.into_iter().collect();
		assert_eq!(by_prefix[&v4([203, 0, 113, 0])].syn_count, 2);
		assert_eq!(by_prefix[&v4([203, 0, 113, 0])].unique_sources, 2);
		assert_eq!(by_prefix[&v4([198, 51, 100, 0])].syn_count, 1);
	}

	#[test]
	fn snapshot_drains_window() {
		let tracker = SubnetTracker::new();
		tracker.record_connection(v4([10, 0, 0, 1]));
		assert_eq!(tracker.take_snapshot().len(), 1);
		assert!(tracker.take_snapshot().is_empty());
	}

	#[test]
	fn mapped_addresses_share_v4_prefix() {
		let tracker = SubnetTracker::new();
		tracker.record_connection(v4([203, 0, 113, 5]));
		// ::ffff:203.0.113.6
		let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7106);
		tracker.record_connection(IpAddr::V6(mapped));
		let snaps = tracker.take_snapshot();
		assert_eq!(snaps.len(), 1);
		assert_eq!(snaps[0].0, v4([203, 0, 113, 0]));
		assert_eq!(snaps[0].1.unique_sources, 2);
	}
}
