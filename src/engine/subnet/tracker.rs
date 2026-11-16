//! Userspace aggregator of new connections per prefix (/24 for IPv4, /64 for
//! IPv6).
//!
//! Fallback path of the subnet detector when XDP is disabled: it feeds
//! [`crate::traffic::prefix::SubnetDetector`] with the same snapshot shape the
//! kernel map produces.
//!
//! Memory is bounded on purpose. Both the prefix table and the per-prefix
//! source set have hard caps, so a source rotating through a /48 (or a /64 with
//! millions of addresses) cannot grow the tracker without limit during one
//! detection window; over-cap events are counted and reported.

use crate::traffic::prefix::{PrefixSnapshot, PrefixStatsSource, prefix_of};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Upper bound on tracked prefixes per window.
pub const DEFAULT_MAX_PREFIXES: usize = 4096;

/// Upper bound on distinct sources remembered per prefix.
///
/// 256 is well above the default `min_unique_sources = 16` spoof gate while
/// keeping the worst-case table at a few megabytes.
pub const DEFAULT_MAX_SOURCES_PER_PREFIX: usize = 256;

struct WindowState {
	syn_count: u64,
	sources: HashSet<IpAddr>,
	started: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Limits {
	max_prefixes: usize,
	max_sources: usize,
}

/// Aggregates new connections per prefix.
///
/// `take_snapshot` drains the accumulated state, so every call closes exactly
/// one detection window.
pub struct SubnetTracker {
	windows: Mutex<HashMap<IpAddr, WindowState>>,
	limits: Limits,
	dropped_prefixes: AtomicU64,
	dropped_sources: AtomicU64,
}

impl Default for SubnetTracker {
	fn default() -> Self {
		Self::new()
	}
}

impl SubnetTracker {
	#[must_use]
	pub fn new() -> Self {
		Self::with_limits(DEFAULT_MAX_PREFIXES, DEFAULT_MAX_SOURCES_PER_PREFIX)
	}

	/// Creates a tracker with explicit caps.
	///
	/// Both limits are clamped to at least one entry. The constructor mainly
	/// lets tests exercise the caps without building thousands of prefixes.
	#[must_use]
	pub fn with_limits(max_prefixes: usize, max_sources_per_prefix: usize) -> Self {
		Self {
			windows: Mutex::new(HashMap::new()),
			limits: Limits {
				max_prefixes: max_prefixes.max(1),
				max_sources: max_sources_per_prefix.max(1),
			},
			dropped_prefixes: AtomicU64::new(0),
			dropped_sources: AtomicU64::new(0),
		}
	}

	/// Records a new inbound connection (userspace equivalent of a SYN).
	///
	/// Call it only after the source passed the blacklist check, so banned
	/// sources cannot allocate tracker memory.
	pub fn record_connection(&self, ip: IpAddr) {
		let prefix = prefix_of(ip);
		let mut windows = self.windows.lock().expect("subnet tracker lock poisoned");
		if let Some(state) = windows.get_mut(&prefix) {
			state.syn_count = state.syn_count.saturating_add(1);
			Self::remember_source(state, ip, self.limits.max_sources, &self.dropped_sources);
			return;
		}
		if windows.len() >= self.limits.max_prefixes {
			self.dropped_prefixes.fetch_add(1, Ordering::Relaxed);
			return;
		}
		let mut sources = HashSet::new();
		sources.insert(ip);
		windows.insert(
			prefix,
			WindowState {
				syn_count: 1,
				sources,
				started: Instant::now(),
			},
		);
	}

	/// Takes and resets the aggregates of the current window.
	#[must_use]
	pub fn take_snapshot(&self) -> Vec<(IpAddr, PrefixSnapshot)> {
		let windows = std::mem::take(&mut *self.windows.lock().expect("subnet tracker lock poisoned"));
		let dropped_prefixes = self.dropped_prefixes.load(Ordering::Relaxed);
		let dropped_sources = self.dropped_sources.load(Ordering::Relaxed);
		if dropped_prefixes > 0 || dropped_sources > 0 {
			tracing::debug!(
				dropped_prefixes,
				dropped_sources,
				"subnet tracker caps reached; aggregates are bounded"
			);
		}
		windows
			.into_iter()
			.filter(|(_, state)| state.syn_count > 0)
			.map(|(prefix, state)| {
				(
					prefix,
					PrefixSnapshot {
						// Userspace only sees established connections, so `pkt_count` mirrors the
						// same flow as `syn_count`.
						pkt_count: state.syn_count,
						syn_count: state.syn_count,
						last_seen_ns: state.started.elapsed().as_nanos() as u64,
						unique_sources: state.sources.len() as u64,
					},
				)
			})
			.collect()
	}

	/// Number of connections from new prefixes dropped because the prefix cap
	/// was reached.
	#[must_use]
	pub fn dropped_prefixes(&self) -> u64 {
		self.dropped_prefixes.load(Ordering::Relaxed)
	}

	/// Number of connections from new source addresses dropped because the
	/// per-prefix source cap was reached.
	#[must_use]
	pub fn dropped_sources(&self) -> u64 {
		self.dropped_sources.load(Ordering::Relaxed)
	}

	fn remember_source(state: &mut WindowState, ip: IpAddr, cap: usize, dropped: &AtomicU64) {
		if state.sources.len() < cap {
			state.sources.insert(ip);
			return;
		}
		if !state.sources.contains(&ip) {
			dropped.fetch_add(1, Ordering::Relaxed);
		}
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
