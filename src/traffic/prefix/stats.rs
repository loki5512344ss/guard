use anyhow::Result;
use std::future::Future;
use std::net::IpAddr;

/// Value of the `prefix_stats` map.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixStatsVal {
	pub syn_count: u64,
	pub pkt_count: u64,
	pub last_seen_ns: u64,
}

impl PrefixStatsVal {
	/// Parses the raw 24-byte map value.
	#[must_use]
	pub fn from_bytes(bytes: [u8; 24]) -> Self {
		let read_u64 =
			|range: std::ops::Range<usize>| u64::from_le_bytes(bytes[range].try_into().expect("8-byte field"));
		Self {
			syn_count: read_u64(0..8),
			pkt_count: read_u64(8..16),
			last_seen_ns: read_u64(16..24),
		}
	}

	/// Serialises the value into the raw 24-byte map layout.
	#[must_use]
	pub fn to_bytes(self) -> [u8; 24] {
		let mut out = [0u8; 24];
		out[0..8].copy_from_slice(&self.syn_count.to_le_bytes());
		out[8..16].copy_from_slice(&self.pkt_count.to_le_bytes());
		out[16..24].copy_from_slice(&self.last_seen_ns.to_le_bytes());
		out
	}
}

/// Aggregated counters for one prefix over a detection window.
///
/// `unique_sources == 0` means the source does not count distinct addresses
/// (the XDP path), and the spoof gate then never confirms `Block`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixSnapshot {
	pub syn_count: u64,
	pub pkt_count: u64,
	pub last_seen_ns: u64,
	pub unique_sources: u64,
}

/// Source of per-prefix aggregates; keeps tests independent of the kernel.
pub trait PrefixStatsSource {
	/// Snapshot of the aggregates for the current window.
	///
	/// # Errors
	/// Returns an error when the source cannot be read (map not loaded, BPF
	/// failure and similar).
	fn snapshot(&self) -> impl Future<Output = Result<Vec<(IpAddr, PrefixSnapshot)>>> + Send;
}

/// Verdict escalation ladder of the subnet-level detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetVerdict {
	Monitor,
	StrictLimit,
	Challenge,
	Block,
}

/// Verdict for a single prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixVerdict {
	pub prefix: IpAddr,
	pub verdict: SubnetVerdict,
	pub snapshot: PrefixSnapshot,
}

/// Detector for distributed attacks at prefix granularity.
///
/// Escalation ladder over the `syn_count` of one window: below `threshold` is
/// `Monitor`, below `2 x threshold` is `StrictLimit`, anything higher is
/// `Challenge`. `Block` requires at least `4 x threshold` *and* a passed spoof
/// gate (at least `min_unique_sources` distinct IPs), which guards against
/// false bans of CGNAT ranges and spoofed sources.
#[derive(Debug, Clone)]
pub struct SubnetDetector {
	syn_threshold: u64,
	min_unique_sources: u64,
}

impl SubnetDetector {
	#[must_use]
	pub fn new(syn_threshold: u64, min_unique_sources: u64) -> Self {
		Self {
			syn_threshold: syn_threshold.max(1),
			min_unique_sources,
		}
	}

	#[must_use]
	pub fn from_config(config: &crate::config::DetectPrefixConfig) -> Self {
		Self::new(config.syn_threshold, config.min_unique_sources)
	}

	/// Evaluates a snapshot and returns verdicts for all active prefixes.
	#[must_use]
	pub fn evaluate(&self, snapshots: &[(IpAddr, PrefixSnapshot)]) -> Vec<PrefixVerdict> {
		snapshots
			.iter()
			.filter(|(_, snap)| snap.syn_count > 0)
			.map(|(prefix, snap)| PrefixVerdict {
				prefix: *prefix,
				verdict: self.verdict_for(snap),
				snapshot: *snap,
			})
			.collect()
	}

	#[must_use]
	fn verdict_for(&self, snap: &PrefixSnapshot) -> SubnetVerdict {
		let t = self.syn_threshold;
		if snap.syn_count < t {
			return SubnetVerdict::Monitor;
		}
		if snap.syn_count < t.saturating_mul(2) {
			return SubnetVerdict::StrictLimit;
		}
		let extreme = snap.syn_count >= t.saturating_mul(4);
		if extreme && self.spoof_gate_passed(snap) {
			return SubnetVerdict::Block;
		}
		SubnetVerdict::Challenge
	}

	#[must_use]
	fn spoof_gate_passed(&self, snap: &PrefixSnapshot) -> bool {
		// The gate is disabled (min_unique_sources == 0) or diversity is confirmed.
		self.min_unique_sources == 0 || snap.unique_sources >= self.min_unique_sources
	}
}

/// [`PrefixStatsSource`] backed by the XDP filter (feature `xdp`).
///
/// Reads the `prefix_stats` map. The kernel does not track distinct source
/// addresses, so the spoof gate never confirms `Block` on this path.
#[cfg(feature = "xdp")]
pub struct XdpPrefixStats {
	filter: std::sync::Arc<std::sync::Mutex<crate::xdp::XdpFilter>>,
}

#[cfg(feature = "xdp")]
impl XdpPrefixStats {
	#[must_use]
	pub fn new(filter: std::sync::Arc<std::sync::Mutex<crate::xdp::XdpFilter>>) -> Self {
		Self { filter }
	}

	/// Locks the filter mutex (needed for kernel enforcement of verdicts).
	///
	/// # Panics
	/// Panics if the mutex is poisoned, that is, if another thread panicked
	/// while holding it.
	pub fn filter_lock(&self) -> std::sync::MutexGuard<'_, crate::xdp::XdpFilter> {
		self.filter.lock().expect("xdp lock poisoned")
	}
}

#[cfg(feature = "xdp")]
impl PrefixStatsSource for XdpPrefixStats {
	async fn snapshot(&self) -> Result<Vec<(IpAddr, PrefixSnapshot)>> {
		let raw = self.filter_lock().read_prefix_stats()?;
		Ok(raw
			.into_iter()
			.filter_map(|(key, val)| {
				let prefix = key.to_prefix()?;
				Some((
					prefix,
					PrefixSnapshot {
						syn_count: val.syn_count,
						pkt_count: val.pkt_count,
						last_seen_ns: val.last_seen_ns,
						unique_sources: 0,
					},
				))
			})
			.collect())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn stats_val_roundtrip() {
		let val = PrefixStatsVal {
			syn_count: 42,
			pkt_count: 100,
			last_seen_ns: 1_234_567_890,
		};
		assert_eq!(PrefixStatsVal::from_bytes(val.to_bytes()), val);
		assert_eq!(size_of::<PrefixStatsVal>(), 24);
	}
}
