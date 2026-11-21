//! XDP program counters and the readers for the kernel statistics maps.
//!
//! `stats_map` is a `BPF_MAP_TYPE_PERCPU_ARRAY` keyed by the `STAT_*` indices
//! from `xdp/core/maps.h`; every element holds one `__u64` per CPU, so a
//! lookup returns a blob whose 8-byte chunks must be summed.
//! `prefix_stats` is a plain LRU hash read as whole key/value records.

#[cfg(feature = "xdp")]
use anyhow::{Context, Result};
#[cfg(feature = "xdp")]
use libbpf_rs::{MapCore, MapFlags};

#[cfg(feature = "xdp")]
use crate::traffic::prefix::{PrefixKey, PrefixStatsVal};
#[cfg(feature = "xdp")]
use crate::xdp::XdpFilter;

/// `STAT_TOTAL`: every packet that reached the filter.
pub const STAT_TOTAL: u32 = 0;
/// `STAT_TCP`: TCP packets seen.
pub const STAT_TCP: u32 = 1;
/// `STAT_WHITELIST`: packets passed by the whitelist check.
pub const STAT_WHITELIST: u32 = 2;
/// `STAT_BLACKLIST`: packets dropped by the blacklist check.
pub const STAT_BLACKLIST: u32 = 3;
/// `STAT_SYN_THROTTLE`: SYNs dropped by the per-source throttle.
pub const STAT_SYN_THROTTLE: u32 = 4;
/// `STAT_PASS`: packets passed to the kernel stack.
pub const STAT_PASS: u32 = 5;
/// `STAT_DROP`: packets dropped by any rule.
pub const STAT_DROP: u32 = 6;
/// `STAT_UDP`: UDP packets seen.
pub const STAT_UDP: u32 = 7;
/// `STAT_RATE_LIMIT`: packets dropped by a rate limiter.
pub const STAT_RATE_LIMIT: u32 = 8;
/// `STAT_CHALLENGE_SENT`: RST challenges sent to suspicious sources.
pub const STAT_CHALLENGE_SENT: u32 = 9;
/// `STAT_CHALLENGE_VERIFIED`: sources that answered a challenge correctly.
pub const STAT_CHALLENGE_VERIFIED: u32 = 10;
/// `STAT_CHALLENGE_FAILED`: sources that failed a challenge.
pub const STAT_CHALLENGE_FAILED: u32 = 11;
/// `STAT_FRAGMENT_BYPASS`: packets passed because their L4 header is unavailable (fragments).
pub const STAT_FRAGMENT_BYPASS: u32 = 12;

/// Sums a per-CPU `__u64` counter over every slot libbpf returned.
///
/// `lookup_percpu` yields one buffer per *possible* CPU (not per online CPU), so the
/// CPU count is never assumed here. Counters wrap like the kernel's and a short
/// trailing chunk (never produced for a `__u64` value) is ignored.
#[must_use]
pub fn sum_percpu_u64(slots: &[Vec<u8>]) -> u64 {
	slots
		.iter()
		.flat_map(|slot| slot.chunks_exact(8))
		.filter_map(|chunk| <[u8; 8]>::try_from(chunk).ok())
		.fold(0u64, |acc, raw| acc.wrapping_add(u64::from_le_bytes(raw)))
}

/// XDP program counters; the indices follow `STAT_*` from `xdp/core/maps.h`.
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStats {
	pub total: u64,
	pub tcp: u64,
	pub whitelist: u64,
	pub blacklist: u64,
	pub syn_throttle: u64,
	pub passed: u64,
	pub dropped: u64,
	pub udp: u64,
	pub rate_limit: u64,
	pub challenge_sent: u64,
	pub challenge_verified: u64,
	pub challenge_failed: u64,
	pub fragment_bypass: u64,
}

#[cfg(feature = "xdp")]
impl XdpFilter {
	/// Reads `stats_map` and sums the per-CPU values.
	///
	/// # Errors
	/// XDP is not loaded, or the map is missing from the object (individual
	/// lookup failures are reported as zero rather than aborting the report).
	pub fn get_stats(&self) -> Result<XdpStats> {
		let map = self.find_map("stats_map")?;
		let sum = |idx: u32| -> u64 {
			let key = idx.to_le_bytes();
			// `stats_map` is a percpu_array: plain `lookup` does not support it and
			// the failure would silently read as zero, so sum the per-CPU slots.
			match map.lookup_percpu(&key, MapFlags::ANY) {
				Ok(Some(slots)) => sum_percpu_u64(&slots),
				_ => 0,
			}
		};
		Ok(XdpStats {
			total: sum(STAT_TOTAL),
			tcp: sum(STAT_TCP),
			whitelist: sum(STAT_WHITELIST),
			blacklist: sum(STAT_BLACKLIST),
			syn_throttle: sum(STAT_SYN_THROTTLE),
			passed: sum(STAT_PASS),
			dropped: sum(STAT_DROP),
			udp: sum(STAT_UDP),
			rate_limit: sum(STAT_RATE_LIMIT),
			challenge_sent: sum(STAT_CHALLENGE_SENT),
			challenge_verified: sum(STAT_CHALLENGE_VERIFIED),
			challenge_failed: sum(STAT_CHALLENGE_FAILED),
			fragment_bypass: sum(STAT_FRAGMENT_BYPASS),
		})
	}

	/// Reads and resets the `prefix_stats` map (aggregates per /24 and /64).
	///
	/// The counters are per-window by contract: the detector compares them
	/// against fixed thresholds, so leaving them cumulative would eventually
	/// flag every prefix. Packets that arrive between the read and the reset
	/// are lost, which is acceptable for statistics.
	///
	/// # Errors
	/// XDP is not loaded, the map is missing from the object, or a BPF read fails.
	pub fn read_prefix_stats(&self) -> Result<Vec<(PrefixKey, PrefixStatsVal)>> {
		let map = self.find_map("prefix_stats")?;
		let mut out = Vec::new();
		for key in map.keys() {
			let Ok(kb) = <[u8; 24]>::try_from(key.as_slice()) else {
				continue;
			};
			let Some(val) = map.lookup(&kb, MapFlags::ANY).context("prefix_stats lookup failed")? else {
				continue;
			};
			let Ok(vb) = <[u8; 32]>::try_from(val.as_slice()) else {
				continue;
			};
			out.push((PrefixKey::from_bytes(kb), PrefixStatsVal::from_bytes(vb)));
			if let Err(e) = map.update(&kb, &[0u8; 32], MapFlags::ANY) {
				tracing::debug!(prefix = ?PrefixKey::from_bytes(kb), error = %e, "prefix_stats reset failed");
			}
		}
		Ok(out)
	}
}
