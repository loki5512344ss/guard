//! Subnet-level (prefix) distributed attack detector.
//!
//! Data arrives through the [`PrefixStatsSource`] trait: either the XDP
//! `prefix_stats` map (feature `xdp`) or the user-space aggregator in
//! [`crate::engine::subnet_tracker`]. [`PrefixKey`] and [`PrefixStatsVal`] must
//! match the kernel structs byte for byte, hence the `repr(C)` layout.

mod key;
mod stats;

pub use key::{PREFIX_FAMILY_V4, PREFIX_FAMILY_V6, PrefixKey, prefix_of};
#[cfg(feature = "xdp")]
pub use stats::XdpPrefixStats;
pub use stats::{PrefixSnapshot, PrefixStatsSource, PrefixStatsVal, PrefixVerdict, SubnetDetector, SubnetVerdict};
