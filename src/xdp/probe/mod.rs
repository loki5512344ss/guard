//! XDP environment probing: diagnostics, statistics, metrics and the shared clock.

mod diagnostics;
#[cfg(feature = "xdp")]
pub(crate) use diagnostics::preflight;
pub use diagnostics::{
	AttachMode, EnvironmentReport, FilesystemProbe, KernelVersion, MIN_KERNEL, SystemProbe, driver_supports_native_xdp,
};

#[cfg(feature = "xdp")]
mod clock;
#[cfg(feature = "xdp")]
pub use clock::{blacklist_expiry_ns, monotonic_ns};

mod stats;
pub use stats::{
	STAT_BLACKLIST, STAT_CHALLENGE_FAILED, STAT_CHALLENGE_SENT, STAT_CHALLENGE_VERIFIED, STAT_DROP,
	STAT_FRAGMENT_BYPASS, STAT_PASS, STAT_RATE_LIMIT, STAT_SYN_THROTTLE, STAT_TCP, STAT_TOTAL, STAT_UDP,
	STAT_WHITELIST, XdpStats,
};

#[cfg(feature = "xdp")]
mod metrics;
#[cfg(feature = "xdp")]
pub use metrics::XdpMetrics;
