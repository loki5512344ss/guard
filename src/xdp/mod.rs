//! Loader for the XDP program (L3/L4 protection layer).
//!
//! Owns the filter lifecycle (`XdpFilter`), the `.rodata` globals image (`XdpGlobals`),
//! ringbuf event parsing, XDP metrics and the pre-attach environment probe. Without the
//! `xdp` feature a no-op filter is exported instead.

mod probe;
pub use probe::{
	AttachMode, EnvironmentReport, FilesystemProbe, KernelVersion, MIN_KERNEL, STAT_BLACKLIST, STAT_CHALLENGE_FAILED,
	STAT_CHALLENGE_SENT, STAT_CHALLENGE_VERIFIED, STAT_DROP, STAT_FRAGMENT_BYPASS, STAT_PASS, STAT_RATE_LIMIT,
	STAT_SYN_THROTTLE, STAT_TCP, STAT_TOTAL, STAT_UDP, STAT_WHITELIST, SystemProbe, XdpStats,
	driver_supports_native_xdp, sum_percpu_u64,
};

#[cfg(feature = "xdp")]
mod globals;
#[cfg(feature = "xdp")]
pub use globals::{RODATA_SIZE, XdpGlobals};

#[cfg(feature = "xdp")]
mod metrics;

#[cfg(feature = "xdp")]
mod filter;
#[cfg(feature = "xdp")]
pub use filter::events::{
	AutoBanConfig, BanAction, XDP_EVENT_LEN, XdpEvent, XdpEventKind, auto_ban_decision, parse_xdp_event,
};
#[cfg(feature = "xdp")]
pub use filter::{
	XdpFilter, blacklist_key, blacklist6_key, canonical_cidr, interface_cstr, is_rodata_map, normalize_cidr,
	whitelist_key, whitelist6_key, xdp_attach_mode_name,
};

#[cfg(feature = "xdp")]
pub use probe::{XdpMetrics, blacklist_expiry_ns, monotonic_ns};

#[cfg(not(feature = "xdp"))]
mod noop;
#[cfg(not(feature = "xdp"))]
pub use noop::XdpFilter;
