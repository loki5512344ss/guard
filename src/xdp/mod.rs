//! Loader for the XDP program (L3/L4 protection layer).
//!
//! Owns the filter lifecycle (`XdpFilter`), the `.rodata` globals image (`XdpGlobals`),
//! ringbuf event parsing, XDP metrics and the pre-attach environment probe. Without the
//! `xdp` feature a no-op filter is exported instead.

mod probe;
pub use probe::{
	AttachMode, EnvironmentReport, FilesystemProbe, KernelVersion, MIN_KERNEL, SystemProbe, XdpStats,
	driver_supports_native_xdp,
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
pub use filter::XdpFilter;
#[cfg(feature = "xdp")]
pub use filter::blacklist6_key;
#[cfg(feature = "xdp")]
pub use filter::events::{
	AutoBanConfig, BanAction, XDP_EVENT_LEN, XdpEvent, XdpEventKind, auto_ban_decision, parse_xdp_event,
};
#[cfg(feature = "xdp")]
pub use filter::monotonic_ns;

#[cfg(feature = "xdp")]
pub use probe::XdpMetrics;

#[cfg(not(feature = "xdp"))]
mod noop;
#[cfg(not(feature = "xdp"))]
pub use noop::XdpFilter;
