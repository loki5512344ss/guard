//! Загрузчик XDP-программы (L3/L4-уровень защиты).
mod stats;
pub use stats::XdpStats;

mod diagnostics;
pub use diagnostics::{
    AttachMode, EnvironmentReport, FilesystemProbe, KernelVersion, MIN_KERNEL, SystemProbe, driver_supports_native_xdp,
};

#[cfg(feature = "xdp")]
mod filter;
#[cfg(feature = "xdp")]
pub use filter::XdpFilter;

#[cfg(feature = "xdp")]
mod metrics;
#[cfg(feature = "xdp")]
pub use metrics::XdpMetrics;

#[cfg(not(feature = "xdp"))]
mod noop;
#[cfg(not(feature = "xdp"))]
pub use noop::XdpFilter;
