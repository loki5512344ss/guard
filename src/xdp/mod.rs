//! Загрузчик XDP-программы (L3/L4-уровень защиты).

mod probe;
pub use probe::{
    AttachMode, EnvironmentReport, FilesystemProbe, KernelVersion, MIN_KERNEL, SystemProbe, XdpStats,
    driver_supports_native_xdp,
};

#[cfg(feature = "xdp")]
mod globals;
#[cfg(feature = "xdp")]
pub use globals::XdpGlobals;

#[cfg(feature = "xdp")]
mod filter;
#[cfg(feature = "xdp")]
pub use filter::XdpFilter;

#[cfg(feature = "xdp")]
pub use probe::XdpMetrics;

#[cfg(not(feature = "xdp"))]
mod noop;
#[cfg(not(feature = "xdp"))]
pub use noop::XdpFilter;
