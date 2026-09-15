//! Зондирование XDP-окружения: диагностика, статистика и метрики.

mod diagnostics;
#[cfg(feature = "xdp")]
pub(crate) use diagnostics::preflight;
pub use diagnostics::{
    AttachMode, EnvironmentReport, FilesystemProbe, KernelVersion, MIN_KERNEL, SystemProbe, driver_supports_native_xdp,
};

mod stats;
pub use stats::XdpStats;

#[cfg(feature = "xdp")]
mod metrics;
#[cfg(feature = "xdp")]
pub use metrics::XdpMetrics;
