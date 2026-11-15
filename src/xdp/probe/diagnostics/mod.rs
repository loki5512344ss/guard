//! Environment diagnostics before XDP attach: kernel, BTF, NIC driver, privileges.
//!
//! The main source of pain with XDP is opaque attach failures on unsupported kernels and
//! drivers. This module collects an [`EnvironmentReport`] before the BPF program is
//! loaded and produces a human-readable verdict with warnings.

mod report;
mod types;

pub use report::EnvironmentReport;
#[cfg(feature = "xdp")]
pub(crate) use report::preflight;
pub use types::{AttachMode, FilesystemProbe, KernelVersion, MIN_KERNEL, SystemProbe, driver_supports_native_xdp};
