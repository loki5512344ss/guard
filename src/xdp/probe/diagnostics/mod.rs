//! Диагностика окружения перед XDP-attach: ядро, BTF, драйвер NIC, привилегии.
//!
//! Основной источник боли при XDP — непонятные ошибки attach на неподдерживаемых
//! ядрах и драйверах. Модуль собирает [`EnvironmentReport`] ДО загрузки BPF-программы
//! и даёт человекочитаемый вердикт с предупреждениями.

mod report;
mod types;

pub use report::EnvironmentReport;
#[cfg(feature = "xdp")]
pub(crate) use report::preflight;
pub use types::{AttachMode, FilesystemProbe, KernelVersion, MIN_KERNEL, SystemProbe, driver_supports_native_xdp};
