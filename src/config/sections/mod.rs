//! Секции единого конфига платформы.

mod detect;
mod edge;
mod platform;

pub use detect::{DetectAlertConfig, DetectAutobanConfig, DetectConfig, DetectPrefixConfig};
#[cfg(feature = "protocol-http")]
pub use detect::{HttpProtocolConfig, ProtocolConfig};
pub use edge::{BackendConfig, BanConfig, BindConfig, LimitsConfig, PowConfig, WorkerConfig};
pub use platform::{LoggingConfig, MetricsConfig, StoreConfig, XdpConfig};
