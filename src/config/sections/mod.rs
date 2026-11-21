//! Sections of the platform config.

mod detect;
mod edge;
#[cfg(feature = "protocol-minecraft")]
mod minecraft;
mod platform;

#[cfg(feature = "protocol-http")]
pub use detect::HttpProtocolConfig;
#[cfg(any(feature = "protocol-http", feature = "protocol-minecraft"))]
pub use detect::ProtocolConfig;
pub use detect::{DetectAlertConfig, DetectAutobanConfig, DetectConfig, DetectPrefixConfig};
pub use edge::{BackendConfig, BanConfig, BindConfig, LimitsConfig, PowConfig, ProxyProtocolConfig, WorkerConfig};
#[cfg(feature = "protocol-minecraft")]
pub use minecraft::{MinecraftProtocolConfig, UsernameCharset};
pub use platform::{LoggingConfig, MetricsConfig, StoreConfig, XdpConfig};
