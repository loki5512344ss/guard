//! Секции единого конфига платформы.

mod detect;
mod edge;
mod platform;

#[cfg(feature = "protocol-http")]
pub use detect::HttpProtocolConfig;
#[cfg(feature = "protocol-minecraft")]
pub use detect::MinecraftProtocolConfig;
#[cfg(any(feature = "protocol-http", feature = "protocol-minecraft"))]
pub use detect::ProtocolConfig;
pub use detect::{DetectAlertConfig, DetectAutobanConfig, DetectConfig, DetectPrefixConfig};
pub use edge::{
    BackendConfig, BanConfig, BindConfig, LimitsConfig, PowConfig, ProxyProtocolConfig, TrustedProxyCidr, WorkerConfig,
};
pub use platform::{LoggingConfig, MetricsConfig, StoreConfig, XdpConfig};
