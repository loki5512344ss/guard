use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
    pub redis_url: Option<String>,
    #[serde(default = "default_blacklist_cache_ttl")]
    pub blacklist_cache_ttl_secs: u64,
    pub clickhouse_url: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            redis_url: None,
            blacklist_cache_ttl_secs: default_blacklist_cache_ttl(),
            clickhouse_url: None,
        }
    }
}

fn default_blacklist_cache_ttl() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize)]
pub struct XdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_xdp_interface")]
    pub interface: String,
    #[serde(default = "default_xdp_port_start")]
    pub protected_port_start: u16,
    #[serde(default = "default_xdp_port_end")]
    pub protected_port_end: u16,
    /// "pass" | "drop" | "rate-limit" → G_UDP_POLICY.
    #[serde(default = "default_xdp_udp_policy")]
    pub udp_policy: String,
    #[serde(default = "default_xdp_udp_hit_count")]
    pub udp_rate_hit_count: u32,
    #[serde(default = "default_xdp_udp_window_ms")]
    pub udp_rate_window_ms: u64,
    #[serde(default)]
    pub syn_challenge_enabled: bool,
    /// 128-битный hex (16 символов) для G_CHALLENGE_SECRET; None = плейсхолдер из config.h.
    #[serde(default)]
    pub challenge_secret_hex: Option<String>,
    #[serde(default = "default_xdp_challenge_timeout_ms")]
    pub challenge_timeout_ms: u32,
    #[serde(default = "default_xdp_throttle_enabled")]
    pub throttle_enabled: bool,
    #[serde(default = "default_xdp_events_enabled")]
    pub events_enabled: bool,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: default_xdp_interface(),
            protected_port_start: default_xdp_port_start(),
            protected_port_end: default_xdp_port_end(),
            udp_policy: default_xdp_udp_policy(),
            udp_rate_hit_count: default_xdp_udp_hit_count(),
            udp_rate_window_ms: default_xdp_udp_window_ms(),
            syn_challenge_enabled: false,
            challenge_secret_hex: None,
            challenge_timeout_ms: default_xdp_challenge_timeout_ms(),
            throttle_enabled: default_xdp_throttle_enabled(),
            events_enabled: default_xdp_events_enabled(),
        }
    }
}

fn default_xdp_interface() -> String {
    "eth0".to_string()
}
fn default_xdp_port_start() -> u16 {
    1
}
fn default_xdp_port_end() -> u16 {
    65535
}
fn default_xdp_udp_policy() -> String {
    "pass".to_string()
}
fn default_xdp_udp_hit_count() -> u32 {
    100
}
fn default_xdp_udp_window_ms() -> u64 {
    1000
}
fn default_xdp_challenge_timeout_ms() -> u32 {
    3000
}
fn default_xdp_throttle_enabled() -> bool {
    true
}
fn default_xdp_events_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_metrics_enabled(),
            port: default_metrics_port(),
        }
    }
}

fn default_metrics_enabled() -> bool {
    true
}
fn default_metrics_port() -> u16 {
    9090
}
