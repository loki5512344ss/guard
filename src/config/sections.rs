//! Секции единого конфига платформы.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BindConfig {
    #[serde(default = "default_bind_address")]
    pub address: String,
    #[serde(default = "default_bind_port")]
    pub port: u16,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self {
            address: default_bind_address(),
            port: default_bind_port(),
        }
    }
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}
fn default_bind_port() -> u16 {
    25565
}

/// Generic upstream-бэкенды (список addr:port) за edge-нодой.
#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<String>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            upstreams: default_upstreams(),
        }
    }
}

fn default_upstreams() -> Vec<String> {
    vec!["127.0.0.1:25566".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    #[serde(default = "default_worker_count")]
    pub count: usize,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self { count: 4 }
    }
}

fn default_worker_count() -> usize {
    4
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_rate_limit_pps")]
    pub rate_limit_pps: f64,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: f64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            handshake_timeout_secs: default_handshake_timeout(),
            max_connections_per_ip: default_max_connections_per_ip(),
            rate_limit_pps: default_rate_limit_pps(),
            rate_limit_burst: default_rate_limit_burst(),
        }
    }
}

fn default_handshake_timeout() -> u64 {
    5
}
fn default_max_connections_per_ip() -> u32 {
    10
}
fn default_rate_limit_pps() -> f64 {
    5.0
}
fn default_rate_limit_burst() -> f64 {
    10.0
}

#[derive(Debug, Clone, Deserialize)]
pub struct BanConfig {
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            ban_duration_secs: default_ban_duration(),
        }
    }
}

fn default_ban_duration() -> u64 {
    3600
}

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
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: default_xdp_interface(),
        }
    }
}

fn default_xdp_interface() -> String {
    "eth0".to_string()
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

#[derive(Debug, Clone, Deserialize)]
pub struct PowConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pow_difficulty")]
    pub difficulty: u8,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            difficulty: default_pow_difficulty(),
        }
    }
}

fn default_pow_difficulty() -> u8 {
    4
}

/// Секция `[detect]`: детекторы распределённых атак.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectConfig {
    #[serde(default)]
    pub prefix: DetectPrefixConfig,
}

/// Секция `[detect.prefix]`: subnet-level детектор распределённых атак.
#[derive(Debug, Clone, Deserialize)]
pub struct DetectPrefixConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_prefix_syn_threshold")]
    pub syn_threshold: u64,
    #[serde(default = "default_prefix_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_prefix_min_unique_sources")]
    pub min_unique_sources: u64,
}

impl Default for DetectPrefixConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            syn_threshold: default_prefix_syn_threshold(),
            window_secs: default_prefix_window_secs(),
            min_unique_sources: default_prefix_min_unique_sources(),
        }
    }
}

fn default_prefix_syn_threshold() -> u64 {
    500
}
fn default_prefix_window_secs() -> u64 {
    10
}
fn default_prefix_min_unique_sources() -> u64 {
    16
}
