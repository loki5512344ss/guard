use serde::Deserialize;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub bind: BindConfig,
    #[serde(default)]
    pub backend: BackendConfig,
    #[serde(default)]
    pub hmac: HmacConfig,
    #[serde(default)]
    pub workers: WorkerConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub xdp: XdpConfig,
    #[serde(default)]
    pub death_code: DeathCodeConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BindConfig {
    #[serde(default = "default_bind_address")]
    pub address: String,
    #[serde(default = "default_bind_port")]
    pub port: u16,
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}
fn default_bind_port() -> u16 {
    25565
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BackendConfig {
    #[serde(default = "default_backend_address")]
    pub address: String,
    #[serde(default = "default_backend_port")]
    pub port: u16,
}

fn default_backend_address() -> String {
    "127.0.0.1".to_string()
}
fn default_backend_port() -> u16 {
    25566
}

#[derive(Debug, Clone, Deserialize)]
pub struct HmacConfig {
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_key_rotation")]
    pub key_rotation_interval_secs: u64,
}

fn default_key_rotation() -> u64 {
    3600
}

impl Default for HmacConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            key_rotation_interval_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    #[serde(default = "default_worker_count")]
    pub count: usize,
}

fn default_worker_count() -> usize {
    4
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self { count: 4 }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_rate_limit_login")]
    pub rate_limit_login_pps: f64,
    #[serde(default = "default_rate_limit_status")]
    pub rate_limit_status_pps: f64,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: f64,
}

fn default_handshake_timeout() -> u64 {
    5
}
fn default_max_connections_per_ip() -> u32 {
    10
}
fn default_rate_limit_login() -> f64 {
    5.0
}
fn default_rate_limit_status() -> f64 {
    2.0
}
fn default_rate_limit_burst() -> f64 {
    10.0
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            handshake_timeout_secs: 5,
            max_connections_per_ip: 10,
            rate_limit_login_pps: 5.0,
            rate_limit_status_pps: 2.0,
            rate_limit_burst: 10.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
    pub redis_url: Option<String>,
    #[serde(default = "default_blacklist_cache_ttl")]
    pub blacklist_cache_ttl_secs: u64,
}

fn default_blacklist_cache_ttl() -> u64 {
    300
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            redis_url: None,
            blacklist_cache_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct XdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_xdp_interface")]
    pub interface: String,
}

fn default_xdp_interface() -> String {
    "eth0".to_string()
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: "eth0".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

fn default_metrics_enabled() -> bool {
    true
}
fn default_metrics_port() -> u16 {
    9090
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeathCodeConfig {
    #[serde(default = "default_death_code_enabled")]
    pub enabled: bool,
    #[serde(default = "default_death_code_ban_duration")]
    pub ban_duration_secs: u64,
}

fn default_death_code_enabled() -> bool {
    true
}
fn default_death_code_ban_duration() -> u64 {
    3600
}

impl Default for DeathCodeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration_secs: 3600,
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
