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
