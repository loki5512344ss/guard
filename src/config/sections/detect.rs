use serde::Deserialize;

/// Секция `[detect]`: детекторы распределённых атак.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectConfig {
    #[serde(default)]
    pub prefix: DetectPrefixConfig,
    #[serde(default)]
    pub autoban: DetectAutobanConfig,
    #[serde(default)]
    pub alert: DetectAlertConfig,
}

/// Секция `[detect.autoban]`: авто-бан источников по репутации и сигналам
/// детектора атак. Порог сравнивается со скором [`crate::traffic::reputation::IpReputation`],
/// TTL берётся из `ban.ban_duration_secs`.
#[derive(Debug, Clone, Deserialize)]
pub struct DetectAutobanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_autoban_reputation_threshold")]
    pub reputation_threshold: i32,
}

impl Default for DetectAutobanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            reputation_threshold: default_autoban_reputation_threshold(),
        }
    }
}

fn default_autoban_reputation_threshold() -> i32 {
    -50
}

/// Секция `[detect.alert]`: webhook-алерты на переходах состояния атаки
/// («атака началась» / «атака закончилась»).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectAlertConfig {
    #[serde(default)]
    pub webhook_url: Option<String>,
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

/// Секция `[protocol]`: протокольные обработчики (plugin-by-feature).
#[cfg(feature = "protocol-http")]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProtocolConfig {
    #[serde(default)]
    pub http: HttpProtocolConfig,
}

/// Секция `[protocol.http]`: политика HTTP/1.1-обработчика на edge-ноде.
#[cfg(feature = "protocol-http")]
#[derive(Debug, Clone, Deserialize)]
pub struct HttpProtocolConfig {
    #[serde(default = "default_http_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_http_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub blocked_paths: Vec<String>,
    #[serde(default)]
    pub require_user_agent: bool,
}

#[cfg(feature = "protocol-http")]
impl Default for HttpProtocolConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: default_http_max_header_bytes(),
            timeout_secs: default_http_timeout_secs(),
            blocked_paths: Vec::new(),
            require_user_agent: false,
        }
    }
}

#[cfg(feature = "protocol-http")]
fn default_http_max_header_bytes() -> usize {
    8192
}
#[cfg(feature = "protocol-http")]
fn default_http_timeout_secs() -> u64 {
    5
}
