//! Единый конфиг платформы Rampart.
mod sections;

pub use sections::{
    BackendConfig, BanConfig, BindConfig, DetectAlertConfig, DetectAutobanConfig, DetectConfig, DetectPrefixConfig,
    LimitsConfig, LoggingConfig, MetricsConfig, PowConfig, StoreConfig, WorkerConfig, XdpConfig,
};

use serde::Deserialize;
use std::fs;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub bind: BindConfig,
    #[serde(default)]
    pub backend: BackendConfig,
    #[serde(default)]
    pub workers: WorkerConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub ban: BanConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub xdp: XdpConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub pow: PowConfig,
    #[serde(default)]
    pub detect: DetectConfig,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

impl Config {
    /// Парсит конфиг из TOML-строки и валидирует семантику.
    ///
    /// # Errors
    /// Возвращает ошибку при невалидном TOML или нарушении инвариантов
    /// (пустой список upstream-бэкендов, некорректные адреса).
    pub fn parse_str(contents: &str) -> anyhow::Result<Self> {
        let config: Config = toml::from_str(contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Читает и парсит конфиг из файла.
    ///
    /// # Errors
    /// Возвращает ошибку при невозможности прочитать файл или невалидном содержимом.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::parse_str(&contents)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.backend.upstreams.is_empty() {
            anyhow::bail!("backend.upstreams must not be empty");
        }
        for upstream in &self.backend.upstreams {
            if upstream.parse::<std::net::SocketAddr>().is_err() {
                anyhow::bail!("invalid upstream address: {upstream}");
            }
        }
        for entry in &self.whitelist {
            if entry.parse::<std::net::IpAddr>().is_err() {
                anyhow::bail!("invalid whitelist entry: {entry}");
            }
        }
        if self.detect.prefix.enabled && self.detect.prefix.syn_threshold == 0 {
            anyhow::bail!("detect.prefix.syn_threshold must be positive when enabled");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let config = Config::parse_str("").expect("empty config should parse");
        assert_eq!(config.bind.address, "0.0.0.0");
        assert_eq!(config.bind.port, 25565);
        assert_eq!(config.backend.upstreams, vec!["127.0.0.1:25566"]);
        assert!(!config.pow.enabled);
        assert!(!config.xdp.enabled);
    }

    #[test]
    fn full_config_parses() {
        let config = Config::parse_str(
            r#"
[bind]
address = "10.0.0.1"
port = 443

[backend]
upstreams = ["192.168.1.10:8080", "192.168.1.11:8080"]

[pow]
enabled = true
difficulty = 6

whitelist = ["203.0.113.7"]
"#,
        )
        .expect("config should parse");
        assert_eq!(config.bind.port, 443);
        assert_eq!(config.backend.upstreams.len(), 2);
        assert!(config.pow.enabled);
        assert_eq!(config.pow.difficulty, 6);
    }

    #[test]
    fn empty_upstreams_rejected() {
        let result = Config::parse_str(
            r#"
[backend]
upstreams = []
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn invalid_upstream_rejected() {
        let result = Config::parse_str(
            r#"
[backend]
upstreams = ["not-an-addr"]
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn invalid_whitelist_entry_rejected() {
        let result = Config::parse_str("whitelist = [\"999.999.1.1\"]");
        assert!(result.is_err());
    }

    #[test]
    fn prefix_detect_defaults_disabled() {
        let config = Config::parse_str("").expect("empty config should parse");
        assert!(!config.detect.prefix.enabled);
        assert_eq!(config.detect.prefix.syn_threshold, 500);
        assert_eq!(config.detect.prefix.window_secs, 10);
        assert_eq!(config.detect.prefix.min_unique_sources, 16);
    }

    #[test]
    fn prefix_detect_section_parses() {
        let config = Config::parse_str(
            r#"
[detect.prefix]
enabled = true
syn_threshold = 1000
window_secs = 5
min_unique_sources = 8
"#,
        )
        .expect("detect.prefix section should parse");
        assert!(config.detect.prefix.enabled);
        assert_eq!(config.detect.prefix.syn_threshold, 1000);
        assert_eq!(config.detect.prefix.window_secs, 5);
        assert_eq!(config.detect.prefix.min_unique_sources, 8);
    }

    #[test]
    fn prefix_detect_zero_threshold_rejected_when_enabled() {
        let result = Config::parse_str(
            r#"
[detect.prefix]
enabled = true
syn_threshold = 0
"#,
        );
        assert!(result.is_err());
    }
}
