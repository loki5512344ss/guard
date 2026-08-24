use rampart::config::Config;

#[test]
fn parses_minimal_config_with_defaults() {
    let config = Config::parse_str("").expect("empty config must parse with defaults");
    assert_eq!(config.bind.address, "0.0.0.0");
    assert_eq!(config.bind.port, 25565);
    assert_eq!(config.backend.upstreams, vec!["127.0.0.1:25566"]);
    assert_eq!(config.workers.count, 4);
    assert!(!config.pow.enabled);
}

#[test]
fn parses_full_config() {
    let config = Config::parse_str(
        r#"
[bind]
port = 8443

[backend]
upstreams = ["10.0.0.1:9000", "10.0.0.2:9000"]

[limits]
rate_limit_pps = 50.0

[pow]
enabled = true
difficulty = 5

[store]
redis_url = "redis://localhost:6379/1"
clickhouse_url = "http://localhost:8123"

whitelist = ["203.0.113.7"]
"#,
    )
    .expect("full config must parse");

    assert_eq!(config.bind.port, 8443);
    assert_eq!(config.backend.upstreams.len(), 2);
    assert!((config.limits.rate_limit_pps - 50.0).abs() < f64::EPSILON);
    assert!(config.pow.enabled);
    assert_eq!(config.pow.difficulty, 5);
    assert_eq!(config.store.redis_url.as_deref(), Some("redis://localhost:6379/1"));
}

#[test]
fn rejects_empty_upstreams() {
    let err = Config::parse_str("[backend]\nupstreams = []\n").expect_err("must reject empty upstream list");
    assert!(err.to_string().contains("upstreams"));
}

#[test]
fn rejects_malformed_upstream_address() {
    let result = Config::parse_str("[backend]\nupstreams = [\"example.invalid\"]\n");
    assert!(result.is_err(), "hostname-only upstreams are not supported");
}

#[test]
fn rejects_invalid_whitelist_ip() {
    let result = Config::parse_str("whitelist = [\"10.0.0.999\"]");
    assert!(result.is_err());
}

#[test]
fn detect_autoban_defaults_disabled() {
    let config = Config::parse_str("").expect("empty config must parse");
    assert!(!config.detect.autoban.enabled);
    assert_eq!(config.detect.autoban.reputation_threshold, -50);
}

#[test]
fn parses_detect_sections() {
    let config = Config::parse_str(
        r#"
[detect.autoban]
enabled = true
reputation_threshold = -30

[detect.alert]
webhook_url = "https://hooks.example.test/rampart"
"#,
    )
    .expect("detect sections must parse");
    assert!(config.detect.autoban.enabled);
    assert_eq!(config.detect.autoban.reputation_threshold, -30);
    assert_eq!(
        config.detect.alert.webhook_url.as_deref(),
        Some("https://hooks.example.test/rampart")
    );
}
