//! Config parsing tests: defaults, section parsing and rejected invariants.

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

#[test]
fn xdp_section_defaults() {
	let config = Config::parse_str("").expect("empty config must parse");
	let xdp = &config.xdp;
	assert_eq!(xdp.protected_port_start, 1);
	assert_eq!(xdp.protected_port_end, 65535);
	assert_eq!(xdp.udp_policy, "pass");
	assert_eq!(xdp.udp_rate_hit_count, 100);
	assert_eq!(xdp.udp_rate_window_ms, 1000);
	assert!(!xdp.syn_challenge_enabled);
	assert!(xdp.challenge_secret_hex.is_none());
	assert_eq!(xdp.challenge_timeout_ms, 3000);
	assert!(xdp.throttle_enabled);
	assert!(xdp.events_enabled);
}

#[test]
fn parses_xdp_section() {
	let config = Config::parse_str(
		r#"
[xdp]
enabled = true
interface = "ens3"
protected_port_start = 25560
protected_port_end = 25600
udp_policy = "drop"
udp_rate_hit_count = 250
udp_rate_window_ms = 500
syn_challenge_enabled = true
challenge_secret_hex = "dead_beef_dead_beef"
challenge_timeout_ms = 1500
throttle_enabled = false
events_enabled = false
"#,
	)
	.expect("[xdp] section must parse");
	let xdp = &config.xdp;
	assert!(xdp.enabled);
	assert_eq!(xdp.interface, "ens3");
	assert_eq!(xdp.protected_port_start, 25560);
	assert_eq!(xdp.protected_port_end, 25600);
	assert_eq!(xdp.udp_policy, "drop");
	assert_eq!(xdp.udp_rate_hit_count, 250);
	assert_eq!(xdp.udp_rate_window_ms, 500);
	assert!(xdp.syn_challenge_enabled);
	assert_eq!(xdp.challenge_secret_hex.as_deref(), Some("dead_beef_dead_beef"));
	assert_eq!(xdp.challenge_timeout_ms, 1500);
	assert!(!xdp.throttle_enabled);
	assert!(!xdp.events_enabled);
}

#[test]
fn prefix_detect_defaults_disabled() {
	let config = Config::parse_str("").expect("empty config must parse");
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
	.expect("detect.prefix section must parse");
	assert!(config.detect.prefix.enabled);
	assert_eq!(config.detect.prefix.syn_threshold, 1000);
	assert_eq!(config.detect.prefix.window_secs, 5);
	assert_eq!(config.detect.prefix.min_unique_sources, 8);
}

#[test]
fn prefix_detect_zero_threshold_rejected_when_enabled() {
	let err = Config::parse_str("[detect.prefix]\nenabled = true\nsyn_threshold = 0\n")
		.expect_err("zero threshold must be rejected");
	assert!(err.to_string().contains("detect.prefix.syn_threshold"));
}

#[test]
fn syn_challenge_requires_a_secret() {
	let err = Config::parse_str("[xdp]\nsyn_challenge_enabled = true\n")
		.expect_err("missing challenge secret must be rejected");
	let message = err.to_string();
	assert!(message.contains("challenge_secret_hex"));
	assert!(message.contains("openssl rand -hex 8"));
}

#[test]
fn syn_challenge_rejects_every_placeholder_spelling() {
	for secret in [
		"a5a5a5a5a5a5a5a5",
		"A5A5A5A5A5A5A5A5",
		"0xA5A5A5A5A5A5A5A5",
		"a5a5-5a5a-5a5a-a5a5",
		"a5a55a5a5a5aa5a5",
		"A5A5_5A5A_5A5A_A5A5",
		"0xa5a55a5a5a5aa5a5",
	] {
		let toml = format!("[xdp]\nsyn_challenge_enabled = true\nchallenge_secret_hex = \"{secret}\"\n");
		let err = Config::parse_str(&toml).expect_err("placeholder secret must be rejected");
		assert!(
			err.to_string().contains("placeholder"),
			"secret '{secret}' must be rejected"
		);
	}
}

#[test]
fn syn_challenge_accepts_a_generated_secret() {
	let config =
		Config::parse_str("[xdp]\nsyn_challenge_enabled = true\nchallenge_secret_hex = \"9f3c71a0b2d84e65\"\n")
			.expect("random challenge secret must be accepted");
	assert_eq!(config.xdp.challenge_secret_hex.as_deref(), Some("9f3c71a0b2d84e65"));
}

#[test]
fn rejects_non_positive_rate_limit() {
	for pps in ["0.0", "-1.0", "nan", "inf"] {
		let toml = format!("[limits]\nrate_limit_pps = {pps}\n");
		let err = Config::parse_str(&toml).expect_err("rate_limit_pps must be positive and finite");
		assert!(
			err.to_string().contains("limits.rate_limit_pps"),
			"pps '{pps}' must be rejected"
		);
	}
}

#[test]
fn rejects_rate_limit_burst_below_one() {
	for burst in ["0.0", "0.5", "nan"] {
		let toml = format!("[limits]\nrate_limit_burst = {burst}\n");
		let err = Config::parse_str(&toml).expect_err("rate_limit_burst must be at least 1");
		assert!(
			err.to_string().contains("limits.rate_limit_burst"),
			"burst '{burst}' must be rejected"
		);
	}
}

#[test]
fn relay_idle_timeout_defaults_to_300_and_accepts_the_full_range() {
	let config = Config::parse_str("").expect("empty config must parse");
	assert_eq!(config.limits.relay_idle_timeout_secs, 300);

	for secs in [1u64, 60, 300, 86_400] {
		let toml = format!("[limits]\nrelay_idle_timeout_secs = {secs}\n");
		let config = Config::parse_str(&toml).expect("in-range idle timeout must parse");
		assert_eq!(config.limits.relay_idle_timeout_secs, secs);
	}
}

#[test]
fn rejects_out_of_range_relay_idle_timeout() {
	for secs in [0u64, 86_401] {
		let toml = format!("[limits]\nrelay_idle_timeout_secs = {secs}\n");
		let err = Config::parse_str(&toml).expect_err("idle timeout outside 1..=86400 must be rejected");
		assert!(
			err.to_string().contains("limits.relay_idle_timeout_secs"),
			"idle timeout '{secs}' must be rejected"
		);
	}
}

#[test]
fn rejects_out_of_range_ban_duration() {
	let err = Config::parse_str("[ban]\nban_duration_secs = 0\n").expect_err("zero ban duration must be rejected");
	assert!(err.to_string().contains("ban.ban_duration_secs"));
	let err = Config::parse_str("[ban]\nban_duration_secs = 31536001\n")
		.expect_err("ban duration above one year must be rejected");
	assert!(err.to_string().contains("ban.ban_duration_secs"));
	assert!(Config::parse_str("[ban]\nban_duration_secs = 31536000\n").is_ok());
}

#[test]
fn rejects_out_of_range_pow_difficulty() {
	for difficulty in ["0", "11"] {
		let toml = format!("[pow]\nenabled = true\ndifficulty = {difficulty}\n");
		let err = Config::parse_str(&toml).expect_err("pow.difficulty must stay in 1..=10");
		assert!(
			err.to_string().contains("pow.difficulty"),
			"difficulty '{difficulty}' must be rejected"
		);
	}
	assert!(Config::parse_str("[pow]\ndifficulty = 10\n").is_ok());
}

#[test]
fn rejects_zero_workers() {
	let err = Config::parse_str("[workers]\ncount = 0\n").expect_err("zero workers must be rejected");
	assert!(err.to_string().contains("workers.count"));
}
