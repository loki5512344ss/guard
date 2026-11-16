//! Edge sections: bind, backend, workers, limits, ban, PoW and PROXY protocol.

use crate::config::trusted::TrustedProxyCidr;
use serde::{Deserialize, Deserializer};

/// `[bind]` section: listen address and port of the edge node.
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

/// `[backend]` section: upstream backends (`addr:port`) behind the edge node.
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

/// `[workers]` section: number of accept loops sharing the listen address.
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

/// `[limits]` section: per-IP connection and rate limits.
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
	#[serde(
		default = "default_relay_idle_timeout",
		deserialize_with = "deserialize_relay_idle_timeout"
	)]
	pub relay_idle_timeout_secs: u64,
}

impl Default for LimitsConfig {
	fn default() -> Self {
		Self {
			handshake_timeout_secs: default_handshake_timeout(),
			max_connections_per_ip: default_max_connections_per_ip(),
			rate_limit_pps: default_rate_limit_pps(),
			rate_limit_burst: default_rate_limit_burst(),
			relay_idle_timeout_secs: default_relay_idle_timeout(),
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
fn default_relay_idle_timeout() -> u64 {
	300
}

/// Deserializes and validates `limits.relay_idle_timeout_secs`.
/// # Errors
/// Fails outside `1..=86_400`; zero would cut every relayed session immediately.
fn deserialize_relay_idle_timeout<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
	let secs = u64::deserialize(deserializer)?;
	if (1..=86_400).contains(&secs) {
		return Ok(secs);
	}
	Err(serde::de::Error::custom(
		"limits.relay_idle_timeout_secs must be between 1 and 86400",
	))
}

/// `[ban]` section: default ban duration.
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

/// `[pow]` section: proof-of-work gate.
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

/// `[proxy_protocol]` section: inbound PROXY protocol ingestion.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyProtocolConfig {
	#[serde(default)]
	pub ingress_enabled: bool,
	#[serde(default)]
	pub trusted_cidrs: Vec<TrustedProxyCidr>,
	#[serde(default = "default_proxy_protocol_timeout_ms")]
	pub ingress_timeout_ms: u64,
	#[serde(default = "default_proxy_protocol_max_header_bytes")]
	pub max_header_bytes: usize,
}

impl Default for ProxyProtocolConfig {
	fn default() -> Self {
		Self {
			ingress_enabled: false,
			trusted_cidrs: Vec::new(),
			ingress_timeout_ms: default_proxy_protocol_timeout_ms(),
			max_header_bytes: default_proxy_protocol_max_header_bytes(),
		}
	}
}
fn default_proxy_protocol_timeout_ms() -> u64 {
	750
}
fn default_proxy_protocol_max_header_bytes() -> usize {
	512
}
