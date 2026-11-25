//! Single configuration of the Rampart platform.
//!
//! Owns the [`Config`] root type, its serde defaults and the semantic validation
//! that runs before the daemon binds a socket.
mod sections;
mod trusted;

#[cfg(feature = "protocol-http")]
pub use sections::HttpProtocolConfig;
#[cfg(any(feature = "protocol-http", feature = "protocol-minecraft"))]
pub use sections::ProtocolConfig;
pub use sections::{
	BackendConfig, BanConfig, BindConfig, DetectAlertConfig, DetectAutobanConfig, DetectConfig, DetectPrefixConfig,
	LimitsConfig, LoggingConfig, MetricsConfig, PowConfig, ProxyProtocolConfig, StoreConfig, WorkerConfig, XdpConfig,
};
#[cfg(feature = "protocol-minecraft")]
pub use sections::{MinecraftProtocolConfig, UsernameCharset};
pub use trusted::TrustedProxyCidr;

use serde::Deserialize;
use std::fs;

/// Upper bound of `ban.ban_duration_secs`: one year.
const MAX_BAN_DURATION_SECS: u64 = 31_536_000;
/// Upper bound of `pow.difficulty`.
const MAX_POW_DIFFICULTY: u8 = 10;
/// Placeholder `xdp.challenge_secret_hex` values baked into the XDP defaults
/// (`xdp/core/config.h` and `XdpGlobals::default()`; both spellings exist).
const PLACEHOLDER_CHALLENGE_SECRETS: [&str; 2] = ["a5a5a5a5a5a5a5a5", "a5a55a5a5a5aa5a5"];

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
	pub proxy_protocol: ProxyProtocolConfig,
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
	#[cfg(any(feature = "protocol-http", feature = "protocol-minecraft"))]
	#[serde(default)]
	pub protocol: ProtocolConfig,
	#[serde(default)]
	pub whitelist: Vec<String>,
}

impl Config {
	/// Parses the config from a TOML string and validates its semantics.
	///
	/// # Errors
	/// Fails on invalid TOML or on a violated invariant (empty upstream list,
	/// malformed addresses, unsafe PROXY protocol settings).
	pub fn parse_str(contents: &str) -> anyhow::Result<Self> {
		let config: Config = toml::from_str(contents)?;
		config.validate()?;
		Ok(config)
	}

	/// Reads and parses the config from a file.
	///
	/// # Errors
	/// Fails when the file cannot be read or its contents are invalid.
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
		if self.xdp.syn_challenge_enabled {
			let secret = self.xdp.challenge_secret_hex.as_deref().ok_or_else(|| {
				anyhow::anyhow!(
					"xdp.syn_challenge_enabled requires xdp.challenge_secret_hex; \
					 generate one with `openssl rand -hex 8`"
				)
			})?;
			if is_placeholder_challenge_secret(secret) {
				anyhow::bail!(
					"xdp.challenge_secret_hex is the built-in placeholder; \
					 generate a random secret with `openssl rand -hex 8`"
				);
			}
		}
		if self.limits.max_connections_per_ip == 0 {
			anyhow::bail!("limits.max_connections_per_ip must be positive");
		}
		if !self.limits.rate_limit_pps.is_finite() || self.limits.rate_limit_pps <= 0.0 {
			anyhow::bail!("limits.rate_limit_pps must be a finite number greater than 0");
		}
		if !self.limits.rate_limit_burst.is_finite() || self.limits.rate_limit_burst < 1.0 {
			anyhow::bail!("limits.rate_limit_burst must be a finite number at least 1");
		}
		if self.ban.ban_duration_secs == 0 || self.ban.ban_duration_secs > MAX_BAN_DURATION_SECS {
			anyhow::bail!("ban.ban_duration_secs must be between 1 and {MAX_BAN_DURATION_SECS}");
		}
		if self.pow.difficulty == 0 || self.pow.difficulty > MAX_POW_DIFFICULTY {
			anyhow::bail!("pow.difficulty must be between 1 and {MAX_POW_DIFFICULTY}");
		}
		if self.workers.count == 0 {
			anyhow::bail!("workers.count must be at least 1: otherwise no accept loops are started");
		}
		if self.proxy_protocol.ingress_enabled {
			if self.proxy_protocol.trusted_cidrs.is_empty() {
				anyhow::bail!("proxy_protocol.ingress_enabled requires at least one trusted_cidrs entry");
			}
			if self.proxy_protocol.ingress_timeout_ms == 0 || self.proxy_protocol.ingress_timeout_ms > 5_000 {
				anyhow::bail!("proxy_protocol.ingress_timeout_ms must be between 1 and 5000");
			}
			if self.proxy_protocol.max_header_bytes < 52 || self.proxy_protocol.max_header_bytes > 4096 {
				anyhow::bail!("proxy_protocol.max_header_bytes must be between 52 and 4096");
			}
			#[cfg(feature = "protocol-minecraft")]
			if !self.protocol.minecraft.enabled {
				anyhow::bail!("proxy_protocol.ingress_enabled requires protocol.minecraft.enabled");
			}
			#[cfg(not(feature = "protocol-minecraft"))]
			anyhow::bail!("proxy_protocol.ingress_enabled requires the protocol-minecraft feature");
		}
		#[cfg(feature = "protocol-http")]
		{
			if self.protocol.http.max_header_bytes == 0 {
				anyhow::bail!("protocol.http.max_header_bytes must be positive");
			}
			if self.protocol.http.timeout_secs == 0 {
				anyhow::bail!("protocol.http.timeout_secs must be positive");
			}
		}
		#[cfg(feature = "protocol-minecraft")]
		if self.protocol.minecraft.enabled {
			if self.pow.enabled {
				anyhow::bail!(
					"pow.enabled is incompatible with protocol.minecraft (the client cannot answer a \
					 text challenge); use xdp.syn_challenge_enabled for liveness checks instead"
				);
			}
			if self.backend.upstreams.len() != 1 {
				anyhow::bail!("protocol.minecraft requires exactly one backend.upstreams entry");
			}
			self.protocol.minecraft.validate()?;
		}
		Ok(())
	}
}

/// Returns whether `secret` spells a built-in placeholder challenge secret.
///
/// Hex digits are compared case-insensitively, with an optional `0x` prefix and
/// `_`, `:` and `-` separators ignored, so every spelling of the placeholder is
/// caught.
fn is_placeholder_challenge_secret(secret: &str) -> bool {
	let normalized = secret
		.trim()
		.trim_start_matches("0x")
		.trim_start_matches("0X")
		.replace(['_', ':', '-'], "")
		.to_ascii_lowercase();
	PLACEHOLDER_CHALLENGE_SECRETS.contains(&normalized.as_str())
}
