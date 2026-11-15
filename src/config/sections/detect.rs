//! Detection sections (`[detect*]`) and the per-protocol handler policy.

use serde::Deserialize;

/// `[detect]` section: distributed attack detectors.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectConfig {
	#[serde(default)]
	pub prefix: DetectPrefixConfig,
	#[serde(default)]
	pub autoban: DetectAutobanConfig,
	#[serde(default)]
	pub alert: DetectAlertConfig,
}

/// `[detect.autoban]` section: auto-ban sources based on reputation and attack
/// detector signals. The threshold is compared against the
/// [`crate::traffic::reputation::IpReputation`] score, the TTL comes from
/// `ban.ban_duration_secs`.
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

/// `[detect.alert]` section: webhook alerts on attack state transitions
/// (attack started, attack ended).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DetectAlertConfig {
	#[serde(default)]
	pub webhook_url: Option<String>,
}

/// `[detect.prefix]` section: subnet-level detector for distributed attacks.
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

/// `[protocol]` section: protocol handlers, enabled one plugin per feature.
#[cfg(any(feature = "protocol-http", feature = "protocol-minecraft"))]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProtocolConfig {
	#[cfg(feature = "protocol-http")]
	#[serde(default)]
	pub http: HttpProtocolConfig,
	#[cfg(feature = "protocol-minecraft")]
	#[serde(default)]
	pub minecraft: MinecraftProtocolConfig,
}

/// `[protocol.minecraft]` section: Minecraft handshake handler policy.
#[cfg(feature = "protocol-minecraft")]
#[derive(Debug, Clone, Deserialize)]
pub struct MinecraftProtocolConfig {
	#[serde(default = "default_minecraft_enabled")]
	pub enabled: bool,
	#[serde(default = "default_minecraft_max_frame_bytes")]
	pub max_frame_bytes: usize,
	#[serde(default = "default_minecraft_timeout_secs")]
	pub timeout_secs: u64,
	#[serde(default, alias = "proxy_protocol")]
	pub send_proxy_protocol: bool,
}

#[cfg(feature = "protocol-minecraft")]
impl Default for MinecraftProtocolConfig {
	fn default() -> Self {
		Self {
			enabled: default_minecraft_enabled(),
			max_frame_bytes: default_minecraft_max_frame_bytes(),
			timeout_secs: default_minecraft_timeout_secs(),
			send_proxy_protocol: false,
		}
	}
}

#[cfg(feature = "protocol-minecraft")]
fn default_minecraft_enabled() -> bool {
	!cfg!(feature = "protocol-http")
}

#[cfg(feature = "protocol-minecraft")]
fn default_minecraft_max_frame_bytes() -> usize {
	8192
}

#[cfg(feature = "protocol-minecraft")]
fn default_minecraft_timeout_secs() -> u64 {
	5
}

/// `[protocol.http]` section: HTTP/1.1 handler policy on the edge node.
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
