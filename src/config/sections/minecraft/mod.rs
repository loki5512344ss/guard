//! `[protocol.minecraft]` section: Minecraft handshake handler policy.

use serde::Deserialize;

/// Character set accepted in login-start usernames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsernameCharset {
	/// ASCII letters, digits, `_`, `.` and `-` (`.` covers Floodgate prefixes).
	#[default]
	Standard,
	/// Any printable ASCII character except space.
	Ascii,
	/// Any UTF-8 text without control characters (length limit still applies).
	Any,
}

/// `[protocol.minecraft]` section.
#[derive(Debug, Clone, Deserialize)]
pub struct MinecraftProtocolConfig {
	#[serde(default = "default_enabled")]
	pub enabled: bool,
	/// Global ceiling for any single frame; per-phase caps are clamped to it.
	#[serde(default = "default_max_frame_bytes")]
	pub max_frame_bytes: usize,
	#[serde(default = "default_timeout_secs")]
	pub timeout_secs: u64,
	#[serde(default, alias = "proxy_protocol")]
	pub send_proxy_protocol: bool,
	#[serde(default = "default_max_handshake_bytes")]
	pub max_handshake_bytes: usize,
	#[serde(default = "default_max_login_start_bytes")]
	pub max_login_start_bytes: usize,
	#[serde(default = "default_max_status_request_bytes")]
	pub max_status_request_bytes: usize,
	/// Lowest accepted protocol id; `None` means no lower bound.
	#[serde(default)]
	pub min_protocol_version: Option<i32>,
	/// Highest accepted protocol id; `None` means no upper bound.
	#[serde(default)]
	pub max_protocol_version: Option<i32>,
	#[serde(default)]
	pub deny_protocol_versions: Vec<i32>,
	#[serde(default = "default_username_max_len")]
	pub username_max_len: usize,
	#[serde(default)]
	pub username_charset: UsernameCharset,
}

impl Default for MinecraftProtocolConfig {
	fn default() -> Self {
		Self {
			enabled: default_enabled(),
			max_frame_bytes: default_max_frame_bytes(),
			timeout_secs: default_timeout_secs(),
			send_proxy_protocol: false,
			max_handshake_bytes: default_max_handshake_bytes(),
			max_login_start_bytes: default_max_login_start_bytes(),
			max_status_request_bytes: default_max_status_request_bytes(),
			min_protocol_version: None,
			max_protocol_version: None,
			deny_protocol_versions: Vec::new(),
			username_max_len: default_username_max_len(),
			username_charset: UsernameCharset::default(),
		}
	}
}

impl MinecraftProtocolConfig {
	/// Checks the invariants of an enabled handler.
	///
	/// # Errors
	/// Returns an error naming the first out-of-range key.
	pub fn validate(&self) -> anyhow::Result<()> {
		if self.max_frame_bytes == 0 {
			anyhow::bail!("protocol.minecraft.max_frame_bytes must be positive");
		}
		if self.timeout_secs == 0 {
			anyhow::bail!("protocol.minecraft.timeout_secs must be positive");
		}
		check_range("max_handshake_bytes", self.max_handshake_bytes, 16, 8192)?;
		check_range("max_login_start_bytes", self.max_login_start_bytes, 16, 8192)?;
		check_range("max_status_request_bytes", self.max_status_request_bytes, 1, 1024)?;
		check_range("username_max_len", self.username_max_len, 1, 64)?;
		let lo = self.min_protocol_version;
		let hi = self.max_protocol_version;
		if lo.is_some_and(|v| v < 0) || hi.is_some_and(|v| v < 0) {
			anyhow::bail!("protocol.minecraft min/max_protocol_version must be non-negative");
		}
		if let (Some(lo), Some(hi)) = (lo, hi)
			&& lo > hi
		{
			anyhow::bail!("protocol.minecraft.min_protocol_version exceeds max_protocol_version");
		}
		if self.deny_protocol_versions.iter().any(|v| *v < 0) {
			anyhow::bail!("protocol.minecraft.deny_protocol_versions must be non-negative");
		}
		Ok(())
	}
}

fn check_range(key: &str, value: usize, min: usize, max: usize) -> anyhow::Result<()> {
	if !(min..=max).contains(&value) {
		anyhow::bail!("protocol.minecraft.{key} must be in {min}..={max}");
	}
	Ok(())
}

fn default_enabled() -> bool {
	!cfg!(feature = "protocol-http")
}

fn default_max_frame_bytes() -> usize {
	8192
}

fn default_timeout_secs() -> u64 {
	5
}

fn default_max_handshake_bytes() -> usize {
	2048
}

fn default_max_login_start_bytes() -> usize {
	5120
}

fn default_max_status_request_bytes() -> usize {
	64
}

fn default_username_max_len() -> usize {
	16
}
