//! Runtime policy derived from `[protocol.minecraft]`: frame caps, version
//! bounds and username rules.

pub mod versions;

use super::reason::Reason;
use crate::config::{MinecraftProtocolConfig, UsernameCharset};

#[derive(Debug, Clone)]
pub struct Policy {
	pub max_frame_bytes: usize,
	pub handshake_cap: usize,
	pub login_start_cap: usize,
	pub status_request_cap: usize,
	pub min_version: Option<i32>,
	pub max_version: Option<i32>,
	pub deny_versions: Vec<i32>,
	pub username_max_len: usize,
	pub username_charset: UsernameCharset,
}

impl Policy {
	#[must_use]
	pub fn from_config(config: &MinecraftProtocolConfig) -> Self {
		let ceiling = config.max_frame_bytes;
		Self {
			max_frame_bytes: ceiling,
			handshake_cap: config.max_handshake_bytes.min(ceiling),
			login_start_cap: config.max_login_start_bytes.min(ceiling),
			status_request_cap: config.max_status_request_bytes.min(ceiling),
			min_version: config.min_protocol_version,
			max_version: config.max_protocol_version,
			deny_versions: config.deny_protocol_versions.clone(),
			username_max_len: config.username_max_len,
			username_charset: config.username_charset,
		}
	}

	/// Applies plausibility, min/max and deny-list rules to a protocol id.
	///
	/// # Errors
	/// Returns the matching [`Reason`] when the version is refused.
	pub fn check_version(&self, id: i32) -> Result<(), Reason> {
		if !versions::is_plausible(id) {
			return Err(Reason::ImplausibleVersion);
		}
		if self.min_version.is_some_and(|min| id < min) {
			return Err(Reason::VersionBelowMin);
		}
		if self.max_version.is_some_and(|max| id > max) {
			return Err(Reason::VersionAboveMax);
		}
		if self.deny_versions.contains(&id) {
			return Err(Reason::VersionDenied);
		}
		Ok(())
	}

	/// Validates a login-start username against length and charset.
	///
	/// # Errors
	/// Returns [`Reason::BadUsername`] when the name is not acceptable.
	pub fn check_username(&self, name: &str) -> Result<(), Reason> {
		let chars = name.chars().count();
		if chars == 0 || chars > self.username_max_len {
			return Err(Reason::BadUsername);
		}
		let ok = match self.username_charset {
			UsernameCharset::Standard => name
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')),
			UsernameCharset::Ascii => name.bytes().all(|b| b.is_ascii_graphic()),
			UsernameCharset::Any => !name.chars().any(char::is_control),
		};
		if ok { Ok(()) } else { Err(Reason::BadUsername) }
	}
}
