//! `[protocol.minecraft]` hygiene options: defaults, parsing and clamps.
#![cfg(feature = "protocol-minecraft")]

use rampart::config::{Config, UsernameCharset};

fn parse(extra: &str) -> anyhow::Result<Config> {
	Config::parse_str(&format!("[protocol.minecraft]\nenabled = true\n{extra}"))
}

#[test]
fn defaults_match_the_documented_values() -> anyhow::Result<()> {
	let mc = parse("")?.protocol.minecraft;
	assert_eq!(mc.max_handshake_bytes, 2048);
	assert_eq!(mc.max_login_start_bytes, 5120);
	assert_eq!(mc.max_status_request_bytes, 64);
	assert_eq!(mc.username_max_len, 16);
	assert_eq!(mc.username_charset, UsernameCharset::Standard);
	assert_eq!(mc.min_protocol_version, None);
	assert_eq!(mc.max_protocol_version, None);
	assert!(mc.deny_protocol_versions.is_empty());
	Ok(())
}

#[test]
fn custom_values_parse() -> anyhow::Result<()> {
	let mc = parse(
		"min_protocol_version = 47\nmax_protocol_version = 772\ndeny_protocol_versions = [340, 754]\n\
		 username_max_len = 32\nusername_charset = \"any\"\nmax_handshake_bytes = 512\n",
	)?
	.protocol
	.minecraft;
	assert_eq!(mc.min_protocol_version, Some(47));
	assert_eq!(mc.deny_protocol_versions, vec![340, 754]);
	assert_eq!(mc.username_charset, UsernameCharset::Any);
	assert_eq!(mc.max_handshake_bytes, 512);
	Ok(())
}

#[test]
fn out_of_range_values_are_rejected() {
	for bad in [
		"max_handshake_bytes = 8",
		"max_handshake_bytes = 100000",
		"max_login_start_bytes = 0",
		"max_status_request_bytes = 0",
		"max_status_request_bytes = 4096",
		"username_max_len = 0",
		"username_max_len = 65",
		"min_protocol_version = 800\nmax_protocol_version = 700",
		"min_protocol_version = -1",
		"deny_protocol_versions = [-5]",
		"username_charset = \"regex\"",
	] {
		assert!(parse(bad).is_err(), "{bad}");
	}
}
