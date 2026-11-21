//! Strict parsing of operator input shared by the manager API and the CLI.
//!
//! Everything here rejects instead of normalising: no surrounding whitespace, no
//! sign characters, no trailing garbage. Untrusted text must name exactly one
//! thing, otherwise a typo could ban a different address than the one intended.

use crate::filter::blacklist::MAX_BAN_DURATION_SECS;
use std::net::IpAddr;

/// A ban target: one address, optionally written with a CIDR prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
	pub ip: IpAddr,
	/// `None` for a bare address; `Some(1..=width)` for a network.
	pub prefix: Option<u8>,
}

/// Parses `1.2.3.4`, `::1`, `10.0.0.0/8` or `2001:db8::/32`.
///
/// # Errors
/// Rejects empty input, whitespace anywhere, a malformed address, a prefix that is
/// not plain decimal digits, `/0` (it would match every address) and a prefix
/// beyond 32 (IPv4) or 128 (IPv6).
pub fn parse_target(text: &str) -> Result<Target, String> {
	if text.is_empty() {
		return Err("target must not be empty".into());
	}
	if text.chars().any(char::is_whitespace) {
		return Err("target must not contain whitespace".into());
	}
	let (addr, prefix) = match text.split_once('/') {
		Some((addr, prefix)) => (addr, Some(prefix)),
		None => (text, None),
	};
	let ip: IpAddr = addr
		.parse()
		.map_err(|_| "target must be a valid IPv4 or IPv6 address".to_string())?;
	let Some(prefix) = prefix else {
		return Ok(Target { ip, prefix: None });
	};
	let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
	if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
		return Err("prefix length must be decimal digits".into());
	}
	let len: u8 = prefix
		.parse()
		.map_err(|_| format!("prefix length exceeds the {width}-bit address width"))?;
	if len == 0 {
		return Err("prefix length /0 is not allowed".into());
	}
	if len > width {
		return Err(format!("prefix length exceeds the {width}-bit address width"));
	}
	Ok(Target { ip, prefix: Some(len) })
}

/// Parses a TCP/UDP port: decimal digits only, `1..=65535`.
///
/// # Errors
/// Rejects empty input, signs, whitespace, `0` and values above 65535.
pub fn parse_port(text: &str) -> Result<u16, String> {
	if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
		return Err("port must be decimal digits".into());
	}
	match text.parse::<u16>() {
		Ok(0) | Err(_) => Err("port must be between 1 and 65535".into()),
		Ok(port) => Ok(port),
	}
}

/// Resolves the ban window of a request into `(duration_secs, expires_at_unix)`.
///
/// Exactly one of `duration_secs` and `expires_at` may be set; with neither,
/// `default_secs` applies.
///
/// # Errors
/// Fails when both are set, a duration is zero or above the one-year cap, or
/// `expires_at` is unrepresentable, not in the future, or beyond the cap.
pub fn resolve_ban_window(
	duration_secs: Option<u64>,
	expires_at: Option<i64>,
	default_secs: u64,
	now: i64,
) -> Result<(u64, i64), &'static str> {
	let secs = match (duration_secs, expires_at) {
		(Some(_), Some(_)) => return Err("specify either duration_secs or expires_at, not both"),
		(None, Some(at)) => {
			if !crate::timeutil::is_valid_unix(at) {
				return Err("expires_at is not a valid unix timestamp");
			}
			if at <= now {
				return Err("expires_at must be in the future");
			}
			u64::try_from(at.saturating_sub(now)).map_err(|_| "expires_at must be in the future")?
		},
		(Some(secs), None) => secs,
		(None, None) => default_secs,
	};
	if secs == 0 {
		return Err("duration_secs must be greater than zero");
	}
	if secs > MAX_BAN_DURATION_SECS {
		return Err("ban duration must not exceed one year");
	}
	let secs_i = i64::try_from(secs).map_err(|_| "ban duration must not exceed one year")?;
	Ok((secs, now.saturating_add(secs_i)))
}
