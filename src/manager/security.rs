//! Startup security policy of the management plane.
//!
//! Weak credentials turn the control plane API into an authentication bypass:
//! an empty `API_PASSWORD` matches an empty login, and a guessable
//! `JWT_SECRET` lets anyone mint admin tokens. The manager validates both
//! before it binds a socket, and derives its CORS policy from an explicit
//! `CORS_ORIGIN` value instead of silently allowing every origin.

use anyhow::{Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Minimum length of `API_PASSWORD` in characters.
const MIN_API_PASSWORD_CHARS: usize = 16;
/// Minimum number of non-whitespace bytes in `JWT_SECRET`.
const MIN_JWT_SECRET_BYTES: usize = 32;
/// Placeholder password shipped in documentation and examples.
const DEFAULT_API_PASSWORD: &str = "changeme";

/// Validates `API_PASSWORD` before the manager starts serving.
///
/// # Errors
/// Rejects an empty or whitespace-only password, a password shorter than
/// `MIN_API_PASSWORD_CHARS` characters, and the `changeme` placeholder.
pub fn validate_api_password(password: &str) -> Result<()> {
	let trimmed = password.trim();
	if trimmed.is_empty() {
		bail!("API_PASSWORD must not be empty: an empty password would accept an empty login");
	}
	if trimmed.chars().count() < MIN_API_PASSWORD_CHARS {
		bail!("API_PASSWORD must be at least {MIN_API_PASSWORD_CHARS} characters long");
	}
	if trimmed.eq_ignore_ascii_case(DEFAULT_API_PASSWORD) {
		bail!("API_PASSWORD must not be the default placeholder '{DEFAULT_API_PASSWORD}'");
	}
	Ok(())
}

/// Validates `JWT_SECRET` before the manager starts serving.
///
/// # Errors
/// Rejects a secret with fewer than `MIN_JWT_SECRET_BYTES` non-whitespace
/// bytes, which includes empty and all-whitespace secrets.
pub fn validate_jwt_secret(secret: &str) -> Result<()> {
	let significant = secret.bytes().filter(|byte| !byte.is_ascii_whitespace()).count();
	if significant < MIN_JWT_SECRET_BYTES {
		bail!("JWT_SECRET must contain at least {MIN_JWT_SECRET_BYTES} non-whitespace bytes, got {significant}");
	}
	Ok(())
}

/// Compares a login password with the configured one in constant time.
///
/// An empty stored password never verifies: that is the authentication bypass
/// the startup policy ([`validate_api_password`]) rules out, and the handler
/// keeps the same guarantee for any state built by other code paths.
#[must_use]
pub fn verify_password(provided: &str, expected: &str) -> bool {
	if expected.is_empty() {
		return false;
	}
	let provided = provided.as_bytes();
	let expected = expected.as_bytes();
	let len_match = (provided.len() as u64).ct_eq(&(expected.len() as u64));
	let min_len = provided.len().min(expected.len());
	let bytes_match = provided[..min_len].ct_eq(&expected[..min_len]);
	bool::from(len_match & bytes_match)
}

/// Cross-origin resource sharing policy derived from `CORS_ORIGIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsPolicy {
	/// No cross-origin layer at all: browsers on other origins are denied.
	Deny,
	/// Every origin is allowed; requires an explicit `CORS_ORIGIN=*`.
	Any,
	/// Only the listed origins are allowed.
	AllowList(Vec<String>),
}

impl CorsPolicy {
	/// Parses the raw `CORS_ORIGIN` value.
	///
	/// An unset or empty variable denies cross-origin access, `*` must be set
	/// explicitly to allow any origin, and anything else is a comma-separated
	/// list of origins.
	///
	/// # Errors
	/// Fails on an empty entry, on a wildcard mixed with concrete origins, and
	/// on an entry that is not a valid HTTP header value.
	pub fn parse(raw: Option<&str>) -> Result<Self> {
		let Some(raw) = raw else {
			return Ok(Self::Deny);
		};
		let raw = raw.trim();
		if raw.is_empty() {
			return Ok(Self::Deny);
		}
		if raw == "*" {
			return Ok(Self::Any);
		}
		let mut origins = Vec::new();
		for entry in raw.split(',') {
			let origin = entry.trim();
			if origin.is_empty() {
				bail!("CORS_ORIGIN contains an empty origin entry");
			}
			if origin == "*" {
				bail!("CORS_ORIGIN wildcard '*' must be used alone, not inside an origin list");
			}
			axum::http::HeaderValue::from_str(origin)
				.map_err(|_| anyhow::anyhow!("CORS_ORIGIN entry '{origin}' is not a valid HTTP header value"))?;
			origins.push(origin.to_owned());
		}
		Ok(Self::AllowList(origins))
	}

	/// Builds the axum CORS layer for this policy.
	///
	/// The layer only configures origins, methods and headers, so a browser
	/// preflight reaches the same endpoints the API documents. It does not
	/// enable credentials: the manager authenticates with a bearer token.
	///
	/// Returns `None` for [`CorsPolicy::Deny`] so the router is served without
	/// any cross-origin layer.
	#[must_use]
	pub fn cors_layer(&self) -> Option<CorsLayer> {
		let origin = match self {
			Self::Deny => return None,
			Self::Any => AllowOrigin::any(),
			Self::AllowList(origins) => {
				let allowed = origins
					.iter()
					.filter_map(|origin| axum::http::HeaderValue::from_str(origin).ok());
				AllowOrigin::list(allowed)
			},
		};
		Some(
			CorsLayer::new()
				.allow_origin(origin)
				.allow_methods([
					axum::http::Method::GET,
					axum::http::Method::POST,
					axum::http::Method::DELETE,
				])
				.allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]),
		)
	}
}

/// An IPv4 or IPv6 network in CIDR notation.
///
/// A bare address parses as a host route (`/32` or `/128`). Used for the
/// `MANAGER_TRUSTED_PROXIES` policy, where a too-broad entry would let a
/// client spoof its address through `X-Forwarded-For`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
	addr: IpAddr,
	prefix: u8,
}

impl IpNet {
	/// Parses `10.0.0.0/8`, `2001:db8::/32` or a bare address.
	///
	/// # Errors
	/// Fails when the address or the prefix is malformed, and when the prefix
	/// length exceeds the address width (32 or 128 bits).
	pub fn parse(value: &str) -> Result<Self> {
		let value = value.trim();
		let (addr, prefix) = match value.split_once('/') {
			Some((addr, prefix)) => (addr, Some(prefix)),
			None => (value, None),
		};
		let addr: IpAddr = addr
			.parse()
			.map_err(|_| anyhow::anyhow!("'{value}' is not an IP address or CIDR network"))?;
		let width = if addr.is_ipv4() { 32 } else { 128 };
		let prefix = match prefix {
			Some(prefix) => prefix
				.parse::<u8>()
				.map_err(|_| anyhow::anyhow!("'{value}' has an invalid prefix length"))?,
			None => width,
		};
		if prefix > width {
			bail!("'{value}' prefix length exceeds the {width}-bit address width");
		}
		Ok(Self { addr, prefix })
	}

	/// Reports whether `ip` belongs to this network.
	#[must_use]
	pub fn contains(&self, ip: IpAddr) -> bool {
		match (self.addr, ip) {
			(IpAddr::V4(net), IpAddr::V4(ip)) => mask_v4(net, self.prefix) == mask_v4(ip, self.prefix),
			(IpAddr::V6(net), IpAddr::V6(ip)) => mask_v6(net, self.prefix) == mask_v6(ip, self.prefix),
			_ => false,
		}
	}
}

/// Returns the network bits of `addr`; a zero prefix masks everything.
fn mask_v4(addr: Ipv4Addr, prefix: u8) -> u32 {
	let shift = u32::from(32_u8.saturating_sub(prefix));
	u32::from(addr) & u32::MAX.checked_shl(shift).unwrap_or(0)
}

/// Returns the network bits of `addr`; a zero prefix masks everything.
fn mask_v6(addr: Ipv6Addr, prefix: u8) -> u128 {
	let shift = u32::from(128_u8.saturating_sub(prefix));
	u128::from(addr) & u128::MAX.checked_shl(shift).unwrap_or(0)
}
