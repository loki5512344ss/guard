//! Startup security policy of the management plane.
//!
//! Weak credentials turn the control plane API into an authentication bypass:
//! an empty `API_PASSWORD` matches an empty login, and a guessable
//! `JWT_SECRET` lets anyone mint admin tokens. The manager validates both
//! before it binds a socket, and derives its CORS policy from an explicit
//! `CORS_ORIGIN` value instead of silently allowing every origin.

use anyhow::{Result, bail};
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

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
	/// Returns `None` for [`CorsPolicy::Deny`] so the router is served without
	/// any cross-origin layer.
	#[must_use]
	pub fn cors_layer(&self) -> Option<CorsLayer> {
		match self {
			Self::Deny => None,
			Self::Any => Some(CorsLayer::new().allow_origin(Any)),
			Self::AllowList(origins) => {
				let allowed = origins
					.iter()
					.filter_map(|origin| axum::http::HeaderValue::from_str(origin).ok());
				Some(CorsLayer::new().allow_origin(AllowOrigin::list(allowed)))
			},
		}
	}
}
