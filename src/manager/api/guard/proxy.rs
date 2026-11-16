//! Proxy-aware client address resolution.
//!
//! Behind a reverse proxy every request arrives from the proxy address, so a
//! per-IP limiter would throttle all administrators together. `X-Forwarded-For`
//! is therefore trusted only when the TCP peer belongs to an explicitly
//! configured network; otherwise the header is ignored and the peer address is
//! used, which keeps a directly connected client from spoofing its identity.

use crate::manager::security::IpNet;
use anyhow::Result;
use axum::http::HeaderValue;
use std::net::IpAddr;

/// Environment variable listing trusted proxy networks, comma separated.
pub const TRUSTED_PROXIES_ENV: &str = "MANAGER_TRUSTED_PROXIES";

/// Networks whose `X-Forwarded-For` header is trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
	nets: Vec<IpNet>,
}

impl TrustedProxies {
	/// Parses a comma-separated list of networks.
	///
	/// An empty or whitespace-only value trusts no proxy, which is the safe
	/// default for a manager exposed directly.
	///
	/// # Errors
	/// Fails on an empty entry or on a malformed address/CIDR, so a typo cannot
	/// silently widen the trust boundary.
	pub fn parse(raw: &str) -> Result<Self> {
		let raw = raw.trim();
		if raw.is_empty() {
			return Ok(Self::default());
		}
		let mut nets = Vec::new();
		for entry in raw.split(',') {
			let entry = entry.trim();
			if entry.is_empty() {
				anyhow::bail!("{TRUSTED_PROXIES_ENV} contains an empty entry");
			}
			nets.push(IpNet::parse(entry)?);
		}
		Ok(Self { nets })
	}

	/// Reads [`TRUSTED_PROXIES_ENV`] from the process environment.
	///
	/// # Errors
	/// Propagates the same validation as [`TrustedProxies::parse`].
	pub fn from_env() -> Result<Self> {
		Self::parse(&std::env::var(TRUSTED_PROXIES_ENV).unwrap_or_default())
	}

	/// Reports whether `ip` is a configured proxy.
	#[must_use]
	pub fn is_trusted(&self, ip: IpAddr) -> bool {
		self.nets.iter().any(|net| net.contains(ip))
	}

	/// Resolves the client address for a request from `peer`.
	///
	/// The forwarded chain is walked from right to left, skipping proxies the
	/// manager trusts, and the first untrusted hop wins: that is the address
	/// the nearest trusted proxy observed. A malformed chain falls back to the
	/// last trusted hop resolved so far, never to an unvalidated entry.
	#[must_use]
	pub fn client_ip(&self, peer: IpAddr, forwarded_for: Option<&HeaderValue>) -> IpAddr {
		if !self.is_trusted(peer) {
			return peer;
		}
		let Some(chain) = forwarded_for.and_then(|value| value.to_str().ok()) else {
			return peer;
		};
		let mut resolved = peer;
		for entry in chain.split(',').rev() {
			match entry.trim().parse::<IpAddr>() {
				Ok(ip) if !self.is_trusted(ip) => return ip,
				Ok(ip) => resolved = ip,
				Err(_) => break,
			}
		}
		resolved
	}
}
