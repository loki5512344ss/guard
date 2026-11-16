//! Trusted PROXY-protocol networks and CIDR helpers shared by the edge paths.

use serde::{Deserialize, Deserializer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// CIDR network allowed to send inbound PROXY protocol headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxyCidr {
	network: IpAddr,
	prefix_len: u8,
}

impl TrustedProxyCidr {
	/// Returns whether `ip` belongs to this network.
	#[must_use]
	pub fn contains(&self, ip: IpAddr) -> bool {
		// Masks are family-specific: a prefix above 32 would underflow the v4 shift.
		let prefix = self.prefix_len;
		match (self.network, normalize(ip)) {
			(IpAddr::V4(net), IpAddr::V4(ip)) => u32::from(net) & mask_v4(prefix) == u32::from(ip) & mask_v4(prefix),
			(IpAddr::V6(net), IpAddr::V6(ip)) => u128::from(net) & mask_v6(prefix) == u128::from(ip) & mask_v6(prefix),
			_ => false,
		}
	}

	/// Returns whether `ip/prefix_len` intersects this network.
	///
	/// Used before banning a prefix: a ban covering a trusted proxy address
	/// would punish the proxy and every client behind it.
	#[must_use]
	pub fn overlaps_prefix(&self, ip: IpAddr, prefix_len: u8) -> bool {
		match (self.network, normalize(ip)) {
			(IpAddr::V4(net), IpAddr::V4(other)) => {
				if prefix_len == 0 || prefix_len > 32 {
					return false;
				}
				let net_mask = mask_v4(self.prefix_len);
				let other_mask = mask_v4(prefix_len);
				let net_start = u32::from(net) & net_mask;
				let net_end = net_start | !net_mask;
				let other_start = u32::from(other) & other_mask;
				let other_end = other_start | !other_mask;
				net_start <= other_end && other_start <= net_end
			},
			(IpAddr::V6(net), IpAddr::V6(other)) => {
				if prefix_len == 0 || prefix_len > 128 {
					return false;
				}
				let net_mask = mask_v6(self.prefix_len);
				let other_mask = mask_v6(prefix_len);
				let net_start = u128::from(net) & net_mask;
				let net_end = net_start | !net_mask;
				let other_start = u128::from(other) & other_mask;
				let other_end = other_start | !other_mask;
				net_start <= other_end && other_start <= net_end
			},
			_ => false,
		}
	}
}

impl FromStr for TrustedProxyCidr {
	type Err = String;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		let (address, prefix) = value.split_once('/').map_or((value, None), |(a, p)| (a, Some(p)));
		let network = IpAddr::from_str(address).map_err(|_| format!("invalid trusted proxy CIDR: {value}"))?;
		let max_prefix = if network.is_ipv4() { 32 } else { 128 };
		let prefix_len = prefix
			.map_or(Ok(max_prefix), |prefix| prefix.parse::<u8>())
			.map_err(|_| format!("invalid trusted proxy CIDR prefix: {value}"))?;
		if prefix_len > max_prefix {
			return Err(format!("trusted proxy CIDR prefix is too large: {value}"));
		}
		let network = match network {
			IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask_v4(prefix_len))),
			IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask_v6(prefix_len))),
		};
		Ok(Self { network, prefix_len })
	}
}

impl<'de> Deserialize<'de> for TrustedProxyCidr {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		value.parse().map_err(serde::de::Error::custom)
	}
}

/// Collapses IPv4-mapped IPv6 addresses to IPv4.
fn normalize(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
		IpAddr::V4(_) => ip,
	}
}

fn mask_v4(prefix: u8) -> u32 {
	if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
}

fn mask_v6(prefix: u8) -> u128 {
	if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) }
}
