//! PROXY protocol v2 support: header encoding for the backend and strict
//! parsing of headers injected by trusted ingress peers.

use crate::config::ProxyProtocolConfig;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

mod inbound;
pub(super) use inbound::read_v2_header;

/// Reason a PROXY header client address is rejected as an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIpRejection {
	/// `0.0.0.0` or `::`: no host behind the header.
	Unspecified,
	/// The header claims a loopback address, which is never a real client.
	Loopback,
	/// The header claims a link-local address (`169.254.0.0/16`, `fe80::/10`).
	LinkLocal,
	/// The header claims a multicast address.
	Multicast,
	/// The header claims the limited IPv4 broadcast address.
	Broadcast,
	/// The header claims an address of the proxy network itself.
	TrustedProxy,
}

/// Validates the client IP claimed in an inbound PROXY v2 header.
///
/// A trusted proxy is allowed to state who the client is, but it must not be
/// able to name an address that can never be a real remote client (host-local,
/// link-local, multicast, broadcast) or another trusted proxy. Without this
/// check a single compromised or misconfigured proxy could ban arbitrary
/// addresses cluster-wide or poison their reputation.
///
/// # Errors
/// Returns the reason `ip` is not usable as a client identity.
pub fn validate_client_ip(config: &ProxyProtocolConfig, ip: IpAddr) -> Result<(), ClientIpRejection> {
	// Collapse IPv4-mapped IPv6 first: the ban tables do the same, so leaving
	// `::ffff:127.0.0.1` as v6 would bypass the loopback and trusted-network
	// checks and then be normalized into a ban for `127.0.0.1`.
	let ip = match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
		IpAddr::V4(_) => ip,
	};
	if ip.is_unspecified() {
		return Err(ClientIpRejection::Unspecified);
	}
	if ip.is_loopback() {
		return Err(ClientIpRejection::Loopback);
	}
	let link_local = match ip {
		IpAddr::V4(v4) => v4.is_link_local(),
		IpAddr::V6(v6) => v6.is_unicast_link_local(),
	};
	if link_local {
		return Err(ClientIpRejection::LinkLocal);
	}
	if ip.is_multicast() {
		return Err(ClientIpRejection::Multicast);
	}
	if ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
		return Err(ClientIpRejection::Broadcast);
	}
	if config.trusted_cidrs.iter().any(|cidr| cidr.contains(ip)) {
		return Err(ClientIpRejection::TrustedProxy);
	}
	Ok(())
}

/// Resolves the effective client address from an inbound PROXY v2 header.
///
/// Only peers inside `config.trusted_cidrs` may inject a header; anyone else
/// is rejected instead of being believed. The whole header must arrive within
/// `config.ingress_timeout_ms` and fit in `config.max_header_bytes`.
///
/// A header whose client address fails [`validate_client_ip`] is not fatal:
/// the transport peer becomes the client identity and the reason is logged once
/// per connection at debug level. Failing closed would drop every connection
/// behind a misbehaving proxy, while trusting the claimed address would hand
/// the ban path to the proxy.
///
/// # Errors
/// Fails when the peer is not trusted, on timeout and on any header parse error.
pub(super) async fn resolve_client_addr(
	config: &ProxyProtocolConfig,
	client: &mut TcpStream,
	peer_addr: SocketAddr,
) -> anyhow::Result<SocketAddr> {
	if !config.trusted_cidrs.iter().any(|cidr| cidr.contains(peer_addr.ip())) {
		anyhow::bail!("untrusted peer attempted inbound PROXY protocol");
	}
	let claimed = read_v2_header(
		client,
		Duration::from_millis(config.ingress_timeout_ms),
		config.max_header_bytes,
	)
	.await?;
	match validate_client_ip(config, claimed.ip()) {
		Ok(()) => Ok(claimed),
		Err(reason) => {
			tracing::debug!(
				peer = %peer_addr,
				claimed = %claimed,
				reason = ?reason,
				"ignoring PROXY header client address, using the transport peer"
			);
			Ok(peer_addr)
		},
	}
}

/// Encodes a PROXY protocol v2 TCP header for the backend.
///
/// The backend must accept connections only from trusted Rampart nodes, since
/// anyone able to reach it could otherwise forge the source address.
///
/// # Errors
/// Fails when the source and destination address families differ.
pub(super) fn protocol_v2(source: SocketAddr, destination: SocketAddr) -> anyhow::Result<Vec<u8>> {
	const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
	if source.is_ipv4() != destination.is_ipv4() {
		anyhow::bail!("PROXY protocol source/destination address families differ");
	}

	let (family, address_len) = if source.is_ipv4() {
		(0x11, 12usize)
	} else {
		(0x21, 36usize)
	};
	let mut header = Vec::with_capacity(16 + address_len);
	header.extend_from_slice(&SIGNATURE);
	header.push(0x21);
	header.push(family);
	header.extend_from_slice(&(address_len as u16).to_be_bytes());
	match (source, destination) {
		(SocketAddr::V4(src), SocketAddr::V4(dst)) => {
			header.extend_from_slice(&src.ip().octets());
			header.extend_from_slice(&dst.ip().octets());
			header.extend_from_slice(&src.port().to_be_bytes());
			header.extend_from_slice(&dst.port().to_be_bytes());
		},
		(SocketAddr::V6(src), SocketAddr::V6(dst)) => {
			header.extend_from_slice(&src.ip().octets());
			header.extend_from_slice(&dst.ip().octets());
			header.extend_from_slice(&src.port().to_be_bytes());
			header.extend_from_slice(&dst.port().to_be_bytes());
		},
		_ => anyhow::bail!("PROXY protocol source/destination address families differ"),
	}
	Ok(header)
}
