//! PROXY protocol v2 support: header encoding for the backend and strict
//! parsing of headers injected by trusted ingress peers.

use crate::config::ProxyProtocolConfig;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

mod inbound;
pub(super) use inbound::read_v2_header;

/// Resolves the effective client address from an inbound PROXY v2 header.
///
/// Only peers inside `config.trusted_cidrs` may inject a header; anyone else
/// is rejected instead of being believed. The whole header must arrive within
/// `config.ingress_timeout_ms` and fit in `config.max_header_bytes`.
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
	read_v2_header(
		client,
		Duration::from_millis(config.ingress_timeout_ms),
		config.max_header_bytes,
	)
	.await
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
