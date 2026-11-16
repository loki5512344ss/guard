//! Client identity behind a trusted PROXY protocol proxy: header address
//! validation, fallback to the transport peer and suppression of bans for
//! addresses inside `proxy_protocol.trusted_cidrs`.

#![cfg(feature = "protocol-minecraft")]

use rampart::config::{Config, ProxyProtocolConfig, TrustedProxyCidr};
use rampart::engine::challenge::DifficultyAdjuster;
use rampart::engine::tunnel::{ClientIpRejection, Gateway, GatewayOutcome, validate_client_ip};
use rampart::filter::blacklist::Blacklist;
use rampart::filter::rate_limit::RateLimiter;
use rampart::protocol::ProtocolRegistry;
use rampart::traffic::reputation::IpReputation;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Builds a gateway with no XDP/ClickHouse writers and an empty protocol
/// registry, so every connection stops at the admission filters.
fn test_gateway(config: Config, whitelist: HashSet<IpAddr>) -> Arc<Gateway> {
	Arc::new(Gateway::new(
		Arc::new(config.clone()),
		Arc::new(RateLimiter::new(
			config.limits.rate_limit_pps,
			config.limits.rate_limit_burst,
		)),
		Arc::new(Blacklist::new()),
		Arc::new(Mutex::new(DifficultyAdjuster::default())),
		Arc::new(whitelist),
		Arc::new(IpReputation::new()),
		None,
		None,
		Arc::new(AtomicU64::new(0)),
		Arc::new(ProtocolRegistry::new()),
		None,
	))
}

/// Encodes a PROXY protocol v2 TCP-over-IPv4 header.
fn proxy_v2_header(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
	const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
	let mut header = Vec::with_capacity(28);
	header.extend_from_slice(&SIGNATURE);
	header.push(0x21);
	header.push(0x11);
	header.extend_from_slice(&12u16.to_be_bytes());
	header.extend_from_slice(&source.octets());
	header.extend_from_slice(&destination.octets());
	header.extend_from_slice(&40_000u16.to_be_bytes());
	header.extend_from_slice(&25565u16.to_be_bytes());
	header
}

/// Runs one connection through the gateway after sending a PROXY v2 header that
/// claims `claimed` as the client address. The transport peer passed to the
/// gateway is `peer`, which lets the test model a trusted proxy explicitly.
async fn handle_with_header(gateway: &Gateway, peer: SocketAddr, claimed: Ipv4Addr) -> GatewayOutcome {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
	let local = listener.local_addr().expect("local addr");
	let (client, accepted) = tokio::join!(TcpStream::connect(local), listener.accept());
	let mut client = client.expect("connect");
	let server = accepted.expect("accept").0;
	let destination = match local.ip() {
		IpAddr::V4(ip) => ip,
		IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
	};
	client
		.write_all(&proxy_v2_header(claimed, destination))
		.await
		.expect("write PROXY header");
	let outcome = gateway.handle(server, peer).await;
	drop(client);
	outcome
}

/// Runs one connection without a PROXY header.
async fn handle_plain(gateway: &Gateway, peer: SocketAddr) -> GatewayOutcome {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
	let local = listener.local_addr().expect("local addr");
	let (_client, server) = tokio::join!(TcpStream::connect(local), listener.accept());
	gateway.handle(server.expect("accept").0, peer).await
}

/// Parses a trusted proxy network for the test config.
fn cidr(value: &str) -> TrustedProxyCidr {
	value.parse().expect("valid trusted proxy CIDR")
}

/// A trusted proxy may state a public client address, and that address is the
/// one used for admission decisions and bans.
#[tokio::test]
async fn trusted_proxy_header_ip_is_used_for_identity_and_bans() {
	let mut config = Config::default();
	config.limits.rate_limit_pps = 0.0;
	config.limits.rate_limit_burst = 0.0;
	config.proxy_protocol.ingress_enabled = true;
	config.proxy_protocol.trusted_cidrs = vec![cidr("127.0.0.1/32")];
	let gateway = test_gateway(config, HashSet::new());

	let claimed = Ipv4Addr::new(198, 51, 100, 7);
	let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 51_100));
	for _ in 0..5 {
		let outcome = handle_with_header(&gateway, peer, claimed).await;
		assert!(outcome.result.is_ok(), "a rate-limited connection is dropped silently");
		assert_eq!(
			outcome.client_ip,
			Some(IpAddr::V4(claimed)),
			"the header IP, not the proxy IP, is the client identity"
		);
	}
	assert!(
		gateway.blacklist.is_blocked(IpAddr::V4(claimed)),
		"repeated rate-limit hits must ban the header IP"
	);
	assert!(
		!gateway.blacklist.is_blocked(peer.ip()),
		"the trusted proxy itself must stay unbanned"
	);
}

/// Header addresses that cannot be a real client are rejected and the
/// transport peer becomes the identity.
#[test]
fn rejects_header_addresses_that_cannot_be_a_client() {
	let config = ProxyProtocolConfig {
		trusted_cidrs: vec![cidr("10.0.0.0/8")],
		..ProxyProtocolConfig::default()
	};
	let cases = [
		("0.0.0.0", ClientIpRejection::Unspecified),
		("::", ClientIpRejection::Unspecified),
		("127.0.0.1", ClientIpRejection::Loopback),
		("::1", ClientIpRejection::Loopback),
		("169.254.10.1", ClientIpRejection::LinkLocal),
		("fe80::1", ClientIpRejection::LinkLocal),
		("224.0.0.1", ClientIpRejection::Multicast),
		("ff02::1", ClientIpRejection::Multicast),
		("255.255.255.255", ClientIpRejection::Broadcast),
		("::ffff:127.0.0.1", ClientIpRejection::Loopback),
		("::ffff:169.254.10.1", ClientIpRejection::LinkLocal),
	];
	for (address, expected) in cases {
		let ip = address.parse().expect("valid test address");
		assert_eq!(validate_client_ip(&config, ip), Err(expected), "address {address}");
	}
}

/// A proxy must not be able to claim an address of the proxy network itself.
#[test]
fn rejects_header_address_inside_trusted_cidrs() {
	let config = ProxyProtocolConfig {
		trusted_cidrs: vec![cidr("198.51.100.0/24"), cidr("2001:db8:2::/48")],
		..ProxyProtocolConfig::default()
	};
	assert_eq!(
		validate_client_ip(&config, "198.51.100.7".parse().expect("ipv4")),
		Err(ClientIpRejection::TrustedProxy)
	);
	assert_eq!(
		validate_client_ip(&config, "2001:db8:2::7".parse().expect("ipv6")),
		Err(ClientIpRejection::TrustedProxy)
	);
	assert_eq!(
		validate_client_ip(&config, "::ffff:198.51.100.7".parse().expect("mapped ipv4")),
		Err(ClientIpRejection::TrustedProxy),
		"an IPv4-mapped address must match the IPv4 proxy network"
	);
	assert!(
		validate_client_ip(&config, "203.0.113.7".parse().expect("ipv4")).is_ok(),
		"an address outside the proxy networks is a valid client identity"
	);
}

/// An invalid header address falls back to the transport peer, and the peer
/// (itself a trusted proxy) is never banned.
#[tokio::test]
async fn invalid_header_ip_falls_back_to_peer_and_suppresses_bans() {
	let mut config = Config::default();
	config.limits.rate_limit_pps = 0.0;
	config.limits.rate_limit_burst = 0.0;
	config.proxy_protocol.ingress_enabled = true;
	config.proxy_protocol.trusted_cidrs = vec![cidr("127.0.0.1/32")];
	let gateway = test_gateway(config, HashSet::new());

	let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 51_101));
	for _ in 0..8 {
		let outcome = handle_with_header(&gateway, peer, Ipv4Addr::LOCALHOST).await;
		assert!(outcome.result.is_ok());
		assert_eq!(
			outcome.client_ip,
			Some(peer.ip()),
			"a rejected header IP must fall back to the transport peer"
		);
	}
	assert!(
		gateway.blacklist.is_empty(),
		"a trusted proxy address must never be banned"
	);
}

/// A header claiming an address inside `trusted_cidrs` is rejected, and the
/// fallback peer (also a trusted proxy) is not banned either.
#[tokio::test]
async fn header_inside_trusted_cidrs_is_rejected_and_never_banned() {
	let mut config = Config::default();
	config.limits.rate_limit_pps = 0.0;
	config.limits.rate_limit_burst = 0.0;
	config.proxy_protocol.ingress_enabled = true;
	config.proxy_protocol.trusted_cidrs = vec![cidr("127.0.0.1/32"), cidr("198.51.100.0/24")];
	let gateway = test_gateway(config, HashSet::new());

	let claimed = Ipv4Addr::new(198, 51, 100, 7);
	let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 51_102));
	for _ in 0..5 {
		let outcome = handle_with_header(&gateway, peer, claimed).await;
		assert_eq!(
			outcome.client_ip,
			Some(peer.ip()),
			"a proxy must not claim another proxy address as the client"
		);
	}
	assert!(
		gateway.blacklist.is_empty(),
		"neither the claimed proxy address nor the fallback peer may be banned"
	);
}

/// Plain traffic without PROXY protocol keeps using the transport peer.
#[tokio::test]
async fn plain_connection_uses_the_transport_peer() {
	let gateway = test_gateway(Config::default(), HashSet::new());
	let peer = SocketAddr::from(([198, 51, 100, 20], 51_103));
	let outcome = handle_plain(&gateway, peer).await;
	assert_eq!(outcome.client_ip, Some(peer.ip()));
}
