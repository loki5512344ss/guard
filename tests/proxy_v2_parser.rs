//! Parser contract for inbound PROXY protocol v2 headers.

#![cfg(feature = "protocol-minecraft")]
//!
//! The parser is pure and total: arbitrary bytes must produce an error, never a
//! panic. These cases pin the accepted wire format and every rejection path.

use std::net::SocketAddr;

use rampart::engine::tunnel::parse_v2_header;

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

fn header(family: u8, payload: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(16 + payload.len());
	out.extend_from_slice(&SIGNATURE);
	out.push(0x21);
	out.push(family);
	out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
	out.extend_from_slice(payload);
	out
}

fn v4_payload(source: [u8; 4], source_port: u16) -> Vec<u8> {
	let mut payload = Vec::with_capacity(12);
	payload.extend_from_slice(&source);
	payload.extend_from_slice(&[192, 0, 2, 10]); // destination
	payload.extend_from_slice(&source_port.to_be_bytes());
	payload.extend_from_slice(&443u16.to_be_bytes());
	payload
}

fn v6_payload(source: [u8; 16], source_port: u16) -> Vec<u8> {
	let mut payload = Vec::with_capacity(36);
	payload.extend_from_slice(&source);
	payload.extend_from_slice(&[0u8; 16]); // destination
	payload.extend_from_slice(&source_port.to_be_bytes());
	payload.extend_from_slice(&443u16.to_be_bytes());
	payload
}

#[test]
fn parses_ipv4_header() {
	let buf = header(0x11, &v4_payload([203, 0, 113, 7], 51234));
	let (client, consumed) = parse_v2_header(&buf, 512).expect("valid v4 header");
	assert_eq!(consumed, buf.len());
	assert_eq!(client, "203.0.113.7:51234".parse::<SocketAddr>().expect("addr"));
}

#[test]
fn parses_ipv6_header() {
	let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
	let buf = header(0x21, &v6_payload(source, 1024));
	let (client, consumed) = parse_v2_header(&buf, 512).expect("valid v6 header");
	assert_eq!(consumed, buf.len());
	assert_eq!(client, "[2001:db8::1]:1024".parse::<SocketAddr>().expect("addr"));
}

#[test]
fn rejects_bad_signature() {
	let mut buf = header(0x11, &v4_payload([1, 2, 3, 4], 1));
	buf[0] = b'X';
	assert!(parse_v2_header(&buf, 512).is_err());
}

#[test]
fn rejects_non_proxy_command() {
	let mut buf = header(0x11, &v4_payload([1, 2, 3, 4], 1));
	buf[12] = 0x20; // LOCAL command, not PROXY
	assert!(parse_v2_header(&buf, 512).is_err());
}

#[test]
fn rejects_tlvs() {
	let mut payload = v4_payload([1, 2, 3, 4], 1);
	payload.extend_from_slice(&[0x04, 0x00, 0x01, 0x00]);
	assert!(parse_v2_header(&header(0x11, &payload), 512).is_err());
}

#[test]
fn rejects_truncated_header() {
	let buf = header(0x11, &v4_payload([1, 2, 3, 4], 1));
	for cut in 0..buf.len() {
		assert!(
			parse_v2_header(&buf[..cut], 512).is_err(),
			"a {cut}-byte prefix must be rejected"
		);
	}
}

#[test]
fn rejects_oversized_header() {
	let buf = header(0x11, &v4_payload([1, 2, 3, 4], 1));
	assert!(parse_v2_header(&buf, 16).is_err(), "limit smaller than the header");
}

#[test]
fn rejects_unsupported_family() {
	let buf = header(0x31, &v4_payload([1, 2, 3, 4], 1));
	assert!(parse_v2_header(&buf, 512).is_err());
}

#[test]
fn rejects_short_address_block() {
	let buf = header(0x11, &[0u8; 8]);
	assert!(parse_v2_header(&buf, 512).is_err());
}

#[test]
fn never_panics_on_arbitrary_bytes() {
	// Deterministic pseudo-random sweep over the interesting prefixes: a
	// signature-valid header with arbitrary family/length/payload bytes.
	for family in 0u8..=255 {
		for len in [0usize, 1, 11, 12, 13, 35, 36, 37, 512, 65535] {
			let mut buf = Vec::new();
			buf.extend_from_slice(&SIGNATURE);
			buf.push(0x21);
			buf.push(family);
			buf.extend_from_slice(&(len as u16).to_be_bytes());
			buf.extend(std::iter::repeat_n(0xA5u8, len.min(64)));
			let _ = parse_v2_header(&buf, 512);
		}
	}
}
