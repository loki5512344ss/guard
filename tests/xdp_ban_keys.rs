//! Ban-key encoding for the IPv4 LPM trie and CIDR normalization.
//!
//! No kernel needed: these exercise the pure functions the loader uses before
//! touching `blacklist_map`. Regression class: two bans of the same /24 with
//! different host bits used to produce distinct LPM keys, and a prefix length
//! of 0 or above the address width was accepted silently.
#![cfg(feature = "xdp")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rampart::xdp::{blacklist_expiry_ns, blacklist_key, normalize_cidr};

#[test]
fn blacklist_key_puts_prefix_len_first_and_octets_last() {
	assert_eq!(blacklist_key(24, &[10, 0, 1, 200]), [24, 0, 0, 0, 10, 0, 1, 200]);
	assert_eq!(blacklist_key(32, &[127, 0, 0, 1]), [32, 0, 0, 0, 127, 0, 0, 1]);
}

#[test]
fn blacklist_key_encodes_prefix_len_as_little_endian_u32() {
	let key = blacklist_key(8, &[10, 1, 2, 3]);
	assert_eq!(u32::from_le_bytes(key[0..4].try_into().expect("4 bytes")), 8);
}

#[test]
fn blacklist_expiry_converts_secs_to_ns() {
	assert_eq!(blacklist_expiry_ns(1_000, 2), 1_000 + 2_000_000_000);
}

#[test]
fn blacklist_expiry_saturates_instead_of_wrapping() {
	assert_eq!(blacklist_expiry_ns(u64::MAX, 1), u64::MAX);
	assert_eq!(blacklist_expiry_ns(0, u64::MAX), u64::MAX);
}

#[test]
fn normalize_cidr_masks_host_bits_for_a_slash_24() {
	let net = normalize_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 24).expect("valid /24");
	assert_eq!(net, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)));
}

#[test]
fn without_masking_host_bits_would_produce_different_ban_keys() {
	// This is the regression: these two keys denote the same /24 but differ.
	assert_ne!(blacklist_key(24, &[10, 1, 2, 3]), blacklist_key(24, &[10, 1, 2, 0]));
}

#[test]
fn a_whole_subnet_shares_one_ban_key_after_normalization() {
	let first = normalize_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 24).expect("valid /24");
	let second = normalize_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 99)), 24).expect("valid /24");
	let (IpAddr::V4(first), IpAddr::V4(second)) = (first, second) else {
		return;
	};
	assert_eq!(blacklist_key(24, &first.octets()), blacklist_key(24, &second.octets()));
}

#[test]
fn normalize_cidr_keeps_slash_32_unchanged() {
	let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
	assert_eq!(normalize_cidr(addr, 32).expect("valid /32"), addr);
}

#[test]
fn normalize_cidr_masks_host_bits_for_ipv6() {
	let addr = IpAddr::V6("2001:db8:1:2:3:4:5:6".parse::<Ipv6Addr>().expect("literal"));
	let net = normalize_cidr(addr, 64).expect("valid /64");
	assert_eq!(net, IpAddr::V6("2001:db8:1:2::".parse::<Ipv6Addr>().expect("literal")));
}

#[test]
fn normalize_cidr_masks_partial_bytes() {
	let net = normalize_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 255)), 20).expect("valid /20");
	assert_eq!(net, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)));
}

#[test]
fn normalize_cidr_keeps_slash_128_unchanged() {
	let addr = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("literal"));
	assert_eq!(normalize_cidr(addr, 128).expect("valid /128"), addr);
}

#[test]
fn normalize_cidr_rejects_prefix_zero() {
	let err = normalize_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 0).expect_err("prefix 0 is invalid");
	assert!(err.to_string().contains("invalid IPv4 prefix length 0"));
}

#[test]
fn normalize_cidr_rejects_ipv4_prefix_above_32() {
	let err = normalize_cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 33).expect_err("prefix 33 is invalid");
	assert!(err.to_string().contains("invalid IPv4 prefix length 33"));
}

#[test]
fn normalize_cidr_rejects_ipv6_prefix_above_128() {
	let addr = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("literal"));
	let err = normalize_cidr(addr, 129).expect_err("prefix 129 is invalid");
	assert!(err.to_string().contains("invalid IPv6 prefix length 129"));
}
