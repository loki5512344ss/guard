//! Whitelist LPM key layouts (`whitelist_map` / `whitelist6_map`).
//!
//! The kernel keys are `struct lpm_key` (8 bytes) and `struct lpm_key6`
//! (20 bytes): a little-endian u32 prefix length followed by the address in
//! network order. A drift here silently whitelists the wrong range.
#![cfg(feature = "xdp")]

use rampart::xdp::{whitelist_key, whitelist6_key};

const ADDR_V4: [u8; 4] = [10, 1, 2, 0];
const ADDR_V6_2001_DB8: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[test]
fn whitelist_key_is_prefix_len_then_address() {
	let key = whitelist_key(24, &ADDR_V4);

	assert_eq!(key.len(), 8);
	assert_eq!(u32::from_le_bytes(key[0..4].try_into().expect("4 bytes")), 24);
	assert_eq!(key[4..8], ADDR_V4, "address kept in network order");
}

#[test]
fn whitelist_key_matches_the_blacklist_layout() {
	assert_eq!(whitelist_key(32, &ADDR_V4), rampart::xdp::blacklist_key(32, &ADDR_V4));
}

#[test]
fn whitelist6_key_is_u32_prefix_len_then_16_address_bytes() {
	let key = whitelist6_key(64, &ADDR_V6_2001_DB8);

	assert_eq!(key.len(), 20);
	assert_eq!(u32::from_le_bytes(key[0..4].try_into().expect("4 bytes")), 64);
	assert_eq!(key[4..20], ADDR_V6_2001_DB8, "address kept in network order");
}

#[test]
fn whitelist6_key_does_not_confuse_leading_zeros_with_the_prefix_len() {
	let key = whitelist6_key(128, &[0u8; 16]);

	assert_eq!(u32::from_le_bytes(key[0..4].try_into().expect("4 bytes")), 128);
	assert_eq!(key[4..20], [0u8; 16]);
}
