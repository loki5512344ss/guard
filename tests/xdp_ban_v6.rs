//! Layout of the `blacklist6_map` key (LPM trie): the prefix length as a little-endian
//! u32 in bytes 0..4 plus the 16-byte address in network order (bytes 4..20).
//! No kernel needed: this exercises the pure key encoding function.
#![cfg(feature = "xdp")]

use rampart::xdp::blacklist6_key;

const ADDR_2001_DB8_1: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[test]
fn key_layout_for_128_prefix() {
	let key = blacklist6_key(128, &ADDR_2001_DB8_1);

	assert_eq!(key.len(), 20);
	assert_eq!(key[0], 128, "prefixlen goes first");
	assert_eq!(key[1..4], [0, 0, 0], "u32 LE padding stays zero");
	assert_eq!(key[4..20], ADDR_2001_DB8_1, "address kept in network order");
}

#[test]
fn key_layout_for_64_prefix() {
	let key = blacklist6_key(64, &ADDR_2001_DB8_1);

	assert_eq!(key[0], 64);
	assert_eq!(key[1..4], [0, 0, 0]);
	assert_eq!(key[4..20], ADDR_2001_DB8_1);
}

#[test]
fn leading_zero_address_is_not_confused_with_prefix_len() {
	// ::1 has fifteen zero bytes before the final one: the key must not consume any of them.
	let key = blacklist6_key(128, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

	assert_eq!(key[0], 128, "prefixlen is not overwritten by the address");
	assert_eq!(key[1..4], [0, 0, 0]);
	assert_eq!(key[4..19], [0u8; 15]);
	assert_eq!(key[19], 1);
}
