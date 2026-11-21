//! IPv6 LPM keys carry the address in network order right after the prefix length.
#![cfg(feature = "xdp")]

use std::net::{IpAddr, Ipv6Addr};

use rampart::xdp::{blacklist6_key, normalize_cidr, whitelist6_key};

#[test]
fn ipv6_keys_hold_the_network_order_bytes_of_the_address() {
	let addr: Ipv6Addr = "2001:db8:1234:5678:9abc:def0:1122:3344".parse().expect("ipv6");
	let wire = addr.octets();
	assert_eq!(
		wire[0..4],
		[0x20, 0x01, 0x0d, 0xb8],
		"sanity: octets() is network order"
	);

	for key in [blacklist6_key(128, &wire), whitelist6_key(128, &wire)] {
		assert_eq!(key[0..4], 128u32.to_le_bytes(), "prefixlen is a host-order (LE) u32");
		assert_eq!(key[4..20], wire, "address bytes are not byte-swapped");
	}
}

#[test]
fn masked_cidr_bytes_feed_the_key_in_network_order() {
	let addr: Ipv6Addr = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff".parse().expect("ipv6");
	let net = normalize_cidr(IpAddr::V6(addr), 48).expect("/48");
	let IpAddr::V6(net) = net else {
		unreachable!("a v6 prefix stays v6");
	};
	let key = blacklist6_key(48, &net.octets());
	assert_eq!(key[4..10], [0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xaa]);
	assert_eq!(key[10..20], [0u8; 10], "host bits cleared");
}
