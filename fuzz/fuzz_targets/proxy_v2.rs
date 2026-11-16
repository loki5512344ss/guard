#![no_main]

//! Fuzz target for the inbound PROXY protocol v2 header parser.
//!
//! The parser runs before authentication on a connection controlled by a
//! trusted proxy, so arbitrary bytes must produce an error, never a panic or
//! an out-of-bounds read.

use libfuzzer_sys::fuzz_target;
use rampart::engine::tunnel::parse_v2_header;

fuzz_target!(|data: &[u8]| {
	const LIMIT: usize = 512;
	if let Ok((client, consumed)) = parse_v2_header(data, LIMIT) {
		assert!(consumed <= data.len(), "parser consumed more than the buffer");
		assert!(consumed <= LIMIT, "parser accepted a header above the limit");
		assert!(consumed >= 16, "a parsed header is at least the fixed part");
		// The address must be in the family advertised by the header byte.
		let family = data[13];
		assert!(
			(family == 0x11 && client.is_ipv4()) || (family == 0x21 && client.is_ipv6()),
			"address family does not match the header"
		);
	}
});
