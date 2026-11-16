#![no_main]

//! Fuzz target for the HTTP/1.x request-head parser.
//!
//! `scan_head` and `evaluate` consume attacker-controlled bytes on every
//! connection, so they must never panic and must stay within the buffer.

use libfuzzer_sys::fuzz_target;
use rampart::protocol::http::parser::{Policy, evaluate, scan_head};

fuzz_target!(|data: &[u8]| {
	if let Some(head_len) = scan_head(data) {
		assert!(head_len <= data.len(), "scan_head returned an out-of-bounds length");
		let policy = Policy {
			max_header_bytes: 8192,
			blocked_paths: vec!["/admin".to_string()],
			require_user_agent: true,
		};
		let _ = evaluate(&data[..head_len], &policy);
	}

	// The whole buffer (not only a terminated head) must also be safe: a
	// truncated head is evaluated defensively by callers.
	let policy = Policy {
		max_header_bytes: 8192,
		blocked_paths: vec![],
		require_user_agent: false,
	};
	let _ = evaluate(data, &policy);
});
