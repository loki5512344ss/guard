//! Pure HTTP/1.x request-head parser: head scanning, method/host/version
//! validation, path blocklist and the user-agent requirement.
#![cfg(feature = "protocol-http")]

use rampart::protocol::http::parser::{Policy, Verdict, evaluate, scan_head};

fn policy() -> Policy {
	Policy {
		max_header_bytes: 8192,
		blocked_paths: Vec::new(),
		require_user_agent: false,
	}
}

#[test]
fn scan_finds_full_head_length() {
	assert_eq!(scan_head(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
	assert_eq!(scan_head(b"GET / HTTP/1.1\r\n"), None);
}

#[test]
fn valid_request_is_allowed() {
	let head = b"POST /api/items?limit=5 HTTP/1.1\r\nHost: example.com\r\n\r\n";
	let verdict = evaluate(head, &policy());
	assert_eq!(
		verdict,
		Verdict::Allow {
			method: "POST".to_string(),
			path: "/api/items".to_string(),
			host: "example.com".to_string()
		}
	);
}

#[test]
fn unknown_method_is_rejected() {
	let head = b"TRACE / HTTP/1.1\r\nHost: h\r\n\r\n";
	assert!(matches!(evaluate(head, &policy()), Verdict::Reject { .. }));
}

#[test]
fn missing_host_is_rejected() {
	let head = b"GET / HTTP/1.1\r\nUser-Agent: t\r\n\r\n";
	assert!(matches!(evaluate(head, &policy()), Verdict::Reject { .. }));
}

#[test]
fn http2_version_is_rejected() {
	let head = b"GET / HTTP/2.0\r\nHost: h\r\n\r\n";
	assert!(matches!(evaluate(head, &policy()), Verdict::Reject { .. }));
}

#[test]
fn malformed_line_is_rejected() {
	assert!(matches!(
		evaluate(b"nonsense\r\n\r\n", &policy()),
		Verdict::Reject { .. }
	));
	assert!(matches!(
		evaluate(b"GET / HTTP/1.1\r\nbroken\r\n\r\n", &policy()),
		Verdict::Reject { .. }
	));
}

#[test]
fn non_utf8_head_is_rejected() {
	assert!(matches!(evaluate(&[0xff, 0xfe], &policy()), Verdict::Reject { .. }));
}

#[test]
fn blocked_path_prefix_is_rejected() {
	let mut custom = policy();
	custom.blocked_paths = vec!["/admin".to_string()];
	assert!(matches!(
		evaluate(b"GET /admin/panel HTTP/1.1\r\nHost: h\r\n\r\n", &custom),
		Verdict::Reject { .. }
	));
	assert!(matches!(
		evaluate(b"GET /public HTTP/1.1\r\nHost: h\r\n\r\n", &custom),
		Verdict::Allow { .. }
	));
}

#[test]
fn required_user_agent_enforced() {
	let mut custom = policy();
	custom.require_user_agent = true;
	let head = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
	assert!(matches!(evaluate(head, &custom), Verdict::Reject { .. }));
	let head_with_ua = b"GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\n\r\n";
	assert!(matches!(evaluate(head_with_ua, &custom), Verdict::Allow { .. }));
}
