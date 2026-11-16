//! Node heartbeat expiry: a stale, missing or unparsable `last_heartbeat`
//! marks the node offline, while a fresh heartbeat leaves the record untouched.
#![cfg(feature = "store-redis")]

use rampart::manager::sync::heartbeat::{NODES_KEY_PATTERN, offline_update};

fn rfc3339(ts: i64) -> String {
	chrono::DateTime::from_timestamp(ts, 0)
		.expect("in-range timestamp")
		.to_rfc3339()
}

#[test]
fn expired_heartbeat_is_marked_offline() {
	let now = 2_000_000_i64;
	let raw = format!(
		r#"{{"name":"edge1","last_heartbeat":"{}","status":"online"}}"#,
		rfc3339(now - 120)
	);
	let updated = offline_update(&raw, now).expect("expired node should be marked offline");
	assert!(updated.contains("offline"));
	assert!(updated.contains("edge1"));
}

#[test]
fn fresh_heartbeat_is_left_untouched() {
	let now = 2_000_000_i64;
	let raw = format!(r#"{{"last_heartbeat":"{}","status":"online"}}"#, rfc3339(now - 5));
	assert!(offline_update(&raw, now).is_none());
}

#[test]
fn missing_or_broken_timestamp_counts_as_expired() {
	let now = 2_000_000_i64;
	let updated = offline_update(r#"{"status":"online"}"#, now).expect("missing heartbeat counts as expired");
	assert!(updated.contains("offline"));
	let updated = offline_update(r#"{"last_heartbeat":"garbage","status":"online"}"#, now)
		.expect("unparseable heartbeat counts as expired");
	assert!(updated.contains("offline"));
}

#[test]
fn invalid_json_is_ignored() {
	assert!(offline_update("not json", 2_000_000).is_none());
}

#[test]
fn node_key_pattern_targets_rampart_nodes() {
	assert_eq!(NODES_KEY_PATTERN, "rampart:nodes:*");
}
