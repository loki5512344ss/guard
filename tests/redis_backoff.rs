//! Integration tests for the Redis reconnect backoff policy.

// The backoff helpers live behind the optional `store-redis` feature, so this
// test target must be skipped when that feature is off (`cargo check
// --no-default-features --all-targets`, CI protocol-http job).
#![cfg(feature = "store-redis")]

use std::time::Duration;

use rampart::store::redis::{BACKOFF_MAX, BACKOFF_MIN, next_backoff};

#[test]
fn backoff_doubles_until_cap() {
	let mut backoff = BACKOFF_MIN;
	for expected_secs in [2, 4, 8, 16, 30, 30] {
		backoff = next_backoff(backoff, BACKOFF_MAX);
		assert_eq!(backoff, Duration::from_secs(expected_secs));
	}
}

#[test]
fn backoff_never_exceeds_max() {
	let backoff = next_backoff(Duration::from_secs(u64::MAX / 2), BACKOFF_MAX);
	assert!(backoff <= BACKOFF_MAX);
}
