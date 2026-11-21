//! Shared keys, metadata records and request validation of the blacklist API.

use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize)]
pub(super) struct BlacklistEvent<'a> {
	ip: &'a str,
	action: &'a str,
	duration_secs: u64,
	#[serde(skip_serializing_if = "Option::is_none")]
	expires_at_unix: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct BlacklistMetadata {
	pub created_at_unix: i64,
	pub expires_at_unix: i64,
	pub reason: String,
}

pub(super) const BLACKLIST_KEY: &str = "rampart:blacklist";
pub(super) const BLACKLIST_METADATA_KEY: &str = "rampart:blacklist:metadata";
pub(super) const BLACKLIST_CHANNEL: &str = "rampart:blacklist:events";
pub(super) const DEFAULT_BAN_DURATION_SECS: u64 = 300;
pub(super) const LEGACY_BAN_DURATION_SECS: u64 = 300;
pub(super) const MAX_BAN_DURATION_SECS: u64 = 31_536_000;
/// Maximum accepted length of a ban reason, in bytes.
pub(super) const MAX_REASON_BYTES: usize = 256;
/// Batch size of SSCAN/HMGET/MGET calls on the blacklist.
pub(super) const PAGE_SCAN_BATCH: usize = 100;
pub(super) const ADD_BAN_SCRIPT: &str = "redis.call('HSET', KEYS[2], ARGV[1], ARGV[2]); redis.call('SADD', KEYS[1], ARGV[1]); redis.call('PUBLISH', KEYS[3], ARGV[3]); return 1";
pub(super) const REMOVE_BAN_SCRIPT: &str = "redis.call('SREM', KEYS[1], ARGV[1]); redis.call('HDEL', KEYS[2], ARGV[1]); redis.call('PUBLISH', KEYS[3], ARGV[2]); return 1";

/// Metadata shown for a set member written by an older manager.
///
/// The read path only displays this record; persisting it is the job of the
/// startup backfill, so a GET never writes to Redis.
pub(super) fn legacy_metadata(now: i64) -> BlacklistMetadata {
	BlacklistMetadata {
		created_at_unix: now,
		expires_at_unix: now.saturating_add(LEGACY_BAN_DURATION_SECS as i64),
		reason: "legacy_unverified".to_string(),
	}
}

pub(super) fn format_timestamp(timestamp: i64) -> String {
	crate::timeutil::format_rfc3339(timestamp).unwrap_or_else(crate::timeutil::now_rfc3339)
}

pub(super) fn event_payload(
	ip: &str,
	action: &str,
	duration_secs: u64,
	expires_at_unix: Option<i64>,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
	serde_json::to_string(&BlacklistEvent {
		ip,
		action,
		duration_secs,
		expires_at_unix,
	})
	.map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to serialize blacklist event"))
}

/// Validates the `target` of a mutate request.
///
/// The Redis ban snapshot is keyed by a single address, so a CIDR network is
/// syntactically valid but unsupported and is rejected with an explicit message
/// instead of being stored as an entry the edges cannot apply.
pub(super) fn validate_target(target: &str) -> Result<IpAddr, (StatusCode, Json<serde_json::Value>)> {
	let target = target.trim();
	if let Ok(ip) = target.parse::<IpAddr>() {
		return Ok(ip);
	}
	if crate::manager::security::IpNet::parse(target).is_ok() {
		return Err(api_error(
			StatusCode::BAD_REQUEST,
			"CIDR targets are not supported; ban a single IP address",
		));
	}
	Err(api_error(
		StatusCode::BAD_REQUEST,
		"target must be a valid IPv4 or IPv6 address",
	))
}

/// Rejects a `reason` longer than [`MAX_REASON_BYTES`] bytes.
pub(super) fn validate_reason(reason: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
	if reason.len() > MAX_REASON_BYTES {
		return Err(api_error(StatusCode::BAD_REQUEST, "reason must not exceed 256 bytes"));
	}
	Ok(())
}

pub(super) fn api_error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
	(status, Json(serde_json::json!({"error": message})))
}

pub(super) fn redis_unavailable(_: redis::RedisError) -> (StatusCode, Json<serde_json::Value>) {
	api_error(StatusCode::SERVICE_UNAVAILABLE, "redis unavailable")
}

pub(super) fn redis_error(error: redis::RedisError) -> (StatusCode, Json<serde_json::Value>) {
	tracing::error!("Blacklist Redis operation failed: {error}");
	api_error(StatusCode::SERVICE_UNAVAILABLE, "redis operation failed")
}
