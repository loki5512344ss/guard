use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};

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
pub(super) const ADD_BAN_SCRIPT: &str = "redis.call('HSET', KEYS[2], ARGV[1], ARGV[2]); redis.call('SADD', KEYS[1], ARGV[1]); redis.call('PUBLISH', KEYS[3], ARGV[3]); return 1";
pub(super) const REMOVE_BAN_SCRIPT: &str = "redis.call('SREM', KEYS[1], ARGV[1]); redis.call('HDEL', KEYS[2], ARGV[1]); redis.call('PUBLISH', KEYS[3], ARGV[2]); return 1";

pub(super) fn legacy_metadata(now: i64) -> BlacklistMetadata {
    BlacklistMetadata {
        created_at_unix: now,
        expires_at_unix: now.saturating_add(LEGACY_BAN_DURATION_SECS as i64),
        reason: "legacy_unverified".to_string(),
    }
}

pub(super) fn format_timestamp(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
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

pub(super) fn parse_ip(target: &str) -> Result<std::net::IpAddr, (StatusCode, Json<serde_json::Value>)> {
    target
        .parse()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "target must be an IP address"))
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
