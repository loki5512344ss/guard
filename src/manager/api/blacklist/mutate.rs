use super::common::{
    ADD_BAN_SCRIPT, BLACKLIST_CHANNEL, BLACKLIST_KEY, BLACKLIST_METADATA_KEY, DEFAULT_BAN_DURATION_SECS,
    MAX_BAN_DURATION_SECS, REMOVE_BAN_SCRIPT, api_error, event_payload, parse_ip, redis_error, redis_unavailable,
};
use super::{AddBlacklistRequest, RemoveBlacklistRequest};
use crate::manager::AppState;
use axum::{Json, extract::State, http::StatusCode};
use std::sync::Arc;

pub async fn add_blacklist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddBlacklistRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip = parse_ip(&req.target)?;
    if req.entry_type != "ip" {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "only IP blacklist entries are supported",
        ));
    }
    let duration_secs = req.duration_secs.unwrap_or(DEFAULT_BAN_DURATION_SECS);
    if duration_secs == 0 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "duration_secs must be greater than zero",
        ));
    }
    if duration_secs > MAX_BAN_DURATION_SECS {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "duration_secs must not exceed one year",
        ));
    }

    let target = ip.to_string();
    let created_at_unix = chrono::Utc::now().timestamp();
    let metadata = super::common::BlacklistMetadata {
        created_at_unix,
        expires_at_unix: created_at_unix + duration_secs as i64,
        reason: req.reason.clone(),
    };
    let encoded_metadata = serde_json::to_string(&metadata)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to encode blacklist metadata"))?;
    let event = event_payload(&target, "ban", duration_secs, Some(metadata.expires_at_unix))?;
    let mut conn = state
        .redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_unavailable)?;
    let _: i64 = redis::cmd("EVAL")
        .arg(ADD_BAN_SCRIPT)
        .arg(3)
        .arg(BLACKLIST_KEY)
        .arg(BLACKLIST_METADATA_KEY)
        .arg(BLACKLIST_CHANNEL)
        .arg(&target)
        .arg(encoded_metadata)
        .arg(event)
        .query_async(&mut conn)
        .await
        .map_err(redis_error)?;

    tracing::info!("Added to blacklist: {} ({})", target, req.reason);
    Ok(Json(serde_json::json!({
        "status": "added",
        "target": target,
        "reason": req.reason,
        "duration_secs": duration_secs
    })))
}

pub async fn remove_blacklist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RemoveBlacklistRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip = parse_ip(&req.target)?;
    let target = ip.to_string();
    let event = event_payload(&target, "unban", 0, None)?;
    let mut conn = state
        .redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_unavailable)?;
    let _: i64 = redis::cmd("EVAL")
        .arg(REMOVE_BAN_SCRIPT)
        .arg(3)
        .arg(BLACKLIST_KEY)
        .arg(BLACKLIST_METADATA_KEY)
        .arg(BLACKLIST_CHANNEL)
        .arg(&target)
        .arg(event)
        .query_async(&mut conn)
        .await
        .map_err(redis_error)?;

    tracing::info!("Removed from blacklist: {target}");
    Ok(Json(serde_json::json!({"status": "removed", "target": target})))
}
