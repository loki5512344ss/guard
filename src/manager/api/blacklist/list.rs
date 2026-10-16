use super::common::{
    BLACKLIST_KEY, BLACKLIST_METADATA_KEY, BlacklistMetadata, format_timestamp, legacy_metadata, redis_error,
    redis_unavailable,
};
use super::{BlacklistEntry, BlacklistResponse};
use crate::manager::AppState;
use axum::{Json, extract::State, http::StatusCode};
use redis::AsyncCommands;
use std::collections::HashMap;
use std::sync::Arc;

pub async fn list_blacklist(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BlacklistResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut conn = state
        .redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(redis_unavailable)?;
    let members: Vec<String> = redis::cmd("SMEMBERS")
        .arg(BLACKLIST_KEY)
        .query_async(&mut conn)
        .await
        .map_err(redis_error)?;
    let metadata: HashMap<String, String> = conn.hgetall(BLACKLIST_METADATA_KEY).await.map_err(redis_error)?;
    let now = chrono::Utc::now().timestamp();
    let mut items = Vec::with_capacity(members.len());

    for target in members {
        let Ok(ip) = target.parse::<std::net::IpAddr>() else {
            continue;
        };
        let record = match metadata.get(&target) {
            Some(encoded) => match serde_json::from_str::<BlacklistMetadata>(encoded) {
                Ok(record) => record,
                Err(_) => continue,
            },
            None => {
                let legacy = legacy_metadata(now);
                let encoded = serde_json::to_string(&legacy).map_err(|_| {
                    super::common::api_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to encode blacklist metadata")
                })?;
                let inserted: i64 = redis::cmd("HSETNX")
                    .arg(BLACKLIST_METADATA_KEY)
                    .arg(&target)
                    .arg(encoded)
                    .query_async(&mut conn)
                    .await
                    .map_err(redis_error)?;
                if inserted == 1 {
                    legacy
                } else {
                    let current: Option<String> =
                        conn.hget(BLACKLIST_METADATA_KEY, &target).await.map_err(redis_error)?;
                    match current.and_then(|value| serde_json::from_str(&value).ok()) {
                        Some(record) => record,
                        None => continue,
                    }
                }
            },
        };
        if record.expires_at_unix <= now
            || chrono::DateTime::from_timestamp(record.created_at_unix, 0).is_none()
            || chrono::DateTime::from_timestamp(record.expires_at_unix, 0).is_none()
        {
            continue;
        }
        items.push(BlacklistEntry {
            target: ip.to_string(),
            entry_type: "ip".to_string(),
            reason: record.reason,
            created_at: format_timestamp(record.created_at_unix),
            expires_at: Some(format_timestamp(record.expires_at_unix)),
        });
    }

    let total = items.len();
    Ok(Json(BlacklistResponse { items, total }))
}
