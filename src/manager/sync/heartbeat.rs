#[cfg(feature = "store-redis")]
use crate::manager::AppState;
#[cfg(feature = "store-redis")]
use futures::StreamExt;
#[cfg(feature = "store-redis")]
use redis::AsyncCommands;
#[cfg(feature = "store-redis")]
use redis::ScanOptions;
#[cfg(feature = "store-redis")]
use std::sync::Arc;
#[cfg(feature = "store-redis")]
use tokio::time::{Duration, interval};

/// SCAN pattern for node records (blocking KEYS is forbidden under load).
#[cfg(feature = "store-redis")]
const NODES_KEY_PATTERN: &str = "rampart:nodes:*";
/// SCAN COUNT hint per round.
#[cfg(feature = "store-redis")]
const SCAN_BATCH: usize = 100;
/// Node is offline when the last heartbeat is older than this.
#[cfg(any(feature = "store-redis", test))]
const NODE_TTL_SECS: i64 = 60;

#[cfg(feature = "store-redis")]
pub async fn start_heartbeat_check(state: Arc<AppState>) {
    let mut ticker = interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        if let Err(e) = check_nodes(&state).await {
            tracing::warn!("heartbeat check failed: {e}");
        }
    }
}

#[cfg(feature = "store-redis")]
async fn check_nodes(state: &AppState) -> anyhow::Result<()> {
    let mut conn = state.redis_client.get_multiplexed_async_connection().await?;
    let keys = collect_node_keys(&mut conn).await?;

    let now = chrono::Utc::now().timestamp();

    for key in &keys {
        let raw: Option<String> = conn.get(key).await?;
        let Some(updated) = raw.and_then(|json| offline_update(&json, now)) else {
            continue;
        };
        tracing::warn!("Node {key} is offline (heartbeat expired)");
        let _: () = conn.set(key.as_str(), updated).await.unwrap_or_default();
    }
    Ok(())
}

/// Incrementally iterates the keyspace via SCAN (cursor-based, non-blocking).
#[cfg(feature = "store-redis")]
async fn collect_node_keys(conn: &mut redis::aio::MultiplexedConnection) -> anyhow::Result<Vec<String>> {
    let opts = ScanOptions::default()
        .with_pattern(NODES_KEY_PATTERN)
        .with_count(SCAN_BATCH);
    let mut iter = conn.scan_options::<String>(opts).await?;
    let mut keys = Vec::new();
    while let Some(key) = iter.next().await {
        keys.push(key);
    }
    Ok(keys)
}

/// Pure decision: returns the updated node JSON with `status: "offline"` when
/// the RFC3339 `last_heartbeat` is older than `NODE_TTL_SECS` (a missing or
/// unparseable timestamp counts as expired, matching the previous behavior);
/// `None` when the node is fresh, unparsable, or not a JSON object.
#[cfg(any(feature = "store-redis", test))]
fn offline_update(raw: &str, now: i64) -> Option<String> {
    let mut node = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    let hb = node["last_heartbeat"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp())
        .unwrap_or(0);
    if now - hb <= NODE_TTL_SECS {
        return None;
    }
    node.as_object_mut()?
        .insert("status".to_string(), serde_json::Value::String("offline".to_string()));
    serde_json::to_string(&node).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(feature = "store-redis")]
    #[test]
    fn node_key_pattern_targets_rampart_nodes() {
        assert_eq!(NODES_KEY_PATTERN, "rampart:nodes:*");
    }
}
