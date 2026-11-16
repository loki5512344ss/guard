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
pub const NODES_KEY_PATTERN: &str = "rampart:nodes:*";
/// SCAN COUNT hint per round.
#[cfg(feature = "store-redis")]
const SCAN_BATCH: usize = 100;
/// Node is offline when the last heartbeat is older than this.
#[cfg(feature = "store-redis")]
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
		keys.push(key?);
	}
	Ok(keys)
}

/// Pure decision: returns the updated node JSON with `status: "offline"` when
/// the RFC3339 `last_heartbeat` is older than `NODE_TTL_SECS` (a missing or
/// unparseable timestamp counts as expired, matching the previous behavior);
/// `None` when the node is fresh, unparsable, or not a JSON object.
#[cfg(feature = "store-redis")]
pub fn offline_update(raw: &str, now: i64) -> Option<String> {
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
