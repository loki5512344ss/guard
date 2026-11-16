//! Manager API inventory: health, nodes and servers.
//!
//! Owns the read-side endpoints that describe the fleet as the manager sees it,
//! plus the shared SCAN/MGET reader that keeps those reads non-blocking.

pub mod health;
pub mod nodes;
pub mod servers;

/// SCAN and MGET batch size of a fleet read.
#[cfg(feature = "store-redis")]
const READ_BATCH: usize = 100;

/// Reads every value stored under `pattern` via SCAN and batched MGET.
///
/// SCAN is used instead of `KEYS` because the latter blocks Redis for every
/// edge in the fleet. Values are fetched in MGET batches instead of one GET per
/// key, so a large fleet costs a bounded number of round trips.
///
/// # Errors
/// Returns the Redis error unchanged: the caller answers 503, because an empty
/// fleet and an unreachable store must stay distinguishable.
#[cfg(feature = "store-redis")]
pub(super) async fn scan_values(
	conn: &mut redis::aio::MultiplexedConnection,
	pattern: &str,
) -> redis::RedisResult<Vec<String>> {
	use futures::StreamExt;
	use redis::AsyncCommands;

	let opts = redis::ScanOptions::default()
		.with_pattern(pattern)
		.with_count(READ_BATCH);
	let mut iter = conn.scan_options::<String>(opts).await?;
	let mut keys = Vec::new();
	while let Some(key) = iter.next().await {
		keys.push(key?);
	}
	drop(iter);

	let mut values = Vec::with_capacity(keys.len());
	for chunk in keys.chunks(READ_BATCH) {
		let batch: Vec<Option<String>> = redis::cmd("MGET").arg(chunk).query_async(conn).await?;
		values.extend(batch.into_iter().flatten());
	}
	Ok(values)
}

/// Parses every value that is a valid JSON record, skipping corrupt entries.
#[cfg(feature = "store-redis")]
pub(super) fn decode_all<T: serde::de::DeserializeOwned>(values: &[String]) -> Vec<T> {
	values
		.iter()
		.filter_map(|value| serde_json::from_str(value).ok())
		.collect()
}

/// Maps a Redis read failure to 503 so it cannot be mistaken for an empty fleet.
#[cfg(feature = "store-redis")]
pub(super) fn unavailable(error: &redis::RedisError) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
	tracing::error!("inventory Redis read failed: {error}");
	(
		axum::http::StatusCode::SERVICE_UNAVAILABLE,
		axum::Json(serde_json::json!({"error": "redis unavailable"})),
	)
}
