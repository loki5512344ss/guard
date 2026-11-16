//! `GET /api/v1/blacklist`: paginated, read-only view of the Redis bans.
//!
//! The endpoint never writes: legacy members keep showing a read-only fallback
//! record and are persisted by [`super::backfill_legacy_metadata`] at startup,
//! so retries and shared caches see an idempotent response.

use super::common::{
	BLACKLIST_KEY, BLACKLIST_METADATA_KEY, BlacklistMetadata, PAGE_SCAN_BATCH, format_timestamp, legacy_metadata,
	redis_error, redis_unavailable,
};
use super::{BlacklistEntry, BlacklistResponse, ListQuery};
use crate::manager::AppState;
use axum::{
	Json,
	extract::{Query, State},
	http::StatusCode,
};
use redis::aio::MultiplexedConnection;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

type ApiResult<T> = Result<T, (StatusCode, Json<serde_json::Value>)>;

pub async fn list_blacklist(
	State(state): State<Arc<AppState>>,
	Query(query): Query<ListQuery>,
) -> ApiResult<Json<BlacklistResponse>> {
	let (offset, limit) = query.bounds();
	let mut conn = state
		.redis_client
		.get_multiplexed_async_connection()
		.await
		.map_err(redis_unavailable)?;
	let total: u64 = redis::cmd("SCARD")
		.arg(BLACKLIST_KEY)
		.query_async(&mut conn)
		.await
		.map_err(redis_error)?;
	if limit == 0 {
		return Ok(Json(BlacklistResponse {
			items: Vec::new(),
			total,
		}));
	}

	// SSCAN is capped at the requested window, so the set is never materialised.
	let targets = scan_targets(&mut conn, offset.saturating_add(limit)).await?;
	let page: Vec<String> = targets
		.into_iter()
		.skip(usize::try_from(offset).unwrap_or(usize::MAX))
		.take(usize::try_from(limit).unwrap_or(usize::MAX))
		.collect();
	let metadata = load_metadata(&mut conn, &page).await?;
	let now = chrono::Utc::now().timestamp();
	let items = page
		.iter()
		.filter_map(|target| entry(target, metadata.get(target), now))
		.collect();
	Ok(Json(BlacklistResponse { items, total }))
}

/// Collects at most `wanted` set members with SSCAN.
async fn scan_targets(conn: &mut MultiplexedConnection, wanted: u64) -> ApiResult<Vec<String>> {
	let mut targets = Vec::new();
	let mut cursor = 0_u64;
	loop {
		let (next, batch): (u64, Vec<String>) = redis::cmd("SSCAN")
			.arg(BLACKLIST_KEY)
			.arg(cursor)
			.arg("COUNT")
			.arg(PAGE_SCAN_BATCH)
			.query_async(conn)
			.await
			.map_err(redis_error)?;
		targets.extend(batch);
		cursor = next;
		if cursor == 0 || u64::try_from(targets.len()).unwrap_or(u64::MAX) >= wanted {
			return Ok(targets);
		}
	}
}

/// Fetches metadata for `targets` in HMGET batches.
///
/// A present key with an unparseable record maps to `None`, which the caller
/// skips; an absent key means the member predates metadata and gets a fallback.
async fn load_metadata(
	conn: &mut MultiplexedConnection,
	targets: &[String],
) -> ApiResult<HashMap<String, Option<BlacklistMetadata>>> {
	let mut metadata = HashMap::with_capacity(targets.len());
	for chunk in targets.chunks(PAGE_SCAN_BATCH) {
		let values: Vec<Option<String>> = redis::cmd("HMGET")
			.arg(BLACKLIST_METADATA_KEY)
			.arg(chunk)
			.query_async(conn)
			.await
			.map_err(redis_error)?;
		for (target, encoded) in chunk.iter().zip(values) {
			metadata.insert(
				target.clone(),
				encoded.and_then(|value| serde_json::from_str(&value).ok()),
			);
		}
	}
	Ok(metadata)
}

/// Builds one response entry, dropping expired and malformed records.
fn entry(target: &str, metadata: Option<&Option<BlacklistMetadata>>, now: i64) -> Option<BlacklistEntry> {
	let ip: IpAddr = target.parse().ok()?;
	let record = match metadata {
		Some(Some(record)) => record.clone(),
		Some(None) => return None,
		None => legacy_metadata(now),
	};
	if record.expires_at_unix <= now
		|| chrono::DateTime::from_timestamp(record.created_at_unix, 0).is_none()
		|| chrono::DateTime::from_timestamp(record.expires_at_unix, 0).is_none()
	{
		return None;
	}
	Some(BlacklistEntry {
		target: ip.to_string(),
		entry_type: "ip".to_string(),
		reason: record.reason,
		created_at: format_timestamp(record.created_at_unix),
		expires_at: Some(format_timestamp(record.expires_at_unix)),
	})
}
