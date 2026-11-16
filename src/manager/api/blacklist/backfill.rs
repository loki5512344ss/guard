//! One-shot startup backfill of legacy blacklist metadata.
//!
//! Older managers wrote `rampart:blacklist` members without a record in
//! `rampart:blacklist:metadata`. The read path is side-effect free now, so the
//! repair happens once at startup instead of on every `GET`: set members are
//! iterated with SSCAN, read in HMGET batches and filled with HSETNX, which
//! never overwrites metadata written by a concurrent add.

use super::common::{
	BLACKLIST_KEY, BLACKLIST_METADATA_KEY, PAGE_SCAN_BATCH, legacy_metadata, redis_error, redis_unavailable,
};
use crate::manager::{AppState, SharedState};
use axum::{Json, http::StatusCode};
use std::net::IpAddr;

type ApiResult<T> = Result<T, (StatusCode, Json<serde_json::Value>)>;

/// Repairs legacy members in the background; failures are logged, not fatal.
pub async fn backfill_legacy_metadata(state: SharedState) {
	match backfill(&state).await {
		Ok(0) => {},
		Ok(filled) => tracing::info!("blacklist metadata backfill repaired {filled} legacy entries"),
		Err((_, Json(body))) => tracing::warn!("blacklist metadata backfill skipped: {body}"),
	}
}

/// Walks the ban set and persists fallback metadata for members without any.
///
/// Returns the number of repaired members. A Redis failure aborts the run: the
/// next manager start retries, and the read path keeps serving meanwhile.
async fn backfill(state: &AppState) -> ApiResult<usize> {
	let mut conn = state
		.redis_client
		.get_multiplexed_async_connection()
		.await
		.map_err(redis_unavailable)?;
	let now = chrono::Utc::now().timestamp();
	let mut cursor = 0_u64;
	let mut filled = 0_usize;
	loop {
		let (next, members): (u64, Vec<String>) = redis::cmd("SSCAN")
			.arg(BLACKLIST_KEY)
			.arg(cursor)
			.arg("COUNT")
			.arg(PAGE_SCAN_BATCH)
			.query_async(&mut conn)
			.await
			.map_err(redis_error)?;
		let targets: Vec<String> = members
			.into_iter()
			.filter(|target| target.parse::<IpAddr>().is_ok())
			.collect();
		if !targets.is_empty() {
			let existing: Vec<Option<String>> = redis::cmd("HMGET")
				.arg(BLACKLIST_METADATA_KEY)
				.arg(&targets)
				.query_async(&mut conn)
				.await
				.map_err(redis_error)?;
			for (target, encoded) in targets.iter().zip(existing) {
				if encoded.is_some() {
					continue;
				}
				let encoded = serde_json::to_string(&legacy_metadata(now)).map_err(|_| {
					super::common::api_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to encode blacklist metadata")
				})?;
				let _: i64 = redis::cmd("HSETNX")
					.arg(BLACKLIST_METADATA_KEY)
					.arg(target)
					.arg(encoded)
					.query_async(&mut conn)
					.await
					.map_err(redis_error)?;
				filled += 1;
			}
		}
		cursor = next;
		if cursor == 0 {
			return Ok(filled);
		}
	}
}
