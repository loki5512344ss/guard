//! Blacklist endpoints: paginated listing plus add and remove mutations.

use serde::{Deserialize, Serialize};

/// Entries returned when the request does not set `limit`.
pub const DEFAULT_PAGE_LIMIT: u64 = 100;
/// Upper bound of `limit`, independent of the request.
pub const MAX_PAGE_LIMIT: u64 = 1000;
/// Upper bound of `offset`, which bounds the work of a single request.
pub const MAX_PAGE_OFFSET: u64 = 10_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct BlacklistEntry {
	pub target: String,
	#[serde(rename = "type")]
	pub entry_type: String,
	pub reason: String,
	pub created_at: String,
	pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct BlacklistResponse {
	pub items: Vec<BlacklistEntry>,
	pub total: u64,
}

#[derive(Deserialize)]
pub struct AddBlacklistRequest {
	pub target: String,
	#[serde(rename = "type")]
	pub entry_type: String,
	pub reason: String,
	pub duration_secs: Option<u64>,
	/// Absolute expiry in unix seconds; mutually exclusive with `duration_secs`.
	pub expires_at: Option<i64>,
}

#[derive(Deserialize)]
pub struct RemoveBlacklistRequest {
	pub target: String,
}

/// `limit`/`offset` query parameters of the list endpoint.
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
	pub limit: Option<u64>,
	pub offset: Option<u64>,
}

impl ListQuery {
	/// Resolves the request into `(offset, limit)` inside the hard bounds.
	///
	/// Missing values use [`DEFAULT_PAGE_LIMIT`] and zero, a too-large `limit`
	/// is clamped to [`MAX_PAGE_LIMIT`] and a too-large `offset` to
	/// [`MAX_PAGE_OFFSET`], so no request can ask for the whole set.
	#[must_use]
	pub fn bounds(&self) -> (u64, u64) {
		let limit = self.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
		let offset = self.offset.unwrap_or(0).min(MAX_PAGE_OFFSET);
		(offset, limit)
	}
}

#[cfg(feature = "store-redis")]
mod backfill;
#[cfg(feature = "store-redis")]
mod common;
#[cfg(feature = "store-redis")]
mod list;
#[cfg(feature = "store-redis")]
mod mutate;

#[cfg(feature = "store-redis")]
pub use backfill::backfill_legacy_metadata;
#[cfg(feature = "store-redis")]
pub use list::list_blacklist;
#[cfg(feature = "store-redis")]
pub use mutate::{add_blacklist, remove_blacklist};
