//! Durable blacklist snapshot reconciliation.
//!
//! The snapshot is rebuilt from `rampart:blacklist` (set) and
//! `rampart:blacklist:metadata` (hash) after every (re)subscribe and then
//! swapped into the mirrored in-memory table.

use crate::filter::blacklist::{Blacklist, MAX_BAN_DURATION_SECS};
use crate::store::redis::connection::command;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

const BLACKLIST_KEY: &str = "rampart:blacklist";
const BLACKLIST_METADATA_KEY: &str = "rampart:blacklist:metadata";
const LEGACY_BAN_DURATION_SECS: i64 = 300;

#[derive(Deserialize, Serialize)]
struct BlacklistMetadata {
	created_at_unix: i64,
	expires_at_unix: i64,
	reason: String,
}

/// Restores current durable bans after subscribing to the event channel.
///
/// # Errors
/// Returns an error when Redis is unreachable, a command times out or a
/// recorded timestamp is outside the representable range.
pub(super) async fn reconcile(manager: &ConnectionManager, blacklist: &Blacklist) -> anyhow::Result<()> {
	let mut conn = manager.clone();
	let members: Vec<String> = command(redis::cmd("SMEMBERS").arg(BLACKLIST_KEY).query_async(&mut conn)).await?;
	let metadata: HashMap<String, String> = command(conn.hgetall(BLACKLIST_METADATA_KEY)).await?;
	let now = crate::timeutil::unix_now();
	let mut active = Vec::with_capacity(members.len());

	for target in members {
		let ip: std::net::IpAddr = match target.parse() {
			Ok(ip) => ip,
			Err(_) => continue,
		};
		let record = match metadata.get(&target) {
			Some(encoded) => match serde_json::from_str::<BlacklistMetadata>(encoded) {
				Ok(record) => record,
				Err(_) => continue,
			},
			None => match legacy_record(&mut conn, &target, now).await? {
				Some(record) => record,
				None => continue,
			},
		};
		if !crate::timeutil::is_valid_unix(record.created_at_unix)
			|| !crate::timeutil::is_valid_unix(record.expires_at_unix)
		{
			continue;
		}
		let remaining = record.expires_at_unix.saturating_sub(now);
		if remaining <= 0 {
			continue;
		}
		let remaining = u64::try_from(remaining)?;
		if remaining > MAX_BAN_DURATION_SECS {
			continue;
		}
		active.push((ip, Duration::from_secs(remaining), record.reason));
	}
	blacklist.replace_redis(active);
	Ok(())
}

/// Backfills metadata for a ban written by an older manager.
async fn legacy_record(
	conn: &mut ConnectionManager,
	target: &str,
	now: i64,
) -> anyhow::Result<Option<BlacklistMetadata>> {
	let legacy = BlacklistMetadata {
		created_at_unix: now,
		expires_at_unix: now.saturating_add(LEGACY_BAN_DURATION_SECS),
		reason: "legacy_unverified".to_string(),
	};
	let inserted: i64 = command(
		redis::cmd("HSETNX")
			.arg(BLACKLIST_METADATA_KEY)
			.arg(target)
			.arg(serde_json::to_string(&legacy)?)
			.query_async(conn),
	)
	.await?;
	if inserted == 1 {
		return Ok(Some(legacy));
	}
	let current: Option<String> = command(conn.hget(BLACKLIST_METADATA_KEY, target)).await?;
	Ok(current.and_then(|value| serde_json::from_str(&value).ok()))
}
