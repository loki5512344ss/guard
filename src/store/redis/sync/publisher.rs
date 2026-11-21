//! Publishes locally detected bans to Redis.
//!
//! Each ban is stored atomically (set member, metadata hash, event publish) via
//! a Lua script on a shared reconnecting connection. Failed publishes retry
//! with exponential backoff and abandon the event when shutdown is requested.

use super::wait_for_shutdown;
use crate::filter::blacklist::{Blacklist, LocalBanEvent};
use crate::store::redis::backoff::{BACKOFF_MAX, BACKOFF_MIN, next_backoff};
use crate::store::redis::connection::{command, connection_manager};
use redis::aio::ConnectionManager;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

const BLACKLIST_KEY: &str = "rampart:blacklist";
const BLACKLIST_METADATA_KEY: &str = "rampart:blacklist:metadata";
const BLACKLIST_CHANNEL: &str = "rampart:blacklist:events";
const STORE_BAN_SCRIPT: &str = "redis.call('HSET', KEYS[2], ARGV[1], ARGV[2]); redis.call('SADD', KEYS[1], ARGV[1]); redis.call('PUBLISH', KEYS[3], ARGV[3]); return 1";

#[derive(Serialize)]
struct BanMetadata<'a> {
	created_at_unix: i64,
	expires_at_unix: i64,
	reason: &'a str,
}

#[derive(Serialize)]
struct BanEvent<'a> {
	ip: String,
	action: &'static str,
	duration_secs: u64,
	expires_at_unix: i64,
	reason: &'a str,
}

/// Publishes local bans and the current local snapshot until shutdown.
pub async fn start_local_ban_publisher(
	client: redis::Client,
	blacklist: Arc<Blacklist>,
	mut events: broadcast::Receiver<LocalBanEvent>,
	mut shutdown: watch::Receiver<bool>,
) {
	let mut manager: Option<ConnectionManager> = None;
	for event in blacklist.local_snapshot() {
		if !publish_with_retry(&client, &mut manager, event, &mut shutdown).await {
			return;
		}
	}

	loop {
		tokio::select! {
			received = events.recv() => match received {
				Ok(event) => {
					if !publish_with_retry(&client, &mut manager, event, &mut shutdown).await {
						return;
					}
				},
				Err(broadcast::error::RecvError::Lagged(skipped)) => {
					tracing::warn!(skipped, "local ban publisher lagged; reconciling active local bans");
					for event in blacklist.local_snapshot() {
						if !publish_with_retry(&client, &mut manager, event, &mut shutdown).await {
							return;
						}
					}
				},
				Err(broadcast::error::RecvError::Closed) => return,
			},
			changed = shutdown.changed() => {
				if changed.is_err() || *shutdown.borrow_and_update() {
					return;
				}
			},
		}
	}
}

/// Publishes one event, retrying until it succeeds or shutdown is requested.
async fn publish_with_retry(
	client: &redis::Client,
	manager: &mut Option<ConnectionManager>,
	event: LocalBanEvent,
	shutdown: &mut watch::Receiver<bool>,
) -> bool {
	let mut delay = BACKOFF_MIN;
	loop {
		let result = tokio::select! {
			result = publish_ban(client, manager, &event) => result,
			() = wait_for_shutdown(shutdown) => return false,
		};
		match result {
			Ok(()) => return true,
			Err(error) => {
				// Force a reconnect on the next attempt.
				*manager = None;
				tracing::warn!(%error, ip = %event.ip, "failed to persist local ban; retrying");
			},
		}
		tokio::select! {
			_ = tokio::time::sleep(delay) => delay = next_backoff(delay, BACKOFF_MAX),
			changed = shutdown.changed() => {
				if changed.is_err() || *shutdown.borrow_and_update() {
					return false;
				}
			},
		}
	}
}

async fn publish_ban(
	client: &redis::Client,
	manager: &mut Option<ConnectionManager>,
	event: &LocalBanEvent,
) -> anyhow::Result<()> {
	let now = crate::timeutil::unix_now();
	let remaining = event.expires_at_unix.saturating_sub(now);
	if remaining <= 0 {
		return Ok(());
	}
	let metadata = serde_json::to_string(&BanMetadata {
		created_at_unix: now,
		expires_at_unix: event.expires_at_unix,
		reason: &event.reason,
	})?;
	let payload = serde_json::to_string(&BanEvent {
		ip: event.ip.to_string(),
		action: "ban",
		duration_secs: u64::try_from(remaining)?,
		expires_at_unix: event.expires_at_unix,
		reason: &event.reason,
	})?;
	let mut conn = match manager {
		Some(conn) => conn.clone(),
		None => {
			let conn = connection_manager(client).await?;
			*manager = Some(conn.clone());
			conn
		},
	};
	let _: i64 = command(
		redis::cmd("EVAL")
			.arg(STORE_BAN_SCRIPT)
			.arg(3)
			.arg(BLACKLIST_KEY)
			.arg(BLACKLIST_METADATA_KEY)
			.arg(BLACKLIST_CHANNEL)
			.arg(event.ip.to_string())
			.arg(metadata)
			.arg(payload)
			.query_async(&mut conn),
	)
	.await?;
	Ok(())
}
