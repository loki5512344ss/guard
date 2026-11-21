//! Decoding and validation of blacklist events received from Redis.
//!
//! A remote or stale manager must not be able to ban an address for an
//! arbitrary duration, so every ban is range-checked against
//! [`MAX_BAN_DURATION_SECS`] before it reaches the in-memory table.

use crate::filter::blacklist::{Blacklist, MAX_BAN_DURATION_SECS};
use redis::Msg;
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct BlacklistEvent {
	ip: String,
	action: String,
	#[serde(default = "default_duration")]
	duration_secs: u64,
	#[serde(default)]
	expires_at_unix: Option<i64>,
}

fn default_duration() -> u64 {
	300
}

pub(super) fn handle(msg: &Msg, blacklist: &Blacklist) -> anyhow::Result<()> {
	let payload: String = msg.get_payload()?;
	let event: BlacklistEvent = serde_json::from_str(&payload)?;
	let ip: std::net::IpAddr = event.ip.parse()?;

	match event.action.as_str() {
		"ban" => {
			let duration = match event.expires_at_unix {
				Some(expires_at) => absolute_duration(expires_at)?,
				None => checked_duration(event.duration_secs)?,
			};
			match duration {
				Some(duration) => {
					blacklist.add_redis(ip, duration, "manager_event");
					tracing::info!(ip = %event.ip, "blacklist add via Redis");
				},
				None => {
					blacklist.remove_redis(ip);
					tracing::info!(ip = %event.ip, "blacklist expiry already passed");
				},
			}
		},
		"unban" => {
			blacklist.remove_redis(ip);
			tracing::info!(ip = %event.ip, "blacklist remove via Redis");
		},
		action => anyhow::bail!("unknown blacklist action: {action}"),
	}
	Ok(())
}

/// Converts an absolute expiry into the remaining ban duration.
///
/// Returns `Ok(None)` when the expiry is already in the past.
fn absolute_duration(expires_at: i64) -> anyhow::Result<Option<Duration>> {
	if !crate::timeutil::is_valid_unix(expires_at) {
		anyhow::bail!("invalid blacklist event expiry timestamp");
	}
	let remaining = expires_at.saturating_sub(crate::timeutil::unix_now());
	if remaining <= 0 {
		return Ok(None);
	}
	let remaining = u64::try_from(remaining)?;
	if remaining > MAX_BAN_DURATION_SECS {
		anyhow::bail!("blacklist event expiry exceeds {MAX_BAN_DURATION_SECS}s");
	}
	Ok(Some(Duration::from_secs(remaining)))
}

/// Validates a relative ban duration.
fn checked_duration(secs: u64) -> anyhow::Result<Option<Duration>> {
	if secs > MAX_BAN_DURATION_SECS {
		anyhow::bail!("blacklist event duration {secs}s exceeds {MAX_BAN_DURATION_SECS}s");
	}
	if secs == 0 {
		return Ok(None);
	}
	Ok(Some(Duration::from_secs(secs)))
}
