use crate::filter::blacklist::Blacklist;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

const BLACKLIST_KEY: &str = "rampart:blacklist";
const BLACKLIST_METADATA_KEY: &str = "rampart:blacklist:metadata";
const LEGACY_BAN_DURATION_SECS: i64 = 300;
const MAX_BAN_DURATION_SECS: i64 = 31_536_000;

#[derive(Deserialize, Serialize)]
struct BlacklistMetadata {
    created_at_unix: i64,
    expires_at_unix: i64,
    reason: String,
}

/// Restore current durable bans after subscribing to the event channel.
pub(super) async fn reconcile(client: &redis::Client, blacklist: &Blacklist) -> anyhow::Result<()> {
    let mut conn = client.get_multiplexed_async_connection().await?;
    let members: Vec<String> = redis::cmd("SMEMBERS").arg(BLACKLIST_KEY).query_async(&mut conn).await?;
    let metadata: HashMap<String, String> = conn.hgetall(BLACKLIST_METADATA_KEY).await?;
    let now = chrono::Utc::now().timestamp();
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
        if record.expires_at_unix <= now
            || chrono::DateTime::from_timestamp(record.created_at_unix, 0).is_none()
            || chrono::DateTime::from_timestamp(record.expires_at_unix, 0).is_none()
            || record.expires_at_unix.saturating_sub(now) > MAX_BAN_DURATION_SECS
        {
            continue;
        }
        let remaining = u64::try_from(record.expires_at_unix - now)?;
        active.push((ip, Duration::from_secs(remaining), record.reason));
    }
    blacklist.replace_redis(active);
    Ok(())
}

async fn legacy_record(
    conn: &mut redis::aio::MultiplexedConnection,
    target: &str,
    now: i64,
) -> anyhow::Result<Option<BlacklistMetadata>> {
    let legacy = BlacklistMetadata {
        created_at_unix: now,
        expires_at_unix: now.saturating_add(LEGACY_BAN_DURATION_SECS),
        reason: "legacy_unverified".to_string(),
    };
    let inserted: i64 = redis::cmd("HSETNX")
        .arg(BLACKLIST_METADATA_KEY)
        .arg(target)
        .arg(serde_json::to_string(&legacy)?)
        .query_async(conn)
        .await?;
    if inserted == 1 {
        return Ok(Some(legacy));
    }
    let current: Option<String> = conn.hget(BLACKLIST_METADATA_KEY, target).await?;
    Ok(current.and_then(|value| serde_json::from_str(&value).ok()))
}
