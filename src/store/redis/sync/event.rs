use crate::filter::blacklist::Blacklist;
use redis::Msg;
use serde::Deserialize;
use std::time::Duration;

const MAX_BAN_DURATION_SECS: u64 = 31_536_000;

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
                Some(expires_at) => {
                    if chrono::DateTime::from_timestamp(expires_at, 0).is_none() {
                        anyhow::bail!("invalid blacklist event expiry timestamp");
                    }
                    let remaining = expires_at.saturating_sub(chrono::Utc::now().timestamp());
                    if remaining <= 0 {
                        blacklist.remove_redis(ip);
                        return Ok(());
                    }
                    let remaining = u64::try_from(remaining)?;
                    if remaining > MAX_BAN_DURATION_SECS {
                        anyhow::bail!("blacklist event expiry exceeds maximum duration");
                    }
                    Duration::from_secs(remaining)
                },
                None => Duration::from_secs(event.duration_secs),
            };
            blacklist.add_redis(ip, duration, "manager_event");
            tracing::info!("blacklist add via Redis: {}", event.ip);
        },
        "unban" => {
            blacklist.remove_redis(ip);
            tracing::info!("blacklist remove via Redis: {}", event.ip);
        },
        action => anyhow::bail!("unknown action: {action}"),
    }
    Ok(())
}
