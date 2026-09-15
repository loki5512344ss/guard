use crate::filter::blacklist::Blacklist;
use crate::store::StateStore;
use futures::StreamExt;
use redis::AsyncCommands;
use redis::Msg;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

pub struct RedisStore {
    client: redis::Client,
}

#[derive(Deserialize)]
struct BlacklistEvent {
    ip: String,
    action: String,
    #[serde(default = "default_duration")]
    duration_secs: u64,
}

fn default_duration() -> u64 {
    300
}

impl RedisStore {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }
}

const BLACKLIST_CHANNEL: &str = "rampart:blacklist:events";
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Capped exponential backoff step: `prev` doubled, clamped to `max`.
fn next_backoff(prev: Duration, max: Duration) -> Duration {
    prev.saturating_mul(2).min(max)
}

/// What the outer reconnect loop should do after one pubsub session.
enum Flow {
    /// Shutdown requested — exit the task.
    Stop,
    /// Connection dropped or session failed — reconnect with backoff.
    Retry,
}

/// Resolves only when shutdown is truly requested (value `true`) or every
/// sender has been dropped; spurious non-shutdown notifications keep it pending
/// so it never cancels in-flight connect/subscribe work.
async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if shutdown.changed().await.is_err() || *shutdown.borrow_and_update() {
            return;
        }
    }
}

/// Blacklist pubsub subscriber with real reconnect: on connect/subscribe
/// failure or stream end it retries with capped exponential backoff (reset to
/// `BACKOFF_MIN` after each successfully applied message). Every await is
/// raced against the shutdown watch so the task stays cancellable.
pub async fn start_blacklist_sync(
    client: &redis::Client,
    blacklist: Arc<Blacklist>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        match subscribe_once(client, &blacklist, &mut shutdown, &mut backoff).await {
            Flow::Stop => {
                tracing::info!("shutting down blacklist subscriber");
                return;
            },
            Flow::Retry => {},
        }

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {},
            () = wait_for_shutdown(&mut shutdown) => {
                tracing::info!("shutting down blacklist subscriber");
                return;
            },
        }
        backoff = next_backoff(backoff, BACKOFF_MAX);
    }
}

/// One connect+subscribe+consume session. Sets `*backoff` to `BACKOFF_MIN`
/// whenever a message is applied, proving the link is healthy. Each blocking
/// await is raced against shutdown. (Connect+subscribe stay inline: the
/// `PubSub` type produced by `into_pubsub` is awkward to name in a split
/// helper's return type.)
async fn subscribe_once(
    client: &redis::Client,
    blacklist: &Blacklist,
    shutdown: &mut watch::Receiver<bool>,
    backoff: &mut Duration,
) -> Flow {
    #[allow(deprecated)]
    let conn = tokio::select! {
        connected = client.get_async_connection() => match connected {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("failed to connect to Redis for blacklist sync: {e}");
                return Flow::Retry;
            },
        },
        () = wait_for_shutdown(shutdown) => return Flow::Stop,
    };

    let mut pubsub = conn.into_pubsub();
    tokio::select! {
        subscribed = pubsub.subscribe(BLACKLIST_CHANNEL) => match subscribed {
            Ok(()) => tracing::info!("subscribed to {BLACKLIST_CHANNEL}"),
            Err(e) => {
                tracing::error!("failed to subscribe to blacklist events: {e}");
                return Flow::Retry;
            },
        },
        () = wait_for_shutdown(shutdown) => return Flow::Stop,
    }

    let mut stream = pubsub.on_message();
    loop {
        tokio::select! {
            maybe_msg = stream.next() => match maybe_msg {
                Some(msg) => {
                    if let Err(e) = handle_event(&msg, blacklist) {
                        tracing::error!("blacklist event error: {e}");
                    } else {
                        *backoff = BACKOFF_MIN;
                    }
                },
                None => {
                    tracing::error!("blacklist pubsub stream ended; resubscribing");
                    return Flow::Retry;
                },
            },
            () = wait_for_shutdown(shutdown) => return Flow::Stop,
        }
    }
}

fn handle_event(msg: &Msg, blacklist: &Blacklist) -> anyhow::Result<()> {
    let payload: String = msg.get_payload()?;
    let event: BlacklistEvent = serde_json::from_str(&payload)?;

    let ip: std::net::IpAddr = event.ip.parse()?;

    match event.action.as_str() {
        "ban" => {
            blacklist.add(ip, Duration::from_secs(event.duration_secs), "redis");
            tracing::info!("blacklist add via Redis: {}", event.ip);
        },
        "unban" => {
            blacklist.remove(ip);
            tracing::info!("blacklist remove via Redis: {}", event.ip);
        },
        a => anyhow::bail!("unknown action: {a}"),
    }
    Ok(())
}

impl StateStore for RedisStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        Ok(conn.get(key).await?)
    }

    async fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.set(key, value).await?;
        Ok(())
    }

    async fn del(&self, key: &str) -> anyhow::Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.del(key).await?;
        Ok(())
    }

    async fn publish(&self, channel: &str, message: &str) -> anyhow::Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.publish(channel, message).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_until_cap() {
        let mut b = BACKOFF_MIN;
        for expected_secs in [2, 4, 8, 16, 30, 30] {
            b = next_backoff(b, BACKOFF_MAX);
            assert_eq!(b, Duration::from_secs(expected_secs));
        }
    }

    #[test]
    fn backoff_never_exceeds_max_even_with_huge_prev() {
        let b = next_backoff(Duration::from_secs(u64::MAX / 2), BACKOFF_MAX);
        assert!(b <= BACKOFF_MAX);
    }
}
