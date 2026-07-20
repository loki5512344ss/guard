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

pub async fn start_blacklist_sync(
    client: &redis::Client,
    blacklist: Arc<Blacklist>,
    mut shutdown: watch::Receiver<bool>,
) {
    #[allow(deprecated)]
    let conn = match client.get_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to connect to Redis for blacklist sync: {e}");
            return;
        },
    };

    let mut pubsub = conn.into_pubsub();
    if let Err(e) = pubsub.subscribe("rampart:blacklist:events").await {
        tracing::error!("failed to subscribe to blacklist events: {e}");
        return;
    }
    tracing::info!("subscribed to rampart:blacklist:events");

    loop {
        let mut stream = pubsub.on_message();
        let msg_fut = stream.next();
        tokio::pin!(msg_fut);

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutting down blacklist subscriber");
                    return;
                }
            }
            result = &mut msg_fut => {
                match result {
                    Some(msg) => {
                        if let Err(e) = handle_event(&msg, &blacklist) {
                            tracing::error!("blacklist event error: {e}");
                        }
                    }
                    None => {
                        tracing::error!("pubsub stream ended");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        return;
                    }
                }
            }
        }
    }
}

fn handle_event(msg: &Msg, blacklist: &Blacklist) -> anyhow::Result<()> {
    let payload: String = msg.get_payload()?;
    let event: BlacklistEvent = serde_json::from_str(&payload)?;

    let ip_parts: Vec<&str> = event.ip.split('.').collect();
    if ip_parts.len() != 4 {
        anyhow::bail!("invalid IP: {}", event.ip);
    }
    let mut ip_u32: u32 = 0;
    for part in &ip_parts {
        let octet: u32 = part.parse()?;
        ip_u32 = (ip_u32 << 8) | octet;
    }

    match event.action.as_str() {
        "ban" => {
            blacklist.add(ip_u32, Duration::from_secs(event.duration_secs), "redis");
            tracing::info!("blacklist add via Redis: {}", event.ip);
        },
        "unban" => {
            blacklist.remove(ip_u32);
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
