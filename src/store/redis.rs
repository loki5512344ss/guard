use crate::store::StateStore;
use redis::AsyncCommands;

mod sync;
pub use sync::{start_blacklist_sync, start_local_ban_publisher};

pub struct RedisStore {
    client: redis::Client,
}

impl RedisStore {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }
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
