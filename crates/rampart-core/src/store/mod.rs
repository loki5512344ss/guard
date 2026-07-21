#[cfg(feature = "store-redis")]
pub mod redis;
#[cfg(feature = "store-redis")]
pub use redis::start_blacklist_sync;

pub mod clickhouse;

#[allow(async_fn_in_trait)]
pub trait StateStore: Send + Sync {
    async fn get(&self, key: &str) -> anyhow::Result<Option<String>>;
    async fn set(&self, key: &str, value: &str) -> anyhow::Result<()>;
    async fn del(&self, key: &str) -> anyhow::Result<()>;
    async fn publish(&self, channel: &str, message: &str) -> anyhow::Result<()>;
}

pub struct NoopStore;

impl StateStore for NoopStore {
    async fn get(&self, _key: &str) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
    async fn set(&self, _key: &str, _value: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn del(&self, _key: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn publish(&self, _channel: &str, _message: &str) -> anyhow::Result<()> {
        Ok(())
    }
}
