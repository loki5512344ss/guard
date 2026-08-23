#[cfg(feature = "store-redis")]
pub mod redis;
#[cfg(feature = "store-redis")]
pub use redis::start_blacklist_sync;

pub mod clickhouse;

/// Общий контракт внешнего хранилища состояния.
#[allow(async_fn_in_trait)]
pub trait StateStore: Send + Sync {
    /// # Errors
    /// Возвращает ошибку при недоступности хранилища.
    async fn get(&self, key: &str) -> anyhow::Result<Option<String>>;

    /// # Errors
    /// Возвращает ошибку при недоступности хранилища.
    async fn set(&self, key: &str, value: &str) -> anyhow::Result<()>;

    /// # Errors
    /// Возвращает ошибку при недоступности хранилища.
    async fn del(&self, key: &str) -> anyhow::Result<()>;

    /// # Errors
    /// Возвращает ошибку при недоступности хранилища.
    async fn publish(&self, channel: &str, message: &str) -> anyhow::Result<()>;
}
