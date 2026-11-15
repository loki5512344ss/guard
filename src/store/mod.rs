//! External state backends.
//!
//! Owns the [`StateStore`] contract plus the Redis implementation (blacklist
//! sync between nodes) and the ClickHouse event sink.

#[cfg(feature = "store-redis")]
pub mod redis;
#[cfg(feature = "store-redis")]
pub use redis::{start_blacklist_sync, start_local_ban_publisher};

pub mod clickhouse;

/// Common contract for an external state store.
#[allow(async_fn_in_trait)]
pub trait StateStore: Send + Sync {
	/// Reads `key`, returning `None` when it is absent.
	///
	/// # Errors
	/// Returns an error when the store is unreachable.
	async fn get(&self, key: &str) -> anyhow::Result<Option<String>>;

	/// Writes `value` under `key`, overwriting any previous value.
	///
	/// # Errors
	/// Returns an error when the store is unreachable.
	async fn set(&self, key: &str, value: &str) -> anyhow::Result<()>;

	/// Deletes `key`; deleting a missing key is not an error.
	///
	/// # Errors
	/// Returns an error when the store is unreachable.
	async fn del(&self, key: &str) -> anyhow::Result<()>;

	/// Publishes `message` to `channel` for subscribers to consume.
	///
	/// # Errors
	/// Returns an error when the store is unreachable.
	async fn publish(&self, channel: &str, message: &str) -> anyhow::Result<()>;
}
