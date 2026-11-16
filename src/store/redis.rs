//! Redis-backed [`StateStore`] and blacklist synchronisation.
//!
//! Commands share one reconnecting [`ConnectionManager`] and are bounded by
//! `connection::REDIS_TIMEOUT`; pub/sub connections are acquired and
//! subscribed under the same timeout.

use crate::store::StateStore;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;

mod backoff;
mod connection;
mod sync;

pub use backoff::{BACKOFF_MAX, BACKOFF_MIN, next_backoff};
pub use sync::{start_blacklist_sync, start_local_ban_publisher};

/// Redis-backed state store.
pub struct RedisStore {
	manager: ConnectionManager,
}

impl RedisStore {
	/// Connects to `url` and establishes a reconnecting manager.
	///
	/// # Errors
	/// Returns an error for an invalid URL, an unreachable server or an attempt
	/// that exceeds `connection::REDIS_TIMEOUT`.
	pub async fn new(url: &str) -> anyhow::Result<Self> {
		let client = redis::Client::open(url)?;
		let manager = connection::connection_manager(&client).await?;
		Ok(Self { manager })
	}
}

impl StateStore for RedisStore {
	async fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
		let mut conn = self.manager.clone();
		connection::command(conn.get(key)).await
	}

	async fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
		let mut conn = self.manager.clone();
		let _: () = connection::command(conn.set(key, value)).await?;
		Ok(())
	}

	async fn del(&self, key: &str) -> anyhow::Result<()> {
		let mut conn = self.manager.clone();
		let _: () = connection::command(conn.del(key)).await?;
		Ok(())
	}

	async fn publish(&self, channel: &str, message: &str) -> anyhow::Result<()> {
		let mut conn = self.manager.clone();
		let _: i64 = connection::command(conn.publish(channel, message)).await?;
		Ok(())
	}
}
