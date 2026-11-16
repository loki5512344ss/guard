//! Timeout-bounded Redis connection helpers.
//!
//! Every connect and command in the store layer goes through this module so a
//! stalled server can never block a data-plane or shutdown path.

use redis::aio::ConnectionManager;
use std::future::Future;
use std::time::Duration;

/// Maximum time spent on one Redis connect or command.
pub const REDIS_TIMEOUT: Duration = Duration::from_secs(2);

/// Opens a reconnecting connection manager, bounded by `REDIS_TIMEOUT`.
///
/// # Errors
/// Returns an error for an unreachable server or a timed-out attempt.
pub async fn connection_manager(client: &redis::Client) -> anyhow::Result<ConnectionManager> {
	match tokio::time::timeout(REDIS_TIMEOUT, client.get_connection_manager()).await {
		Ok(result) => Ok(result?),
		Err(_) => anyhow::bail!("redis connection timed out after {REDIS_TIMEOUT:?}"),
	}
}

/// Awaits a Redis command future, bounded by `REDIS_TIMEOUT`.
///
/// # Errors
/// Returns an error when the command fails or exceeds the timeout.
pub async fn command<F, T>(future: F) -> anyhow::Result<T>
where
	F: Future<Output = redis::RedisResult<T>>,
{
	match tokio::time::timeout(REDIS_TIMEOUT, future).await {
		Ok(result) => Ok(result?),
		Err(_) => anyhow::bail!("redis command timed out after {REDIS_TIMEOUT:?}"),
	}
}
