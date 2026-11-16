//! Blacklist synchronisation over a Redis pub/sub channel.
//!
//! The subscriber reconciles the durable snapshot on every (re)connect, then
//! applies events. All connects, subscribes and commands are timeout-bounded;
//! a failed attempt backs off exponentially and a panicking handler is logged
//! instead of killing the task.

mod event;
mod publisher;
mod snapshot;

pub use publisher::start_local_ban_publisher;

use super::backoff::{BACKOFF_MAX, BACKOFF_MIN, next_backoff};
use super::connection::{REDIS_TIMEOUT, connection_manager};
use crate::filter::blacklist::Blacklist;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const BLACKLIST_CHANNEL: &str = "rampart:blacklist:events";

/// Why a subscription attempt ended.
enum Flow {
	/// Shutdown was requested.
	Stop,
	/// The attempt failed; reconnect after a backoff delay.
	Retry,
}

/// Resolves once shutdown is requested or the channel is closed.
pub(super) async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
	loop {
		if shutdown.changed().await.is_err() || *shutdown.borrow_and_update() {
			return;
		}
	}
}

/// Runs the blacklist subscriber until shutdown.
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

async fn subscribe_once(
	client: &redis::Client,
	blacklist: &Blacklist,
	shutdown: &mut watch::Receiver<bool>,
	backoff: &mut Duration,
) -> Flow {
	let mut pubsub = tokio::select! {
		connected = tokio::time::timeout(REDIS_TIMEOUT, client.get_async_pubsub()) => match connected {
			Ok(Ok(pubsub)) => pubsub,
			Ok(Err(e)) => {
				tracing::error!("failed to connect to Redis for blacklist sync: {e}");
				return Flow::Retry;
			},
			Err(_) => {
				tracing::error!("timed out connecting to Redis for blacklist sync");
				return Flow::Retry;
			},
		},
		() = wait_for_shutdown(shutdown) => return Flow::Stop,
	};

	tokio::select! {
		subscribed = tokio::time::timeout(REDIS_TIMEOUT, pubsub.subscribe(BLACKLIST_CHANNEL)) => match subscribed {
			Ok(Ok(())) => {
				tracing::info!("subscribed to {BLACKLIST_CHANNEL}");
				*backoff = BACKOFF_MIN;
			},
			Ok(Err(e)) => {
				tracing::error!("failed to subscribe to blacklist events: {e}");
				return Flow::Retry;
			},
			Err(_) => {
				tracing::error!("timed out subscribing to blacklist events");
				return Flow::Retry;
			},
		},
		() = wait_for_shutdown(shutdown) => return Flow::Stop,
	}

	tokio::select! {
		loaded = reconcile(blacklist, client) => match loaded {
			Ok(()) => {
				tracing::info!("blacklist snapshot reconciled from Redis");
				*backoff = BACKOFF_MIN;
			},
			Err(e) => {
				tracing::error!("failed to reconcile blacklist snapshot: {e}");
				return Flow::Retry;
			},
		},
		() = wait_for_shutdown(shutdown) => return Flow::Stop,
	}

	let mut stream = pubsub.on_message();
	loop {
		tokio::select! {
			maybe_msg = stream.next() => match maybe_msg {
				Some(msg) => handle_message(&msg, blacklist, backoff),
				None => {
					tracing::error!("blacklist pubsub stream ended; resubscribing");
					return Flow::Retry;
				},
			},
			() = wait_for_shutdown(shutdown) => return Flow::Stop,
		}
	}
}

/// Handles one event without letting a rejected or panicking payload kill the
/// subscriber task.
fn handle_message(msg: &redis::Msg, blacklist: &Blacklist, backoff: &mut Duration) {
	let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| event::handle(msg, blacklist)));
	match handled {
		Ok(Ok(())) => *backoff = BACKOFF_MIN,
		Ok(Err(error)) => tracing::warn!(%error, "rejected blacklist event"),
		Err(_) => tracing::error!("blacklist event handler panicked; continuing"),
	}
}

async fn reconcile(blacklist: &Blacklist, client: &redis::Client) -> anyhow::Result<()> {
	let manager = connection_manager(client).await?;
	snapshot::reconcile(&manager, blacklist).await
}
