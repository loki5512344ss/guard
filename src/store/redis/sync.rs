mod event;
mod publisher;
mod snapshot;

pub use publisher::start_local_ban_publisher;

use crate::filter::blacklist::Blacklist;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const BLACKLIST_CHANNEL: &str = "rampart:blacklist:events";
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

fn next_backoff(prev: Duration, max: Duration) -> Duration {
    prev.saturating_mul(2).min(max)
}

enum Flow {
    Stop,
    Retry,
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if shutdown.changed().await.is_err() || *shutdown.borrow_and_update() {
            return;
        }
    }
}

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
        connected = client.get_async_pubsub() => match connected {
            Ok(pubsub) => pubsub,
            Err(e) => {
                tracing::error!("failed to connect to Redis for blacklist sync: {e}");
                return Flow::Retry;
            },
        },
        () = wait_for_shutdown(shutdown) => return Flow::Stop,
    };

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

    tokio::select! {
        loaded = snapshot::reconcile(client, blacklist) => match loaded {
            Ok(()) => tracing::info!("blacklist snapshot reconciled from Redis"),
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
                Some(msg) => {
                    if let Err(e) = event::handle(&msg, blacklist) {
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
