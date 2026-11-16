//! Exponential reconnect backoff shared by the Redis sync tasks.

use std::time::Duration;

/// Initial reconnect delay.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Upper bound for the reconnect delay.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Doubles `previous`, capped at `max`; never overflows.
#[must_use]
pub fn next_backoff(previous: Duration, max: Duration) -> Duration {
	previous.saturating_mul(2).min(max)
}
