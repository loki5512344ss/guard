//! Per-source token-bucket rate limiter for the accept path.
//!
//! # Capacity policy
//!
//! The bucket table is a hard-bounded sharded hash map: at most `max_buckets`
//! live buckets (one million for [`RateLimiter::new`]). Admission uses an
//! atomic reservation, so concurrent accept loops cannot overshoot the bound
//! the way a plain `len()` check would.
//!
//! # Saturation policy
//!
//! When the table is full, [`RateLimiter::check`] fails closed for a *new*
//! source: the connection is rejected until [`RateLimiter::sweep`] frees a
//! slot. Existing sources keep their token state and are never refused because
//! of the cap. Failing closed is deliberate for a protection device - the
//! alternative (unbounded buckets, or silently allowing everything once the
//! table is full) turns a memory exhaustion vector into a bypass.
//!
//! # Eviction policy
//!
//! [`RateLimiter::sweep`] visits eight of the sixty-four shards and drops
//! buckets idle for longer than `eviction_idle` (ten minutes by default). Work
//! per call is bounded, so the accept path never stalls on a full-table
//! `retain`, and one full cycle takes eight one-minute ticks.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Default hard bound of the bucket table (one million sources).
const MAX_BUCKETS: usize = 1_000_000;
/// Default idle age after which a bucket may be reclaimed.
const EVICTION_IDLE: Duration = Duration::from_secs(600);
/// Number of independently locked map shards.
const SHARDS: usize = 64;
/// Shards examined by one [`RateLimiter::sweep`] call.
const SWEEP_SHARDS_PER_TICK: usize = 8;

/// Token-bucket state of one source address.
struct Bucket {
	tokens: f64,
	last_refill: Instant,
	last_access: Instant,
}

/// Per-source token buckets with a hard capacity bound.
pub struct RateLimiter {
	shards: Box<[Mutex<HashMap<IpAddr, Bucket>>]>,
	hasher: RandomState,
	live: AtomicUsize,
	max_buckets: usize,
	max_tokens: f64,
	refill_rate: f64,
	eviction_idle: Duration,
	sweep_cursor: AtomicUsize,
}

impl RateLimiter {
	/// Builds a limiter with the production capacity policy.
	#[must_use]
	pub fn new(rate_per_sec: f64, burst: f64) -> Self {
		Self::with_capacity(rate_per_sec, burst, MAX_BUCKETS, EVICTION_IDLE)
	}

	/// Builds a limiter with an explicit capacity policy.
	///
	/// `max_buckets` is the hard bound of the table and `eviction_idle` the
	/// idle age after which [`Self::sweep`] may reclaim a bucket. [`Self::new`]
	/// supplies the production defaults; this constructor exists for tests and
	/// for deployments with a tighter memory budget.
	#[must_use]
	pub fn with_capacity(rate_per_sec: f64, burst: f64, max_buckets: usize, eviction_idle: Duration) -> Self {
		Self {
			shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
			hasher: RandomState::new(),
			live: AtomicUsize::new(0),
			max_buckets,
			max_tokens: burst,
			refill_rate: rate_per_sec,
			eviction_idle,
			sweep_cursor: AtomicUsize::new(0),
		}
	}

	/// Consumes one token for `ip`, returning `false` when the source is over
	/// its rate or the table is saturated (see the module documentation).
	pub fn check(&self, ip: IpAddr) -> bool {
		let now = Instant::now();
		let index = self.shard_index(ip);
		let mut shard = self.lock(index);
		if let Some(bucket) = shard.get_mut(&ip) {
			return refill_and_take(bucket, now, self.max_tokens, self.refill_rate);
		}
		if !self.reserve() {
			return false;
		}
		let mut bucket = Bucket {
			tokens: self.max_tokens,
			last_refill: now,
			last_access: now,
		};
		let allowed = refill_and_take(&mut bucket, now, self.max_tokens, self.refill_rate);
		shard.insert(ip, bucket);
		allowed
	}

	/// Number of live buckets.
	#[must_use]
	pub fn len(&self) -> usize {
		(0..self.shards.len()).map(|index| self.lock(index).len()).sum()
	}

	/// Whether the table is empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Evicts idle buckets from the next shard slice and returns how many were
	/// removed. See the eviction policy in the module documentation.
	pub fn sweep(&self) -> usize {
		let now = Instant::now();
		let shard_count = self.shards.len();
		let start = self.sweep_cursor.fetch_add(SWEEP_SHARDS_PER_TICK, Ordering::Relaxed);
		let mut removed = 0;
		for offset in 0..SWEEP_SHARDS_PER_TICK.min(shard_count) {
			let index = (start + offset) % shard_count;
			let mut shard = self.lock(index);
			let before = shard.len();
			shard.retain(|_, bucket| now.duration_since(bucket.last_access) < self.eviction_idle);
			removed += before - shard.len();
		}
		if removed > 0 {
			self.live.fetch_sub(removed, Ordering::AcqRel);
		}
		removed
	}

	/// Reserves one slot in the table, enforcing the hard bound.
	fn reserve(&self) -> bool {
		let live = self.live.fetch_add(1, Ordering::AcqRel);
		if live >= self.max_buckets {
			self.live.fetch_sub(1, Ordering::AcqRel);
			return false;
		}
		true
	}

	fn shard_index(&self, ip: IpAddr) -> usize {
		(self.hasher.hash_one(ip) as usize) % self.shards.len()
	}

	fn lock(&self, index: usize) -> MutexGuard<'_, HashMap<IpAddr, Bucket>> {
		// A poisoned shard still holds consistent token buckets; keep serving
		// instead of taking the whole limiter down.
		self.shards[index].lock().unwrap_or_else(|poison| poison.into_inner())
	}
}

fn refill_and_take(bucket: &mut Bucket, now: Instant, max_tokens: f64, refill_rate: f64) -> bool {
	let elapsed = now.duration_since(bucket.last_refill);
	bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * refill_rate).min(max_tokens);
	bucket.last_refill = now;
	bucket.last_access = now;
	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0;
		true
	} else {
		false
	}
}
