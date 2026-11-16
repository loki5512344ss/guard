//! Per-source reputation with time decay and idle-TTL eviction.
//!
//! A source starts neutral (`0`); [`IpReputation::record_bad`] subtracts ten
//! points and [`IpReputation::record_good`] adds one, clamped to `[-100, 100]`.
//! Scores decay toward neutral on read (half of the magnitude per thirty
//! minutes of inactivity), so one old success cannot keep a source trusted
//! forever and one old failure cannot keep it toxic.
//!
//! State lives in sixty-four locked shards. [`IpReputation::sweep`] visits
//! eight of them per call and drops entries idle for longer than ten minutes;
//! recording advances one step per minute, so the table is reclaimed without
//! an external scheduler and no full-map `retain`.
//!
//! [`IpReputation::offenders_below`] returns at most 64 of the worst sources,
//! so one escalation cannot flood the ban list or the log.

use std::collections::hash_map::RandomState;
use std::collections::{BinaryHeap, HashMap};
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Idle age after which a source is forgotten.
const IDLE_TTL: Duration = Duration::from_secs(600);
/// Time after which a dead source's score is halved.
const DECAY_HALF_LIFE: Duration = Duration::from_secs(1800);
/// Minimum interval between two automatic sweep steps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Number of independently locked score shards.
const SHARDS: usize = 64;
/// Shards examined by one [`IpReputation::sweep`] call.
const SWEEP_SHARDS_PER_TICK: usize = 8;
/// Upper bound of a single offender batch.
const MAX_OFFENDERS_PER_CYCLE: usize = 64;
const GOOD_STEP: i32 = 1;
const BAD_STEP: i32 = -10;
const MAX_SCORE: i32 = 100;
const MIN_SCORE: i32 = -100;

/// Tunables of [`IpReputation`].
#[derive(Debug, Clone, Copy)]
pub struct ReputationPolicy {
	/// Idle age after which a source is forgotten.
	pub idle_ttl: Duration,
	/// Time after which a dead source's score is halved.
	pub decay_half_life: Duration,
	/// Upper bound of a single [`IpReputation::offenders_below`] batch.
	pub max_offenders: usize,
}

impl Default for ReputationPolicy {
	fn default() -> Self {
		Self {
			idle_ttl: IDLE_TTL,
			decay_half_life: DECAY_HALF_LIFE,
			max_offenders: MAX_OFFENDERS_PER_CYCLE,
		}
	}
}

/// Reputation entry: the raw score and when it was last touched.
struct Entry {
	score: i32,
	last_update: Instant,
}

/// Reputation scores of the sources seen by the edge node.
pub struct IpReputation {
	shards: Box<[Mutex<HashMap<IpAddr, Entry>>]>,
	hasher: RandomState,
	policy: ReputationPolicy,
	epoch: Instant,
	last_sweep: AtomicU64,
	sweep_cursor: AtomicUsize,
}

impl Default for IpReputation {
	fn default() -> Self {
		Self::new()
	}
}

impl IpReputation {
	/// Builds a reputation table with the production policy.
	#[must_use]
	pub fn new() -> Self {
		Self::with_policy(ReputationPolicy::default())
	}

	/// Builds a reputation table with an explicit policy.
	pub fn with_policy(policy: ReputationPolicy) -> Self {
		Self {
			shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
			hasher: RandomState::new(),
			policy,
			epoch: Instant::now(),
			last_sweep: AtomicU64::new(0),
			sweep_cursor: AtomicUsize::new(0),
		}
	}

	/// Records a successful connection.
	pub fn record_good(&self, ip: IpAddr) {
		self.sweep_if_due();
		self.adjust(ip, GOOD_STEP);
	}

	/// Records a failed or abusive connection.
	pub fn record_bad(&self, ip: IpAddr) {
		self.sweep_if_due();
		self.adjust(ip, BAD_STEP);
	}

	/// Current decayed score of `ip`; `0` for unknown or idle sources.
	pub fn score(&self, ip: IpAddr) -> i32 {
		let now = Instant::now();
		let index = self.shard_index(ip);
		let shard = self.lock(index);
		let Some(entry) = shard.get(&ip) else { return 0 };
		let idle = now.duration_since(entry.last_update);
		if idle > self.policy.idle_ttl {
			return 0;
		}
		decayed_score(entry.score, idle, self.policy.decay_half_life)
	}

	/// Returns up to [`ReputationPolicy::max_offenders`] of the worst sources
	/// scored at or below `threshold`.
	///
	/// The snapshot is safe to ban from while other threads keep recording
	/// events. When more offenders exist than the batch cap, exactly one
	/// aggregated warning carries the total count.
	pub fn offenders_below(&self, threshold: i32) -> Vec<IpAddr> {
		let now = Instant::now();
		let limit = self.policy.max_offenders;
		let mut worst: BinaryHeap<(i32, IpAddr)> = BinaryHeap::new();
		let mut found = 0usize;
		for index in 0..self.shards.len() {
			let shard = self.lock(index);
			for (ip, entry) in shard.iter() {
				let idle = now.duration_since(entry.last_update);
				if idle > self.policy.idle_ttl {
					continue;
				}
				let score = decayed_score(entry.score, idle, self.policy.decay_half_life);
				if score > threshold {
					continue;
				}
				found += 1;
				worst.push((score, *ip));
				if worst.len() > limit {
					worst.pop();
				}
			}
		}
		let offenders: Vec<IpAddr> = worst.into_iter().map(|(_, ip)| ip).collect();
		if found > offenders.len() {
			tracing::warn!(
				found,
				returned = offenders.len(),
				"reputation offender batch truncated for this cycle"
			);
		}
		offenders
	}

	/// Whether the source is above the trusted score.
	pub fn is_trusted(&self, ip: IpAddr) -> bool {
		self.score(ip) > 50
	}

	/// Number of live entries.
	pub fn len(&self) -> usize {
		(0..self.shards.len()).map(|index| self.lock(index).len()).sum()
	}

	/// Whether the table is empty.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Evicts idle entries from the next shard slice; returns the count.
	pub fn sweep(&self) -> usize {
		let now = Instant::now();
		let shard_count = self.shards.len();
		let start = self.sweep_cursor.fetch_add(SWEEP_SHARDS_PER_TICK, Ordering::Relaxed);
		let mut removed = 0;
		for offset in 0..SWEEP_SHARDS_PER_TICK.min(shard_count) {
			let index = (start + offset) % shard_count;
			let mut shard = self.lock(index);
			let before = shard.len();
			shard.retain(|_, entry| now.duration_since(entry.last_update) <= self.policy.idle_ttl);
			removed += before - shard.len();
		}
		removed
	}

	fn adjust(&self, ip: IpAddr, delta: i32) {
		let now = Instant::now();
		let index = self.shard_index(ip);
		let mut shard = self.lock(index);
		let entry = shard.entry(ip).or_insert(Entry {
			score: 0,
			last_update: now,
		});
		let idle = now.duration_since(entry.last_update);
		let decayed = decayed_score(entry.score, idle, self.policy.decay_half_life);
		entry.score = (decayed + delta).clamp(MIN_SCORE, MAX_SCORE);
		entry.last_update = now;
	}

	/// Advances one sweep step when [`SWEEP_INTERVAL`] has elapsed, so eviction
	/// does not depend on an external timer.
	fn sweep_if_due(&self) {
		let elapsed = self.epoch.elapsed().as_secs();
		let last = self.last_sweep.load(Ordering::Relaxed);
		if elapsed.saturating_sub(last) < SWEEP_INTERVAL.as_secs() {
			return;
		}
		let advanced = self
			.last_sweep
			.compare_exchange(last, elapsed, Ordering::AcqRel, Ordering::Relaxed);
		if advanced.is_ok() {
			self.sweep();
		}
	}

	fn shard_index(&self, ip: IpAddr) -> usize {
		(self.hasher.hash_one(ip) as usize) % self.shards.len()
	}

	fn lock(&self, index: usize) -> MutexGuard<'_, HashMap<IpAddr, Entry>> {
		// A poisoned shard still holds consistent scores; keep serving.
		self.shards[index].lock().unwrap_or_else(|poison| poison.into_inner())
	}
}

fn decayed_score(score: i32, idle: Duration, half_life: Duration) -> i32 {
	if score == 0 || half_life.is_zero() {
		return 0;
	}
	let factor = 0.5f64.powf(idle.as_secs_f64() / half_life.as_secs_f64());
	// Rounding (instead of truncation) keeps an immediate second update from
	// decaying a score of `1` back to zero on the microsecond scale.
	(f64::from(score) * factor).round() as i32
}
