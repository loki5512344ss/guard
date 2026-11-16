//! Adaptive proof-of-work difficulty driven by the observed connection rate.

use crate::metrics;
use std::collections::VecDeque;
use std::time::Instant;

/// Lowest usable difficulty: 0 disables the PoW gate before the adjuster runs.
pub const MIN_DIFFICULTY: u8 = 1;

/// Highest adaptive difficulty. Every extra hex digit quadruples solver work.
pub const MAX_DIFFICULTY: u8 = 12;

/// Difficulty the adjuster climbs to under the heaviest observed load.
const DEFAULT_MAX_DIFFICULTY: u8 = 10;

/// Adapts the PoW difficulty to the current connection rate.
///
/// The rate is counted over a sliding one-second window and the resulting
/// difficulty is clamped to `[min, max]`. The lower bound is also the floor and
/// the starting difficulty, so a configured value takes effect immediately.
pub struct DifficultyAdjuster {
	window: VecDeque<Instant>,
	min: u8,
	max: u8,
	current: u8,
}

impl Default for DifficultyAdjuster {
	fn default() -> Self {
		Self::new(4, 10)
	}
}

impl DifficultyAdjuster {
	/// Creates an adjuster with the explicit `[min, max]` range.
	///
	/// Inverted bounds are swapped, and both ends are clamped to
	/// [`MIN_DIFFICULTY`]..=[`MAX_DIFFICULTY`]. The lower bound doubles as the
	/// starting difficulty.
	#[must_use]
	pub fn new(min: u8, max: u8) -> Self {
		let (min, max) = if min > max { (max, min) } else { (min, max) };
		let min = min.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);
		let max = max.clamp(min, MAX_DIFFICULTY);
		Self {
			window: VecDeque::new(),
			min,
			max,
			current: min,
		}
	}

	/// Creates an adjuster whose floor and starting point is the configured PoW
	/// difficulty.
	///
	/// The ceiling stays at the default maximum, or rises to the configured
	/// value when that value is higher. Values outside
	/// [`MIN_DIFFICULTY`]..=[`MAX_DIFFICULTY`] are clamped.
	#[must_use]
	pub fn with_floor(difficulty: u8) -> Self {
		let floor = difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);
		Self::new(floor, floor.max(DEFAULT_MAX_DIFFICULTY))
	}

	/// Records one connection and recomputes the difficulty for the window.
	pub fn record_connection(&mut self) {
		let now = Instant::now();
		self.window.push_back(now);
		while let Some(&t) = self.window.front() {
			if now.duration_since(t).as_secs() >= 1 {
				self.window.pop_front();
			} else {
				break;
			}
		}
		let new_diff = self.compute_difficulty();
		if self.current != new_diff {
			tracing::info!(
				old = self.current,
				new = new_diff,
				window = self.window.len(),
				"pow: difficulty adjusted"
			);
			self.current = new_diff;
			metrics::POW_CURRENT_DIFFICULTY.set(self.current as i64);
		}
	}

	/// Returns the current difficulty and publishes it to the metrics gauge.
	#[must_use]
	pub fn current_difficulty(&self) -> u8 {
		metrics::POW_CURRENT_DIFFICULTY.set(self.current as i64);
		self.current
	}

	/// Rate step before it is clamped to the configured range.
	fn rate_difficulty(&self) -> u8 {
		match self.window.len() {
			cps if cps > 500 => MAX_DIFFICULTY,
			cps if cps > 200 => 8,
			cps if cps > 50 => 6,
			_ => self.min,
		}
	}

	fn compute_difficulty(&self) -> u8 {
		// The rate ladder is global; the configured range is authoritative.
		self.rate_difficulty().clamp(self.min, self.max)
	}
}
