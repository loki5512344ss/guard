//! Adaptive proof-of-work difficulty driven by the observed connection rate.

use crate::metrics;
use std::collections::VecDeque;
use std::time::Instant;

/// Adapts the PoW difficulty to the current connection rate.
///
/// The rate is counted over a sliding one-second window and the resulting
/// difficulty is clamped to `[min, max]`.
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
	/// Creates an adjuster clamped to `min.max(4)` and `max.min(10)`.
	#[must_use]
	pub fn new(min: u8, max: u8) -> Self {
		Self {
			window: VecDeque::new(),
			min: min.max(4),
			max: max.min(10),
			current: min.max(4),
		}
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

	fn compute_difficulty(&self) -> u8 {
		match self.window.len() {
			cps if cps > 500 => self.max.max(self.min),
			cps if cps > 200 => 8,
			cps if cps > 50 => 6,
			_ => self.min,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn adjuster_raises_difficulty_under_load() {
		let mut adjuster = DifficultyAdjuster::new(4, 10);
		for _ in 0..600 {
			adjuster.record_connection();
		}
		assert_eq!(adjuster.current_difficulty(), 10);
	}

	#[test]
	fn adjuster_stays_minimal_when_idle() {
		let mut adjuster = DifficultyAdjuster::new(4, 10);
		adjuster.record_connection();
		assert_eq!(adjuster.current_difficulty(), 4);
	}
}
