//! Time-aware exponential moving average used by the traffic profilers.
//!
//! The average is expressed in samples per unit time and is fed once per
//! metrics window by [`crate::traffic::profiler::TrafficProfiler`].

use std::time::Instant;

/// Smoothing factor used for `alpha` values outside the valid `(0, 1]` range
/// and for `NaN`, so a malformed configuration cannot freeze the baseline.
const DEFAULT_ALPHA: f64 = 0.125;

/// Exponential moving average with a wall-clock aware step count.
///
/// # Formula
///
/// For a sample `x` that arrives `dt` seconds after the previous update,
/// `steps = max(dt, 1)` and `weight = (1 - alpha)^steps`. The average is then
///
/// ```text
/// value = value * weight + x * (1 - weight)
/// ```
///
/// A larger `alpha` gives more weight to the newest sample; `alpha = 1` makes
/// the average equal to the last finite sample. The step count keeps the
/// smoothing independent of the tick rate: one update after a two-second gap
/// is worth two one-second updates.
pub struct Ewma {
	value: f64,
	last: Instant,
	alpha: f64,
}

impl Ewma {
	/// Builds a smoothed average that starts at zero.
	///
	/// `alpha` is clamped to `(0, 1]`; `NaN`, infinity and non-positive values
	/// fall back to the default 0.125 instead of silently disabling the
	/// smoothing or producing a non-finite baseline.
	#[must_use]
	pub fn new(alpha: f64) -> Self {
		Self {
			value: 0.0,
			last: Instant::now(),
			alpha: sanitize_alpha(alpha),
		}
	}

	/// Folds `sample` into the average, following the formula in the type
	/// documentation.
	///
	/// Non-finite samples are ignored (the update timestamp is not advanced
	/// either), so one broken counter reading cannot poison the baseline.
	pub fn update(&mut self, sample: f64) {
		if !sample.is_finite() {
			return;
		}
		let now = Instant::now();
		let steps = now.duration_since(self.last).as_secs_f64().max(1.0);
		let weight = (1.0 - self.alpha).powf(steps);
		self.value = self.value * weight + sample * (1.0 - weight);
		self.last = now;
	}

	/// Replaces the average with `value` and restarts the step timer.
	///
	/// Used to prime a baseline from the first observed window instead of
	/// climbing from zero, which would otherwise read as an anomaly.
	pub fn seed(&mut self, value: f64) {
		if !value.is_finite() {
			return;
		}
		self.value = value;
		self.last = Instant::now();
	}

	/// Current smoothed value.
	#[must_use]
	pub fn value(&self) -> f64 {
		self.value
	}
}

fn sanitize_alpha(alpha: f64) -> f64 {
	if alpha.is_finite() && alpha > 0.0 {
		alpha.min(1.0)
	} else {
		DEFAULT_ALPHA
	}
}
