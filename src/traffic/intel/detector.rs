//! Attack state machine over the hour-of-week traffic profile.
//!
//! [`AttackDetector`] scores every one-second window against the baselines
//! *before* the window is folded into them. Scoring first is what keeps a
//! sustained flood visible: a detector that learns the attack as normal stops
//! escalating after a few ticks, and anything that depends on
//! [`AttackStatus::UnderAttack`] (for example offender bans) stops working for
//! the rest of the attack.
//!
//! Two baselines are combined:
//!
//! - [`TrafficProfiler`]: the hour-of-week shape, updated from clean windows.
//! - A slow seeded EWMA (1% per window): the global traffic level. It covers
//!   the cold start and the first tick of every hour slot, where the
//!   hour-of-week baseline is still zero or close to it.
//!
//! A window is scored against the higher of the two, and attack-level windows
//! are not recorded at all. A flood therefore never becomes the baseline it is
//! compared to, while ordinary drift (below [`DetectorThresholds::attack_score`])
//! keeps both baselines current.
//!
//! Leaving [`AttackStatus::UnderAttack`] requires
//! [`DetectorThresholds::recover_after`] consecutive windows below
//! [`DetectorThresholds::attack_score`]. The exit hysteresis keeps a single
//! calm window in the middle of an attack from restarting the escalation
//! count.

use crate::traffic::ewma::Ewma;
use crate::traffic::profiler::TrafficProfiler;

/// Smoothing factor of the slow global baseline: one percent per window, so a
/// legitimate traffic shift is learned in about a hundred seconds.
const SLOW_ALPHA: f64 = 0.01;
/// Upper bound of a reported score; `10` means "at least ten times the
/// baseline" and keeps the attack state machine from chasing huge ratios.
const MAX_ANOMALY_RATIO: f64 = 10.0;

/// Classification of the current traffic window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackStatus {
	/// Traffic is within the learned baseline.
	Normal,
	/// A ratio above [`DetectorThresholds::suspicious_score`] was observed,
	/// but the escalation count is not reached yet.
	Suspicious,
	/// Consecutive anomalous windows were observed; the edge escalates.
	UnderAttack,
}

/// Tunables of the attack state machine.
///
/// The scores are ratios to the baseline (a value of `3.0` means "three times
/// the usual rate"). The defaults match the v0.3 policy; a caller that needs a
/// different sensitivity passes its own values to
/// [`AttackDetector::with_thresholds`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectorThresholds {
	/// Ratio that marks a window as suspicious.
	pub suspicious_score: f64,
	/// Ratio that counts a window as anomalous for escalation.
	pub attack_score: f64,
	/// Consecutive anomalous windows required to enter `UnderAttack`.
	pub escalate_after: u32,
	/// Consecutive sub-attack windows required to leave `UnderAttack`.
	pub recover_after: u32,
}

impl Default for DetectorThresholds {
	fn default() -> Self {
		Self {
			suspicious_score: 2.0,
			attack_score: 3.0,
			escalate_after: 3,
			recover_after: 5,
		}
	}
}

/// Detects floods from the packets-per-second and connections-per-second
/// profiles.
pub struct AttackDetector {
	pps_profiler: TrafficProfiler,
	cps_profiler: TrafficProfiler,
	pps_slow: Ewma,
	cps_slow: Ewma,
	primed: bool,
	thresholds: DetectorThresholds,
	consecutive_anomalies: u32,
	recovery_windows: u32,
	under_attack: bool,
}

impl Default for AttackDetector {
	fn default() -> Self {
		Self::new()
	}
}

impl AttackDetector {
	/// Builds a detector with the default [`DetectorThresholds`].
	#[must_use]
	pub fn new() -> Self {
		Self::with_thresholds(DetectorThresholds::default())
	}

	/// Builds a detector with explicit thresholds.
	#[must_use]
	pub fn with_thresholds(thresholds: DetectorThresholds) -> Self {
		Self {
			pps_profiler: TrafficProfiler::new(),
			cps_profiler: TrafficProfiler::new(),
			pps_slow: Ewma::new(SLOW_ALPHA),
			cps_slow: Ewma::new(SLOW_ALPHA),
			primed: false,
			thresholds,
			consecutive_anomalies: 0,
			recovery_windows: 0,
			under_attack: false,
		}
	}

	/// Analyses one metrics window (packets/s and new connections/s) and
	/// returns the attack classification.
	///
	/// A window is anomalous when its ratio to the baseline reaches
	/// [`DetectorThresholds::attack_score`].
	/// [`DetectorThresholds::escalate_after`] consecutive anomalous windows
	/// enter `UnderAttack`; the status is left only after
	/// [`DetectorThresholds::recover_after`] consecutive windows below the
	/// attack score. The first window only primes the baselines.
	pub fn analyze(&mut self, pps: f64, cps: f64) -> AttackStatus {
		if !self.primed {
			self.primed = true;
			self.pps_slow.seed(pps);
			self.cps_slow.seed(cps);
			self.pps_profiler.record(pps);
			self.cps_profiler.record(cps);
			return AttackStatus::Normal;
		}

		// Score against the baselines first: recording first would fold the
		// spike into the baseline it is scored against.
		let pps_baseline = self.pps_profiler.baseline().max(self.pps_slow.value());
		let cps_baseline = self.cps_profiler.baseline().max(self.cps_slow.value());
		let score = anomaly_ratio(pps, pps_baseline).max(anomaly_ratio(cps, cps_baseline));

		self.update_state(score);

		// Attack-level windows never enter the baselines (see the module
		// documentation); everything else keeps both of them current.
		if score < self.thresholds.attack_score {
			self.pps_profiler.record(pps);
			self.cps_profiler.record(cps);
			self.pps_slow.update(pps);
			self.cps_slow.update(cps);
		}

		if self.under_attack {
			AttackStatus::UnderAttack
		} else if score >= self.thresholds.suspicious_score {
			AttackStatus::Suspicious
		} else {
			AttackStatus::Normal
		}
	}

	fn update_state(&mut self, score: f64) {
		if score >= self.thresholds.attack_score {
			self.consecutive_anomalies = self.consecutive_anomalies.saturating_add(1);
			self.recovery_windows = 0;
		} else {
			self.consecutive_anomalies = 0;
			self.recovery_windows = self.recovery_windows.saturating_add(1);
		}

		if self.under_attack {
			if self.recovery_windows >= self.thresholds.recover_after {
				self.under_attack = false;
			}
		} else if self.consecutive_anomalies >= self.thresholds.escalate_after {
			self.under_attack = true;
		}
	}
}

/// Ratio of a window to its baseline, capped at [`MAX_ANOMALY_RATIO`].
///
/// Returns zero for an unset baseline and for non-finite windows, so a broken
/// counter cannot pin the detector in the attack state.
fn anomaly_ratio(sample: f64, baseline: f64) -> f64 {
	if !sample.is_finite() || baseline <= 0.0 {
		return 0.0;
	}
	(sample.max(0.0) / baseline).min(MAX_ANOMALY_RATIO)
}
