//! Shared TUI state: the last metrics snapshot, the pps/drops history and the
//! rate calculation.
//!
//! Owns the only hand-off point between the fetch task and the UI loop; every
//! accessor is mutex-guarded and tolerates a poisoned lock.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use crate::tui::prometheus::MetricSet;

/// Maximum length of the chart's sliding window.
pub const HISTORY_CAPACITY: usize = 120;

/// A single history sample; the values are rates in units per second.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HistoryPoint {
	pub packets_per_sec: f64,
	pub drops_per_sec: f64,
}

/// Fixed-capacity sliding window of history samples.
#[derive(Debug, Clone)]
pub struct History {
	points: VecDeque<HistoryPoint>,
}

impl Default for History {
	fn default() -> Self {
		Self {
			points: VecDeque::with_capacity(HISTORY_CAPACITY),
		}
	}
}

impl History {
	/// Appends a point, evicting the oldest one once the window is full.
	pub fn push(&mut self, point: HistoryPoint) {
		if self.points.len() == HISTORY_CAPACITY {
			self.points.pop_front();
		}
		self.points.push_back(point);
	}

	/// Points in chronological order.
	#[must_use]
	pub fn points(&self) -> &VecDeque<HistoryPoint> {
		&self.points
	}
}

/// Application state shared between the fetch task and the UI loop.
#[derive(Debug)]
pub struct AppState {
	url: String,
	snapshot: Mutex<Snapshot>,
	history: Mutex<History>,
	started_at: Instant,
}

impl AppState {
	/// Creates the state for a metrics source URL (shown in the status panel).
	#[must_use]
	pub fn new(url: impl Into<String>) -> Self {
		Self {
			url: url.into(),
			snapshot: Mutex::new(Snapshot::default()),
			history: Mutex::new(History::default()),
			started_at: Instant::now(),
		}
	}

	/// URL of the metrics source.
	#[must_use]
	pub fn url(&self) -> &str {
		&self.url
	}
}

/// Result of the latest successful or failed fetch.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
	pub metrics: Option<MetricSet>,
	pub fetched_at: Option<Instant>,
	pub error: Option<String>,
}

impl AppState {
	/// Records the result of the latest fetch and extends the rate history.
	pub fn apply_fetch(&self, result: Result<MetricSet, String>, elapsed_secs: f64) {
		let mut snapshot = match self.snapshot.lock() {
			Ok(guard) => guard,
			Err(poisoned) => poisoned.into_inner(),
		};
		match result {
			Ok(metrics) => {
				let mut history = match self.history.lock() {
					Ok(guard) => guard,
					Err(poisoned) => poisoned.into_inner(),
				};
				let previous = snapshot.metrics.take();
				let point = HistoryPoint {
					packets_per_sec: counter_rate(
						previous.as_ref().map(|p| p.sum("rampart_xdp_total")),
						Some(metrics.sum("rampart_xdp_total")),
						elapsed_secs,
					),
					drops_per_sec: counter_rate(
						previous.as_ref().map(|p| p.sum("rampart_xdp_dropped")),
						Some(metrics.sum("rampart_xdp_dropped")),
						elapsed_secs,
					),
				};
				history.push(point);
				snapshot.metrics = Some(metrics);
				snapshot.fetched_at = Some(Instant::now());
				snapshot.error = None;
			},
			Err(message) => {
				snapshot.error = Some(message);
			},
		}
	}

	/// Copy of the metrics snapshot plus history for rendering one frame.
	///
	/// The UI never holds a lock: it draws from the copy.
	#[must_use]
	pub fn frame_data(&self) -> FrameData {
		let snapshot = self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		let history = self
			.history
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.clone();
		FrameData {
			url: self.url.clone(),
			snapshot: snapshot.clone(),
			history,
			uptime_secs: self.started_at.elapsed().as_secs(),
		}
	}
}

/// Snapshot consumed by a single UI frame.
#[derive(Debug, Default, Clone)]
pub struct FrameData {
	/// URL of the metrics source.
	pub url: String,
	pub snapshot: Snapshot,
	pub history: History,
	/// TUI uptime in seconds.
	pub uptime_secs: u64,
}

/// Counter rate from two samples: `(current - previous) / dt`.
///
/// A `None` previous value (first sample) yields 0.0. A counter reset
/// (`current < previous`) is treated as a process restart and also yields 0.0.
#[must_use]
pub fn counter_rate(previous: Option<f64>, current: Option<f64>, elapsed_secs: f64) -> f64 {
	let (Some(previous), Some(current)) = (previous, current) else {
		return 0.0;
	};
	if !(elapsed_secs > 0.0 && current.is_finite()) || current < previous {
		return 0.0;
	}
	(current - previous) / elapsed_secs
}
