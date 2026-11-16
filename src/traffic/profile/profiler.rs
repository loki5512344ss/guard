use crate::traffic::ewma::Ewma;
use std::time::Instant;

pub struct TrafficProfiler {
	slots: [Ewma; 168],
	current_slot: usize,
	epoch: Instant,
}

impl Default for TrafficProfiler {
	fn default() -> Self {
		Self::new()
	}
}

impl TrafficProfiler {
	pub fn new() -> Self {
		Self {
			slots: std::array::from_fn(|_| Ewma::new(0.125)),
			current_slot: 0,
			epoch: Instant::now(),
		}
	}

	fn slot_index(&self) -> usize {
		(self.epoch.elapsed().as_secs() / 3600) as usize % 168
	}

	pub fn record(&mut self, pps: f64) {
		self.current_slot = self.slot_index();
		self.slots[self.current_slot].update(pps);
	}

	pub fn baseline(&self) -> f64 {
		self.slots[self.slot_index()].value()
	}

	pub fn anomaly_score(&self, pps: f64) -> f64 {
		let base = self.baseline();
		if base <= 0.0 {
			return 0.0;
		}
		(pps / base).min(10.0)
	}
}
