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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profiler_record_and_baseline() {
        let mut p = TrafficProfiler::new();
        p.record(1000.0);
        p.record(1100.0);
        let base = p.baseline();
        assert!(base > 0.0);
    }

    #[test]
    fn test_anomaly_score_normal() {
        let mut p = TrafficProfiler::new();
        for _ in 0..10 {
            p.record(100.0);
        }
        let score = p.anomaly_score(100.0);
        assert!(score < 2.0);
    }

    #[test]
    fn test_anomaly_score_capped() {
        let mut p = TrafficProfiler::new();
        for _ in 0..10 {
            p.record(1.0);
        }
        let score = p.anomaly_score(1_000_000.0);
        assert!((score - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_anomaly_score_zero_baseline() {
        let p = TrafficProfiler::new();
        assert_eq!(p.anomaly_score(100.0), 0.0);
    }
}
