//! Hourly EWMA traffic profiler: baseline warming and the capped anomaly score.

use rampart::traffic::profiler::TrafficProfiler;

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
