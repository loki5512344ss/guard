//! Integration tests for Traffic Intelligence on the hot path: EWMA sanity,
//! attack detection across a sustained flood, reputation decay/eviction and
//! auto-ban driven by reputation.

use rampart::config::DetectAutobanConfig;
use rampart::filter::blacklist::Blacklist;
use rampart::traffic::alert::AlertDispatcher;
use rampart::traffic::detector::{AttackDetector, AttackStatus, DetectorThresholds};
use rampart::traffic::ewma::Ewma;
use rampart::traffic::hook::TrafficHook;
use rampart::traffic::reputation::{IpReputation, ReputationPolicy};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

fn ip(octets: [u8; 4]) -> IpAddr {
	IpAddr::V4(Ipv4Addr::from(octets))
}

fn autoban_cfg(enabled: bool) -> DetectAutobanConfig {
	DetectAutobanConfig {
		enabled,
		reputation_threshold: -50,
	}
}

fn quiet(detector: &mut AttackDetector) {
	for _ in 0..12 {
		detector.analyze(500.0, 50.0);
	}
}

// EWMA

#[test]
fn ewma_starts_at_zero() {
	assert_eq!(Ewma::new(0.125).value(), 0.0);
}

#[test]
fn ewma_alpha_one_follows_the_sample() {
	let mut ewma = Ewma::new(1.0);
	ewma.update(100.0);
	assert!((ewma.value() - 100.0).abs() < 1.0);
}

#[test]
fn ewma_converges_to_a_constant_sample() {
	let mut ewma = Ewma::new(0.5);
	for _ in 0..10 {
		ewma.update(50.0);
	}
	assert!((ewma.value() - 50.0).abs() < 1.0);
}

#[test]
fn ewma_falls_back_on_invalid_alpha() {
	for alpha in [f64::NAN, f64::INFINITY, 0.0, -0.5] {
		let mut ewma = Ewma::new(alpha);
		ewma.update(100.0);
		assert!(ewma.value().is_finite(), "alpha={alpha} must keep the average finite");
		assert!(
			ewma.value() > 0.0 && ewma.value() < 100.0,
			"alpha={alpha} must fall back to the default smoothing"
		);
	}
}

#[test]
fn ewma_seed_primes_the_baseline() {
	let mut ewma = Ewma::new(0.01);
	ewma.seed(500.0);
	assert_eq!(ewma.value(), 500.0, "a seeded baseline starts at the observed value");
	ewma.update(500.0);
	assert_eq!(ewma.value(), 500.0);
	assert!(!ewma.value().is_nan());
}

#[test]
fn ewma_ignores_non_finite_samples() {
	let mut ewma = Ewma::new(0.5);
	ewma.update(10.0);
	let before = ewma.value();
	ewma.update(f64::NAN);
	ewma.update(f64::INFINITY);
	assert_eq!(ewma.value(), before, "non-finite samples must not move the average");
}

// Attack detector

#[test]
fn attack_detector_reports_normal_traffic() {
	let mut detector = AttackDetector::new();
	quiet(&mut detector);
	assert_eq!(detector.analyze(500.0, 50.0), AttackStatus::Normal);
}

#[test]
fn attack_detector_flags_pps_spike_as_suspicious() {
	let mut detector = AttackDetector::new();
	for _ in 0..10 {
		detector.analyze(1.0, 1.0);
	}
	assert_eq!(detector.analyze(5.0, 1.0), AttackStatus::Suspicious);
}

#[test]
fn attack_detector_flags_cps_spike_as_suspicious() {
	let mut detector = AttackDetector::new();
	for _ in 0..10 {
		detector.analyze(1.0, 1.0);
	}
	assert_eq!(detector.analyze(1.0, 5.0), AttackStatus::Suspicious);
}

#[test]
fn attack_detector_escalates_after_three_anomalies() {
	let mut detector = AttackDetector::new();
	for _ in 0..10 {
		detector.analyze(1.0, 1.0);
	}
	detector.analyze(10_000.0, 100.0);
	detector.analyze(10_000.0, 100.0);
	assert_eq!(detector.analyze(10_000.0, 100.0), AttackStatus::UnderAttack);
}

#[test]
fn attack_detector_resets_on_a_normal_window() {
	let mut detector = AttackDetector::new();
	for _ in 0..10 {
		detector.analyze(1.0, 1.0);
	}
	detector.analyze(100.0, 10.0);
	detector.analyze(100.0, 10.0);
	detector.analyze(1.0, 1.0);
	assert_eq!(detector.analyze(1.0, 1.0), AttackStatus::Normal);
}

#[test]
fn detector_flags_synthetic_traffic_spike() {
	let mut detector = AttackDetector::new();

	// Baseline: a quiet profile.
	for _ in 0..12 {
		detector.analyze(500.0, 50.0);
	}

	// Synthetic spike: 200x pps and cps for three consecutive windows.
	assert_eq!(
		detector.analyze(100_000.0, 10_000.0),
		AttackStatus::Suspicious,
		"first anomalous window is suspicious"
	);
	assert_eq!(detector.analyze(100_000.0, 10_000.0), AttackStatus::Suspicious);
	assert_eq!(
		detector.analyze(100_000.0, 10_000.0),
		AttackStatus::UnderAttack,
		"three anomalous windows in a row must escalate to UnderAttack"
	);
}

#[test]
fn sustained_flood_stays_under_attack_and_keeps_banning_offenders() {
	let reputation = Arc::new(IpReputation::new());
	let blacklist = Arc::new(Blacklist::new());
	let hook = TrafficHook::new(Arc::clone(&reputation), Arc::clone(&blacklist), autoban_cfg(true), 60);
	let mut detector = AttackDetector::new();
	quiet(&mut detector);

	for tick in 0..10u8 {
		let status = detector.analyze(100_000.0, 10_000.0);
		if tick < 2 {
			assert_eq!(status, AttackStatus::Suspicious, "flood tick {tick}");
		} else {
			assert_eq!(
				status,
				AttackStatus::UnderAttack,
				"flood tick {tick}: the detector must not learn the attack as normal"
			);
		}

		// A fresh offender joins on every tick of the attack. The edge keeps
		// banning them only while the detector stays in UnderAttack.
		let offender = ip([203, 0, 113, tick + 1]);
		for _ in 0..6 {
			reputation.record_bad(offender);
		}
		assert!(hook.ban_offenders() >= 1, "flood tick {tick} must produce a ban");
		assert!(
			blacklist.is_blocked(offender),
			"flood tick {tick}: offender must be banned"
		);
	}
}

#[test]
fn under_attack_exits_only_after_the_recovery_window() {
	let mut detector = AttackDetector::new();
	quiet(&mut detector);
	for _ in 0..3 {
		detector.analyze(100_000.0, 10_000.0);
	}
	assert_eq!(detector.analyze(100_000.0, 10_000.0), AttackStatus::UnderAttack);

	// Four calm windows are not enough: the exit hysteresis is five ticks.
	for tick in 0..4 {
		assert_eq!(
			detector.analyze(500.0, 50.0),
			AttackStatus::UnderAttack,
			"calm tick {tick} must not end the attack"
		);
	}
	assert_eq!(
		detector.analyze(500.0, 50.0),
		AttackStatus::Normal,
		"the fifth calm tick ends the attack"
	);
}

#[test]
fn detector_thresholds_are_configurable() {
	let thresholds = DetectorThresholds {
		suspicious_score: 1.5,
		attack_score: 2.0,
		escalate_after: 1,
		recover_after: 2,
	};
	let mut detector = AttackDetector::with_thresholds(thresholds);
	for _ in 0..10 {
		detector.analyze(100.0, 10.0);
	}
	assert_eq!(
		detector.analyze(1_000.0, 100.0),
		AttackStatus::UnderAttack,
		"escalate_after = 1 must escalate on the first anomalous window"
	);
	assert_eq!(detector.analyze(100.0, 10.0), AttackStatus::UnderAttack);
	assert_ne!(
		detector.analyze(100.0, 10.0),
		AttackStatus::UnderAttack,
		"recover_after = 2 must end the attack"
	);
}

// Reputation

#[test]
fn reputation_initial_score_is_neutral() {
	let rep = IpReputation::new();
	assert_eq!(rep.score(ip([192, 168, 1, 1])), 0);
}

#[test]
fn reputation_good_and_bad_steps() {
	let rep = IpReputation::new();
	let good = ip([10, 0, 0, 1]);
	let bad = ip([10, 0, 0, 2]);
	rep.record_good(good);
	rep.record_bad(bad);
	assert_eq!(rep.score(good), 1);
	assert_eq!(rep.score(bad), -10);
}

#[test]
fn reputation_scores_are_clamped() {
	let rep = IpReputation::new();
	let good = ip([10, 0, 0, 3]);
	let bad = ip([10, 0, 0, 4]);
	for _ in 0..200 {
		rep.record_good(good);
	}
	for _ in 0..20 {
		rep.record_bad(bad);
	}
	assert_eq!(rep.score(good), 100);
	assert_eq!(rep.score(bad), -100);
}

#[test]
fn reputation_trusts_after_enough_good_connections() {
	let rep = IpReputation::new();
	let ip = ip([10, 0, 0, 5]);
	assert!(!rep.is_trusted(ip));
	for _ in 0..51 {
		rep.record_good(ip);
	}
	assert!(rep.is_trusted(ip));
}

#[test]
fn reputation_tracks_ipv6() {
	let rep = IpReputation::new();
	let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
	rep.record_bad(ip);
	assert_eq!(rep.score(ip), -10);
}

#[test]
fn reputation_decays_toward_neutral() {
	let policy = ReputationPolicy {
		idle_ttl: Duration::from_secs(10),
		decay_half_life: Duration::from_millis(20),
		max_offenders: 64,
	};
	let rep = IpReputation::with_policy(policy);
	let bad = ip([10, 0, 0, 6]);
	for _ in 0..20 {
		rep.record_bad(bad);
	}
	assert_eq!(rep.score(bad), -100);
	std::thread::sleep(Duration::from_millis(40));
	let decayed = rep.score(bad);
	assert!(
		decayed > -100 && decayed < 0,
		"two half-lives must move the score toward neutral, got {decayed}"
	);
}

#[test]
fn reputation_sweep_evicts_idle_and_keeps_active() {
	let policy = ReputationPolicy {
		idle_ttl: Duration::from_millis(20),
		decay_half_life: Duration::from_secs(1800),
		max_offenders: 64,
	};
	let rep = IpReputation::with_policy(policy);
	let idle = ip([10, 0, 0, 7]);
	let active = ip([10, 0, 0, 8]);
	rep.record_bad(idle);
	rep.record_bad(active);

	std::thread::sleep(Duration::from_millis(40));
	rep.record_bad(active);
	for _ in 0..8 {
		rep.sweep();
	}

	assert_eq!(rep.len(), 1, "only the idle source may be evicted");
	assert_eq!(rep.score(idle), 0, "evicted source is neutral again");
	assert!(rep.score(active) < 0, "active source keeps its score");
}

#[test]
fn offenders_are_capped_per_cycle() {
	let policy = ReputationPolicy {
		idle_ttl: Duration::from_secs(600),
		decay_half_life: Duration::from_secs(1800),
		max_offenders: 3,
	};
	let rep = IpReputation::with_policy(policy);
	for last in 1..=20u8 {
		let source = ip([198, 51, 100, last]);
		for _ in 0..6 {
			rep.record_bad(source);
		}
	}
	assert_eq!(
		rep.offenders_below(-50).len(),
		3,
		"one cycle must not return the whole offender table"
	);
}

#[test]
fn offenders_below_returns_worst_sources() {
	let rep = IpReputation::new();
	let bad = ip([10, 0, 0, 1]);
	let good = ip([10, 0, 0, 2]);
	for _ in 0..6 {
		rep.record_bad(bad);
	}
	rep.record_good(good);
	assert_eq!(rep.offenders_below(-50), vec![bad]);
}

#[test]
fn offenders_below_is_empty_without_offenders() {
	let rep = IpReputation::new();
	assert!(rep.offenders_below(-50).is_empty());
}

// Traffic hook auto-ban

#[test]
fn reputation_fall_after_drops_triggers_autoban() {
	let reputation = Arc::new(IpReputation::new());
	let blacklist = Arc::new(Blacklist::new());
	let hook = TrafficHook::new(Arc::clone(&reputation), Arc::clone(&blacklist), autoban_cfg(true), 60);
	let attacker = ip([198, 51, 100, 7]);

	for _ in 0..6 {
		// Six drops through the rate limiter: -10 each, auto-ban threshold is -50.
		reputation.record_bad(attacker);
		hook.on_connection_end(attacker);
	}

	assert!(
		reputation.score(attacker) <= -50,
		"reputation must fall below threshold"
	);
	assert!(
		blacklist.is_blocked(attacker),
		"auto-ban must fire after repeated drops"
	);
}

#[test]
fn autoban_ttl_expires_ban() {
	let reputation = Arc::new(IpReputation::new());
	let blacklist = Arc::new(Blacklist::new());
	let hook = TrafficHook::new(
		Arc::clone(&reputation),
		Arc::clone(&blacklist),
		autoban_cfg(true),
		// Zero TTL taken from the config as a time mock.
		0,
	);
	let attacker = ip([198, 51, 100, 8]);
	for _ in 0..20 {
		reputation.record_bad(attacker);
	}
	hook.on_connection_end(attacker);
	std::thread::sleep(Duration::from_millis(5));
	assert!(
		!blacklist.is_blocked(attacker),
		"zero TTL must not produce an active ban"
	);
}

#[test]
fn alerts_fire_only_on_state_transitions() {
	let dispatcher = AlertDispatcher::new();
	let sequence = [
		AttackStatus::Normal,
		AttackStatus::Normal,
		AttackStatus::Suspicious,
		AttackStatus::UnderAttack,
		AttackStatus::UnderAttack,
		AttackStatus::UnderAttack,
		AttackStatus::Suspicious,
		AttackStatus::Normal,
		AttackStatus::Normal,
	];
	let alerts: Vec<_> = sequence.iter().filter_map(|s| dispatcher.on_status(*s)).collect();
	assert_eq!(alerts.len(), 2, "two transitions must yield exactly two alerts");
	assert!(alerts[0].message.contains("attack started"));
	assert!(alerts[1].message.contains("attack ended"));
}

#[test]
fn auto_ban_never_targets_a_trusted_proxy_network() {
	let reputation = Arc::new(IpReputation::new());
	let blacklist = Arc::new(Blacklist::new());
	let trusted: Vec<rampart::config::TrustedProxyCidr> = vec!["10.0.0.0/8".parse().expect("trusted cidr")];
	let hook =
		TrafficHook::new(Arc::clone(&reputation), Arc::clone(&blacklist), autoban_cfg(true), 60).with_trusted(trusted);
	let inside = ip([10, 1, 2, 3]);

	for _ in 0..6 {
		reputation.record_bad(inside);
		hook.on_connection_end(inside);
	}
	assert!(
		reputation.score(inside) <= -50,
		"reputation must fall below the threshold"
	);
	assert_eq!(hook.ban_offenders(), 0, "trusted addresses are never banned");

	let public = ip([198, 51, 100, 9]);
	for _ in 0..6 {
		reputation.record_bad(public);
		hook.on_connection_end(public);
	}
	assert!(
		blacklist.is_blocked(public),
		"non-trusted offenders are still banned by the reputation path"
	);
}
