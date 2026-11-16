//! Alert formatting and the deduplicating dispatcher: alerts fire only on the
//! detector's attack-boundary transitions, never on every tick.

use rampart::traffic::alert::{Alert, AlertDispatcher, AlertLevel};
use rampart::traffic::detector::AttackStatus;
use std::net::Ipv4Addr;

#[test]
fn test_alert_display_with_ip() {
	let alert = Alert::new(
		AlertLevel::Critical,
		"possible attack".into(),
		Some(Ipv4Addr::new(192, 168, 1, 1)),
		100500.0,
	);
	let s = alert.to_string();
	assert!(s.contains("CRITICAL"));
	assert!(s.contains("192.168.1.1"));
}

#[test]
fn test_alert_display_without_ip() {
	let alert = Alert::new(AlertLevel::Info, "traffic spike".into(), None, 5000.0);
	let s = alert.to_string();
	assert!(s.contains("INFO"));
	assert!(s.contains("traffic spike"));
}

#[test]
fn test_dispatcher_two_transitions_two_alerts() {
	let dispatcher = AlertDispatcher::new();
	assert_eq!(dispatcher.on_status(AttackStatus::Normal), None);
	assert_eq!(dispatcher.on_status(AttackStatus::Suspicious), None);
	let started = dispatcher.on_status(AttackStatus::UnderAttack);
	assert_eq!(dispatcher.on_status(AttackStatus::UnderAttack), None);
	assert_eq!(dispatcher.on_status(AttackStatus::UnderAttack), None);
	let ended = dispatcher.on_status(AttackStatus::Normal);
	assert_eq!(dispatcher.on_status(AttackStatus::Normal), None);
	assert!(started.is_some());
	assert!(ended.is_some());
	assert!(
		started.expect("started alert").message.contains("attack started")
			&& ended.expect("ended alert").message.contains("attack ended")
	);
}

#[test]
fn test_dispatcher_suspicious_does_not_flap_alerts() {
	let dispatcher = AlertDispatcher::new();
	for status in [
		AttackStatus::Normal,
		AttackStatus::Suspicious,
		AttackStatus::Normal,
		AttackStatus::Suspicious,
	] {
		assert_eq!(dispatcher.on_status(status), None);
	}
}
