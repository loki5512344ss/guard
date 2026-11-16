//! Traffic hook on the hot path: the cps window, reputation-driven auto-ban,
//! the attack-detector escalation and the ban TTL.

use rampart::config::DetectAutobanConfig;
use rampart::filter::blacklist::Blacklist;
use rampart::traffic::hook::TrafficHook;
use rampart::traffic::reputation::IpReputation;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn ip(octets: [u8; 4]) -> IpAddr {
	IpAddr::V4(Ipv4Addr::from(octets))
}

fn hook(rep: &Arc<IpReputation>, bl: &Arc<Blacklist>) -> TrafficHook {
	TrafficHook::new(
		Arc::clone(rep),
		Arc::clone(bl),
		DetectAutobanConfig {
			enabled: true,
			reputation_threshold: -50,
		},
		60,
	)
}

#[test]
fn test_cps_window_counts_and_resets() {
	let rep = Arc::new(IpReputation::new());
	let bl = Arc::new(Blacklist::new());
	let hook = hook(&rep, &bl);
	hook.on_accept();
	hook.on_accept();
	hook.on_accept();
	assert_eq!(hook.take_cps(), 3);
	assert_eq!(hook.take_cps(), 0);
}

#[test]
fn test_reputation_fall_triggers_autoban() {
	let rep = Arc::new(IpReputation::new());
	let bl = Arc::new(Blacklist::new());
	let hook = hook(&rep, &bl);
	let target = ip([10, 1, 0, 1]);
	for _ in 0..6 {
		rep.record_bad(target);
	}
	assert_eq!(rep.score(target), -60);
	assert!(!bl.is_blocked(target));
	hook.on_connection_end(target);
	assert!(bl.is_blocked(target));
}

#[test]
fn test_no_autoban_above_threshold() {
	let rep = Arc::new(IpReputation::new());
	let bl = Arc::new(Blacklist::new());
	let hook = hook(&rep, &bl);
	let target = ip([10, 1, 0, 2]);
	for _ in 0..4 {
		rep.record_bad(target);
	}
	assert_eq!(rep.score(target), -40);
	hook.on_connection_end(target);
	assert!(!bl.is_blocked(target));
}

#[test]
fn test_disabled_autoban_never_bans() {
	let rep = Arc::new(IpReputation::new());
	let bl = Arc::new(Blacklist::new());
	let hook = TrafficHook::new(
		Arc::clone(&rep),
		Arc::clone(&bl),
		DetectAutobanConfig {
			enabled: false,
			reputation_threshold: -50,
		},
		60,
	);
	let target = ip([10, 1, 0, 3]);
	for _ in 0..20 {
		rep.record_bad(target);
	}
	hook.on_connection_end(target);
	assert!(hook.ban_offenders() == 0);
	assert!(!bl.is_blocked(target));
}

#[test]
fn test_ban_offenders_bans_only_below_threshold() {
	let rep = Arc::new(IpReputation::new());
	let bl = Arc::new(Blacklist::new());
	let hook = hook(&rep, &bl);
	let bad = ip([10, 2, 0, 1]);
	let ok = ip([10, 2, 0, 2]);
	for _ in 0..8 {
		rep.record_bad(bad);
	}
	rep.record_good(ok);
	assert_eq!(hook.ban_offenders(), 1);
	assert!(bl.is_blocked(bad));
	assert!(!bl.is_blocked(ok));
	assert_eq!(hook.ban_offenders(), 0);
}

#[test]
fn test_autoban_ttl_expires() {
	let rep = Arc::new(IpReputation::new());
	let bl = Arc::new(Blacklist::new());
	let hook = TrafficHook::new(
		Arc::clone(&rep),
		Arc::clone(&bl),
		DetectAutobanConfig {
			enabled: true,
			reputation_threshold: -50,
		},
		// Zero TTL as a time mock: the ban must be dead on arrival.
		0,
	);
	let target = ip([10, 3, 0, 1]);
	for _ in 0..20 {
		rep.record_bad(target);
	}
	hook.on_connection_end(target);
	assert!(!bl.is_blocked(target), "zero TTL must not produce an active ban");
}
