//! Интеграционные тесты Traffic Intelligence в hot path: авто-бан по
//! репутации, детектор атак на синтетическом всплеске, алерты на переходах.

use rampart::config::DetectAutobanConfig;
use rampart::filter::blacklist::Blacklist;
use rampart::traffic::alert::AlertDispatcher;
use rampart::traffic::detector::{AttackDetector, AttackStatus};
use rampart::traffic::hook::TrafficHook;
use rampart::traffic::reputation::IpReputation;
use std::net::{IpAddr, Ipv4Addr};
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

#[test]
fn reputation_fall_after_drops_triggers_autoban() {
    let reputation = Arc::new(IpReputation::new());
    let blacklist = Arc::new(Blacklist::new());
    let hook = TrafficHook::new(Arc::clone(&reputation), Arc::clone(&blacklist), autoban_cfg(true), 60);
    let attacker = ip([198, 51, 100, 7]);

    for _ in 0..6 {
        // Шесть дропов rate-limit'ом: -10 за каждый, порог auto-ban = -50.
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
        // Короткий TTL из «конфига» как мок времени.
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
fn detector_flags_synthetic_traffic_spike() {
    let mut detector = AttackDetector::new();

    // Базовая линия: тихий профиль.
    for _ in 0..12 {
        detector.analyze(500.0, 50.0);
    }

    // Синтетический всплеск: x200 pps и cps три окна подряд.
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
