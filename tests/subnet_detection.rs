//! Интеграционные тесты subnet-level детекции: трекер → детектор → вердикты.

use rampart::config::Config;
use rampart::engine::subnet_tracker::SubnetTracker;
use rampart::traffic::prefix::{
    PrefixKey, PrefixSnapshot, PrefixStatsSource, PrefixStatsVal, SubnetDetector, SubnetVerdict, prefix_of,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(octets))
}

/// Фиксированный источник снапшотов — имитирует XDP-карту без ядра.
struct FixedSource(Vec<(IpAddr, PrefixSnapshot)>);

impl PrefixStatsSource for FixedSource {
    async fn snapshot(&self) -> anyhow::Result<Vec<(IpAddr, PrefixSnapshot)>> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn tracker_feeds_detector_and_blocks_distributed_attack() {
    let tracker = SubnetTracker::new();
    // 40 уникальных источников из одного /24 — распределённая атака
    // (6 SYN от каждого: 240 >= 4 × threshold(50)).
    for _ in 0..6 {
        for last in 1..=40u8 {
            tracker.record_connection(v4([203, 0, 113, last]));
        }
    }
    let snaps = tracker.take_snapshot();

    let detector = SubnetDetector::new(50, 16);
    let verdicts = detector.evaluate(&snaps);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].prefix, v4([203, 0, 113, 0]));
    assert_eq!(verdicts[0].verdict, SubnetVerdict::Block);
    assert_eq!(verdicts[0].snapshot.syn_count, 240);
    assert_eq!(verdicts[0].snapshot.unique_sources, 40);

    // Полный конвейер через трейт-источник (как в бинарнике).
    let source_snaps = FixedSource(snaps).snapshot().await.expect("source snapshot");
    assert_eq!(detector.evaluate(&source_snaps)[0].verdict, SubnetVerdict::Block);
}

#[tokio::test]
async fn spoof_gate_many_syn_few_sources_no_block() {
    let tracker = SubnetTracker::new();
    // 500 SYN всего из 3 адресов — всплеск, но не распределённый.
    for _ in 0..167 {
        for ip in [v4([198, 51, 100, 1]), v4([198, 51, 100, 2]), v4([198, 51, 100, 3])] {
            tracker.record_connection(ip);
        }
    }
    let snaps = tracker.take_snapshot();
    let detector = SubnetDetector::new(50, 16);
    let verdicts = detector.evaluate(&snaps);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].snapshot.syn_count, 501);
    assert_eq!(verdicts[0].snapshot.unique_sources, 3);
    assert_ne!(verdicts[0].verdict, SubnetVerdict::Block);
    assert_eq!(verdicts[0].verdict, SubnetVerdict::Challenge);
}

#[test]
fn ipv6_prefixes_aggregated_separately_from_ipv4() {
    let tracker = SubnetTracker::new();
    let v6a = IpAddr::V6("2001:db8:1:2::1".parse::<Ipv6Addr>().expect("valid"));
    let v6b = IpAddr::V6("2001:db8:1:2::ffff".parse::<Ipv6Addr>().expect("valid"));
    tracker.record_connection(v6a);
    tracker.record_connection(v6b);
    tracker.record_connection(v4([10, 0, 0, 1]));

    let snaps: HashMap<IpAddr, PrefixSnapshot> = tracker.take_snapshot().into_iter().collect();
    assert_eq!(snaps.len(), 2);
    assert_eq!(
        snaps[&IpAddr::V6("2001:db8:1:2::".parse::<Ipv6Addr>().expect("valid"))].unique_sources,
        2
    );
    assert_eq!(snaps[&v4([10, 0, 0, 0])].unique_sources, 1);
}

#[test]
fn mapped_v6_joins_ipv4_prefix_bucket() {
    // ::ffff:192.0.2.9
    assert_eq!(
        prefix_of(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0209))),
        v4([192, 0, 2, 0])
    );
}

#[test]
fn detect_prefix_config_section_parses_end_to_end() {
    let config = Config::parse_str(
        r#"
[detect.prefix]
enabled = true
syn_threshold = 250
window_secs = 30
min_unique_sources = 4
"#,
    )
    .expect("[detect.prefix] must parse");
    assert!(config.detect.prefix.enabled);
    let detector = SubnetDetector::from_config(&config.detect.prefix);
    let snaps = vec![(
        v4([203, 0, 113, 0]),
        PrefixSnapshot {
            syn_count: 1200,
            unique_sources: 5,
            ..PrefixSnapshot::default()
        },
    )];
    let verdicts = detector.evaluate(&snaps);
    assert_eq!(verdicts[0].verdict, SubnetVerdict::Block);
}

fn verdict_for(detector: &SubnetDetector, snap: &PrefixSnapshot) -> SubnetVerdict {
    let verdicts = detector.evaluate(&[(v4([10, 9, 9, 0]), *snap)]);
    verdicts[0].verdict
}

#[test]
fn ipv4_prefix_masked_to_24() {
    assert_eq!(prefix_of(v4([203, 0, 113, 77])), v4([203, 0, 113, 0]));
    assert_eq!(prefix_of(v4([198, 51, 100, 1])), v4([198, 51, 100, 0]));
}

#[test]
fn ipv6_prefix_masked_to_64() {
    let ip = IpAddr::V6("2001:db8:1:2:3:4:5:6".parse::<Ipv6Addr>().expect("valid"));
    assert_eq!(
        prefix_of(ip),
        IpAddr::V6("2001:db8:1:2::".parse::<Ipv6Addr>().expect("valid"))
    );
}

#[test]
fn mapped_ipv6_treated_as_ipv4() {
    // ::ffff:203.0.113.77
    let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x714d));
    assert_eq!(prefix_of(mapped), v4([203, 0, 113, 0]));
}

#[test]
fn prefix_key_roundtrip_and_layout() {
    assert_eq!(size_of::<PrefixKey>(), 24);
    assert_eq!(size_of::<PrefixStatsVal>(), 24);
    let key = PrefixKey::new(v4([10, 1, 2, 3]));
    assert_eq!(key.family, rampart::traffic::prefix::PREFIX_FAMILY_V4);
    assert_eq!(key.to_prefix(), Some(v4([10, 1, 2, 0])));
    assert_eq!(PrefixKey::from_bytes(key.to_bytes()), key);

    let key6 = PrefixKey::new(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("valid")));
    assert_eq!(key6.family, rampart::traffic::prefix::PREFIX_FAMILY_V6);
    assert_eq!(
        key6.to_prefix(),
        Some(IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().expect("valid")))
    );
}

#[test]
fn escalation_ladder_monitor_to_block() {
    let detector = SubnetDetector::new(100, 16);
    let snap = |syn: u64| PrefixSnapshot {
        syn_count: syn,
        unique_sources: 32,
        ..PrefixSnapshot::default()
    };
    assert_eq!(verdict_for(&detector, &snap(99)), SubnetVerdict::Monitor);
    assert_eq!(verdict_for(&detector, &snap(100)), SubnetVerdict::StrictLimit);
    assert_eq!(verdict_for(&detector, &snap(150)), SubnetVerdict::StrictLimit);
    assert_eq!(verdict_for(&detector, &snap(200)), SubnetVerdict::Challenge);
    assert_eq!(verdict_for(&detector, &snap(400)), SubnetVerdict::Block);
}

#[test]
fn spoof_gate_downgrades_block_to_challenge() {
    let detector = SubnetDetector::new(100, 16);
    // Много SYN из одного источника (или неизвестное разнообразие) → нет Block.
    let few = PrefixSnapshot {
        syn_count: 1000,
        unique_sources: 3,
        ..PrefixSnapshot::default()
    };
    let unknown = PrefixSnapshot {
        syn_count: 1000,
        ..PrefixSnapshot::default()
    };
    assert_eq!(verdict_for(&detector, &few), SubnetVerdict::Challenge);
    assert_eq!(verdict_for(&detector, &unknown), SubnetVerdict::Challenge);
}

#[test]
fn evaluate_skips_empty_prefixes() {
    let detector = SubnetDetector::new(100, 0);
    let snaps = vec![
        (v4([10, 0, 0, 0]), PrefixSnapshot::default()),
        (
            v4([10, 0, 1, 0]),
            PrefixSnapshot {
                syn_count: 500,
                unique_sources: 40,
                ..PrefixSnapshot::default()
            },
        ),
    ];
    let verdicts = detector.evaluate(&snaps);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].prefix, v4([10, 0, 1, 0]));
    assert_eq!(verdicts[0].verdict, SubnetVerdict::Block);
}
