//! Integration tests for subnet-level detection: tracker, detector and verdicts.

use rampart::config::{Config, TrustedProxyCidr};
use rampart::engine::subnet::monitor::enforce_tracker_verdicts;
use rampart::engine::subnet_tracker::SubnetTracker;
use rampart::filter::blacklist::Blacklist;
use rampart::traffic::prefix::{
	PrefixKey, PrefixSnapshot, PrefixStatsSource, PrefixStatsVal, PrefixVerdict, SubnetDetector, SubnetVerdict,
	prefix_of,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

fn v4(octets: [u8; 4]) -> IpAddr {
	IpAddr::V4(Ipv4Addr::from(octets))
}

/// Fixed snapshot source that imitates the XDP map without a kernel.
struct FixedSource(Vec<(IpAddr, PrefixSnapshot)>);

impl PrefixStatsSource for FixedSource {
	async fn snapshot(&self) -> anyhow::Result<Vec<(IpAddr, PrefixSnapshot)>> {
		Ok(self.0.clone())
	}
}

#[tokio::test]
async fn tracker_feeds_detector_and_blocks_distributed_attack() {
	let tracker = SubnetTracker::new();
	// 40 unique sources from one /24 is a distributed attack: 6 SYNs each,
	// i.e. 240 >= 4 x threshold(50).
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

	// Full pipeline through the trait source, the way the binary drives it.
	let source_snaps = FixedSource(snaps).snapshot().await.expect("source snapshot");
	assert_eq!(detector.evaluate(&source_snaps)[0].verdict, SubnetVerdict::Block);
}

#[tokio::test]
async fn spoof_gate_many_syn_few_sources_no_block() {
	let tracker = SubnetTracker::new();
	// 500 SYNs from only 3 addresses: a burst, but not distributed.
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
	assert_eq!(size_of::<PrefixStatsVal>(), 32);
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
	// Many SYNs from one source (or unknown diversity) must not yield Block.
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
fn tracker_groups_connections_by_prefix() {
	let tracker = SubnetTracker::new();
	tracker.record_connection(v4([203, 0, 113, 1]));
	tracker.record_connection(v4([203, 0, 113, 2]));
	tracker.record_connection(v4([198, 51, 100, 9]));
	let by_prefix: HashMap<IpAddr, PrefixSnapshot> = tracker.take_snapshot().into_iter().collect();
	assert_eq!(by_prefix.len(), 2);
	assert_eq!(by_prefix[&v4([203, 0, 113, 0])].syn_count, 2);
	assert_eq!(by_prefix[&v4([203, 0, 113, 0])].unique_sources, 2);
	assert_eq!(by_prefix[&v4([198, 51, 100, 0])].syn_count, 1);
}

#[test]
fn tracker_snapshot_drains_window() {
	let tracker = SubnetTracker::new();
	tracker.record_connection(v4([10, 0, 0, 1]));
	assert_eq!(tracker.take_snapshot().len(), 1);
	assert!(tracker.take_snapshot().is_empty());
}

#[test]
fn tracker_mapped_addresses_share_v4_prefix() {
	let tracker = SubnetTracker::new();
	tracker.record_connection(v4([203, 0, 113, 5]));
	// ::ffff:203.0.113.6
	let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7106);
	tracker.record_connection(IpAddr::V6(mapped));
	let snaps = tracker.take_snapshot();
	assert_eq!(snaps.len(), 1);
	assert_eq!(snaps[0].0, v4([203, 0, 113, 0]));
	assert_eq!(snaps[0].1.unique_sources, 2);
}

#[test]
fn tracker_prefix_cap_drops_new_prefixes_and_counts_them() {
	let tracker = SubnetTracker::with_limits(2, 8);
	tracker.record_connection(v4([10, 0, 0, 1]));
	tracker.record_connection(v4([10, 0, 1, 1]));
	tracker.record_connection(v4([10, 0, 2, 1]));
	assert_eq!(tracker.dropped_prefixes(), 1);
	// Existing prefixes keep accumulating even while the table is full.
	tracker.record_connection(v4([10, 0, 0, 2]));

	let snaps: HashMap<IpAddr, PrefixSnapshot> = tracker.take_snapshot().into_iter().collect();
	assert_eq!(snaps.len(), 2);
	assert_eq!(snaps[&v4([10, 0, 0, 0])].syn_count, 2);
	assert!(
		!snaps.contains_key(&v4([10, 0, 2, 0])),
		"over-cap prefix was not stored"
	);
}

#[test]
fn tracker_source_cap_bounds_per_prefix_memory() {
	let tracker = SubnetTracker::with_limits(8, 3);
	for last in 1..=100u8 {
		tracker.record_connection(v4([203, 0, 113, last]));
	}
	assert_eq!(
		tracker.dropped_sources(),
		97,
		"only the first three distinct sources are stored"
	);

	let snaps = tracker.take_snapshot();
	assert_eq!(snaps.len(), 1);
	assert_eq!(snaps[0].1.syn_count, 100, "the aggregate counter is not capped");
	assert_eq!(snaps[0].1.unique_sources, 3);
}

#[test]
fn tracker_source_cap_counts_only_new_addresses() {
	let tracker = SubnetTracker::with_limits(1, 2);
	tracker.record_connection(v4([198, 51, 100, 1]));
	tracker.record_connection(v4([198, 51, 100, 2]));
	tracker.record_connection(v4([198, 51, 100, 3]));
	assert_eq!(tracker.dropped_sources(), 1);
	// Repeated traffic from a remembered source is not a dropped new source.
	tracker.record_connection(v4([198, 51, 100, 1]));
	assert_eq!(tracker.dropped_sources(), 1);
	tracker.record_connection(v4([198, 51, 100, 4]));
	assert_eq!(tracker.dropped_sources(), 2);
}

fn block_verdict(prefix: IpAddr) -> PrefixVerdict {
	PrefixVerdict {
		prefix,
		verdict: SubnetVerdict::Block,
		snapshot: PrefixSnapshot {
			syn_count: 4000,
			unique_sources: 64,
			..PrefixSnapshot::default()
		},
	}
}

#[test]
fn trusted_tracker_block_reaches_the_blacklist_with_the_configured_ttl() {
	let blacklist = Blacklist::new();
	let verdicts = [block_verdict(v4([203, 0, 113, 0]))];
	let banned = enforce_tracker_verdicts(&verdicts, &blacklist, Duration::from_secs(120), true, &[]);
	assert_eq!(banned, 1);
	assert!(blacklist.is_blocked(v4([203, 0, 113, 0])));
}

#[test]
fn untrusted_tracker_block_only_warns() {
	let blacklist = Blacklist::new();
	let verdicts = [block_verdict(v4([198, 51, 100, 0]))];
	let banned = enforce_tracker_verdicts(&verdicts, &blacklist, Duration::from_secs(120), false, &[]);
	assert_eq!(banned, 0);
	assert!(blacklist.is_empty());
}

#[test]
fn tracker_ban_uses_the_given_duration() {
	let blacklist = Blacklist::new();
	let verdicts = [block_verdict(v4([192, 0, 2, 0]))];
	enforce_tracker_verdicts(&verdicts, &blacklist, Duration::from_millis(1), true, &[]);
	std::thread::sleep(Duration::from_millis(2));
	assert!(
		!blacklist.is_blocked(v4([192, 0, 2, 0])),
		"ban must expire with its TTL"
	);
}

#[test]
fn non_block_verdicts_do_not_ban() {
	let blacklist = Blacklist::new();
	let mut verdict = block_verdict(v4([203, 0, 113, 0]));
	verdict.verdict = SubnetVerdict::Challenge;
	assert_eq!(
		enforce_tracker_verdicts(&[verdict], &blacklist, Duration::from_secs(60), true, &[]),
		0
	);
	assert!(blacklist.is_empty());
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

#[test]
fn prefix_key_normalises_ipv4_mapped_addresses() {
	// ::ffff:1.2.3.4
	let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304));
	let plain = v4([1, 2, 3, 4]);

	assert_eq!(
		PrefixKey::new(mapped),
		PrefixKey::new(plain),
		"a mapped client must produce one key in XDP prefix stats and the user-space tracker"
	);
	assert_eq!(
		PrefixKey::new(mapped).family,
		rampart::traffic::prefix::PREFIX_FAMILY_V4
	);
	assert_eq!(PrefixKey::new(mapped).to_prefix(), Some(prefix_of(mapped)));
	assert_eq!(PrefixKey::new(mapped).to_prefix(), Some(v4([1, 2, 3, 0])));
}

#[test]
fn tracker_block_is_suppressed_when_a_trusted_proxy_lives_in_the_prefix() {
	let blacklist = Blacklist::new();
	let verdicts = [block_verdict(v4([10, 9, 0, 0]))];
	let trusted: Vec<TrustedProxyCidr> = vec!["10.9.0.5/32".parse().expect("trusted cidr")];
	let banned = enforce_tracker_verdicts(&verdicts, &blacklist, Duration::from_secs(120), true, &trusted);
	assert_eq!(banned, 0, "a ban covering a trusted proxy must be suppressed");
	assert!(blacklist.is_empty());
}

#[test]
fn tracker_block_still_applies_when_trusted_networks_do_not_overlap() {
	let blacklist = Blacklist::new();
	let verdicts = [block_verdict(v4([10, 9, 0, 0]))];
	let trusted: Vec<TrustedProxyCidr> = vec!["192.0.2.0/24".parse().expect("trusted cidr")];
	let banned = enforce_tracker_verdicts(&verdicts, &blacklist, Duration::from_secs(120), true, &trusted);
	assert_eq!(banned, 1);
	assert!(blacklist.is_blocked(v4([10, 9, 0, 7])));
}
