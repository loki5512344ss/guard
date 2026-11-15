//! Integration tests for the wire format and the auto-ban policy of XDP events.
//! No kernel or Redis needed: the pure parser and decision are covered, plus config defaults.
#![cfg(feature = "xdp")]

use rampart::config::Config;
use rampart::xdp::{AutoBanConfig, XDP_EVENT_LEN, XdpEventKind, auto_ban_decision, parse_xdp_event};
use std::net::Ipv4Addr;

const IP: [u8; 4] = [203, 0, 113, 7];

/// Builds a frame exactly as the kernel does (`push_event`, common.h:87-97): scalars in
/// native (host) order, `src_ip` in network octet order (raw from the packet header).
fn frame(kind: u32, octets: [u8; 4], metadata: u32, ts: u64) -> [u8; XDP_EVENT_LEN] {
	let mut b = [0u8; XDP_EVENT_LEN];
	b[0..4].copy_from_slice(&kind.to_ne_bytes());
	b[4..8].copy_from_slice(&octets);
	b[8..12].copy_from_slice(&metadata.to_ne_bytes());
	// b[12..16] is padding for `__u64`; the kernel does not initialise it.
	b[16..24].copy_from_slice(&ts.to_ne_bytes());
	b
}

#[test]
fn struct_size_is_24_bytes() {
	// common.h layout: __u32 x3 + pad(4) + __u64 = 24, not 16 as the code parsed before.
	assert_eq!(XDP_EVENT_LEN, 24);
}

#[test]
fn round_trip_recovers_all_fields() {
	let ev = parse_xdp_event(&frame(1, IP, 100, 0xDEAD_BEEF)).expect("valid frame parses");
	assert_eq!(ev.kind, XdpEventKind::RateLimit);
	assert_eq!(ev.src_ip, Ipv4Addr::new(203, 0, 113, 7));
	assert_eq!(ev.metadata, 100);
	assert_eq!(ev.timestamp_ns, 0xDEAD_BEEF);
}

#[test]
fn dirty_padding_does_not_corrupt_parse() {
	let mut f = frame(3, IP, 5, 0x1_0000_0000);
	f[12..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
	let ev = parse_xdp_event(&f).expect("padding must be ignored");
	assert_eq!(ev.kind, XdpEventKind::ConnDrop);
	assert_eq!(ev.metadata, 5);
	assert_eq!(ev.timestamp_ns, 0x1_0000_0000);
}

#[test]
fn src_ip_is_network_order_octets_not_native_u32() {
	// Key endianness insight: the octets sit in dotted order directly.
	let f = frame(2, [198, 51, 100, 23], 0, 0);
	let ev = parse_xdp_event(&f).expect("parses");
	assert_eq!(ev.src_ip, Ipv4Addr::new(198, 51, 100, 23));
	// The old bug (`u32::from_ne_bytes` -> `Ipv4Addr::from(u32)`) produced a reversed
	// address on little-endian; this pins down that we do not do that.
	if cfg!(target_endian = "little") {
		let naive = u32::from_ne_bytes(<[u8; 4]>::try_from(&f[4..8]).expect("4 octets"));
		assert_eq!(Ipv4Addr::from(naive), Ipv4Addr::new(23, 100, 51, 198));
		assert_ne!(Ipv4Addr::from(naive), ev.src_ip);
	}
}

#[test]
fn truncated_frames_are_rejected() {
	let full = frame(1, IP, 0, 0);
	assert!(parse_xdp_event(&full[..16]).is_none(), "старая длина 16 — не валидна");
	assert!(parse_xdp_event(&full[..23]).is_none(), "на 1 байт короче — не валидна");
	assert!(parse_xdp_event(&full).is_some(), "ровно 24 — валидна");
	assert!(parse_xdp_event(&[]).is_none());
}

#[test]
fn unknown_event_type_is_rejected() {
	for kind in [4u32, 9, 255, u32::MAX] {
		assert!(parse_xdp_event(&frame(kind, IP, 0, 0)).is_none(), "type {kind} unknown");
	}
}

#[test]
fn decision_matrix_by_type_and_enablement() {
	let enabled = AutoBanConfig {
		enabled: true,
		..AutoBanConfig::default()
	};
	let disabled = AutoBanConfig {
		enabled: false,
		..AutoBanConfig::default()
	};
	// (kind, metadata=fails/hits, whether to ban when enabled)
	let rows = [
		(0u32, 255u32, false), // EVENT_BAN: already banned by the kernel, never
		(1, 100, true),        // EVENT_RATE_LIMIT: always ban
		(2, 0, false),         // EVENT_POLICY_DROP: the policy does not ban by default
		(3, 10, true),         // EVENT_CONN_DROP fails=10 >= 3: ban
		(3, 0, false),         // EVENT_CONN_DROP fails=0 (hook drop): no ban
		(3, 2, false),         // EVENT_CONN_DROP fails=2 < 3: no ban
	];
	for (kind, meta, should_ban_when_on) in rows {
		let ev = parse_xdp_event(&frame(kind, IP, meta, 0)).expect("known type");
		assert!(
			auto_ban_decision(&ev, &disabled).is_none(),
			"disabled: kind {kind} meta {meta} must never ban"
		);
		let decided = auto_ban_decision(&ev, &enabled).is_some();
		assert_eq!(
			decided, should_ban_when_on,
			"enabled: kind {kind} meta {meta} -> ban={decided}, expected {should_ban_when_on}"
		);
	}
}

#[test]
fn ban_carries_configured_duration_and_reason() {
	let cfg = AutoBanConfig {
		enabled: true,
		duration_secs: 120,
		conn_drop_fails: 3,
	};
	let rl = parse_xdp_event(&frame(1, IP, 0, 0)).expect("rate limit frame");
	let ban = auto_ban_decision(&rl, &cfg).expect("rate limit bans");
	assert_eq!(ban.ip, Ipv4Addr::new(203, 0, 113, 7));
	assert_eq!(ban.duration_secs, 120);
	assert_eq!(ban.reason, "xdp-rate-limit");

	let cd = parse_xdp_event(&frame(3, IP, 4, 0)).expect("conn drop frame");
	assert_eq!(
		auto_ban_decision(&cd, &cfg).expect("conn drop bans").reason,
		"xdp-conn-drop"
	);
}

#[test]
fn defaults_disable_autoban_without_xdp_keys() {
	let cfg = Config::parse_str("").expect("empty config parses");
	assert!(
		!cfg.xdp.auto_ban_enabled,
		"авто-бан обязан быть выключен по умолчанию (safe-by-default)"
	);
	assert_eq!(cfg.xdp.auto_ban_duration_secs, 60);
	assert_eq!(cfg.xdp.auto_ban_conn_drop_fails, 3);

	let policy = AutoBanConfig::from_xdp(&cfg.xdp);
	let rl = parse_xdp_event(&frame(1, IP, 0, 0)).expect("frame parses");
	assert!(auto_ban_decision(&rl, &policy).is_none(), "default policy bans nothing");
}

#[test]
fn xdp_section_enables_autoban_and_maps_fields() {
	let cfg = Config::parse_str(
		r#"
[xdp]
auto_ban_enabled = true
auto_ban_duration_secs = 45
auto_ban_conn_drop_fails = 5
"#,
	)
	.expect("[xdp] auto-ban keys parse");
	let policy = AutoBanConfig::from_xdp(&cfg.xdp);
	assert!(policy.enabled);
	assert_eq!(policy.duration_secs, 45);
	assert_eq!(policy.conn_drop_fails, 5);

	// fails=4 is below the new threshold of 5 (no ban); fails=5 reaches it (ban).
	let below = parse_xdp_event(&frame(3, IP, 4, 0)).expect("frame parses");
	assert!(auto_ban_decision(&below, &policy).is_none());
	let at = parse_xdp_event(&frame(3, IP, 5, 0)).expect("frame parses");
	assert_eq!(
		auto_ban_decision(&at, &policy)
			.expect("at-threshold bans")
			.duration_secs,
		45
	);
}
