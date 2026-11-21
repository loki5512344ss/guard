//! ABI layout of every Rust type that mirrors a BPF map key/value, ringbuf record or
//! `.rodata` image.
//!
//! The expected numbers are parsed by hand from the C definitions in `xdp/core/`
//! (natural alignment rules of clang/BPF: every field aligned to its own size, struct
//! size rounded up to its largest member). A failure here means one side of the ABI
//! moved without the other. Value-level checks live in `xdp_globals.rs`,
//! `xdp_ban_keys.rs` and `xdp_whitelist_keys.rs`.

use std::mem::{align_of, offset_of, size_of};

use rampart::traffic::prefix::{PrefixKey, PrefixStatsVal};

#[test]
fn prefix_key_mirrors_struct_prefix_key() {
	// prefix_stats.h: struct prefix_key { __u8 family; __u8 pad[7]; __u8 addr[16]; }
	assert_eq!(size_of::<PrefixKey>(), 24);
	assert_eq!(align_of::<PrefixKey>(), 1);
	assert_eq!(offset_of!(PrefixKey, family), 0);
	assert_eq!(offset_of!(PrefixKey, pad), 1);
	assert_eq!(offset_of!(PrefixKey, addr), 8);
}

#[test]
fn prefix_key_byte_codec_matches_the_c_offsets() {
	let key = PrefixKey {
		family: 6,
		pad: [0; 7],
		addr: [7; 16],
	};
	let bytes = key.to_bytes();
	assert_eq!(bytes[0], 6, "family @0");
	assert_eq!(bytes[8..24], [7; 16], "addr @8");
	assert_eq!(PrefixKey::from_bytes(bytes), key);
}

#[test]
fn prefix_stats_val_mirrors_struct_prefix_stats_val() {
	// prefix_stats.h: struct prefix_stats_val { __u64 syn_count, pkt_count, last_seen_ns, source_bits; }
	assert_eq!(size_of::<PrefixStatsVal>(), 32);
	assert_eq!(align_of::<PrefixStatsVal>(), 8);
	assert_eq!(offset_of!(PrefixStatsVal, syn_count), 0);
	assert_eq!(offset_of!(PrefixStatsVal, pkt_count), 8);
	assert_eq!(offset_of!(PrefixStatsVal, last_seen_ns), 16);
	assert_eq!(offset_of!(PrefixStatsVal, source_bits), 24);
}

#[test]
fn prefix_stats_val_byte_codec_matches_the_c_offsets() {
	let val = PrefixStatsVal {
		syn_count: 1,
		pkt_count: 2,
		last_seen_ns: 3,
		source_bits: 4,
	};
	let bytes = val.to_bytes();
	for (i, expected) in [1u64, 2, 3, 4].into_iter().enumerate() {
		let at = i * 8;
		assert_eq!(
			u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes")),
			expected
		);
	}
}

#[cfg(feature = "xdp")]
mod xdp {
	use super::{align_of, offset_of, size_of};
	use rampart::xdp::{RODATA_SIZE, XDP_EVENT_LEN, XdpGlobals, blacklist_key, blacklist6_key};

	#[test]
	fn xdp_globals_mirrors_struct_rampart_config() {
		// config.h: struct rampart_config, sizeof == 96 (its own _Static_assert).
		assert_eq!(size_of::<XdpGlobals>(), 96);
		assert_eq!(align_of::<XdpGlobals>(), 8);
		assert_eq!(RODATA_SIZE, 96);
		let expected = [
			(offset_of!(XdpGlobals, start_port), 0),
			(offset_of!(XdpGlobals, end_port), 2),
			(offset_of!(XdpGlobals, syn_hit_count), 4),
			(offset_of!(XdpGlobals, syn_window_ns), 8),
			(offset_of!(XdpGlobals, syn_ban_duration_ns), 16),
			(offset_of!(XdpGlobals, conntrack_idle_ns), 24),
			(offset_of!(XdpGlobals, player_idle_ns), 32),
			(offset_of!(XdpGlobals, ban_duration_ns), 40),
			(offset_of!(XdpGlobals, max_out_of_order), 48),
			(offset_of!(XdpGlobals, udp_policy), 49),
			(offset_of!(XdpGlobals, udp_hit_count), 52),
			(offset_of!(XdpGlobals, udp_window_ns), 56),
			(offset_of!(XdpGlobals, feature_syn_throttle), 64),
			(offset_of!(XdpGlobals, feature_events), 65),
			(offset_of!(XdpGlobals, syn_challenge_enabled), 66),
			(offset_of!(XdpGlobals, challenge_secret), 72),
			(offset_of!(XdpGlobals, challenge_timeout_ms), 80),
			(offset_of!(XdpGlobals, challenge_verified_ttl_ns), 88),
		];
		for (rust, c) in expected {
			assert_eq!(rust, c);
		}
	}

	#[test]
	fn lpm_keys_have_the_size_of_struct_lpm_key_and_key6() {
		// common.h: struct lpm_key { __u32 prefixlen; __u32 ip; } -> 8
		assert_eq!(size_of_val(&blacklist_key(24, &[0; 4])), 8);
		// common.h: struct lpm_key6 { __u32 prefixlen; __u8 addr[16]; } -> 20, align 4
		assert_eq!(size_of_val(&blacklist6_key(64, &[0; 16])), 20);
	}

	#[test]
	fn xdp_event_len_matches_struct_xdp_event() {
		// common.h: struct xdp_event { __u32 type, src_ip, metadata; (4 pad) __u64 timestamp; } -> 24
		assert_eq!(XDP_EVENT_LEN, 24);
	}
}
