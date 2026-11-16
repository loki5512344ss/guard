//! Layout of the `prefix_stats` BPF map value: the 32-byte little-endian
//! encoding round-trips and the struct size matches the kernel side.

use rampart::traffic::prefix::PrefixStatsVal;

#[test]
fn stats_val_roundtrip() {
	let val = PrefixStatsVal {
		syn_count: 42,
		pkt_count: 100,
		last_seen_ns: 1_234_567_890,
		source_bits: 0b1011,
	};
	assert_eq!(PrefixStatsVal::from_bytes(val.to_bytes()), val);
	assert_eq!(size_of::<PrefixStatsVal>(), 32);
}

#[test]
fn unique_sources_counts_set_bits() {
	let val = PrefixStatsVal {
		source_bits: 0b1011,
		..PrefixStatsVal::default()
	};
	assert_eq!(val.unique_sources(), 3);
}
