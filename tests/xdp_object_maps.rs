#![cfg(feature = "xdp")]

//! Contract between the loader (`src/xdp/filter/*`) and the C object: map names and the
//! `.rodata` size. Catches drift without root and without loading the program into the
//! kernel — exactly the class of bug that made XDP fail silently ("events_map not found",
//! "Invalid argument" on `.rodata`).

use libbpf_rs::ObjectBuilder;
use rampart::xdp::RODATA_SIZE;

fn open_object() -> libbpf_rs::OpenObject {
	let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/universal_filter.o"));
	ObjectBuilder::default()
		.name("rampart")
		.expect("object name")
		.open_memory(bytes)
		.expect("open XDP object (ELF/BTF parse must not need privileges)")
}

#[test]
fn every_map_the_loader_uses_exists_in_the_object() {
	let obj = open_object();
	let names: Vec<String> = obj.maps().map(|m| m.name().to_string_lossy().into_owned()).collect();
	// Names come from `find_map`, `build_ringbuf` and `patch_rodata`.
	for expected in [
		"stats_map",
		"prefix_stats",
		"events_ringbuf",
		"blacklist_map",
		"blacklist6_map",
		"whitelist_map",
		"whitelist6_map",
		"udp_rate_limit",
		"udp_rate_limit6",
	] {
		assert!(
			names.iter().any(|n| n == expected),
			"loader expects map '{expected}', object has {names:?}"
		);
	}
	assert!(
		names.iter().any(|n| n.ends_with(".rodata")),
		"loader expects a '.rodata' map, object has {names:?}"
	);
}

#[test]
fn rodata_map_value_size_matches_loader_image() {
	let obj = open_object();
	let map = obj
		.maps()
		.find(|m| m.name().to_string_lossy().ends_with(".rodata"))
		.expect("rodata map");
	assert_eq!(
		map.value_size() as usize,
		RODATA_SIZE,
		"sizeof(struct rampart_config) in config.h must equal sizeof(XdpGlobals)"
	);
}

#[test]
fn map_key_and_value_sizes_match_the_rust_encoding() {
	let obj = open_object();
	// (map, key size, value size) as encoded by src/xdp/filter/maps.rs and
	// src/xdp/probe/stats.rs. The C structs come from xdp/core/common.h,
	// xdp/core/prefix_stats.h and xdp/core/maps.h.
	let expected = [
		("blacklist_map", 8, 8),
		("blacklist6_map", 20, 8),
		("whitelist_map", 8, 1),
		("whitelist6_map", 20, 1),
		("prefix_stats", 24, 24),
		("stats_map", 4, 8),
	];
	for (name, key_size, value_size) in expected {
		let map = obj.maps().find(|m| m.name().to_string_lossy() == name);
		assert!(map.is_some(), "map '{name}' is missing from the XDP object");
		let map = map.expect("map existence asserted above");
		assert_eq!(
			map.key_size(),
			key_size,
			"map '{name}' key size drifted from the Rust encoding"
		);
		assert_eq!(
			map.value_size(),
			value_size,
			"map '{name}' value size drifted from the Rust encoding"
		);
	}
}
