//! Pure helpers of the XDP loader: interface-name conversion, `.rodata` map
//! naming and the honest attach-mode names.
//!
//! These used to be inline tests in `src/xdp/filter/attach.rs`. They need no
//! kernel; the real attach path is exercised by the netns smoke scripts.
#![cfg(feature = "xdp")]

use rampart::xdp::{interface_cstr, is_rodata_map, xdp_attach_mode_name};

#[test]
fn interface_cstr_accepts_plain_names() {
	let c = interface_cstr("eth0").expect("valid interface name");
	assert_eq!(c.as_bytes(), b"eth0");
	assert_eq!(c.as_bytes_with_nul(), b"eth0\0");
}

#[test]
fn interface_cstr_rejects_interior_nul() {
	assert!(interface_cstr("et\0h0").is_err());
}

#[test]
fn rodata_map_matches_libbpf_naming() {
	// libbpf builds the name as `<obj><section>` without rewriting the dot
	// (libbpf.c ~1911); with open_memory and no name the object is called "memory":
	assert!(is_rodata_map("rampart.rodata"));
	assert!(is_rodata_map("memory.rodata"));
	assert!(is_rodata_map(".rodata"));
	assert!(!is_rodata_map("rampart.bss"));
	assert!(!is_rodata_map("stats_map"));
}

#[test]
fn attach_mode_names_are_honest() {
	// Kernel order (linux/netlink.h): NONE=0, DRV=1, SKB=2, HW=3, MULTI=4.
	assert_eq!(xdp_attach_mode_name(1), "native (drv)");
	assert_eq!(xdp_attach_mode_name(2), "generic (skb)");
	assert_eq!(xdp_attach_mode_name(3), "hardware offload");
	assert_eq!(xdp_attach_mode_name(0), "none");
	assert_eq!(xdp_attach_mode_name(4), "multiple programs");
}
