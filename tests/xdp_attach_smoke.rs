//! Opt-in live attach check for the XDP loader.
//!
//! Ignored by default: it needs root (CAP_BPF/CAP_NET_ADMIN) and a disposable
//! interface, best inside a throwaway network namespace. Run it through
//! `/tmp/opencode/loaderchk.sh` (creates a veth pair in a netns) or manually:
//!
//! ```text
//! sudo ip netns exec <ns> env RAMPART_XDP_TEST_IFACE=veth-test \
//!     target/debug/deps/xdp_attach_smoke-<hash> --ignored --nocapture
//! ```
//!
//! It covers the regressions this suite is about: the attach mode is
//! remembered for detach (a generic-mode attach must not leave an orphaned
//! filter behind), whitelist entries load into both LPM tries, a live ban
//! survives the reaper, an expired prefix ban is reaped, and `unload` reports
//! a clean interface.
#![cfg(feature = "xdp")]

use std::net::IpAddr;

use rampart::xdp::XdpFilter;

fn ip(text: &str) -> IpAddr {
	text.parse().expect("test literal must be a valid address")
}

#[test]
#[ignore = "needs root/CAP_NET_ADMIN and a disposable interface in a network namespace"]
fn attach_ban_whitelist_reap_and_detach() {
	let interface = std::env::var("RAMPART_XDP_TEST_IFACE")
		.expect("set RAMPART_XDP_TEST_IFACE to a disposable interface (inside a netns)");

	let mut filter = XdpFilter::new(&interface);
	filter.load().expect("XDP load and attach must succeed");

	filter
		.whitelist_add(ip("192.0.2.7"))
		.expect("IPv4 whitelist entry must load into whitelist_map");
	filter
		.whitelist_add(ip("2001:db8::7"))
		.expect("IPv6 whitelist entry must load into whitelist6_map");

	// A live prefix ban must not be removed by the periodic reaper.
	filter
		.ban_cidr(ip("10.1.2.3"), 24, 600)
		.expect("CIDR ban must be accepted");
	assert_eq!(
		filter.reap_expired_bans().expect("reaper must run"),
		0,
		"a ban that expires in 10 minutes must survive the reaper"
	);

	// A zero-duration ban is already expired on the monotonic clock.
	filter
		.ban_cidr(ip("10.9.8.7"), 24, 0)
		.expect("zero-duration ban must be accepted");
	assert!(
		filter.reap_expired_bans().expect("reaper must run") >= 1,
		"the expired prefix ban must be removed"
	);

	// unload() uses the remembered attach flags and verifies mode NONE.
	filter
		.unload()
		.expect("detach must succeed and leave the interface clean");
	drop(filter);

	// A second attach proves no orphaned program remained on the interface.
	let mut again = XdpFilter::new(&interface);
	again.load().expect("re-attach on the same interface must succeed");
	again.unload().expect("second detach must succeed");
}
