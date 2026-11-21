//! Prefix/CIDR validation for every ban and whitelist entry point.
//!
//! A `/0` would blackhole (or whitelist) a whole address family, anything above the
//! address width is nonsense, and the mask math must never shift by the full width.
#![cfg(feature = "xdp")]

use std::net::IpAddr;
use std::time::Duration;

use rampart::filter::blacklist::Blacklist;
use rampart::xdp::{canonical_cidr, normalize_cidr};

fn ip(s: &str) -> IpAddr {
	s.parse().expect("test address")
}

#[test]
fn zero_prefix_is_rejected_for_both_families() {
	assert!(normalize_cidr(ip("10.0.0.1"), 0).is_err());
	assert!(normalize_cidr(ip("2001:db8::1"), 0).is_err());
	assert!(canonical_cidr(ip("::ffff:10.0.0.1"), 0).is_err());
}

#[test]
fn prefix_above_the_address_width_is_rejected() {
	assert!(normalize_cidr(ip("10.0.0.1"), 33).is_err());
	assert!(normalize_cidr(ip("10.0.0.1"), 255).is_err());
	assert!(normalize_cidr(ip("2001:db8::1"), 129).is_err());
}

#[test]
fn full_width_prefixes_do_not_overflow_the_mask() {
	assert_eq!(normalize_cidr(ip("10.1.2.3"), 32).expect("/32"), ip("10.1.2.3"));
	assert_eq!(normalize_cidr(ip("2001:db8::1"), 128).expect("/128"), ip("2001:db8::1"));
	assert_eq!(normalize_cidr(ip("10.1.2.3"), 1).expect("/1"), ip("0.0.0.0"));
	assert_eq!(normalize_cidr(ip("ffff::1"), 1).expect("/1"), ip("8000::"));
}

#[test]
fn ipv6_masks_partial_bytes() {
	assert_eq!(
		normalize_cidr(ip("2001:db8:ffff::1"), 36).expect("/36"),
		ip("2001:db8:f000::")
	);
}

#[test]
fn mapped_ipv6_folds_into_ipv4_with_the_length_shifted() {
	let (net, len) = canonical_cidr(ip("::ffff:10.1.2.3"), 120).expect("mapped /120");
	assert_eq!((net, len), (ip("10.1.2.0"), 24));
	let (net, len) = canonical_cidr(ip("::ffff:10.1.2.3"), 128).expect("mapped /128");
	assert_eq!((net, len), (ip("10.1.2.3"), 32));
	// The empty IPv4 prefix is /0 in disguise.
	assert!(canonical_cidr(ip("::ffff:10.1.2.3"), 96).is_err());
	// Wider than IPv4 space: stays IPv6.
	let (net, len) = canonical_cidr(ip("::ffff:10.1.2.3"), 64).expect("mapped /64");
	assert_eq!((net, len), (ip("::"), 64));
}

#[test]
fn userspace_blacklist_rejects_zero_and_oversized_prefixes() {
	let blacklist = Blacklist::new();
	for (addr, len) in [
		("10.0.0.1", 0),
		("10.0.0.1", 33),
		("2001:db8::1", 0),
		("2001:db8::1", 129),
		("::ffff:10.0.0.1", 0),
		("::ffff:10.0.0.1", 96),
	] {
		blacklist.add_cidr(ip(addr), len, Duration::from_secs(60), "test");
	}
	assert!(blacklist.is_empty(), "no invalid CIDR may be installed");
	assert!(!blacklist.is_blocked(ip("10.0.0.1")));
}

#[test]
fn userspace_blacklist_accepts_full_width_prefixes() {
	let blacklist = Blacklist::new();
	blacklist.add_cidr(ip("10.0.0.7"), 32, Duration::from_secs(60), "test");
	blacklist.add_cidr(ip("2001:db8::7"), 128, Duration::from_secs(60), "test");
	assert!(blacklist.is_blocked(ip("10.0.0.7")));
	assert!(!blacklist.is_blocked(ip("10.0.0.8")));
	assert!(blacklist.is_blocked(ip("2001:db8::7")));
	assert!(!blacklist.is_blocked(ip("2001:db8::8")));
}

#[test]
fn userspace_blacklist_folds_mapped_prefixes_like_the_xdp_loader() {
	let blacklist = Blacklist::new();
	blacklist.add_cidr(ip("::ffff:10.9.8.7"), 120, Duration::from_secs(60), "test");
	assert!(blacklist.is_blocked(ip("10.9.8.200")), "/120 mapped == v4 /24");
	assert!(!blacklist.is_blocked(ip("10.9.9.1")));
	assert!(blacklist.is_blocked(ip("::ffff:10.9.8.1")));
}
