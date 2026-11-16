//! Integration tests for the accept-path filters: token-bucket rate limiting
//! and blacklist TTL handling.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use rampart::filter::blacklist::Blacklist;
use rampart::filter::rate_limit::RateLimiter;

fn ip(octet: u8) -> IpAddr {
	IpAddr::V4(Ipv4Addr::new(192, 168, 0, octet))
}

#[test]
fn rate_limiter_allows_burst_then_blocks() {
	let limiter = RateLimiter::new(1.0, 3.0);
	for _ in 0..3 {
		assert!(limiter.check(ip(1)), "burst tokens must be available");
	}
	assert!(!limiter.check(ip(1)), "exhausted bucket must block");
	assert!(limiter.check(ip(2)), "other IPs are independent buckets");
}

#[test]
fn rate_limiter_refills_over_time() {
	let limiter = RateLimiter::new(100.0, 1.0);
	assert!(limiter.check(ip(3)));
	assert!(!limiter.check(ip(3)));
	std::thread::sleep(Duration::from_millis(30));
	assert!(limiter.check(ip(3)), "tokens must refill at configured rate");
}

#[test]
fn rate_limiter_buckets_are_independent() {
	let limiter = RateLimiter::new(1.0, 1.0);
	assert!(limiter.check(ip(4)));
	assert!(!limiter.check(ip(4)));
	assert!(limiter.check(ip(5)), "other IPs are independent buckets");
}

#[test]
fn blacklist_blocks_until_ttl_expires() {
	let blacklist = Blacklist::new();
	blacklist.add(ip(6), Duration::from_millis(30), "test");

	assert!(blacklist.is_blocked(ip(6)), "fresh ban must block");
	assert_eq!(blacklist.len(), 1);
	std::thread::sleep(Duration::from_millis(40));
	assert!(!blacklist.is_blocked(ip(6)), "expired ban must not block");
	assert!(blacklist.is_empty(), "expired entry must be dropped on check");
}

#[test]
fn blacklist_remove_clears_ban() {
	let blacklist = Blacklist::new();
	blacklist.add(ip(7), Duration::from_secs(60), "test");
	blacklist.remove(ip(7));
	assert!(!blacklist.is_blocked(ip(7)));
}

#[test]
fn blacklist_expired_cleanup_keeps_fresh_reban() {
	let blacklist = Blacklist::new();
	blacklist.add(ip(8), Duration::ZERO, "stale");
	assert!(!blacklist.is_blocked(ip(8)), "zero-duration ban is already expired");

	blacklist.add(ip(8), Duration::from_secs(60), "fresh");
	assert!(
		blacklist.is_blocked(ip(8)),
		"expired-entry cleanup must not delete a fresh ban"
	);
	assert_eq!(blacklist.len(), 1);
}

#[test]
fn blacklist_expired_cleanup_does_not_race_with_reban() {
	let blacklist = std::sync::Arc::new(Blacklist::new());
	let reader = blacklist.clone();
	let handle = std::thread::spawn(move || {
		for _ in 0..2000 {
			let _ = reader.is_blocked(ip(9));
			std::thread::yield_now();
		}
	});
	for _ in 0..2000 {
		blacklist.add(ip(9), Duration::ZERO, "stale");
		blacklist.add(ip(9), Duration::from_secs(60), "fresh");
	}
	handle.join().expect("reader thread must not panic");
	assert!(
		blacklist.is_blocked(ip(9)),
		"a concurrently refreshed ban must survive stale cleanup"
	);
}

#[test]
fn blacklist_clamps_huge_durations_without_panicking() {
	let blacklist = Blacklist::new();
	blacklist.add(ip(10), Duration::from_secs(u64::MAX), "hostile");
	blacklist.add_redis(ip(11), Duration::from_secs(u64::MAX), "hostile");

	assert!(blacklist.is_blocked(ip(10)), "local ban must be clamped, not dropped");
	assert!(blacklist.is_blocked(ip(11)), "redis ban must be clamped, not dropped");
}

#[test]
fn replace_redis_keeps_new_bans_and_local_entries() {
	let blacklist = Blacklist::new();
	blacklist.add(ip(12), Duration::from_secs(60), "local");
	blacklist.add_redis(ip(13), Duration::from_secs(60), "stale-upstream");

	blacklist.replace_redis([
		(ip(14), Duration::from_secs(60), "upstream".to_string()),
		(ip(15), Duration::from_secs(60), "upstream".to_string()),
	]);

	assert!(blacklist.is_blocked(ip(14)), "new upstream ban must apply immediately");
	assert!(blacklist.is_blocked(ip(15)), "new upstream ban must apply immediately");
	assert!(!blacklist.is_blocked(ip(13)), "ban removed upstream must stop applying");
	assert!(
		blacklist.is_blocked(ip(12)),
		"local bans must survive a Redis reconcile"
	);
}

#[test]
fn replace_redis_can_clear_every_mirrored_ban() {
	let blacklist = Blacklist::new();
	blacklist.add_redis(ip(16), Duration::from_secs(60), "stale-upstream");

	blacklist.replace_redis(std::iter::empty());

	assert!(!blacklist.is_blocked(ip(16)));
	assert!(blacklist.is_empty());
}

fn numbered(index: u32) -> IpAddr {
	IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + index))
}

#[test]
fn rate_limiter_enforces_a_hard_bucket_cap() {
	let limiter = RateLimiter::with_capacity(1.0, 1.0, 4, Duration::from_secs(600));
	let admitted = (0..100).filter(|index| limiter.check(numbered(*index))).count();
	assert_eq!(admitted, 4, "only max_buckets new sources may be admitted");
	assert_eq!(limiter.len(), 4);
	assert!(
		!limiter.check(numbered(500)),
		"a new source fails closed once the table is saturated"
	);
	assert_eq!(limiter.len(), 4, "a refused source must not allocate a bucket");
}

#[test]
fn rate_limiter_sweep_frees_capacity_and_keeps_active() {
	let limiter = RateLimiter::with_capacity(1.0, 10.0, 2, Duration::from_millis(100));
	assert!(limiter.check(ip(1)));
	assert!(limiter.check(ip(2)));
	std::thread::sleep(Duration::from_millis(200));
	assert!(limiter.check(ip(2)), "the active source still has tokens");

	for _ in 0..8 {
		limiter.sweep();
	}
	assert_eq!(limiter.len(), 1, "idle bucket evicted, active bucket kept");
	assert!(limiter.check(ip(3)), "eviction must free a slot for a new source");
}

#[test]
fn rate_limiter_sweep_is_incremental() {
	let limiter = RateLimiter::with_capacity(1000.0, 1.0, 4096, Duration::from_millis(10));
	for index in 0..4096 {
		assert!(limiter.check(numbered(index)));
	}
	std::thread::sleep(Duration::from_millis(20));

	let first = limiter.sweep();
	assert!(first > 0, "the first sweep must reclaim idle buckets");
	assert!(first < 4096, "one sweep must not scan the whole table");
	assert!(!limiter.is_empty(), "a single sweep leaves work for the next tick");

	for _ in 0..8 {
		limiter.sweep();
	}
	assert!(limiter.is_empty(), "a full shard cycle reclaims every idle bucket");
}

#[test]
fn cidr_ban_covers_the_whole_range() {
	let blacklist = Blacklist::new();
	blacklist.add_cidr(
		IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
		24,
		Duration::from_secs(60),
		"subnet",
	);
	assert!(blacklist.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 1))));
	assert!(blacklist.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 255))));
	assert!(!blacklist.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 1, 3, 1))));
}

#[test]
fn cidr_ban_normalises_host_bits_and_v4_mapped_addresses() {
	let blacklist = Blacklist::new();
	blacklist.add_cidr(
		IpAddr::V4(Ipv4Addr::new(10, 7, 9, 200)),
		24,
		Duration::from_secs(60),
		"subnet",
	);
	let mapped: IpAddr = "::ffff:10.7.9.1".parse().expect("mapped ipv4");
	assert!(blacklist.is_blocked(mapped), "/24 ban must cover the mapped form too");
}

#[test]
fn cidr_ban_expires() {
	let blacklist = Blacklist::new();
	blacklist.add_cidr(
		IpAddr::V4(Ipv4Addr::new(10, 8, 0, 0)),
		16,
		Duration::from_millis(1),
		"subnet",
	);
	std::thread::sleep(Duration::from_millis(5));
	assert!(!blacklist.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))));
	blacklist.clear_expired();
	assert!(blacklist.is_empty());
}

#[test]
fn invalid_cidr_prefix_is_ignored() {
	let blacklist = Blacklist::new();
	blacklist.add_cidr(
		IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
		0,
		Duration::from_secs(60),
		"subnet",
	);
	blacklist.add_cidr(
		IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
		33,
		Duration::from_secs(60),
		"subnet",
	);
	assert!(blacklist.is_empty(), "a /0 or /33 ban must not be installed");
}

#[test]
fn ipv6_cidr_ban_covers_the_range() {
	let blacklist = Blacklist::new();
	let prefix: IpAddr = "fd00:1234:5678:9abc::".parse().expect("ipv6 prefix");
	blacklist.add_cidr(prefix, 64, Duration::from_secs(60), "subnet");
	let inside: IpAddr = "fd00:1234:5678:9abc::42".parse().expect("ipv6 inside");
	let outside: IpAddr = "fd00:1234:5678:9abd::1".parse().expect("ipv6 outside");
	assert!(blacklist.is_blocked(inside));
	assert!(!blacklist.is_blocked(outside));
}
