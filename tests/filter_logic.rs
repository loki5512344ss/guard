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
