//! Micro-benchmarks for the per-connection hot path.
//!
//! Run with `cargo bench --all-features --bench hot_paths`. Baseline numbers
//! live in `docs/research/benchmark.md`; compare medians before and after a
//! change instead of absolute values, which depend on the machine.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use rampart::filter::blacklist::Blacklist;
use rampart::filter::rate_limit::RateLimiter;
use rampart::protocol::http::parser::{Policy, evaluate};
use rampart::traffic::prefix::{PrefixSnapshot, SubnetDetector};

fn addr(last: u8) -> IpAddr {
	IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
}

/// Token-bucket admission, the first filter on every accepted connection.
fn bench_rate_limiter(c: &mut Criterion) {
	c.bench_function("rate_limiter/check", |b| {
		let limiter = RateLimiter::new(1_000_000.0, 1_000_000.0);
		let mut n = 0u32;
		b.iter(|| {
			n = n.wrapping_add(1);
			black_box(limiter.check(addr((n % 200) as u8)));
		});
	});
}

/// Exact-IP and CIDR lookups of the ban tables (both on the accept path).
fn bench_blacklist(c: &mut Criterion) {
	let blacklist = Blacklist::new();
	for octet in 1..=200u8 {
		blacklist.add(addr(octet), Duration::from_secs(60), "bench");
	}
	blacklist.add_cidr(
		IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
		24,
		Duration::from_secs(60),
		"bench",
	);

	c.bench_function("blacklist/is_blocked_exact", |b| {
		let mut n = 0u32;
		b.iter(|| {
			n = n.wrapping_add(1);
			black_box(blacklist.is_blocked(addr((n % 200) as u8 + 1)));
		});
	});

	c.bench_function("blacklist/is_blocked_cidr", |b| {
		b.iter(|| black_box(blacklist.is_blocked(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)))));
	});

	c.bench_function("blacklist/is_blocked_miss", |b| {
		b.iter(|| black_box(blacklist.is_blocked(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))));
	});
}

/// Subnet detector over a full window (called once per monitor tick).
fn bench_detector(c: &mut Criterion) {
	let snapshots: Vec<(IpAddr, PrefixSnapshot)> = (0..256u32)
		.map(|i| {
			let prefix = IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 0));
			(
				prefix,
				PrefixSnapshot {
					syn_count: 120,
					pkt_count: 400,
					last_seen_ns: 0,
					unique_sources: 40,
				},
			)
		})
		.collect();
	let detector = SubnetDetector::new(100, 16);

	c.bench_function("subnet_detector/evaluate_256", |b| {
		b.iter(|| black_box(detector.evaluate(black_box(&snapshots))));
	});
}

/// HTTP request-head validation for every new HTTP connection.
fn bench_http_parser(c: &mut Criterion) {
	let request = b"GET /api/v1/status HTTP/1.1\r\nHost: edge.example\r\nUser-Agent: bench/1.0\r\nAccept: */*\r\n\r\n";
	let policy = Policy {
		max_header_bytes: 8192,
		blocked_paths: vec!["/admin".to_string()],
		require_user_agent: true,
	};

	c.bench_function("http_parser/evaluate", |b| {
		b.iter(|| black_box(evaluate(black_box(request), &policy)));
	});
}

criterion_group!(
	hot_paths,
	bench_rate_limiter,
	bench_blacklist,
	bench_detector,
	bench_http_parser
);
criterion_main!(hot_paths);
