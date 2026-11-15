//! Часы бана: XDP сравнивает expiry с `bpf_ktime_get_ns()` (монотонные ns
//! с загрузки), поэтому userspace обязан писать то же самое. Регрессия:
//! раньше писался `SystemTime` (epoch ns ≈ 1.7e18), и бан не истекал никогда.
#![cfg(feature = "xdp")]

use rampart::xdp::monotonic_ns;

fn clock_monotonic_ns() -> u64 {
	let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
	// SAFETY: `ts` — валидный writable `timespec`; CLOCK_MONOTONIC на Linux
	// поддерживается всегда (xdp-фича собирается только под Linux).
	let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
	assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
	let secs = u64::try_from(ts.tv_sec).expect("tv_sec fits u64");
	let nanos = u64::try_from(ts.tv_nsec).expect("tv_nsec fits u64");
	secs * 1_000_000_000 + nanos
}

#[test]
fn ban_clock_is_monotonic_not_wall_clock() {
	let expected = clock_monotonic_ns();
	let got = monotonic_ns();

	let diff = got.abs_diff(expected);
	assert!(
		diff < 5_000_000_000,
		"monotonic_ns must read CLOCK_MONOTONIC: got {got}, expected ~{expected}"
	);
}
