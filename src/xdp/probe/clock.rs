//! Monotonic clock shared by the XDP userspace path.
//!
//! The kernel writes `bpf_ktime_get_ns()` values (CLOCK_MONOTONIC nanoseconds
//! since boot) into the ban maps, and the packet path compares expiry
//! against the same clock. Userspace must therefore never use `SystemTime`
//! (epoch nanoseconds, about 50 years larger) for bans.

/// Monotonic clock in ns since boot — the same clock as `bpf_ktime_get_ns()`,
/// which is what the XDP program compares ban expiry against. `SystemTime`
/// (epoch ns) is ~50 years larger, so bans written with it never expired.
///
/// # Panics
/// Never: `clock_gettime(CLOCK_MONOTONIC)` cannot fail on Linux.
#[must_use]
pub fn monotonic_ns() -> u64 {
	let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
	// SAFETY: `ts` is a valid, writable `timespec` and CLOCK_MONOTONIC is
	// always available on Linux (the only target of the `xdp` feature).
	unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
	let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
	secs.saturating_mul(1_000_000_000)
		.saturating_add(u64::try_from(ts.tv_nsec).unwrap_or(0))
}

/// Absolute ban expiry on the monotonic clock, saturating so an absurd duration
/// clamps to `u64::MAX` rather than wrapping into the past.
#[must_use]
pub fn blacklist_expiry_ns(now_ns: u64, duration_secs: u64) -> u64 {
	now_ns.saturating_add(duration_secs.saturating_mul(1_000_000_000))
}
