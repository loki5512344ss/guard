use super::XdpFilter;
use anyhow::Result;
use libbpf_rs::{MapCore, MapFlags};
use std::net::{IpAddr, Ipv4Addr};

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

/// Encodes an LPM-trie key for `blacklist_map`: prefix length in byte 0 and the
/// four IPv4 octets in bytes 4..8 (bytes 1..3 are padding the kernel ignores).
pub(super) fn blacklist_key(prefix_len: u8, v4: &[u8; 4]) -> [u8; 8] {
	let mut key = [0u8; 8];
	key[0] = prefix_len;
	key[4..8].copy_from_slice(v4);
	key
}

/// Encodes an LPM-trie key for `blacklist6_map`: prefix length as a
/// little-endian u32 in bytes 0..4 and the 16-byte IPv6 address in network
/// order in bytes 4..20 (20 bytes total, matching the C `struct lpm_key6`).
pub fn blacklist6_key(prefix_len: u8, v6: &[u8; 16]) -> [u8; 20] {
	let mut key = [0u8; 20];
	key[0] = prefix_len;
	key[4..20].copy_from_slice(v6);
	key
}

/// Absolute ban expiry on the monotonic clock, saturating so an absurd duration
/// clamps to `u64::MAX` rather than wrapping into the past.
pub(super) fn blacklist_expiry_ns(now_ns: u64, duration_secs: u64) -> u64 {
	now_ns.saturating_add(duration_secs.saturating_mul(1_000_000_000))
}

impl XdpFilter {
	/// Adds a CIDR ban to the matching LPM trie: `blacklist_map` for IPv4,
	/// `blacklist6_map` for IPv6.
	///
	/// # Errors
	/// XDP not loaded, map missing from the object, or a BPF update failure.
	pub fn ban_cidr(&self, prefix: IpAddr, prefix_len: u8, duration_secs: u64) -> Result<()> {
		match prefix {
			IpAddr::V4(net) => self.blacklist_update(prefix_len, &net.octets(), duration_secs),
			IpAddr::V6(net) => self.blacklist6_update(prefix_len, &net.octets(), duration_secs),
		}
	}

	fn blacklist_update(&self, prefix_len: u8, v4: &[u8; 4], duration_secs: u64) -> Result<()> {
		let map = self.find_map("blacklist_map")?;
		let key = blacklist_key(prefix_len, v4);
		let expiry_ns = blacklist_expiry_ns(monotonic_ns(), duration_secs);
		map.update(&key, &expiry_ns.to_le_bytes(), MapFlags::ANY)?;
		Ok(())
	}

	fn blacklist6_update(&self, prefix_len: u8, v6: &[u8; 16], duration_secs: u64) -> Result<()> {
		let map = self.find_map("blacklist6_map")?;
		let key = blacklist6_key(prefix_len, v6);
		let expiry_ns = blacklist_expiry_ns(monotonic_ns(), duration_secs);
		map.update(&key, &expiry_ns.to_le_bytes(), MapFlags::ANY)?;
		Ok(())
	}

	pub fn unban_ip(&self, ip: Ipv4Addr) -> Result<()> {
		let map = self.find_map("blacklist_map")?;
		let key = blacklist_key(32, &ip.octets());
		map.delete(&key)?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn blacklist_key_puts_prefix_len_first_and_octets_last() {
		assert_eq!(blacklist_key(24, &[10, 0, 1, 200]), [24, 0, 0, 0, 10, 0, 1, 200]);
		assert_eq!(blacklist_key(32, &[127, 0, 0, 1]), [32, 0, 0, 0, 127, 0, 0, 1]);
	}

	#[test]
	fn blacklist_expiry_converts_secs_to_ns() {
		assert_eq!(blacklist_expiry_ns(1_000, 2), 1_000 + 2_000_000_000);
	}

	#[test]
	fn blacklist_expiry_saturates_instead_of_wrapping() {
		assert_eq!(blacklist_expiry_ns(u64::MAX, 1), u64::MAX);
		assert_eq!(blacklist_expiry_ns(0, u64::MAX), u64::MAX);
	}
}
