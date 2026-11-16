use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};
use libbpf_rs::{MapCore, MapFlags};

use super::XdpFilter;
use crate::xdp::probe::{blacklist_expiry_ns, monotonic_ns};

/// Encodes an LPM-trie key for `blacklist_map` and `whitelist_map`:
/// prefix length as a little-endian u32 in bytes 0..4 and the four IPv4
/// octets in network order in bytes 4..8 (`struct lpm_key` in `common.h`).
#[must_use]
pub fn blacklist_key(prefix_len: u8, v4: &[u8; 4]) -> [u8; 8] {
	ipv4_lpm_key(prefix_len, v4)
}

/// Encodes an LPM-trie key for `whitelist_map`; the layout is identical to
/// [`blacklist_key`] because both C maps use `struct lpm_key`.
#[must_use]
pub fn whitelist_key(prefix_len: u8, v4: &[u8; 4]) -> [u8; 8] {
	ipv4_lpm_key(prefix_len, v4)
}

/// Encodes an LPM-trie key for `blacklist6_map`: prefix length as a
/// little-endian u32 in bytes 0..4 and the 16-byte IPv6 address in network
/// order in bytes 4..20 (20 bytes total, matching the C `struct lpm_key6`).
#[must_use]
pub fn blacklist6_key(prefix_len: u8, v6: &[u8; 16]) -> [u8; 20] {
	ipv6_lpm_key(prefix_len, v6)
}

/// Encodes an LPM-trie key for `whitelist6_map`; identical to
/// [`blacklist6_key`] because both C maps use `struct lpm_key6`.
#[must_use]
pub fn whitelist6_key(prefix_len: u8, v6: &[u8; 16]) -> [u8; 20] {
	ipv6_lpm_key(prefix_len, v6)
}

fn ipv4_lpm_key(prefix_len: u8, v4: &[u8; 4]) -> [u8; 8] {
	let mut key = [0u8; 8];
	key[0..4].copy_from_slice(&u32::from(prefix_len).to_le_bytes());
	key[4..8].copy_from_slice(v4);
	key
}

fn ipv6_lpm_key(prefix_len: u8, v6: &[u8; 16]) -> [u8; 20] {
	let mut key = [0u8; 20];
	key[0..4].copy_from_slice(&u32::from(prefix_len).to_le_bytes());
	key[4..20].copy_from_slice(v6);
	key
}

/// Validates a CIDR prefix length and clears the host bits of `prefix`.
///
/// The kernel's LPM trie compares keys bit by bit, so `10.1.2.3/24` and
/// `10.1.2.0/24` are different keys for the same range: without masking, two
/// bans of the same subnet never share an entry and expiry bookkeeping falls
/// apart. A zero-length prefix is rejected because "ban the entire address
/// space" is never an intentional operator request.
///
/// # Errors
/// `prefix_len` is 0 or exceeds 32 for IPv4 / 128 for IPv6.
pub fn normalize_cidr(prefix: IpAddr, prefix_len: u8) -> Result<IpAddr> {
	match prefix {
		IpAddr::V4(addr) => {
			ensure_prefix_len(prefix_len, 32, "IPv4")?;
			Ok(IpAddr::V4(Ipv4Addr::from(mask_v4(addr, prefix_len))))
		},
		IpAddr::V6(addr) => {
			ensure_prefix_len(prefix_len, 128, "IPv6")?;
			Ok(IpAddr::V6(Ipv6Addr::from(mask_v6(addr, prefix_len))))
		},
	}
}

fn ensure_prefix_len(prefix_len: u8, max: u8, family: &str) -> Result<()> {
	if prefix_len == 0 || prefix_len > max {
		bail!("invalid {family} prefix length {prefix_len}: expected 1..={max}");
	}
	Ok(())
}

fn mask_v4(addr: Ipv4Addr, prefix_len: u8) -> [u8; 4] {
	let bits = u32::from(addr);
	let mask = u32::MAX << (32 - u32::from(prefix_len));
	(bits & mask).to_be_bytes()
}

fn mask_v6(addr: Ipv6Addr, prefix_len: u8) -> [u8; 16] {
	let mut octets = addr.octets();
	let full_bytes = usize::from(prefix_len) / 8;
	let remainder = prefix_len % 8;
	for byte in octets.iter_mut().skip(full_bytes) {
		*byte = 0;
	}
	if remainder != 0 {
		// `full_bytes` is always < 16 here: a partial byte follows the full ones.
		octets[full_bytes] &= 0xffu8 << (8 - remainder);
	}
	octets
}

impl XdpFilter {
	/// Adds a CIDR ban to the matching LPM trie: `blacklist_map` for IPv4,
	/// `blacklist6_map` for IPv6.
	///
	/// The prefix is masked first (see [`normalize_cidr`]), so every ban of
	/// the same subnet addresses the same kernel key.
	///
	/// # Errors
	/// Invalid prefix length, XDP not loaded, map missing from the object, or
	/// a BPF update failure.
	pub fn ban_cidr(&self, prefix: IpAddr, prefix_len: u8, duration_secs: u64) -> Result<()> {
		match normalize_cidr(prefix, prefix_len)? {
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

	/// Adds one address to the kernel whitelist: `/32` for IPv4, `/128` for IPv6.
	///
	/// # Errors
	/// XDP not loaded, the matching whitelist map is missing, or a BPF update
	/// failure.
	pub fn whitelist_add(&self, ip: IpAddr) -> Result<()> {
		let prefix_len = match ip {
			IpAddr::V4(_) => 32,
			IpAddr::V6(_) => 128,
		};
		self.whitelist_add_cidr(ip, prefix_len)
	}

	/// Adds a CIDR to the matching whitelist LPM trie: `whitelist_map` for
	/// IPv4, `whitelist6_map` for IPv6.
	///
	/// The C filter treats a present key as "trusted" and ignores the value,
	/// so the stored `u8` is always `1`.
	///
	/// # Errors
	/// Invalid prefix length, XDP not loaded, map missing from the object, or
	/// a BPF update failure.
	pub fn whitelist_add_cidr(&self, prefix: IpAddr, prefix_len: u8) -> Result<()> {
		match normalize_cidr(prefix, prefix_len)? {
			IpAddr::V4(net) => {
				let map = self.find_map("whitelist_map")?;
				map.update(&whitelist_key(prefix_len, &net.octets()), &[1u8], MapFlags::ANY)?;
			},
			IpAddr::V6(net) => {
				let map = self.find_map("whitelist6_map")?;
				map.update(&whitelist6_key(prefix_len, &net.octets()), &[1u8], MapFlags::ANY)?;
			},
		}
		Ok(())
	}

	/// Removes one address from the kernel whitelist.
	///
	/// # Errors
	/// XDP not loaded, the matching whitelist map is missing, or a BPF delete
	/// failure.
	pub fn whitelist_remove(&self, ip: IpAddr) -> Result<()> {
		match ip {
			IpAddr::V4(addr) => {
				let map = self.find_map("whitelist_map")?;
				map.delete(&whitelist_key(32, &addr.octets()))?;
			},
			IpAddr::V6(addr) => {
				let map = self.find_map("whitelist6_map")?;
				map.delete(&whitelist6_key(128, &addr.octets()))?;
			},
		}
		Ok(())
	}

	/// Removes expired entries from `blacklist_map` and `blacklist6_map`.
	///
	/// The packet path can only expire the exact `/32` or `/128` key it looked
	/// up, so a ban on a wider prefix (for example a `/24`) stays resident and
	/// keeps blocking sources until it is deleted here. Call periodically.
	///
	/// Expiry semantics are the kernel's: an entry is alive while
	/// `expiry > bpf_ktime_get_ns()`. There is no "permanent" sentinel; `0` is
	/// already expired and is deleted, while a permanent ban is stored as
	/// `u64::MAX` and naturally survives every comparison. Keys are collected
	/// before deletion because the LPM iterator is not stable across deletes,
	/// and the expiry is re-read immediately before the delete so a
	/// concurrent refresh wins over the reaper.
	///
	/// # Errors
	/// XDP not loaded, a blacklist map is missing, or a BPF lookup/delete fails.
	pub fn reap_expired_bans(&self) -> Result<usize> {
		let now = monotonic_ns();
		let reaped = self.reap_map("blacklist_map", now)? + self.reap_map("blacklist6_map", now)?;
		Ok(reaped)
	}

	fn reap_map(&self, name: &str, now: u64) -> Result<usize> {
		let map = self.find_map(name)?;
		let keys: Vec<Vec<u8>> = map.keys().collect();
		let mut reaped = 0;
		for key in keys {
			let Some(value) = map.lookup(&key, MapFlags::ANY)? else {
				continue;
			};
			let Ok(raw) = <[u8; 8]>::try_from(value.as_slice()) else {
				continue;
			};
			if u64::from_le_bytes(raw) > now {
				continue;
			}
			// A ban may have been refreshed after the first read; never delete a fresh one.
			let Some(value) = map.lookup(&key, MapFlags::ANY)? else {
				continue;
			};
			let Ok(raw) = <[u8; 8]>::try_from(value.as_slice()) else {
				continue;
			};
			if u64::from_le_bytes(raw) > monotonic_ns() {
				continue;
			}
			map.delete(&key)?;
			reaped += 1;
		}
		Ok(reaped)
	}

	pub fn unban_ip(&self, ip: Ipv4Addr) -> Result<()> {
		let map = self.find_map("blacklist_map")?;
		let key = blacklist_key(32, &ip.octets());
		map.delete(&key)?;
		Ok(())
	}
}
