//! CIDR ban table.
//!
//! Exact-address bans live in two `DashMap`s in [`super`]; substrate-wide bans
//! (`/24`, `/64`, ...) are stored here as inclusive address ranges. The table is
//! a plain `RwLock<Vec<_>>`: entries are few (the subnet monitor bans at most a
//! handful per tick), so a linear scan is cheaper than a trie, and the hard cap
//! bounds the worst case under abuse.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::Instant;

/// Upper bound on distinct CIDR bans kept in memory.
const MAX_PREFIX_BANS: usize = 256;

/// One CIDR ban, stored as an inclusive address range.
struct PrefixBan {
	start: IpAddr,
	end: IpAddr,
	expires: Instant,
}

/// Thread-safe set of active CIDR bans.
pub(super) struct PrefixBans {
	entries: RwLock<Vec<PrefixBan>>,
}

impl PrefixBans {
	/// Creates an empty table.
	pub(super) fn new() -> Self {
		Self {
			entries: RwLock::new(Vec::new()),
		}
	}

	/// Inserts `ip/prefix_len` until `expires`.
	///
	/// Returns the network address when the ban was inserted, or `None` for an
	/// invalid prefix length (`0`, `> 32` for IPv4, `> 128` for IPv6): a `/0`
	/// ban would blackhole an entire address family.
	pub(super) fn add(&self, ip: IpAddr, prefix_len: u8, expires: Instant) -> Option<IpAddr> {
		let (start, end) = cidr_range(ip, prefix_len)?;
		let now = Instant::now();
		let mut bans = self.entries.write().unwrap_or_else(|poison| poison.into_inner());
		bans.retain(|ban| ban.expires > now);
		if bans.len() >= MAX_PREFIX_BANS {
			bans.remove(0);
		}
		bans.push(PrefixBan { start, end, expires });
		Some(start)
	}

	/// Returns whether `ip` falls into an active CIDR ban.
	pub(super) fn is_blocked(&self, ip: IpAddr, now: Instant) -> bool {
		let bans = self.entries.read().unwrap_or_else(|poison| poison.into_inner());
		bans.iter().any(|ban| ban.expires > now && range_contains(ban, ip))
	}

	/// Drops expired CIDR bans.
	pub(super) fn clear_expired(&self, now: Instant) {
		self.entries
			.write()
			.unwrap_or_else(|poison| poison.into_inner())
			.retain(|ban| ban.expires > now);
	}

	/// Number of tracked CIDR bans (including not-yet-reaped expired ones).
	pub(super) fn len(&self) -> usize {
		self.entries.read().unwrap_or_else(|poison| poison.into_inner()).len()
	}
}

/// Converts `ip/prefix_len` into an inclusive address range.
///
/// IPv4-mapped IPv6 addresses are normalised to IPv4 first, matching the prefix
/// keys used by the subnet detector and the XDP prefix stats.
fn cidr_range(ip: IpAddr, prefix_len: u8) -> Option<(IpAddr, IpAddr)> {
	let ip = match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
		IpAddr::V4(_) => ip,
	};
	match ip {
		IpAddr::V4(v4) => {
			if prefix_len == 0 || prefix_len > 32 {
				return None;
			}
			let mask = u32::MAX << (32 - prefix_len);
			let base = u32::from(v4) & mask;
			Some((
				IpAddr::V4(Ipv4Addr::from(base)),
				IpAddr::V4(Ipv4Addr::from(base | !mask)),
			))
		},
		IpAddr::V6(v6) => {
			if prefix_len == 0 || prefix_len > 128 {
				return None;
			}
			let mask = u128::MAX << (128 - prefix_len);
			let base = u128::from(v6) & mask;
			Some((
				IpAddr::V6(Ipv6Addr::from(base)),
				IpAddr::V6(Ipv6Addr::from(base | !mask)),
			))
		},
	}
}

/// Returns whether `ip` is inside `ban`'s inclusive range.
fn range_contains(ban: &PrefixBan, ip: IpAddr) -> bool {
	match (ban.start, ban.end, ip) {
		(IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(addr)) => {
			u32::from(start) <= u32::from(addr) && u32::from(addr) <= u32::from(end)
		},
		(IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(addr)) => {
			u128::from(start) <= u128::from(addr) && u128::from(addr) <= u128::from(end)
		},
		_ => false,
	}
}
