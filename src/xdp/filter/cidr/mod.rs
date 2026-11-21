//! CIDR validation and canonicalisation shared by the ban and whitelist paths.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

/// Prefix bits that an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) spends before its IPv4 part.
const MAPPED_V4_BITS: u8 = 96;

/// Validates a CIDR prefix length and clears the host bits of `prefix`.
///
/// The kernel's LPM trie compares keys bit by bit, so `10.1.2.3/24` and
/// `10.1.2.0/24` are different keys for the same range: without masking, two
/// bans of the same subnet never share an entry and expiry bookkeeping falls
/// apart. A zero-length prefix is rejected because "ban the entire address
/// space" is never an intentional operator request.
///
/// IPv4-mapped IPv6 input is folded into IPv4 (see [`canonical_cidr`]); only the
/// address is returned here, use [`canonical_cidr`] when the length is needed too.
///
/// # Errors
/// `prefix_len` is 0 or exceeds 32 for IPv4 / 128 for IPv6, or a mapped address
/// carries a prefix of exactly 96 bits (an empty IPv4 prefix).
pub fn normalize_cidr(prefix: IpAddr, prefix_len: u8) -> Result<IpAddr> {
	canonical_cidr(prefix, prefix_len).map(|(net, _)| net)
}

/// Like [`normalize_cidr`], but also returns the prefix length to use in the key.
///
/// XDP looks up a plain IPv4 packet in the IPv4 trie, so a ban of the mapped form
/// `::ffff:a.b.c.d/(96+n)` must land there as `a.b.c.d/n`, exactly as the userspace
/// blacklist treats it. A mapped address with a prefix shorter than 96 bits spans
/// more than IPv4 space and stays an IPv6 prefix.
///
/// # Errors
/// Same as [`normalize_cidr`].
pub fn canonical_cidr(prefix: IpAddr, prefix_len: u8) -> Result<(IpAddr, u8)> {
	match prefix {
		IpAddr::V4(addr) => {
			ensure_prefix_len(prefix_len, 32, "IPv4")?;
			Ok((IpAddr::V4(Ipv4Addr::from(mask_v4(addr, prefix_len))), prefix_len))
		},
		IpAddr::V6(addr) => {
			ensure_prefix_len(prefix_len, 128, "IPv6")?;
			if let Some(v4) = addr.to_ipv4_mapped()
				&& prefix_len >= MAPPED_V4_BITS
			{
				return canonical_cidr(IpAddr::V4(v4), prefix_len - MAPPED_V4_BITS);
			}
			Ok((IpAddr::V6(Ipv6Addr::from(mask_v6(addr, prefix_len))), prefix_len))
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
	let shift = 32_u32.saturating_sub(u32::from(prefix_len));
	let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
	(u32::from(addr) & mask).to_be_bytes()
}

fn mask_v6(addr: Ipv6Addr, prefix_len: u8) -> [u8; 16] {
	let shift = 128_u32.saturating_sub(u32::from(prefix_len));
	let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
	(u128::from(addr) & mask).to_be_bytes()
}
