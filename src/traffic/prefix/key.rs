use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `family` tag for IPv4 prefixes (/24).
pub const PREFIX_FAMILY_V4: u8 = 4;
/// `family` tag for IPv6 prefixes (/64).
pub const PREFIX_FAMILY_V6: u8 = 6;

/// Key of the `prefix_stats` map (`BPF_MAP_TYPE_LRU_HASH`, 65536 entries).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixKey {
	pub family: u8,
	pub pad: [u8; 7],
	pub addr: [u8; 16],
}

impl PrefixKey {
	/// Builds the prefix key for an address (v4 maps to /24 in the first four
	/// bytes, v6 maps to /64).
	///
	/// The address is normalised through [`prefix_of`] first, so an
	/// IPv4-mapped IPv6 source (`::ffff:a.b.c.d`) produces exactly the same key
	/// as the plain IPv4 address. XDP `prefix_stats` entries and the user-space
	/// tracker therefore agree on the bucket of a dual-stack client.
	#[must_use]
	pub fn new(ip: IpAddr) -> Self {
		let mut key = Self::default();
		match prefix_of(ip) {
			IpAddr::V4(v4) => {
				key.family = PREFIX_FAMILY_V4;
				key.addr[..4].copy_from_slice(&v4.octets());
			},
			IpAddr::V6(v6) => {
				key.family = PREFIX_FAMILY_V6;
				key.addr.copy_from_slice(&v6.octets());
			},
		}
		key
	}

	/// The prefix as a masked IP address; `None` for an unknown `family` tag.
	#[must_use]
	pub fn to_prefix(self) -> Option<IpAddr> {
		match self.family {
			PREFIX_FAMILY_V4 => Some(IpAddr::V4(Ipv4Addr::new(
				self.addr[0],
				self.addr[1],
				self.addr[2],
				self.addr[3],
			))),
			PREFIX_FAMILY_V6 => Some(IpAddr::V6(Ipv6Addr::from(self.addr))),
			_ => None,
		}
	}

	#[must_use]
	pub fn from_bytes(bytes: [u8; 24]) -> Self {
		Self {
			family: bytes[0],
			pad: bytes[1..8].try_into().expect("7 pad bytes"),
			addr: bytes[8..24].try_into().expect("16 addr bytes"),
		}
	}

	#[must_use]
	pub fn to_bytes(self) -> [u8; 24] {
		let mut out = [0u8; 24];
		out[0] = self.family;
		out[1..8].copy_from_slice(&self.pad);
		out[8..24].copy_from_slice(&self.addr);
		out
	}
}

/// Returns the prefix of an address: IPv4 and IPv4-mapped share /24, IPv6 uses /64.
#[must_use]
pub fn prefix_of(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V4(v4) => IpAddr::V4(masked_v4(v4)),
		IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
			// ::ffff:a.b.c.d must land in the same /24 bucket as a.b.c.d,
			// otherwise a dual-stack client could escape its own ban.
			Some(v4) => IpAddr::V4(masked_v4(v4)),
			None => IpAddr::V6(Ipv6Addr::from(masked_v6_segments(v6))),
		},
	}
}

fn masked_v4(ip: Ipv4Addr) -> Ipv4Addr {
	let o = ip.octets();
	Ipv4Addr::new(o[0], o[1], o[2], 0)
}

fn masked_v6_segments(ip: Ipv6Addr) -> [u8; 16] {
	let mut segs = ip.octets();
	segs[8..].fill(0);
	segs
}
