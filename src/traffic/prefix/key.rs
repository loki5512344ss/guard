use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `family` для IPv4-префиксов (/24).
pub const PREFIX_FAMILY_V4: u8 = 4;
/// `family` для IPv6-префиксов (/64).
pub const PREFIX_FAMILY_V6: u8 = 6;

/// Ключ карты `prefix_stats` (`BPF_MAP_TYPE_LRU_HASH`, max_entries 65536).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixKey {
    pub family: u8,
    pub pad: [u8; 7],
    pub addr: [u8; 16],
}

impl PrefixKey {
    /// Строит ключ префикса для адреса (v4 → /24 в первых 4 байтах, v6 → /64).
    #[must_use]
    pub fn new(ip: IpAddr) -> Self {
        let mut key = Self::default();
        match ip {
            IpAddr::V4(v4) => {
                key.family = PREFIX_FAMILY_V4;
                key.addr[..4].copy_from_slice(&masked_v4(v4).octets());
            },
            IpAddr::V6(v6) => {
                key.family = PREFIX_FAMILY_V6;
                key.addr.copy_from_slice(&masked_v6_segments(v6));
            },
        }
        key
    }

    /// Префикс как IP-адрес (маскированный).
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

/// Возвращает префикс адреса: IPv4 и IPv4-mapped → /24, IPv6 → /64.
#[must_use]
pub fn prefix_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(masked_v4(v4)),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // ::ffff:a.b.c.d живёт в том же /24-пространстве, что и a.b.c.d.
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
