use super::XdpFilter;
use anyhow::{Result, bail};
use libbpf_rs::{MapCore, MapFlags};
use std::net::{IpAddr, Ipv4Addr};

pub(super) fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Encodes an LPM-trie key for `blacklist_map`: prefix length in byte 0 and the
/// four IPv4 octets in bytes 4..8 (bytes 1..3 are padding the kernel ignores).
pub(super) fn blacklist_key(prefix_len: u8, v4: &[u8; 4]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = prefix_len;
    key[4..8].copy_from_slice(v4);
    key
}

/// Absolute ban expiry in ns-since-epoch, saturating so an absurd duration
/// clamps to `u64::MAX` rather than wrapping into the past.
pub(super) fn blacklist_expiry_ns(now_ns: u64, duration_secs: u64) -> u64 {
    now_ns.saturating_add(duration_secs.saturating_mul(1_000_000_000))
}

impl XdpFilter {
    pub fn ban_ip(&self, ip: Ipv4Addr, duration_secs: u64) -> Result<()> {
        self.blacklist_update(32, &ip.octets(), duration_secs)
    }

    /// Adds a CIDR ban to the LPM trie. IPv6 enforcement is not supported yet.
    pub fn ban_cidr(&self, prefix: IpAddr, prefix_len: u8, duration_secs: u64) -> Result<()> {
        let IpAddr::V4(net) = prefix else {
            bail!("ipv6 cidr bans not supported yet");
        };
        self.blacklist_update(prefix_len, &net.octets(), duration_secs)
    }

    fn blacklist_update(&self, prefix_len: u8, v4: &[u8; 4], duration_secs: u64) -> Result<()> {
        let map = self.find_map("blacklist_map")?;
        let key = blacklist_key(prefix_len, v4);
        let expiry_ns = blacklist_expiry_ns(unix_ns(), duration_secs);
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
