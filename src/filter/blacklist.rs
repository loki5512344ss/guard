use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct BanEntry {
    expires: Instant,
    _reason: String,
}

pub struct Blacklist {
    entries: Arc<DashMap<IpAddr, BanEntry>>,
}

impl Default for Blacklist {
    fn default() -> Self {
        Self::new()
    }
}

impl Blacklist {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if let Some(entry) = self.entries.get(&ip) {
            if entry.expires > Instant::now() {
                return true;
            }
            drop(entry);
            self.entries.remove(&ip);
        }
        false
    }

    pub fn add(&self, ip: IpAddr, duration: Duration, reason: &str) {
        self.entries.insert(
            ip,
            BanEntry {
                expires: Instant::now() + duration,
                _reason: reason.to_string(),
            },
        );
    }

    pub fn remove(&self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear_expired(&self) {
        self.entries.retain(|_, entry| entry.expires > Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    #[test]
    fn test_blacklist_block() {
        let bl = Blacklist::new();
        bl.add(ip([1, 2, 3, 4]), Duration::from_secs(60), "test");
        assert!(bl.is_blocked(ip([1, 2, 3, 4])));
    }

    #[test]
    fn test_blacklist_not_blocked() {
        let bl = Blacklist::new();
        bl.add(ip([1, 2, 3, 4]), Duration::from_secs(60), "test");
        assert!(!bl.is_blocked(ip([5, 6, 7, 8])));
    }

    #[test]
    fn test_blacklist_expired() {
        let bl = Blacklist::new();
        bl.add(ip([1, 2, 3, 4]), Duration::from_millis(1), "test");
        std::thread::sleep(Duration::from_millis(2));
        assert!(!bl.is_blocked(ip([1, 2, 3, 4])));
    }

    #[test]
    fn test_blacklist_remove() {
        let bl = Blacklist::new();
        bl.add(ip([1, 2, 3, 4]), Duration::from_secs(60), "test");
        bl.remove(ip([1, 2, 3, 4]));
        assert!(!bl.is_blocked(ip([1, 2, 3, 4])));
    }
}
