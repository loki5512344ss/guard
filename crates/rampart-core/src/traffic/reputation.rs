use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

pub struct IpReputation {
    scores: Arc<DashMap<Ipv4Addr, i32>>,
}

impl Default for IpReputation {
    fn default() -> Self {
        Self::new()
    }
}

impl IpReputation {
    pub fn new() -> Self {
        Self {
            scores: Arc::new(DashMap::new()),
        }
    }

    pub fn record_good(&self, ip: Ipv4Addr) {
        let mut entry = self.scores.entry(ip).or_insert(0);
        *entry = (*entry + 1).min(100);
    }

    pub fn record_bad(&self, ip: Ipv4Addr) {
        let mut entry = self.scores.entry(ip).or_insert(0);
        *entry = (*entry - 10).max(-100);
    }

    pub fn score(&self, ip: Ipv4Addr) -> i32 {
        self.scores.get(&ip).map(|v| *v).unwrap_or(0)
    }

    pub fn is_trusted(&self, ip: Ipv4Addr) -> bool {
        self.score(ip) > 50
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_reputation_initial_score() {
        let rep = IpReputation::new();
        assert_eq!(rep.score(Ipv4Addr::new(192, 168, 1, 1)), 0);
    }

    #[test]
    fn test_reputation_good() {
        let rep = IpReputation::new();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        rep.record_good(ip);
        assert_eq!(rep.score(ip), 1);
    }

    #[test]
    fn test_reputation_bad() {
        let rep = IpReputation::new();
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        rep.record_bad(ip);
        assert_eq!(rep.score(ip), -10);
    }

    #[test]
    fn test_reputation_cap_positive() {
        let rep = IpReputation::new();
        let ip = Ipv4Addr::new(10, 0, 0, 3);
        for _ in 0..200 {
            rep.record_good(ip);
        }
        assert_eq!(rep.score(ip), 100);
    }

    #[test]
    fn test_reputation_cap_negative() {
        let rep = IpReputation::new();
        let ip = Ipv4Addr::new(10, 0, 0, 4);
        for _ in 0..20 {
            rep.record_bad(ip);
        }
        assert_eq!(rep.score(ip), -100);
    }

    #[test]
    fn test_is_trusted() {
        let rep = IpReputation::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        assert!(!rep.is_trusted(ip));
        for _ in 0..51 {
            rep.record_good(ip);
        }
        assert!(rep.is_trusted(ip));
    }
}
