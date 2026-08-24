use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub struct IpReputation {
    scores: Arc<DashMap<IpAddr, i32>>,
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

    pub fn record_good(&self, ip: IpAddr) {
        let mut entry = self.scores.entry(ip).or_insert(0);
        *entry = (*entry + 1).min(100);
    }

    pub fn record_bad(&self, ip: IpAddr) {
        let mut entry = self.scores.entry(ip).or_insert(0);
        *entry = (*entry - 10).max(-100);
    }

    pub fn score(&self, ip: IpAddr) -> i32 {
        self.scores.get(&ip).map(|v| *v).unwrap_or(0)
    }

    /// Возвращает источники со скором не выше `threshold` (нарушители).
    pub fn offenders_below(&self, threshold: i32) -> Vec<IpAddr> {
        self.scores
            .iter()
            .filter(|entry| *entry.value() <= threshold)
            .map(|entry| *entry.key())
            .collect()
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.score(ip) > 50
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    #[test]
    fn test_reputation_initial_score() {
        let rep = IpReputation::new();
        assert_eq!(rep.score(v4([192, 168, 1, 1])), 0);
    }

    #[test]
    fn test_reputation_good() {
        let rep = IpReputation::new();
        let ip = v4([10, 0, 0, 1]);
        rep.record_good(ip);
        assert_eq!(rep.score(ip), 1);
    }

    #[test]
    fn test_reputation_bad() {
        let rep = IpReputation::new();
        let ip = v4([10, 0, 0, 2]);
        rep.record_bad(ip);
        assert_eq!(rep.score(ip), -10);
    }

    #[test]
    fn test_reputation_cap_positive() {
        let rep = IpReputation::new();
        let ip = v4([10, 0, 0, 3]);
        for _ in 0..200 {
            rep.record_good(ip);
        }
        assert_eq!(rep.score(ip), 100);
    }

    #[test]
    fn test_reputation_cap_negative() {
        let rep = IpReputation::new();
        let ip = v4([10, 0, 0, 4]);
        for _ in 0..20 {
            rep.record_bad(ip);
        }
        assert_eq!(rep.score(ip), -100);
    }

    #[test]
    fn test_is_trusted() {
        let rep = IpReputation::new();
        let ip = v4([10, 0, 0, 5]);
        assert!(!rep.is_trusted(ip));
        for _ in 0..51 {
            rep.record_good(ip);
        }
        assert!(rep.is_trusted(ip));
    }

    #[test]
    fn test_reputation_v6() {
        let rep = IpReputation::new();
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        rep.record_bad(ip);
        assert_eq!(rep.score(ip), -10);
    }

    #[test]
    fn test_offenders_below_threshold() {
        let rep = IpReputation::new();
        let bad = v4([10, 0, 0, 1]);
        let good = v4([10, 0, 0, 2]);
        for _ in 0..6 {
            rep.record_bad(bad);
        }
        rep.record_good(good);
        let offenders = rep.offenders_below(-50);
        assert_eq!(offenders, vec![bad]);
    }

    #[test]
    fn test_offenders_empty_when_none_below() {
        let rep = IpReputation::new();
        assert!(rep.offenders_below(-50).is_empty());
    }
}
