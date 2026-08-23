use crate::traffic::profiler::TrafficProfiler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackStatus {
    Normal,
    Suspicious,
    UnderAttack,
}

pub struct AttackDetector {
    profiler: TrafficProfiler,
    consecutive_anomalies: u32,
}

impl Default for AttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackDetector {
    pub fn new() -> Self {
        Self {
            profiler: TrafficProfiler::new(),
            consecutive_anomalies: 0,
        }
    }

    pub fn analyze(&mut self, pps: f64) -> AttackStatus {
        self.profiler.record(pps);
        let score = self.profiler.anomaly_score(pps);

        if score > 3.0 {
            self.consecutive_anomalies += 1;
        } else {
            self.consecutive_anomalies = 0;
        }

        if self.consecutive_anomalies >= 3 {
            AttackStatus::UnderAttack
        } else if score > 2.0 {
            AttackStatus::Suspicious
        } else {
            AttackStatus::Normal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_status_normal() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(100.0);
        }
        assert_eq!(d.analyze(100.0), AttackStatus::Normal);
    }

    #[test]
    fn test_attack_status_suspicious() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(1.0);
        }
        assert_eq!(d.analyze(5.0), AttackStatus::Suspicious);
    }

    #[test]
    fn test_attack_status_under_attack() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(1.0);
        }
        d.analyze(10_000.0);
        d.analyze(10_000.0);
        assert_eq!(d.analyze(10_000.0), AttackStatus::UnderAttack);
    }

    #[test]
    fn test_consecutive_resets_on_normal() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(1.0);
        }
        d.analyze(100.0);
        d.analyze(100.0);
        d.analyze(1.0);
        assert_eq!(d.analyze(1.0), AttackStatus::Normal);
    }
}
