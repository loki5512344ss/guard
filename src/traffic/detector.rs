use crate::traffic::profiler::TrafficProfiler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackStatus {
    Normal,
    Suspicious,
    UnderAttack,
}

pub struct AttackDetector {
    pps_profiler: TrafficProfiler,
    cps_profiler: TrafficProfiler,
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
            pps_profiler: TrafficProfiler::new(),
            cps_profiler: TrafficProfiler::new(),
            consecutive_anomalies: 0,
        }
    }

    /// Анализирует окно метрик (пакеты/с и новые соединения/с) относительно
    /// накопленных профилей. Аномалией считается всплеск любой из метрик.
    pub fn analyze(&mut self, pps: f64, cps: f64) -> AttackStatus {
        self.pps_profiler.record(pps);
        self.cps_profiler.record(cps);
        let score = self
            .pps_profiler
            .anomaly_score(pps)
            .max(self.cps_profiler.anomaly_score(cps));

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
            d.analyze(100.0, 10.0);
        }
        assert_eq!(d.analyze(100.0, 10.0), AttackStatus::Normal);
    }

    #[test]
    fn test_attack_status_suspicious_pps_spike() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(1.0, 1.0);
        }
        assert_eq!(d.analyze(5.0, 1.0), AttackStatus::Suspicious);
    }

    #[test]
    fn test_attack_status_suspicious_cps_spike() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(1.0, 1.0);
        }
        assert_eq!(d.analyze(1.0, 5.0), AttackStatus::Suspicious);
    }

    #[test]
    fn test_attack_status_under_attack() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(1.0, 1.0);
        }
        d.analyze(10_000.0, 100.0);
        d.analyze(10_000.0, 100.0);
        assert_eq!(d.analyze(10_000.0, 100.0), AttackStatus::UnderAttack);
    }

    #[test]
    fn test_consecutive_resets_on_normal() {
        let mut d = AttackDetector::new();
        for _ in 0..10 {
            d.analyze(1.0, 1.0);
        }
        d.analyze(100.0, 10.0);
        d.analyze(100.0, 10.0);
        d.analyze(1.0, 1.0);
        assert_eq!(d.analyze(1.0, 1.0), AttackStatus::Normal);
    }
}
