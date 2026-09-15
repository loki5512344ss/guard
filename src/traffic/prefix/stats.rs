use anyhow::Result;
use std::future::Future;
use std::net::IpAddr;

/// Значение карты `prefix_stats`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixStatsVal {
    pub syn_count: u64,
    pub pkt_count: u64,
    pub last_seen_ns: u64,
}

impl PrefixStatsVal {
    /// Разбирает сырые 24 байта значения карты.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        let read_u64 =
            |range: std::ops::Range<usize>| u64::from_le_bytes(bytes[range].try_into().expect("8-byte field"));
        Self {
            syn_count: read_u64(0..8),
            pkt_count: read_u64(8..16),
            last_seen_ns: read_u64(16..24),
        }
    }

    /// Сериализует значение в сырые 24 байта карты.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..8].copy_from_slice(&self.syn_count.to_le_bytes());
        out[8..16].copy_from_slice(&self.pkt_count.to_le_bytes());
        out[16..24].copy_from_slice(&self.last_seen_ns.to_le_bytes());
        out
    }
}

/// Агрегат по одному префиксу за окно детекции.
///
/// `unique_sources == 0` означает, что источник не считает уникальные адреса
/// (XDP-путь); spoof-gate в этом случае Block не подтверждает.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrefixSnapshot {
    pub syn_count: u64,
    pub pkt_count: u64,
    pub last_seen_ns: u64,
    pub unique_sources: u64,
}

/// Источник агрегатов по префиксам. Позволяет тестам работать без ядра.
pub trait PrefixStatsSource {
    /// Снимок агрегатов за текущее окно.
    ///
    /// # Errors
    /// Ошибка чтения источника (карта не загружена, BPF-сбой и т.п.).
    fn snapshot(&self) -> impl Future<Output = Result<Vec<(IpAddr, PrefixSnapshot)>>> + Send;
}

/// Эскалация вердиктов subnet-level детектора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetVerdict {
    Monitor,
    StrictLimit,
    Challenge,
    Block,
}

/// Вердикт по одному префиксу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixVerdict {
    pub prefix: IpAddr,
    pub verdict: SubnetVerdict,
    pub snapshot: PrefixSnapshot,
}

/// Детектор распределённых атак по префиксам.
///
/// Лестница эскалации по `syn_count` за окно: `< threshold` → Monitor,
/// `< 2×threshold` → StrictLimit, иначе Challenge; Block только при
/// `≥ 4×threshold` И прохождении spoof-gate (≥ `min_unique_sources`
/// уникальных IP — защита от ложного бана CGNAT/спуфинга).
#[derive(Debug, Clone)]
pub struct SubnetDetector {
    syn_threshold: u64,
    min_unique_sources: u64,
}

impl SubnetDetector {
    #[must_use]
    pub fn new(syn_threshold: u64, min_unique_sources: u64) -> Self {
        Self {
            syn_threshold: syn_threshold.max(1),
            min_unique_sources,
        }
    }

    #[must_use]
    pub fn from_config(config: &crate::config::DetectPrefixConfig) -> Self {
        Self::new(config.syn_threshold, config.min_unique_sources)
    }

    /// Оценивает снимок и возвращает вердикты по активным префиксам.
    #[must_use]
    pub fn evaluate(&self, snapshots: &[(IpAddr, PrefixSnapshot)]) -> Vec<PrefixVerdict> {
        snapshots
            .iter()
            .filter(|(_, snap)| snap.syn_count > 0)
            .map(|(prefix, snap)| PrefixVerdict {
                prefix: *prefix,
                verdict: self.verdict_for(snap),
                snapshot: *snap,
            })
            .collect()
    }

    #[must_use]
    fn verdict_for(&self, snap: &PrefixSnapshot) -> SubnetVerdict {
        let t = self.syn_threshold;
        if snap.syn_count < t {
            return SubnetVerdict::Monitor;
        }
        if snap.syn_count < t.saturating_mul(2) {
            return SubnetVerdict::StrictLimit;
        }
        let extreme = snap.syn_count >= t.saturating_mul(4);
        if extreme && self.spoof_gate_passed(snap) {
            return SubnetVerdict::Block;
        }
        SubnetVerdict::Challenge
    }

    #[must_use]
    fn spoof_gate_passed(&self, snap: &PrefixSnapshot) -> bool {
        // gate отключён (min_unique_sources == 0) либо подтверждено разнообразие.
        self.min_unique_sources == 0 || snap.unique_sources >= self.min_unique_sources
    }
}

/// Реализация [`PrefixStatsSource`] поверх XDP-фильтра (feature `xdp`).
/// Читает карту `prefix_stats`; уникальные источники ядро не считает,
/// поэтому spoof-gate на этом пути Block не подтверждает.
#[cfg(feature = "xdp")]
pub struct XdpPrefixStats {
    filter: std::sync::Arc<std::sync::Mutex<crate::xdp::XdpFilter>>,
}

#[cfg(feature = "xdp")]
impl XdpPrefixStats {
    #[must_use]
    pub fn new(filter: std::sync::Arc<std::sync::Mutex<crate::xdp::XdpFilter>>) -> Self {
        Self { filter }
    }

    /// Блокирует мьютекс фильтра (для kernel-enforcement вердиктов).
    ///
    /// # Panics
    /// Если мьютекс отравлен (паника в другом потоке во время удержания).
    pub fn filter_lock(&self) -> std::sync::MutexGuard<'_, crate::xdp::XdpFilter> {
        self.filter.lock().expect("xdp lock poisoned")
    }
}

#[cfg(feature = "xdp")]
impl PrefixStatsSource for XdpPrefixStats {
    async fn snapshot(&self) -> Result<Vec<(IpAddr, PrefixSnapshot)>> {
        let raw = self.filter_lock().read_prefix_stats()?;
        Ok(raw
            .into_iter()
            .filter_map(|(key, val)| {
                let prefix = key.to_prefix()?;
                Some((
                    prefix,
                    PrefixSnapshot {
                        syn_count: val.syn_count,
                        pkt_count: val.pkt_count,
                        last_seen_ns: val.last_seen_ns,
                        unique_sources: 0,
                    },
                ))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_val_roundtrip() {
        let val = PrefixStatsVal {
            syn_count: 42,
            pkt_count: 100,
            last_seen_ns: 1_234_567_890,
        };
        assert_eq!(PrefixStatsVal::from_bytes(val.to_bytes()), val);
        assert_eq!(size_of::<PrefixStatsVal>(), 24);
    }
}
