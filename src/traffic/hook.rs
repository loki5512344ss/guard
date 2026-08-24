//! Traffic Intelligence в hot path: репутация → авто-бан → метрики окна.
//!
//! Все вызовы из accept-пути дешёвые (DashMap/атомики), блокирующего
//! ввода-вывода нет.

use crate::config::DetectAutobanConfig;
use crate::filter::blacklist::Blacklist;
use crate::metrics;
use crate::traffic::reputation::IpReputation;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const BAN_REASON_LOW_REPUTATION: &str = "low_reputation";
const BAN_REASON_ATTACK: &str = "attack_detector";

/// Точка входа Traffic Intelligence для сетевого пути.
///
/// События: новое соединение (`on_accept`), завершение обработки соединения
/// (`on_connection_end`), эскалация детектора атак (`ban_offenders`).
pub struct TrafficHook {
    reputation: Arc<IpReputation>,
    blacklist: Arc<Blacklist>,
    autoban: DetectAutobanConfig,
    ban_ttl_secs: u64,
    conn_window: AtomicU64,
}

impl TrafficHook {
    pub fn new(
        reputation: Arc<IpReputation>,
        blacklist: Arc<Blacklist>,
        autoban: DetectAutobanConfig,
        ban_ttl_secs: u64,
    ) -> Self {
        Self {
            reputation,
            blacklist,
            autoban,
            ban_ttl_secs,
            conn_window: AtomicU64::new(0),
        }
    }

    /// Новое соединение принято accept-loop'ом. Только счётчик окна cps.
    pub fn on_accept(&self) {
        self.conn_window.fetch_add(1, Ordering::Relaxed);
    }

    /// Соединение обработано. Если источник попал под rate-limit (репутация
    /// упала до порога) — авто-бан с TTL из конфига.
    pub fn on_connection_end(&self, ip: IpAddr) {
        if !self.autoban.enabled || self.blacklist.is_blocked(ip) {
            return;
        }
        self.autoban_if_toxic(ip, BAN_REASON_LOW_REPUTATION);
    }

    /// Эскалация детектора атак: бан всех источников ниже порога репутации.
    /// Вызывается один раз на переход в `UnderAttack`, не на каждый тик.
    pub fn ban_offenders(&self) -> usize {
        if !self.autoban.enabled {
            return 0;
        }
        let offenders = self.reputation.offenders_below(self.autoban.reputation_threshold);
        let mut banned = 0;
        for ip in offenders {
            if self.blacklist.is_blocked(ip) {
                continue;
            }
            self.ban(ip, BAN_REASON_ATTACK);
            banned += 1;
        }
        banned
    }

    /// Забирает накопленное окно новых соединений за секунду (cps).
    pub fn take_cps(&self) -> u64 {
        self.conn_window.swap(0, Ordering::Relaxed)
    }

    fn autoban_if_toxic(&self, ip: IpAddr, reason: &str) {
        if self.reputation.score(ip) > self.autoban.reputation_threshold {
            return;
        }
        self.ban(ip, reason);
    }

    fn ban(&self, ip: IpAddr, reason: &str) {
        self.blacklist.add(ip, Duration::from_secs(self.ban_ttl_secs), reason);
        metrics::AUTO_BANS_TOTAL.with_label_values(&[reason]).inc();
        tracing::warn!(%ip, reason, ttl_secs = self.ban_ttl_secs, "auto-ban issued by traffic intelligence");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn hook(rep: &Arc<IpReputation>, bl: &Arc<Blacklist>) -> TrafficHook {
        TrafficHook::new(
            Arc::clone(rep),
            Arc::clone(bl),
            DetectAutobanConfig {
                enabled: true,
                reputation_threshold: -50,
            },
            60,
        )
    }

    #[test]
    fn test_cps_window_counts_and_resets() {
        let rep = Arc::new(IpReputation::new());
        let bl = Arc::new(Blacklist::new());
        let hook = hook(&rep, &bl);
        hook.on_accept();
        hook.on_accept();
        hook.on_accept();
        assert_eq!(hook.take_cps(), 3);
        assert_eq!(hook.take_cps(), 0);
    }

    #[test]
    fn test_reputation_fall_triggers_autoban() {
        let rep = Arc::new(IpReputation::new());
        let bl = Arc::new(Blacklist::new());
        let hook = hook(&rep, &bl);
        let target = ip([10, 1, 0, 1]);
        for _ in 0..6 {
            rep.record_bad(target);
        }
        assert_eq!(rep.score(target), -60);
        assert!(!bl.is_blocked(target));
        hook.on_connection_end(target);
        assert!(bl.is_blocked(target));
    }

    #[test]
    fn test_no_autoban_above_threshold() {
        let rep = Arc::new(IpReputation::new());
        let bl = Arc::new(Blacklist::new());
        let hook = hook(&rep, &bl);
        let target = ip([10, 1, 0, 2]);
        for _ in 0..4 {
            rep.record_bad(target);
        }
        assert_eq!(rep.score(target), -40);
        hook.on_connection_end(target);
        assert!(!bl.is_blocked(target));
    }

    #[test]
    fn test_disabled_autoban_never_bans() {
        let rep = Arc::new(IpReputation::new());
        let bl = Arc::new(Blacklist::new());
        let hook = TrafficHook::new(
            Arc::clone(&rep),
            Arc::clone(&bl),
            DetectAutobanConfig {
                enabled: false,
                reputation_threshold: -50,
            },
            60,
        );
        let target = ip([10, 1, 0, 3]);
        for _ in 0..20 {
            rep.record_bad(target);
        }
        hook.on_connection_end(target);
        assert!(hook.ban_offenders() == 0);
        assert!(!bl.is_blocked(target));
    }

    #[test]
    fn test_ban_offenders_bans_only_below_threshold() {
        let rep = Arc::new(IpReputation::new());
        let bl = Arc::new(Blacklist::new());
        let hook = hook(&rep, &bl);
        let bad = ip([10, 2, 0, 1]);
        let ok = ip([10, 2, 0, 2]);
        for _ in 0..8 {
            rep.record_bad(bad);
        }
        rep.record_good(ok);
        assert_eq!(hook.ban_offenders(), 1);
        assert!(bl.is_blocked(bad));
        assert!(!bl.is_blocked(ok));
        assert_eq!(hook.ban_offenders(), 0);
    }

    #[test]
    fn test_autoban_ttl_expires() {
        let rep = Arc::new(IpReputation::new());
        let bl = Arc::new(Blacklist::new());
        let hook = TrafficHook::new(
            Arc::clone(&rep),
            Arc::clone(&bl),
            DetectAutobanConfig {
                enabled: true,
                reputation_threshold: -50,
            },
            // Короткий TTL как мок времени: бан жив, потом истекает.
            0,
        );
        let target = ip([10, 3, 0, 1]);
        for _ in 0..20 {
            rep.record_bad(target);
        }
        hook.on_connection_end(target);
        assert!(!bl.is_blocked(target), "zero TTL must not produce an active ban");
    }
}
