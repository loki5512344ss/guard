use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::traffic::detector::AttackStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertLevel::Info => write!(f, "INFO"),
            AlertLevel::Warning => write!(f, "WARNING"),
            AlertLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub level: AlertLevel,
    pub message: String,
    pub ip: Option<Ipv4Addr>,
    pub pps: f64,
    pub timestamp: Instant,
}

impl Alert {
    pub fn new(level: AlertLevel, message: String, ip: Option<Ipv4Addr>, pps: f64) -> Self {
        Self {
            level,
            message,
            ip,
            pps,
            timestamp: Instant::now(),
        }
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ip {
            Some(ip) => write!(
                f,
                "[{}] {} | IP: {} | PPS: {:.2}",
                self.level, self.message, ip, self.pps
            ),
            None => write!(f, "[{}] {} | PPS: {:.2}", self.level, self.message, self.pps),
        }
    }
}

/// Дедуплицирующий диспетчер алертов: алерт выдаётся только на переходе
/// состояния детектора (вход в `UnderAttack` и выход из него), не на каждом
/// тике. Логика — poll-and-persist (LNVPS issue #331).
#[derive(Default)]
pub struct AlertDispatcher {
    previous: Mutex<Option<AttackStatus>>,
}

impl AlertDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Возвращает `Some(Alert)` только при переходе через границу атаки:
    /// вход в `UnderAttack` («attack started») или выход из него
    /// («attack ended»). Первое наблюдение алерта не порождает.
    pub fn on_status(&self, status: AttackStatus) -> Option<Alert> {
        let mut previous = self.previous.lock().expect("alert dispatcher lock poisoned");
        if *previous == Some(status) {
            return None;
        }
        let was_under_attack = *previous == Some(AttackStatus::UnderAttack);
        *previous = Some(status);
        match (was_under_attack, status) {
            (false, AttackStatus::UnderAttack) => {
                Some(Alert::new(AlertLevel::Critical, "attack started".into(), None, 0.0))
            },
            (true, _) => Some(Alert::new(AlertLevel::Info, "attack ended".into(), None, 0.0)),
            _ => None,
        }
    }
}

/// Отправляет алерт на webhook (fire-and-forget, с таймаутом).
///
/// Вызывать следует из фоновых задач: сетевой ввод-вывод недопустим в hot path.
pub async fn send_webhook(url: String, alert: Alert) {
    let payload = serde_json::json!({
        "level": alert.level.to_string(),
        "message": alert.message,
        "pps": alert.pps,
    });
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build();
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("webhook client build failed: {e}");
            return;
        },
    };
    if let Err(e) = client.post(url).json(&payload).send().await {
        tracing::warn!("webhook delivery failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_display_with_ip() {
        let alert = Alert::new(
            AlertLevel::Critical,
            "possible attack".into(),
            Some(Ipv4Addr::new(192, 168, 1, 1)),
            100500.0,
        );
        let s = alert.to_string();
        assert!(s.contains("CRITICAL"));
        assert!(s.contains("192.168.1.1"));
    }

    #[test]
    fn test_alert_display_without_ip() {
        let alert = Alert::new(AlertLevel::Info, "traffic spike".into(), None, 5000.0);
        let s = alert.to_string();
        assert!(s.contains("INFO"));
        assert!(s.contains("traffic spike"));
    }

    #[test]
    fn test_dispatcher_two_transitions_two_alerts() {
        let dispatcher = AlertDispatcher::new();
        assert_eq!(dispatcher.on_status(AttackStatus::Normal), None);
        assert_eq!(dispatcher.on_status(AttackStatus::Suspicious), None);
        let started = dispatcher.on_status(AttackStatus::UnderAttack);
        assert_eq!(dispatcher.on_status(AttackStatus::UnderAttack), None);
        assert_eq!(dispatcher.on_status(AttackStatus::UnderAttack), None);
        let ended = dispatcher.on_status(AttackStatus::Normal);
        assert_eq!(dispatcher.on_status(AttackStatus::Normal), None);
        assert!(started.is_some());
        assert!(ended.is_some());
        assert!(
            started.expect("started alert").message.contains("attack started")
                && ended.expect("ended alert").message.contains("attack ended")
        );
    }

    #[test]
    fn test_dispatcher_suspicious_does_not_flap_alerts() {
        let dispatcher = AlertDispatcher::new();
        for status in [
            AttackStatus::Normal,
            AttackStatus::Suspicious,
            AttackStatus::Normal,
            AttackStatus::Suspicious,
        ] {
            assert_eq!(dispatcher.on_status(status), None);
        }
    }
}
