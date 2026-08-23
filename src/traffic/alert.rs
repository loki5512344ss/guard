use std::fmt;
use std::net::Ipv4Addr;
use std::time::Instant;

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

#[derive(Clone)]
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
}
