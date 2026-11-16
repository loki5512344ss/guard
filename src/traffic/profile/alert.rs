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

/// Deduplicating alert dispatcher.
///
/// An alert is emitted only on a detector state transition (entering
/// `UnderAttack` and leaving it), never on every tick. The behaviour is
/// poll-and-persist: the previous status is kept as the baseline.
#[derive(Default)]
pub struct AlertDispatcher {
	previous: Mutex<Option<AttackStatus>>,
}

impl AlertDispatcher {
	pub fn new() -> Self {
		Self::default()
	}

	/// Returns `Some(Alert)` only when the attack boundary is crossed: entering
	/// `UnderAttack` ("attack started") or leaving it ("attack ended").
	///
	/// The first observation never produces an alert, so a node that starts up
	/// during an attack does not report a transition it never saw.
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

/// Delivers an alert to a webhook (fire-and-forget, with a timeout).
///
/// Call it from background tasks only: network I/O is not allowed on the hot
/// path.
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
