//! Per-IP attempt throttling for login and mutating requests.
//!
//! Both limiters share one representation, `IpAddr -> (window start, attempts)`.
//! A counter resets when its window elapses, a successful login clears the entry
//! outright, and an eviction sweep keeps the map from growing one entry per
//! source address forever.

use super::RequestGuard;
use axum::{
	Json,
	extract::{Request, State},
	http::StatusCode,
	middleware::Next,
	response::Response,
};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Sliding window of the login limiter.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(60);
/// Login attempts allowed per window and source address.
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
/// Sliding window of the mutating-request limiter.
pub const MUTATION_WINDOW: Duration = Duration::from_secs(60);
/// Mutating requests allowed per window and source address.
pub const MUTATION_MAX_ATTEMPTS: u32 = 30;

/// Records one attempt for `ip` and reports whether it is allowed.
///
/// The first attempt after `window` starts a fresh window; once `max` attempts
/// were spent the call returns `false` without extending the window.
pub fn check_attempt(limiter: &DashMap<IpAddr, (Instant, u32)>, ip: IpAddr, window: Duration, max: u32) -> bool {
	let now = Instant::now();
	let mut slot = limiter.entry(ip).or_insert((now, 0));
	let (window_start, attempts) = &mut *slot;
	if now.duration_since(*window_start) >= window {
		*window_start = now;
		*attempts = 1;
	} else if *attempts >= max {
		return false;
	} else {
		*attempts += 1;
	}
	true
}

/// Drops the counter of `ip`, used after a successful login.
pub fn reset_attempts(limiter: &DashMap<IpAddr, (Instant, u32)>, ip: IpAddr) {
	limiter.remove(&ip);
}

/// Removes every counter whose window already elapsed.
pub fn evict_idle(limiter: &DashMap<IpAddr, (Instant, u32)>, window: Duration) {
	let now = Instant::now();
	limiter.retain(|_, (window_start, _)| now.duration_since(*window_start) < window);
}

/// Reports whether `method` changes server state and therefore is rate limited.
#[must_use]
pub fn is_mutating(method: &axum::http::Method) -> bool {
	matches!(
		*method,
		axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::PATCH | axum::http::Method::DELETE
	)
}

/// Middleware that throttles mutating requests per client address.
///
/// Read-only requests pass through untouched so the limiter never affects the
/// inventory and blacklist views. Authenticated mutations share one budget per
/// address, regardless of which endpoint they target.
pub async fn rate_limit_mutations(
	State(guard): State<Arc<RequestGuard>>,
	request: Request,
	next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
	if is_mutating(request.method()) {
		let ip = guard.request_client_ip(&request);
		if !guard.allow_mutation(ip) {
			return Err((
				StatusCode::TOO_MANY_REQUESTS,
				Json(serde_json::json!({"error": "too many requests"})),
			));
		}
	}
	Ok(next.run(request).await)
}
