//! `POST /api/v1/auth/login`: password check with a per-IP attempt limiter.

use crate::manager::AppState;
use crate::manager::api::guard::{RequestGuard, limit};
use axum::{
	Extension, Json,
	extract::{ConnectInfo, State},
	http::{HeaderMap, StatusCode},
};
use dashmap::DashMap;
use serde::Deserialize;
use std::{
	net::{IpAddr, SocketAddr},
	sync::Arc,
	time::{Duration, Instant},
};

/// Window of the login limiter, exported for the eviction sweep.
pub const LOGIN_WINDOW: Duration = limit::LOGIN_WINDOW;
/// Login attempts allowed per window and source address.
pub const LOGIN_MAX_ATTEMPTS: u32 = limit::LOGIN_MAX_ATTEMPTS;

#[derive(Deserialize)]
pub struct LoginRequest {
	pub password: String,
}

/// Verifies the API password and returns a bearer token.
///
/// The client address comes from [`RequestGuard`]: the transport peer unless a
/// trusted reverse proxy forwarded the request. The attempt counter is reset
/// after a successful login so a legitimate administrator starts clean.
pub async fn login(
	State(state): State<Arc<AppState>>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Extension(guard): Extension<Arc<RequestGuard>>,
	headers: HeaderMap,
	Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
	let ip = guard.client_ip(addr.ip(), &headers);
	if !allow_login_attempt(&state.login_limiter, ip) {
		return Err((
			StatusCode::TOO_MANY_REQUESTS,
			Json(serde_json::json!({"error": "too many requests"})),
		));
	}

	if !crate::manager::security::verify_password(&req.password, &state.api_password) {
		return Err((
			StatusCode::UNAUTHORIZED,
			Json(serde_json::json!({"error": "invalid password"})),
		));
	}
	reset_login_attempts(&state.login_limiter, ip);

	match crate::manager::auth::create_token(&state.jwt_secret, state.jwt_expiration, &state.jwt_audience) {
		Ok(token) => Ok(Json(serde_json::json!({"token": token}))),
		Err(_) => Err((
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(serde_json::json!({"error": "token creation failed"})),
		)),
	}
}

/// Records a login attempt for `ip` and reports whether it is within the window.
///
/// The limiter allows [`LOGIN_MAX_ATTEMPTS`] attempts per [`LOGIN_WINDOW`] and
/// resets the counter when the window elapses.
pub fn allow_login_attempt(limiter: &DashMap<IpAddr, (Instant, u32)>, ip: IpAddr) -> bool {
	limit::check_attempt(limiter, ip, LOGIN_WINDOW, LOGIN_MAX_ATTEMPTS)
}

/// Clears the login counter of `ip` after a successful authentication.
pub fn reset_login_attempts(limiter: &DashMap<IpAddr, (Instant, u32)>, ip: IpAddr) {
	limit::reset_attempts(limiter, ip);
}
