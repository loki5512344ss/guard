//! `POST /api/v1/auth/login`: password check with a per-IP attempt limiter.

use crate::manager::AppState;
use axum::{
	Json,
	extract::{ConnectInfo, State},
	http::StatusCode,
};
use dashmap::DashMap;
use serde::Deserialize;
use std::{
	net::{IpAddr, SocketAddr},
	sync::Arc,
	time::{Duration, Instant},
};

const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_ATTEMPTS: u32 = 5;

#[derive(Deserialize)]
pub struct LoginRequest {
	pub password: String,
}

pub async fn login(
	State(state): State<Arc<AppState>>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
	if !allow_login_attempt(&state.login_limiter, addr.ip()) {
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
/// The limiter allows `LOGIN_MAX_ATTEMPTS` attempts per `LOGIN_WINDOW` and
/// resets the counter when the window elapses.
pub fn allow_login_attempt(limiter: &DashMap<IpAddr, (Instant, u32)>, ip: IpAddr) -> bool {
	let now = Instant::now();
	let mut slot = limiter.entry(ip).or_insert((now, 0));
	let (last_reset, attempts) = &mut *slot;
	if now.duration_since(*last_reset) >= LOGIN_WINDOW {
		*last_reset = now;
		*attempts = 1;
	} else if *attempts >= LOGIN_MAX_ATTEMPTS {
		return false;
	} else {
		*attempts += 1;
	}
	true
}
