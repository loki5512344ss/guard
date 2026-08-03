use crate::AppState;
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
use subtle::ConstantTimeEq;

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

    if !verify_password(&req.password, &state.api_password) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid password"})),
        ));
    }

    match crate::auth::create_token(&state.jwt_secret, state.jwt_expiration, &state.jwt_audience) {
        Ok(token) => Ok(Json(serde_json::json!({"token": token}))),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "token creation failed"})),
        )),
    }
}

fn verify_password(provided: &str, expected: &str) -> bool {
    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    let len_match = (provided.len() as u64).ct_eq(&(expected.len() as u64));
    let min_len = provided.len().min(expected.len());
    let bytes_match = provided[..min_len].ct_eq(&expected[..min_len]);
    bool::from(len_match & bytes_match)
}

fn allow_login_attempt(limiter: &DashMap<IpAddr, (Instant, u32)>, ip: IpAddr) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_password_matches() {
        assert!(verify_password("s3cret-pass", "s3cret-pass"));
    }

    #[test]
    fn verify_password_rejects_wrong() {
        assert!(!verify_password("wrong-pass", "s3cret-pass"));
    }

    #[test]
    fn verify_password_rejects_different_length() {
        assert!(!verify_password("short", "a-longer-password"));
    }

    #[test]
    fn allow_login_attempt_respects_limit() {
        let limiter = DashMap::new();
        let ip = IpAddr::from([127, 0, 0, 1]);
        for _ in 0..LOGIN_MAX_ATTEMPTS {
            assert!(allow_login_attempt(&limiter, ip));
        }
        assert!(!allow_login_attempt(&limiter, ip));
    }
}
