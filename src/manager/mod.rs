//! Management-плоскость Rampart: REST API, аутентификация, синхронизация узлов.
pub mod api;
pub mod auth;
pub mod sync;

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

/// Общее состояние management-API.
pub struct AppState {
    pub redis_client: redis::Client,
    pub jwt_secret: String,
    pub jwt_audience: String,
    pub jwt_expiration: u64,
    pub api_password: String,
    pub login_limiter: DashMap<IpAddr, (Instant, u32)>,
}

pub type SharedState = Arc<AppState>;
