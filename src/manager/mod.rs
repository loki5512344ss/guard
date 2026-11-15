//! Rampart management plane: REST API, authentication and node synchronisation.
//!
//! Owns [`AppState`], the handle shared by every handler through [`SharedState`].
pub mod api;
pub mod auth;
pub mod sync;

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

/// Shared state of the management API.
pub struct AppState {
	/// Redis client for state management; present only when the `store-redis`
	/// feature is compiled in (the manager requires it at startup, see
	/// bin/rampart-manager).
	#[cfg(feature = "store-redis")]
	pub redis_client: redis::Client,
	pub jwt_secret: String,
	pub jwt_audience: String,
	pub jwt_expiration: u64,
	pub api_password: String,
	pub login_limiter: DashMap<IpAddr, (Instant, u32)>,
}

pub type SharedState = Arc<AppState>;
