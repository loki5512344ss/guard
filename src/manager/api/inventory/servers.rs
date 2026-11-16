//! `GET /api/v1/servers`: backend servers from the Redis registry keys.

#[cfg(feature = "store-redis")]
use crate::manager::AppState;
#[cfg(feature = "store-redis")]
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "store-redis")]
use std::sync::Arc;

/// SCAN pattern of server records.
#[cfg(feature = "store-redis")]
const SERVERS_PATTERN: &str = "rampart:servers:*";

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerEntry {
	pub name: String,
	#[serde(rename = "type")]
	pub server_type: String,
	pub ip: String,
	pub port: u16,
	pub status: String,
}

#[derive(Serialize)]
pub struct ServersResponse {
	pub servers: Vec<ServerEntry>,
}

/// Lists the registry with SCAN and batched MGET reads.
///
/// # Errors
/// Returns 503 when Redis is unreachable or a command fails; an empty `servers`
/// array then always means a healthy but empty registry.
#[cfg(feature = "store-redis")]
pub async fn list_servers(
	State(state): State<Arc<AppState>>,
) -> Result<Json<ServersResponse>, (StatusCode, Json<serde_json::Value>)> {
	let mut conn = state
		.redis_client
		.get_multiplexed_async_connection()
		.await
		.map_err(|error| super::unavailable(&error))?;
	let values = super::scan_values(&mut conn, SERVERS_PATTERN)
		.await
		.map_err(|error| super::unavailable(&error))?;
	Ok(Json(ServersResponse {
		servers: super::decode_all(&values),
	}))
}
