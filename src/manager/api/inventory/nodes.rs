//! `GET /api/v1/nodes`: registered edge nodes from the Redis heartbeat keys.

#[cfg(feature = "store-redis")]
use crate::manager::AppState;
#[cfg(feature = "store-redis")]
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "store-redis")]
use std::sync::Arc;

/// SCAN pattern of node records.
#[cfg(feature = "store-redis")]
const NODES_PATTERN: &str = "rampart:nodes:*";

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeInfo {
	pub id: String,
	pub role: String,
	pub ip: String,
	pub status: String,
	pub last_heartbeat: String,
}

#[derive(Serialize)]
pub struct NodesResponse {
	pub nodes: Vec<NodeInfo>,
}

/// Lists the fleet with SSCAN-style iteration and batched reads.
///
/// # Errors
/// Returns 503 when Redis is unreachable or a command fails; an empty `nodes`
/// array then always means a healthy but empty fleet.
#[cfg(feature = "store-redis")]
pub async fn list_nodes(
	State(state): State<Arc<AppState>>,
) -> Result<Json<NodesResponse>, (StatusCode, Json<serde_json::Value>)> {
	let mut conn = state
		.redis_client
		.get_multiplexed_async_connection()
		.await
		.map_err(|error| super::unavailable(&error))?;
	let values = super::scan_values(&mut conn, NODES_PATTERN)
		.await
		.map_err(|error| super::unavailable(&error))?;
	Ok(Json(NodesResponse {
		nodes: super::decode_all(&values),
	}))
}
