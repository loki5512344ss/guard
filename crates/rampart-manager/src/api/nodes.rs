use crate::AppState;
use axum::{Json, extract::State};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

pub async fn list_nodes(State(state): State<Arc<AppState>>) -> Json<NodesResponse> {
    let mut conn = match state.redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return Json(NodesResponse { nodes: vec![] }),
    };

    let keys: Vec<String> = match redis::cmd("KEYS").arg("rampart:nodes:*").query_async(&mut conn).await {
        Ok(k) => k,
        Err(_) => return Json(NodesResponse { nodes: vec![] }),
    };

    let mut nodes = Vec::with_capacity(keys.len());
    for key in &keys {
        let raw: Option<String> = conn.get(key).await.unwrap_or(None);
        if let Some(json) = raw
            && let Ok(node) = serde_json::from_str::<NodeInfo>(&json)
        {
            nodes.push(node);
        }
    }

    Json(NodesResponse { nodes })
}
