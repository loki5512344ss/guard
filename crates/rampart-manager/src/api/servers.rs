use crate::AppState;
use axum::{Json, extract::State};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub server_type: String,
    pub ip: String,
    pub port: u16,
    pub status: String,
    pub online: u32,
    pub max_players: u32,
    pub tps: f64,
}

#[derive(Serialize)]
pub struct ServersResponse {
    pub servers: Vec<ServerEntry>,
}

pub async fn list_servers(State(state): State<Arc<AppState>>) -> Json<ServersResponse> {
    let mut conn = match state.redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return Json(ServersResponse { servers: vec![] }),
    };

    let keys: Vec<String> = match redis::cmd("KEYS").arg("rampart:servers:*").query_async(&mut conn).await {
        Ok(k) => k,
        Err(_) => return Json(ServersResponse { servers: vec![] }),
    };

    let mut servers = Vec::with_capacity(keys.len());
    for key in &keys {
        let raw: Option<String> = conn.get(key).await.unwrap_or(None);
        if let Some(json) = raw
            && let Ok(server) = serde_json::from_str::<ServerEntry>(&json)
        {
            servers.push(server);
        }
    }

    Json(ServersResponse { servers })
}
