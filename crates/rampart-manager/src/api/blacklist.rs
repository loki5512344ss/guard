use crate::AppState;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub target: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub reason: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct BlacklistResponse {
    pub items: Vec<BlacklistEntry>,
    pub total: usize,
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct AddBlacklistRequest {
    pub target: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub reason: String,
    pub duration_secs: Option<u64>,
}

pub async fn list_blacklist(State(state): State<Arc<AppState>>) -> Json<BlacklistResponse> {
    let mut conn = match state.redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => {
            return Json(BlacklistResponse {
                items: vec![],
                total: 0,
            });
        },
    };

    let members: Vec<String> = match redis::cmd("SMEMBERS")
        .arg("rampart:blacklist")
        .query_async(&mut conn)
        .await
    {
        Ok(m) => m,
        Err(_) => {
            return Json(BlacklistResponse {
                items: vec![],
                total: 0,
            });
        },
    };

    let items: Vec<BlacklistEntry> = members
        .into_iter()
        .map(|target| BlacklistEntry {
            target,
            entry_type: "ip".to_string(),
            reason: "manual".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        })
        .collect();

    let total = items.len();
    Json(BlacklistResponse { items, total })
}

pub async fn add_blacklist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddBlacklistRequest>,
) -> Json<serde_json::Value> {
    let mut conn = match state.redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return Json(serde_json::json!({"error": "redis unavailable"})),
    };

    let _: () = redis::cmd("SADD")
        .arg("rampart:blacklist")
        .arg(&req.target)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();
    tracing::info!("Added to blacklist: {} ({})", req.target, req.reason);

    Json(serde_json::json!({
        "status": "added",
        "target": req.target,
        "reason": req.reason
    }))
}
