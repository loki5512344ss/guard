use crate::AppState;
use axum::Json;
use axum::extract::State;
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

pub async fn health_check(State(_state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
