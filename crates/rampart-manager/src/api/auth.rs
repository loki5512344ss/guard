use crate::AppState;
use axum::{Json, extract::State};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

pub async fn login(State(state): State<Arc<AppState>>, Json(req): Json<LoginRequest>) -> Json<serde_json::Value> {
    let api_password = std::env::var("API_PASSWORD").unwrap_or_else(|_| "changeme".to_string());
    if req.password != api_password {
        return Json(serde_json::json!({"error": "invalid password"}));
    }

    match crate::auth::create_token(&state.jwt_secret, state.jwt_expiration) {
        Ok(token) => Json(serde_json::json!({"token": token})),
        Err(_) => Json(serde_json::json!({"error": "token creation failed"})),
    }
}
