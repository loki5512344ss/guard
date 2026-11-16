use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
	pub sub: String,
	pub aud: String,
	pub exp: usize,
	pub iat: usize,
}

pub fn create_token(secret: &str, expiration: u64, audience: &str) -> Result<String, jsonwebtoken::errors::Error> {
	let now = chrono::Utc::now().timestamp() as usize;
	let claims = Claims {
		sub: "rampart-admin".to_string(),
		aud: audience.to_string(),
		exp: now + expiration as usize,
		iat: now,
	};
	encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
}

pub fn verify_token(token: &str, secret: &str, audience: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
	let mut validation = Validation::default();
	validation.set_audience(&[audience]);
	let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)?;
	Ok(token_data.claims)
}

pub async fn auth_middleware(
	State(state): State<Arc<crate::manager::AppState>>,
	request: Request<Body>,
	next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
	let auth_header = request
		.headers()
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "));

	let token = match auth_header {
		Some(t) => t,
		None => {
			return Err((
				StatusCode::UNAUTHORIZED,
				Json(serde_json::json!({"error": "unauthorized"})),
			));
		},
	};

	if verify_token(token, &state.jwt_secret, &state.jwt_audience).is_err() {
		return Err((
			StatusCode::UNAUTHORIZED,
			Json(serde_json::json!({"error": "unauthorized"})),
		));
	}

	Ok(next.run(request).await)
}
