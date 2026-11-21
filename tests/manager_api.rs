//! Manager HTTP API contract: authentication, request validation, body limit,
//! per-IP rate limiting, Redis failure mapping and CORS preflight.
//!
//! The tests drive the production router through `tower::ServiceExt::oneshot`,
//! so they exercise the same layer stack as the daemon without opening a
//! listening socket. The Redis URL points at a closed loopback port; no server
//! is started and no external network is used.

#![cfg(feature = "store-redis")]

use axum::{
	Router,
	body::Body,
	extract::ConnectInfo,
	http::{Method, Request, StatusCode, header},
};
use dashmap::DashMap;
use rampart::manager::{
	AppState,
	api::{
		blacklist::{DEFAULT_PAGE_LIMIT, ListQuery, MAX_PAGE_LIMIT, MAX_PAGE_OFFSET},
		build_router,
		guard::RequestGuard,
		guard::limit::MUTATION_MAX_ATTEMPTS,
		guard::proxy::TrustedProxies,
	},
	auth::create_token,
	security::CorsPolicy,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const AUDIENCE: &str = "rampart";
const PASSWORD: &str = "correct-horse-battery-staple";
const UNREACHABLE_REDIS: &str = "redis://127.0.0.1:1/0";
const LOGIN_BODY: &str = r#"{"password":"wrong-password"}"#;
const BAN_BODY: &str = r#"{"target":"1.2.3.4","type":"ip","reason":"manual_ban"}"#;

fn peer() -> SocketAddr {
	SocketAddr::from(([10, 0, 0, 5], 53_000))
}

fn state(redis_url: &str) -> Arc<AppState> {
	Arc::new(AppState {
		redis_client: redis::Client::open(redis_url).expect("redis URL must parse"),
		jwt_secret: SECRET.to_string(),
		jwt_audience: AUDIENCE.to_string(),
		jwt_expiration: 3600,
		api_password: PASSWORD.to_string(),
		login_limiter: DashMap::new(),
	})
}

/// Builds the production router with no trusted proxy and no CORS layer.
fn app() -> Router {
	build_router(
		state(UNREACHABLE_REDIS),
		Arc::new(RequestGuard::new(TrustedProxies::default())),
		None,
	)
}

fn request(method: Method, uri: &str, body: Body) -> Request<Body> {
	Request::builder()
		.method(method)
		.uri(uri)
		.extension(ConnectInfo(peer()))
		.header(header::CONTENT_TYPE, "application/json")
		.body(body)
		.expect("request must build")
}

fn authorized(mut request: Request<Body>) -> Request<Body> {
	let token = create_token(SECRET, 3600, AUDIENCE).expect("token must be created");
	request.headers_mut().insert(
		header::AUTHORIZATION,
		format!("Bearer {token}").parse().expect("header value must be valid"),
	);
	request
}

async fn status(router: &Router, request: Request<Body>) -> StatusCode {
	router
		.clone()
		.oneshot(request)
		.await
		.expect("router must answer")
		.status()
}

#[tokio::test]
async fn protected_routes_require_a_token() {
	let router = app();
	for uri in ["/api/v1/servers", "/api/v1/nodes", "/api/v1/blacklist"] {
		let response = status(&router, request(Method::GET, uri, Body::empty())).await;
		assert_eq!(response, StatusCode::UNAUTHORIZED, "{uri} must reject anonymous access");
	}
}

#[tokio::test]
async fn blacklist_rejects_invalid_targets() {
	let router = app();
	for target in [
		"not-an-ip",
		"10.0.0.0/8",
		"999.1.1.1",
		"",
		" 1.2.3.4",
		"1.2.3.4 ",
		"1.2.3.4x",
		"1.2.3.4/0",
		"1.2.3.4/33",
		"::1/129",
		"1.2.3.4/+8",
	] {
		let body = format!(r#"{{"target":"{target}","type":"ip","reason":"manual_ban"}}"#);
		let response = status(
			&router,
			authorized(request(Method::POST, "/api/v1/blacklist", Body::from(body))),
		)
		.await;
		assert_eq!(response, StatusCode::BAD_REQUEST, "target '{target}' must be rejected");
	}
	let body = r#"{"target":"300.1.1.1"}"#;
	let response = status(
		&router,
		authorized(request(Method::DELETE, "/api/v1/blacklist", Body::from(body))),
	)
	.await;
	assert_eq!(response, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn blacklist_rejects_an_overlong_reason() {
	let reason = "a".repeat(257);
	let body = format!(r#"{{"target":"1.2.3.4","type":"ip","reason":"{reason}"}}"#);
	let response = status(
		&app(),
		authorized(request(Method::POST, "/api/v1/blacklist", Body::from(body))),
	)
	.await;
	assert_eq!(response, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_body_is_rejected_before_the_handler() {
	let reason = "a".repeat(9 * 1024);
	let body = format!(r#"{{"target":"1.2.3.4","type":"ip","reason":"{reason}"}}"#);
	let response = status(
		&app(),
		authorized(request(Method::POST, "/api/v1/blacklist", Body::from(body))),
	)
	.await;
	assert_eq!(response, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn login_is_rate_limited_per_client() {
	let router = app();
	for attempt in 1..=5 {
		let response = status(
			&router,
			request(Method::POST, "/api/v1/auth/login", Body::from(LOGIN_BODY)),
		)
		.await;
		assert_eq!(
			response,
			StatusCode::UNAUTHORIZED,
			"attempt {attempt} must reach the password check"
		);
	}
	let response = status(
		&router,
		request(Method::POST, "/api/v1/auth/login", Body::from(LOGIN_BODY)),
	)
	.await;
	assert_eq!(response, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn mutating_requests_are_rate_limited_per_client() {
	let router = app();
	for _ in 0..MUTATION_MAX_ATTEMPTS {
		let response = status(
			&router,
			authorized(request(Method::POST, "/api/v1/blacklist", Body::from(BAN_BODY))),
		)
		.await;
		assert_ne!(
			response,
			StatusCode::TOO_MANY_REQUESTS,
			"budget must cover the first window"
		);
	}
	let response = status(
		&router,
		authorized(request(Method::POST, "/api/v1/blacklist", Body::from(BAN_BODY))),
	)
	.await;
	assert_eq!(response, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn redis_failure_is_distinguishable_from_an_empty_fleet() {
	let router = app();
	for uri in ["/api/v1/nodes", "/api/v1/servers", "/api/v1/blacklist"] {
		let response = status(&router, authorized(request(Method::GET, uri, Body::empty()))).await;
		assert_eq!(
			response,
			StatusCode::SERVICE_UNAVAILABLE,
			"{uri} must report a store failure"
		);
	}
}

#[tokio::test]
async fn cors_preflight_answers_only_configured_origins() {
	let policy = CorsPolicy::parse(Some("https://admin.example")).expect("policy must parse");
	let router = build_router(
		state(UNREACHABLE_REDIS),
		Arc::new(RequestGuard::new(TrustedProxies::default())),
		policy.cors_layer(),
	);

	let allowed = preflight(&router, "https://admin.example").await;
	assert_eq!(allowed.status(), StatusCode::OK);
	assert_eq!(
		allowed
			.headers()
			.get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
			.and_then(|value| value.to_str().ok()),
		Some("https://admin.example")
	);
	let methods = allowed
		.headers()
		.get(header::ACCESS_CONTROL_ALLOW_METHODS)
		.and_then(|value| value.to_str().ok())
		.unwrap_or_default();
	assert!(methods.contains("POST"), "preflight must advertise the mutating verb");

	let denied = preflight(&router, "https://evil.example").await;
	assert_eq!(denied.status(), StatusCode::OK);
	assert!(denied.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
}

async fn preflight(router: &Router, origin: &str) -> axum::response::Response {
	let request = Request::builder()
		.method(Method::OPTIONS)
		.uri("/api/v1/blacklist")
		.header(header::ORIGIN, origin)
		.header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
		.extension(ConnectInfo(peer()))
		.body(Body::empty())
		.expect("preflight request must build");
	router.clone().oneshot(request).await.expect("router must answer")
}

#[test]
fn list_query_is_capped_regardless_of_the_request() {
	assert_eq!(
		ListQuery {
			limit: None,
			offset: None
		}
		.bounds(),
		(0, DEFAULT_PAGE_LIMIT)
	);
	assert_eq!(
		ListQuery {
			limit: Some(5000),
			offset: Some(50)
		}
		.bounds(),
		(50, MAX_PAGE_LIMIT)
	);
	assert_eq!(
		ListQuery {
			limit: Some(10),
			offset: Some(u64::MAX)
		}
		.bounds(),
		(MAX_PAGE_OFFSET, 10)
	);
	assert_eq!(
		ListQuery {
			limit: Some(0),
			offset: Some(0)
		}
		.bounds(),
		(0, 0)
	);
}

async fn post_ban(router: &Router, extra: &str) -> StatusCode {
	let body = format!(r#"{{"target":"1.2.3.4","type":"ip","reason":"manual_ban"{extra}}}"#);
	status(
		router,
		authorized(request(Method::POST, "/api/v1/blacklist", Body::from(body))),
	)
	.await
}

#[tokio::test]
async fn ban_accepts_absolute_expiry_as_an_alternative_to_duration() {
	let router = app();
	let now = rampart::timeutil::unix_now();
	// Valid requests pass validation and fail only at the unreachable Redis (503).
	for extra in [
		String::new(),
		r#","duration_secs":3600"#.to_string(),
		format!(r#","expires_at":{}"#, now + 3600),
		format!(r#","expires_at":{}"#, now + 31_536_000 - 5),
	] {
		assert_eq!(
			post_ban(&router, &extra).await,
			StatusCode::SERVICE_UNAVAILABLE,
			"{extra}"
		);
	}
}

#[tokio::test]
async fn ban_rejects_invalid_expiry_combinations() {
	let router = app();
	let now = rampart::timeutil::unix_now();
	for extra in [
		format!(r#","duration_secs":60,"expires_at":{}"#, now + 60),
		format!(r#","expires_at":{}"#, now - 10),
		r#","expires_at":0"#.to_string(),
		r#","expires_at":-5"#.to_string(),
		format!(r#","expires_at":{}"#, now + 31_536_000 + 60),
		format!(r#","expires_at":{}"#, i64::MAX),
		r#","duration_secs":0"#.to_string(),
		r#","duration_secs":31536001"#.to_string(),
	] {
		assert_eq!(post_ban(&router, &extra).await, StatusCode::BAD_REQUEST, "{extra}");
	}
}
