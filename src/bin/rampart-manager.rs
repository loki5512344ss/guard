//! Rampart manager daemon: HTTP API in front of the redis state store.

use axum::{
	Router, middleware,
	routing::{get, post},
};
use dashmap::DashMap;
#[cfg(feature = "store-redis")]
use rampart::manager::sync;
use rampart::manager::{AppState, api, auth, security};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env().add_directive("rampart=info".parse()?))
		.init();

	// The manager lives exclusively on the redis store: without the feature there
	// is nothing to start, so fail fast instead of serving a half-dead API.
	if !cfg!(feature = "store-redis") {
		anyhow::bail!("rampart-manager requires a redis state store: built without store-redis feature");
	}

	#[cfg(feature = "store-redis")]
	let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());
	#[cfg(feature = "store-redis")]
	let redis_client = redis::Client::open(redis_url)?;

	let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| anyhow::anyhow!("JWT_SECRET must be set"))?;
	security::validate_jwt_secret(&jwt_secret)?;
	let jwt_audience = std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "rampart".to_string());
	let jwt_expiration = std::env::var("JWT_EXPIRATION_SECS")
		.unwrap_or_else(|_| "86400".to_string())
		.parse::<u64>()
		.map_err(|_| anyhow::anyhow!("JWT_EXPIRATION_SECS must be a valid u64"))?;

	let api_password = std::env::var("API_PASSWORD").map_err(|_| anyhow::anyhow!("API_PASSWORD must be set"))?;
	security::validate_api_password(&api_password)?;

	let state = Arc::new(AppState {
		#[cfg(feature = "store-redis")]
		redis_client,
		jwt_secret,
		jwt_audience,
		jwt_expiration,
		api_password,
		login_limiter: DashMap::new(),
	});

	#[cfg(feature = "store-redis")]
	tokio::spawn(sync::heartbeat::start_heartbeat_check(state.clone()));

	let public = Router::new()
		.route("/api/v1/health", get(api::inventory::health::health_check))
		.route("/api/v1/auth/login", post(api::auth::login));

	// Redis-backed routes only exist together with the feature; the manager bails
	// out above without it, so 501 stubs here would be unreachable code.
	let protected = Router::new();
	#[cfg(feature = "store-redis")]
	let protected = protected
		.route("/api/v1/servers", get(api::inventory::servers::list_servers))
		.route(
			"/api/v1/blacklist",
			get(api::blacklist::list_blacklist)
				.post(api::blacklist::add_blacklist)
				.delete(api::blacklist::remove_blacklist),
		)
		.route("/api/v1/nodes", get(api::inventory::nodes::list_nodes));
	let protected = protected.route_layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware));

	let cors_policy = security::CorsPolicy::parse(std::env::var("CORS_ORIGIN").ok().as_deref())?;
	tracing::info!("CORS policy: {cors_policy:?}");

	let mut app = Router::new().merge(public).merge(protected).with_state(state);
	if let Some(cors) = cors_policy.cors_layer() {
		app = app.layer(cors);
	}

	let addr = "0.0.0.0:8080";
	tracing::info!("Manager API listening on {addr}");
	let listener = tokio::net::TcpListener::bind(addr).await?;
	let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
	axum::serve(listener, app).await?;
	Ok(())
}
