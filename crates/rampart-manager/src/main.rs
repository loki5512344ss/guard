use axum::{
    Router, middleware,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

mod api;
mod auth;
mod sync;

pub struct AppState {
    pub redis_client: redis::Client,
    pub jwt_secret: String,
    pub jwt_expiration: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rampart_manager=info".parse()?))
        .init();

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());
    let redis_client = redis::Client::open(redis_url)?;

    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| anyhow::anyhow!("JWT_SECRET must be set"))?;
    let jwt_expiration = std::env::var("JWT_EXPIRATION_SECS")
        .unwrap_or_else(|_| "86400".to_string())
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("JWT_EXPIRATION_SECS must be a valid u64"))?;

    let state = Arc::new(AppState {
        redis_client,
        jwt_secret,
        jwt_expiration,
    });

    tokio::spawn(sync::heartbeat::start_heartbeat_check(state.clone()));

    let public = Router::new()
        .route("/api/v1/health", get(api::health::health_check))
        .route("/api/v1/auth/login", post(api::auth::login));

    let protected = Router::new()
        .route("/api/v1/servers", get(api::servers::list_servers))
        .route(
            "/api/v1/blacklist",
            get(api::blacklist::list_blacklist).post(api::blacklist::add_blacklist),
        )
        .route("/api/v1/nodes", get(api::nodes::list_nodes))
        .route_layer(middleware::from_fn(auth::auth_middleware));

    let app = Router::new()
        .merge(public)
        .merge(protected)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:8080";
    tracing::info!("Manager API listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
