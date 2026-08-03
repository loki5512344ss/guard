use axum::{
    Router,
    http::HeaderValue,
    middleware,
    routing::{get, post},
};
use dashmap::DashMap;
use std::{net::IpAddr, sync::Arc, time::Instant};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

mod api;
mod auth;
mod sync;

pub struct AppState {
    pub redis_client: redis::Client,
    pub jwt_secret: String,
    pub jwt_audience: String,
    pub jwt_expiration: u64,
    pub api_password: String,
    pub login_limiter: DashMap<IpAddr, (Instant, u32)>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rampart_manager=info".parse()?))
        .init();

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());
    let redis_client = redis::Client::open(redis_url)?;

    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| anyhow::anyhow!("JWT_SECRET must be set"))?;
    if jwt_secret.len() < 32 {
        return Err(anyhow::anyhow!("JWT_SECRET must be at least 32 bytes"));
    }
    let jwt_audience = std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "rampart".to_string());
    let jwt_expiration = std::env::var("JWT_EXPIRATION_SECS")
        .unwrap_or_else(|_| "86400".to_string())
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("JWT_EXPIRATION_SECS must be a valid u64"))?;

    let api_password = std::env::var("API_PASSWORD").map_err(|_| anyhow::anyhow!("API_PASSWORD must be set"))?;
    if api_password == "changeme" {
        return Err(anyhow::anyhow!("API_PASSWORD must not be the default 'changeme'"));
    }

    let state = Arc::new(AppState {
        redis_client,
        jwt_secret,
        jwt_audience,
        jwt_expiration,
        api_password,
        login_limiter: DashMap::new(),
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

    let cors = match std::env::var("CORS_ORIGIN") {
        Ok(origin) if origin.is_empty() || origin == "*" => CorsLayer::new().allow_origin(tower_http::cors::Any),
        Ok(origin) => CorsLayer::new().allow_origin(HeaderValue::from_str(&origin)?),
        Err(_) => CorsLayer::new().allow_origin(HeaderValue::from_static("http://localhost:5173")),
    };

    let app = Router::new()
        .merge(public)
        .merge(protected)
        .layer(cors)
        .with_state(state);

    let addr = "0.0.0.0:8080";
    tracing::info!("Manager API listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, app).await?;
    Ok(())
}
