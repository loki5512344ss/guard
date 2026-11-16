//! Rampart manager daemon: HTTP API in front of the redis state store.

use dashmap::DashMap;
#[cfg(feature = "store-redis")]
use rampart::manager::api;
#[cfg(feature = "store-redis")]
use rampart::manager::sync;
use rampart::manager::{
	AppState, SharedState,
	api::{build_router, guard},
	security,
};
use std::sync::Arc;
use tokio::sync::watch;
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

	let state: SharedState = Arc::new(AppState {
		#[cfg(feature = "store-redis")]
		redis_client,
		jwt_secret,
		jwt_audience,
		jwt_expiration,
		api_password,
		login_limiter: DashMap::new(),
	});
	let guard = Arc::new(guard::RequestGuard::from_env()?);

	// Background tasks share one shutdown signal, so SIGTERM stops them together
	// with the HTTP server instead of leaving detached tasks behind.
	let (shutdown_tx, shutdown_rx) = watch::channel(false);
	#[cfg(feature = "store-redis")]
	let heartbeat = spawn_heartbeat(state.clone(), shutdown_rx.clone());
	let eviction = guard::spawn_eviction(state.clone(), guard.clone(), shutdown_rx.clone());
	// One-shot legacy migration; losing it on shutdown is harmless because the
	// read path no longer depends on the metadata being present.
	#[cfg(feature = "store-redis")]
	tokio::spawn(api::blacklist::backfill_legacy_metadata(state.clone()));

	let cors_policy = security::CorsPolicy::parse(std::env::var("CORS_ORIGIN").ok().as_deref())?;
	tracing::info!("CORS policy: {cors_policy:?}");

	let app = build_router(state, guard, cors_policy.cors_layer());
	let addr = "0.0.0.0:8080";
	let listener = tokio::net::TcpListener::bind(addr).await?;
	tracing::info!("Manager API listening on {addr}");
	let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();

	// Graceful shutdown drains in-flight requests, so a ban removal that already
	// reached a handler is written to Redis before the process exits.
	axum::serve(listener, app)
		.with_graceful_shutdown(shutdown_signal())
		.await?;

	let _ = shutdown_tx.send(true);
	let _ = eviction.await;
	#[cfg(feature = "store-redis")]
	let _ = heartbeat.await;
	tracing::info!("manager stopped");
	Ok(())
}

/// Spawns the heartbeat check loop and stops it on the shared shutdown signal.
#[cfg(feature = "store-redis")]
fn spawn_heartbeat(state: SharedState, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		tokio::select! {
			() = sync::heartbeat::start_heartbeat_check(state) => {},
			_ = shutdown.changed() => {},
		}
	})
}

/// Resolves on `SIGTERM` or Ctrl-C, whichever arrives first.
async fn shutdown_signal() {
	let ctrl_c = async {
		if let Err(error) = tokio::signal::ctrl_c().await {
			tracing::error!("failed to listen for Ctrl-C: {error}");
		}
	};
	#[cfg(unix)]
	let terminate = async {
		match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
			Ok(mut signal) => {
				signal.recv().await;
			},
			Err(error) => {
				tracing::error!("failed to listen for SIGTERM: {error}");
				std::future::pending::<()>().await;
			},
		}
	};
	#[cfg(not(unix))]
	let terminate = std::future::pending::<()>();
	tokio::select! {
		() = ctrl_c => {},
		() = terminate => {},
	}
	tracing::info!("shutdown signal received: draining in-flight requests");
}
