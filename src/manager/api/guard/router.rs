//! Router assembly for the manager API.
//!
//! Every deployment path, including integration tests, builds the router here
//! so the body limit, request deadline, CORS policy and per-IP rate limiting
//! cannot drift between the daemon and its tests.

use super::RequestGuard;
#[cfg(feature = "store-redis")]
use super::limit::rate_limit_mutations;
#[cfg(feature = "store-redis")]
use crate::manager::auth;
use crate::manager::{SharedState, api};
#[cfg(feature = "store-redis")]
use axum::middleware;
use axum::{
	Extension, Router,
	extract::DefaultBodyLimit,
	http::StatusCode,
	routing::{get, post},
};
use std::sync::Arc;
use std::time::Duration;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer};

/// Hard cap on any request body accepted by the manager API.
///
/// The largest documented payload is a blacklist entry with a 256-byte reason,
/// so 8 KiB leaves room for JSON overhead while keeping an unauthenticated
/// client from buffering megabytes.
pub const MAX_BODY_BYTES: usize = 8 * 1024;
/// Whole-request deadline, including authentication and a Redis round trip.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds the complete manager router.
///
/// `cors` is the layer derived from `CORS_ORIGIN`; `None` serves no cross-origin
/// policy at all. The returned router is ready to be attached to a listener
/// through `into_make_service_with_connect_info`, which the handlers require for
/// the client address.
pub fn build_router(state: SharedState, guard: Arc<RequestGuard>, cors: Option<CorsLayer>) -> Router {
	let public = Router::new()
		.route("/api/v1/health", get(api::inventory::health::health_check))
		.route("/api/v1/auth/login", post(api::auth::login));

	// Redis-backed routes only exist together with the feature; the manager
	// refuses to start without it, so 501 stubs here would be unreachable.
	#[cfg(feature = "store-redis")]
	let protected = Router::new()
		.route("/api/v1/servers", get(api::inventory::servers::list_servers))
		.route(
			"/api/v1/blacklist",
			get(api::blacklist::list_blacklist)
				.post(api::blacklist::add_blacklist)
				.delete(api::blacklist::remove_blacklist),
		)
		.route("/api/v1/nodes", get(api::inventory::nodes::list_nodes))
		.route_layer(middleware::from_fn_with_state(guard.clone(), rate_limit_mutations))
		.route_layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware));
	#[cfg(not(feature = "store-redis"))]
	let protected = Router::new();

	let mut app = Router::new()
		.merge(public)
		.merge(protected)
		.with_state(state)
		.layer(Extension(guard))
		.layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
		.layer(TimeoutLayer::with_status_code(
			StatusCode::REQUEST_TIMEOUT,
			REQUEST_TIMEOUT,
		));
	if let Some(cors) = cors {
		app = app.layer(cors);
	}
	app
}
