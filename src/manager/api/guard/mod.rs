//! HTTP hardening shared by the manager endpoints.
//!
//! Owns the [`RequestGuard`] (proxy-aware client address plus the mutating
//! request limiter), the per-IP attempt helpers and [`build_router`], so the
//! daemon and the integration tests exercise the same body limit, timeout, CORS
//! and rate-limit stack.

pub mod limit;
pub mod proxy;
mod router;

use axum::extract::ConnectInfo;
pub use limit::{check_attempt, evict_idle, reset_attempts};
pub use proxy::{TRUSTED_PROXIES_ENV, TrustedProxies};
pub use router::{MAX_BODY_BYTES, REQUEST_TIMEOUT, build_router};

use crate::manager::SharedState;
use axum::{extract::Request, http::HeaderMap};
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How often the background eviction task sweeps idle limiter entries.
const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

/// Per-request security context: trusted proxies and the mutation budget.
pub struct RequestGuard {
	trusted_proxies: TrustedProxies,
	mutations: DashMap<IpAddr, (Instant, u32)>,
}

impl RequestGuard {
	/// Builds a guard for `trusted_proxies` with an empty mutation budget.
	#[must_use]
	pub fn new(trusted_proxies: TrustedProxies) -> Self {
		Self {
			trusted_proxies,
			mutations: DashMap::new(),
		}
	}

	/// Builds a guard from `MANAGER_TRUSTED_PROXIES`.
	///
	/// # Errors
	/// Fails when the variable contains a malformed network entry.
	pub fn from_env() -> anyhow::Result<Self> {
		Ok(Self::new(TrustedProxies::from_env()?))
	}

	/// Resolves the client address from the peer address and forwarded chain.
	#[must_use]
	pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
		self.trusted_proxies.client_ip(peer, headers.get("x-forwarded-for"))
	}

	/// Resolves the client address of `request`, falling back to the unspecified
	/// address when the server was built without connect info.
	#[must_use]
	pub fn request_client_ip(&self, request: &Request) -> IpAddr {
		let peer = request
			.extensions()
			.get::<ConnectInfo<SocketAddr>>()
			.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.ip());
		self.client_ip(peer, request.headers())
	}

	/// Records one mutating request for `ip` and reports whether it is allowed.
	pub fn allow_mutation(&self, ip: IpAddr) -> bool {
		check_attempt(
			&self.mutations,
			ip,
			limit::MUTATION_WINDOW,
			limit::MUTATION_MAX_ATTEMPTS,
		)
	}

	/// Drops mutation counters whose window elapsed.
	pub fn evict_idle(&self) {
		evict_idle(&self.mutations, limit::MUTATION_WINDOW);
	}
}

/// Sweeps idle login and mutation counters until shutdown is requested.
///
/// Without the sweep a long-lived manager keeps one map entry per source
/// address forever, which slowly turns the limiters into a memory leak.
pub async fn run_eviction(state: SharedState, guard: Arc<RequestGuard>, mut shutdown: watch::Receiver<bool>) {
	let mut ticker = tokio::time::interval(EVICTION_INTERVAL);
	ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		tokio::select! {
			_ = ticker.tick() => {
				evict_idle(&state.login_limiter, limit::LOGIN_WINDOW);
				guard.evict_idle();
			},
			changed = shutdown.changed() => {
				if changed.is_err() || *shutdown.borrow_and_update() {
					return;
				}
			},
		}
	}
}

/// Spawns [`run_eviction`] on the current runtime.
pub fn spawn_eviction(state: SharedState, guard: Arc<RequestGuard>, shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
	tokio::spawn(run_eviction(state, guard, shutdown))
}
