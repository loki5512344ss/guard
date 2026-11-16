//! Multi-worker TCP accept loop with `SO_REUSEPORT` and graceful shutdown.

use crate::config::Config;
use crate::engine::tunnel::Gateway;
use crate::traffic::hook::TrafficHook;
use anyhow::Context;
use socket2::{Domain, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_millis(500);
/// Consecutive accept failures between full-rate ERROR logs.
///
/// Every intervening failure is still reported at `debug`, so the log stays
/// diagnosable without amplifying a spin into a disk-filling storm.
const ACCEPT_ERROR_LOG_EVERY: u32 = 32;

/// Linux errno values that mean "the listener is temporarily unable to accept".
///
/// `libc` is an optional dependency of the `xdp` feature, so the values are
/// spelled out here; they are ABI constants on the platforms Rampart targets.
#[cfg(target_os = "linux")]
mod errno {
	pub const ENOMEM: i32 = 12;
	pub const ENFILE: i32 = 23;
	pub const EMFILE: i32 = 24;
	pub const ENOBUFS: i32 = 105;
}

/// Exponential backoff for transient `accept()` failures.
///
/// File-descriptor exhaustion (`EMFILE`/`ENFILE`) makes `accept()` fail
/// synchronously and forever: a plain `continue` turns every worker into a
/// 100% CPU spin that also floods the log. Each transient failure therefore
/// yields a mandatory sleep, growing from `ACCEPT_BACKOFF_MIN` to
/// `ACCEPT_BACKOFF_MAX` and resetting after the next successful accept.
pub struct AcceptBackoff {
	delay: Duration,
	failures: u32,
}

impl Default for AcceptBackoff {
	fn default() -> Self {
		Self::new()
	}
}

impl AcceptBackoff {
	#[must_use]
	pub fn new() -> Self {
		Self {
			delay: Duration::ZERO,
			failures: 0,
		}
	}

	/// Returns how long the accept loop must sleep before retrying `error`.
	///
	/// `None` means the error is not a capacity or readiness condition
	/// (`ECONNABORTED`, `EPROTO`, ...): the connection was abandoned by the peer
	/// or the kernel, so an immediate retry is correct.
	pub fn delay(&mut self, error: &std::io::Error) -> Option<Duration> {
		if !is_transient(error) {
			return None;
		}
		self.failures = self.failures.saturating_add(1);
		self.delay = if self.delay.is_zero() {
			ACCEPT_BACKOFF_MIN
		} else {
			(self.delay * 2).min(ACCEPT_BACKOFF_MAX)
		};
		Some(self.delay)
	}

	/// Clears the accumulated backoff after a successful accept.
	pub fn reset(&mut self) {
		self.delay = Duration::ZERO;
		self.failures = 0;
	}

	/// Reports whether the current failure deserves a full-rate ERROR log.
	#[must_use]
	pub fn should_log(&self) -> bool {
		self.failures == 1 || self.failures % ACCEPT_ERROR_LOG_EVERY == 0
	}
}

fn is_transient(error: &std::io::Error) -> bool {
	if matches!(
		error.kind(),
		ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::OutOfMemory
	) {
		return true;
	}
	#[cfg(target_os = "linux")]
	if matches!(
		error.raw_os_error(),
		Some(errno::EMFILE | errno::ENFILE | errno::ENOBUFS | errno::ENOMEM)
	) {
		return true;
	}
	false
}

/// Starts `workers.count` accept loops on a single address.
///
/// Each worker binds its own socket with `SO_REUSEPORT` and `SO_REUSEADDR`, so
/// the kernel distributes incoming connections across them and a restart does
/// not fail on `TIME_WAIT` sockets.
///
/// # Errors
/// Fails when the address cannot be bound or when one of the accept loops dies.
pub async fn run(
	config: Arc<Config>,
	gateway: Arc<Gateway>,
	hook: Arc<TrafficHook>,
	shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
	let addr = parse_listen_addr(&config.bind.address, config.bind.port)?;
	let workers = config.workers.count.max(1);

	let mut handles = Vec::with_capacity(workers);
	for _ in 0..workers {
		let listener = build_listener(addr)?;
		handles.push(tokio::spawn(accept_loop(
			listener,
			Arc::clone(&gateway),
			Arc::clone(&hook),
			shutdown.clone(),
		)));
	}

	for h in handles {
		h.await?;
	}
	Ok(())
}

/// Parses the configured listen address into a socket address.
///
/// The address must be an IP literal: resolving a host name at startup would
/// make the bound family depend on resolver state, and the listener needs the
/// family up front to pick the correct socket domain.
///
/// # Errors
/// Fails when `address` is not a valid IPv4 or IPv6 literal.
pub fn parse_listen_addr(address: &str, port: u16) -> anyhow::Result<SocketAddr> {
	let ip: IpAddr = address
		.parse()
		.with_context(|| format!("bind.address must be an IP address, got {address:?}"))?;
	Ok(SocketAddr::new(ip, port))
}

/// Binds a TCP listener on `addr` with `SO_REUSEPORT` and `SO_REUSEADDR`.
///
/// The socket domain follows the address family, so IPv6 listen addresses work
/// as well as IPv4 ones. An IPv6 wildcard socket is switched to dual-stack mode
/// (`IPV6_V6ONLY=0`), which keeps `bind.address = "::"` accepting IPv4 clients
/// through IPv4-mapped addresses.
///
/// # Errors
/// Fails when the socket cannot be created, configured or bound.
pub fn build_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
	let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
	let socket = Socket::new(domain, Type::STREAM, None)?;
	socket.set_reuse_port(true)?;
	socket.set_reuse_address(true)?;
	socket.set_nonblocking(true)?;
	if addr.is_ipv6() && addr.ip().is_unspecified() {
		socket.set_only_v6(false)?;
	}
	socket.bind(&addr.into())?;
	socket.listen(65535)?;
	Ok(TcpListener::from_std(socket.into())?)
}

async fn accept_loop(
	listener: TcpListener,
	gateway: Arc<Gateway>,
	hook: Arc<TrafficHook>,
	mut shutdown: watch::Receiver<bool>,
) {
	let mut backoff = AcceptBackoff::new();
	loop {
		tokio::select! {
			biased;
			changed = shutdown.changed() => {
				match changed {
					Ok(()) if *shutdown.borrow() => {
						tracing::info!("shutdown signal received, stopping accept loop");
						return;
					},
					// An update that does not raise the flag: keep serving.
					Ok(()) => {},
					// The sender is gone. `changed()` would return `Err` immediately
					// and forever, so treat it as shutdown instead of spinning.
					Err(_) => {
						tracing::info!("shutdown channel closed, stopping accept loop");
						return;
					},
				}
			}
			result = listener.accept() => {
				let (stream, peer_addr) = match result {
					Ok(conn) => {
						backoff.reset();
						conn
					},
					Err(e) => {
						if let Some(delay) = backoff.delay(&e) {
							if backoff.should_log() {
								tracing::error!("accept error, backing off {delay:?}: {e}");
							} else {
								tracing::debug!("accept error, backing off {delay:?}: {e}");
							}
							tokio::time::sleep(delay).await;
						} else {
							tracing::debug!("accept error: {e}");
						}
						continue;
					},
				};
				let gateway = Arc::clone(&gateway);
				let hook = Arc::clone(&hook);
				tokio::spawn(async move {
					// Traffic intelligence hot path: atomics and `DashMap` only.
					hook.on_accept();
					let outcome = gateway.handle(stream, peer_addr).await;
					if let Err(e) = outcome.result {
						tracing::debug!("connection from {peer_addr}: {e}");
					}
					if let Some(client_ip) = outcome.client_ip {
						hook.on_connection_end(client_ip);
					}
				});
			}
		}
	}
}
