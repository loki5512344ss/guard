//! Shared loopback harness for `tests/edge_e2e.rs`; cargo does not build it as
//! its own test binary because it lives in a subdirectory.

use rampart::config::Config;
use rampart::engine::challenge::DifficultyAdjuster;
use rampart::engine::listener;
use rampart::engine::tunnel::Gateway;
use rampart::filter::blacklist::Blacklist;
use rampart::filter::rate_limit::RateLimiter;
use rampart::protocol::ProtocolRegistry;
use rampart::protocol::http::HttpProtocolHandler;
use rampart::traffic::hook::TrafficHook;
use rampart::traffic::reputation::IpReputation;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: edge\r\n\r\n";
pub const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
pub const POW_DIFFICULTY: u8 = 2;
/// Upper bound of every I/O wait, so a regression fails instead of hanging.
pub const IO_BUDGET: Duration = Duration::from_secs(4);
const READY_BUDGET: Duration = Duration::from_secs(2);
const MAX_REPLY_BYTES: usize = 64 * 1024;

// --- upstream -------------------------------------------------------------

/// Real upstream: returns its address, an accept counter and the heads it saw.
pub async fn start_upstream() -> (SocketAddr, Arc<AtomicUsize>, Arc<Mutex<Vec<Vec<u8>>>>) {
	let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
		.await
		.expect("bind upstream");
	let addr = listener.local_addr().expect("upstream address");
	let accepted = Arc::new(AtomicUsize::new(0));
	let requests = Arc::new(Mutex::new(Vec::new()));
	let (count, seen) = (Arc::clone(&accepted), Arc::clone(&requests));
	// Detached: the per-test runtime drops this server when the test ends.
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			count.fetch_add(1, Ordering::SeqCst);
			let seen = Arc::clone(&seen);
			tokio::spawn(async move {
				let head = read_head(&mut stream).await;
				seen.lock().expect("requests lock").push(head);
				let _ = stream.write_all(RESPONSE).await;
				let _ = stream.shutdown().await;
			});
		}
	});
	(addr, accepted, requests)
}

/// Reads until the request head ends (`\r\n\r\n`), the peer closes or a read fails.
async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
	let mut head = Vec::new();
	let mut buf = [0u8; 512];
	while head.len() < 4096 {
		match stream.read(&mut buf).await {
			Ok(0) | Err(_) => break,
			Ok(n) => {
				head.extend_from_slice(&buf[..n]);
				if head.windows(4).any(|w| w == b"\r\n\r\n".as_slice()) {
					break;
				}
			},
		}
	}
	head
}

// --- edge -----------------------------------------------------------------

/// Production-shaped config from serde defaults, plus the per-test overrides.
fn test_config(port: u16, upstream: SocketAddr) -> Config {
	let mut config = Config::default();
	config.bind.address = Ipv4Addr::LOCALHOST.to_string();
	config.bind.port = port;
	config.backend.upstreams = vec![upstream.to_string()];
	config.workers.count = 1;
	config.limits.handshake_timeout_secs = 2;
	config.limits.relay_idle_timeout_secs = 5;
	config.limits.max_connections_per_ip = 8;
	config.protocol.http.max_header_bytes = 4096;
	config.protocol.http.timeout_secs = 2;
	config
}

/// Running accept loop plus the shared state a test may pre-seed.
pub struct Edge {
	pub addr: SocketAddr,
	pub blacklist: Arc<Blacklist>,
	shutdown: watch::Sender<bool>,
	task: JoinHandle<anyhow::Result<()>>,
}

impl Edge {
	/// Stops the accept loop and waits for it, so no task outlives the test.
	pub async fn stop(mut self) -> anyhow::Result<()> {
		let _ = self.shutdown.send(true);
		match tokio::time::timeout(IO_BUDGET, &mut self.task).await {
			Ok(result) => result?,
			Err(_) => anyhow::bail!("edge accept loop did not stop within {IO_BUDGET:?}"),
		}
	}
}

impl Drop for Edge {
	fn drop(&mut self) {
		// Panic path: still wake the accept loop instead of leaking it.
		let _ = self.shutdown.send(true);
	}
}

/// Starts `listener::run`, retrying once if the throwaway port was stolen.
///
/// The port comes from binding `:0` and dropping the probe, so another process
/// can claim it before the edge binds; `run` then fails immediately and a fresh
/// port is used. The retry is bounded, never a loop.
pub async fn start_edge(upstream: SocketAddr, tune: impl Fn(&mut Config)) -> anyhow::Result<Edge> {
	let mut last_error = anyhow::anyhow!("edge listener did not bind");
	for _ in 0..2 {
		let port = free_port()?;
		let mut config = test_config(port, upstream);
		tune(&mut config);
		let config = Arc::new(config);
		let (gateway, blacklist, hook) = build_gateway(&config);
		let (shutdown, shutdown_rx) = watch::channel(false);
		let task = tokio::spawn(listener::run(config, gateway, hook, shutdown_rx));
		let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
		if wait_until_bound(addr, &task).await {
			return Ok(Edge {
				addr,
				blacklist,
				shutdown,
				task,
			});
		}
		let _ = shutdown.send(true);
		if let Ok(Err(error)) = task.await {
			last_error = error;
		}
	}
	Err(last_error.context("edge listener failed to bind a loopback port after two attempts"))
}

/// Binds `127.0.0.1:0`, reads the assigned port and releases it.
fn free_port() -> anyhow::Result<u16> {
	let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
	let port = probe.local_addr()?.port();
	drop(probe);
	Ok(port)
}

/// Waits until the edge owns `addr`. A second bind without `SO_REUSEPORT` fails
/// with `EADDRINUSE` exactly then, so no throwaway connection spends a
/// rate-limit token and pollutes the assertions.
async fn wait_until_bound(addr: SocketAddr, task: &JoinHandle<anyhow::Result<()>>) -> bool {
	let deadline = Instant::now() + READY_BUDGET;
	while Instant::now() < deadline {
		if task.is_finished() {
			return false;
		}
		if std::net::TcpListener::bind(addr).is_err() {
			return true;
		}
		tokio::time::sleep(Duration::from_millis(2)).await;
	}
	false
}

/// Assembles the edge state as `app::runtime` does, minus XDP, Redis and the
/// ClickHouse writer (all optional, all `None` here).
fn build_gateway(config: &Arc<Config>) -> (Arc<Gateway>, Arc<Blacklist>, Arc<TrafficHook>) {
	let blacklist = Arc::new(Blacklist::new());
	let reputation = Arc::new(IpReputation::new());
	let mut registry = ProtocolRegistry::new();
	registry.register(Box::new(HttpProtocolHandler::new(
		&config.protocol.http,
		&config.backend.upstreams,
	)));
	let gateway = Gateway::new(
		Arc::clone(config),
		Arc::new(RateLimiter::new(
			config.limits.rate_limit_pps,
			config.limits.rate_limit_burst,
		)),
		Arc::clone(&blacklist),
		Arc::new(Mutex::new(DifficultyAdjuster::with_floor(config.pow.difficulty))),
		Arc::new(HashSet::new()),
		Arc::clone(&reputation),
		None,
		None,
		Arc::new(AtomicU64::new(0)),
		Arc::new(registry),
		None,
	);
	// Auto-ban stays at its default (disabled), so a drop cannot leak a ban into
	// a later assertion.
	let hook = Arc::new(TrafficHook::new(
		reputation,
		Arc::clone(&blacklist),
		config.detect.autoban.clone(),
		config.ban.ban_duration_secs,
	));
	(Arc::new(gateway), blacklist, hook)
}

// --- client ---------------------------------------------------------------

/// Reads until the peer closes; a reset also means "closed, no extra data".
pub async fn read_to_close(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
	let mut out = Vec::new();
	let mut buf = [0u8; 512];
	loop {
		match stream.read(&mut buf).await {
			Ok(0) => return Ok(out),
			Ok(n) => {
				out.extend_from_slice(&buf[..n]);
				if out.len() > MAX_REPLY_BYTES {
					anyhow::bail!("peer kept sending past {MAX_REPLY_BYTES} bytes");
				}
			},
			Err(error) if error.kind() == ErrorKind::ConnectionReset => return Ok(out),
			Err(error) => return Err(error.into()),
		}
	}
}

/// Sends `payload` on a fresh connection and returns everything until the close.
pub async fn exchange(addr: SocketAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
	let mut client = TcpStream::connect(addr).await?;
	client.write_all(payload).await?;
	tokio::time::timeout(IO_BUDGET, read_to_close(&mut client)).await?
}

/// Best-effort request on a fresh connection: a rejected peer may already be
/// gone, so write errors are ignored. The reply is what the caller asserts on —
/// a gate that let the request through would return the upstream response.
pub async fn rejected_reply(addr: SocketAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
	let mut client = TcpStream::connect(addr).await?;
	let _ = client.write_all(payload).await;
	tokio::time::timeout(IO_BUDGET, read_to_close(&mut client)).await?
}
