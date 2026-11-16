//! Connection-path limits: filter order around the PoW gate, the whitelist
//! exemption from bans, accept-loop backoff and the idle relay timeout.

use rampart::config::Config;
use rampart::engine::challenge::DifficultyAdjuster;
use rampart::engine::listener::AcceptBackoff;
use rampart::engine::tunnel::Gateway;
use rampart::filter::blacklist::Blacklist;
use rampart::filter::rate_limit::RateLimiter;
use rampart::protocol::ProtocolRegistry;
use rampart::traffic::reputation::IpReputation;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Linux `EMFILE` (too many open files), the errno behind the accept spin.
#[cfg(target_os = "linux")]
const EMFILE: i32 = 24;

/// Builds a gateway with the cheap collaborators and no XDP/ClickHouse/protocol
/// handler, so every stage past the filters fails fast.
fn test_gateway(config: Config, whitelist: HashSet<IpAddr>) -> Arc<Gateway> {
	Arc::new(Gateway::new(
		Arc::new(config.clone()),
		Arc::new(RateLimiter::new(
			config.limits.rate_limit_pps,
			config.limits.rate_limit_burst,
		)),
		Arc::new(Blacklist::new()),
		Arc::new(Mutex::new(DifficultyAdjuster::default())),
		Arc::new(whitelist),
		Arc::new(IpReputation::new()),
		None,
		None,
		Arc::new(AtomicU64::new(0)),
		Arc::new(ProtocolRegistry::new()),
		None,
	))
}

/// Returns a connected client/server pair over loopback.
async fn loopback() -> (TcpStream, TcpStream) {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
	let addr = listener.local_addr().expect("local addr");
	let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
	(client.expect("connect"), accepted.expect("accept").0)
}

/// Reads one newline-terminated line without blocking past `limit`.
async fn read_line(stream: &mut TcpStream, limit: Duration) -> io::Result<Vec<u8>> {
	let mut line = Vec::new();
	let mut byte = [0u8; 1];
	loop {
		let read = tokio::time::timeout(limit, stream.read(&mut byte)).await??;
		if read == 0 || byte[0] == b'\n' {
			return Ok(line);
		}
		line.push(byte[0]);
	}
}

/// A rate-limited client must be rejected before the PoW exchange starts, so
/// no challenge is written and the task never waits for a solver.
#[tokio::test]
async fn rate_limit_runs_before_pow() {
	let mut config = Config::default();
	config.limits.rate_limit_pps = 0.0;
	config.limits.rate_limit_burst = 0.0;
	config.pow.enabled = true;
	config.pow.difficulty = 1;
	let gateway = test_gateway(config, HashSet::new());

	let (mut client, server) = loopback().await;
	let peer = SocketAddr::from(([203, 0, 113, 7], 51_000));
	let started = tokio::time::Instant::now();
	let outcome = gateway.handle(server, peer).await;
	assert!(outcome.result.is_ok(), "a rate-limited connection is dropped silently");
	assert!(
		started.elapsed() < Duration::from_millis(500),
		"rate limit must short-circuit the PoW gate"
	);

	let mut scratch = [0u8; 64];
	let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut scratch))
		.await
		.expect("read must not hang")
		.expect("read must succeed");
	assert_eq!(read, 0, "a rate-limited client must not receive a PoW challenge");
}

/// A client that never answers PoW must still burn its own token, so the next
/// attempt from the same source is rate limited instead of parked in PoW.
#[tokio::test]
async fn silent_pow_client_exhausts_budget_for_next_attempt() {
	let mut config = Config::default();
	config.limits.rate_limit_pps = 0.0;
	config.limits.rate_limit_burst = 1.0;
	config.pow.enabled = true;
	config.pow.difficulty = 1;
	let gateway = test_gateway(config, HashSet::new());
	let peer = SocketAddr::from(([203, 0, 113, 8], 51_001));

	let (mut first_client, first_server) = loopback().await;
	let first_gateway = Arc::clone(&gateway);
	let first = tokio::spawn(async move { first_gateway.handle(first_server, peer).await.result });

	let challenge = read_line(&mut first_client, Duration::from_secs(2))
		.await
		.expect("first attempt must reach the PoW gate");
	assert!(!challenge.is_empty(), "PoW gate issues a challenge line");

	let (mut second_client, second_server) = loopback().await;
	let started = tokio::time::Instant::now();
	let outcome = gateway.handle(second_server, peer).await;
	assert!(outcome.result.is_ok());
	assert!(
		started.elapsed() < Duration::from_millis(500),
		"second attempt must be rejected by the rate limiter, not queued behind PoW"
	);
	let mut scratch = [0u8; 1];
	let read = second_client.read(&mut scratch).await.expect("read must succeed");
	assert_eq!(read, 0, "second attempt is closed without a challenge");

	first.abort();
}

/// A whitelisted source stays exempt from the rate limiter and is never
/// auto-banned, even after enough abuse to drive reputation below the ban
/// threshold, and an existing ban entry is ignored for it.
#[tokio::test]
async fn whitelisted_peer_is_exempt_from_rate_limit_and_ban() {
	let mut config = Config::default();
	config.limits.rate_limit_pps = 0.0;
	config.limits.rate_limit_burst = 0.0;
	let trusted = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
	let gateway = test_gateway(config, HashSet::from([trusted]));
	let peer = SocketAddr::new(trusted, 51_002);

	for _ in 0..8 {
		let (_client, server) = loopback().await;
		let outcome = gateway.handle(server, peer).await;
		assert!(
			outcome.result.is_err(),
			"a trusted peer must pass every filter and reach the (empty) registry"
		);
	}
	assert!(
		!gateway.blacklist.is_blocked(trusted),
		"a trusted peer must never be banned"
	);
	assert_eq!(
		gateway.reputation.score(trusted),
		0,
		"trusted traffic is not scored as abusive"
	);

	gateway
		.blacklist
		.add(trusted, Duration::from_secs(60), "stale-test-ban");
	let (_client, server) = loopback().await;
	assert!(
		gateway.handle(server, peer).await.result.is_err(),
		"the whitelist overrides an existing blacklist entry"
	);
}

/// The untrusted counterpart: repeated rate-limit hits drive reputation below
/// the threshold and the peer is banned.
#[tokio::test]
async fn repeated_rate_limit_hits_auto_ban_untrusted_peer() {
	let mut config = Config::default();
	config.limits.rate_limit_pps = 0.0;
	config.limits.rate_limit_burst = 0.0;
	let gateway = test_gateway(config, HashSet::new());
	let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
	let peer = SocketAddr::new(peer_ip, 51_003);

	for _ in 0..5 {
		let (_client, server) = loopback().await;
		assert!(
			gateway.handle(server, peer).await.result.is_ok(),
			"a rate-limited connection is dropped silently"
		);
	}
	assert!(
		gateway.blacklist.is_blocked(peer_ip),
		"reputation below -40 must ban the peer"
	);
}

/// Backoff doubles from 50ms to a 500ms cap and restarts after a successful
/// accept.
#[cfg(target_os = "linux")]
#[test]
fn accept_backoff_grows_caps_and_resets() {
	let mut backoff = AcceptBackoff::new();
	let error = io::Error::from_raw_os_error(EMFILE);
	let expected = [50u64, 100, 200, 400, 500, 500];
	for milliseconds in expected {
		assert_eq!(backoff.delay(&error), Some(Duration::from_millis(milliseconds)));
	}
	backoff.reset();
	assert_eq!(
		backoff.delay(&error),
		Some(Duration::from_millis(50)),
		"reset after a successful accept restarts at the minimum"
	);
}

/// Peer-abort errors need no delay: retrying immediately is correct there.
#[test]
fn accept_backoff_skips_non_transient_errors() {
	let mut backoff = AcceptBackoff::new();
	assert_eq!(backoff.delay(&io::Error::from(io::ErrorKind::ConnectionAborted)), None);
	assert_eq!(backoff.delay(&io::Error::from(io::ErrorKind::InvalidInput)), None);
}

/// Error logging is rate limited: first failure and then one per window.
#[cfg(target_os = "linux")]
#[test]
fn accept_backoff_rate_limits_error_logs() {
	let mut backoff = AcceptBackoff::new();
	let error = io::Error::from_raw_os_error(EMFILE);
	assert!(backoff.delay(&error).is_some());
	assert!(
		backoff.should_log(),
		"the first failure is always logged at error level"
	);
	assert!(backoff.delay(&error).is_some());
	assert!(!backoff.should_log(), "repeated failures stay at debug level");
	for _ in 2..32 {
		assert!(backoff.delay(&error).is_some());
	}
	assert!(backoff.should_log(), "a periodic reminder keeps the condition visible");
}

/// The loop must spend real time sleeping instead of spinning. `tokio`'s
/// `test-util` feature is not compiled in, so this uses the real minimum
/// backoff (50ms) with a short iteration count.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn accept_backoff_sleeps_instead_of_spinning() {
	let mut backoff = AcceptBackoff::new();
	let error = io::Error::from_raw_os_error(EMFILE);
	let started = tokio::time::Instant::now();
	let mut slept = Duration::ZERO;
	for _ in 0..3 {
		let delay = backoff.delay(&error).expect("transient error must back off");
		assert!(!delay.is_zero(), "a failed accept must yield a non-zero delay");
		tokio::time::sleep(delay).await;
		slept += delay;
	}
	assert!(slept >= Duration::from_millis(350), "50+100+200ms of mandatory backoff");
	assert!(
		started.elapsed() >= slept,
		"the loop cannot advance faster than its backoff"
	);
}

/// A silent pair is closed by the relay idle timeout instead of pinning two
/// descriptors forever.
#[tokio::test]
async fn relay_idle_timeout_closes_silent_pair() {
	let gateway = test_gateway(Config::default(), HashSet::new());
	let (_client_peer, gateway_side) = loopback().await;
	let (backend_gateway_side, _backend_peer) = loopback().await;

	let idle = Duration::from_millis(60);
	let started = tokio::time::Instant::now();
	let result = tokio::time::timeout(
		Duration::from_secs(2),
		gateway.relay_with_idle(gateway_side, backend_gateway_side, idle),
	)
	.await
	.expect("relay must be cut by the idle timeout, not hang");
	assert!(result.is_err(), "silent relay must be cut by the idle timeout");
	assert!(started.elapsed() >= idle, "the idle budget must actually elapse");
}

/// The idle budget must not break normal forwarding in either direction.
#[tokio::test]
async fn relay_forwards_bytes_in_both_directions() {
	let gateway = test_gateway(Config::default(), HashSet::new());
	let (mut client_peer, client_side) = loopback().await;
	let (backend_side, mut backend_peer) = loopback().await;

	let relay = tokio::spawn(async move {
		gateway
			.relay_with_idle(client_side, backend_side, Duration::from_secs(5))
			.await
	});

	client_peer.write_all(b"ping").await.expect("write to relay");
	let mut buffer = [0u8; 4];
	backend_peer.read_exact(&mut buffer).await.expect("backend read");
	assert_eq!(&buffer, b"ping");

	backend_peer.write_all(b"pong").await.expect("write from backend");
	client_peer.read_exact(&mut buffer).await.expect("client read");
	assert_eq!(&buffer, b"pong");

	drop(client_peer);
	assert!(
		relay.await.expect("relay task").is_ok(),
		"clean half-close is not an error"
	);
}
