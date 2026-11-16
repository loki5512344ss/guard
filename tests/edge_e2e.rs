//! End-to-end tests of the real edge connection path over loopback.
//!
//! A TCP client is driven through the production accept loop (`engine::listener`)
//! and pipeline (`engine::tunnel::Gateway`) to a real upstream socket on
//! `127.0.0.1`: framing, the PoW gate, the admission filters and the relay are
//! exercised as one system, without root and without any external network.
#![cfg(feature = "protocol-http")]

#[path = "edge_e2e/support.rs"]
mod support;

use rampart::engine::challenge::solve;
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::{
	IO_BUDGET, POW_DIFFICULTY, REQUEST, RESPONSE, exchange, read_to_close, rejected_reply, start_edge, start_upstream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Reads one newline-terminated line (the PoW challenge).
async fn read_line(stream: &mut TcpStream) -> anyhow::Result<String> {
	let mut line = Vec::new();
	for _ in 0..128 {
		let mut byte = [0u8; 1];
		if stream.read(&mut byte).await? == 0 || byte[0] == b'\n' {
			break;
		}
		line.push(byte[0]);
	}
	Ok(String::from_utf8_lossy(&line).trim().to_string())
}

fn hash_satisfies(challenge: &str, nonce: &str, difficulty: u8) -> bool {
	let digest = Sha256::digest(format!("{challenge}{nonce}").as_bytes());
	hex::encode(digest)
		.as_bytes()
		.iter()
		.take(difficulty as usize)
		.all(|byte| byte.is_ascii_digit() && *byte <= b'3')
}

/// Finds a nonce the gate must reject; the caller re-checks the result.
fn invalid_nonce(challenge: &str, difficulty: u8) -> String {
	// At difficulty 2 about fifteen of sixteen candidates fail, so this stops
	// within a handful of iterations.
	for candidate in 0u64..1_000_000 {
		let nonce = candidate.to_string();
		if !hash_satisfies(challenge, &nonce, difficulty) {
			return nonce;
		}
	}
	"0".to_string()
}

#[tokio::test]
async fn plain_http_request_is_proxied_to_the_upstream() -> anyhow::Result<()> {
	let (upstream, accepted, seen) = start_upstream().await;
	let edge = start_edge(upstream, |_| {}).await?;

	let response = exchange(edge.addr, REQUEST).await?;
	assert_eq!(response.as_slice(), RESPONSE);
	assert_eq!(accepted.load(Ordering::SeqCst), 1);
	assert_eq!(*seen.lock().expect("requests lock"), vec![REQUEST.to_vec()]);

	edge.stop().await
}

#[tokio::test]
async fn pow_gate_accepts_a_solved_challenge_and_drops_a_wrong_nonce() -> anyhow::Result<()> {
	let (upstream, accepted, seen) = start_upstream().await;
	let edge = start_edge(upstream, |config| {
		config.pow.enabled = true;
		config.pow.difficulty = POW_DIFFICULTY;
	})
	.await?;

	let mut client = TcpStream::connect(edge.addr).await?;
	let challenge = tokio::time::timeout(IO_BUDGET, read_line(&mut client)).await??;
	let nonce = solve(&challenge, POW_DIFFICULTY)
		.ok_or_else(|| anyhow::anyhow!("no solution found for challenge {challenge}"))?;
	// Coalesced write: the PoW reader must consume exactly the nonce line and
	// leave the HTTP head buffered for the handshake that runs next.
	let mut payload = format!("{nonce}\r\n").into_bytes();
	payload.extend_from_slice(REQUEST);
	client.write_all(&payload).await?;
	let response = tokio::time::timeout(IO_BUDGET, read_to_close(&mut client)).await??;
	assert_eq!(response.as_slice(), RESPONSE);
	assert_eq!(accepted.load(Ordering::SeqCst), 1);

	let mut hostile = TcpStream::connect(edge.addr).await?;
	let challenge = tokio::time::timeout(IO_BUDGET, read_line(&mut hostile)).await??;
	let wrong = invalid_nonce(&challenge, POW_DIFFICULTY);
	assert!(!hash_satisfies(&challenge, &wrong, POW_DIFFICULTY));
	// Send the request after the wrong nonce: if the gate accepted it, the head
	// would be buffered and proxied, and the upstream response would come back.
	let mut payload = format!("{wrong}\r\n").into_bytes();
	payload.extend_from_slice(REQUEST);
	let _ = hostile.write_all(&payload).await;
	let reply = tokio::time::timeout(IO_BUDGET, read_to_close(&mut hostile)).await??;
	assert!(reply.is_empty(), "a wrong nonce must be dropped, got {reply:?}");
	assert_eq!(
		accepted.load(Ordering::SeqCst),
		1,
		"a failed PoW must not reach the upstream"
	);
	assert_eq!(seen.lock().expect("requests lock").len(), 1);

	edge.stop().await
}

#[tokio::test]
async fn rate_limit_drops_the_second_connection_before_the_upstream() -> anyhow::Result<()> {
	let (upstream, accepted, _seen) = start_upstream().await;
	let edge = start_edge(upstream, |config| {
		// One token, practically no refill: the second connection is over budget.
		config.limits.rate_limit_pps = 0.001;
		config.limits.rate_limit_burst = 1.0;
	})
	.await?;

	let response = exchange(edge.addr, REQUEST).await?;
	assert_eq!(response.as_slice(), RESPONSE);
	assert_eq!(accepted.load(Ordering::SeqCst), 1);

	let reply = rejected_reply(edge.addr, REQUEST).await?;
	assert!(
		reply.is_empty(),
		"rate-limited connection must not be proxied, got {reply:?}"
	);
	// EOF above means the reject path already ran; it precedes the upstream
	// stage, so a second accept cannot appear afterwards.
	assert_eq!(accepted.load(Ordering::SeqCst), 1);

	edge.stop().await
}

#[tokio::test]
async fn blacklisted_client_never_reaches_the_upstream() -> anyhow::Result<()> {
	let (upstream, accepted, seen) = start_upstream().await;
	let edge = start_edge(upstream, |_| {}).await?;
	edge.blacklist
		.add(Ipv4Addr::LOCALHOST.into(), Duration::from_secs(60), "edge_e2e");

	let reply = rejected_reply(edge.addr, REQUEST).await?;
	assert!(reply.is_empty(), "a banned client must be dropped, got {reply:?}");
	assert_eq!(accepted.load(Ordering::SeqCst), 0);
	assert!(seen.lock().expect("requests lock").is_empty());

	edge.stop().await
}
