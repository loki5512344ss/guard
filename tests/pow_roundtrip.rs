//! PoW roundtrip tests: solver output must satisfy the verifier, replays and
//! garbage must not, and the nonce exchange must survive TCP framing quirks.

use rampart::engine::challenge::{Challenge, enforce, solve};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, sleep};

/// Fixed 32-byte token: sha256(hex(token) || "garbage") starts with "ebc1",
/// so "garbage" provably fails the difficulty-2 check (first two hex chars
/// must be in "0123"). A random token made this flaky with probability 1/16
/// per run, since any digest lands in the accepted prefix with p=(4/16)^2.
const FIXED_TOKEN: [u8; 32] = *b"rampart-pow-fixed-token-test-v1!";

const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

#[test]
fn solver_output_passes_verifier() {
	let mut challenge = Challenge::generate(3);
	let nonce = solve(&challenge.challenge_string(), 3).expect("solver must find nonce for difficulty 3");
	assert!(challenge.verify(&nonce));
}

#[test]
fn verifier_rejects_garbage_and_replay() {
	let mut challenge = Challenge::with_token(FIXED_TOKEN, 2);
	assert!(!challenge.verify("garbage"));

	let nonce = solve(&challenge.challenge_string(), 2).expect("solved");
	assert!(challenge.verify(&nonce), "first use passes");
	assert!(!challenge.verify(&nonce), "replay is rejected");
}

#[test]
fn verifier_rejects_oversized_nonce() {
	let mut challenge = Challenge::with_token(FIXED_TOKEN, 2);
	let big_nonce = "0".repeat(65);
	assert!(!challenge.verify(&big_nonce));
}

/// Connects a server/client loopback pair; the first value is the server side.
async fn pair() -> (TcpStream, TcpStream) {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
	let addr = listener.local_addr().expect("local address");
	let accept = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
	let client = TcpStream::connect(addr).await.expect("connect loopback");
	let server = accept.await.expect("accept task");
	(server, client)
}

/// Reads one newline-terminated server line byte by byte.
async fn read_line(stream: &mut TcpStream) -> String {
	let mut line = Vec::new();
	loop {
		let mut byte = [0u8; 1];
		let n = stream.read(&mut byte).await.expect("read line");
		if n == 0 || byte[0] == b'\n' {
			break;
		}
		line.push(byte[0]);
	}
	String::from_utf8(line).expect("challenge is hex")
}

#[tokio::test]
async fn nonce_coalesced_with_handshake_is_preserved() {
	let (mut server, mut client) = pair().await;
	let server_task = tokio::spawn(async move {
		let passed = enforce(&mut server, PEER, 2).await.expect("enforce");
		let mut tail = [0u8; 5];
		server
			.read_exact(&mut tail)
			.await
			.expect("handshake bytes after the nonce");
		(passed, tail)
	});

	let challenge = read_line(&mut client).await;
	let nonce = solve(&challenge, 2).expect("solved");
	// One write: nonce delimiter and the first handshake bytes in one segment.
	client
		.write_all(format!("{nonce}\nHELLO").as_bytes())
		.await
		.expect("write nonce and handshake");
	let (passed, tail) = server_task.await.expect("server task");
	assert!(passed);
	assert_eq!(&tail, b"HELLO", "bytes after the delimiter must reach the handshake");
}

#[tokio::test]
async fn nonce_split_across_segments_is_accepted() {
	let (mut server, mut client) = pair().await;
	let server_task = tokio::spawn(async move { enforce(&mut server, PEER, 2).await.expect("enforce") });

	let challenge = read_line(&mut client).await;
	let nonce = solve(&challenge, 2).expect("solved");
	let split = nonce.len() / 2;
	client
		.write_all(&nonce.as_bytes()[..split])
		.await
		.expect("first segment");
	sleep(Duration::from_millis(20)).await;
	client
		.write_all(&nonce.as_bytes()[split..])
		.await
		.expect("second segment");
	client.write_all(b"\n").await.expect("delimiter");

	assert!(server_task.await.expect("server task"));
}

#[tokio::test]
async fn eof_terminated_nonce_is_still_accepted() {
	let (mut server, mut client) = pair().await;
	let server_task = tokio::spawn(async move { enforce(&mut server, PEER, 2).await.expect("enforce") });

	let challenge = read_line(&mut client).await;
	let nonce = solve(&challenge, 2).expect("solved");
	client.write_all(nonce.as_bytes()).await.expect("write nonce");
	client.shutdown().await.expect("close write half");

	assert!(server_task.await.expect("server task"));
}

#[tokio::test]
async fn oversized_nonce_without_delimiter_is_rejected() {
	let (mut server, mut client) = pair().await;
	let server_task = tokio::spawn(async move { enforce(&mut server, PEER, 2).await.expect("enforce") });

	let _challenge = read_line(&mut client).await;
	client.write_all(&[b'0'; 65]).await.expect("oversized nonce");
	assert!(!server_task.await.expect("server task"));
}
