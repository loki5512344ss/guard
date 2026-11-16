//! Universal SHA-256 hashcash challenge generation, solver and verifier.

use rand::Rng;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CHALLENGE_TTL_SECS: u64 = 30;
const MAX_NONCE_LEN: usize = 64;
const ALLOWED_HEX_PREFIX: [u8; 4] = *b"0123";

/// Maximum time a peer gets to read the challenge and return a nonce.
const NONCE_TIMEOUT: Duration = Duration::from_secs(10);

/// Active PoW challenge issued to one connection.
pub struct Challenge {
	token: [u8; 32],
	created_at: Instant,
	difficulty: u8,
	used: bool,
}

impl Challenge {
	#[must_use]
	pub fn generate(difficulty: u8) -> Self {
		let mut token = [0u8; 32];
		rand::rng().fill_bytes(&mut token);
		Self {
			token,
			created_at: Instant::now(),
			difficulty,
			used: false,
		}
	}

	/// Builds a challenge with an explicit token.
	///
	/// Intended for deterministic tests, where a random token makes the outcome
	/// hard to predict.
	#[must_use]
	pub fn with_token(token: [u8; 32], difficulty: u8) -> Self {
		Self {
			token,
			created_at: Instant::now(),
			difficulty,
			used: false,
		}
	}

	#[must_use]
	pub fn is_expired(&self) -> bool {
		self.created_at.elapsed().as_secs() >= CHALLENGE_TTL_SECS
	}

	#[must_use]
	pub fn challenge_string(&self) -> String {
		hex::encode(self.token)
	}

	/// Verifies `nonce` and marks the challenge as used on success.
	///
	/// A challenge is single-use and expires after `CHALLENGE_TTL_SECS`.
	#[must_use]
	pub fn verify(&mut self, nonce: &str) -> bool {
		if self.used || self.is_expired() || nonce.len() > MAX_NONCE_LEN {
			return false;
		}

		let input = format!("{}{nonce}", self.challenge_string());
		let hash = Sha256::digest(input.as_bytes());
		let hex_hash = hex::encode(hash);
		let d = self.difficulty as usize;
		let ok = hex_hash.as_bytes().iter().take(d).all(|c| {
			let r = c.ct_eq(&ALLOWED_HEX_PREFIX[0])
				| c.ct_eq(&ALLOWED_HEX_PREFIX[1])
				| c.ct_eq(&ALLOWED_HEX_PREFIX[2])
				| c.ct_eq(&ALLOWED_HEX_PREFIX[3]);
			r.unwrap_u8() == 1
		});
		if ok {
			self.used = true;
		}
		ok
	}
}

/// Brute-force hashcash solver used by clients and tests.
#[must_use]
pub fn solve(challenge: &str, difficulty: u8) -> Option<String> {
	let d = difficulty as usize;
	for nonce in 0..u64::MAX {
		let nonce_str = nonce.to_string();
		let input = format!("{challenge}{nonce_str}");
		let hash = Sha256::digest(input.as_bytes());
		let hex_hash = hex::encode(hash);
		if hex_hash
			.as_bytes()
			.iter()
			.take(d)
			.all(|c| ALLOWED_HEX_PREFIX.contains(c))
		{
			return Some(nonce_str);
		}
	}
	None
}

/// Runs the textual PoW gate on `stream`: issues a challenge and checks the
/// answer.
///
/// Wire format: the server writes the hex challenge followed by `\n`; the
/// client answers with the nonce followed by `\n`. A reply terminated by EOF is
/// also accepted for compatibility with clients that close their write half
/// after sending the nonce. Anything the client sent after the delimiter stays
/// in the socket buffer and is seen by the protocol handshake that runs next.
///
/// # Errors
/// Only I/O failures are reported; a wrong or missing solution is `Ok(false)`.
pub async fn enforce(stream: &mut TcpStream, peer_ip: IpAddr, difficulty: u8) -> anyhow::Result<bool> {
	if difficulty == 0 {
		tracing::debug!("pow: difficulty 0, skipping for {peer_ip}");
		return Ok(true);
	}

	let mut challenge = Challenge::generate(difficulty);
	let line = format!("{}\n", challenge.challenge_string());
	timeout(NONCE_TIMEOUT, stream.write_all(line.as_bytes())).await??;

	let nonce = match timeout(NONCE_TIMEOUT, read_nonce_line(stream)).await {
		Ok(result) => result?,
		Err(_) => {
			tracing::debug!("pow: nonce read timed out for {peer_ip}");
			return Ok(false);
		},
	};
	let Some(nonce) = nonce else {
		tracing::debug!("pow: invalid or missing nonce from {peer_ip}");
		return Ok(false);
	};

	let valid = challenge.verify(&nonce);
	tracing::debug!(
		"pow: verification {} for {peer_ip}",
		if valid { "passed" } else { "failed" }
	);
	Ok(valid)
}

/// Reads a newline-terminated nonce without consuming the bytes that follow the
/// delimiter.
///
/// `peek` inspects the buffer first; only the nonce and its `\n` are consumed, so
/// a client that coalesces the nonce and the handshake into one TCP segment is
/// not truncated. A nonce split across segments is accumulated until the
/// delimiter arrives or the connection reports EOF.
///
/// Returns `None` for an empty, oversized or non-UTF-8 reply.
async fn read_nonce_line(stream: &mut TcpStream) -> anyhow::Result<Option<String>> {
	let mut buf = [0u8; MAX_NONCE_LEN + 1];
	let mut nonce = Vec::with_capacity(MAX_NONCE_LEN);
	loop {
		let n = stream.peek(&mut buf).await?;
		if n == 0 {
			// EOF without a delimiter: accept the bytes received so far.
			break;
		}
		if let Some(pos) = buf[..n].iter().position(|&b| b == b'\n') {
			if nonce.len() + pos > MAX_NONCE_LEN {
				return Ok(None);
			}
			nonce.extend_from_slice(&buf[..pos]);
			// Consume exactly the nonce line; the handshake bytes stay buffered.
			stream.read_exact(&mut buf[..=pos]).await?;
			break;
		}
		if nonce.len() + n > MAX_NONCE_LEN {
			return Ok(None);
		}
		stream.read_exact(&mut buf[..n]).await?;
		nonce.extend_from_slice(&buf[..n]);
	}

	let text = std::str::from_utf8(&nonce).unwrap_or("").trim();
	if text.is_empty() || text.len() > MAX_NONCE_LEN {
		return Ok(None);
	}
	Ok(Some(text.to_string()))
}
