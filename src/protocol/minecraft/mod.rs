//! Minecraft Java TCP handshake validation (feature `protocol-minecraft`).
//!
//! Reads the handshake and the first status/login frame, validates both against
//! [`policy::Policy`] and replays the raw bytes to the upstream unchanged.

pub mod parser;
pub mod policy;
pub mod reason;
pub mod state;

use crate::config::MinecraftProtocolConfig;
use crate::metrics;
use crate::protocol::{HandshakeResult, ProtocolHandler, Upstream};
use policy::{Policy, versions};
use reason::Reason;
use state::Session;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;

pub struct MinecraftProtocolHandler {
	upstream: String,
	policy: Policy,
	timeout: Duration,
}

impl MinecraftProtocolHandler {
	#[must_use]
	pub fn new(config: &MinecraftProtocolConfig, upstreams: &[String]) -> Self {
		Self {
			// Config validation requires exactly one backend when this handler is enabled.
			upstream: upstreams.first().cloned().unwrap_or_default(),
			policy: Policy::from_config(config),
			timeout: Duration::from_secs(config.timeout_secs),
		}
	}

	async fn read_frames<R: AsyncRead + Unpin>(&self, stream: &mut R) -> Result<Vec<u8>, Reason> {
		let mut session = Session::new(&self.policy);
		let mut raw = Vec::new();
		// Handshake, then the status request or login-start that follows at once.
		for _ in 0..2 {
			let (frame, prefix_len) = read_frame(stream, session.frame_cap()).await?;
			let step = session.feed(&frame[prefix_len..]);
			// Count the version before the verdict: refused versions are the
			// interesting ones on the dashboard.
			if let Some(version) = session.take_parsed_version() {
				metrics::MC_PROTOCOL_VERSION_TOTAL
					.with_label_values(&[versions::label(version)])
					.inc();
			}
			step?;
			raw.extend_from_slice(&frame);
		}
		Ok(raw)
	}
}

/// Reads one length-prefixed frame, enforcing `cap` as soon as the length
/// VarInt is decoded so oversized bodies are never buffered.
///
/// Returns the raw bytes (prefix included) and the prefix length.
///
/// # Errors
/// Returns the [`Reason`] for a bad length, an oversized frame or an I/O error.
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R, cap: usize) -> Result<(Vec<u8>, usize), Reason> {
	let mut frame = Vec::with_capacity(32);
	for _ in 0..5 {
		let mut byte = [0u8; 1];
		stream.read_exact(&mut byte).await.map_err(|_| Reason::Io)?;
		frame.push(byte[0]);
		if byte[0] & 0x80 == 0 {
			break;
		}
	}
	let (frame_len, prefix_len) = parser::decode_frame_length(&frame)?;
	if frame_len == 0 {
		return Err(Reason::FrameLength);
	}
	if frame_len > cap {
		return Err(Reason::FrameTooLarge);
	}
	frame.resize(prefix_len + frame_len, 0);
	stream
		.read_exact(&mut frame[prefix_len..])
		.await
		.map_err(|_| Reason::Io)?;
	Ok((frame, prefix_len))
}

fn record(reason: Reason) {
	metrics::MC_HANDSHAKE_TOTAL
		.with_label_values(&[reason.result(), reason.as_str()])
		.inc();
}

impl ProtocolHandler for MinecraftProtocolHandler {
	fn name(&self) -> &'static str {
		"minecraft"
	}

	fn handshake<'a>(
		&'a self,
		stream: &'a mut TcpStream,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<HandshakeResult>> + Send + 'a>> {
		Box::pin(async move {
			let outcome = tokio::time::timeout(self.timeout, self.read_frames(stream))
				.await
				.unwrap_or(Err(Reason::Timeout));
			record(outcome.as_ref().err().copied().unwrap_or(Reason::Ok));
			let frame = outcome.map_err(|reason| anyhow::anyhow!("Minecraft handshake rejected: {reason}"))?;
			Ok(HandshakeResult::with_initial_data(
				Upstream::new(self.upstream.clone()),
				frame,
			))
		})
	}
}
