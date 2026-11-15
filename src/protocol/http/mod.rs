//! HTTP/1.1 protocol handler (feature `protocol-http`).
//!
//! Owns the first plugin implementation of [`ProtocolHandler`]: it reads the
//! request head incrementally (TCP arrives in fragments), evaluates it against
//! the policy from the `[protocol.http]` section and returns the upstream to
//! tunnel to.
//!
//! The bytes already consumed for the head are forwarded to the upstream as the
//! initial tunnel payload, so the request is not lost.

mod parser;

use crate::config::HttpProtocolConfig;
use crate::protocol::{HandshakeResult, ProtocolHandler, Upstream};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// HTTP/1.1 handler: verdict `Allow` tunnels to the upstream, `Reject` drops.
pub struct HttpProtocolHandler {
	policy: parser::Policy,
	timeout: Duration,
	upstream: String,
}

impl HttpProtocolHandler {
	/// Builds the handler from the `[protocol.http]` config and the upstream list.
	///
	/// The first upstream wins; falling back to `127.0.0.1:80` keeps the handler
	/// usable in tests where the list is empty.
	#[must_use]
	pub fn new(http: &HttpProtocolConfig, upstreams: &[String]) -> Self {
		Self {
			policy: parser::Policy {
				max_header_bytes: http.max_header_bytes,
				blocked_paths: http.blocked_paths.clone(),
				require_user_agent: http.require_user_agent,
			},
			timeout: Duration::from_secs(http.timeout_secs),
			upstream: upstreams.first().cloned().unwrap_or_else(|| "127.0.0.1:80".to_string()),
		}
	}

	/// Accumulates the request head without re-reading an already scanned prefix.
	///
	/// # Errors
	/// Times out, the client closes, `max_header_bytes` is exceeded, or the
	/// socket reports an I/O error.
	async fn read_head(&self, stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
		let limit = self.policy.max_header_bytes;
		if limit == 0 {
			anyhow::bail!("protocol.http.max_header_bytes must be positive");
		}
		let mut buf = Vec::with_capacity(limit);
		let accumulate = async {
			loop {
				if parser::scan_head(&buf).is_some() {
					return Ok(buf);
				}
				if buf.len() >= limit {
					anyhow::bail!("request head exceeds {limit} bytes");
				}
				let mut byte = [0u8; 1];
				stream.read_exact(&mut byte).await?;
				buf.push(byte[0]);
			}
		};
		match tokio::time::timeout(self.timeout, accumulate).await {
			Ok(result) => result,
			Err(_) => anyhow::bail!("timed out reading request head"),
		}
	}
}

impl ProtocolHandler for HttpProtocolHandler {
	fn name(&self) -> &'static str {
		"http"
	}

	fn handshake<'a>(
		&'a self,
		stream: &'a mut TcpStream,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<HandshakeResult>> + Send + 'a>> {
		Box::pin(async move {
			let head = self.read_head(stream).await?;
			match parser::evaluate(&head, &self.policy) {
				parser::Verdict::Allow { .. } => Ok(HandshakeResult::with_initial_data(
					Upstream::new(self.upstream.clone()),
					head,
				)),
				parser::Verdict::Reject { reason } => Err(anyhow::anyhow!("http: {reason}")),
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn zero_limit_fails_fast_without_io() {
		let config = HttpProtocolConfig::default();
		let mut broken = config.clone();
		broken.max_header_bytes = 0;
		let handler = HttpProtocolHandler::new(&broken, &[]);
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let client = tokio::net::TcpStream::connect(listener.local_addr().expect("addr"))
			.await
			.expect("connect");
		let (mut server, _) = listener.accept().await.expect("accept");
		drop(listener);
		assert!(handler.read_head(&mut server).await.is_err());
		drop(client);
	}
}
