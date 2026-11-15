//! Protocol handler contracts.
//!
//! Owns the [`ProtocolHandler`] trait implemented by L7 plugins and the
//! [`ProtocolRegistry`] that selects the active handler at startup. Concrete
//! handlers live behind features (`protocol-http`, `protocol-minecraft`).

#[cfg(feature = "protocol-http")]
pub mod http;
#[cfg(feature = "protocol-minecraft")]
pub mod minecraft;

use std::future::Future;
use std::pin::Pin;
use tokio::net::TcpStream;

/// Result of a successful protocol handshake: the upstream backend address the
/// connection must be proxied to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
	pub addr: String,
}

impl Upstream {
	#[must_use]
	pub fn new(addr: impl Into<String>) -> Self {
		Self { addr: addr.into() }
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResult {
	pub upstream: Upstream,
	pub initial_backend_data: Vec<u8>,
}

impl HandshakeResult {
	#[must_use]
	pub fn new(upstream: Upstream) -> Self {
		Self {
			upstream,
			initial_backend_data: Vec::new(),
		}
	}

	#[must_use]
	pub fn with_initial_data(upstream: Upstream, initial_backend_data: Vec<u8>) -> Self {
		Self {
			upstream,
			initial_backend_data,
		}
	}
}

/// Platform extension point: one implementation per L7 protocol.
///
/// The contract is deliberately small. A handler drives the handshake with the
/// client (reading and writing on the stream up to the point where proxying is
/// possible) and returns the target [`Upstream`]. Implementations ship as
/// features (`--features protocol-http`, external plugin crates); the core
/// itself contains none.
///
/// The method is async through a boxed future so the trait stays
/// dyn-compatible (`ProtocolRegistry` stores `Box<dyn ProtocolHandler>`).
pub trait ProtocolHandler: Send + Sync {
	/// Protocol name, used in metrics, logs and the registry.
	fn name(&self) -> &'static str;

	/// Drives the client handshake and resolves the upstream.
	///
	/// # Errors
	/// Returns an error when the client stream is invalid or access is denied.
	fn handshake<'a>(
		&'a self,
		stream: &'a mut TcpStream,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<HandshakeResult>> + Send + 'a>>;
}

/// Registry of the protocol handlers compiled into this binary.
#[derive(Default)]
pub struct ProtocolRegistry {
	handlers: Vec<Box<dyn ProtocolHandler>>,
}

impl ProtocolRegistry {
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	pub fn register(&mut self, handler: Box<dyn ProtocolHandler>) {
		self.handlers.push(handler);
	}

	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.handlers.is_empty()
	}

	#[must_use]
	pub fn len(&self) -> usize {
		self.handlers.len()
	}

	#[must_use]
	pub fn names(&self) -> Vec<&'static str> {
		self.handlers.iter().map(|h| h.name()).collect()
	}

	#[must_use]
	pub fn get(&self, name: &str) -> Option<&dyn ProtocolHandler> {
		self.handlers.iter().find(|h| h.name() == name).map(|h| h.as_ref())
	}

	/// Returns the primary handler, the first one registered.
	///
	/// # Errors
	/// Returns an error when no protocol is compiled in; an edge node must
	/// fail fast at startup in that case.
	pub fn primary(&self) -> anyhow::Result<&dyn ProtocolHandler> {
		let Some(handler) = self.handlers.first() else {
			anyhow::bail!(
				"no protocol plugins compiled; build with --features protocol-http \
                 or link an external ProtocolHandler implementation"
			);
		};
		Ok(handler.as_ref())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct DummyHandler;

	impl ProtocolHandler for DummyHandler {
		fn name(&self) -> &'static str {
			"dummy"
		}

		fn handshake<'a>(
			&'a self,
			_stream: &'a mut TcpStream,
		) -> Pin<Box<dyn Future<Output = anyhow::Result<HandshakeResult>> + Send + 'a>> {
			Box::pin(async { Ok(HandshakeResult::new(Upstream::new("127.0.0.1:9000"))) })
		}
	}

	#[test]
	fn empty_registry_fails_fast() {
		let registry = ProtocolRegistry::new();
		assert!(registry.is_empty());
		assert!(registry.primary().is_err());
	}

	#[test]
	fn registered_handler_is_resolvable() {
		let mut registry = ProtocolRegistry::new();
		registry.register(Box::new(DummyHandler));
		assert_eq!(registry.len(), 1);
		assert_eq!(registry.names(), vec!["dummy"]);
		assert!(registry.primary().is_ok());
		assert!(registry.get("dummy").is_some());
		assert!(registry.get("missing").is_none());
	}
}
