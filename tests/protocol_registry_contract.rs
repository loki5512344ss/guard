//! Protocol registry contract: an empty registry fails fast at startup and a
//! registered handler resolves by name.

use std::future::Future;
use std::pin::Pin;

use rampart::protocol::{HandshakeResult, ProtocolHandler, ProtocolRegistry, Upstream};
use tokio::net::TcpStream;

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
