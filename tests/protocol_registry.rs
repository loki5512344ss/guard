use std::future::Future;
use std::pin::Pin;

use rampart::protocol::{ProtocolHandler, ProtocolRegistry, Upstream};
use tokio::net::TcpStream;

struct NoopHandler;

impl ProtocolHandler for NoopHandler {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn handshake<'a>(
        &'a self,
        _stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Upstream>> + Send + 'a>> {
        Box::pin(async { Ok(Upstream::new("127.0.0.1:9000")) })
    }
}

#[tokio::test]
async fn empty_registry_reports_missing_protocols() {
    let registry = ProtocolRegistry::new();
    assert!(registry.is_empty());
    let err = registry.primary().err().expect("empty registry must fail fast");
    assert!(err.to_string().contains("no protocol plugins compiled"));
}

#[tokio::test]
async fn registered_handler_resolves_by_name() {
    let mut registry = ProtocolRegistry::new();
    registry.register(Box::new(NoopHandler));

    assert_eq!(registry.names(), vec!["noop"]);
    let handler = registry.primary().expect("registered handler must resolve");
    assert_eq!(handler.name(), "noop");
}
