//! HTTP protocol handler: a zero `max_header_bytes` fails on the public
//! handshake path before any socket I/O happens.
#![cfg(feature = "protocol-http")]

use rampart::config::HttpProtocolConfig;
use rampart::protocol::ProtocolHandler;
use rampart::protocol::http::HttpProtocolHandler;

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
	assert!(handler.handshake(&mut server).await.is_err());
	drop(client);
}
