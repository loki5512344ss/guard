#![cfg(feature = "protocol-http")]

use rampart::config::HttpProtocolConfig;
use rampart::protocol::http::HttpProtocolHandler;
use rampart::protocol::{ProtocolHandler, ProtocolRegistry};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const REQUEST: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

fn handler() -> HttpProtocolHandler {
    HttpProtocolHandler::new(&HttpProtocolConfig::default(), &["127.0.0.1:9000".to_string()])
}

async fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).await.expect("connect");
    let (server, _) = listener.accept().await.expect("accept");
    (client, server)
}

#[tokio::test]
async fn valid_request_is_allowed() {
    let (mut client, mut server) = socket_pair().await;
    client.write_all(REQUEST).await.expect("write");
    assert!(handler().handshake(&mut server).await.is_ok());
}

#[tokio::test]
async fn fragmented_head_is_accumulated_and_parsed() {
    let (mut client, mut server) = socket_pair().await;
    for chunk in REQUEST.chunks(7) {
        client.write_all(chunk).await.expect("write chunk");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(handler().handshake(&mut server).await.is_ok());
}

#[tokio::test]
async fn oversized_head_is_rejected() {
    let config = HttpProtocolConfig {
        max_header_bytes: 32,
        ..HttpProtocolConfig::default()
    };
    let (mut client, mut server) = socket_pair().await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: a-very-long-host-name-value\r\n")
        .await
        .expect("write");
    let err = handler_with(&config)
        .handshake(&mut server)
        .await
        .expect_err("oversized head must be rejected");
    assert!(err.to_string().contains("exceeds"));
}

#[tokio::test]
async fn unknown_method_is_rejected() {
    let (mut client, mut server) = socket_pair().await;
    client
        .write_all(b"TRACE / HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .expect("write");
    let err = handler()
        .handshake(&mut server)
        .await
        .expect_err("unknown method must be rejected");
    assert!(err.to_string().contains("method"));
}

#[tokio::test]
async fn missing_host_is_rejected() {
    let (mut client, mut server) = socket_pair().await;
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.expect("write");
    let err = handler()
        .handshake(&mut server)
        .await
        .expect_err("missing host must be rejected");
    assert!(err.to_string().contains("host"));
}

#[tokio::test]
async fn blocked_path_is_rejected() {
    let config = HttpProtocolConfig {
        blocked_paths: vec!["/admin".to_string()],
        ..HttpProtocolConfig::default()
    };
    let (mut client, mut server) = socket_pair().await;
    client
        .write_all(b"GET /admin/secrets HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .expect("write");
    let err = handler_with(&config)
        .handshake(&mut server)
        .await
        .expect_err("blocked path must be rejected");
    assert!(err.to_string().contains("blocklisted"));
}

#[tokio::test]
async fn required_user_agent_missing_is_rejected() {
    let config = HttpProtocolConfig {
        require_user_agent: true,
        ..HttpProtocolConfig::default()
    };
    let (mut client, mut server) = socket_pair().await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .expect("write");
    let err = handler_with(&config)
        .handshake(&mut server)
        .await
        .expect_err("missing user-agent must be rejected");
    assert!(err.to_string().contains("user-agent"));
}

#[tokio::test]
async fn registry_resolves_http_handler_when_feature_enabled() {
    let mut registry = ProtocolRegistry::new();
    registry.register(Box::new(handler()));
    assert_eq!(registry.names(), vec!["http"]);
    let resolved = registry.get("http").expect("http handler must resolve");
    assert_eq!(resolved.name(), "http");
    assert!(registry.primary().is_ok());
}

fn handler_with(config: &HttpProtocolConfig) -> HttpProtocolHandler {
    HttpProtocolHandler::new(config, &["127.0.0.1:9000".to_string()])
}
