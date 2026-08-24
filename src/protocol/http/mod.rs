//! HTTP/1.1 protocol handler (feature `protocol-http`).
//!
//! Первый plugin-реализаций [`ProtocolHandler`]: читает request-head
//! постепенно (TCP приходит фрагментами), проверяет его по политике из
//! секции `[protocol.http]` и возвращает upstream для туннелирования.
//! Голова читается через `peek`, чтобы байты остались в сокете и движок
//! проксировал запрос на backend без потерь.

mod parser;

use crate::config::HttpProtocolConfig;
use crate::protocol::{ProtocolHandler, Upstream};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::TcpStream;

/// Обработчик HTTP/1.1: verdict Allow → tunnel на upstream, Reject → drop.
pub struct HttpProtocolHandler {
    policy: parser::Policy,
    timeout: Duration,
    upstream: String,
}

impl HttpProtocolHandler {
    /// Собирает обработчик из конфига `[protocol.http]` и списка upstream'ов.
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

    /// Накапливает request-head через `peek` до терминатора или лимита.
    ///
    /// # Errors
    /// Таймаут, закрытие клиента, превышение `max_header_bytes` или ошибка I/O.
    async fn read_head(&self, stream: &TcpStream) -> anyhow::Result<Vec<u8>> {
        let limit = self.policy.max_header_bytes;
        if limit == 0 {
            anyhow::bail!("protocol.http.max_header_bytes must be positive");
        }
        let mut buf = vec![0u8; limit];
        let mut len = 0usize;
        let accumulate = async {
            loop {
                if let Some(head_len) = parser::scan_head(&buf[..len]) {
                    buf.truncate(head_len);
                    return Ok(buf);
                }
                if len >= limit {
                    anyhow::bail!("request head exceeds {limit} bytes");
                }
                let n = stream.peek(&mut buf[len..]).await?;
                if n == 0 {
                    anyhow::bail!("client closed connection before head was complete");
                }
                len += n;
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
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Upstream>> + Send + 'a>> {
        Box::pin(async move {
            let head = self.read_head(stream).await?;
            match parser::evaluate(&head, &self.policy) {
                parser::Verdict::Allow { .. } => Ok(Upstream::new(self.upstream.clone())),
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
        let (server, _) = listener.accept().await.expect("accept");
        drop(listener);
        assert!(handler.read_head(&server).await.is_err());
        drop(client);
    }
}
