//! Minecraft Java TCP handshake validation (feature `protocol-minecraft`).

mod parser;

use crate::config::MinecraftProtocolConfig;
use crate::protocol::{HandshakeResult, ProtocolHandler, Upstream};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub struct MinecraftProtocolHandler {
    upstream: String,
    max_frame_bytes: usize,
    timeout: Duration,
}

impl MinecraftProtocolHandler {
    #[must_use]
    pub fn new(config: &MinecraftProtocolConfig, upstreams: &[String]) -> Self {
        Self {
            // Config validation requires exactly one backend when this handler is enabled.
            upstream: upstreams.first().cloned().unwrap_or_default(),
            max_frame_bytes: config.max_frame_bytes,
            timeout: Duration::from_secs(config.timeout_secs),
        }
    }

    async fn read_handshake(&self, stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
        let mut frame = Vec::with_capacity(64);
        let mut frame_len = 0usize;
        for index in 0..5 {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await?;
            frame.push(byte[0]);
            if index == 4 && byte[0] & 0xf0 != 0 {
                anyhow::bail!("Minecraft frame length VarInt exceeds 32 bits");
            }
            if byte[0] & 0x80 == 0 {
                let (decoded, prefix_len) = parser::decode_frame_length(&frame)?;
                frame_len = decoded;
                if frame_len == 0 || frame_len > self.max_frame_bytes {
                    anyhow::bail!("Minecraft handshake frame length {frame_len} is outside allowed range");
                }
                if prefix_len != frame.len() {
                    anyhow::bail!("invalid Minecraft frame length prefix");
                }
                break;
            }
            if index == 4 {
                anyhow::bail!("Minecraft frame length VarInt exceeds five bytes");
            }
        }
        if frame_len == 0 {
            anyhow::bail!("invalid empty Minecraft handshake frame");
        }
        let prefix_len = frame.len();
        frame.resize(prefix_len + frame_len, 0);
        stream.read_exact(&mut frame[prefix_len..]).await?;
        parser::parse_frame(&frame, self.max_frame_bytes)?;
        Ok(frame)
    }
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
            let frame = tokio::time::timeout(self.timeout, self.read_handshake(stream))
                .await
                .map_err(|_| anyhow::anyhow!("timed out reading Minecraft handshake"))??;
            Ok(HandshakeResult::with_initial_data(
                Upstream::new(self.upstream.clone()),
                frame,
            ))
        })
    }
}
