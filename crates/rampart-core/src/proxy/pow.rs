use crate::pow::challenge::Challenge;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

pub async fn handle_pow(stream: &mut TcpStream, peer_ip: IpAddr, difficulty: u8) -> anyhow::Result<bool> {
    if difficulty == 0 {
        tracing::debug!("pow: difficulty 0, skipping for {peer_ip}");
        return Ok(true);
    }

    let mut challenge = Challenge::generate(difficulty);
    let challenge_str = challenge.challenge_string();
    let line = format!("{challenge_str}\n");
    stream.write_all(line.as_bytes()).await?;

    let mut buf = [0u8; 65];
    let n = timeout(Duration::from_secs(10), stream.read(&mut buf)).await??;
    if n == 0 {
        tracing::debug!("pow: no response from {peer_ip}");
        return Ok(false);
    }

    let nonce = std::str::from_utf8(&buf[..n.min(64)]).unwrap_or("").trim();
    if nonce.is_empty() || nonce.len() > 64 {
        tracing::debug!("pow: invalid nonce from {peer_ip}");
        return Ok(false);
    }

    let valid = crate::pow::verifier::verify(&mut challenge, nonce);
    tracing::debug!(
        "pow: verification {} for {peer_ip}",
        if valid { "passed" } else { "failed" }
    );
    Ok(valid)
}
