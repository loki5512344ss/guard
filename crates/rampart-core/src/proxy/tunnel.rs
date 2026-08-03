use crate::config::Config;
use crate::crypto::hmac;
use crate::filter::blacklist::Blacklist;
use crate::filter::death_code;
use crate::filter::rate_limit::RateLimiter;
use crate::metrics;
use crate::pow::difficulty::DifficultyAdjuster;
use crate::proxy::handshake::{McHandshake, ParseError, read_varint};
use crate::proxy::pow::handle_pow;
use crate::store::clickhouse::{ClickHouseEvent, ClickHouseWriter};
use crate::traffic::reputation::IpReputation;
use crate::xdp::XdpFilter;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;

const MAX_FRAME_SIZE: usize = 8192;
const READ_CHUNK_SIZE: usize = 512;

pub struct ConnectionHandler {
    config: Arc<Config>,
    rate_limiter: Arc<RateLimiter>,
    blacklist: Arc<Blacklist>,
    adjuster: Arc<Mutex<DifficultyAdjuster>>,
    whitelist: Arc<HashSet<IpAddr>>,
    reputation: Arc<IpReputation>,
    xdp: Option<Arc<Mutex<XdpFilter>>>,
    clickhouse: Option<Arc<TokioMutex<ClickHouseWriter>>>,
    allowed_1s: Arc<AtomicU64>,
}

impl ConnectionHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        rate_limiter: Arc<RateLimiter>,
        blacklist: Arc<Blacklist>,
        adjuster: Arc<Mutex<DifficultyAdjuster>>,
        whitelist: Arc<HashSet<IpAddr>>,
        reputation: Arc<IpReputation>,
        xdp: Option<Arc<Mutex<XdpFilter>>>,
        clickhouse: Option<Arc<TokioMutex<ClickHouseWriter>>>,
        allowed_1s: Arc<AtomicU64>,
    ) -> Self {
        Self {
            config,
            rate_limiter,
            blacklist,
            adjuster,
            whitelist,
            reputation,
            xdp,
            clickhouse,
            allowed_1s,
        }
    }

    pub async fn handle(&self, mut client: TcpStream, peer_addr: std::net::SocketAddr) -> anyhow::Result<()> {
        let peer_ip = peer_addr.ip();

        if self.blacklist.is_blocked(peer_ip) {
            metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
            return Ok(());
        }

        let pow_config = &self.config.pow;
        if pow_config.enabled && pow_config.difficulty > 0 && !self.whitelist.contains(&peer_ip) {
            self.adjuster
                .lock()
                .expect("adjuster lock poisoned")
                .record_connection();
            let diff = self
                .adjuster
                .lock()
                .expect("adjuster lock poisoned")
                .current_difficulty();
            let result = handle_pow(&mut client, peer_ip, diff).await?;
            if !result {
                metrics::POW_CHALLENGES_TOTAL.with_label_values(&["failed"]).inc();
                tracing::debug!("pow: failed for {peer_ip}, dropping connection");
                return Ok(());
            }
            metrics::POW_CHALLENGES_TOTAL.with_label_values(&["passed"]).inc();
            metrics::POW_CURRENT_DIFFICULTY.set(diff as i64);
        } else if pow_config.enabled && pow_config.difficulty > 0 {
            metrics::POW_CHALLENGES_TOTAL.with_label_values(&["skipped"]).inc();
            metrics::POW_CURRENT_DIFFICULTY.set(pow_config.difficulty as i64);
        }

        if !self.rate_limiter.check(peer_ip) {
            self.block_rate_limit(peer_ip).await;
            return Ok(());
        }

        let timeout = Duration::from_secs(self.config.limits.handshake_timeout_secs);
        let mut buf: Vec<u8> = Vec::new();
        match read_full_frame(&mut client, timeout, &mut buf).await {
            Ok(false) => return Ok(()),
            Ok(true) => {},
            Err(e) => {
                tracing::debug!("read error from {peer_addr}: {e}");
                metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
                self.handle_death_code(peer_addr, &buf).await;
                return Ok(());
            },
        }

        let parsed = McHandshake::parse(&buf);
        match parsed {
            Ok(handshake) => {
                if !self.rate_limiter.check(peer_ip) {
                    self.block_rate_limit(peer_ip).await;
                    return Ok(());
                }

                metrics::CONNECTIONS_TOTAL.with_label_values(&["allowed"]).inc();
                self.allowed_1s.fetch_add(1, Ordering::Relaxed);
                self.reputation.record_good(peer_ip);

                let backend_addr = format!("{}:{}", self.config.backend.address, self.config.backend.port);
                let mut backend = TcpStream::connect(&backend_addr).await?;

                let signed = hmac::sign_hostname(
                    &handshake.server_address,
                    self.config.hmac.secret.as_bytes(),
                    self.config.hmac.key_rotation_interval_secs,
                );
                let modified = replace_hostname(&buf, &handshake.server_address, &signed)?;
                backend.write_all(&modified).await?;

                tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
            },
            Err(e) => {
                tracing::debug!("parse error from {peer_addr}: {e}");
                metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
                self.handle_death_code(peer_addr, &buf).await;
            },
        }
        Ok(())
    }

    async fn block_rate_limit(&self, ip: IpAddr) {
        metrics::RATE_LIMIT_HITS.with_label_values(&["hit"]).inc();
        metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
        self.reputation.record_bad(ip);
        if self.reputation.score(ip) < -40 {
            let duration_secs = self.config.death_code.ban_duration_secs;
            self.blacklist
                .add(ip, Duration::from_secs(duration_secs), "low_reputation");
            self.xdp_ban(ip, duration_secs);
            self.push_event("block", ip, "low_reputation").await;
            tracing::info!("low reputation ban {ip}: rate-limit abuse");
        }
    }

    async fn handle_death_code(&self, peer_addr: std::net::SocketAddr, buf: &[u8]) {
        if !self.config.death_code.enabled {
            return;
        }
        if let Some(code) = death_code::detect(buf) {
            let duration_secs = self.config.death_code.ban_duration_secs;
            let ip = peer_addr.ip();
            self.blacklist
                .add(ip, Duration::from_secs(duration_secs), code.as_str());
            self.reputation.record_bad(ip);
            self.xdp_ban(ip, duration_secs);
            self.push_event("ban", ip, code.as_str()).await;
            metrics::DEATH_CODE_BANS_TOTAL.with_label_values(&[code.as_str()]).inc();
            tracing::info!("death code ban {peer_addr}: {}", code.as_str());
        }
    }

    fn xdp_ban(&self, ip: IpAddr, duration_secs: u64) {
        let Some(xdp) = &self.xdp else {
            return;
        };
        let IpAddr::V4(ip_v4) = ip else {
            return;
        };
        match xdp.lock().expect("xdp lock poisoned").ban_ip(ip_v4, duration_secs) {
            Ok(()) => tracing::debug!("xdp ban {ip_v4} for {duration_secs}s"),
            Err(e) => tracing::warn!("xdp ban failed for {ip_v4}: {e}"),
        }
    }

    async fn push_event(&self, event_type: &str, ip: IpAddr, data_string: &str) {
        let Some(writer) = &self.clickhouse else {
            return;
        };
        let event = ClickHouseEvent {
            timestamp: chrono::Utc::now(),
            event_type: event_type.to_string(),
            ip: ip.to_string(),
            data_float: 0.0,
            data_int: 0,
            data_string: data_string.to_string(),
        };
        if let Err(e) = writer.lock().await.push(event).await {
            tracing::debug!("clickhouse push error: {e}");
        }
    }
}

async fn read_full_frame(client: &mut TcpStream, timeout: Duration, buf: &mut Vec<u8>) -> anyhow::Result<bool> {
    let mut chunk = [0u8; READ_CHUNK_SIZE];

    let first = tokio::time::timeout(timeout, client.read(&mut chunk)).await??;
    if first == 0 {
        return Ok(false);
    }
    buf.extend_from_slice(&chunk[..first]);

    let total_len = loop {
        match read_varint(buf, 0) {
            Ok((packet_len, after_len)) => break after_len + packet_len as usize,
            Err(ParseError::Incomplete(_)) => {
                if buf.len() >= 5 {
                    anyhow::bail!("length varint incomplete after {} bytes", buf.len());
                }
                let n = tokio::time::timeout(timeout, client.read(&mut chunk)).await??;
                if n == 0 {
                    anyhow::bail!("connection closed while reading packet length");
                }
                buf.extend_from_slice(&chunk[..n]);
            },
            Err(e) => anyhow::bail!("invalid packet length varint: {e}"),
        }
    };

    if total_len > MAX_FRAME_SIZE {
        anyhow::bail!("frame too large: {total_len} bytes (max {MAX_FRAME_SIZE})");
    }

    while buf.len() < total_len {
        let n = tokio::time::timeout(timeout, client.read(&mut chunk)).await??;
        if n == 0 {
            anyhow::bail!("connection closed while reading frame body");
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    buf.truncate(total_len);
    Ok(true)
}

fn replace_hostname(original: &[u8], _old_hostname: &str, new_hostname: &str) -> anyhow::Result<Vec<u8>> {
    let (packet_len, after_packet_len) =
        read_varint(original, 0).map_err(|_| anyhow::anyhow!("corrupt packet length"))?;
    let mut pos = after_packet_len;

    let (_packet_id, after_id) = read_varint(original, pos).map_err(|_| anyhow::anyhow!("corrupt packet id"))?;
    pos = after_id;

    let (_protocol_version, after_pv) =
        read_varint(original, pos).map_err(|_| anyhow::anyhow!("corrupt protocol version"))?;
    pos = after_pv;

    let (old_host_len, host_field_start) =
        read_varint(original, pos).map_err(|_| anyhow::anyhow!("corrupt hostname length"))?;
    let host_data_end = host_field_start + old_host_len as usize;
    let old_field_size = host_data_end - pos;

    let new_hostname_bytes = new_hostname.as_bytes();
    let new_len_field_bytes = varint_bytes(new_hostname_bytes.len() as i32);
    let new_field_size = new_len_field_bytes.len() + new_hostname_bytes.len();
    let size_diff = new_field_size as isize - old_field_size as isize;
    let new_packet_len = (packet_len as isize + size_diff) as i32;

    let cap = original.len().wrapping_add(size_diff as usize);
    let mut result = Vec::with_capacity(cap);

    result.extend_from_slice(&varint_bytes(new_packet_len));
    result.extend_from_slice(&original[after_packet_len..pos]);
    result.extend_from_slice(&new_len_field_bytes);
    result.extend_from_slice(new_hostname_bytes);
    result.extend_from_slice(&original[host_data_end..]);

    Ok(result)
}

fn varint_bytes(mut value: i32) -> Vec<u8> {
    let mut result = Vec::with_capacity(5);
    loop {
        if (value & !0x7F) == 0 {
            result.push(value as u8);
            return result;
        }
        result.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_packet(hostname: &str) -> Vec<u8> {
        let addr = hostname.as_bytes();
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.extend_from_slice(&varint_bytes(765));
        buf.extend_from_slice(&varint_bytes(addr.len() as i32));
        buf.extend_from_slice(addr);
        buf.extend_from_slice(&[0x63, 0xDD]);
        buf.push(0x02);

        let len = buf.len() as i32;
        let mut pkt = varint_bytes(len);
        pkt.extend_from_slice(&buf);
        pkt
    }

    #[test]
    fn test_replace_hostname_basic() {
        let pkt = build_test_packet("play.example.com");
        let new_hostname = "play.example.com\0shield\0abcdef1234567890";
        let modified = replace_hostname(&pkt, "play.example.com", new_hostname).expect("should replace hostname");
        assert!(modified.len() > pkt.len());

        let parsed = McHandshake::parse(&modified).expect("signed hostname should parse");
        assert_eq!(parsed.server_address, new_hostname);
    }

    #[test]
    fn test_replace_hostname_shorter() {
        let pkt = build_test_packet("very.long.hostname.example.com");
        let new_hostname = "short.com";
        let modified =
            replace_hostname(&pkt, "very.long.hostname.example.com", new_hostname).expect("should replace hostname");
        assert!(modified.len() < pkt.len());

        let parsed = McHandshake::parse(&modified).expect("short hostname should parse");
        assert_eq!(parsed.server_address, new_hostname);
    }

    #[test]
    fn test_replace_hostname_preserves_port_and_protocol() {
        let pkt = build_test_packet("mc.example.com");
        let new_hostname = "mc.example.com\0shield\x00deadbeef";
        let modified = replace_hostname(&pkt, "mc.example.com", new_hostname).expect("should replace hostname");

        let parsed = McHandshake::parse(&modified).expect("signed hostname should parse");
        assert_eq!(parsed.server_port, 25565);
        assert_eq!(parsed.protocol_version, 765);
        assert!(parsed.is_login());
    }

    #[test]
    fn test_varint_roundtrip() {
        let cases = vec![0, 1, 127, 128, 255, 65535, 1000000, i32::MAX];
        for val in cases {
            let bytes = varint_bytes(val);
            let (decoded, _) = read_varint(&bytes, 0).expect("varint should parse");
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }
}
