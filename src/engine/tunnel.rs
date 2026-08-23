//! Generic TCP proxy: фильтры входа → protocol handshake → upstream.

use crate::config::Config;
use crate::engine::challenge::{DifficultyAdjuster, enforce as enforce_pow};
use crate::filter::blacklist::Blacklist;
use crate::filter::rate_limit::RateLimiter;
use crate::metrics;
use crate::protocol::ProtocolRegistry;
use crate::store::clickhouse::{ClickHouseEvent, ClickHouseWriter};
use crate::traffic::reputation::IpReputation;
use crate::xdp::XdpFilter;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;

/// Общее состояние edge-движка, разделяемое между accept-loop'ами.
pub struct Gateway {
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
    pub blacklist: Arc<Blacklist>,
    pub adjuster: Arc<Mutex<DifficultyAdjuster>>,
    pub whitelist: Arc<HashSet<IpAddr>>,
    pub reputation: Arc<IpReputation>,
    pub xdp: Option<Arc<Mutex<XdpFilter>>>,
    pub clickhouse: Option<Arc<TokioMutex<ClickHouseWriter>>>,
    pub allowed_1s: Arc<AtomicU64>,
    pub registry: Arc<ProtocolRegistry>,
    upstream_cursor: AtomicUsize,
}

impl Gateway {
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
        registry: Arc<ProtocolRegistry>,
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
            registry,
            upstream_cursor: AtomicUsize::new(0),
        }
    }

    /// Полный конвейер обработки входящего соединения.
    ///
    /// # Errors
    /// Возвращает ошибку только при сбое ввода-вывода апстрима; блокировки
    /// клиента ошибкой не считаются.
    pub async fn handle(&self, mut client: TcpStream, peer_addr: std::net::SocketAddr) -> anyhow::Result<()> {
        let peer_ip = peer_addr.ip();

        if self.blacklist.is_blocked(peer_ip) {
            metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
            return Ok(());
        }

        if !self.pass_pow_gate(&mut client, peer_ip).await? {
            return Ok(());
        }

        if !self.rate_limiter.check(peer_ip) {
            self.block_rate_limit(peer_ip).await;
            return Ok(());
        }

        let handler = self.registry.primary()?;
        let upstream = match handler.handshake(&mut client).await {
            Ok(upstream) => upstream,
            Err(e) => {
                tracing::debug!("handshake rejected from {peer_addr}: {e}");
                metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
                return Ok(());
            },
        };

        if !self.rate_limiter.check(peer_ip) {
            self.block_rate_limit(peer_ip).await;
            return Ok(());
        }

        metrics::CONNECTIONS_TOTAL.with_label_values(&["allowed"]).inc();
        self.allowed_1s.fetch_add(1, Ordering::Relaxed);
        self.reputation.record_good(peer_ip);

        let mut backend = TcpStream::connect(self.next_upstream(&upstream.addr)).await?;
        tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
        Ok(())
    }

    async fn pass_pow_gate(&self, client: &mut TcpStream, peer_ip: IpAddr) -> anyhow::Result<bool> {
        let pow_config = &self.config.pow;
        if !(pow_config.enabled && pow_config.difficulty > 0) {
            return Ok(true);
        }
        if self.whitelist.contains(&peer_ip) {
            metrics::POW_CHALLENGES_TOTAL.with_label_values(&["skipped"]).inc();
            metrics::POW_CURRENT_DIFFICULTY.set(pow_config.difficulty as i64);
            return Ok(true);
        }

        let diff = {
            let mut adjuster = self.adjuster.lock().expect("adjuster lock poisoned");
            adjuster.record_connection();
            adjuster.current_difficulty()
        };
        let result = enforce_pow(client, peer_ip, diff).await?;
        if !result {
            metrics::POW_CHALLENGES_TOTAL.with_label_values(&["failed"]).inc();
            tracing::debug!("pow: failed for {peer_ip}, dropping connection");
            return Ok(false);
        }
        metrics::POW_CHALLENGES_TOTAL.with_label_values(&["passed"]).inc();
        metrics::POW_CURRENT_DIFFICULTY.set(diff as i64);
        Ok(true)
    }

    fn next_upstream<'a>(&'a self, negotiated: &'a str) -> &'a str {
        let upstreams = &self.config.backend.upstreams;
        if upstreams.len() > 1 {
            let idx = self.upstream_cursor.fetch_add(1, Ordering::Relaxed) % upstreams.len();
            return upstreams[idx].as_str();
        }
        if let Some(first) = upstreams.first() {
            return first.as_str();
        }
        negotiated
    }

    async fn block_rate_limit(&self, ip: IpAddr) {
        metrics::RATE_LIMIT_HITS.with_label_values(&["hit"]).inc();
        metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
        self.reputation.record_bad(ip);
        if self.reputation.score(ip) < -40 {
            let duration_secs = Duration::from_secs(self.config.ban.ban_duration_secs);
            self.blacklist.add(ip, duration_secs, "low_reputation");
            self.xdp_ban(ip, duration_secs.as_secs());
            self.push_event("block", ip, "low_reputation").await;
            tracing::info!("low reputation ban {ip}: rate-limit abuse");
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
