mod challenge;

#[cfg(feature = "protocol-minecraft")]
use super::proxy;
use super::{Gateway, GatewayOutcome};
use crate::config::Config;
use crate::engine::challenge::DifficultyAdjuster;
use crate::engine::subnet::tracker::SubnetTracker;
use crate::filter::blacklist::Blacklist;
use crate::filter::connection_limit::ConnectionLimiter;
use crate::filter::rate_limit::RateLimiter;
use crate::metrics;
use crate::protocol::ProtocolRegistry;
use crate::store::clickhouse::{ClickHouseEvent, ClickHouseWriter};
use crate::traffic::reputation::IpReputation;
use crate::xdp::XdpFilter;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;

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
        subnet_tracker: Option<Arc<SubnetTracker>>,
    ) -> Self {
        let max_connections = config.limits.max_connections_per_ip as usize;
        Self {
            config,
            rate_limiter,
            connection_limiter: ConnectionLimiter::new(max_connections),
            blacklist,
            adjuster,
            whitelist,
            reputation,
            xdp,
            clickhouse,
            allowed_1s,
            registry,
            subnet_tracker,
            upstream_cursor: AtomicUsize::new(0),
        }
    }

    /// Полный конвейер обработки входящего соединения.
    ///
    /// # Errors
    /// Возвращает ошибку только при сбое ввода-вывода апстрима; блокировки
    /// клиента ошибкой не считаются.
    #[allow(unused_mut)]
    pub async fn handle(&self, mut client: TcpStream, peer_addr: std::net::SocketAddr) -> GatewayOutcome {
        let client_addr = if self.config.proxy_protocol.ingress_enabled {
            #[cfg(feature = "protocol-minecraft")]
            {
                if !self
                    .config
                    .proxy_protocol
                    .trusted_cidrs
                    .iter()
                    .any(|cidr| cidr.contains(peer_addr.ip()))
                {
                    return GatewayOutcome {
                        client_ip: None,
                        result: Err(anyhow::anyhow!("untrusted peer attempted inbound PROXY protocol")),
                    };
                }
                match proxy::read_v2_header(
                    &mut client,
                    Duration::from_millis(self.config.proxy_protocol.ingress_timeout_ms),
                    self.config.proxy_protocol.max_header_bytes,
                )
                .await
                {
                    Ok(client_addr) => client_addr,
                    Err(error) => {
                        return GatewayOutcome {
                            client_ip: None,
                            result: Err(error),
                        };
                    },
                }
            }
            #[cfg(not(feature = "protocol-minecraft"))]
            {
                return GatewayOutcome {
                    client_ip: None,
                    result: Err(anyhow::anyhow!("inbound PROXY protocol requires protocol-minecraft")),
                };
            }
        } else {
            peer_addr
        };
        let client_ip = client_addr.ip();
        let result = self.handle_client(client, peer_addr, client_addr).await;
        GatewayOutcome {
            client_ip: Some(client_ip),
            result,
        }
    }

    async fn handle_client(
        &self,
        mut client: TcpStream,
        peer_addr: std::net::SocketAddr,
        client_addr: std::net::SocketAddr,
    ) -> anyhow::Result<()> {
        let peer_ip = client_addr.ip();

        if let Some(tracker) = &self.subnet_tracker {
            tracker.record_connection(peer_ip);
        }

        if self.blacklist.is_blocked(peer_ip) {
            metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
            return Ok(());
        }

        let Some(_connection_permit) = self.connection_limiter.try_acquire(peer_ip) else {
            self.block_rate_limit(peer_ip).await;
            return Ok(());
        };

        if !self.pass_pow_gate(&mut client, peer_ip).await? {
            return Ok(());
        }

        if !self.rate_limiter.check(peer_ip) {
            self.block_rate_limit(peer_ip).await;
            return Ok(());
        }

        let handler = self.registry.primary()?;
        let handshake = match handler.handshake(&mut client).await {
            Ok(handshake) => handshake,
            Err(e) => {
                tracing::debug!("handshake rejected from {peer_addr}: {e}");
                metrics::CONNECTIONS_TOTAL.with_label_values(&["blocked"]).inc();
                return Ok(());
            },
        };

        metrics::CONNECTIONS_TOTAL.with_label_values(&["allowed"]).inc();
        self.allowed_1s.fetch_add(1, Ordering::Relaxed);
        self.reputation.record_good(peer_ip);

        let mut backend = TcpStream::connect(self.next_upstream(&handshake.upstream.addr)).await?;
        #[cfg(feature = "protocol-minecraft")]
        if self.config.protocol.minecraft.enabled && self.config.protocol.minecraft.send_proxy_protocol {
            let source = client_addr;
            let destination = client.local_addr()?;
            backend.write_all(&proxy::protocol_v2(source, destination)?).await?;
        }
        if !handshake.initial_backend_data.is_empty() {
            backend.write_all(&handshake.initial_backend_data).await?;
        }
        tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
        Ok(())
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
            if !self.config.proxy_protocol.ingress_enabled {
                self.xdp_ban(ip, duration_secs.as_secs());
            }
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
