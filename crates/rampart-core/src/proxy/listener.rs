use crate::config::Config;
use crate::filter::blacklist::Blacklist;
use crate::filter::rate_limit::RateLimiter;
use crate::pow::difficulty::DifficultyAdjuster;
use crate::proxy::tunnel::ConnectionHandler;
use crate::store::clickhouse::ClickHouseWriter;
use crate::traffic::reputation::IpReputation;
use crate::xdp::XdpFilter;
use socket2::{Domain, Socket, Type};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::watch;

pub struct ProxyListener {
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

impl ProxyListener {
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

    pub async fn run(&self, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.bind.address, self.config.bind.port).parse::<std::net::SocketAddr>()?;
        let workers = self.config.workers.count.max(1);

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let listener = build_listener(addr)?;
            let config = self.config.clone();
            let rate_limiter = self.rate_limiter.clone();
            let blacklist = self.blacklist.clone();
            let adjuster = self.adjuster.clone();
            let whitelist = self.whitelist.clone();
            let reputation = self.reputation.clone();
            let xdp = self.xdp.clone();
            let clickhouse = self.clickhouse.clone();
            let allowed_1s = self.allowed_1s.clone();
            let shutdown = shutdown.clone();
            handles.push(tokio::spawn(accept_loop(
                listener,
                config,
                rate_limiter,
                blacklist,
                adjuster,
                whitelist,
                reputation,
                xdp,
                clickhouse,
                allowed_1s,
                shutdown,
            )));
        }

        for h in handles {
            h.await??;
        }
        Ok(())
    }
}

fn build_listener(addr: std::net::SocketAddr) -> anyhow::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(65535)?;
    Ok(TcpListener::from_std(socket.into())?)
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    config: Arc<Config>,
    rate_limiter: Arc<RateLimiter>,
    blacklist: Arc<Blacklist>,
    adjuster: Arc<Mutex<DifficultyAdjuster>>,
    whitelist: Arc<HashSet<IpAddr>>,
    reputation: Arc<IpReputation>,
    xdp: Option<Arc<Mutex<XdpFilter>>>,
    clickhouse: Option<Arc<TokioMutex<ClickHouseWriter>>>,
    allowed_1s: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutdown signal received, stopping accept loop");
                    return Ok(());
                }
            }
            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::error!("accept error: {e}");
                        continue;
                    }
                };
                let handler = ConnectionHandler::new(
                    config.clone(),
                    rate_limiter.clone(),
                    blacklist.clone(),
                    adjuster.clone(),
                    whitelist.clone(),
                    reputation.clone(),
                    xdp.clone(),
                    clickhouse.clone(),
                    allowed_1s.clone(),
                );
                tokio::spawn(async move {
                    if let Err(e) = handler.handle(stream, peer_addr).await {
                        tracing::debug!("connection from {peer_addr}: {e}");
                    }
                });
            }
        }
    }
}
