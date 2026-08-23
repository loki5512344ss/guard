//! Multi-worker TCP accept-loop с SO_REUSEPORT и graceful shutdown.

use crate::config::Config;
use crate::engine::tunnel::Gateway;
use socket2::{Domain, Socket, Type};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Запускает `workers.count` accept-loop'ов на одном адресе.
///
/// # Errors
/// Возвращает ошибку при невозможности забиндить адрес или падении одного
/// из accept-loop'ов.
pub async fn run(config: Arc<Config>, gateway: Arc<Gateway>, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let _ = &config;
    let addr: std::net::SocketAddr = format!("{}:{}", config.bind.address, config.bind.port).parse()?;
    let workers = config.workers.count.max(1);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let listener = build_listener(addr)?;
        handles.push(tokio::spawn(accept_loop(
            listener,
            Arc::clone(&gateway),
            shutdown.clone(),
        )));
    }

    for h in handles {
        h.await?;
    }
    Ok(())
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

async fn accept_loop(listener: TcpListener, gateway: Arc<Gateway>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutdown signal received, stopping accept loop");
                    return;
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
                let gateway = Arc::clone(&gateway);
                tokio::spawn(async move {
                    if let Err(e) = gateway.handle(stream, peer_addr).await {
                        tracing::debug!("connection from {peer_addr}: {e}");
                    }
                });
            }
        }
    }
}
