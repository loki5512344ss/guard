use prometheus::{Encoder, IntCounterVec, IntGauge, register_int_counter_vec, register_int_gauge};
use std::sync::LazyLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub static CONNECTIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!("rampart_connections_total", "Total connections handled", &["result"])
        .expect("CONNECTIONS_TOTAL")
});

pub static RATE_LIMIT_HITS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!("rampart_rate_limit_hits", "Rate limit hits", &["action"]).expect("RATE_LIMIT_HITS")
});

pub static ACTIVE_CONNECTIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!("rampart_active_connections", "Active connections").expect("ACTIVE_CONNECTIONS")
});

pub static BLACKLIST_SIZE: LazyLock<IntGauge> =
    LazyLock::new(|| register_int_gauge!("rampart_blacklist_size", "Blacklist entries").expect("BLACKLIST_SIZE"));

pub static DEATH_CODE_BANS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!("rampart_death_code_bans_total", "Death code auto-bans", &["code"])
        .expect("DEATH_CODE_BANS_TOTAL")
});

pub static POW_CHALLENGES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!("rampart_pow_challenges_total", "PoW challenges issued", &["result"])
        .expect("POW_CHALLENGES_TOTAL")
});

pub static POW_CURRENT_DIFFICULTY: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!("rampart_pow_current_difficulty", "Current PoW difficulty").expect("POW_CURRENT_DIFFICULTY")
});

pub async fn run_metrics_server(addr: &str) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind metrics server: {e}");
            return;
        },
    };
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Metrics accept error: {e}");
                continue;
            },
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_err() {
                return;
            }
            let metric_families = prometheus::gather();
            let encoder = prometheus::TextEncoder::new();
            let mut payload = Vec::new();
            if encoder.encode(&metric_families, &mut payload).is_err() {
                return;
            }
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let mut response = header.into_bytes();
            response.extend_from_slice(&payload);
            let _ = stream.write_all(&response).await;
        });
    }
}
