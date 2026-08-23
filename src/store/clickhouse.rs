use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::watch;

const BATCH_SIZE: usize = 1000;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize)]
pub struct ClickHouseEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub ip: String,
    pub data_float: f64,
    pub data_int: i64,
    pub data_string: String,
}

pub struct ClickHouseWriter {
    url: String,
    client: reqwest::Client,
    buffer: Vec<ClickHouseEvent>,
}

impl ClickHouseWriter {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
            buffer: Vec::with_capacity(BATCH_SIZE),
        }
    }

    pub async fn push(&mut self, event: ClickHouseEvent) -> anyhow::Result<()> {
        self.buffer.push(event);
        if self.buffer.len() >= BATCH_SIZE {
            self.flush().await?;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> anyhow::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let events = std::mem::take(&mut self.buffer);
        let json = serde_json::to_string(&events)?;
        let response = self
            .client
            .post(&self.url)
            .query(&[("query", "INSERT INTO rampart_events FORMAT JSONEachRow")])
            .header("Content-Type", "application/json")
            .body(json)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await?;
            anyhow::bail!("clickhouse insert failed ({}): {}", status, text);
        }
        tracing::debug!("flushed {} events to clickhouse", events.len());
        Ok(())
    }
}

pub fn start_flush_task(writer: Arc<Mutex<ClickHouseWriter>>, mut shutdown: watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(FLUSH_INTERVAL) => {
                    if let Err(e) = writer.lock().await.flush().await {
                        tracing::error!("clickhouse flush error: {e}");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("flushing clickhouse on shutdown");
                        if let Err(e) = writer.lock().await.flush().await {
                            tracing::error!("clickhouse final flush error: {e}");
                        }
                        return;
                    }
                }
            }
        }
    });
}
