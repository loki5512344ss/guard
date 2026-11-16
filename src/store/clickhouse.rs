//! ClickHouse event sink.
//!
//! The data plane must never block on the sink: [`ClickHouseWriter::push`] only
//! touches memory, while the background task drains a batch under the writer
//! lock and performs network I/O outside of it. Every request is bounded by a
//! request timeout and every flush by a global timeout, so an unreachable or
//! hung ClickHouse degrades into dropped events instead of a stalled daemon.

use chrono::{DateTime, Utc};
use prometheus::IntCounter;
use serde::Serialize;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::watch;

/// Maximum number of events sent in one INSERT.
pub const BATCH_SIZE: usize = 1000;
/// Hard cap on buffered events; further pushes are dropped and counted.
pub const MAX_BUFFER_EVENTS: usize = 10_000;

const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const ERROR_BODY_LIMIT: usize = 512;
/// Batches drained per tick; keeps sustained event rates from backing up.
const MAX_BATCHES_PER_FLUSH: usize = 4;

/// Events discarded because the buffer was full or a retry could not fit.
pub static CLICKHOUSE_DROPPED: LazyLock<IntCounter> = LazyLock::new(|| {
	prometheus::register_int_counter!(
		"rampart_clickhouse_dropped_total",
		"ClickHouse events dropped (buffer overflow or failed flush)"
	)
	.expect("CLICKHOUSE_DROPPED")
});

/// One row of the `rampart_events` table.
#[derive(Debug, Clone, Serialize)]
pub struct ClickHouseEvent {
	pub timestamp: DateTime<Utc>,
	pub event_type: String,
	pub ip: String,
	pub data_float: f64,
	pub data_int: i64,
	pub data_string: String,
}

/// Buffered ClickHouse writer shared by the data plane and the flush task.
pub struct ClickHouseWriter {
	url: String,
	client: reqwest::Client,
	buffer: Vec<ClickHouseEvent>,
	dropped: u64,
}

impl ClickHouseWriter {
	/// Creates a writer for `url` with bounded request and connect timeouts.
	pub fn new(url: &str) -> Self {
		let client = reqwest::Client::builder()
			.timeout(REQUEST_TIMEOUT)
			.connect_timeout(CONNECT_TIMEOUT)
			.build()
			.expect("clickhouse http client");
		Self {
			url: url.to_string(),
			client,
			buffer: Vec::with_capacity(BATCH_SIZE),
			dropped: 0,
		}
	}

	/// Queues `event` for the next flush.
	///
	/// This never performs I/O and never fails; when the buffer is full the
	/// event is dropped and counted instead of blocking the data plane.
	///
	/// # Errors
	/// Currently infallible; the result is kept for API stability.
	pub async fn push(&mut self, event: ClickHouseEvent) -> anyhow::Result<()> {
		if self.buffer.len() >= MAX_BUFFER_EVENTS {
			self.record_drop(1);
			return Ok(());
		}
		self.buffer.push(event);
		Ok(())
	}

	/// Sends every buffered event, re-queueing the batch on failure.
	///
	/// # Errors
	/// Returns an error when the insert fails or exceeds `FLUSH_TIMEOUT`; the
	/// batch stays buffered for the next attempt.
	pub async fn flush(&mut self) -> anyhow::Result<()> {
		let batch = std::mem::take(&mut self.buffer);
		if batch.is_empty() {
			return Ok(());
		}
		match tokio::time::timeout(FLUSH_TIMEOUT, send_batch(&self.client, &self.url, &batch)).await {
			Ok(Ok(())) => {
				tracing::debug!(events = batch.len(), "flushed events to clickhouse");
				Ok(())
			},
			Ok(Err(error)) => {
				self.requeue_batch(batch);
				Err(error)
			},
			Err(_) => {
				self.requeue_batch(batch);
				anyhow::bail!("clickhouse flush timed out after {FLUSH_TIMEOUT:?}")
			},
		}
	}

	/// Number of events waiting in the buffer.
	pub fn pending(&self) -> usize {
		self.buffer.len()
	}

	/// Number of events this writer discarded.
	pub fn dropped(&self) -> u64 {
		self.dropped
	}

	fn take_batch(&mut self) -> Vec<ClickHouseEvent> {
		let take = self.buffer.len().min(BATCH_SIZE);
		self.buffer.drain(..take).collect()
	}

	/// Puts a failed batch back in front of the buffer, keeping it bounded.
	fn requeue_batch(&mut self, mut batch: Vec<ClickHouseEvent>) {
		batch.append(&mut self.buffer);
		if batch.len() > MAX_BUFFER_EVENTS {
			let overflow = batch.len() - MAX_BUFFER_EVENTS;
			batch.truncate(MAX_BUFFER_EVENTS);
			self.record_drop(overflow);
		}
		self.buffer = batch;
	}

	fn record_drop(&mut self, count: usize) {
		let count = u64::try_from(count).unwrap_or(u64::MAX);
		let first_drop = self.dropped == 0;
		self.dropped = self.dropped.saturating_add(count);
		CLICKHOUSE_DROPPED.inc_by(count);
		// Log once per writer: further drops are visible in the counter only,
		// so a sustained outage cannot flood the log.
		if first_drop {
			tracing::warn!(count, "clickhouse buffer full; dropping events");
		}
	}
}

/// Runs the periodic flush loop until shutdown.
///
/// A closed shutdown channel is treated as a shutdown request: the final
/// flush runs and the task exits instead of busy-looping on `changed()`.
pub fn start_flush_task(writer: Arc<Mutex<ClickHouseWriter>>, mut shutdown: watch::Receiver<bool>) {
	tokio::spawn(async move {
		loop {
			tokio::select! {
				_ = tokio::time::sleep(FLUSH_INTERVAL) => {
					for _ in 0..MAX_BATCHES_PER_FLUSH {
						if !flush_batch(&writer).await {
							break;
						}
					}
				},
				changed = shutdown.changed() => {
					if changed.is_err() || *shutdown.borrow_and_update() {
						tracing::info!("flushing clickhouse on shutdown");
						flush_batch(&writer).await;
						return;
					}
				},
			}
		}
	});
}

/// Drains one batch under the lock and sends it without holding the lock.
///
/// Returns `false` when there was nothing to send or the send failed.
async fn flush_batch(writer: &Arc<Mutex<ClickHouseWriter>>) -> bool {
	let (client, url, batch) = {
		let mut writer = writer.lock().await;
		let batch = writer.take_batch();
		(writer.client.clone(), writer.url.clone(), batch)
	};
	if batch.is_empty() {
		return false;
	}
	match tokio::time::timeout(FLUSH_TIMEOUT, send_batch(&client, &url, &batch)).await {
		Ok(Ok(())) => {
			tracing::debug!(events = batch.len(), "flushed events to clickhouse");
			true
		},
		Ok(Err(error)) => {
			tracing::warn!(%error, events = batch.len(), "clickhouse flush failed; re-queueing");
			requeue_batch(writer, batch).await;
			false
		},
		Err(_) => {
			tracing::warn!(events = batch.len(), "clickhouse flush timed out; re-queueing");
			requeue_batch(writer, batch).await;
			false
		},
	}
}

async fn requeue_batch(writer: &Arc<Mutex<ClickHouseWriter>>, batch: Vec<ClickHouseEvent>) {
	writer.lock().await.requeue_batch(batch);
}

async fn send_batch(client: &reqwest::Client, url: &str, batch: &[ClickHouseEvent]) -> anyhow::Result<()> {
	let json = serde_json::to_string(batch)?;
	let response = client
		.post(url)
		.query(&[("query", "INSERT INTO rampart_events FORMAT JSONEachRow")])
		.header("Content-Type", "application/json")
		.body(json)
		.send()
		.await?;
	let status = response.status();
	if !status.is_success() {
		let mut text = response.text().await.unwrap_or_default();
		text.truncate(ERROR_BODY_LIMIT);
		anyhow::bail!("clickhouse insert failed ({status}): {text}");
	}
	Ok(())
}
