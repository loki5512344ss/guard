//! Integration tests for the ClickHouse sink: buffering, bounded flush and
//! retry on failure.

use std::time::{Duration, Instant};

use rampart::store::clickhouse::{ClickHouseEvent, ClickHouseWriter, MAX_BUFFER_EVENTS};

fn event(seq: usize) -> ClickHouseEvent {
	ClickHouseEvent {
		timestamp: time::OffsetDateTime::now_utc(),
		event_type: "test".to_string(),
		ip: format!("192.0.2.{}", seq % 250),
		data_float: 0.0,
		data_int: 0,
		data_string: String::new(),
	}
}

#[tokio::test]
async fn push_only_buffers_events() {
	let mut writer = ClickHouseWriter::new("http://127.0.0.1:1");
	writer.push(event(0)).await.expect("push must succeed");

	assert_eq!(writer.pending(), 1, "push must not flush eagerly");
	assert_eq!(writer.dropped(), 0);
}

#[tokio::test]
async fn empty_flush_is_a_noop() {
	let mut writer = ClickHouseWriter::new("http://127.0.0.1:1");
	writer.flush().await.expect("empty flush must not touch the network");
}

#[tokio::test]
async fn failed_flush_requeues_the_batch() {
	let mut writer = ClickHouseWriter::new("http://127.0.0.1:1");
	writer.push(event(1)).await.expect("push must succeed");

	let result = writer.flush().await;

	assert!(result.is_err(), "connection refused must surface as an error");
	assert_eq!(writer.pending(), 1, "failed batch must be re-queued");
	assert_eq!(writer.dropped(), 0, "a single failed batch is not a drop");
}

#[tokio::test]
async fn stalled_server_flush_is_bounded() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("local addr");
	let server = tokio::spawn(async move {
		let (_stream, _) = listener.accept().await.expect("accept");
		// Keep the connection open without ever answering.
		std::future::pending::<()>().await;
	});

	let mut writer = ClickHouseWriter::new(&format!("http://{addr}/"));
	writer.push(event(2)).await.expect("push must succeed");

	let started = Instant::now();
	let result = writer.flush().await;
	let elapsed = started.elapsed();
	server.abort();

	assert!(result.is_err(), "a stalled server must fail the flush");
	assert!(
		elapsed < Duration::from_secs(5),
		"flush must be bounded, took {elapsed:?}"
	);
	assert_eq!(writer.pending(), 1, "timed-out batch must be re-queued");
}

#[tokio::test]
async fn buffer_is_bounded_and_overflow_is_counted() {
	let mut writer = ClickHouseWriter::new("http://127.0.0.1:1");
	for seq in 0..MAX_BUFFER_EVENTS + 7 {
		writer.push(event(seq)).await.expect("push must succeed");
	}

	assert_eq!(writer.pending(), MAX_BUFFER_EVENTS, "buffer must stay bounded");
	assert_eq!(writer.dropped(), 7, "overflow must be counted");
}
