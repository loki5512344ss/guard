//! Minecraft handler over loopback: byte-exact replay, rejects, per-phase frame
//! caps enforced before buffering, and the handshake metrics.
#![cfg(feature = "protocol-minecraft")]

use rampart::config::MinecraftProtocolConfig;
use rampart::metrics::{MC_HANDSHAKE_TOTAL, MC_PROTOCOL_VERSION_TOTAL};
use rampart::protocol::ProtocolHandler;
use rampart::protocol::minecraft::MinecraftProtocolHandler;
use rampart::protocol::minecraft::read_frame;
use rampart::protocol::minecraft::reason::Reason;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

fn varint(mut value: u32) -> Vec<u8> {
	let mut out = Vec::new();
	loop {
		let byte = (value & 0x7f) as u8;
		value >>= 7;
		if value == 0 {
			out.push(byte);
			return out;
		}
		out.push(byte | 0x80);
	}
}

fn frame(body: &[u8]) -> Vec<u8> {
	let mut out = varint(body.len() as u32);
	out.extend_from_slice(body);
	out
}

fn handshake(version: u32, host: &str, state: u32) -> Vec<u8> {
	let mut body = varint(0);
	body.extend(varint(version));
	body.extend(varint(host.len() as u32));
	body.extend(host.as_bytes());
	body.extend(25565u16.to_be_bytes());
	body.extend(varint(state));
	frame(&body)
}

fn login(name: &str) -> Vec<u8> {
	let mut body = varint(0);
	body.extend(varint(name.len() as u32));
	body.extend(name.as_bytes());
	body.extend([9u8; 16]);
	frame(&body)
}

fn handler(tune: impl FnOnce(&mut MinecraftProtocolConfig)) -> MinecraftProtocolHandler {
	let mut config = MinecraftProtocolConfig {
		timeout_secs: 5,
		..MinecraftProtocolConfig::default()
	};
	tune(&mut config);
	MinecraftProtocolHandler::new(&config, &["127.0.0.1:25566".to_string()])
}

/// Sends `payload` from a client, runs the handler on the accepted side and
/// returns its outcome (the client stays open while the handler runs).
async fn run(handler: &MinecraftProtocolHandler, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let mut client = TcpStream::connect(listener.local_addr()?).await?;
	let (mut server, _) = listener.accept().await?;
	client.write_all(payload).await?;
	let result = handler.handshake(&mut server).await;
	drop(client);
	result.map(|r| r.initial_backend_data)
}

fn counter(result: &str, reason: &str) -> u64 {
	MC_HANDSHAKE_TOTAL.with_label_values(&[result, reason]).get()
}

#[tokio::test]
async fn valid_login_is_replayed_byte_for_byte() -> anyhow::Result<()> {
	let mut payload = handshake(765, "mc.example.com", 2);
	payload.extend(login("Steve_01"));
	let before = counter("accepted", "ok");
	let replay = run(&handler(|_| {}), &payload).await?;
	assert_eq!(replay, payload);
	assert!(counter("accepted", "ok") > before);
	Ok(())
}

#[tokio::test]
async fn valid_status_request_is_replayed() -> anyhow::Result<()> {
	let mut payload = handshake(47, "mc.example.com", 1);
	payload.extend(frame(&[0]));
	assert_eq!(run(&handler(|_| {}), &payload).await?, payload);
	Ok(())
}

#[tokio::test]
async fn bad_clients_are_rejected_and_counted_by_reason() -> anyhow::Result<()> {
	let cases: Vec<(&str, Vec<u8>)> = vec![
		("empty_hostname", [handshake(765, "", 2), login("Steve")].concat()),
		("bad_next_state", [handshake(765, "h", 9), login("Steve")].concat()),
		("bad_username", [handshake(765, "h", 2), login("bad name!")].concat()),
		(
			"duplicate_handshake",
			[handshake(765, "h", 2), handshake(765, "h", 2)].concat(),
		),
		("login_before_handshake", login("Steve")),
		("implausible_version", [handshake(0, "h", 2), login("Steve")].concat()),
		("bad_status_request", [handshake(765, "h", 1), frame(&[0, 0])].concat()),
	];
	for (reason, payload) in cases {
		let before = counter("rejected", reason);
		assert!(run(&handler(|_| {}), &payload).await.is_err(), "{reason}");
		assert!(counter("rejected", reason) > before, "{reason}");
	}
	Ok(())
}

#[tokio::test]
async fn denied_version_is_rejected_and_version_label_is_bounded() -> anyhow::Result<()> {
	let strict = handler(|c| c.deny_protocol_versions = vec![765]);
	let mut payload = handshake(765, "h", 2);
	payload.extend(login("Steve"));
	assert!(run(&strict, &payload).await.is_err());
	let known = MC_PROTOCOL_VERSION_TOTAL.with_label_values(&["1.20.3-4"]).get();
	assert!(known >= 1);
	let other_before = MC_PROTOCOL_VERSION_TOTAL.with_label_values(&["other"]).get();
	let mut unknown = handshake(31_337, "h", 2);
	unknown.extend(login("Steve"));
	assert!(run(&handler(|_| {}), &unknown).await.is_ok());
	assert!(MC_PROTOCOL_VERSION_TOTAL.with_label_values(&["other"]).get() > other_before);
	Ok(())
}

#[tokio::test]
async fn oversized_declared_frames_are_rejected_without_a_body() -> anyhow::Result<()> {
	// Only the length prefix is sent: rejection must not wait for the body.
	let handler = handler(|c| c.timeout_secs = 30);
	let started = std::time::Instant::now();
	let before = counter("rejected", "frame_too_large");
	let result = run(&handler, &varint(2049)).await;
	assert!(result.is_err());
	let mut login_phase = handshake(765, "h", 2);
	login_phase.extend(varint(5121));
	assert!(run(&handler, &login_phase).await.is_err());
	let mut status_phase = handshake(765, "h", 1);
	status_phase.extend(varint(65));
	assert!(run(&handler, &status_phase).await.is_err());
	assert!(started.elapsed() < Duration::from_secs(5));
	// Counters are process-global and other tests run in parallel.
	assert!(counter("rejected", "frame_too_large") >= before + 3);
	Ok(())
}

#[tokio::test]
async fn frame_caps_are_configurable_and_clamped_to_the_global_ceiling() -> anyhow::Result<()> {
	let mut long_host = handshake(765, &"a".repeat(200), 2);
	long_host.extend(login("Steve"));
	assert!(run(&handler(|_| {}), &long_host).await.is_ok());
	let tight = handler(|c| c.max_handshake_bytes = 32);
	assert!(run(&tight, &long_host).await.is_err());
	let ceiling = handler(|c| c.max_frame_bytes = 40);
	assert!(run(&ceiling, &long_host).await.is_err());
	Ok(())
}

#[tokio::test]
async fn read_frame_checks_cap_before_reading_the_body() {
	let (mut writer, mut reader) = tokio::io::duplex(64);
	writer.write_all(&varint(100)).await.expect("write prefix");
	assert_eq!(
		read_frame(&mut reader, 99).await.expect_err("must be rejected"),
		Reason::FrameTooLarge
	);
	let mut zero = &[0u8][..];
	assert_eq!(
		read_frame(&mut zero, 10).await.expect_err("must be rejected"),
		Reason::FrameLength
	);
	let mut overlong = &[0x80u8, 0x80, 0x80, 0x80, 0x80, 0x01][..];
	assert_eq!(
		read_frame(&mut overlong, 10).await.expect_err("must be rejected"),
		Reason::Malformed
	);
}

#[tokio::test]
async fn silent_client_times_out_and_is_counted() -> anyhow::Result<()> {
	let quick = handler(|c| c.timeout_secs = 1);
	let before = counter("rejected", "timeout");
	assert!(run(&quick, &[]).await.is_err());
	assert!(counter("rejected", "timeout") > before);
	Ok(())
}
