//! Strict, bounded parser for trusted inbound PROXY protocol v2 headers.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Length of the fixed part that precedes the address block.
pub const FIXED_HEADER_BYTES: usize = 16;

/// Reads and validates an inbound PROXY protocol v2 header.
///
/// The whole header must arrive within `timeout`.
///
/// # Errors
/// Fails on timeout, on a bad signature or command, on an unsupported address
/// family, on TLVs, and on a header larger than `max_header_bytes`.
pub(crate) async fn read_v2_header(
	stream: &mut TcpStream,
	timeout: Duration,
	max_header_bytes: usize,
) -> anyhow::Result<SocketAddr> {
	tokio::time::timeout(timeout, read_v2_header_inner(stream, max_header_bytes))
		.await
		.map_err(|_| anyhow::anyhow!("timed out reading inbound PROXY v2 header"))?
}

async fn read_v2_header_inner(stream: &mut TcpStream, max_header_bytes: usize) -> anyhow::Result<SocketAddr> {
	let mut header = vec![0u8; FIXED_HEADER_BYTES];
	stream.read_exact(&mut header).await?;

	let payload_len = usize::from(u16::from_be_bytes([header[14], header[15]]));
	let total_len = FIXED_HEADER_BYTES
		.checked_add(payload_len)
		.ok_or_else(|| anyhow::anyhow!("inbound PROXY header length overflow"))?;
	if total_len > max_header_bytes {
		anyhow::bail!("inbound PROXY header exceeds configured limit");
	}

	header.resize(total_len, 0);
	stream.read_exact(&mut header[FIXED_HEADER_BYTES..]).await?;
	let (client, consumed) = parse_v2_header(&header, max_header_bytes)?;
	debug_assert_eq!(consumed, total_len, "parser must consume exactly one header");
	Ok(client)
}

/// Parses a complete inbound PROXY v2 header from `buf`.
///
/// Pure and total: every read is bounds-checked, so arbitrary bytes can only
/// produce an error, never a panic (covered by the `proxy_v2` fuzz target).
///
/// # Errors
/// Fails on a short buffer, bad signature or command, unsupported address
/// family, TLVs, and on a header larger than `max_header_bytes`.
pub fn parse_v2_header(buf: &[u8], max_header_bytes: usize) -> anyhow::Result<(SocketAddr, usize)> {
	if buf.len() < FIXED_HEADER_BYTES {
		anyhow::bail!("inbound PROXY header is truncated");
	}
	if buf[..12] != SIGNATURE {
		anyhow::bail!("invalid inbound PROXY protocol signature");
	}
	if buf[12] != 0x21 {
		anyhow::bail!("inbound PROXY protocol requires version 2 PROXY command");
	}

	let payload_len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
	let total_len = FIXED_HEADER_BYTES
		.checked_add(payload_len)
		.ok_or_else(|| anyhow::anyhow!("inbound PROXY header length overflow"))?;
	if total_len > max_header_bytes {
		anyhow::bail!("inbound PROXY header exceeds configured limit");
	}
	if buf.len() < total_len {
		anyhow::bail!("inbound PROXY header is truncated");
	}

	let address_len = match buf[13] {
		0x11 => 12,
		0x21 => 36,
		family => anyhow::bail!("unsupported inbound PROXY address family/protocol 0x{family:02x}"),
	};
	if payload_len < address_len {
		anyhow::bail!("inbound PROXY header is shorter than its address block");
	}
	if payload_len != address_len {
		anyhow::bail!("inbound PROXY v2 TLVs are not supported");
	}

	let payload = &buf[FIXED_HEADER_BYTES..total_len];
	let client = match buf[13] {
		0x11 => {
			let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
			let port = u16::from_be_bytes([payload[8], payload[9]]);
			SocketAddr::V4(SocketAddrV4::new(source, port))
		},
		_ => {
			let source_bytes: [u8; 16] = payload[..16]
				.try_into()
				.map_err(|_| anyhow::anyhow!("invalid inbound PROXY IPv6 source address"))?;
			let source = Ipv6Addr::from(source_bytes);
			let port = u16::from_be_bytes([payload[32], payload[33]]);
			SocketAddr::V6(SocketAddrV6::new(source, port, 0, 0))
		},
	};
	Ok((client, total_len))
}
