//! Strict, bounded parser for trusted inbound PROXY protocol v2 headers.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const FIXED_HEADER_BYTES: usize = 16;

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
    let mut fixed = [0u8; FIXED_HEADER_BYTES];
    stream.read_exact(&mut fixed).await?;

    if fixed[..12] != SIGNATURE {
        anyhow::bail!("invalid inbound PROXY protocol signature");
    }
    if fixed[12] != 0x21 {
        anyhow::bail!("inbound PROXY protocol requires version 2 PROXY command");
    }

    let payload_len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    let total_len = FIXED_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| anyhow::anyhow!("inbound PROXY header length overflow"))?;
    if total_len > max_header_bytes {
        anyhow::bail!("inbound PROXY header exceeds configured limit");
    }

    let address_len = match fixed[13] {
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

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    match fixed[13] {
        0x11 => {
            let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(SocketAddr::V4(SocketAddrV4::new(source, port)))
        },
        0x21 => {
            let source_bytes: [u8; 16] = payload[..16]
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid inbound PROXY IPv6 source address"))?;
            let source = Ipv6Addr::from(source_bytes);
            let port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(SocketAddr::V6(SocketAddrV6::new(source, port, 0, 0)))
        },
        family => anyhow::bail!("unsupported inbound PROXY address family/protocol 0x{family:02x}"),
    }
}
