use std::net::SocketAddr;

mod inbound;
pub(super) use inbound::read_v2_header;

/// Encodes a PROXY protocol v2 TCP header for the backend.
/// The backend must accept connections only from trusted Rampart nodes.
pub(super) fn protocol_v2(source: SocketAddr, destination: SocketAddr) -> anyhow::Result<Vec<u8>> {
    const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
    if source.is_ipv4() != destination.is_ipv4() {
        anyhow::bail!("PROXY protocol source/destination address families differ");
    }

    let (family, address_len) = if source.is_ipv4() {
        (0x11, 12usize)
    } else {
        (0x21, 36usize)
    };
    let mut header = Vec::with_capacity(16 + address_len);
    header.extend_from_slice(&SIGNATURE);
    header.push(0x21);
    header.push(family);
    header.extend_from_slice(&(address_len as u16).to_be_bytes());
    match (source, destination) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        },
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        },
        _ => anyhow::bail!("PROXY protocol source/destination address families differ"),
    }
    Ok(header)
}
