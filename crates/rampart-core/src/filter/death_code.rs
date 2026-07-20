use crate::proxy::handshake::{read_string, read_varint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeathCode {
    EmptyPacket,
    PacketTooShort,
    InvalidPacketId,
    NegativeProtocolVersion,
    NonCanonicalVarint,
    NullByteInHostname,
    UnprintableHostname,
    MalformedPacket,
}

impl DeathCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyPacket => "empty_packet",
            Self::PacketTooShort => "packet_too_short",
            Self::InvalidPacketId => "invalid_packet_id",
            Self::NegativeProtocolVersion => "negative_protocol_version",
            Self::NonCanonicalVarint => "non_canonical_varint",
            Self::NullByteInHostname => "null_byte_in_hostname",
            Self::UnprintableHostname => "unprintable_hostname",
            Self::MalformedPacket => "malformed_packet",
        }
    }
}

pub fn detect(buf: &[u8]) -> Option<DeathCode> {
    if buf.is_empty() {
        return Some(DeathCode::EmptyPacket);
    }

    if buf.len() < 3 {
        return Some(DeathCode::PacketTooShort);
    }

    let (packet_len, after_len) = match read_varint(buf, 0) {
        Ok(r) => r,
        Err(_) => return Some(DeathCode::MalformedPacket),
    };

    if !is_canonical_varint(buf, 0) {
        return Some(DeathCode::NonCanonicalVarint);
    }

    if packet_len <= 0 || (after_len + packet_len as usize) > buf.len() {
        return Some(DeathCode::MalformedPacket);
    }

    let (packet_id, after_id) = match read_varint(buf, after_len) {
        Ok(r) => r,
        Err(_) => return Some(DeathCode::MalformedPacket),
    };

    if !is_canonical_varint(buf, after_len) {
        return Some(DeathCode::NonCanonicalVarint);
    }

    if packet_id != 0x00 {
        return Some(DeathCode::InvalidPacketId);
    }

    let (_protocol_version, after_pv) = match read_varint(buf, after_id) {
        Ok(r) => r,
        Err(_) => return Some(DeathCode::MalformedPacket),
    };

    if !is_canonical_varint(buf, after_id) {
        return Some(DeathCode::NonCanonicalVarint);
    }

    let (server_address, _) = match read_string(buf, after_pv) {
        Ok(r) => r,
        Err(_) => return Some(DeathCode::MalformedPacket),
    };

    if !is_canonical_varint(buf, after_pv) {
        return Some(DeathCode::NonCanonicalVarint);
    }

    if server_address.contains('\0') {
        return Some(DeathCode::NullByteInHostname);
    }

    if !server_address.chars().all(|c| c.is_ascii_graphic() || c == '.') {
        return Some(DeathCode::UnprintableHostname);
    }

    None
}

fn is_canonical_varint(buf: &[u8], start: usize) -> bool {
    let mut value: u32 = 0;
    let mut shift = 0;
    let mut bytes_used = 0;

    for (i, &byte) in buf[start..].iter().enumerate() {
        if i >= 5 {
            return false;
        }
        bytes_used = i + 1;
        value |= ((byte & 0x7F) as u32) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
    }

    if bytes_used >= 5 {
        return false;
    }

    let min_varint = |val: u32| -> usize {
        if val == 0 {
            return 1;
        }
        let mut bits = 32 - val.leading_zeros();
        let mut bytes = 0;
        while bits > 0 {
            bytes += 1;
            bits = bits.saturating_sub(7);
        }
        bytes.max(1)
    };

    bytes_used == min_varint(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_varint(buf: &mut Vec<u8>, mut value: i32) {
        loop {
            if (value & !0x7F) == 0 {
                buf.push(value as u8);
                return;
            }
            buf.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
    }

    fn build_handshake_raw(hostname: &str) -> Vec<u8> {
        let addr = hostname.as_bytes();
        let mut buf = Vec::new();
        buf.push(0x00);
        write_varint(&mut buf, 765);
        write_varint(&mut buf, addr.len() as i32);
        buf.extend_from_slice(addr);
        buf.extend_from_slice(&[0x63, 0xDD]);
        buf.push(0x02);

        let len = buf.len() as i32;
        let mut pkt = Vec::new();
        write_varint(&mut pkt, len);
        pkt.extend_from_slice(&buf);
        pkt
    }

    #[test]
    fn test_valid_handshake() {
        let pkt = build_handshake_raw("play.example.com");
        assert_eq!(detect(&pkt), None);
    }

    #[test]
    fn test_empty_packet() {
        assert_eq!(detect(&[]), Some(DeathCode::EmptyPacket));
    }

    #[test]
    fn test_null_byte_in_hostname() {
        let pkt = build_handshake_raw("play.example.com\0extra");
        assert_eq!(detect(&pkt), Some(DeathCode::NullByteInHostname));
    }

    #[test]
    fn test_non_canonical_varint() {
        let pkt: Vec<u8> = vec![0x08, 0x00, 0x80, 0x00, 0x02, b'e', b'x', 0x63, 0xDD, 0x02];
        assert_eq!(detect(&pkt), Some(DeathCode::NonCanonicalVarint));
    }

    #[test]
    fn test_invalid_packet_id() {
        let addr = b"play.example.com";
        let mut buf = Vec::new();
        write_varint(&mut buf, 1);
        buf.extend_from_slice(addr);
        buf.extend_from_slice(&[0x63, 0xDD]);
        buf.push(0x02);

        let len = buf.len() as i32;
        let mut pkt = Vec::new();
        write_varint(&mut pkt, len);
        pkt.extend_from_slice(&buf);
        assert_eq!(detect(&pkt), Some(DeathCode::InvalidPacketId));
    }

    #[test]
    fn test_unprintable_hostname() {
        let pkt = build_handshake_raw("play\x01example.com");
        assert_eq!(detect(&pkt), Some(DeathCode::UnprintableHostname));
    }
}
