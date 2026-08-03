use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Incomplete packet: {0}")]
    Incomplete(&'static str),
    #[error("VarInt too big (>5 bytes)")]
    VarIntTooBig,
    #[error("VarInt overflow")]
    VarIntOverflow,
    #[error("Invalid UTF-8 in string")]
    InvalidUtf8,
    #[error("String too long: {0}")]
    StringTooLong(usize),
    #[error("Hostname too long")]
    HostnameTooLong,
    #[error("Not a handshake packet: id={0}")]
    NotHandshake(i32),
}

#[derive(Debug, Clone, PartialEq)]
pub enum NextState {
    Status,
    Login,
    Unknown(i32),
}

#[derive(Debug, Clone)]
pub struct McHandshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: NextState,
}

impl McHandshake {
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let mut pos;
        let (_, after_len) = read_varint(buf, 0)?;
        pos = after_len;

        let (packet_id, after_id) = read_varint(buf, pos)?;
        pos = after_id;
        if packet_id != 0x00 {
            return Err(ParseError::NotHandshake(packet_id));
        }

        let (protocol_version, after_pv) = read_varint(buf, pos)?;
        pos = after_pv;

        let (server_address, after_addr) = read_string(buf, pos)?;
        pos = after_addr;

        if server_address.len() > 255 {
            return Err(ParseError::HostnameTooLong);
        }

        if pos + 2 > buf.len() {
            return Err(ParseError::Incomplete("missing port"));
        }
        let server_port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;

        let (next_state_raw, _) = read_varint(buf, pos)?;
        let next_state = match next_state_raw {
            1 => NextState::Status,
            2 => NextState::Login,
            n => NextState::Unknown(n),
        };

        Ok(McHandshake {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }

    pub fn is_login(&self) -> bool {
        self.next_state == NextState::Login
    }
}

pub fn read_varint(buf: &[u8], start: usize) -> Result<(i32, usize), ParseError> {
    let mut value: i32 = 0;
    let mut shift = 0;

    for (i, &byte) in buf[start..].iter().enumerate() {
        if i >= 5 {
            return Err(ParseError::VarIntTooBig);
        }
        let segment = (byte & 0x7F) as i32;
        if shift >= 32 || (shift == 28 && segment > 0x0F) {
            return Err(ParseError::VarIntOverflow);
        }
        value |= segment << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            return Ok((value, start + i + 1));
        }
    }
    Err(ParseError::Incomplete("varint"))
}

pub fn read_string(buf: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let (len, after_len) = read_varint(buf, start)?;
    if !(0..=32767).contains(&len) {
        return Err(ParseError::StringTooLong(len as usize));
    }
    let end = after_len + len as usize;
    if end > buf.len() {
        return Err(ParseError::Incomplete("string data"));
    }
    let s = std::str::from_utf8(&buf[after_len..end])
        .map_err(|_| ParseError::InvalidUtf8)?
        .to_string();
    Ok((s, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_zero() {
        let buf = vec![0x00];
        assert_eq!(read_varint(&buf, 0).expect("varint should parse"), (0, 1));
    }

    #[test]
    fn test_varint_single() {
        let buf = vec![0x7F];
        assert_eq!(read_varint(&buf, 0).expect("varint should parse"), (127, 1));
    }

    #[test]
    fn test_varint_multi() {
        let buf = vec![0x80, 0x01];
        assert_eq!(read_varint(&buf, 0).expect("varint should parse"), (128, 2));
    }

    #[test]
    fn test_varint_max() {
        let buf = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        assert_eq!(read_varint(&buf, 0).expect("varint should parse"), (i32::MAX, 5));
    }

    #[test]
    fn test_varint_overflow() {
        let buf = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x10];
        assert!(matches!(read_varint(&buf, 0), Err(ParseError::VarIntOverflow)));
    }

    #[test]
    fn test_varint_incomplete() {
        let buf = vec![0x80];
        assert!(matches!(read_varint(&buf, 0), Err(ParseError::Incomplete(_))));
    }

    #[test]
    fn test_handshake_login() {
        let addr = b"play.example.com";
        let mut buf = Vec::new();

        buf.extend_from_slice(&[0x00]);
        buf.push(0x00);
        write_varint(&mut buf, 765);
        write_varint(&mut buf, addr.len() as i32);
        buf.extend_from_slice(addr);
        buf.extend_from_slice(&[0x63, 0xDD]);
        buf.push(0x02);

        let len = (buf.len() - 1) as u8;
        buf[0] = len;

        let hs = McHandshake::parse(&buf).expect("valid login handshake should parse");
        assert_eq!(hs.protocol_version, 765);
        assert_eq!(hs.server_address, "play.example.com");
        assert_eq!(hs.server_port, 25565);
        assert!(hs.is_login());
    }

    fn write_varint(buf: &mut Vec<u8>, mut value: i32) {
        loop {
            if (value & !0x7F) == 0 {
                buf.push(value as u8);
                return;
            }
            buf.push((value as u8 & 0x7F) | 0x80);
            value = (value >> 7) & (i32::MAX >> 6);
        }
    }

    #[test]
    fn test_handshake_status() {
        let addr = b"play.example";
        let mut buf = Vec::new();
        // packet length will be set below
        buf.push(0x00);
        buf.push(0x00); // packet ID
        buf.push(0x02); // protocol version 2
        write_varint(&mut buf, addr.len() as i32);
        buf.extend_from_slice(addr);
        buf.extend_from_slice(&[0x63, 0xDD]); // port 25565
        buf.push(0x01); // next state = status
        let len = (buf.len() - 1) as u8;
        buf[0] = len;

        let hs = McHandshake::parse(&buf).expect("valid status handshake should parse");
        assert_eq!(hs.protocol_version, 2);
        assert_eq!(hs.server_address, "play.example");
        assert_eq!(hs.server_port, 25565);
        assert_eq!(hs.next_state, NextState::Status);
    }
}
