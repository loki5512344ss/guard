//! Bounded parser for the Minecraft Java handshake packet.

const HANDSHAKE_PACKET_ID: i32 = 0;
const MAX_VARINT_BYTES: usize = 5;
const MAX_HOST_BYTES: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NextState {
    Status,
    Login,
}

pub(super) fn decode_frame_length(prefix: &[u8]) -> anyhow::Result<(usize, usize)> {
    let (length, bytes_read) = decode_varint(prefix, 0)?;
    let length = usize::try_from(length).map_err(|_| anyhow::anyhow!("negative frame length"))?;
    Ok((length, bytes_read))
}

/// Validates a complete length-prefixed handshake frame and returns its state.
pub(super) fn parse_frame(frame: &[u8], max_frame_bytes: usize) -> anyhow::Result<NextState> {
    let (frame_len, prefix_len) = decode_varint(frame, 0)?;
    let frame_len = usize::try_from(frame_len).map_err(|_| anyhow::anyhow!("negative frame length"))?;
    if frame_len == 0 || frame_len > max_frame_bytes {
        anyhow::bail!("Minecraft handshake frame length {frame_len} is outside allowed range");
    }
    if frame.len() != prefix_len + frame_len {
        anyhow::bail!("Minecraft handshake frame length does not match packet");
    }

    let body = &frame[prefix_len..];
    let (packet_id, mut cursor) = decode_varint(body, 0)?;
    if packet_id != HANDSHAKE_PACKET_ID {
        anyhow::bail!("unexpected Minecraft packet id {packet_id} in handshake state");
    }

    let (protocol_version, next) = decode_varint(body, cursor)?;
    if protocol_version < 0 {
        anyhow::bail!("Minecraft protocol version must be non-negative");
    }
    cursor = next;

    let (host_len, next) = decode_varint(body, cursor)?;
    let host_len = usize::try_from(host_len).map_err(|_| anyhow::anyhow!("negative host length"))?;
    if host_len == 0 || host_len > MAX_HOST_BYTES {
        anyhow::bail!("Minecraft handshake hostname length is outside allowed range");
    }
    cursor = next;
    let host_end = cursor
        .checked_add(host_len)
        .ok_or_else(|| anyhow::anyhow!("hostname length overflow"))?;
    let host_bytes = body
        .get(cursor..host_end)
        .ok_or_else(|| anyhow::anyhow!("truncated Minecraft handshake hostname"))?;
    std::str::from_utf8(host_bytes).map_err(|_| anyhow::anyhow!("Minecraft handshake hostname is not UTF-8"))?;
    cursor = host_end;

    let port_end = cursor
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("port length overflow"))?;
    if body.get(cursor..port_end).is_none() {
        anyhow::bail!("truncated Minecraft handshake port");
    }
    cursor = port_end;

    let (state, next) = decode_varint(body, cursor)?;
    cursor = next;
    if cursor != body.len() {
        anyhow::bail!("unexpected trailing bytes in Minecraft handshake");
    }

    match state {
        1 => Ok(NextState::Status),
        2 => Ok(NextState::Login),
        _ => anyhow::bail!("unsupported Minecraft next state {state}; expected status or login"),
    }
}

/// Decodes signed Minecraft VarInt from a packet, returning value and next offset.
fn decode_varint(bytes: &[u8], start: usize) -> anyhow::Result<(i32, usize)> {
    let mut value = 0u32;
    for index in 0..MAX_VARINT_BYTES {
        let byte = *bytes
            .get(start + index)
            .ok_or_else(|| anyhow::anyhow!("truncated Minecraft VarInt"))?;
        if index == 4 && byte & 0xf0 != 0 {
            anyhow::bail!("Minecraft VarInt exceeds 32 bits");
        }
        value |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value as i32, start + index + 1));
        }
    }
    anyhow::bail!("Minecraft VarInt exceeds five bytes")
}
