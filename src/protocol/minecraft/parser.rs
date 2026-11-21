//! Bounded parsers for the Minecraft Java handshake and login-start packets.
//!
//! Parsers take the frame body (packet id onward, without the length prefix) and
//! never allocate based on client-declared lengths.

use super::policy::Policy;
use super::reason::Reason;

const MAX_VARINT_BYTES: usize = 5;
const MAX_HOST_CHARS: usize = 255;
/// A UTF-8 character takes at most four bytes.
const MAX_UTF8_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextState {
	Status,
	Login,
	/// Protocol 766+ transfer intent; handled like login.
	Transfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handshake {
	pub protocol_version: i32,
	pub next_state: NextState,
}

/// Decodes the frame length prefix, returning `(length, prefix bytes)`.
///
/// # Errors
/// Returns [`Reason::Malformed`] for an over-long or negative VarInt.
pub fn decode_frame_length(prefix: &[u8]) -> Result<(usize, usize), Reason> {
	let (length, read) = decode_varint(prefix, 0)?;
	let length = usize::try_from(length).map_err(|_| Reason::Malformed)?;
	Ok((length, read))
}

/// Parses a handshake body. Independent of the protocol version.
///
/// # Errors
/// Returns the [`Reason`] for the first structural violation.
pub fn parse_handshake(body: &[u8]) -> Result<Handshake, Reason> {
	let (packet_id, cursor) = decode_varint(body, 0)?;
	if packet_id != 0 {
		return Err(Reason::UnexpectedPacket);
	}
	let (protocol_version, cursor) = decode_varint(body, cursor)?;
	if protocol_version < 0 {
		return Err(Reason::ImplausibleVersion);
	}
	let (host_len, cursor) = decode_varint(body, cursor)?;
	let host_len = usize::try_from(host_len).map_err(|_| Reason::OversizedHostname)?;
	if host_len == 0 {
		return Err(Reason::EmptyHostname);
	}
	if host_len > MAX_HOST_CHARS * MAX_UTF8_BYTES {
		return Err(Reason::OversizedHostname);
	}
	let host_end = cursor.checked_add(host_len).ok_or(Reason::Malformed)?;
	let host = body.get(cursor..host_end).ok_or(Reason::Malformed)?;
	let host = std::str::from_utf8(host).map_err(|_| Reason::BadHostname)?;
	if host.chars().count() > MAX_HOST_CHARS {
		return Err(Reason::OversizedHostname);
	}
	let port_end = host_end.checked_add(2).ok_or(Reason::Malformed)?;
	if body.get(host_end..port_end).is_none() {
		return Err(Reason::Malformed);
	}
	let (state, cursor) = decode_varint(body, port_end)?;
	if cursor != body.len() {
		return Err(Reason::Malformed);
	}
	let next_state = match state {
		1 => NextState::Status,
		2 => NextState::Login,
		3 => NextState::Transfer,
		_ => return Err(Reason::BadNextState),
	};
	Ok(Handshake {
		protocol_version,
		next_state,
	})
}

/// Parses a login-start body and validates the username.
///
/// Bytes after the name (UUID, signature data) differ per protocol version and
/// are bounded only by the frame cap.
///
/// # Errors
/// Returns the [`Reason`] for the first violation.
pub fn parse_login_start(body: &[u8], policy: &Policy) -> Result<(), Reason> {
	let (packet_id, cursor) = decode_varint(body, 0)?;
	if packet_id != 0 {
		return Err(Reason::UnexpectedPacket);
	}
	let (name_len, cursor) = decode_varint(body, cursor)?;
	let name_len = usize::try_from(name_len).map_err(|_| Reason::BadUsername)?;
	if name_len == 0 || name_len > policy.username_max_len * MAX_UTF8_BYTES {
		return Err(Reason::BadUsername);
	}
	let end = cursor.checked_add(name_len).ok_or(Reason::Malformed)?;
	let name = body.get(cursor..end).ok_or(Reason::Malformed)?;
	let name = std::str::from_utf8(name).map_err(|_| Reason::BadUsername)?;
	policy.check_username(name)
}

/// Decodes a signed Minecraft VarInt, returning the value and the next offset.
///
/// # Errors
/// Returns [`Reason::Malformed`] when truncated or longer than 32 bits.
pub fn decode_varint(bytes: &[u8], start: usize) -> Result<(i32, usize), Reason> {
	let mut value = 0u32;
	for index in 0..MAX_VARINT_BYTES {
		let byte = *bytes.get(start + index).ok_or(Reason::Malformed)?;
		if index == 4 && byte & 0xf0 != 0 {
			return Err(Reason::Malformed);
		}
		value |= u32::from(byte & 0x7f) << (index * 7);
		if byte & 0x80 == 0 {
			return Ok((value as i32, start + index + 1));
		}
	}
	Err(Reason::Malformed)
}
