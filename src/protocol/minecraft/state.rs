//! Handshake -> status/login state machine.
//!
//! Fed one frame body at a time; it decides which packet shapes are legal in the
//! current phase and reports a closed [`Reason`] for everything else.

use super::parser::{self, Handshake, NextState};
use super::policy::Policy;
use super::reason::Reason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
	Handshake,
	/// Handshake done, waiting for the status request.
	Status,
	/// Handshake done, waiting for login-start.
	Login,
	/// Status request or login-start seen; later packets are not inspected.
	Established,
}

/// What a successfully validated frame was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
	Handshake(Handshake),
	StatusRequest,
	LoginStart,
	/// A later packet that this proxy does not inspect (encrypted or opaque).
	Passthrough,
}

pub struct Session<'a> {
	policy: &'a Policy,
	phase: Phase,
	started: Option<NextState>,
}

impl<'a> Session<'a> {
	#[must_use]
	pub fn new(policy: &'a Policy) -> Self {
		Self {
			policy,
			phase: Phase::Handshake,
			started: None,
		}
	}

	#[must_use]
	pub fn phase(&self) -> Phase {
		self.phase
	}

	/// Maximum frame length the next frame may declare in this phase.
	#[must_use]
	pub fn frame_cap(&self) -> usize {
		match self.phase {
			Phase::Handshake => self.policy.handshake_cap,
			Phase::Status => self.policy.status_request_cap,
			Phase::Login => self.policy.login_start_cap,
			Phase::Established => self.policy.max_frame_bytes,
		}
	}

	/// Validates one frame body and advances the phase.
	///
	/// # Errors
	/// Returns the [`Reason`] the connection must be dropped for.
	pub fn feed(&mut self, body: &[u8]) -> Result<Step, Reason> {
		match self.phase {
			Phase::Handshake => self.on_handshake(body),
			Phase::Status => self.on_status(body),
			Phase::Login => self.on_login(body),
			Phase::Established => self.on_established(body),
		}
	}

	fn on_handshake(&mut self, body: &[u8]) -> Result<Step, Reason> {
		let handshake = match parser::parse_handshake(body) {
			Ok(handshake) => handshake,
			Err(_) if parser::parse_login_start(body, self.policy).is_ok() => return Err(Reason::LoginBeforeHandshake),
			Err(reason) => return Err(reason),
		};
		self.policy.check_version(handshake.protocol_version)?;
		self.phase = match handshake.next_state {
			NextState::Status => Phase::Status,
			NextState::Login | NextState::Transfer => Phase::Login,
		};
		self.started = Some(handshake.next_state);
		Ok(Step::Handshake(handshake))
	}

	fn on_status(&mut self, body: &[u8]) -> Result<Step, Reason> {
		if body == [0] {
			self.phase = Phase::Established;
			return Ok(Step::StatusRequest);
		}
		Err(self.misplaced(body).unwrap_or(Reason::BadStatusRequest))
	}

	fn on_login(&mut self, body: &[u8]) -> Result<Step, Reason> {
		match parser::parse_login_start(body, self.policy) {
			Ok(()) => {
				self.phase = Phase::Established;
				Ok(Step::LoginStart)
			},
			Err(reason) => Err(self.misplaced(body).unwrap_or(reason)),
		}
	}

	fn on_established(&mut self, body: &[u8]) -> Result<Step, Reason> {
		if let Some(reason) = self.misplaced(body) {
			return Err(reason);
		}
		let is_packet_zero = parser::decode_varint(body, 0).is_ok_and(|(id, _)| id == 0);
		match (self.started, is_packet_zero) {
			(Some(NextState::Login | NextState::Transfer), true)
				if parser::parse_login_start(body, self.policy).is_ok() =>
			{
				Err(Reason::DuplicateLoginStart)
			},
			(Some(NextState::Status), true) if body == [0] => Err(Reason::BadStatusRequest),
			_ => Ok(Step::Passthrough),
		}
	}

	/// Detects a handshake sent in a later phase.
	fn misplaced(&self, body: &[u8]) -> Option<Reason> {
		parser::parse_handshake(body).ok().map(|_| Reason::DuplicateHandshake)
	}
}
