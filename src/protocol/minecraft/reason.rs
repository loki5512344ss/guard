//! Closed set of reasons a Minecraft handshake is accepted or rejected.
//!
//! The `as_str` values are used as Prometheus label values, so the set must stay
//! small and must never be built from client input.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
	Ok,
	FrameLength,
	FrameTooLarge,
	Malformed,
	UnexpectedPacket,
	EmptyHostname,
	OversizedHostname,
	BadHostname,
	DuplicateHandshake,
	LoginBeforeHandshake,
	DuplicateLoginStart,
	BadNextState,
	ImplausibleVersion,
	VersionBelowMin,
	VersionAboveMax,
	VersionDenied,
	BadUsername,
	BadStatusRequest,
	Timeout,
	Io,
}

impl Reason {
	/// Every reason, for exhaustive tests and documentation.
	pub const ALL: [Reason; 20] = [
		Reason::Ok,
		Reason::FrameLength,
		Reason::FrameTooLarge,
		Reason::Malformed,
		Reason::UnexpectedPacket,
		Reason::EmptyHostname,
		Reason::OversizedHostname,
		Reason::BadHostname,
		Reason::DuplicateHandshake,
		Reason::LoginBeforeHandshake,
		Reason::DuplicateLoginStart,
		Reason::BadNextState,
		Reason::ImplausibleVersion,
		Reason::VersionBelowMin,
		Reason::VersionAboveMax,
		Reason::VersionDenied,
		Reason::BadUsername,
		Reason::BadStatusRequest,
		Reason::Timeout,
		Reason::Io,
	];

	/// Stable label value for metrics and logs.
	#[must_use]
	pub fn as_str(self) -> &'static str {
		match self {
			Reason::Ok => "ok",
			Reason::FrameLength => "frame_length",
			Reason::FrameTooLarge => "frame_too_large",
			Reason::Malformed => "malformed",
			Reason::UnexpectedPacket => "unexpected_packet",
			Reason::EmptyHostname => "empty_hostname",
			Reason::OversizedHostname => "oversized_hostname",
			Reason::BadHostname => "bad_hostname",
			Reason::DuplicateHandshake => "duplicate_handshake",
			Reason::LoginBeforeHandshake => "login_before_handshake",
			Reason::DuplicateLoginStart => "duplicate_login_start",
			Reason::BadNextState => "bad_next_state",
			Reason::ImplausibleVersion => "implausible_version",
			Reason::VersionBelowMin => "version_below_min",
			Reason::VersionAboveMax => "version_above_max",
			Reason::VersionDenied => "version_denied",
			Reason::BadUsername => "bad_username",
			Reason::BadStatusRequest => "bad_status_request",
			Reason::Timeout => "timeout",
			Reason::Io => "io",
		}
	}

	/// Metrics `result` label: `accepted` only for [`Reason::Ok`].
	#[must_use]
	pub fn result(self) -> &'static str {
		if self == Reason::Ok { "accepted" } else { "rejected" }
	}
}

impl fmt::Display for Reason {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl std::error::Error for Reason {}
