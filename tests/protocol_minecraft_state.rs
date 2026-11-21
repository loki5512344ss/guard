//! Minecraft handshake/login state machine, parsers, version policy and the
//! closed reason set.
#![cfg(feature = "protocol-minecraft")]

use rampart::config::{MinecraftProtocolConfig, UsernameCharset};
use rampart::protocol::minecraft::parser::{NextState, parse_handshake};
use rampart::protocol::minecraft::policy::{Policy, versions};
use rampart::protocol::minecraft::reason::Reason;
use rampart::protocol::minecraft::state::{Phase, Session, Step};

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

fn handshake_body(version: u32, host: &str, state: u32) -> Vec<u8> {
	let mut body = varint(0);
	body.extend(varint(version));
	body.extend(varint(host.len() as u32));
	body.extend(host.as_bytes());
	body.extend(25565u16.to_be_bytes());
	body.extend(varint(state));
	body
}

fn login_body(name: &str) -> Vec<u8> {
	let mut body = varint(0);
	body.extend(varint(name.len() as u32));
	body.extend(name.as_bytes());
	body.extend([7u8; 16]);
	body
}

fn policy_with(tune: impl FnOnce(&mut MinecraftProtocolConfig)) -> Policy {
	let mut config = MinecraftProtocolConfig::default();
	tune(&mut config);
	Policy::from_config(&config)
}

fn default_policy() -> Policy {
	policy_with(|_| {})
}

#[test]
fn valid_login_flow_is_accepted() {
	let policy = default_policy();
	let mut session = Session::new(&policy);
	assert!(matches!(
		session.feed(&handshake_body(765, "mc.example.com", 2)),
		Ok(Step::Handshake(_))
	));
	assert_eq!(session.phase(), Phase::Login);
	assert_eq!(session.feed(&login_body("Steve_01")), Ok(Step::LoginStart));
	assert_eq!(session.phase(), Phase::Established);
}

#[test]
fn valid_status_flow_and_transfer_state_are_accepted() {
	let policy = default_policy();
	let mut session = Session::new(&policy);
	assert!(session.feed(&handshake_body(47, "h", 1)).is_ok());
	assert_eq!(session.feed(&[0]), Ok(Step::StatusRequest));
	let mut transfer = Session::new(&policy);
	assert!(transfer.feed(&handshake_body(766, "h", 3)).is_ok());
	assert_eq!(transfer.phase(), Phase::Login);
}

#[test]
fn handshake_hostname_bounds() {
	assert_eq!(parse_handshake(&handshake_body(765, "", 2)), Err(Reason::EmptyHostname));
	let long = "a".repeat(256);
	assert_eq!(
		parse_handshake(&handshake_body(765, &long, 2)),
		Err(Reason::OversizedHostname)
	);
	let max = "a".repeat(255);
	assert!(parse_handshake(&handshake_body(765, &max, 2)).is_ok());
}

#[test]
fn next_state_must_be_status_login_or_transfer() {
	for state in [0, 4, 99] {
		assert_eq!(
			parse_handshake(&handshake_body(765, "h", state)),
			Err(Reason::BadNextState)
		);
	}
	assert_eq!(
		parse_handshake(&handshake_body(765, "h", 3)).map(|h| h.next_state),
		Ok(NextState::Transfer)
	);
}

#[test]
fn login_start_before_handshake_is_rejected() {
	let policy = default_policy();
	let mut session = Session::new(&policy);
	assert_eq!(session.feed(&login_body("Steve")), Err(Reason::LoginBeforeHandshake));
}

#[test]
fn second_handshake_is_rejected_in_every_phase() {
	let policy = default_policy();
	let again = handshake_body(765, "mc.example.com", 2);
	let mut login = Session::new(&policy);
	login.feed(&again).expect("first handshake");
	assert_eq!(login.feed(&again), Err(Reason::DuplicateHandshake));
	let mut status = Session::new(&policy);
	status.feed(&handshake_body(765, "h", 1)).expect("first handshake");
	assert_eq!(status.feed(&again), Err(Reason::DuplicateHandshake));
	let mut done = Session::new(&policy);
	done.feed(&again).expect("first handshake");
	done.feed(&login_body("Steve")).expect("login");
	assert_eq!(done.feed(&again), Err(Reason::DuplicateHandshake));
}

#[test]
fn second_login_start_is_rejected_but_encryption_response_passes() {
	let policy = default_policy();
	let mut session = Session::new(&policy);
	session.feed(&handshake_body(765, "h", 2)).expect("handshake");
	session.feed(&login_body("Steve")).expect("login");
	assert_eq!(session.feed(&login_body("Alex")), Err(Reason::DuplicateLoginStart));
	assert_eq!(session.feed(&[1, 0, 0]), Ok(Step::Passthrough));
}

#[test]
fn bad_status_requests_are_rejected() {
	let policy = default_policy();
	let mut session = Session::new(&policy);
	session.feed(&handshake_body(765, "h", 1)).expect("handshake");
	assert_eq!(session.feed(&[0, 0]), Err(Reason::BadStatusRequest));
	let mut twice = Session::new(&policy);
	twice.feed(&handshake_body(765, "h", 1)).expect("handshake");
	twice.feed(&[0]).expect("status request");
	assert_eq!(twice.feed(&[0]), Err(Reason::BadStatusRequest));
	assert_eq!(twice.feed(&[1, 0, 0, 0, 0, 0, 0, 0, 1]), Ok(Step::Passthrough));
}

#[test]
fn usernames_are_validated() {
	let policy = default_policy();
	for good in ["Steve", "a", "Player_123", "x_y_z_0123456789", ".Floodgate"] {
		assert_eq!(policy.check_username(good), Ok(()), "{good}");
	}
	for bad in ["", "seventeen_chars_ab", "has space", "tab\t", "caf\u{e9}"] {
		assert_eq!(policy.check_username(bad), Err(Reason::BadUsername), "{bad:?}");
	}
	let mut session = Session::new(&policy);
	session.feed(&handshake_body(765, "h", 2)).expect("handshake");
	assert_eq!(
		session.feed(&login_body("seventeen_chars_ab")),
		Err(Reason::BadUsername)
	);
}

#[test]
fn username_policy_is_configurable() {
	let any = policy_with(|c| {
		c.username_charset = UsernameCharset::Any;
		c.username_max_len = 32;
	});
	assert_eq!(any.check_username("caf\u{e9}"), Ok(()));
	assert_eq!(any.check_username(&"a".repeat(32)), Ok(()));
	assert_eq!(any.check_username("bell\u{7}"), Err(Reason::BadUsername));
	let ascii = policy_with(|c| c.username_charset = UsernameCharset::Ascii);
	assert_eq!(ascii.check_username("a!b#"), Ok(()));
}

#[test]
fn version_policy_min_max_deny_and_plausibility() {
	let policy = policy_with(|c| {
		c.min_protocol_version = Some(47);
		c.max_protocol_version = Some(770);
		c.deny_protocol_versions = vec![340];
	});
	assert_eq!(policy.check_version(765), Ok(()));
	assert_eq!(policy.check_version(340), Err(Reason::VersionDenied));
	assert_eq!(policy.check_version(5), Err(Reason::VersionBelowMin));
	assert_eq!(policy.check_version(771), Err(Reason::VersionAboveMax));
	let open = default_policy();
	assert_eq!(open.check_version(0), Err(Reason::ImplausibleVersion));
	assert_eq!(open.check_version(1_000_000), Err(Reason::ImplausibleVersion));
	assert_eq!(open.check_version(i32::MAX), Err(Reason::ImplausibleVersion));
	assert_eq!(open.check_version(0x4000_0000 | 200), Ok(()));
	let mut session = Session::new(&policy);
	assert_eq!(session.feed(&handshake_body(340, "h", 2)), Err(Reason::VersionDenied));
}

#[test]
fn version_table_covers_required_ids_and_labels_are_bounded() {
	for id in [47, 340, 754, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767] {
		assert!(versions::name(id).is_some(), "{id}");
	}
	assert!(versions::VERSIONS.windows(2).all(|pair| pair[0].0 < pair[1].0));
	assert_eq!(versions::label(765), "1.20.3-4");
	assert_eq!(versions::label(123_456), "other");
	assert_eq!(versions::label(-1), "other");
}

#[test]
fn reasons_are_a_closed_label_set() {
	let mut seen = std::collections::HashSet::new();
	for reason in Reason::ALL {
		let label = reason.as_str();
		assert!(label.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
		assert!(seen.insert(label), "duplicate label {label}");
		let expected = if reason == Reason::Ok { "accepted" } else { "rejected" };
		assert_eq!(reason.result(), expected);
	}
}
