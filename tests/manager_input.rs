//! Strict input validation for ban targets, ports and ban windows.

use rampart::manager::input::{parse_port, parse_target, resolve_ban_window};

const NOW: i64 = 1_800_000_000;
const YEAR: i64 = 31_536_000;

#[test]
fn accepts_addresses_and_valid_prefixes() {
	assert_eq!(parse_target("1.2.3.4").map(|t| t.prefix), Ok(None));
	assert_eq!(parse_target("::1").map(|t| t.prefix), Ok(None));
	assert_eq!(parse_target("10.0.0.0/8").map(|t| t.prefix), Ok(Some(8)));
	assert_eq!(parse_target("1.2.3.4/32").map(|t| t.prefix), Ok(Some(32)));
	assert_eq!(parse_target("2001:db8::/128").map(|t| t.prefix), Ok(Some(128)));
}

#[test]
fn rejects_malformed_targets() {
	for text in [
		"",
		" ",
		" 1.2.3.4",
		"1.2.3.4 ",
		"1.2.3.4\n",
		"1. 2.3.4",
		"1.2.3.4x",
		"1.2.3.4:80",
		"1.2.3.4/",
		"1.2.3.4/0",
		"::/0",
		"1.2.3.4/33",
		"::1/129",
		"1.2.3.4/+8",
		"1.2.3.4/8x",
		"1.2.3.4/-1",
		"1.2.3.4/256",
		"1.2.3.4/8/8",
		"999.1.1.1",
		"not-an-ip",
	] {
		assert!(parse_target(text).is_err(), "'{text}' must be rejected");
	}
}

#[test]
fn ports_are_strict_decimal_in_range() {
	assert_eq!(parse_port("1"), Ok(1));
	assert_eq!(parse_port("443"), Ok(443));
	assert_eq!(parse_port("65535"), Ok(65535));
	for text in [
		"",
		"0",
		"00",
		"65536",
		"99999999999",
		"-1",
		"+80",
		" 80",
		"80 ",
		"80x",
		"0x50",
		"8.0",
	] {
		assert!(parse_port(text).is_err(), "'{text}' must be rejected");
	}
}

#[test]
fn window_defaults_and_duration_are_unchanged() {
	assert_eq!(resolve_ban_window(None, None, 300, NOW), Ok((300, NOW + 300)));
	assert_eq!(resolve_ban_window(Some(3600), None, 300, NOW), Ok((3600, NOW + 3600)));
	assert!(resolve_ban_window(Some(0), None, 300, NOW).is_err());
	assert!(resolve_ban_window(Some(YEAR as u64 + 1), None, 300, NOW).is_err());
	assert_eq!(
		resolve_ban_window(Some(YEAR as u64), None, 300, NOW),
		Ok((YEAR as u64, NOW + YEAR))
	);
}

#[test]
fn absolute_expiry_is_validated() {
	assert_eq!(resolve_ban_window(None, Some(NOW + 60), 300, NOW), Ok((60, NOW + 60)));
	assert_eq!(
		resolve_ban_window(None, Some(NOW + YEAR), 300, NOW),
		Ok((YEAR as u64, NOW + YEAR))
	);
	for at in [NOW, NOW - 1, 0, -1, i64::MIN, i64::MAX, NOW + YEAR + 1] {
		assert!(
			resolve_ban_window(None, Some(at), 300, NOW).is_err(),
			"{at} must be rejected"
		);
	}
}

#[test]
fn duration_and_expiry_are_mutually_exclusive() {
	assert!(resolve_ban_window(Some(60), Some(NOW + 60), 300, NOW).is_err());
}
