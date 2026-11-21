//! Human-readable duration parser of `rampart-cli` and its clap value parsers.

use rampart::cli::commands::blacklist::{parse_duration_arg, parse_target_arg};
use rampart::cli::duration::{format_duration_secs, parse_duration_secs};

#[test]
fn accepts_single_and_compound_units() {
	assert_eq!(parse_duration_secs("30s"), Ok(30));
	assert_eq!(parse_duration_secs("5m"), Ok(300));
	assert_eq!(parse_duration_secs("1h30m"), Ok(5400));
	assert_eq!(parse_duration_secs("2d"), Ok(172_800));
	assert_eq!(parse_duration_secs("1d2h3m4s"), Ok(93_784));
	assert_eq!(parse_duration_secs("0"), Ok(0));
}

#[test]
fn bare_numbers_are_rejected_with_a_unit_hint() {
	for text in ["90", "1", "3600"] {
		let error = parse_duration_secs(text).expect_err(text);
		assert!(error.contains("valid units"), "{text}: {error}");
	}
}

#[test]
fn malformed_input_is_rejected() {
	for text in [
		"", " ", "5 m", " 5m", "5m ", "m", "-5m", "+5m", "1.5h", "5x", "5M", "1h1h", "30s5m", "5m30", "1h-5m", "0x10s",
		"５m", "5mm",
	] {
		assert!(parse_duration_secs(text).is_err(), "'{text}' must be rejected");
	}
}

#[test]
fn overflow_is_an_error_not_a_wrap() {
	assert!(parse_duration_secs("99999999999999999999s").is_err());
	assert!(parse_duration_secs("999999999999999999d").is_err());
	assert!(parse_duration_secs("18446744073709551615h").is_err());
}

#[test]
fn ban_flag_rejects_zero_and_formats_remaining_time() {
	assert_eq!(parse_duration_arg("1h30m"), Ok(5400));
	assert!(parse_duration_arg("0").is_err());
	assert!(parse_duration_arg("90").is_err());
	assert_eq!(format_duration_secs(5400), "1h30m");
	assert_eq!(format_duration_secs(90_061), "1d1h");
	assert_eq!(format_duration_secs(45), "45s");
	assert_eq!(format_duration_secs(0), "0s");
}

#[test]
fn cli_target_is_a_single_strict_address() {
	assert_eq!(parse_target_arg("1.2.3.4"), Ok("1.2.3.4".to_string()));
	for text in [
		"",
		" 1.2.3.4",
		"1.2.3.4 ",
		"1.2.3.4x",
		"10.0.0.0/8",
		"1.2.3.4/0",
		"1.2.3.4/33",
	] {
		assert!(parse_target_arg(text).is_err(), "'{text}' must be rejected");
	}
}
