//! Management-plane security: API password/JWT policy and the CORS downgrade.
//!
//! Regression tests for the authentication bypass where an empty
//! `API_PASSWORD` matched an empty login (`verify_password("", "")`).

use dashmap::DashMap;
use rampart::manager::api::auth::allow_login_attempt;
use rampart::manager::security::{CorsPolicy, validate_api_password, validate_jwt_secret, verify_password};
use std::net::IpAddr;

const STRONG_PASSWORD: &str = "correct-horse-battery-staple";
const STRONG_SECRET: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn rejects_empty_api_password() {
	let err = validate_api_password("").expect_err("empty password must be rejected");
	assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn rejects_whitespace_only_api_password() {
	assert!(validate_api_password("                ").is_err());
}

#[test]
fn rejects_short_api_password() {
	let short = "a".repeat(15);
	let err = validate_api_password(&short).expect_err("15 characters must be rejected");
	assert!(err.to_string().contains("at least 16"));
	assert!(validate_api_password(&"a".repeat(16)).is_ok());
}

#[test]
fn rejects_placeholder_api_password() {
	assert!(validate_api_password("changeme").is_err());
	assert!(validate_api_password("ChangeMe").is_err());
	assert!(validate_api_password("  changeme  ").is_err());
}

#[test]
fn accepts_strong_api_password() {
	assert!(validate_api_password(STRONG_PASSWORD).is_ok());
}

#[test]
fn empty_stored_password_never_verifies() {
	assert!(!verify_password("", ""));
	assert!(!verify_password("anything", ""));
}

#[test]
fn verify_password_matches_exact_value_only() {
	assert!(verify_password(STRONG_PASSWORD, STRONG_PASSWORD));
	assert!(!verify_password("wrong-password", STRONG_PASSWORD));
	assert!(!verify_password("short", STRONG_PASSWORD));
}

#[test]
fn rejects_empty_or_short_jwt_secret() {
	assert!(validate_jwt_secret("").is_err());
	assert!(validate_jwt_secret(&" ".repeat(64)).is_err());
	assert!(validate_jwt_secret(&"a".repeat(31)).is_err());
	let err = validate_jwt_secret(" \t\n").expect_err("whitespace must be rejected");
	assert!(err.to_string().contains("non-whitespace"));
}

#[test]
fn accepts_strong_jwt_secret() {
	assert!(validate_jwt_secret(STRONG_SECRET).is_ok());
	assert!(validate_jwt_secret(&format!("  {STRONG_SECRET}  ")).is_ok());
}

#[test]
fn cors_without_explicit_origin_is_denied() {
	assert_eq!(CorsPolicy::parse(None).expect("unset is valid"), CorsPolicy::Deny);
	assert_eq!(CorsPolicy::parse(Some("")).expect("empty is valid"), CorsPolicy::Deny);
	assert_eq!(
		CorsPolicy::parse(Some("   ")).expect("blank is valid"),
		CorsPolicy::Deny
	);
	assert!(CorsPolicy::Deny.cors_layer().is_none());
}

#[test]
fn cors_wildcard_requires_explicit_flag() {
	assert_eq!(
		CorsPolicy::parse(Some("*")).expect("wildcard is valid"),
		CorsPolicy::Any
	);
	assert!(CorsPolicy::Any.cors_layer().is_some());
}

#[test]
fn cors_origin_list_is_trimmed() {
	let policy = CorsPolicy::parse(Some("https://a.example, https://b.example")).expect("list must parse");
	assert_eq!(
		policy,
		CorsPolicy::AllowList(vec!["https://a.example".to_owned(), "https://b.example".to_owned()])
	);
	assert!(policy.cors_layer().is_some());
}

#[test]
fn cors_rejects_empty_entries_and_mixed_wildcard() {
	assert!(CorsPolicy::parse(Some("https://a.example,")).is_err());
	assert!(CorsPolicy::parse(Some("https://a.example,*")).is_err());
}

#[test]
fn cors_rejects_invalid_header_value() {
	// A newline inside an origin is a header-injection attempt, not a valid value.
	assert!(CorsPolicy::parse(Some("https://evil.example\nSet-Cookie: x")).is_err());
	assert!(CorsPolicy::parse(Some("https://evil.example/\u{7f}")).is_err());
}

#[test]
fn login_limiter_blocks_after_five_attempts() {
	let limiter = DashMap::new();
	let ip = IpAddr::from([127, 0, 0, 1]);
	for _ in 0..5 {
		assert!(allow_login_attempt(&limiter, ip));
	}
	assert!(!allow_login_attempt(&limiter, ip));
}
