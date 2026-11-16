//! Management-plane security: API password/JWT policy and the CORS downgrade.
//!
//! Regression tests for the authentication bypass where an empty
//! `API_PASSWORD` matched an empty login (`verify_password("", "")`).

use axum::http::HeaderValue;
use dashmap::DashMap;
use rampart::manager::api::auth::{allow_login_attempt, reset_login_attempts};
use rampart::manager::api::guard::limit::{LOGIN_MAX_ATTEMPTS, check_attempt, evict_idle};
use rampart::manager::api::guard::proxy::TrustedProxies;
use rampart::manager::security::{CorsPolicy, IpNet, validate_api_password, validate_jwt_secret, verify_password};
use std::net::IpAddr;
use std::time::Duration;

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

#[test]
fn successful_login_resets_the_counter() {
	let limiter = DashMap::new();
	let ip = IpAddr::from([127, 0, 0, 1]);
	for _ in 0..LOGIN_MAX_ATTEMPTS {
		assert!(allow_login_attempt(&limiter, ip));
	}
	assert!(!allow_login_attempt(&limiter, ip));

	reset_login_attempts(&limiter, ip);
	for _ in 0..LOGIN_MAX_ATTEMPTS {
		assert!(
			allow_login_attempt(&limiter, ip),
			"a successful login must give a fresh budget"
		);
	}
}

#[test]
fn idle_limiter_entries_are_evicted() {
	let limiter = DashMap::new();
	let first = IpAddr::from([127, 0, 0, 1]);
	let second = IpAddr::from([127, 0, 0, 2]);
	assert!(check_attempt(&limiter, first, Duration::from_secs(60), 5));
	assert!(check_attempt(&limiter, second, Duration::from_secs(60), 5));

	evict_idle(&limiter, Duration::from_secs(600));
	assert_eq!(limiter.len(), 2, "a live window must survive the sweep");

	evict_idle(&limiter, Duration::ZERO);
	assert!(limiter.is_empty(), "expired counters must not accumulate forever");
}

#[test]
fn forwarded_for_is_ignored_from_an_untrusted_peer() {
	let proxies = TrustedProxies::parse("10.0.0.0/8").expect("network must parse");
	let peer: IpAddr = "203.0.113.7".parse().expect("peer must parse");
	let forwarded = HeaderValue::from_static("198.51.100.9");
	assert_eq!(proxies.client_ip(peer, Some(&forwarded)), peer);
}

#[test]
fn forwarded_for_is_used_from_a_trusted_peer() {
	let proxies = TrustedProxies::parse("10.0.0.0/8,2001:db8::/32").expect("networks must parse");
	let peer: IpAddr = "10.1.2.3".parse().expect("peer must parse");
	let forwarded = HeaderValue::from_static("203.0.113.9");
	assert_eq!(
		proxies.client_ip(peer, Some(&forwarded)),
		"203.0.113.9".parse::<IpAddr>().expect("client must parse")
	);
	let v6_peer: IpAddr = "2001:db8::5".parse().expect("peer must parse");
	assert_eq!(
		proxies.client_ip(v6_peer, Some(&forwarded)),
		"203.0.113.9".parse::<IpAddr>().expect("client must parse")
	);
}

#[test]
fn forwarded_chain_is_walked_right_to_left() {
	let proxies = TrustedProxies::parse("10.0.0.0/8").expect("network must parse");
	let peer: IpAddr = "10.1.2.3".parse().expect("peer must parse");

	let chain = HeaderValue::from_static("203.0.113.9, 10.9.9.9");
	assert_eq!(
		proxies.client_ip(peer, Some(&chain)),
		"203.0.113.9".parse::<IpAddr>().expect("client must parse")
	);

	// The leftmost entry is client supplied: the nearest untrusted hop wins.
	let spoofed = HeaderValue::from_static("1.2.3.4, 198.51.100.7");
	assert_eq!(
		proxies.client_ip(peer, Some(&spoofed)),
		"198.51.100.7".parse::<IpAddr>().expect("client must parse")
	);
}

#[test]
fn malformed_forwarded_chain_falls_back_to_the_peer() {
	let proxies = TrustedProxies::parse("10.0.0.0/8").expect("network must parse");
	let peer: IpAddr = "10.1.2.3".parse().expect("peer must parse");
	assert_eq!(proxies.client_ip(peer, None), peer);
	let garbage = HeaderValue::from_static("not-an-address");
	assert_eq!(proxies.client_ip(peer, Some(&garbage)), peer);
}

#[test]
fn trusted_proxy_list_rejects_malformed_entries() {
	assert!(
		!TrustedProxies::parse("")
			.expect("empty is valid")
			.is_trusted("10.0.0.1".parse().expect("ip"))
	);
	assert!(TrustedProxies::parse("10.0.0.0/8,").is_err());
	assert!(TrustedProxies::parse("10.0.0.0/33").is_err());
	assert!(TrustedProxies::parse("not-a-network").is_err());
	assert!(TrustedProxies::parse("::/129").is_err());
}

#[test]
fn ip_net_matches_the_configured_prefix() {
	let network = IpNet::parse("192.168.1.0/24").expect("network must parse");
	assert!(network.contains("192.168.1.200".parse().expect("ip")));
	assert!(!network.contains("192.168.2.1".parse().expect("ip")));
	assert!(!network.contains("::ffff:192.168.1.1".parse().expect("ip")));

	let host = IpNet::parse("192.168.1.5").expect("host route must parse");
	assert!(host.contains("192.168.1.5".parse().expect("ip")));
	assert!(!host.contains("192.168.1.6".parse().expect("ip")));

	let v6 = IpNet::parse("2001:db8::/32").expect("network must parse");
	assert!(v6.contains("2001:db8::1".parse().expect("ip")));
	assert!(!v6.contains("2001:db9::1".parse().expect("ip")));

	assert!(
		IpNet::parse("0.0.0.0/0")
			.expect("default route must parse")
			.contains("203.0.113.1".parse().expect("ip"))
	);
	assert!(IpNet::parse("bad").is_err());
}
