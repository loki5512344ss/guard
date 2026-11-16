//! Edge service wiring: whitelist parsing and the XDP startup path.
//!
//! These used to be inline `#[cfg(test)]` tests in `src/app/services.rs`; the
//! project keeps tests out of source files (TODO.md §4). Kernel-touching
//! behaviour is not exercised here: `start_xdp` is called with `[xdp]`
//! disabled, and the whitelist-map load needs a live interface.

use std::net::IpAddr;
use std::sync::Arc;

use rampart::app::services::{build_whitelist, start_xdp};
use rampart::config::{Config, StoreConfig};
use rampart::filter::blacklist::Blacklist;
use tokio::sync::watch;

fn config_with_redis() -> Config {
	Config {
		store: StoreConfig {
			redis_url: Some("redis://127.0.0.1:6379/0".to_string()),
			..Default::default()
		},
		..Default::default()
	}
}

#[cfg(not(feature = "store-redis"))]
#[test]
fn redis_config_without_feature_fails_fast() {
	let err = build_whitelist(&config_with_redis()).expect_err("must fail without store-redis");
	assert!(err.to_string().contains("built without store-redis feature"));
}

#[cfg(not(feature = "store-redis"))]
#[test]
fn empty_store_config_passes_without_feature() {
	assert!(build_whitelist(&Config::default()).is_ok());
}

#[cfg(feature = "store-redis")]
#[test]
fn redis_config_passes_with_store_feature() {
	assert!(build_whitelist(&config_with_redis()).is_ok());
}

#[test]
fn build_whitelist_parses_both_address_families() {
	let config = Config {
		whitelist: vec!["192.0.2.10".to_string(), "2001:db8::1".to_string()],
		..Default::default()
	};
	let set = build_whitelist(&config).expect("valid whitelist entries");
	assert!(set.contains(&"192.0.2.10".parse::<IpAddr>().expect("ipv4 literal")));
	assert!(set.contains(&"2001:db8::1".parse::<IpAddr>().expect("ipv6 literal")));
	assert_eq!(set.len(), 2);
}

#[test]
fn build_whitelist_rejects_a_malformed_entry() {
	let config = Config {
		whitelist: vec!["definitely-not-an-ip".to_string()],
		..Default::default()
	};
	let err = build_whitelist(&config).expect_err("malformed entry must fail");
	assert!(err.to_string().contains("invalid whitelist entry"));
}

/// XDP auto-ban wiring: `start_xdp` must accept the `Arc<Blacklist>` and, with
/// `[xdp]` disabled, touch neither the kernel nor the blacklist. The
/// `set_autoban` -> `load()` order inside the enabled branch cannot be checked
/// without a kernel.
#[test]
fn start_xdp_accepts_blacklist_and_skips_kernel_when_disabled() {
	let (_tx, rx) = watch::channel(false);
	let blacklist = Arc::new(Blacklist::new());
	let started =
		start_xdp(&Arc::new(Config::default()), &rx, &blacklist).expect("xdp disabled: no kernel work and no error");
	assert!(started.is_none());
	assert!(blacklist.is_empty());
}
