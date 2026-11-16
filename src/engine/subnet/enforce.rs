//! Verdict enforcement: turning subnet `Block` verdicts into bans.
//!
//! Kept apart from [`super::monitor`] so the monitor task and the ban policy
//! stay within the module-size budget.

use crate::filter::blacklist::Blacklist;
use crate::traffic::prefix::{PrefixVerdict, SubnetVerdict};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Verdict enforcement settings shared by every snapshot tick.
pub(super) struct BanPolicy {
	pub(super) blacklist: Arc<Blacklist>,
	pub(super) ttl: Duration,
	pub(super) trusted: bool,
	/// Trusted PROXY-protocol networks; a prefix ban overlapping one of them is
	/// suppressed, because it would punish the proxy and every client behind it.
	pub(super) trusted_networks: Vec<crate::config::TrustedProxyCidr>,
}

/// Applies userspace `Block` verdicts to the shared blacklist.
///
/// Returns the number of banned prefixes. When `trusted` is false the observed
/// addresses belong to an unverified ingress path, so the verdict is only logged
/// at warn level and no ban is installed.
///
/// The ban is inserted as a CIDR range, so every address inside the detected
/// `/24` or `/64` is blocked, not just its network address.
pub fn enforce_tracker_verdicts(
	verdicts: &[PrefixVerdict],
	blacklist: &Blacklist,
	ttl: Duration,
	trusted: bool,
	trusted_networks: &[crate::config::TrustedProxyCidr],
) -> usize {
	let mut banned = 0;
	for pv in verdicts.iter().filter(|pv| pv.verdict == SubnetVerdict::Block) {
		if !trusted {
			tracing::warn!(
				prefix = %pv.prefix,
				"subnet block verdict on an untrusted peer path; not adding to the blacklist"
			);
			continue;
		}
		if overlaps_trusted(pv.prefix, trusted_networks) {
			tracing::warn!(
				prefix = %pv.prefix,
				"subnet ban suppressed: the prefix contains a trusted proxy network"
			);
			continue;
		}
		blacklist.add_cidr(pv.prefix, prefix_len(pv.prefix), ttl, "subnet_attack");
		banned += 1;
		tracing::warn!(
			prefix = %pv.prefix,
			ttl_secs = ttl.as_secs(),
			"subnet blocked in the userspace blacklist"
		);
	}
	banned
}

/// Installs XDP prefix bans for `Block` verdicts.
#[cfg(feature = "xdp")]
pub(super) fn ban_xdp_verdicts(
	xdp: &crate::traffic::prefix::XdpPrefixStats,
	verdicts: &[PrefixVerdict],
	ttl: Duration,
	trusted_networks: &[crate::config::TrustedProxyCidr],
) {
	for pv in verdicts.iter().filter(|pv| pv.verdict == SubnetVerdict::Block) {
		if overlaps_trusted(pv.prefix, trusted_networks) {
			tracing::warn!(
				prefix = %pv.prefix,
				"subnet kernel ban suppressed: the prefix contains a trusted proxy network"
			);
			continue;
		}
		let result = {
			let guard = xdp.filter_lock();
			guard.ban_cidr(pv.prefix, prefix_len(pv.prefix), ttl.as_secs())
		};
		match result {
			Ok(()) => tracing::warn!(
				prefix = %pv.prefix,
				ttl_secs = ttl.as_secs(),
				"subnet blocked in XDP"
			),
			Err(e) => tracing::warn!("subnet block failed for {}: {e}", pv.prefix),
		}
	}
}

/// Returns whether a ban of `prefix/prefix_len` would cover a trusted proxy.
fn overlaps_trusted(prefix: IpAddr, trusted_networks: &[crate::config::TrustedProxyCidr]) -> bool {
	trusted_networks
		.iter()
		.any(|net| net.overlaps_prefix(prefix, prefix_len(prefix)))
}

/// Prefix length matching the detection granularity (v4 /24, v6 /64).
pub(super) fn prefix_len(prefix: IpAddr) -> u8 {
	match prefix {
		IpAddr::V4(_) => 24,
		IpAddr::V6(_) => 64,
	}
}
