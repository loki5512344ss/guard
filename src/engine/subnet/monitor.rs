//! Periodic subnet monitor: snapshot source, detector and verdict escalation.
//!
//! The source is chosen by build features and config: the XDP `prefix_stats` map
//! (feature `xdp` with a loaded filter) or the userspace aggregator
//! [`SubnetTracker`].

use crate::config::DetectPrefixConfig;
use crate::engine::subnet_tracker::{SubnetTracker, TrackerSource};
use crate::filter::blacklist::Blacklist;
use crate::metrics;
#[cfg(feature = "xdp")]
use crate::traffic::prefix::XdpPrefixStats;
use crate::traffic::prefix::{PrefixSnapshot, PrefixStatsSource, PrefixVerdict, SubnetDetector, SubnetVerdict};
use crate::xdp::XdpFilter;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

enum Source {
	#[cfg(feature = "xdp")]
	Xdp(XdpPrefixStats),
	Tracker(TrackerSource),
}

impl Source {
	async fn snapshot(&self) -> anyhow::Result<Vec<(IpAddr, PrefixSnapshot)>> {
		match self {
			#[cfg(feature = "xdp")]
			Source::Xdp(xdp) => xdp.snapshot().await,
			Source::Tracker(tracker) => tracker.snapshot().await,
		}
	}
}

/// Verdict enforcement settings shared by every snapshot tick.
struct BanPolicy {
	blacklist: Arc<Blacklist>,
	ttl: Duration,
	trusted: bool,
	/// Trusted PROXY-protocol networks; a prefix ban overlapping one of them is
	/// suppressed, because it would punish the proxy and every client behind it.
	trusted_networks: Vec<crate::config::TrustedProxyCidr>,
}

/// Spawns the background subnet monitor when `[detect.prefix] enabled`.
///
/// Source priority: the XDP map when a filter is loaded, otherwise the userspace
/// aggregator. Without either source the monitor stays disabled and logs a
/// warning.
///
/// Everything the monitor task needs besides the detection config.
pub struct MonitorSetup {
	/// Ban lifetime, from `[ban].ban_duration_secs`.
	pub ban_ttl: Duration,
	/// Shared ban table.
	pub blacklist: Arc<Blacklist>,
	/// False when the observed address comes from an unverified ingress path
	/// (inbound PROXY protocol), where banning it could punish the transport
	/// proxy instead of the real client.
	pub trusted_peer: bool,
	/// Trusted proxy networks; a prefix ban overlapping one is suppressed.
	pub trusted_networks: Vec<crate::config::TrustedProxyCidr>,
	/// Userspace aggregator, used when XDP is not available.
	pub tracker: Option<Arc<SubnetTracker>>,
	/// Loaded XDP filter, preferred over the userspace tracker when present.
	pub xdp: Option<Arc<Mutex<XdpFilter>>>,
}

/// Spawns the background subnet monitor when `[detect.prefix] enabled`.
pub fn spawn(detect: &DetectPrefixConfig, setup: MonitorSetup, mut shutdown: watch::Receiver<bool>) {
	if !detect.enabled {
		return;
	}
	let MonitorSetup {
		ban_ttl,
		blacklist,
		trusted_peer,
		trusted_networks,
		tracker,
		xdp,
	} = setup;
	let Some(source) = build_source(tracker, xdp) else {
		tracing::warn!("detect.prefix enabled but no stats source available; monitor disabled");
		return;
	};
	let detector = SubnetDetector::from_config(detect);
	let window = Duration::from_secs(detect.window_secs.max(1));
	let policy = BanPolicy {
		blacklist,
		ttl: ban_ttl,
		trusted: trusted_peer,
		trusted_networks,
	};

	tokio::spawn(async move {
		let mut tick = tokio::time::interval(window);
		tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			tokio::select! {
				biased;
				_ = shutdown.changed() => {
					if *shutdown.borrow() {
						return;
					}
				}
				_ = tick.tick() => {
					match source.snapshot().await {
						Ok(snaps) => {
							let verdicts = detector.evaluate(&snaps);
							apply_verdicts(&verdicts, &source, &policy);
						},
						Err(e) => tracing::debug!("prefix stats unavailable: {e}"),
					}
				}
			}
		}
	});
}

fn build_source(tracker: Option<Arc<SubnetTracker>>, xdp: Option<Arc<Mutex<XdpFilter>>>) -> Option<Source> {
	#[cfg(feature = "xdp")]
	if let Some(filter) = xdp {
		return Some(Source::Xdp(XdpPrefixStats::new(filter)));
	}
	#[cfg(not(feature = "xdp"))]
	let _ = xdp;
	tracker.map(|t| Source::Tracker(TrackerSource { tracker: t }))
}

fn apply_verdicts(verdicts: &[PrefixVerdict], source: &Source, policy: &BanPolicy) {
	for pv in verdicts {
		metrics::SUBNET_VERDICTS
			.with_label_values(&[verdict_name(pv.verdict)])
			.inc();
		tracing::info!(
			prefix = %pv.prefix,
			syn = pv.snapshot.syn_count,
			unique = pv.snapshot.unique_sources,
			verdict = verdict_name(pv.verdict),
			"subnet verdict"
		);
	}
	match source {
		#[cfg(feature = "xdp")]
		Source::Xdp(xdp) if policy.trusted => ban_xdp_verdicts(xdp, verdicts, policy.ttl, &policy.trusted_networks),
		#[cfg(feature = "xdp")]
		Source::Xdp(_) => {
			if verdicts.iter().any(|pv| pv.verdict == SubnetVerdict::Block) {
				tracing::warn!("subnet kernel bans suppressed: peer identity comes from an untrusted ingress path");
			}
		},
		Source::Tracker(_) => {
			enforce_tracker_verdicts(
				verdicts,
				&policy.blacklist,
				policy.ttl,
				policy.trusted,
				&policy.trusted_networks,
			);
		},
	}
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
		if trusted_networks
			.iter()
			.any(|net| net.overlaps_prefix(pv.prefix, prefix_len(pv.prefix)))
		{
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

#[cfg(feature = "xdp")]
fn ban_xdp_verdicts(
	xdp: &XdpPrefixStats,
	verdicts: &[PrefixVerdict],
	ttl: Duration,
	trusted_networks: &[crate::config::TrustedProxyCidr],
) {
	for pv in verdicts.iter().filter(|pv| pv.verdict == SubnetVerdict::Block) {
		let len = prefix_len(pv.prefix);
		if trusted_networks.iter().any(|net| net.overlaps_prefix(pv.prefix, len)) {
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

/// Prefix length matching the detection granularity (v4 /24, v6 /64).
fn prefix_len(prefix: IpAddr) -> u8 {
	match prefix {
		IpAddr::V4(_) => 24,
		IpAddr::V6(_) => 64,
	}
}

#[must_use]
fn verdict_name(verdict: SubnetVerdict) -> &'static str {
	match verdict {
		SubnetVerdict::Monitor => "monitor",
		SubnetVerdict::StrictLimit => "strict_limit",
		SubnetVerdict::Challenge => "challenge",
		SubnetVerdict::Block => "block",
	}
}
