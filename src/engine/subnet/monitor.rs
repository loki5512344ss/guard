//! Periodic subnet monitor: snapshot source, detector and verdict escalation.
//!
//! The source is chosen by build features and config: the XDP `prefix_stats` map
//! (feature `xdp` with a loaded filter) or the userspace aggregator
//! [`SubnetTracker`].

use super::enforce::BanPolicy;
#[cfg(feature = "xdp")]
use super::enforce::ban_xdp_verdicts;
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

pub use super::enforce::enforce_tracker_verdicts;

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

#[must_use]
fn verdict_name(verdict: SubnetVerdict) -> &'static str {
	match verdict {
		SubnetVerdict::Monitor => "monitor",
		SubnetVerdict::StrictLimit => "strict_limit",
		SubnetVerdict::Challenge => "challenge",
		SubnetVerdict::Block => "block",
	}
}
