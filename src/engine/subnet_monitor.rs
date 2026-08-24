//! Периодический subnet-монитор: источник снапшотов → детектор → эскалация.
//!
//! Источник выбирается по сборке и конфигу: XDP-карта `prefix_stats`
//! (feature `xdp` + загруженный фильтр) либо юзерспейс-агрегатор
//! [`SubnetTracker`].

use crate::config::DetectPrefixConfig;
use crate::engine::subnet_tracker::{SubnetTracker, TrackerSource};
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

/// Запускает фоновый subnet-монитор, если `[detect.prefix] enabled`.
///
/// Приоритет источника: XDP-карта при загруженном фильтре, иначе
/// юзерспейс-агрегатор. Без обоих источников монитор не запускается.
pub fn spawn(
    detect: &DetectPrefixConfig,
    tracker: Option<Arc<SubnetTracker>>,
    xdp: Option<Arc<Mutex<XdpFilter>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    if !detect.enabled {
        return;
    }
    let Some(source) = build_source(tracker, xdp) else {
        tracing::warn!("detect.prefix enabled but no stats source available; monitor disabled");
        return;
    };
    let detector = SubnetDetector::from_config(detect);
    let window = Duration::from_secs(detect.window_secs.max(1));

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
                        Ok(snaps) => apply_verdicts(&detector.evaluate(&snaps), &source).await,
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

async fn apply_verdicts(verdicts: &[PrefixVerdict], source: &Source) {
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
        if pv.verdict == SubnetVerdict::Block {
            enforce_block(source, pv).await;
        }
    }
}

async fn enforce_block(source: &Source, pv: &PrefixVerdict) {
    match source {
        #[cfg(feature = "xdp")]
        Source::Xdp(xdp) => {
            let result = {
                let guard = xdp.filter_lock();
                guard.ban_cidr(pv.prefix, prefix_len(pv.prefix), 3600)
            };
            if let Err(e) = result {
                tracing::warn!("subnet block failed for {}: {e}", pv.prefix);
            }
        },
        Source::Tracker(_) => {
            tracing::warn!(
                prefix = %pv.prefix,
                "block verdict without kernel enforcement; escalate at L7"
            );
        },
    }
}

/// Длина префикса, соответствующая гранулярности детекции (v4 /24, v6 /64).
#[cfg(feature = "xdp")]
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
