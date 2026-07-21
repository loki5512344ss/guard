use anyhow::{Context, Result};
use prometheus::{IntGauge, register};

use super::XdpStats;

pub struct XdpMetrics {
    total: IntGauge,
    tcp_mc: IntGauge,
    whitelist: IntGauge,
    blacklist: IntGauge,
    syn_throttle: IntGauge,
    passed: IntGauge,
    dropped: IntGauge,
    verified: IntGauge,
}

impl XdpMetrics {
    fn new_gauge(name: &str, help: &str) -> Result<IntGauge> {
        let gauge = IntGauge::new(name, help)?;
        register(Box::new(gauge.clone())).context(format!("failed to register {name}"))?;
        Ok(gauge)
    }

    pub fn register() -> Result<Self> {
        let m = Self {
            total: Self::new_gauge("rampart_xdp_total", "Total XDP packets processed")?,
            tcp_mc: Self::new_gauge("rampart_xdp_tcp_mc", "TCP packets matched to Minecraft profile")?,
            whitelist: Self::new_gauge("rampart_xdp_whitelist", "Whitelisted packets")?,
            blacklist: Self::new_gauge("rampart_xdp_blacklist", "Blacklisted packets")?,
            syn_throttle: Self::new_gauge("rampart_xdp_syn_throttle", "SYN packets rate-limited")?,
            passed: Self::new_gauge("rampart_xdp_passed", "Packets passed to upper layers")?,
            dropped: Self::new_gauge("rampart_xdp_dropped", "Packets dropped by filter")?,
            verified: Self::new_gauge("rampart_xdp_verified", "Packets challenge-verified")?,
        };
        tracing::info!("XDP Prometheus metrics registered");
        Ok(m)
    }

    pub fn update(&self, stats: &XdpStats) {
        self.total.set(stats.total as i64);
        self.tcp_mc.set(stats.tcp_mc as i64);
        self.whitelist.set(stats.whitelist as i64);
        self.blacklist.set(stats.blacklist as i64);
        self.syn_throttle.set(stats.syn_throttle as i64);
        self.passed.set(stats.passed as i64);
        self.dropped.set(stats.dropped as i64);
        self.verified.set(stats.verified as i64);
        tracing::debug!("XDP metrics updated");
    }
}
