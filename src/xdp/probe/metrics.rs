use anyhow::{Context, Result};
use prometheus::{IntGauge, register};

use super::XdpStats;

pub struct XdpMetrics {
    total: IntGauge,
    tcp: IntGauge,
    whitelist: IntGauge,
    blacklist: IntGauge,
    syn_throttle: IntGauge,
    passed: IntGauge,
    dropped: IntGauge,
    udp: IntGauge,
    rate_limit: IntGauge,
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
            tcp: Self::new_gauge("rampart_xdp_tcp", "TCP packets processed")?,
            whitelist: Self::new_gauge("rampart_xdp_whitelist", "Whitelisted packets")?,
            blacklist: Self::new_gauge("rampart_xdp_blacklist", "Blacklisted packets")?,
            syn_throttle: Self::new_gauge("rampart_xdp_syn_throttle", "SYN packets rate-limited")?,
            passed: Self::new_gauge("rampart_xdp_passed", "Packets passed to upper layers")?,
            dropped: Self::new_gauge("rampart_xdp_dropped", "Packets dropped by filter")?,
            udp: Self::new_gauge("rampart_xdp_udp", "UDP packets processed")?,
            rate_limit: Self::new_gauge("rampart_xdp_rate_limit", "Packets rate-limited by window counter")?,
        };
        tracing::info!("XDP Prometheus metrics registered");
        Ok(m)
    }

    pub fn update(&self, stats: &XdpStats) {
        self.total.set(stats.total as i64);
        self.tcp.set(stats.tcp as i64);
        self.whitelist.set(stats.whitelist as i64);
        self.blacklist.set(stats.blacklist as i64);
        self.syn_throttle.set(stats.syn_throttle as i64);
        self.passed.set(stats.passed as i64);
        self.dropped.set(stats.dropped as i64);
        self.udp.set(stats.udp as i64);
        self.rate_limit.set(stats.rate_limit as i64);
        tracing::debug!("XDP metrics updated");
    }
}
