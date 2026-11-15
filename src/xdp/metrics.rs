//! Prometheus metrics of the XDP loader.
//!
//! They register into the global `prometheus` registry — the same one that
//! `prometheus::gather()` in `crate::metrics::run_metrics_server` scrapes — so the
//! `/metrics` endpoint picks them up without changes outside `src/xdp/`.

use prometheus::{IntCounter, register_int_counter};
use std::sync::LazyLock;

/// How many times an XDP ringbuf event resulted in a userspace auto-ban.
///
/// The counter is incremented only for a new ban, never for a refresh of an active one.
pub static XDP_AUTOBANS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
	register_int_counter!("rampart_xdp_autobans_total", "Auto-bans issued from XDP ringbuf events")
		.expect("XDP_AUTOBANS_TOTAL")
});

/// Forces registration of the counter (called at the start of the XDP load).
pub fn init() {
	LazyLock::force(&XDP_AUTOBANS_TOTAL);
}
