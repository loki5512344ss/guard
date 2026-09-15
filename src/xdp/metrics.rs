//! Prometheus-метрики загрузчика XDP.
//!
//! Регистрируются в глобальный реестр `prometheus` (тот же, что собирает
//! `prometheus::gather()` в `crate::metrics::run_metrics_server`), поэтому
//! endpoint `/metrics` подхватывает их без правок вне `src/xdp/`.

use prometheus::{IntCounter, register_int_counter};
use std::sync::LazyLock;

/// Сколько раз событие XDP-ringbuf привело к userspace-авто-бану
/// (счётчик инкрементится только на НОВЫЙ бан, не на продление).
pub static XDP_AUTOBANS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!("rampart_xdp_autobans_total", "Auto-bans issued from XDP ringbuf events")
        .expect("XDP_AUTOBANS_TOTAL")
});

/// Форсирует регистрацию счётчика (для вызова на старте загрузки XDP).
pub fn init() {
    LazyLock::force(&XDP_AUTOBANS_TOTAL);
}
