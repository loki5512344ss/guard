/// Счётчики XDP-программы; индексы соответствуют STAT_* из xdp/core/maps.h.
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStats {
    pub total: u64,
    pub tcp: u64,
    pub whitelist: u64,
    pub blacklist: u64,
    pub syn_throttle: u64,
    pub passed: u64,
    pub dropped: u64,
    pub udp: u64,
    pub rate_limit: u64,
}
