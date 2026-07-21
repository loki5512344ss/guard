#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStats {
    pub total: u64,
    pub tcp_mc: u64,
    pub whitelist: u64,
    pub blacklist: u64,
    pub syn_throttle: u64,
    pub passed: u64,
    pub dropped: u64,
    pub verified: u64,
}
