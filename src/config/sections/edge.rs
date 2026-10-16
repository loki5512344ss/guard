use serde::{Deserialize, Deserializer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize)]
pub struct BindConfig {
    #[serde(default = "default_bind_address")]
    pub address: String,
    #[serde(default = "default_bind_port")]
    pub port: u16,
}

impl Default for BindConfig {
    fn default() -> Self {
        Self {
            address: default_bind_address(),
            port: default_bind_port(),
        }
    }
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}
fn default_bind_port() -> u16 {
    25565
}

/// Generic upstream-бэкенды (список addr:port) за edge-нодой.
#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<String>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            upstreams: default_upstreams(),
        }
    }
}

fn default_upstreams() -> Vec<String> {
    vec!["127.0.0.1:25566".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    #[serde(default = "default_worker_count")]
    pub count: usize,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self { count: 4 }
    }
}

fn default_worker_count() -> usize {
    4
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_rate_limit_pps")]
    pub rate_limit_pps: f64,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: f64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            handshake_timeout_secs: default_handshake_timeout(),
            max_connections_per_ip: default_max_connections_per_ip(),
            rate_limit_pps: default_rate_limit_pps(),
            rate_limit_burst: default_rate_limit_burst(),
        }
    }
}

fn default_handshake_timeout() -> u64 {
    5
}
fn default_max_connections_per_ip() -> u32 {
    10
}
fn default_rate_limit_pps() -> f64 {
    5.0
}
fn default_rate_limit_burst() -> f64 {
    10.0
}

#[derive(Debug, Clone, Deserialize)]
pub struct BanConfig {
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            ban_duration_secs: default_ban_duration(),
        }
    }
}

fn default_ban_duration() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize)]
pub struct PowConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pow_difficulty")]
    pub difficulty: u8,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            difficulty: default_pow_difficulty(),
        }
    }
}

fn default_pow_difficulty() -> u8 {
    4
}

/// CIDR network allowed to send inbound PROXY protocol headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxyCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedProxyCidr {
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                u32::from(network) & mask == u32::from(ip) & mask
            },
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                u128::from(network) & mask == u128::from(ip) & mask
            },
            _ => false,
        }
    }
}

impl FromStr for TrustedProxyCidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value, None),
        };
        let network = IpAddr::from_str(address).map_err(|_| format!("invalid trusted proxy CIDR: {value}"))?;
        let max_prefix = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|_| format!("invalid trusted proxy CIDR prefix: {value}"))?,
            None => max_prefix,
        };
        if prefix_len > max_prefix {
            return Err(format!("trusted proxy CIDR prefix is too large: {value}"));
        }
        let network = match network {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask_v4(prefix_len))),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask_v6(prefix_len))),
        };
        Ok(Self { network, prefix_len })
    }
}

impl<'de> Deserialize<'de> for TrustedProxyCidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyProtocolConfig {
    #[serde(default)]
    pub ingress_enabled: bool,
    #[serde(default)]
    pub trusted_cidrs: Vec<TrustedProxyCidr>,
    #[serde(default = "default_proxy_protocol_timeout_ms")]
    pub ingress_timeout_ms: u64,
    #[serde(default = "default_proxy_protocol_max_header_bytes")]
    pub max_header_bytes: usize,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            ingress_enabled: false,
            trusted_cidrs: Vec::new(),
            ingress_timeout_ms: default_proxy_protocol_timeout_ms(),
            max_header_bytes: default_proxy_protocol_max_header_bytes(),
        }
    }
}

fn default_proxy_protocol_timeout_ms() -> u64 {
    750
}
fn default_proxy_protocol_max_header_bytes() -> usize {
    512
}
