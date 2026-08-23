#[cfg(feature = "geoip")]
pub struct GeoIp {
    #[allow(dead_code)]
    reader: maxminddb::Reader<Vec<u8>>,
}

#[cfg(feature = "geoip")]
impl GeoIp {
    pub fn new(db_path: &str) -> anyhow::Result<Self> {
        let reader = maxminddb::Reader::open_readfile(db_path)?;
        Ok(Self { reader })
    }
}

pub enum IpCategory {
    Residential,
    Datacenter,
    Mobile,
    Vpn,
    Tor,
    Unknown,
}

impl std::fmt::Display for IpCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Residential => write!(f, "residential"),
            Self::Datacenter => write!(f, "datacenter"),
            Self::Mobile => write!(f, "mobile"),
            Self::Vpn => write!(f, "vpn"),
            Self::Tor => write!(f, "tor"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}
