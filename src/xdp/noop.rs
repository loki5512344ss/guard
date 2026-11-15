use anyhow::{Ok, Result};
use std::net::{IpAddr, Ipv4Addr};

use crate::traffic::prefix::{PrefixKey, PrefixStatsVal};

pub struct XdpFilter;

impl XdpFilter {
	pub fn new(_interface: &str) -> Self {
		Self
	}
	pub fn load(&mut self) -> Result<()> {
		Ok(())
	}
	pub fn unload(&mut self) -> Result<()> {
		Ok(())
	}
	pub fn drain_events(&self) {}
	pub fn ban_cidr(&self, _prefix: IpAddr, _prefix_len: u8, _duration_secs: u64) -> Result<()> {
		Ok(())
	}
	pub fn unban_ip(&self, _ip: Ipv4Addr) -> Result<()> {
		Ok(())
	}

	/// Honest failure: reading `prefix_stats` is not wired up without the `xdp` feature.
	///
	/// # Errors
	/// Always: a build without XDP has no access to the kernel maps.
	pub fn read_prefix_stats(&self) -> Result<Vec<(PrefixKey, PrefixStatsVal)>> {
		anyhow::bail!("prefix_stats reading not wired yet: built without xdp feature")
	}

	pub fn get_stats(&self) -> Result<super::XdpStats> {
		Ok(super::XdpStats::default())
	}
}
