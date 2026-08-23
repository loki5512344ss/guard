use anyhow::Result;
use std::net::Ipv4Addr;

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
    pub fn ban_ip(&self, _ip: Ipv4Addr, _duration_secs: u64) -> Result<()> {
        Ok(())
    }
    pub fn unban_ip(&self, _ip: Ipv4Addr) -> Result<()> {
        Ok(())
    }
    pub fn get_stats(&self) -> Result<super::XdpStats> {
        Ok(super::XdpStats::default())
    }
}
