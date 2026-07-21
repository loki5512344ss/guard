use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, RingBuffer, RingBufferBuilder, Xdp, XdpFlags};
use std::net::Ipv4Addr;
use std::os::unix::io::AsFd;

use super::XdpStats;

pub struct XdpFilter {
    obj: Option<Object>,
    ringbuf: Option<RingBuffer<'static>>,
    ifindex: i32,
    interface: String,
}

impl XdpFilter {
    pub fn new(interface: &str) -> Self {
        Self {
            obj: None,
            ringbuf: None,
            ifindex: 0,
            interface: interface.to_string(),
        }
    }

    pub fn load(&mut self) -> Result<()> {
        let bpf_obj = include_bytes!(concat!(env!("OUT_DIR"), "/xdp_filter.o"));
        let obj = ObjectBuilder::default()
            .open_memory(bpf_obj)
            .context("Failed to open XDP object")?
            .load()
            .context("Failed to load XDP object (verifier error?)")?;

        let ifindex = unsafe { libc::if_nametoindex(self.interface.as_ptr() as *const libc::c_char) };
        if ifindex == 0 {
            bail!("interface '{}' not found", self.interface);
        }

        let prog = obj
            .progs()
            .find(|p| p.name() == "rampart_xdp_filter")
            .context("XDP program 'rampart_xdp_filter' not found")?;
        Xdp::new(prog.as_fd()).attach(ifindex as i32, XdpFlags::NONE)?;

        let rbuf = build_ringbuf(&obj)?;

        self.obj = Some(obj);
        self.ringbuf = Some(rbuf);
        self.ifindex = ifindex as i32;
        tracing::info!("XDP filter attached to {}", self.interface);
        Ok(())
    }

    pub fn unload(&mut self) -> Result<()> {
        if self.ifindex != 0 {
            let fd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(std::os::unix::io::RawFd::from(-1)) };
            let _ = Xdp::new(fd).detach(self.ifindex, XdpFlags::NONE);
        }
        self.ringbuf = None;
        self.obj = None;
        self.ifindex = 0;
        tracing::info!("XDP filter detached from {}", self.interface);
        Ok(())
    }

    pub fn drain_events(&self) {
        if let Some(rb) = &self.ringbuf {
            let _ = rb.consume();
        }
    }

    fn find_map<'a>(&'a self, name: &str) -> Result<impl MapCore + 'a> {
        self.obj
            .as_ref()
            .context("XDP not loaded")?
            .maps()
            .find(|m| m.name() == name)
            .with_context(|| format!("map '{}' not found", name))
    }

    pub fn ban_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let map = self.find_map("blacklist_map")?;
        let mut key = [0u8; 8];
        key[0] = 32;
        key[4..8].copy_from_slice(&ip.octets());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        map.update(&key, &(now + 300_000_000_000).to_le_bytes(), MapFlags::ANY)?;
        Ok(())
    }

    pub fn unban_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let map = self.find_map("blacklist_map")?;
        let mut key = [0u8; 8];
        key[0] = 32;
        key[4..8].copy_from_slice(&ip.octets());
        map.delete(&key)?;
        Ok(())
    }

    pub fn get_stats(&self) -> Result<XdpStats> {
        let map = self.find_map("stats_map")?;
        let sum = |idx: u32| -> u64 {
            let key = idx.to_le_bytes();
            match map.lookup(&key, MapFlags::ANY) {
                Ok(Some(v)) => v
                    .chunks_exact(8)
                    .map(|c| u64::from_le_bytes(c.try_into().expect("chunk size 8")))
                    .sum(),
                _ => 0,
            }
        };
        Ok(XdpStats {
            total: sum(0),
            tcp_mc: sum(1),
            whitelist: sum(2),
            blacklist: sum(3),
            syn_throttle: sum(4),
            passed: sum(5),
            dropped: sum(6),
            verified: sum(7),
        })
    }
}

unsafe impl Send for XdpFilter {}

impl Drop for XdpFilter {
    fn drop(&mut self) {
        let _ = self.unload();
    }
}

fn build_ringbuf(obj: &Object) -> Result<RingBuffer<'static>> {
    let map = obj
        .maps()
        .find(|m| m.name() == "events_map")
        .context("events_map not found")?;
    let mut builder = RingBufferBuilder::new();
    builder.add(&map, |data: &[u8]| {
        if data.len() >= 16 {
            let ty = u32::from_ne_bytes(data[0..4].try_into().expect("4 bytes for type"));
            let ip4 = u32::from_ne_bytes(data[4..8].try_into().expect("4 bytes for ip"));
            let val = u64::from_ne_bytes(data[8..16].try_into().expect("8 bytes for val"));
            tracing::debug!(event = ty, src_ip = ip4, data = val, "xdp event");
        }
        0
    })?;
    Ok(builder.build()?)
}
