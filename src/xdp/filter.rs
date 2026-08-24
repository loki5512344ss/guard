use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, OpenObject, RingBuffer, RingBufferBuilder, Xdp, XdpFlags};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::AsFd;

use super::XdpStats;
use super::globals::{RODATA_MAP_NAME, XdpGlobals};
use crate::traffic::prefix::{PrefixKey, PrefixStatsVal};

pub struct XdpFilter {
    obj: Option<Object>,
    ringbuf: Option<RingBuffer<'static>>,
    ifindex: i32,
    interface: String,
    globals: XdpGlobals,
}

impl XdpFilter {
    pub fn new(interface: &str) -> Self {
        Self {
            obj: None,
            ringbuf: None,
            ifindex: 0,
            interface: interface.to_string(),
            globals: XdpGlobals::default(),
        }
    }

    /// Задаёт глобалы для патчинга `.rodata` при следующем `load()`.
    pub fn set_globals(&mut self, globals: XdpGlobals) {
        self.globals = globals;
    }

    pub fn load(&mut self) -> Result<()> {
        // Диагностика ДО загрузки: fail-fast на неподдерживаемом ядре/драйвере.
        super::diagnostics::preflight(&self.interface)?;

        let bpf_obj = include_bytes!(concat!(env!("OUT_DIR"), "/universal_filter.o"));
        let mut open_obj = ObjectBuilder::default()
            .open_memory(bpf_obj)
            .context("Failed to open XDP object")?;
        patch_rodata(&mut open_obj, &self.globals)?;
        let obj = open_obj.load().context("Failed to load XDP object (verifier error?)")?;

        let ifindex = unsafe { libc::if_nametoindex(self.interface.as_ptr() as *const libc::c_char) };
        if ifindex == 0 {
            bail!("interface '{}' not found", self.interface);
        }

        let prog = obj
            .progs()
            .find(|p| p.name() == "rampart_universal_filter")
            .context("XDP program 'rampart_universal_filter' not found")?;
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

    pub fn ban_ip(&self, ip: Ipv4Addr, duration_secs: u64) -> Result<()> {
        self.blacklist_update(32, &ip.octets(), duration_secs)
    }

    /// Бан CIDR через `blacklist_map` (LPM trie): длина префикса в key[0].
    ///
    /// # Errors
    /// XDP не загружен, IPv6-префиксы (ядро их пока не банит) или ошибка карты.
    pub fn ban_cidr(&self, prefix: IpAddr, prefix_len: u8, duration_secs: u64) -> Result<()> {
        let IpAddr::V4(net) = prefix else {
            bail!("ipv6 cidr bans not supported yet");
        };
        self.blacklist_update(prefix_len, &net.octets(), duration_secs)
    }

    fn blacklist_update(&self, prefix_len: u8, v4: &[u8; 4], duration_secs: u64) -> Result<()> {
        let map = self.find_map("blacklist_map")?;
        let mut key = [0u8; 8];
        key[0] = prefix_len;
        key[4..8].copy_from_slice(v4);
        map.update(
            &key,
            &(unix_ns() + duration_secs * 1_000_000_000).to_le_bytes(),
            MapFlags::ANY,
        )?;
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

    /// Читает карту `prefix_stats` (агрегаты по префиксам /24 и /64).
    ///
    /// # Errors
    /// XDP не загружен, карта отсутствует в объекте или ошибка BPF-чтения.
    pub fn read_prefix_stats(&self) -> Result<Vec<(PrefixKey, PrefixStatsVal)>> {
        let map = self.find_map("prefix_stats")?;
        let mut out = Vec::new();
        for key in map.keys() {
            let Ok(kb) = <[u8; 24]>::try_from(key.as_slice()) else {
                continue;
            };
            let Some(val) = map.lookup(&kb, MapFlags::ANY).context("prefix_stats lookup failed")? else {
                continue;
            };
            let Ok(vb) = <[u8; 24]>::try_from(val.as_slice()) else {
                continue;
            };
            out.push((PrefixKey::from_bytes(kb), PrefixStatsVal::from_bytes(vb)));
        }
        Ok(out)
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
            tcp: sum(1),
            whitelist: sum(2),
            blacklist: sum(3),
            syn_throttle: sum(4),
            passed: sum(5),
            dropped: sum(6),
            udp: sum(7),
            rate_limit: sum(8),
        })
    }
}

unsafe impl Send for XdpFilter {}

impl Drop for XdpFilter {
    fn drop(&mut self) {
        let _ = self.unload();
    }
}

fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Патчит карту `rampart_.rodata` (volatile const глобалы) ДО загрузки объекта.
fn patch_rodata(open_obj: &mut OpenObject, globals: &XdpGlobals) -> Result<()> {
    let image = globals.build_rodata_image();
    let mut map = open_obj
        .maps_mut()
        .find(|m| m.name() == RODATA_MAP_NAME)
        .with_context(|| format!("map '{RODATA_MAP_NAME}' not found in XDP object"))?;
    map.set_initial_value(&image)
        .with_context(|| format!("failed to set initial value of '{RODATA_MAP_NAME}'"))
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
