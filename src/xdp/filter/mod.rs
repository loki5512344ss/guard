use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, RingBuffer, Xdp, XdpFlags};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::AsFd;
use std::sync::Arc;

use super::XdpStats;
use super::globals::XdpGlobals;
use crate::config::XdpConfig;
use crate::filter::blacklist::Blacklist;
use crate::traffic::prefix::{PrefixKey, PrefixStatsVal};

use attach::{build_ringbuf, interface_cstr, patch_rodata, xdp_attach_mode_name};
use events::AutoBanConfig;
use maps::{blacklist_expiry_ns, blacklist_key, unix_ns};

mod attach;
pub(crate) mod events;
mod maps;

pub struct XdpFilter {
    obj: Option<Object>,
    ringbuf: Option<RingBuffer<'static>>,
    ifindex: i32,
    interface: String,
    globals: XdpGlobals,
    blacklist: Option<Arc<Blacklist>>,
    autoban: AutoBanConfig,
}

impl XdpFilter {
    pub fn new(interface: &str) -> Self {
        Self {
            obj: None,
            ringbuf: None,
            ifindex: 0,
            interface: interface.to_string(),
            globals: XdpGlobals::default(),
            blacklist: None,
            autoban: AutoBanConfig::default(),
        }
    }

    /// Задаёт глобалы для патчинга `.rodata` при следующем `load()`.
    pub fn set_globals(&mut self, globals: XdpGlobals) {
        self.globals = globals;
    }

    /// Подключает OPT-IN авто-бан по ringbuf-событиям к userspace-`Blacklist`.
    ///
    /// До вызова `load()`. Политика читается из `[xdp]`-секции; если
    /// `auto_ban_enabled = false` (по умолчанию), колбэк лишь логирует события и
    /// не трогает blacklist.
    pub fn set_autoban(&mut self, blacklist: Arc<Blacklist>, config: &XdpConfig) {
        self.blacklist = Some(blacklist);
        self.autoban = AutoBanConfig::from_xdp(config);
    }

    pub fn load(&mut self) -> Result<()> {
        // Диагностика ДО загрузки: fail-fast на неподдерживаемом ядре/драйвере.
        super::probe::preflight(&self.interface)?;

        let bpf_obj = include_bytes!(concat!(env!("OUT_DIR"), "/universal_filter.o"));
        // Имя объекта задаётся ЯВНО: при open_memory libbpf не знает имени файла,
        // а по нему именуются внутренние maps ("rampart_.rodata" в patch_rodata).
        let mut open_obj = ObjectBuilder::default()
            .name("rampart")
            .context("failed to set BPF object name")?
            .open_memory(bpf_obj)
            .context("Failed to open XDP object")?;
        patch_rodata(&mut open_obj, &self.globals)?;
        let obj = open_obj.load().context("Failed to load XDP object (verifier error?)")?;

        let c_interface = interface_cstr(&self.interface)?;
        // SAFETY: `c_interface` is a valid, NUL-terminated C string and is kept
        // alive until the end of this scope (past the `if_nametoindex` call), so
        // the raw pointer satisfies the `const char *` contract of the libc FFI.
        // Rust `&str` is NOT NUL-terminated, hence the `CString` conversion above.
        let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if ifindex == 0 {
            let err = std::io::Error::last_os_error();
            bail!("interface '{}' not found: {err}", self.interface);
        }

        let prog = obj
            .progs()
            .find(|p| p.name() == "rampart_universal_filter")
            .context("XDP program 'rampart_universal_filter' not found")?;
        let xdp = Xdp::new(prog.as_fd());
        // Лестница режимов: пробуем native (drv); если драйвер не тянет —
        // честный fallback в generic (skb) с предупреждением (вывод №1 из
        // конкурентного анализа: печатать режим как есть, без вранья).
        let ifindex = ifindex as i32;
        if let Err(e) = xdp.attach(ifindex, XdpFlags::NONE) {
            tracing::warn!(
                interface = %self.interface,
                error = %e,
                "native XDP attach failed, falling back to generic (skb) mode"
            );
            xdp.attach(ifindex, XdpFlags::SKB_MODE)
                .context("XDP attach failed in both native and generic modes")?;
        }
        let mode = xdp
            .query(ifindex, XdpFlags::NONE)
            .map(|q| xdp_attach_mode_name(q.attach_mode))
            .unwrap_or("unknown");

        super::metrics::init();
        let rbuf = build_ringbuf(&obj, self.blacklist.clone(), self.autoban)?;

        self.obj = Some(obj);
        self.ringbuf = Some(rbuf);
        self.ifindex = ifindex;
        tracing::info!("XDP filter attached to {} (mode: {mode})", self.interface);
        Ok(())
    }

    pub fn unload(&mut self) -> Result<()> {
        let was_attached = self.obj.is_some();
        let mut result = Ok(());
        if let Some(obj) = self.obj.as_ref() {
            result = self.detach_program(obj);
        }
        self.ringbuf = None;
        self.obj = None;
        self.ifindex = 0;
        if was_attached {
            tracing::info!("XDP filter detached from {}", self.interface);
        }
        result
    }

    /// Detaches the XDP program using the real program fd owned by the loaded
    /// `Object` (mirroring `load`'s `Xdp::new(prog.as_fd()).attach(..)`). A
    /// detach failure while a filter is active is surfaced loudly and returned,
    /// never swallowed — otherwise the kernel keeps dropping packets we no
    /// longer intend to filter.
    fn detach_program(&self, obj: &Object) -> Result<()> {
        let prog = obj
            .progs()
            .find(|p| p.name() == "rampart_universal_filter")
            .context("XDP program 'rampart_universal_filter' not found while detaching")?;
        if let Err(e) = Xdp::new(prog.as_fd()).detach(self.ifindex, XdpFlags::NONE) {
            tracing::error!(
                interface = %self.interface,
                ifindex = self.ifindex,
                error = %e,
                "XDP detach failed while filter was active"
            );
            return Err(e).with_context(|| format!("failed to detach XDP from '{}'", self.interface));
        }
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
        let key = blacklist_key(prefix_len, v4);
        let expiry_ns = blacklist_expiry_ns(unix_ns(), duration_secs);
        map.update(&key, &expiry_ns.to_le_bytes(), MapFlags::ANY)?;
        Ok(())
    }

    pub fn unban_ip(&self, ip: Ipv4Addr) -> Result<()> {
        let map = self.find_map("blacklist_map")?;
        let key = blacklist_key(32, &ip.octets());
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

// SAFETY: `XdpFilter` is only ever accessed from the single thread that owns it,
// held behind `Arc<Mutex<XdpFilter>>`; that Mutex serialization is the invariant
// that makes moving it across threads sound. Auto-`Send` is not derived because
// `libbpf_rs::Object` and the `RingBuffer<'static>` wrap non-`Send` libbpf
// handles, so the marker is asserted manually under the ownership discipline above.
unsafe impl Send for XdpFilter {}

impl Drop for XdpFilter {
    fn drop(&mut self) {
        let _ = self.unload();
    }
}
