use anyhow::{Context, Result, bail};
use libbpf_rs::{MapCore, Object, OpenObject, RingBuffer, RingBufferBuilder};
use std::ffi::CString;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::filter::blacklist::Blacklist;
use crate::xdp::globals::{RODATA_MAP_NAME, XdpGlobals};
use crate::xdp::metrics::XDP_AUTOBANS_TOTAL;

use super::events::{AutoBanConfig, auto_ban_decision, parse_xdp_event};

/// Builds the NUL-terminated C string libc's `if_nametoindex` requires.
/// Rejects interface names containing an interior NUL byte instead of
/// silently truncating at it (the `&str`-as-`*const c_char` UB we removed).
pub(super) fn interface_cstr(name: &str) -> Result<CString> {
    CString::new(name).with_context(|| format!("interface name {name:?} contains an interior NUL byte"))
}

/// Внутренний data-map `.rodata` ищется по суффиксу: libbpf именует его
/// `<obj_name>.rodata`, а имя объекта при `open_memory` без явного `.name()`
/// вообще `memory` — точное сравнение ломалось на живом ядре (smoke-тест).
pub(super) fn is_rodata_map(name: &str) -> bool {
    name.ends_with(".rodata")
}

/// Патчит карту `*.rodata` (volatile const глобалы) ДО загрузки объекта.
pub(super) fn patch_rodata(open_obj: &mut OpenObject, globals: &XdpGlobals) -> Result<()> {
    let image = globals.build_rodata_image();
    if !open_obj
        .maps_mut()
        .any(|m| m.name().to_str().is_some_and(is_rodata_map))
    {
        let names: Vec<String> = open_obj
            .maps()
            .map(|m| m.name().to_string_lossy().into_owned())
            .collect();
        bail!("no .rodata map ('{RODATA_MAP_NAME}') in XDP object, maps: {names:?}");
    }
    let mut map = open_obj
        .maps_mut()
        .find(|m| m.name().to_str().is_some_and(is_rodata_map))
        .context("rodata map vanished between passes")?;
    map.set_initial_value(&image)
        .with_context(|| format!("failed to set initial value of '{RODATA_MAP_NAME}'"))
}

/// Честное имя режима attach по `attach_mode` из `bpf_xdp_query_opts`
/// (kernel `enum xdp_attached_mode`: NONE=0, DRV=1, OFFLOAD=2, SKB=3).
pub(super) fn xdp_attach_mode_name(mode: u8) -> &'static str {
    match mode {
        1 => "native (drv)",
        2 => "hardware offload",
        3 => "generic (skb)",
        _ => "none",
    }
}

/// Собирает ringbuf-колбэк для `events_map`.
///
/// Колбэк обязан быть `'static`, поэтому всё разделяемое состояние (`Arc<Blacklist>`,
/// копия `AutoBanConfig`) захватывается `move`-клонами. Когда `blacklist` — `None`
/// (фича не подключена) или политика выключена, события только парсятся и
/// логируются структурированно; баны не пишутся. В горячем пути нет `format!` —
/// `tracing`-поля и `&'static str` причины.
pub(super) fn build_ringbuf(
    obj: &Object,
    blacklist: Option<Arc<Blacklist>>,
    cfg: AutoBanConfig,
) -> Result<RingBuffer<'static>> {
    let map = obj
        .maps()
        .find(|m| m.name() == "events_map")
        .context("events_map not found")?;
    let mut builder = RingBufferBuilder::new();
    builder.add(&map, move |data: &[u8]| {
        let Some(event) = parse_xdp_event(data) else {
            tracing::debug!(
                len = data.len(),
                "xdp ringbuf frame ignored (too short or unknown type)"
            );
            return 0;
        };
        tracing::debug!(
            kind = ?event.kind,
            src_ip = %event.src_ip,
            metadata = event.metadata,
            "xdp event"
        );
        let Some(blacklist) = &blacklist else {
            return 0;
        };
        if let Some(ban) = auto_ban_decision(&event, &cfg) {
            let addr = IpAddr::V4(ban.ip);
            // `Blacklist::add` возвращает `()` (DashMap::insert игнорируется), а
            // править blacklist.rs вне нашей зоны нельзя — поэтому «новый ли бан»
            // определяем через публичный `is_blocked` ДО перезаписи. Это дедуп
            // лога/метрики по активному бану, а не по факту вставки.
            let already_banned = blacklist.is_blocked(addr);
            blacklist.add(addr, Duration::from_secs(ban.duration_secs), ban.reason);
            if already_banned {
                tracing::debug!(src_ip = %ban.ip, reason = ban.reason, "xdp auto-ban refreshed");
            } else {
                XDP_AUTOBANS_TOTAL.inc();
                tracing::info!(
                    src_ip = %ban.ip,
                    reason = ban.reason,
                    duration_secs = ban.duration_secs,
                    "xdp auto-ban issued"
                );
            }
        }
        0
    })?;
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_cstr_accepts_plain_names() {
        let c = interface_cstr("eth0").expect("valid interface name");
        assert_eq!(c.as_bytes(), b"eth0");
        assert_eq!(c.as_bytes_with_nul(), b"eth0\0");
    }

    #[test]
    fn interface_cstr_rejects_interior_nul() {
        assert!(interface_cstr("et\0h0").is_err());
    }

    #[test]
    fn rodata_map_matches_libbpf_naming() {
        // libbpf строит имя `<obj><section>` без замены точки (libbpf.c ~1911),
        // при open_memory без name объект называется "memory":
        assert!(is_rodata_map("rampart.rodata"));
        assert!(is_rodata_map("memory.rodata"));
        assert!(is_rodata_map(".rodata"));
        assert!(!is_rodata_map("rampart.bss"));
        assert!(!is_rodata_map("stats_map"));
    }

    #[test]
    fn attach_mode_names_are_honest() {
        assert_eq!(xdp_attach_mode_name(1), "native (drv)");
        assert_eq!(xdp_attach_mode_name(3), "generic (skb)");
        assert_eq!(xdp_attach_mode_name(2), "hardware offload");
        assert_eq!(xdp_attach_mode_name(0), "none");
    }
}
