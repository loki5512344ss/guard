use anyhow::{Context, Result};
use libbpf_rs::{MapCore, Object, OpenObject, RingBuffer, RingBufferBuilder};
use std::ffi::CString;

use crate::xdp::globals::{RODATA_MAP_NAME, XdpGlobals};

/// Builds the NUL-terminated C string libc's `if_nametoindex` requires.
/// Rejects interface names containing an interior NUL byte instead of
/// silently truncating at it (the `&str`-as-`*const c_char` UB we removed).
pub(super) fn interface_cstr(name: &str) -> Result<CString> {
    CString::new(name).with_context(|| format!("interface name {name:?} contains an interior NUL byte"))
}

/// Патчит карту `rampart_.rodata` (volatile const глобалы) ДО загрузки объекта.
pub(super) fn patch_rodata(open_obj: &mut OpenObject, globals: &XdpGlobals) -> Result<()> {
    let image = globals.build_rodata_image();
    let mut map = open_obj
        .maps_mut()
        .find(|m| m.name() == RODATA_MAP_NAME)
        .with_context(|| format!("map '{RODATA_MAP_NAME}' not found in XDP object"))?;
    map.set_initial_value(&image)
        .with_context(|| format!("failed to set initial value of '{RODATA_MAP_NAME}'"))
}

pub(super) fn build_ringbuf(obj: &Object) -> Result<RingBuffer<'static>> {
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
}
