use std::ffi::CString;
use std::os::unix::io::AsFd;

use anyhow::{Context, Result, bail};
use libbpf_rs::{Object, OpenObject, Program, Xdp, XdpFlags};

use crate::xdp::globals::{RODATA_MAP_NAME, XdpGlobals};

/// Name of the XDP program inside the compiled object.
const XDP_PROG_NAME: &str = "rampart_universal_filter";

/// Builds the NUL-terminated C string libc's `if_nametoindex` requires.
/// Rejects interface names containing an interior NUL byte instead of
/// silently truncating at it (the `&str`-as-`*const c_char` UB we removed).
pub fn interface_cstr(name: &str) -> Result<CString> {
	CString::new(name).with_context(|| format!("interface name {name:?} contains an interior NUL byte"))
}

/// The internal `.rodata` data map is matched by suffix: libbpf names it
/// `<obj_name>.rodata`, and with `open_memory` and no explicit `.name()` the object is
/// called `memory` — an exact comparison broke on a live kernel (smoke test).
pub fn is_rodata_map(name: &str) -> bool {
	name.ends_with(".rodata")
}

/// Patches the `*.rodata` map (volatile-const globals) before the object is loaded.
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
	// libbpf rejects a value whose size differs from the map's (EINVAL, and the
	// error message says nothing useful). Fail loudly here instead: a mismatch
	// means `struct rampart_config` in config.h and `XdpGlobals` drifted apart.
	let expected = map.value_size() as usize;
	if image.len() != expected {
		bail!(
			"XDP .rodata map expects {expected} bytes, loader image has {} — \
			 struct rampart_config (xdp/core/config.h) and XdpGlobals (src/xdp/globals.rs) diverged",
			image.len()
		);
	}
	map.set_initial_value(&image)
		.with_context(|| format!("failed to set initial value of '{RODATA_MAP_NAME}'"))
}

/// `XDP_ATTACHED_*` values from `linux/netlink.h` (`IFLA_XDP_ATTACHED`).
///
/// The order is NONE, DRV, SKB, HW, MULTI — hardware offload is 3, not 2.
const XDP_ATTACHED_DRV: u8 = 1;
const XDP_ATTACHED_SKB: u8 = 2;
const XDP_ATTACHED_HW: u8 = 3;
const XDP_ATTACHED_MULTI: u8 = 4;

/// Honest name of the attach mode, derived from the `attach_mode` field of
/// `bpf_xdp_query_opts` (kernel `enum xdp_attach_mode`).
pub fn xdp_attach_mode_name(mode: u8) -> &'static str {
	match mode {
		XDP_ATTACHED_DRV => "native (drv)",
		XDP_ATTACHED_SKB => "generic (skb)",
		XDP_ATTACHED_HW => "hardware offload",
		XDP_ATTACHED_MULTI => "multiple programs",
		_ => "none",
	}
}

/// Detach flags matching the mode the kernel actually attached the program in.
///
/// The mode is discovered after attach via `bpf_xdp_query`; using the flags
/// that were *requested* is wrong when the kernel picked a different mode
/// (for example generic after a failed native attach).
fn detach_flags_for_mode(mode: u8) -> Option<XdpFlags> {
	match mode {
		XDP_ATTACHED_DRV => Some(XdpFlags::DRV_MODE),
		XDP_ATTACHED_SKB => Some(XdpFlags::SKB_MODE),
		XDP_ATTACHED_HW => Some(XdpFlags::HW_MODE),
		XDP_ATTACHED_MULTI => None,
		// NONE: the query failed after a successful attach.
		_ => None,
	}
}

/// Attaches with the native-first mode ladder and returns the detach flags.
fn attach_with_fallback(xdp: &Xdp<'_>, ifindex: i32, interface: &str) -> Result<XdpFlags> {
	if let Err(e) = xdp.attach(ifindex, XdpFlags::NONE) {
		tracing::warn!(
			interface = %interface,
			error = %e,
			"native XDP attach failed, falling back to generic (skb) mode"
		);
		xdp.attach(ifindex, XdpFlags::SKB_MODE)
			.context("XDP attach failed in both native and generic modes")?;
		Ok(XdpFlags::SKB_MODE)
	} else {
		Ok(XdpFlags::NONE)
	}
}

/// Finds the loader's XDP program in a loaded object.
fn find_xdp_program<'obj>(obj: &'obj Object) -> Result<Program<'obj>> {
	obj.progs()
		.find(|p| p.name() == XDP_PROG_NAME)
		.with_context(|| format!("XDP program '{XDP_PROG_NAME}' not found"))
}

/// Detaches the program if it is dropped while still armed.
///
/// Any error between a successful attach and the moment `XdpFilter` takes
/// ownership leaves an XDP program attached that drops traffic but has no
/// userspace reader (an orphaned filter). This guard makes that window fail
/// safe: unless [`DetachGuard::disarm`] was called, dropping it detaches.
pub(super) struct DetachGuard<'obj> {
	prog: Program<'obj>,
	ifindex: i32,
	/// Raw `XdpFlags` bits: `XdpFlags` itself is neither `Copy` nor `Clone`.
	flags_bits: u32,
	armed: bool,
}

impl<'obj> DetachGuard<'obj> {
	fn new(prog: Program<'obj>, ifindex: i32, flags_bits: u32) -> Self {
		Self {
			prog,
			ifindex,
			flags_bits,
			armed: true,
		}
	}

	/// Marks the attach as committed; dropping the guard is then a no-op.
	pub(super) fn disarm(mut self) {
		self.armed = false;
	}
}

impl Drop for DetachGuard<'_> {
	fn drop(&mut self) {
		if !self.armed {
			return;
		}
		if let Err(e) = Xdp::new(self.prog.as_fd()).detach(self.ifindex, XdpFlags::from_bits_truncate(self.flags_bits))
		{
			tracing::error!(
				ifindex = self.ifindex,
				error = %e,
				"XDP attach rollback failed: the program may still be attached"
			);
		} else {
			tracing::warn!(ifindex = self.ifindex, "XDP attach rolled back after a setup failure");
		}
	}
}

/// Attaches the program and returns `(detach flags, mode name, rollback guard)`.
///
/// The returned guard must be disarmed only after every fallible step that
/// follows the attach has succeeded. The attach mode is queried from the
/// kernel (not assumed from the requested flags) so that a generic-mode
/// fallback is detached from the generic slot.
pub(super) fn attach_program<'obj>(
	obj: &'obj Object,
	ifindex: i32,
	interface: &str,
) -> Result<(u32, &'static str, DetachGuard<'obj>)> {
	let prog = find_xdp_program(obj)?;
	let requested = {
		let xdp = Xdp::new(prog.as_fd());
		attach_with_fallback(&xdp, ifindex, interface)?
	};
	let mode = match Xdp::new(prog.as_fd()).query(ifindex, XdpFlags::NONE) {
		Ok(query) => query.attach_mode,
		Err(e) => {
			tracing::warn!(
				interface = %interface,
				error = %e,
				"XDP attach-mode query failed; assuming the requested flags"
			);
			0
		},
	};
	// Fall back to the requested flags when the query failed or the interface
	// reports several programs (MULTI): that is the best detach handle we have.
	let flags_bits = detach_flags_for_mode(mode).unwrap_or(requested).bits();
	let guard = DetachGuard::new(prog, ifindex, flags_bits);
	let name = if mode == 0 {
		"unknown"
	} else {
		xdp_attach_mode_name(mode)
	};
	Ok((flags_bits, name, guard))
}
