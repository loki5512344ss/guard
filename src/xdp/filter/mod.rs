use anyhow::{Context, Result};
use libbpf_rs::{MapCore, Object, ObjectBuilder, RingBuffer, Xdp, XdpFlags};
use std::os::unix::io::AsFd;
use std::sync::Arc;

use super::globals::XdpGlobals;
use crate::config::XdpConfig;
use crate::filter::blacklist::Blacklist;

use attach::{attach_program, patch_rodata};
use events::{AutoBanConfig, build_ringbuf};

mod attach;
pub(crate) mod events;
mod maps;

pub use attach::{interface_cstr, is_rodata_map, xdp_attach_mode_name};
pub use maps::{blacklist_key, blacklist6_key, normalize_cidr, whitelist_key, whitelist6_key};

pub struct XdpFilter {
	obj: Option<Object>,
	ringbuf: Option<RingBuffer<'static>>,
	ifindex: i32,
	/// Raw `XdpFlags` bits of the slot the program was actually attached to
	/// (libbpf-rs's `XdpFlags` is neither `Copy` nor `Clone`, so the bits are
	/// stored and rebuilt with `from_bits_truncate`). The kernel may pick
	/// generic (skb) mode after a failed native attach; detaching the native
	/// slot in that case would leave an orphaned filter behind.
	attach_flags: Option<u32>,
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
			attach_flags: None,
			interface: interface.to_string(),
			globals: XdpGlobals::default(),
			blacklist: None,
			autoban: AutoBanConfig::default(),
		}
	}

	/// Sets the globals used to patch `.rodata` on the next `load()`.
	pub fn set_globals(&mut self, globals: XdpGlobals) {
		self.globals = globals;
	}

	/// Wires the opt-in auto-ban from ringbuf events into the userspace `Blacklist`.
	///
	/// Must be called before `load()`. The policy is read from the `[xdp]` section; when
	/// `auto_ban_enabled = false` (the default) the callback only logs events and never
	/// touches the blacklist.
	pub fn set_autoban(&mut self, blacklist: Arc<Blacklist>, config: &XdpConfig) {
		self.blacklist = Some(blacklist);
		self.autoban = AutoBanConfig::from_xdp(config);
	}

	/// Loads the object, attaches it and registers the ringbuf reader.
	///
	/// Fallible setup (`build_ringbuf`) runs before the attach, so a failure
	/// there cannot leave a filter behind. Everything after the attach is
	/// covered by an `attach::DetachGuard`: any early return detaches instead
	/// of leaving an orphaned program that drops traffic without a reader.
	///
	/// # Errors
	/// The environment probe, object load, map setup or attach failed. On an
	/// attach failure no program is left installed.
	pub fn load(&mut self) -> Result<()> {
		// Diagnostics before loading: fail fast on an unsupported kernel or driver.
		let report = super::probe::preflight(&self.interface)?;

		let bpf_obj = include_bytes!(concat!(env!("OUT_DIR"), "/universal_filter.o"));
		// The object name is set explicitly: with `open_memory` libbpf does not know the
		// file name, yet the internal maps are named after it (`rampart_.rodata`, see
		// `patch_rodata`).
		let mut open_obj = ObjectBuilder::default()
			.name("rampart")
			.context("failed to set BPF object name")?
			.open_memory(bpf_obj)
			.context("Failed to open XDP object")?;
		patch_rodata(&mut open_obj, &self.globals)?;
		let obj = open_obj.load().with_context(|| {
			format!(
				"Failed to load XDP object (verifier error?); hint: {}",
				report.failure_hint()
			)
		})?;

		let c_interface = interface_cstr(&self.interface)?;
		// SAFETY: `c_interface` is a valid, NUL-terminated C string and is kept
		// alive until the end of this scope (past the `if_nametoindex` call), so
		// the raw pointer satisfies the `const char *` contract of the libc FFI.
		// Rust `&str` is NOT NUL-terminated, hence the `CString` conversion above.
		let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
		if ifindex == 0 {
			let err = std::io::Error::last_os_error();
			anyhow::bail!("interface '{}' not found: {err}", self.interface);
		}
		// The ringbuf is the only fallible post-attach step; building it first
		// removes the failure mode entirely instead of relying on rollback.
		super::metrics::init();
		let rbuf = build_ringbuf(&obj, self.blacklist.clone(), self.autoban)?;

		let (attach_flags, mode, guard) = attach_program(&obj, ifindex as i32, &self.interface).with_context(|| {
			format!(
				"XDP attach to '{}' failed ({}); hint: {}",
				self.interface,
				report.verdict(),
				report.failure_hint()
			)
		})?;
		guard.disarm();

		self.obj = Some(obj);
		self.ringbuf = Some(rbuf);
		self.ifindex = ifindex as i32;
		self.attach_flags = Some(attach_flags);
		tracing::info!("XDP filter attached to {} (mode: {mode})", self.interface);
		Ok(())
	}

	/// Detaches the program from the interface and drops the ringbuf.
	///
	/// The stored attach flags select the slot the kernel actually used, and
	/// the interface is queried afterwards: a detach that silently did
	/// nothing (the old `XdpFlags::NONE` on a generic-mode program) must not
	/// be reported as success.
	///
	/// # Errors
	/// The detach failed or the interface still reports an attached program.
	pub fn unload(&mut self) -> Result<()> {
		let Some(obj) = self.obj.as_ref() else {
			self.ringbuf = None;
			self.ifindex = 0;
			self.attach_flags = None;
			return Ok(());
		};
		let Some(flags) = self.attach_flags else {
			anyhow::bail!("XDP state is inconsistent: object present without attach flags");
		};
		let result = self.detach_program(obj, flags);
		self.ringbuf = None;
		if result.is_ok() {
			self.obj = None;
			self.ifindex = 0;
			self.attach_flags = None;
			tracing::info!("XDP filter detached from {}", self.interface);
		}
		result
	}

	/// Detaches the XDP program using the real program fd owned by the loaded
	/// `Object`. A detach failure while a filter is active is surfaced loudly
	/// and returned, never swallowed — otherwise the kernel keeps dropping
	/// packets we no longer intend to filter.
	fn detach_program(&self, obj: &Object, flags: u32) -> Result<()> {
		let prog = obj
			.progs()
			.find(|p| p.name() == "rampart_universal_filter")
			.context("XDP program 'rampart_universal_filter' not found while detaching")?;
		let xdp = Xdp::new(prog.as_fd());
		if let Err(e) = xdp.detach(self.ifindex, XdpFlags::from_bits_truncate(flags)) {
			tracing::error!(
				interface = %self.interface,
				ifindex = self.ifindex,
				error = %e,
				"XDP detach failed while filter was active"
			);
			return Err(e).with_context(|| format!("failed to detach XDP from '{}'", self.interface));
		}
		// Query every mode (`NONE`), not just the one we detached: only an
		// attach mode of NONE proves the interface is clean.
		let remaining = xdp
			.query(self.ifindex, XdpFlags::NONE)
			.context("failed to verify the XDP detach (query)")?
			.attach_mode;
		if remaining != 0 {
			let mode = xdp_attach_mode_name(remaining);
			anyhow::bail!(
				"XDP program is still attached to '{}' after detach (mode: {mode})",
				self.interface
			);
		}
		Ok(())
	}

	pub fn drain_events(&self) {
		if let Some(rb) = &self.ringbuf {
			let _ = rb.consume();
		}
	}

	pub(crate) fn find_map<'a>(&'a self, name: &str) -> Result<impl MapCore + 'a> {
		self.obj
			.as_ref()
			.context("XDP not loaded")?
			.maps()
			.find(|m| m.name() == name)
			.with_context(|| format!("map '{}' not found", name))
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
