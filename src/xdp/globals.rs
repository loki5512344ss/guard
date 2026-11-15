//! Patches the XDP program's volatile-const globals (`xdp/core/config.h`) from the TOML config.
//!
//! The globals live in the `.rodata` section, which libbpf turns into a map named
//! `rampart_.rodata` on load. The image is patched before `load()` via
//! `OpenMapMut::set_initial_value()` (see [`crate::xdp::filter`]).
//!
//! # `[xdp]` -> `G_*` mapping (single source of truth)
//!
//! | Config key              | Global                       | Type |
//! |-------------------------|------------------------------|-----|
//! | `protected_port_start`  | `G_START_PORT`               | u16 |
//! | `protected_port_end`    | `G_END_PORT`                 | u16 |
//! | `udp_policy`            | `G_UDP_POLICY`               | u8 ("pass"=0, "drop"=1, "rate-limit"=2) |
//! | `udp_rate_hit_count`    | `G_UDP_HIT_COUNT`            | u32 |
//! | `udp_rate_window_ms`    | `G_UDP_WINDOW_NS`            | u64 (ms -> ns) |
//! | `throttle_enabled`      | `G_FEATURE_SYN_THROTTLE`     | u8 (bool -> 0/1) |
//! | `events_enabled`        | `G_FEATURE_EVENTS`           | u8 (bool -> 0/1) |
//! | `syn_challenge_enabled` | `G_SYN_CHALLENGE_ENABLED`    | u8 (bool -> 0/1) |
//! | `challenge_secret_hex`  | `G_CHALLENGE_SECRET`         | u64 (hex, big-endian) |
//! | `challenge_timeout_ms`  | `G_CHALLENGE_TIMEOUT_MS`     | u32 |
//!
//! The remaining globals (`G_SYN_*`, `G_CONNTRACK_IDLE_NS`, `G_PLAYER_IDLE_NS`,
//! `G_BAN_DURATION_NS`, `G_MAX_OUT_OF_ORDER`, `G_CHALLENGE_VERIFIED_TTL_NS`) are not
//! configurable yet; they are patched with the defaults from config.h.

use anyhow::{Context, Result, bail};
use std::mem::offset_of;

use crate::config::XdpConfig;

/// Name of the map holding the loaded BPF object's `.rodata` image.
///
/// This is the name of libbpf's internal `.rodata` map when the object is built with
/// `ObjectBuilder::name("rampart")`: libbpf concatenates `<obj_name><section>` without
/// rewriting the dot (the sanitizer passes `.` through; see libbpf.c map naming), so the
/// result is `rampart.rodata`. `patch_rodata` matches by suffix anyway, so the name is
/// only used for diagnostics.
pub(crate) const RODATA_MAP_NAME: &str = "rampart.rodata";

/// Size of the `.rodata` image in bytes: exactly `sizeof(struct rampart_config)` from
/// `xdp/core/config.h`, which `XdpGlobals` (`#[repr(C)]`) mirrors field for field.
pub const RODATA_SIZE: usize = std::mem::size_of::<XdpGlobals>();

/// `G_UDP_POLICY` value: pass UDP through.
pub const UDP_POLICY_PASS: u8 = 0;
/// `G_UDP_POLICY` value: drop all UDP.
pub const UDP_POLICY_DROP: u8 = 1;
/// `G_UDP_POLICY` value: rate-limit per window/threshold.
pub const UDP_POLICY_RATE_LIMIT: u8 = 2;

/// Default placeholder for `G_CHALLENGE_SECRET` from config.h.
const DEFAULT_CHALLENGE_SECRET: u64 = 0xA5A5_A5A5_A5A5_A5A5;

/// Runtime values of the XDP program globals; `Default` matches config.h.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpGlobals {
	pub start_port: u16,
	pub end_port: u16,
	pub syn_hit_count: u32,
	pub syn_window_ns: u64,
	pub syn_ban_duration_ns: u64,
	pub conntrack_idle_ns: u64,
	pub player_idle_ns: u64,
	pub ban_duration_ns: u64,
	pub max_out_of_order: u8,
	pub udp_policy: u8,
	pub udp_hit_count: u32,
	pub udp_window_ns: u64,
	pub feature_syn_throttle: bool,
	pub feature_events: bool,
	pub syn_challenge_enabled: bool,
	pub challenge_secret: u64,
	pub challenge_timeout_ms: u32,
	pub challenge_verified_ttl_ns: u64,
}

impl Default for XdpGlobals {
	fn default() -> Self {
		Self {
			start_port: 1,
			end_port: 65535,
			syn_hit_count: 10,
			syn_window_ns: 3_000_000_000,
			syn_ban_duration_ns: 60_000_000_000,
			conntrack_idle_ns: 30_000_000_000,
			player_idle_ns: 120_000_000_000,
			ban_duration_ns: 300_000_000_000,
			max_out_of_order: 4,
			udp_policy: UDP_POLICY_PASS,
			udp_hit_count: 100,
			udp_window_ns: 1_000_000_000,
			feature_syn_throttle: true,
			feature_events: true,
			syn_challenge_enabled: false,
			challenge_secret: DEFAULT_CHALLENGE_SECRET,
			challenge_timeout_ms: 3000,
			challenge_verified_ttl_ns: 300_000_000_000,
		}
	}
}

impl XdpGlobals {
	/// Builds the byte image of `.rodata`: a mirror of `struct rampart_config` from
	/// `xdp/core/config.h`.
	///
	/// Offsets come from the `#[repr(C)]` type itself (`offset_of!`) instead of being
	/// hardcoded, because the layout is defined by the C struct — not by the symbol order
	/// the linker happens to pick.
	pub fn build_rodata_image(&self) -> Vec<u8> {
		let mut img = vec![0u8; RODATA_SIZE];
		let put16 = |img: &mut [u8], off: usize, v: u16| img[off..off + 2].copy_from_slice(&v.to_le_bytes());
		let put32 = |img: &mut [u8], off: usize, v: u32| img[off..off + 4].copy_from_slice(&v.to_le_bytes());
		let put64 = |img: &mut [u8], off: usize, v: u64| img[off..off + 8].copy_from_slice(&v.to_le_bytes());
		put16(&mut img, offset_of!(Self, start_port), self.start_port);
		put16(&mut img, offset_of!(Self, end_port), self.end_port);
		put32(&mut img, offset_of!(Self, syn_hit_count), self.syn_hit_count);
		put64(&mut img, offset_of!(Self, syn_window_ns), self.syn_window_ns);
		put64(
			&mut img,
			offset_of!(Self, syn_ban_duration_ns),
			self.syn_ban_duration_ns,
		);
		put64(&mut img, offset_of!(Self, conntrack_idle_ns), self.conntrack_idle_ns);
		put64(&mut img, offset_of!(Self, player_idle_ns), self.player_idle_ns);
		put64(&mut img, offset_of!(Self, ban_duration_ns), self.ban_duration_ns);
		img[offset_of!(Self, max_out_of_order)] = self.max_out_of_order;
		img[offset_of!(Self, udp_policy)] = self.udp_policy;
		put32(&mut img, offset_of!(Self, udp_hit_count), self.udp_hit_count);
		put64(&mut img, offset_of!(Self, udp_window_ns), self.udp_window_ns);
		img[offset_of!(Self, feature_syn_throttle)] = u8::from(self.feature_syn_throttle);
		img[offset_of!(Self, feature_events)] = u8::from(self.feature_events);
		img[offset_of!(Self, syn_challenge_enabled)] = u8::from(self.syn_challenge_enabled);
		put64(&mut img, offset_of!(Self, challenge_secret), self.challenge_secret);
		put32(
			&mut img,
			offset_of!(Self, challenge_timeout_ms),
			self.challenge_timeout_ms,
		);
		put64(
			&mut img,
			offset_of!(Self, challenge_verified_ttl_ns),
			self.challenge_verified_ttl_ns,
		);
		img
	}

	/// Builds the globals from the `[xdp]` section of the config.
	///
	/// # Errors
	/// Unknown `udp_policy` value; malformed `challenge_secret_hex` (not hex, or not
	/// 8 bytes); `protected_port_end < protected_port_start`.
	pub fn from_config(cfg: &XdpConfig) -> Result<Self> {
		let mut g = Self {
			start_port: cfg.protected_port_start,
			end_port: cfg.protected_port_end,
			udp_hit_count: cfg.udp_rate_hit_count,
			udp_window_ns: cfg.udp_rate_window_ms.saturating_mul(1_000_000),
			feature_syn_throttle: cfg.throttle_enabled,
			feature_events: cfg.events_enabled,
			syn_challenge_enabled: cfg.syn_challenge_enabled,
			challenge_timeout_ms: cfg.challenge_timeout_ms,
			..Self::default()
		};
		if g.end_port < g.start_port {
			bail!(
				"xdp.protected_port_end ({}) < xdp.protected_port_start ({})",
				g.end_port,
				g.start_port
			);
		}
		g.udp_policy = match cfg.udp_policy.as_str() {
			"pass" => UDP_POLICY_PASS,
			"drop" => UDP_POLICY_DROP,
			"rate-limit" => UDP_POLICY_RATE_LIMIT,
			other => bail!("invalid xdp.udp_policy '{other}' (expected pass|drop|rate-limit)"),
		};
		if let Some(secret) = cfg.challenge_secret_hex.as_deref() {
			g.challenge_secret = parse_secret_hex(secret)?;
		}
		Ok(g)
	}
}

/// Parses a 16-hex-digit secret (8 bytes, optional `0x` prefix) into a big-endian u64.
/// `_`, `:` and `-` separators are ignored.
fn parse_secret_hex(s: &str) -> Result<u64> {
	let cleaned = s.trim().trim_start_matches("0x").replace(['_', ':', '-'], "");
	let bytes = hex::decode(&cleaned).with_context(|| format!("invalid xdp.challenge_secret_hex '{s}'"))?;
	let arr: [u8; 8] = bytes
		.try_into()
		.map_err(|v: Vec<u8>| anyhow::anyhow!("xdp.challenge_secret_hex must be exactly 8 bytes, got {}", v.len()))?;
	Ok(u64::from_be_bytes(arr))
}
