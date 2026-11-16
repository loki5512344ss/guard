//! Parsing and policy for XDP ringbuf events (`struct xdp_event`).
//!
//! Parsing and the auto-ban policy are pure functions covered by
//! `tests/xdp_events.rs`; [`build_ringbuf`] wires the same policy into the libbpf
//! ringbuf callback.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, Object, RingBuffer, RingBufferBuilder};

use crate::config::XdpConfig;
use crate::filter::blacklist::Blacklist;
use crate::xdp::metrics::XDP_AUTOBANS_TOTAL;

/// Exact size of `struct xdp_event` (see `xdp/core/common.h:61-66`):
/// `__u32 type` @0, `__u32 src_ip` @4, `__u32 metadata` @8,
/// 4 bytes of padding @12 (to align `__u64`), `__u64 timestamp` @16 -> 24.
pub const XDP_EVENT_LEN: usize = 24;

/// Event type from `enum event_type` (`common.h:54-59`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpEventKind {
	/// `EVENT_BAN` — the packet was already in `blacklist_map` and was dropped by the kernel.
	Ban,
	/// `EVENT_RATE_LIMIT` — the throttling threshold was exceeded (SYN/UDP).
	RateLimit,
	/// `EVENT_POLICY_DROP` — a static policy match (UDP drop / malicious TCP flags).
	PolicyDrop,
	/// `EVENT_CONN_DROP` — the flow was dropped (sequence mismatch or a hook verdict).
	ConnDrop,
}

impl XdpEventKind {
	/// Decodes the numeric value of the C enum. An unknown type yields `None` plus a debug log.
	fn from_u32(raw: u32) -> Option<Self> {
		match raw {
			0 => Some(Self::Ban),
			1 => Some(Self::RateLimit),
			2 => Some(Self::PolicyDrop),
			3 => Some(Self::ConnDrop),
			other => {
				tracing::debug!(event_type = other, "xdp event: unknown type, dropped");
				None
			},
		}
	}
}

/// A parsed ringbuf event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpEvent {
	pub kind: XdpEventKind,
	/// Source IPv4 address (for IPv4-mapped IPv6 the kernel stores the low u32 in `src_ip`).
	pub src_ip: Ipv4Addr,
	/// The `__u32 metadata` field: for `RateLimit` the throttling threshold that fired, for
	/// `ConnDrop` the `conn->fails` counter, `0` otherwise.
	pub metadata: u32,
	/// `bpf_ktime_get_ns()` at generation time (monotonic, not wall clock).
	pub timestamp_ns: u64,
}

/// Parses a 24-byte `struct xdp_event` frame.
///
/// # Byte order (verified against the C source)
/// The scalar fields (`type`, `metadata`, `timestamp`) are written by the kernel in host
/// order without conversion: `push_event` assigns them as they are — `e->type = type`,
/// `e->metadata = meta`, `e->timestamp = bpf_ktime_get_ns()` (`common.h:92-95`; no
/// `bpf_htonl`/`bpf_ntohl` is applied). Userspace reads the same bytes on the same
/// machine, so `from_ne_bytes` is correct.
///
/// `src_ip` is different: it is in network order (big-endian octets) because it comes
/// straight from the packet header as `src_ip = ip->saddr` (`universal_filter.c:149`)
/// and is copied into the event without `bpf_htonl` (`common.h:93`). Bytes `data[4..8]`
/// are therefore the address octets in dotted order and must be read as
/// `Ipv4Addr::new(octets...)`, not as `from_ne_bytes(u32)` (the old bug produced a
/// reversed IP on little-endian hosts).
///
/// Returns `None` if the frame is shorter than `XDP_EVENT_LEN` or the type is unknown.
pub fn parse_xdp_event(bytes: &[u8]) -> Option<XdpEvent> {
	let raw: &[u8; XDP_EVENT_LEN] = bytes.get(..XDP_EVENT_LEN)?.try_into().ok()?;
	let kind = XdpEventKind::from_u32(u32::from_ne_bytes(raw[0..4].try_into().ok()?))?;
	let src_ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
	let metadata = u32::from_ne_bytes(raw[8..12].try_into().ok()?);
	// `raw[12..16]` is alignment padding for `__u64`; it is not read because the kernel
	// never initialises it.
	let timestamp_ns = u64::from_ne_bytes(raw[16..24].try_into().ok()?);
	Some(XdpEvent {
		kind,
		src_ip,
		metadata,
		timestamp_ns,
	})
}

/// Auto-ban parameters, resolved from the `[xdp]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoBanConfig {
	pub enabled: bool,
	pub duration_secs: u64,
	pub conn_drop_fails: u8,
}

impl Default for AutoBanConfig {
	fn default() -> Self {
		Self {
			enabled: false,
			duration_secs: 60,
			conn_drop_fails: 3,
		}
	}
}

impl AutoBanConfig {
	/// Takes the values from the `[xdp]` config section (the single source of truth).
	pub fn from_xdp(cfg: &XdpConfig) -> Self {
		Self {
			enabled: cfg.auto_ban_enabled,
			duration_secs: cfg.auto_ban_duration_secs,
			conn_drop_fails: cfg.auto_ban_conn_drop_fails,
		}
	}
}

/// A ready-to-apply ban for the userspace `Blacklist`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanAction {
	pub ip: Ipv4Addr,
	pub duration_secs: u64,
	/// Static reason (no allocation on the hot path).
	pub reason: &'static str,
}

/// Pure decision: whether the event source should be banned and for how long.
///
/// Returns `None` when the feature is disabled or the event type is not bannable. The
/// per-type split follows the C code:
///
/// * [`XdpEventKind::Ban`] — not banned. The event is emitted only after the kernel has
///   already found the IP in `blacklist_map` and dropped the packet
///   (`universal_filter.c:220-225`), so a second userspace ban is pointless and could
///   mask the regular expiry.
/// * [`XdpEventKind::PolicyDrop`] — not banned by default. This is a static per-packet
///   policy: the UDP drop policy (`:234`) and malicious TCP flags (`:259`). Banning on a
///   single malformed packet would re-ban legitimate but buggy clients, and there is no
///   accumulation threshold here by design.
/// * [`XdpEventKind::RateLimit`] — banned. The throttling threshold has already been
///   exceeded; the UDP path (`:237-243`) only drops and does not insert into the
///   blacklist (unlike the SYN path at `:295`), so the userspace ban adds real
///   protection.
/// * [`XdpEventKind::ConnDrop`] — banned only when `metadata` (= `conn->fails`) reached
///   the threshold (`:364-368`). A protocol-hook drop arrives with `fails = 0` (`:418`),
///   below the threshold, so it is not banned.
#[must_use]
pub fn auto_ban_decision(event: &XdpEvent, config: &AutoBanConfig) -> Option<BanAction> {
	if !config.enabled {
		return None;
	}
	match event.kind {
		XdpEventKind::Ban | XdpEventKind::PolicyDrop => None,
		XdpEventKind::RateLimit => Some(BanAction {
			ip: event.src_ip,
			duration_secs: config.duration_secs,
			reason: "xdp-rate-limit",
		}),
		XdpEventKind::ConnDrop if event.metadata >= u32::from(config.conn_drop_fails) => Some(BanAction {
			ip: event.src_ip,
			duration_secs: config.duration_secs,
			reason: "xdp-conn-drop",
		}),
		XdpEventKind::ConnDrop => None,
	}
}

/// Builds the ringbuf callback for `events_ringbuf`.
///
/// The callback must be `'static`, so all shared state (`Arc<Blacklist>`, a copy of
/// `AutoBanConfig`) is captured by `move` clones. When `blacklist` is `None` (feature not
/// wired) or the policy is disabled, events are only parsed and logged in a structured
/// way; no bans are written. The hot path does no `format!` — only `tracing` fields and
/// `&'static str` reasons.
pub(super) fn build_ringbuf(
	obj: &Object,
	blacklist: Option<Arc<Blacklist>>,
	cfg: AutoBanConfig,
) -> Result<RingBuffer<'static>> {
	let map = obj
		.maps()
		.find(|m| m.name() == "events_ringbuf")
		.context("events_ringbuf not found")?;
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
			// `Blacklist::add` returns `()` (it ignores `DashMap::insert`) and blacklist.rs is
			// out of our edit scope, so "is this a new ban" is decided through the public
			// `is_blocked` before the overwrite. This dedups the log line and the metric by
			// active ban, not by the fact of insertion.
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

// Parser and policy coverage lives in `tests/xdp_events.rs` (this module is kept under
// the 250-line limit; `src/xdp/filter/` already has the maximum of 4 files per directory).
