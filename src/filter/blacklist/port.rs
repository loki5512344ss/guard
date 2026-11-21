//! Per-port ban table.
//!
//! A ban keyed by `(address, local port)` cuts an attacker off from one protected
//! service while leaving its other ports (SSH, monitoring) reachable. These bans are
//! local to the node: the Redis mirror and the XDP maps are keyed by address only, so
//! a port ban is deliberately never published or pushed into the kernel.

use super::{Blacklist, clamp_duration, deadline, normalize};
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Upper bound on distinct port bans kept in memory.
const MAX_PORT_BANS: usize = 4096;

/// Thread-safe set of active `(address, port)` bans.
pub(super) struct PortBans {
	entries: DashMap<(IpAddr, u16), Instant>,
}

impl PortBans {
	pub(super) fn new() -> Self {
		Self {
			entries: DashMap::new(),
		}
	}

	/// Bans `ip` on `port` until `expires`. Port `0` is rejected (it would mean
	/// "any port"); a full table refuses new keys but still extends existing ones.
	pub(super) fn add(&self, ip: IpAddr, port: u16, expires: Instant) -> bool {
		if port == 0 || (self.entries.len() >= MAX_PORT_BANS && !self.entries.contains_key(&(ip, port))) {
			return false;
		}
		self.entries.insert((ip, port), expires);
		true
	}

	pub(super) fn remove(&self, ip: IpAddr, port: u16) {
		self.entries.remove(&(ip, port));
	}

	/// Whether `ip` is banned on exactly `port`; an expired entry is dropped only
	/// if it is still expired (no TOCTOU against a concurrent re-ban).
	pub(super) fn is_blocked(&self, ip: IpAddr, port: u16, now: Instant) -> bool {
		if let Some(expires) = self.entries.get(&(ip, port))
			&& *expires > now
		{
			return true;
		}
		self.entries.remove_if(&(ip, port), |_, expires| *expires <= now);
		false
	}

	pub(super) fn len(&self) -> usize {
		self.entries.len()
	}

	pub(super) fn clear_expired(&self, now: Instant) {
		self.entries.retain(|_, expires| *expires > now);
	}
}

impl Blacklist {
	/// Whether `ip` is banned for local `port`: address-wide bans, or this exact port.
	pub fn is_blocked_on(&self, ip: IpAddr, port: u16) -> bool {
		self.is_blocked(ip) || self.ports.is_blocked(normalize(ip), port, Instant::now())
	}

	/// Bans `ip` on `port` only; local to this node (Redis and XDP are keyed by address).
	/// Returns `false` for port `0` or when the table is full.
	pub fn add_port(&self, ip: IpAddr, port: u16, duration: Duration) -> bool {
		self.ports.add(normalize(ip), port, deadline(clamp_duration(duration)))
	}

	/// Removes a per-port ban.
	pub fn remove_port(&self, ip: IpAddr, port: u16) {
		self.ports.remove(normalize(ip), port);
	}
}
