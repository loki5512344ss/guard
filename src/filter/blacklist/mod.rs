//! In-memory ban tables.
//!
//! Two tables are kept: bans detected locally and bans mirrored from Redis.
//! Expired entries are removed lazily on lookup and periodically by
//! [`Blacklist::clear_expired`]. Deadlines are monotonic and clamped, so a
//! hostile expiry can never overflow or panic.

mod prefix;

use self::prefix::PrefixBans;
use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const LOCAL_BAN_EVENT_CAPACITY: usize = 4096;

/// Upper bound for a single ban; longer requests are clamped.
pub const MAX_BAN_DURATION_SECS: u64 = 31_536_000;

/// A locally detected ban, forwarded to the Redis publisher.
#[derive(Clone, Debug)]
pub struct LocalBanEvent {
	pub ip: IpAddr,
	/// Wall-clock expiry as Unix seconds.
	pub expires_at_unix: i64,
	pub reason: String,
}

struct BanEntry {
	expires: Instant,
	_reason: String,
}

/// Combined view of local and Redis-mirrored bans.
pub struct Blacklist {
	entries: Arc<DashMap<IpAddr, BanEntry>>,
	redis_entries: Arc<DashMap<IpAddr, BanEntry>>,
	prefixes: PrefixBans,
	local_ban_events: broadcast::Sender<LocalBanEvent>,
}

impl Default for Blacklist {
	fn default() -> Self {
		Self::new()
	}
}

impl Blacklist {
	/// Creates an empty blacklist.
	pub fn new() -> Self {
		let (local_ban_events, _) = broadcast::channel(LOCAL_BAN_EVENT_CAPACITY);
		Self {
			entries: Arc::new(DashMap::new()),
			redis_entries: Arc::new(DashMap::new()),
			prefixes: PrefixBans::new(),
			local_ban_events,
		}
	}

	/// Returns whether `ip` is banned: exact match or inside a CIDR ban.
	pub fn is_blocked(&self, ip: IpAddr) -> bool {
		let ip = normalize(ip);
		Self::is_blocked_in(&self.entries, ip)
			|| Self::is_blocked_in(&self.redis_entries, ip)
			|| self.prefixes.is_blocked(ip, Instant::now())
	}

	/// Adds a CIDR ban covering `ip/prefix_len` and broadcasts its network
	/// address, so other nodes mirror at least that host.
	///
	/// Invalid prefix lengths (`0`, `> 32` for IPv4, `> 128` for IPv6) are
	/// ignored: a `/0` ban would blackhole the whole address family.
	pub fn add_cidr(&self, ip: IpAddr, prefix_len: u8, duration: Duration, reason: &str) {
		let duration = clamp_duration(duration);
		let Some(start) = self.prefixes.add(ip, prefix_len, deadline(duration)) else {
			tracing::warn!(%ip, prefix_len, "ignoring CIDR ban with an invalid prefix length");
			return;
		};
		let expires_at_unix = now_unix().saturating_add(duration.as_secs()).min(i64::MAX as u64) as i64;
		let _ = self.local_ban_events.send(LocalBanEvent {
			ip: start,
			expires_at_unix,
			reason: reason.to_string(),
		});
	}

	/// Adds a local ban and broadcasts it for the Redis publisher.
	pub fn add(&self, ip: IpAddr, duration: Duration, reason: &str) {
		let ip = normalize(ip);
		let duration = clamp_duration(duration);
		let expires_at_unix = now_unix().saturating_add(duration.as_secs()).min(i64::MAX as u64) as i64;
		self.entries.insert(
			ip,
			BanEntry {
				expires: deadline(duration),
				_reason: reason.to_string(),
			},
		);
		let _ = self.local_ban_events.send(LocalBanEvent {
			ip,
			expires_at_unix,
			reason: reason.to_string(),
		});
	}

	/// Subscribes to locally detected bans.
	pub fn subscribe_local_bans(&self) -> broadcast::Receiver<LocalBanEvent> {
		self.local_ban_events.subscribe()
	}

	/// Returns all active local bans.
	pub fn local_snapshot(&self) -> Vec<LocalBanEvent> {
		let now = Instant::now();
		let now_unix = now_unix();
		self.entries
			.iter()
			.filter(|entry| entry.expires > now)
			.map(|entry| LocalBanEvent {
				ip: *entry.key(),
				expires_at_unix: now_unix
					.saturating_add(entry.expires.saturating_duration_since(now).as_secs())
					.min(i64::MAX as u64) as i64,
				reason: entry._reason.clone(),
			})
			.collect()
	}

	/// Removes a local ban.
	pub fn remove(&self, ip: IpAddr) {
		self.entries.remove(&normalize(ip));
	}

	/// Adds a Redis-mirrored ban.
	pub fn add_redis(&self, ip: IpAddr, duration: Duration, reason: &str) {
		let ip = normalize(ip);
		let duration = clamp_duration(duration);
		self.redis_entries.insert(
			ip,
			BanEntry {
				expires: deadline(duration),
				_reason: reason.to_string(),
			},
		);
	}

	/// Removes a Redis-mirrored ban.
	pub fn remove_redis(&self, ip: IpAddr) {
		self.redis_entries.remove(&normalize(ip));
	}

	/// Replaces the Redis-managed ban set, preserving locally detected bans.
	///
	/// New entries are inserted before stale ones are removed, so a reconnect
	/// never exposes a window without bans. A ban that disappeared upstream
	/// stops applying after this call.
	pub fn replace_redis<I>(&self, entries: I)
	where
		I: IntoIterator<Item = (IpAddr, Duration, String)>,
	{
		let mut fresh = HashSet::new();
		for (ip, duration, reason) in entries {
			fresh.insert(ip);
			self.add_redis(ip, duration, &reason);
		}
		self.redis_entries.retain(|ip, _| fresh.contains(ip));
	}

	/// Total number of tracked bans.
	pub fn len(&self) -> usize {
		self.entries.len() + self.redis_entries.len() + self.prefixes.len()
	}

	/// Returns whether all ban tables are empty.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Drops expired entries from all tables.
	pub fn clear_expired(&self) {
		let now = Instant::now();
		self.entries.retain(|_, entry| entry.expires > now);
		self.redis_entries.retain(|_, entry| entry.expires > now);
		self.prefixes.clear_expired(now);
	}

	/// Checks `entries`, lazily removing `ip` only if it is still expired.
	///
	/// The conditional removal avoids a TOCTOU race in which a concurrent
	/// re-ban would be deleted right after the expired entry was observed.
	fn is_blocked_in(entries: &DashMap<IpAddr, BanEntry>, ip: IpAddr) -> bool {
		let now = Instant::now();
		if let Some(entry) = entries.get(&ip)
			&& entry.expires > now
		{
			return true;
		}
		entries.remove_if(&ip, |_, entry| entry.expires <= now);
		false
	}
}

/// Collapses IPv4-mapped IPv6 addresses to IPv4, so one client never occupies
/// two different keys in the ban tables.
fn normalize(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
		IpAddr::V4(_) => ip,
	}
}

/// Clamps a requested duration to [`MAX_BAN_DURATION_SECS`].
fn clamp_duration(duration: Duration) -> Duration {
	duration.min(Duration::from_secs(MAX_BAN_DURATION_SECS))
}

/// Returns the monotonic deadline for an already clamped duration.
///
/// Overflow cannot occur for clamped values, but is handled defensively so a
/// malformed duration can never panic the data plane.
fn deadline(duration: Duration) -> Instant {
	Instant::now()
		.checked_add(duration)
		.unwrap_or_else(|| Instant::now() + Duration::from_secs(MAX_BAN_DURATION_SECS))
}

/// Current wall-clock time as Unix seconds.
fn now_unix() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}
