//! Anti-lockout: warn when an administrator's live SSH session is not whitelisted.
//!
//! A blind ban by IP cuts off SSH together with the attack. At startup the edge reads the
//! established TCP connections to the SSH port from procfs (no root, no `ss`) and warns
//! about every remote client that is not in the whitelist.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TCP_ESTABLISHED: &str = "01";
const DEFAULT_SSH_PORT: u16 = 22;

/// SSH port to inspect: the server port of the current session (`SSH_CONNECTION`) when the
/// daemon is started from SSH, otherwise 22.
#[must_use]
pub fn ssh_port(ssh_connection: Option<&str>) -> u16 {
	ssh_connection
		.and_then(|value| value.split_whitespace().nth(3))
		.and_then(|port| port.parse().ok())
		.unwrap_or(DEFAULT_SSH_PORT)
}

/// Remote addresses of established connections whose local port is `port`, parsed from
/// the contents of `/proc/net/tcp` or `/proc/net/tcp6`.
#[must_use]
pub fn established_peers(proc_net_tcp: &str, port: u16) -> Vec<IpAddr> {
	proc_net_tcp
		.lines()
		.skip(1)
		.filter_map(|line| {
			let mut fields = line.split_whitespace();
			let local = fields.nth(1)?;
			let remote = fields.next()?;
			let state = fields.next()?;
			let (_, local_port) = local.rsplit_once(':')?;
			if state != TCP_ESTABLISHED || u16::from_str_radix(local_port, 16).ok()? != port {
				return None;
			}
			parse_proc_addr(remote.rsplit_once(':')?.0)
		})
		.collect()
}

/// Decodes a procfs address: one little-endian word for IPv4, four for IPv6.
fn parse_proc_addr(hex: &str) -> Option<IpAddr> {
	match hex.len() {
		8 => Some(IpAddr::V4(Ipv4Addr::from(
			u32::from_str_radix(hex, 16).ok()?.swap_bytes(),
		))),
		32 => {
			let mut octets = [0u8; 16];
			for (index, chunk) in octets.chunks_exact_mut(4).enumerate() {
				let word = u32::from_str_radix(hex.get(index * 8..index * 8 + 8)?, 16).ok()?;
				chunk.copy_from_slice(&word.swap_bytes().to_be_bytes());
			}
			let addr = Ipv6Addr::from(octets);
			Some(addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4))
		},
		_ => None,
	}
}

/// Remote SSH clients that would be exposed to filtering: not loopback, not whitelisted.
/// The result is sorted and deduplicated.
#[must_use]
pub fn unprotected_clients(peers: &[IpAddr], whitelist: &HashSet<IpAddr>) -> Vec<IpAddr> {
	let mut exposed: Vec<IpAddr> = peers
		.iter()
		.copied()
		.filter(|ip| !ip.is_loopback() && !whitelist.contains(ip))
		.collect();
	exposed.sort();
	exposed.dedup();
	exposed
}

/// Logs a warning for every active SSH client missing from the whitelist.
pub fn warn_unlisted_ssh_clients(whitelist: &HashSet<IpAddr>) {
	let port = ssh_port(std::env::var("SSH_CONNECTION").ok().as_deref());
	let mut peers = Vec::new();
	for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
		if let Ok(table) = std::fs::read_to_string(path) {
			peers.extend(established_peers(&table, port));
		}
	}
	for ip in unprotected_clients(&peers, whitelist) {
		tracing::warn!(
			client = %ip,
			ssh_port = port,
			"active SSH client is not in `whitelist`: an XDP/blacklist ban of this address would lock you out; \
			 add it to `whitelist` in config.toml"
		);
	}
}
