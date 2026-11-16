//! Idle-aware bidirectional relay between the accepted client and the backend.

use super::Gateway;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const RELAY_BUFFER_BYTES: usize = 16 * 1024;

/// Idle budget of the client/backend relay.
///
/// Minecraft keeps one connection alive for a whole session and a legitimately
/// silent gap (menus, chunk loading, AFK timeouts) can last minutes, so 300s is
/// the safe default: it never cuts a real session and still reaps dead peers.
/// The value is a constant because `[limits]` is owned by a parallel change; it
/// is plumbed as a parameter through [`Gateway::relay_with_idle`] so a config
/// field can be wired in without touching the relay itself.
pub const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

impl Gateway {
	/// Relays bytes in both directions until either side closes, an I/O error
	/// occurs or a direction stays silent for `idle`.
	///
	/// The idle budget restarts on every successful read/write, so a long-lived
	/// session with steady traffic is never cut, while a dead or half-open peer
	/// is reaped instead of pinning two descriptors forever. Both directions run
	/// under one `select!`: when one pump finishes the other is dropped and both
	/// sockets close, preserving the cancellation semantics of
	/// `copy_bidirectional`.
	///
	/// `idle` is a parameter rather than a constant so tests can exercise the
	/// timeout with a short budget and per-upstream tuning can override it.
	///
	/// # Errors
	/// Fails on the first I/O error and on an idle timeout; a clean half-close is
	/// `Ok`.
	pub async fn relay_with_idle(&self, client: TcpStream, backend: TcpStream, idle: Duration) -> anyhow::Result<()> {
		let (client_read, mut client_write) = client.into_split();
		let (backend_read, mut backend_write) = backend.into_split();
		tokio::select! {
			result = pump(client_read, &mut backend_write, idle) => result?,
			result = pump(backend_read, &mut client_write, idle) => result?,
		}
		Ok(())
	}
}

/// Copies one direction, bounded by `idle` between chunks.
///
/// # Errors
/// Fails on a read/write error and when a direction makes no progress within
/// `idle`.
async fn pump<R, W>(mut source: R, mut sink: W, idle: Duration) -> io::Result<()>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let mut buffer = vec![0u8; RELAY_BUFFER_BYTES];
	loop {
		let read = tokio::time::timeout(idle, source.read(&mut buffer))
			.await
			.map_err(|_| idle_error())??;
		if read == 0 {
			return Ok(());
		}
		tokio::time::timeout(idle, sink.write_all(&buffer[..read]))
			.await
			.map_err(|_| idle_error())??;
	}
}

fn idle_error() -> io::Error {
	io::Error::new(io::ErrorKind::TimedOut, "relay idle timeout")
}
