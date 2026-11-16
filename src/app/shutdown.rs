//! Edge daemon shutdown drain: signal handling, drain timer and exit code.

use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::watch;

/// Daemon exit outcome. The exit code is computed here, but `process::exit` is
/// only called from the binary entry point (`src/bin/rampart.rs`), which keeps
/// the library free of the `exit` lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunExit {
	/// The listener finished cleanly: the drain fit into the timeout.
	Ok,
	/// The drain timeout expired: the binary must terminate the process immediately
	/// (replaces the former `process::exit(0)` inside the shutdown timer).
	DrainTimeout,
}

impl RunExit {
	/// Process exit code for this outcome.
	///
	/// A forced drain timeout loses connections that did not finish in time, so
	/// it must not look like a clean shutdown to supervisors and scripts.
	#[must_use]
	pub const fn code(self) -> i32 {
		match self {
			Self::Ok => 0,
			Self::DrainTimeout => 1,
		}
	}
}

/// Spawns the background shutdown task.
///
/// The timer must end the process, but `process::exit` now lives in the binary,
/// so this only reports the drain timeout to `run` over a oneshot channel. The
/// process is given five seconds to drain after the signal.
pub(crate) fn spawn_shutdown_drain(shutdown_tx: watch::Sender<bool>, drain_tx: oneshot::Sender<()>) {
	tokio::spawn(async move {
		wait_for_signal().await;
		tracing::info!("shutdown signal received, draining connections...");
		let _ = shutdown_tx.send(true);
		tokio::time::sleep(Duration::from_secs(5)).await;
		tracing::info!("shutdown timeout reached, exiting");
		let _ = drain_tx.send(());
	});
}

async fn wait_for_signal() {
	let ctrl_c = tokio::signal::ctrl_c();
	let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
		.expect("failed to install SIGTERM handler");

	tokio::select! {
		_ = ctrl_c => {}
		_ = term.recv() => {}
	}
}
