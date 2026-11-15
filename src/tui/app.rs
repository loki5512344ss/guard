//! Application loops: the fetch task (tokio) and the UI loop (tick plus
//! keyboard events).
//!
//! Owns the wiring between a [`Fetcher`] and the terminal: the fetch task never
//! draws and the UI loop never performs I/O beyond the terminal itself.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::tui::fetch::{FetchError, Fetcher};
use crate::tui::prometheus::parse;
use crate::tui::state::AppState;
use crate::tui::ui;

/// Commands the user can trigger from the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
	Quit,
	Refresh,
}

/// Key mapping: `q`/`Esc` quit, `r` refreshes immediately.
#[must_use]
pub fn handle_key(code: crossterm::event::KeyCode) -> Option<Command> {
	match code {
		crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => Some(Command::Quit),
		crossterm::event::KeyCode::Char('r') => Some(Command::Refresh),
		_ => None,
	}
}

/// Converts a fetch result into the shape expected by [`AppState::apply_fetch`].
pub fn normalize(result: Result<String, FetchError>) -> Result<crate::tui::prometheus::MetricSet, String> {
	match result {
		Ok(body) => Ok(parse(&body)),
		Err(FetchError::Network(message)) => Err(message),
		Err(FetchError::Status(status)) => Err(format!("http status {status}")),
	}
}

/// Background task: fetch into [`AppState`].
///
/// Network failures are stored in the snapshot and rendered as an error banner,
/// so a dead endpoint degrades the view instead of ending the session.
pub async fn spawn_fetch_loop(fetcher: Arc<dyn Fetcher>, state: Arc<AppState>, refresh: Duration, notify: Arc<Notify>) {
	loop {
		let started = std::time::Instant::now();
		let result = normalize(fetcher.fetch().await);
		let elapsed_secs = started.elapsed().as_secs_f64();
		state.apply_fetch(result, elapsed_secs);

		tokio::select! {
			() = tokio::time::sleep(refresh) => {},
			() = notify.notified() => {},
		}
	}
}

/// UI loop: draws a frame roughly every 100 ms and handles key presses.
///
/// # Errors
/// Returns the terminal error from draw/poll; the caller is responsible for
/// restoring the TTY.
pub async fn run_ui(
	terminal: &mut ratatui::Terminal<impl ratatui::backend::Backend<Error = std::io::Error>>,
	state: Arc<AppState>,
	notify: Arc<Notify>,
) -> std::io::Result<()> {
	loop {
		terminal.draw(|frame| ui::render(frame, &state.frame_data()))?;
		if let Some(command) = poll_command(Duration::from_millis(100))? {
			match command {
				Command::Quit => return Ok(()),
				Command::Refresh => notify.notify_one(),
			}
		}
	}
}

/// Non-blocking wait for a key press within `timeout`.
fn poll_command(timeout: Duration) -> std::io::Result<Option<Command>> {
	if !crossterm::event::poll(timeout)? {
		return Ok(None);
	}
	if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
		// React to presses only, ignoring auto-repeat and key releases.
		if key.kind == crossterm::event::KeyEventKind::Press {
			return Ok(handle_key(key.code));
		}
	}
	Ok(None)
}
