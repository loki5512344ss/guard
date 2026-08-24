//! Циклы приложения: fetch-таска (tokio) и UI-цикл (tick + события клавиатуры).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::tui::fetch::{FetchError, Fetcher};
use crate::tui::prometheus::parse;
use crate::tui::state::AppState;
use crate::tui::ui;

/// Управляемые пользователем команды (клавиши).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Quit,
    Refresh,
}

/// Маппинг клавиш: `q`/`Esc` — выход, `r` — обновить немедленно.
#[must_use]
pub fn handle_key(code: crossterm::event::KeyCode) -> Option<Command> {
    match code {
        crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => Some(Command::Quit),
        crossterm::event::KeyCode::Char('r') => Some(Command::Refresh),
        _ => None,
    }
}

/// Приводит результат fetch к виду для [`AppState::apply_fetch`].
pub fn normalize(result: Result<String, FetchError>) -> Result<crate::tui::prometheus::MetricSet, String> {
    match result {
        Ok(body) => Ok(parse(&body)),
        Err(FetchError::Network(message)) => Err(message),
        Err(FetchError::Status(status)) => Err(format!("http status {status}")),
    }
}

/// Фоновая задача: fetch → [`AppState`]. Ошибки сети пишутся в снапшот баннером.
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

/// UI-цикл: рисует кадр каждые ~100 мс, обрабатывает клавиши.
///
/// # Errors
/// Возвращает ошибку терминала (draw/poll) — вызывающий восстанавливает TTY.
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

/// Неблокирующее ожидание клавиши в течение `timeout`.
fn poll_command(timeout: Duration) -> std::io::Result<Option<Command>> {
    if !crossterm::event::poll(timeout)? {
        return Ok(None);
    }
    if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
        // Реагируем только на нажатие (не автоповтор/отпускание).
        if key.kind == crossterm::event::KeyEventKind::Press {
            return Ok(handle_key(key.code));
        }
    }
    Ok(None)
}
