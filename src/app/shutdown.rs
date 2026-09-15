//! Shutdown-drain машина edge-демона: сигнал, drain-таймер и код завершения.

use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::watch;

/// Результат завершения демона. Код выхода вычисляется здесь, но сам
/// `process::exit` вызывается только в точке входа бинаря (`src/bin/rampart.rs`),
/// поэтому библиотечный код остаётся свободным от lint `exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunExit {
    /// Listener отработал штатно: drain уложился в таймаут.
    Ok,
    /// Истёк drain-таймаут: бинарь обязан завершить процесс немедленно
    /// (замена прежнему `process::exit(0)` внутри shutdown-таймера).
    DrainTimeout,
}

impl RunExit {
    /// Код завершения процесса для данного результата.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::DrainTimeout => 0,
        }
    }
}

/// Ставит фоновую shutdown-задачу.
///
/// shutdown-таймер обязан завершить процесс: сам `process::exit` вынесен в
/// бинарь, а здесь мы лишь уведомляем `run` об истечении drain-таймаута через
/// oneshot-канал. Логи и тайминг (5s после сигнала) сохранены без изменений.
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

#[cfg(test)]
mod tests {
    use super::RunExit;

    #[test]
    fn run_exit_codes_match_previous_process_exit() {
        // Штатный путь и прежний drain-timeout (`process::exit(0)`) завершались с кодом 0.
        assert_eq!(RunExit::Ok.code(), 0);
        assert_eq!(RunExit::DrainTimeout.code(), 0);
    }
}
