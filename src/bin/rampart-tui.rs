//! `rampart-tui` — интерактивный терминальный дашборд live-метрик Rampart.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::Notify;

use rampart::tui::app;
use rampart::tui::fetch::{Fetcher, HttpFetcher};
use rampart::tui::state::AppState;

#[derive(Parser)]
#[command(
    name = "rampart-tui",
    about = "Rampart live metrics TUI (Prometheus /metrics source)"
)]
struct Cli {
    /// URL Prometheus metrics endpoint
    #[arg(long, default_value = "http://127.0.0.1:9090/metrics")]
    url: String,
    /// Период опроса, секунды
    #[arg(long, default_value_t = 1)]
    refresh_secs: u64,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Some(fetcher) = HttpFetcher::new(cli.url.clone()) else {
        anyhow::bail!("failed to build http client");
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

    let terminal = ratatui::try_init()?;
    let result = runtime.block_on(run(
        terminal,
        Arc::new(fetcher) as Arc<dyn Fetcher>,
        cli.url,
        Duration::from_secs(cli.refresh_secs.max(1)),
    ));
    ratatui::restore();
    result
}

async fn run(
    mut terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
    fetcher: Arc<dyn Fetcher>,
    url: String,
    refresh: Duration,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new(url));
    let notify = Arc::new(Notify::new());
    tokio::spawn(app::spawn_fetch_loop(
        fetcher,
        Arc::clone(&state),
        refresh,
        Arc::clone(&notify),
    ));
    app::run_ui(&mut terminal, state, notify)
        .await
        .map_err(anyhow::Error::from)
}
