use rampart::app::{self, RunExit};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match app::run().await? {
        // Штатное завершение listener: управление возвращается tokio-рантайму.
        RunExit::Ok => Ok(()),
        // Drain-таймаут: бинарь — единственное место, где допустим process::exit.
        exit => std::process::exit(exit.code()),
    }
}
