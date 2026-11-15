//! Edge daemon entry point; all work is delegated to [`rampart::app::run`].

use rampart::app::{self, RunExit};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	match app::run().await? {
		// Clean listener shutdown: control returns to the tokio runtime.
		RunExit::Ok => Ok(()),
		// Drain timeout: the binary is the only place where process::exit is allowed.
		exit => std::process::exit(exit.code()),
	}
}
