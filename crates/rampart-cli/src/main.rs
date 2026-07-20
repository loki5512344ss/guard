#![allow(clippy::print_stdout, clippy::print_stderr)]

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "rampart", about = "Rampart CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show overall system status
    Status,
    /// Run full diagnostics
    Doctor,
    /// Get/set configuration
    Config {
        #[arg(required = false)]
        key: Option<String>,
        #[arg(required = false)]
        value: Option<String>,
    },
    /// Manage blacklist
    Blacklist {
        #[command(subcommand)]
        action: BlacklistAction,
    },
    /// Emergency mode
    Emergency {
        #[arg(value_enum)]
        mode: EmergencyMode,
    },
    /// Gracefully drain a node
    Drain { node: String },
}

#[derive(Subcommand)]
enum BlacklistAction {
    Add { target: String, reason: Option<String> },
    Remove { target: String },
    List,
}

#[derive(clap::ValueEnum, Clone)]
enum EmergencyMode {
    Enable,
    Disable,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => commands::status::run().await,
        Commands::Doctor => commands::doctor::run().await,
        Commands::Config { key, value } => commands::config::run(key, value).await,
        Commands::Blacklist { action } => match action {
            BlacklistAction::Add { target, reason } => commands::blacklist::add(target, reason).await,
            BlacklistAction::Remove { target } => commands::blacklist::remove(target).await,
            BlacklistAction::List => commands::blacklist::list().await,
        },
        Commands::Emergency { mode } => match mode {
            EmergencyMode::Enable => commands::emergency::enable().await,
            EmergencyMode::Disable => commands::emergency::disable().await,
        },
        Commands::Drain { node } => commands::drain::run(&node).await,
    }
}
