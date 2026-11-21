//! Command-line client for the Rampart manager API.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use clap::{Parser, Subcommand};
use rampart::cli::commands;

#[derive(Parser)]
#[command(name = "rampart-cli", about = "Rampart management CLI")]
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
	/// Ban an address, optionally for a limited time (`--for 1h30m`)
	Add {
		/// Single IPv4/IPv6 address
		#[arg(value_parser = commands::blacklist::parse_target_arg)]
		target: String,
		reason: Option<String>,
		/// Ban duration: 30s, 5m, 1h30m, 2d (a bare number is rejected)
		#[arg(long = "for", value_name = "DURATION", value_parser = commands::blacklist::parse_duration_arg)]
		duration: Option<u64>,
	},
	/// Remove a ban
	Remove {
		#[arg(value_parser = commands::blacklist::parse_target_arg)]
		target: String,
	},
	/// List active bans with remaining time
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
		Commands::Status => commands::node::status::run().await,
		Commands::Doctor => commands::doctor::run().await,
		Commands::Config { key, value } => commands::config::run(key, value).await,
		Commands::Blacklist { action } => match action {
			BlacklistAction::Add {
				target,
				reason,
				duration,
			} => commands::blacklist::add(target, reason, duration).await,
			BlacklistAction::Remove { target } => commands::blacklist::remove(target).await,
			BlacklistAction::List => commands::blacklist::list().await,
		},
		Commands::Emergency { mode } => match mode {
			EmergencyMode::Enable => commands::node::emergency::enable().await,
			EmergencyMode::Disable => commands::node::emergency::disable().await,
		},
		Commands::Drain { node } => commands::node::drain::run(&node).await,
	}
}
