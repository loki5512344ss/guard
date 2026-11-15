//! `emergency` subcommand: switch the edge policy into or out of emergency mode.

/// Switches emergency mode on.
///
/// # Errors
/// Always fails: emergency mode is not implemented yet.
pub async fn enable() -> anyhow::Result<()> {
	anyhow::bail!("emergency mode is not implemented; change the edge policy and restart Rampart")
}

/// Switches emergency mode off.
///
/// # Errors
/// Always fails: emergency mode is not implemented yet.
pub async fn disable() -> anyhow::Result<()> {
	anyhow::bail!("emergency mode is not implemented; change the edge policy and restart Rampart")
}
