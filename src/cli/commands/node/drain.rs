//! `drain` subcommand: gracefully drain a node.

/// Drains `node` gracefully.
///
/// # Errors
/// Always fails: draining is not implemented yet.
pub async fn run(node: &str) -> anyhow::Result<()> {
	anyhow::bail!("graceful drain is not implemented for node {node}")
}
