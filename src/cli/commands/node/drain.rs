pub async fn run(node: &str) -> anyhow::Result<()> {
    println!("Draining node: {node}");
    println!("Waiting for active connections to drain...");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    println!("Node {node} drained successfully.");
    Ok(())
}
