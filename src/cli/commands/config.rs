pub async fn run(key: Option<String>, value: Option<String>) -> anyhow::Result<()> {
    match (key, value) {
        (Some(_), Some(_)) => {
            anyhow::bail!("config updates are not implemented; edit the edge config and restart Rampart")
        },
        (Some(_), None) => anyhow::bail!("config lookup is not implemented"),
        (None, Some(_)) | (None, None) => {
            println!("Configuration");
            println!("=============\n");
            println!("Use: rampart config <key> [value]");
            println!();
            println!("Example keys:");
            println!("  workers.count");
            println!("  limits.rate_limit_login_pps");
            println!("  limits.max_connections_per_ip");
            Ok(())
        },
    }
}
