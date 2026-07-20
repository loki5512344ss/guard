pub async fn run(key: Option<String>, value: Option<String>) -> anyhow::Result<()> {
    match (key, value) {
        (Some(k), Some(v)) => {
            println!("Setting {k} = {v}");
            Ok(())
        },
        (Some(k), None) => {
            println!("Reading config key: {k}");
            println!("(not implemented in v0.1)");
            Ok(())
        },
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
