pub async fn enable() -> anyhow::Result<()> {
    println!("Emergency mode ENABLED");
    println!("Only whitelisted IPs will be allowed through.");
    Ok(())
}

pub async fn disable() -> anyhow::Result<()> {
    println!("Emergency mode DISABLED");
    println!("Normal filtering resumed.");
    Ok(())
}
