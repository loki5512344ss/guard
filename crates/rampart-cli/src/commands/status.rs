pub async fn run() -> anyhow::Result<()> {
    println!("Rampart Status");
    println!("================\n");

    let manager_url = std::env::var("RAMPART_MANAGER").unwrap_or_else(|_| "http://localhost:8080".to_string());

    match reqwest::get(format!("{manager_url}/api/v1/health")).await {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                println!(
                    "Manager:     {} (v{})",
                    body["status"].as_str().unwrap_or("unknown"),
                    body["version"].as_str().unwrap_or("?")
                );
            }
        },
        Err(e) => println!("Manager:     unreachable ({e})"),
    }

    println!();
    println!("To check individual components, run: rampart doctor");
    Ok(())
}
