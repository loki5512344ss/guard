pub async fn run() -> anyhow::Result<()> {
    println!("Rampart Diagnostics");
    println!("=====================\n");

    let mut all_ok = true;

    let manager_url = std::env::var("RAMPART_MANAGER").unwrap_or_else(|_| "http://localhost:8080".to_string());

    match reqwest::get(format!("{manager_url}/api/v1/health")).await {
        Ok(resp) if resp.status().is_success() => {
            println!("[OK] Manager API");
        },
        _ => {
            println!("[FAIL] Manager API");
            all_ok = false;
        },
    }

    match reqwest::get(format!("{manager_url}/api/v1/blacklist")).await {
        Ok(resp) if resp.status().is_success() => {
            println!("[OK] Blacklist API");
        },
        _ => {
            println!("[WARN] Blacklist API unavailable");
        },
    }

    match reqwest::get(format!("{manager_url}/api/v1/servers")).await {
        Ok(resp) if resp.status().is_success() => {
            println!("[OK] Servers API");
        },
        _ => {
            println!("[WARN] Servers API unavailable");
        },
    }

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        println!("Some checks failed. Run with --verbose for details.");
    }

    Ok(())
}
