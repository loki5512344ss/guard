use serde::Deserialize;

#[derive(Deserialize)]
struct AddResponse {
    status: String,
    target: String,
}

#[derive(Deserialize)]
struct BlacklistItem {
    target: String,
    reason: String,
}

#[derive(Deserialize)]
struct BlacklistResponse {
    items: Vec<BlacklistItem>,
    total: usize,
}

pub async fn add(target: String, reason: Option<String>) -> anyhow::Result<()> {
    let manager_url = std::env::var("MC_SHIELD_MANAGER").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let body = serde_json::json!({
        "target": target,
        "type": "ip",
        "reason": reason.unwrap_or_else(|| "manual".to_string()),
    });

    let client = reqwest::Client::new();
    match client
        .post(format!("{manager_url}/api/v1/blacklist"))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(add_resp) = resp.json::<AddResponse>().await {
                println!("[OK] {}: {}", add_resp.status, add_resp.target);
            }
        },
        Err(e) => println!("[FAIL] {e}"),
    }
    Ok(())
}

pub async fn remove(target: String) -> anyhow::Result<()> {
    println!("Removing {target} from blacklist...");
    println!("(not implemented in v0.1)");
    Ok(())
}

pub async fn list() -> anyhow::Result<()> {
    let manager_url = std::env::var("MC_SHIELD_MANAGER").unwrap_or_else(|_| "http://localhost:8080".to_string());

    match reqwest::get(format!("{manager_url}/api/v1/blacklist")).await {
        Ok(resp) => {
            if let Ok(list) = resp.json::<BlacklistResponse>().await {
                println!("Blacklist ({} entries)", list.total);
                println!("----------------------");
                for item in &list.items {
                    println!("  {} ({})", item.target, item.reason);
                }
            }
        },
        Err(e) => println!("[FAIL] {e}"),
    }
    Ok(())
}
