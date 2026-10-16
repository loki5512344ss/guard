use serde::Deserialize;
use serde::Serialize;

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

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct RemoveRequest<'a> {
    target: &'a str,
}

async fn authenticated_client() -> anyhow::Result<(reqwest::Client, String, String)> {
    let manager_url = std::env::var("RAMPART_MANAGER").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let password = std::env::var("RAMPART_API_PASSWORD")
        .map_err(|_| anyhow::anyhow!("RAMPART_API_PASSWORD must be set to use the manager blacklist API"))?;
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{manager_url}/api/v1/auth/login"))
        .json(&serde_json::json!({"password": password}))
        .send()
        .await?
        .error_for_status()?;
    let token = response.json::<LoginResponse>().await?.token;
    Ok((client, manager_url, token))
}

pub async fn add(target: String, reason: Option<String>) -> anyhow::Result<()> {
    let (client, manager_url, token) = authenticated_client().await?;

    let body = serde_json::json!({
        "target": target,
        "type": "ip",
        "reason": reason.unwrap_or_else(|| "manual".to_string()),
    });

    let resp = client
        .post(format!("{manager_url}/api/v1/blacklist"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json::<AddResponse>()
        .await?;
    println!("[OK] {}: {}", resp.status, resp.target);
    Ok(())
}

pub async fn remove(target: String) -> anyhow::Result<()> {
    let (client, manager_url, token) = authenticated_client().await?;
    let response = client
        .delete(format!("{manager_url}/api/v1/blacklist"))
        .bearer_auth(token)
        .json(&RemoveRequest { target: &target })
        .send()
        .await?
        .error_for_status()?;
    let result: serde_json::Value = response.json().await?;
    println!("[OK] {}: {}", result["status"].as_str().unwrap_or("removed"), target);
    Ok(())
}

pub async fn list() -> anyhow::Result<()> {
    let (client, manager_url, token) = authenticated_client().await?;
    let list = client
        .get(format!("{manager_url}/api/v1/blacklist"))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json::<BlacklistResponse>()
        .await?;
    println!("Blacklist ({} entries)", list.total);
    println!("----------------------");
    for item in &list.items {
        println!("  {} ({})", item.target, item.reason);
    }
    Ok(())
}
