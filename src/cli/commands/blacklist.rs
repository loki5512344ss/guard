//! `blacklist` subcommands: manage the manager blacklist over its HTTP API.

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
	expires_at: Option<String>,
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

/// clap value parser: a single address, strictly validated.
///
/// # Errors
/// Returns the validation message for anything but a bare IPv4/IPv6 address.
pub fn parse_target_arg(text: &str) -> Result<String, String> {
	let parsed = crate::manager::input::parse_target(text)?;
	if parsed.prefix.is_some() {
		return Err("CIDR targets are not supported; ban a single IP address".into());
	}
	Ok(parsed.ip.to_string())
}

/// clap value parser for `--for`: a human duration that must be non-zero.
///
/// # Errors
/// Returns the parser message (with the valid units) or a zero-duration message.
pub fn parse_duration_arg(text: &str) -> Result<u64, String> {
	match crate::cli::duration::parse_duration_secs(text)? {
		0 => Err("duration must be greater than zero".into()),
		secs => Ok(secs),
	}
}

fn remaining(expires_at: Option<&str>) -> String {
	let Some(at) = expires_at.and_then(crate::timeutil::parse_rfc3339_unix) else {
		return "permanent".to_string();
	};
	let left = at.saturating_sub(crate::timeutil::unix_now());
	match u64::try_from(left) {
		Ok(secs) if secs > 0 => format!("{} left", crate::cli::duration::format_duration_secs(secs)),
		_ => "expired".to_string(),
	}
}

pub async fn add(target: String, reason: Option<String>, duration_secs: Option<u64>) -> anyhow::Result<()> {
	let (client, manager_url, token) = authenticated_client().await?;

	let mut body = serde_json::json!({
		"target": target,
		"type": "ip",
		"reason": reason.unwrap_or_else(|| "manual".to_string()),
	});
	if let Some(secs) = duration_secs {
		body["duration_secs"] = secs.into();
	}

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
		println!(
			"  {} ({}) [{}]",
			item.target,
			item.reason,
			remaining(item.expires_at.as_deref())
		);
	}
	Ok(())
}
