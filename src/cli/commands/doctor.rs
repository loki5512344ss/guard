//! `doctor` subcommand: environment, manager API and XDP diagnostics.

use crate::xdp::{EnvironmentReport, FilesystemProbe, SystemProbe};

/// Environment variable holding a ready-to-use manager bearer token.
const TOKEN_ENV: &str = "RAMPART_TOKEN";
/// Environment variable holding the manager API password used to log in.
const PASSWORD_ENV: &str = "RAMPART_API_PASSWORD";

/// Finds the interface that owns the default route in `/proc/net/route`
/// (destination `00000000`). Works without root.
fn default_route_interface(probe: &impl SystemProbe) -> Option<String> {
	let routes = probe.read_file("/proc/net/route").ok()?;
	routes.lines().skip(1).find_map(|line| {
		let fields: Vec<&str> = line.split_whitespace().collect();
		(fields.len() > 7 && fields[1] == "00000000").then(|| fields[0].to_owned())
	})
}

/// Obtains a bearer token for the protected manager endpoints.
///
/// `RAMPART_TOKEN` is used as is; otherwise `RAMPART_API_PASSWORD` is exchanged
/// for a token via `/api/v1/auth/login`. Protected endpoints are never called
/// anonymously, so `None` means the caller has to be told to provide a
/// credential instead of seeing a misleading failure.
async fn manager_token(client: &reqwest::Client, manager_url: &str) -> Option<String> {
	if let Ok(token) = std::env::var(TOKEN_ENV) {
		if !token.trim().is_empty() {
			return Some(token);
		}
	}
	let password = std::env::var(PASSWORD_ENV).ok().filter(|value| !value.is_empty())?;
	let response = client
		.post(format!("{manager_url}/api/v1/auth/login"))
		.json(&serde_json::json!({"password": password}))
		.send()
		.await
		.ok()?;
	if !response.status().is_success() {
		println!("[WARN] Manager login rejected ({})", response.status());
		return None;
	}
	let body = response.json::<serde_json::Value>().await.ok()?;
	body["token"].as_str().map(str::to_owned)
}

/// Probes one protected manager endpoint with a bearer token.
async fn check_protected(client: &reqwest::Client, manager_url: &str, path: &str, label: &str, token: Option<&str>) {
	let Some(token) = token else {
		println!("[SKIP] {label}: set {TOKEN_ENV} or {PASSWORD_ENV} to check it");
		return;
	};
	match client
		.get(format!("{manager_url}{path}"))
		.bearer_auth(token)
		.send()
		.await
	{
		Ok(resp) if resp.status().is_success() => println!("[OK] {label}"),
		Ok(resp) => println!("[WARN] {label} unavailable ({})", resp.status()),
		Err(e) => println!("[WARN] {label} unavailable: {e}"),
	}
}

/// Network/XDP section: what the environment exposes without root.
fn print_network_section(all_ok: &mut bool) {
	println!("\nNetwork / XDP");
	println!("-------------");

	let probe = FilesystemProbe;
	let Some(interface) = default_route_interface(&probe) else {
		println!("[WARN] Default route interface not found, XDP checks skipped");
		return;
	};
	let report = EnvironmentReport::collect(&probe, &interface);
	for (label, value) in report.summary_fields(&interface) {
		println!("{label}: {value}");
	}
	println!("Verdict: {}", report.verdict());
	for warning in &report.warnings {
		println!("[WARN] {warning}");
	}
	if let Err(e) = report.validate() {
		println!("[FAIL] {e}");
		*all_ok = false;
	} else {
		println!("[OK] XDP environment");
		println!("hint if attach fails: {}", report.failure_hint());
	}
}

/// Runs every diagnostic and prints the report.
///
/// # Errors
/// Returns an error when any check failed, so scripts and CI see a non-zero
/// exit status instead of a report that only looks alarming.
pub async fn run() -> anyhow::Result<()> {
	println!("Rampart Diagnostics");
	println!("=====================\n");

	let mut all_ok = true;

	let manager_url = std::env::var("RAMPART_MANAGER").unwrap_or_else(|_| "http://localhost:8080".to_string());
	let client = reqwest::Client::new();

	match client.get(format!("{manager_url}/api/v1/health")).send().await {
		Ok(resp) if resp.status().is_success() => {
			println!("[OK] Manager API");
		},
		_ => {
			println!("[FAIL] Manager API");
			all_ok = false;
		},
	}

	let token = manager_token(&client, &manager_url).await;
	check_protected(
		&client,
		&manager_url,
		"/api/v1/blacklist",
		"Blacklist API",
		token.as_deref(),
	)
	.await;
	check_protected(
		&client,
		&manager_url,
		"/api/v1/servers",
		"Servers API",
		token.as_deref(),
	)
	.await;

	print_network_section(&mut all_ok);

	println!();
	if !all_ok {
		println!("Some checks failed. Run with --verbose for details.");
		anyhow::bail!("doctor: one or more checks failed");
	}
	println!("All checks passed.");
	Ok(())
}
