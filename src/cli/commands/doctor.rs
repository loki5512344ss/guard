use crate::xdp::{EnvironmentReport, FilesystemProbe, SystemProbe};

/// Ищет интерфейс с маршрутом по умолчанию в /proc/net/route
/// (destination == 00000000). Работает без root.
fn default_route_interface(probe: &impl SystemProbe) -> Option<String> {
    let routes = probe.read_file("/proc/net/route").ok()?;
    routes.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.len() > 7 && fields[1] == "00000000").then(|| fields[0].to_owned())
    })
}

/// Подсекция network/XDP: что видно окружению без root.
fn print_network_section(all_ok: &mut bool) {
    println!("\nNetwork / XDP");
    println!("-------------");

    let probe = FilesystemProbe;
    let Some(interface) = default_route_interface(&probe) else {
        println!("[WARN] Default route interface not found, XDP checks skipped");
        return;
    };
    println!("Interface: {interface}");

    let report = EnvironmentReport::collect(&probe, &interface);
    let kernel = report
        .kernel_version
        .map_or_else(|| "unknown".to_owned(), |v| v.to_string());
    println!("Kernel: {kernel}");
    println!(
        "BTF: {}",
        if report.btf_available {
            "available"
        } else {
            "missing (CO-RE disabled)"
        }
    );
    println!(
        "Privileges: {}",
        if report.privileged {
            "root (capabilities assumed)"
        } else {
            "non-root"
        }
    );
    println!("Driver: {}", report.driver_name.as_deref().unwrap_or("unknown"));
    println!("Attach mode: {}", report.attach_mode());
    println!("Verdict: {}", report.verdict());
    for warning in &report.warnings {
        println!("[WARN] {warning}");
    }
    if let Err(e) = report.validate() {
        println!("[FAIL] {e}");
        *all_ok = false;
    } else {
        println!("[OK] XDP environment");
    }
}

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

    print_network_section(&mut all_ok);

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        println!("Some checks failed. Run with --verbose for details.");
    }

    Ok(())
}
