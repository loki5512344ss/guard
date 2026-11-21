use anyhow::{Result, bail};

use super::types::{
	AttachMode, BTF_PATH, KernelVersion, MIN_KERNEL, OSRELEASE_PATH, SystemProbe, container_blocks_xdp,
	detect_container, driver_from_link, driver_supports_native_xdp,
};

/// Structured report on how suitable the environment is for XDP.
pub struct EnvironmentReport {
	pub kernel_version: Option<KernelVersion>,
	pub btf_available: bool,
	pub privileged: bool,
	pub driver_name: Option<String>,
	/// Container the process runs in (`lxc`, `openvz`, `docker`, ...), if any.
	pub container: Option<String>,
	pub warnings: Vec<String>,
}

impl EnvironmentReport {
	/// Collects the report through any [`SystemProbe`] implementation.
	#[must_use]
	pub fn collect(probe: &dyn SystemProbe, interface: &str) -> Self {
		let kernel_version = probe
			.read_file(OSRELEASE_PATH)
			.ok()
			.and_then(|r| KernelVersion::parse(r.trim()));
		let btf_available = probe.path_exists(BTF_PATH);
		let privileged = probe.effective_uid() == 0;
		let driver_link = probe.symlink_target(&format!("/sys/class/net/{interface}/device/driver"));
		let driver_name = driver_link.as_deref().and_then(driver_from_link);

		let container = detect_container(probe);

		let mut warnings = Vec::new();
		if let Some(kind) = container.as_deref().filter(|k| container_blocks_xdp(k)) {
			warnings.push(format!(
				"запуск внутри контейнера '{kind}': гостю обычно недоступен BPF/XDP attach — \
                 используйте KVM/bare metal или запускайте edge без [xdp]"
			));
		}
		if !privileged {
			warnings.push(
				"процесс не от root: CAP_BPF/CAP_NET_ADMIN не подтверждены, \
                 attach скорее всего завершится EPERM"
					.to_owned(),
			);
		}
		if !btf_available {
			warnings.push(format!(
				"{BTF_PATH} недоступен: CO-RE релокации невозможны, переносимость BPF-программы ограничена"
			));
		}
		if kernel_version.is_some_and(|v| v < KernelVersion::new(5, 11, 0)) {
			warnings.push(
				"ядро < 5.11: память BPF-карт ограничена RLIMIT_MEMLOCK — увеличьте `ulimit -l` или обновите ядро"
					.to_owned(),
			);
		}
		if driver_name.is_none() {
			warnings.push(format!(
				"драйвер интерфейса '{interface}' не определён (нет device/driver symlink): ожидается generic mode"
			));
		}

		Self {
			kernel_version,
			btf_available,
			privileged,
			driver_name,
			container,
			warnings,
		}
	}

	/// Ordered `(label, value)` pairs describing the environment. Shared by the daemon
	/// log and `rampart-cli doctor`, so both print exactly the same facts.
	#[must_use]
	pub fn summary_fields(&self, interface: &str) -> Vec<(&'static str, String)> {
		vec![
			("interface", interface.to_owned()),
			(
				"kernel",
				self.kernel_version
					.map_or_else(|| "unknown".to_owned(), |v| v.to_string()),
			),
			("virt", self.container.clone().unwrap_or_else(|| "none/vm".to_owned())),
			(
				"btf",
				if self.btf_available { "available" } else { "missing" }.to_owned(),
			),
			(
				"privileges",
				if self.privileged { "root" } else { "non-root" }.to_owned(),
			),
			(
				"driver",
				self.driver_name.clone().unwrap_or_else(|| "unknown".to_owned()),
			),
			("expected_mode", self.expected_mode_label().to_owned()),
		]
	}

	/// Predicted attach mode. Generic is spelled `generic (skb)` so it is never mistaken
	/// for driver-level XDP; the real mode is logged after attach.
	#[must_use]
	pub fn expected_mode_label(&self) -> &'static str {
		match self.attach_mode() {
			AttachMode::Native => "native (drv), prediction by driver table",
			AttachMode::Generic => "generic (skb)",
			AttachMode::Offload => "offload",
		}
	}

	/// One-line hint appended to attach failures so `journalctl` explains what to do.
	#[must_use]
	pub fn failure_hint(&self) -> String {
		if let Some(kind) = self.container.as_deref().filter(|k| container_blocks_xdp(k)) {
			return format!("контейнер '{kind}' не поддерживает XDP: нужна KVM-VDS или bare metal");
		}
		if !self.privileged {
			return "запустите от root или выдайте CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON".to_owned();
		}
		if !self.btf_available {
			return "ядро без BTF (/sys/kernel/btf/vmlinux): используйте ядро с CONFIG_DEBUG_INFO_BTF=y".to_owned();
		}
		"см. docs/troubleshooting.md, раздел «XDP не загружается»".to_owned()
	}

	/// Expected attach mode according to the driver table.
	#[must_use]
	pub fn attach_mode(&self) -> AttachMode {
		match self.driver_name.as_deref() {
			Some(driver) if driver_supports_native_xdp(driver) => AttachMode::Native,
			_ => AttachMode::Generic,
		}
	}

	/// Human-readable explanation of the verdict.
	#[must_use]
	pub fn verdict(&self) -> String {
		let kernel = self
			.kernel_version
			.map_or_else(|| "неизвестна".to_owned(), |v| v.to_string());
		match (self.attach_mode(), self.driver_name.as_deref()) {
			(AttachMode::Native, Some(driver)) => format!(
				"ядро {kernel}: драйвер '{driver}' поддерживает native XDP — программа работает в драйвере, минимальные накладные расходы"
			),
			(_, driver) => format!(
				"ядро {kernel}: драйвер '{}' не поддерживает native XDP → будет generic mode, CPU дороже",
				driver.unwrap_or("неизвестный")
			),
		}
	}

	/// Fail-fast check of the minimum kernel version.
	///
	/// # Errors
	/// The kernel version is unknown or below [`MIN_KERNEL`].
	pub fn validate(&self) -> Result<()> {
		let Some(version) = self.kernel_version else {
			bail!("не удалось определить версию ядра ({OSRELEASE_PATH}) — XDP attach отклонён");
		};
		if version < MIN_KERNEL {
			bail!("ядро {version} ниже минимально поддерживаемой {MIN_KERNEL}: XDP attach отклонён, обновите ядро");
		}
		Ok(())
	}
}

/// Pre-attach diagnostics before the XDP program is loaded: a structured report in the
/// log, warnings, and a fail-fast check for an old kernel. Returns the report so the
/// caller can attach it to a later attach failure.
///
/// # Errors
/// See [`EnvironmentReport::validate`].
#[cfg(feature = "xdp")]
pub(crate) fn preflight(interface: &str) -> Result<EnvironmentReport> {
	use super::types::FilesystemProbe;

	let report = EnvironmentReport::collect(&FilesystemProbe, interface);
	let fields = report
		.summary_fields(interface)
		.into_iter()
		.map(|(k, v)| format!("{k}={v}"))
		.collect::<Vec<_>>()
		.join(" ");
	tracing::info!("XDP environment: {fields}; {}", report.verdict());
	for warning in &report.warnings {
		tracing::warn!(interface, "{warning}");
	}
	report.validate()?;
	Ok(report)
}
