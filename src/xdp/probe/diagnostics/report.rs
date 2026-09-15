use anyhow::{Result, bail};

use super::types::{
    AttachMode, BTF_PATH, FilesystemProbe, KernelVersion, MIN_KERNEL, OSRELEASE_PATH, SystemProbe, driver_from_link,
    driver_supports_native_xdp,
};

/// Структурированный отчёт о пригодности окружения для XDP.
pub struct EnvironmentReport {
    pub kernel_version: Option<KernelVersion>,
    pub btf_available: bool,
    pub privileged: bool,
    pub driver_name: Option<String>,
    pub warnings: Vec<String>,
}

impl EnvironmentReport {
    /// Собирает отчёт через произвольную реализацию [`SystemProbe`].
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

        let mut warnings = Vec::new();
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
            warnings,
        }
    }

    /// Ожидаемый режим attach по таблице драйверов.
    #[must_use]
    pub fn attach_mode(&self) -> AttachMode {
        match self.driver_name.as_deref() {
            Some(driver) if driver_supports_native_xdp(driver) => AttachMode::Native,
            _ => AttachMode::Generic,
        }
    }

    /// Человекочитаемое объяснение вердикта.
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

    /// Fail-fast проверка минимальной версии ядра.
    ///
    /// # Errors
    /// Версия ядра не определена или ниже [`MIN_KERNEL`].
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

/// Предстартовая диагностика перед загрузкой XDP-программы:
/// структурный отчёт в лог, предупреждения, fail-fast на старом ядре.
///
/// # Errors
/// См. [`EnvironmentReport::validate`].
#[cfg(feature = "xdp")]
pub(crate) fn preflight(interface: &str) -> Result<()> {
    let report = EnvironmentReport::collect(&FilesystemProbe, interface);
    let kernel = report
        .kernel_version
        .map_or_else(|| "unknown".to_owned(), |v| v.to_string());
    tracing::info!(
        interface,
        kernel = %kernel,
        btf = report.btf_available,
        privileged = report.privileged,
        driver = report.driver_name.as_deref().unwrap_or("unknown"),
        mode = %report.attach_mode(),
        "XDP environment: {}",
        report.verdict()
    );
    for warning in &report.warnings {
        tracing::warn!(interface, "{warning}");
    }
    report.validate()
}
