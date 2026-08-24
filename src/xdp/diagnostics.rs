//! Диагностика окружения перед XDP-attach: ядро, BTF, драйвер NIC, привилегии.
//!
//! Основной источник боли при XDP — непонятные ошибки attach на неподдерживаемых
//! ядрах и драйверах. Модуль собирает [`EnvironmentReport`] ДО загрузки BPF-программы
//! и даёт человекочитаемый вердикт с предупреждениями.

use anyhow::{Result, bail};
use std::fmt;

/// Минимально поддерживаемая версия ядра: 5.15 LTS.
pub const MIN_KERNEL: KernelVersion = KernelVersion::new(5, 15, 0);

const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const STATUS_PATH: &str = "/proc/self/status";

/// Драйверы с известной поддержкой native XDP (по данным xdpgeneric/native
/// матриц upstream-ядра). Отсутствие в списке не означает отсутствие поддержки,
/// но для таких драйверов предсказываем generic mode.
const NATIVE_XDP_DRIVERS: &[&str] = &[
    "virtio_net",
    "ixgbe",
    "ixgbevf",
    "i40e",
    "iavf",
    "ice",
    "mlx4_core",
    "mlx5_core",
    "igb",
    "igc",
    "e1000e",
    "vmxnet3",
    "bnxt_en",
    "nfp",
    "sfc",
    "ena",
    "hv_netvsc",
    "macvlan",
];

/// Версия ядра Linux, пригодная для сравнения (`major.minor.patch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl KernelVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    /// Парсит строку формата `uname -r`. Берёт первые три числовых компонента,
    /// дистрибутивные суффиксы (`6.8.0-45-generic`, `5.15.0-rc2`) отбрасываются.
    /// Строка без цифр не парсится.
    #[must_use]
    pub fn parse(release: &str) -> Option<Self> {
        let mut nums = release
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|part| part.parse::<u16>().ok());
        let major = nums.next()?;
        let minor = nums.next().unwrap_or(0);
        let patch = nums.next().unwrap_or(0);
        Some(Self::new(major, minor, patch))
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Режим присоединения XDP-программы к интерфейсу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Программа исполняется в контексте драйвера NIC — минимальные накладные расходы.
    Native,
    /// Программа вызывается из сетевого стека после ingress — работает везде, дороже по CPU.
    Generic,
    /// Аппаратная разгрузка в NIC — требует явного включения и поддержки железа,
    /// автоматически не выбирается.
    Offload,
}

impl fmt::Display for AttachMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Generic => "generic",
            Self::Offload => "offload",
        })
    }
}

/// Абстракция над procfs/sysfs: реальная реализация — [`FilesystemProbe`],
/// в тестах — мок. Изолирует диагностику от реального ядра.
pub trait SystemProbe {
    /// Читает файл целиком.
    ///
    /// # Errors
    /// Проксирует ошибку чтения файла.
    fn read_file(&self, path: &str) -> std::io::Result<String>;

    #[must_use]
    fn path_exists(&self, path: &str) -> bool;

    #[must_use]
    fn symlink_target(&self, path: &str) -> Option<String>;

    #[must_use]
    fn effective_uid(&self) -> u32;
}

/// Реальная реализация [`SystemProbe`] поверх `std::fs`.
pub struct FilesystemProbe;

impl SystemProbe for FilesystemProbe {
    fn read_file(&self, path: &str) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn path_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn symlink_target(&self, path: &str) -> Option<String> {
        Some(std::fs::read_link(path).ok()?.to_string_lossy().into_owned())
    }

    /// Эвристика: эффективный uid берётся из `/proc/self/status`.
    /// root почти всегда имеет CAP_BPF/CAP_NET_ADMIN (если явно не урезаны);
    /// для не-root подтверждение возможно только попыткой attach.
    /// Нечитаемый статус трактуем как непривилегированный процесс.
    fn effective_uid(&self) -> u32 {
        std::fs::read_to_string(STATUS_PATH)
            .ok()
            .and_then(|status| parse_euid(&status))
            .unwrap_or(1)
    }
}

fn parse_euid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        let mut fields = line.strip_prefix("Uid:")?.split_whitespace();
        fields.nth(1)?.parse().ok()
    })
}

fn driver_from_link(target: &str) -> Option<String> {
    let name = target.rsplit('/').next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

/// Поддерживает ли драйвер native XDP (по таблице известных драйверов).
#[must_use]
pub fn driver_supports_native_xdp(driver: &str) -> bool {
    NATIVE_XDP_DRIVERS.contains(&driver)
}

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
