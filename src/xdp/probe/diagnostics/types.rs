use std::fmt;

/// Минимально поддерживаемая версия ядра: 5.15 LTS.
pub const MIN_KERNEL: KernelVersion = KernelVersion::new(5, 15, 0);

pub(super) const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
pub(super) const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
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

pub(super) fn driver_from_link(target: &str) -> Option<String> {
    let name = target.rsplit('/').next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

/// Поддерживает ли драйвер native XDP (по таблице известных драйверов).
#[must_use]
pub fn driver_supports_native_xdp(driver: &str) -> bool {
    NATIVE_XDP_DRIVERS.contains(&driver)
}
