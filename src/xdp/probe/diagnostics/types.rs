use std::fmt;

/// Minimum supported kernel version: 5.15 LTS.
pub const MIN_KERNEL: KernelVersion = KernelVersion::new(5, 15, 0);

pub(super) const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
pub(super) const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
pub(super) const STATUS_PATH: &str = "/proc/self/status";

const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

pub(super) const SYSTEMD_CONTAINER_PATH: &str = "/run/systemd/container";
const OPENVZ_PATH: &str = "/proc/vz";
const OPENVZ_HOST_PATH: &str = "/proc/bc";
const DOCKERENV_PATH: &str = "/.dockerenv";

/// Detects the container/virtualization layer the process runs in, if it is a container.
///
/// Returns the systemd container id (`lxc`, `docker`, ...) or `openvz`. Full VMs (KVM,
/// VMware) are not reported: for XDP they only matter through the NIC driver.
pub(super) fn detect_container(probe: &dyn SystemProbe) -> Option<String> {
	if let Ok(raw) = probe.read_file(SYSTEMD_CONTAINER_PATH) {
		let id = raw.trim();
		if !id.is_empty() {
			return Some(id.to_owned());
		}
	}
	// `/proc/vz` without `/proc/bc` is the guest side of OpenVZ/Virtuozzo.
	if probe.path_exists(OPENVZ_PATH) && !probe.path_exists(OPENVZ_HOST_PATH) {
		return Some("openvz".to_owned());
	}
	probe.path_exists(DOCKERENV_PATH).then(|| "docker".to_owned())
}

/// Whether the container kind is known to block BPF/XDP attach (shared host kernel
/// without BPF privileges for the guest).
#[must_use]
pub fn container_blocks_xdp(kind: &str) -> bool {
	matches!(kind, "openvz" | "lxc" | "lxc-libvirt")
}

/// Drivers with known native XDP support (from the upstream kernel's native/generic
/// matrices). Absence from this list does not mean support is missing, but for such
/// drivers generic mode is predicted.
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

/// Linux kernel version, suitable for comparison (`major.minor.patch`).
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

	/// Parses a `uname -r` style string. Takes the first three numeric components and
	/// discards distribution suffixes (`6.8.0-45-generic`, `5.15.0-rc2`). A string without
	/// digits does not parse.
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

/// Mode in which the XDP program is attached to the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
	/// The program runs in the NIC driver context: lowest overhead.
	Native,
	/// The program is invoked from the network stack after ingress: works everywhere, but
	/// costs more CPU.
	Generic,
	/// Hardware offload into the NIC: requires explicit enablement and hardware support,
	/// never selected automatically.
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

/// Abstraction over procfs/sysfs: the real implementation is [`FilesystemProbe`], tests
/// supply a mock. Keeps the diagnostics independent of the real kernel.
pub trait SystemProbe {
	/// Reads a file in full.
	///
	/// # Errors
	/// Proxies the file read error.
	fn read_file(&self, path: &str) -> std::io::Result<String>;

	#[must_use]
	fn path_exists(&self, path: &str) -> bool;

	#[must_use]
	fn symlink_target(&self, path: &str) -> Option<String>;

	#[must_use]
	fn effective_uid(&self) -> u32;
}

/// Real [`SystemProbe`] implementation on top of `std::fs`.
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

	/// Heuristic: the effective uid is taken from `/proc/self/status`. root almost always
	/// holds CAP_BPF/CAP_NET_ADMIN (unless explicitly dropped); for non-root the only
	/// confirmation is an actual attach attempt. An unreadable status is treated as an
	/// unprivileged process.
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

/// Whether the driver supports native XDP (per the table of known drivers).
#[must_use]
pub fn driver_supports_native_xdp(driver: &str) -> bool {
	NATIVE_XDP_DRIVERS.contains(&driver)
}

/// Effective capability mask (`CapEff`) from `/proc/self/status`.
pub(super) fn parse_cap_eff(status: &str) -> Option<u64> {
	status
		.lines()
		.find_map(|line| u64::from_str_radix(line.strip_prefix("CapEff:")?.trim(), 16).ok())
}

/// Whether the mask allows loading and attaching XDP: `CAP_NET_ADMIN` plus
/// `CAP_BPF`+`CAP_PERFMON` (kernel 5.8+) or the legacy `CAP_SYS_ADMIN`.
pub(super) fn caps_allow_xdp(mask: u64) -> bool {
	let has = |bit: u32| mask & (1 << bit) != 0;
	has(CAP_NET_ADMIN) && ((has(CAP_BPF) && has(CAP_PERFMON)) || has(CAP_SYS_ADMIN))
}
