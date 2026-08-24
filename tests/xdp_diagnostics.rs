use rampart::xdp::{AttachMode, EnvironmentReport, KernelVersion, MIN_KERNEL, SystemProbe, driver_supports_native_xdp};
use std::collections::HashMap;

struct MockProbe {
    files: HashMap<String, String>,
    symlinks: HashMap<String, String>,
    uid: u32,
}

impl MockProbe {
    fn linux(driver: &str, release: &str) -> Self {
        let mut files = HashMap::new();
        files.insert("/proc/sys/kernel/osrelease".to_owned(), format!("{release}\n"));
        files.insert("/sys/kernel/btf/vmlinux".to_owned(), String::new());
        files.insert("/proc/self/status".to_owned(), "Uid:\t0\t0\t0\t0\n".to_owned());
        let mut symlinks = HashMap::new();
        if !driver.is_empty() {
            symlinks.insert(
                "/sys/class/net/eth0/device/driver".to_owned(),
                format!("/sys/bus/pci/drivers/{driver}"),
            );
        }
        Self {
            files,
            symlinks,
            uid: 0,
        }
    }

    fn collect(&self) -> EnvironmentReport {
        EnvironmentReport::collect(self, "eth0")
    }
}

impl SystemProbe for MockProbe {
    fn read_file(&self, path: &str) -> std::io::Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| std::io::Error::other("file not found"))
    }

    fn path_exists(&self, path: &str) -> bool {
        self.files.contains_key(path) || self.symlinks.contains_key(path)
    }

    fn symlink_target(&self, path: &str) -> Option<String> {
        self.symlinks.get(path).cloned()
    }

    fn effective_uid(&self) -> u32 {
        self.uid
    }
}

#[test]
fn parses_kernel_release_with_distro_suffixes() {
    assert_eq!(
        KernelVersion::parse("6.8.0-45-generic"),
        Some(KernelVersion::new(6, 8, 0))
    );
    assert_eq!(KernelVersion::parse("5.15.0"), Some(KernelVersion::new(5, 15, 0)));
    assert_eq!(KernelVersion::parse("6.12"), Some(KernelVersion::new(6, 12, 0)));
    assert_eq!(KernelVersion::parse(""), None);
    assert_eq!(KernelVersion::parse("generic"), None);
}

#[test]
fn selects_attach_mode_by_driver_table() {
    let virtio = MockProbe::linux("virtio_net", "6.8.0-45-generic").collect();
    assert_eq!(virtio.attach_mode(), AttachMode::Native);

    let realtek = MockProbe::linux("r8169", "6.8.0-45-generic").collect();
    assert_eq!(realtek.attach_mode(), AttachMode::Generic);
}

#[test]
fn unknown_driver_falls_back_to_generic() {
    assert!(!driver_supports_native_xdp("r8169"));
    assert!(driver_supports_native_xdp("mlx5_core"));

    let no_driver = MockProbe::linux("", "6.1.0").collect();
    assert_eq!(no_driver.driver_name, None);
    assert_eq!(no_driver.attach_mode(), rampart::xdp::AttachMode::Generic);
}

#[test]
fn verdict_explains_generic_cpu_cost() {
    let report = MockProbe::linux("r8169", "6.8.0-45-generic").collect();
    let verdict = report.verdict();
    assert!(verdict.contains("r8169"), "verdict must name the driver: {verdict}");
    assert!(
        verdict.contains("generic mode"),
        "verdict must mention generic: {verdict}"
    );
    assert!(verdict.contains("CPU"), "verdict must explain CPU cost: {verdict}");

    let native = MockProbe::linux("ixgbe", "6.1.0").collect();
    assert!(native.verdict().contains("native XDP"));
}

#[test]
fn fails_fast_on_kernel_below_minimum() {
    let old = MockProbe::linux("virtio_net", "5.10.0-rc6");
    let err = old.collect().validate().expect_err("kernel 5.10 must be rejected");
    assert!(err.to_string().contains("5.10"));

    let mut unknown = MockProbe::linux("virtio_net", "6.8.0");
    unknown.files.remove("/proc/sys/kernel/osrelease");
    assert!(unknown.collect().validate().is_err(), "unknown kernel must be rejected");
}

#[test]
fn accepts_supported_kernels() {
    assert!(MIN_KERNEL == KernelVersion::new(5, 15, 0));
    for release in ["5.15.0", "6.1.0-13-amd64", "6.12.8"] {
        let report = MockProbe::linux("virtio_net", release).collect();
        report.validate().expect("supported kernel must pass validation");
    }
}

#[test]
fn warns_when_not_privileged_and_btf_missing() {
    let mut probe = MockProbe::linux("virtio_net", "6.8.0");
    probe.uid = 1000;
    probe.files.remove("/sys/kernel/btf/vmlinux");

    let report = probe.collect();
    assert!(!report.privileged);
    assert!(!report.btf_available);
    let joined = report.warnings.join("\n");
    assert!(joined.contains("CAP_BPF"), "must warn about capabilities: {joined}");
    assert!(joined.contains("CO-RE"), "must warn about missing BTF: {joined}");
}
