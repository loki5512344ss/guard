use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let has_xdp_feature = std::env::var("CARGO_FEATURE_XDP").is_ok();
    if !has_xdp_feature {
        return Ok(());
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let xdp_dir = manifest_dir.join("../../xdp");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    let src = xdp_dir.join("xdp_filter.c");
    let dst = out_dir.join("xdp_filter.o");

    println!("cargo:rerun-if-changed={}", src.display());

    let host_arch = std::env::var("HOST").unwrap_or_default();
    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-mcpu=v3",
            "-c",
            src.to_str().ok_or("src path is not valid UTF-8")?,
            "-o",
            dst.to_str().ok_or("dst path is not valid UTF-8")?,
            &format!("-I{}", xdp_dir.display()),
            &format!("-I/usr/include/{}-linux-gnu", host_arch),
        ])
        .status()?;

    if !status.success() {
        return Err("XDP C compilation failed (see clang errors above)".into());
    }

    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_XDP");
    Ok(())
}
