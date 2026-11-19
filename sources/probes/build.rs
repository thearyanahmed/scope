//! Builds ../../ebpf into $OUT_DIR/scope-probes when the `ebpf` feature is on
//! and the target is linux. SCOPE_EBPF_OBJ=<file> uses a prebuilt object instead.
//!
//! aya-build is not used: it expects the ebpf crate inside this workspace, and
//! ours is a separate workspace so the stable build never touches nightly.
//! The flags mirror aya-build 0.2 (bpf_target_arch cfg, BTF, build-std=core).

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SCOPE_EBPF_OBJ");
    let linux = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() || !linux {
        return;
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    if let Some(obj) = std::env::var_os("SCOPE_EBPF_OBJ") {
        std::fs::copy(&obj, out.join("scope-probes")).expect("copy SCOPE_EBPF_OBJ");
        return;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ebpf");
    for p in ["src", "Cargo.toml", "../sources/probes/abi/src"] {
        println!("cargo:rerun-if-changed={}", root.join(p).display());
    }
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("target arch");
    let target_dir = out.join("ebpf-target");
    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--release",
            "--bins",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        // the outer build's compiler and wrappers are for the host target, not bpf.
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!("--cfg=bpf_target_arch=\"{arch}\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf"),
        )
        .status();
    match status {
        Ok(s) if s.success() => {}
        other => panic!(
            "building ebpf programs failed ({other:?}).\n\
             needs rustup nightly with rust-src and bpf-linker (lab/docker/ebpf.Dockerfile is a working setup),\n\
             or SCOPE_EBPF_OBJ=<prebuilt object>. without them: cargo build --no-default-features (top and fault only)"
        ),
    }
    std::fs::copy(target_dir.join("bpfel-unknown-none/release/scope-probes"), out.join("scope-probes"))
        .expect("copy ebpf object");
}
