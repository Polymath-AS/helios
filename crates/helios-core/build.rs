//! Builds libhelios (Zig) as a static library and links it with libzstd.
//!
//! Environment:
//! - `ZIG`: zig executable (default `zig`)
//! - `HELIOS_ZIG_CPU`: `-Dcpu` value (default `native`; use `baseline` for
//!   portable binaries, which loses SHA-NI accelerated hashing)
//! - `HELIOS_ZIG_TARGET`: `-Dtarget` value when cross-compiling

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let core = manifest.join("../../core").canonicalize().expect("core/ directory");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let prefix = out.join("zig-out");

    for path in ["build.zig", "build.zig.zon", "src", "include"] {
        println!("cargo:rerun-if-changed={}", core.join(path).display());
    }
    for pkg in std::fs::read_dir(core.join("../pkg")).expect("pkg/ directory").flatten() {
        println!("cargo:rerun-if-changed={}", pkg.path().display());
    }
    for var in ["ZIG", "HELIOS_ZIG_CPU", "HELIOS_ZIG_TARGET"] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let zig = env::var("ZIG").unwrap_or_else(|_| "zig".into());
    let cpu = env::var("HELIOS_ZIG_CPU").unwrap_or_else(|_| "native".into());
    let mut cmd = Command::new(&zig);
    cmd.current_dir(&core)
        .arg("build")
        .arg("-Doptimize=ReleaseFast")
        .arg(format!("-Dcpu={cpu}"))
        .arg("--prefix")
        .arg(&prefix)
        .arg("--cache-dir")
        .arg(out.join("zig-cache"));
    if let Ok(target) = env::var("HELIOS_ZIG_TARGET") {
        cmd.arg(format!("-Dtarget={target}"));
    }
    if env::var_os("ZIG_GLOBAL_CACHE_DIR").is_none() {
        cmd.env("ZIG_GLOBAL_CACHE_DIR", out.join("zig-global-cache"));
    }
    let status = cmd.status().unwrap_or_else(|e| panic!("failed to run `{zig} build` (is zig 0.16 on PATH?): {e}"));
    assert!(status.success(), "zig build failed for libhelios");

    println!("cargo:rustc-link-search=native={}", prefix.join("lib").display());
    println!("cargo:rustc-link-lib=static=helios");
    println!("cargo:include={}", prefix.join("include").display());

    if pkg_config::Config::new().atleast_version("1.5").probe("libzstd").is_err() {
        println!("cargo:rustc-link-lib=zstd");
    }
}
