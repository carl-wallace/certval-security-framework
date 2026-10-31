//! Compiles the CryptoKit shim in `swift/` into a static library when the `pqc` feature is enabled
//! on an Apple target. Nothing is built otherwise, so the crate needs no Swift toolchain unless the
//! feature is asked for.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const SHIM: &str = "swift/MLDSAShim.swift";

fn main() {
    println!("cargo:rerun-if-changed={SHIM}");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=IPHONEOS_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    // docs.rs has no Swift toolchain. Rustdoc never links, so the shim is not needed there.
    if env::var_os("CARGO_FEATURE_PQC").is_none()
        || env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("apple")
        || env::var_os("DOCS_RS").is_some()
    {
        return;
    }

    let target = env::var("TARGET").expect("cargo sets TARGET");
    let platform = Platform::for_target(&target);
    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    let sdk = xcrun(&out, &["--sdk", platform.sdk, "--show-sdk-path"]);
    let swiftc = xcrun(&out, &["--find", "swiftc"]);

    let library = out.join("libcertval_sf_shim.a");
    let status = Command::new(&swiftc)
        .env("TMPDIR", &out)
        .args(["-emit-library", "-static", "-parse-as-library", "-O"])
        .args(["-module-name", "CertvalSfShim"])
        .arg("-module-cache-path")
        .arg(out.join("module-cache"))
        .args(["-target", &platform.swift_target])
        .args(["-sdk", &sdk])
        .arg("-o")
        .arg(&library)
        .arg(SHIM)
        .status()
        .unwrap_or_else(|e| panic!("could not run {swiftc}: {e}"));
    assert!(status.success(), "swiftc failed to compile {SHIM}");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=certval_sf_shim");

    // The Swift runtime ships with the OS, and the toolchain supplies the compatibility libraries
    // a Swift object built for an older deployment target links against.
    let toolchain_lib = Path::new(&swiftc)
        .parent()
        .and_then(Path::parent)
        .expect("swiftc lives in <toolchain>/usr/bin")
        .join("lib/swift")
        .join(platform.runtime_dir);
    println!("cargo:rustc-link-search=native={}", toolchain_lib.display());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
}

/// What swiftc needs to know about the Rust target.
struct Platform {
    swift_target: String,
    sdk: &'static str,
    runtime_dir: &'static str,
}

impl Platform {
    fn for_target(target: &str) -> Self {
        let macos = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".into());
        let ios = env::var("IPHONEOS_DEPLOYMENT_TARGET").unwrap_or_else(|_| "13.0".into());
        let (swift_target, sdk, runtime_dir) = match target {
            "aarch64-apple-darwin" => (format!("arm64-apple-macosx{macos}"), "macosx", "macosx"),
            "x86_64-apple-darwin" => (format!("x86_64-apple-macosx{macos}"), "macosx", "macosx"),
            "aarch64-apple-ios" => (format!("arm64-apple-ios{ios}"), "iphoneos", "iphoneos"),
            "aarch64-apple-ios-sim" => (
                format!("arm64-apple-ios{ios}-simulator"),
                "iphonesimulator",
                "iphonesimulator",
            ),
            "x86_64-apple-ios" => (
                format!("x86_64-apple-ios{ios}-simulator"),
                "iphonesimulator",
                "iphonesimulator",
            ),
            other => panic!(
                "the pqc feature builds a CryptoKit shim, and {other} is not a target it knows \
                 how to build for"
            ),
        };
        Platform {
            swift_target,
            sdk,
            runtime_dir,
        }
    }
}

/// Runs xcrun and returns its trimmed standard output.
fn xcrun(out: &Path, args: &[&str]) -> String {
    let output = Command::new("xcrun")
        // xcrun caches lookups under TMPDIR; pointing it at OUT_DIR keeps that inside the build.
        .env("TMPDIR", out)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("could not run xcrun: {e}"));
    assert!(
        output.status.success(),
        "xcrun {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("xcrun prints UTF-8")
        .trim()
        .to_string()
}
