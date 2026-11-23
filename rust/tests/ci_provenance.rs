use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, process::Command};
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[test]
fn manifest_records_exact_source_packages_and_package_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let package = tmp.path();
    fs::write(
        package.join("vorda-0.1.0-x86_64-unknown-linux-gnu"),
        b"artifact bytes",
    )
    .unwrap();
    fs::write(
        package.join("SHA256SUMS"),
        format!(
            "{}  vorda-0.1.0-x86_64-unknown-linux-gnu\n",
            hash(b"artifact bytes")
        ),
    )
    .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_ci_helper"))
        .args(["provenance", package.to_str().unwrap()])
        .env("GITHUB_RUN_ID", "123")
        .env("GITHUB_RUN_ATTEMPT", "2")
        .status()
        .unwrap();
    assert!(status.success());
    let manifest_bytes = fs::read(package.join("BUILD-MANIFEST.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .unwrap();
    assert_eq!(
        manifest["source_commit"],
        String::from_utf8(head.stdout).unwrap().trim()
    );
    let rustc = Command::new("rustc").arg("-Vv").output().unwrap();
    assert_eq!(
        manifest["rustc"],
        String::from_utf8(rustc.stdout).unwrap().trim()
    );
    assert_eq!(manifest["schema"], "vorda-candidate-v1");
    assert_eq!(manifest["target"], "x86_64-unknown-linux-gnu");
    assert_eq!(manifest["profile"], "release");
    assert_eq!(manifest["run_id"], "123");
    assert_eq!(manifest["run_attempt"], "2");
    assert_eq!(manifest["features"], "default");
    assert_eq!(
        manifest["lock_sha256"],
        hash(&fs::read(repo.join("rust/Cargo.lock")).unwrap())
    );
    assert_eq!(
        manifest["artifacts"]["vorda-0.1.0-x86_64-unknown-linux-gnu"],
        hash(b"artifact bytes")
    );
    assert_eq!(manifest["artifacts"].as_object().unwrap().len(), 1);
    assert!(manifest["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "vorda"));
    let checksums = fs::read_to_string(package.join("SHA256SUMS")).unwrap();
    assert!(checksums.ends_with(&format!("{}  BUILD-MANIFEST.json\n", hash(&manifest_bytes))));
}

#[cfg(target_os = "linux")]
#[test]
fn release_checksums_reject_artifact_and_manifest_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let package = tmp.path();
    fs::write(
        package.join("vorda-0.1.0-x86_64-unknown-linux-gnu"),
        b"artifact bytes",
    )
    .unwrap();
    fs::write(
        package.join("SHA256SUMS"),
        format!(
            "{}  vorda-0.1.0-x86_64-unknown-linux-gnu\n",
            hash(b"artifact bytes")
        ),
    )
    .unwrap();
    assert!(Command::new(env!("CARGO_BIN_EXE_ci_helper"))
        .arg("provenance")
        .arg(package)
        .status()
        .unwrap()
        .success());
    let verify = || {
        Command::new("sha256sum")
            .args(["--check", "SHA256SUMS"])
            .current_dir(package)
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(verify());
    fs::write(
        package.join("vorda-0.1.0-x86_64-unknown-linux-gnu"),
        b"changed artifact",
    )
    .unwrap();
    assert!(!verify());
    fs::write(
        package.join("vorda-0.1.0-x86_64-unknown-linux-gnu"),
        b"artifact bytes",
    )
    .unwrap();
    assert!(verify());
    fs::write(package.join("BUILD-MANIFEST.json"), b"changed manifest").unwrap();
    assert!(!verify());
}

#[test]
fn provenance_refuses_existing_metadata_and_other_targets_without_mutation() {
    for case in ["manifest", "checksum", "windows", "aarch64", "repeat"] {
        let tmp = tempfile::tempdir().unwrap();
        let package = tmp.path();
        let name = match case {
            "windows" => "vorda-0.1.0-x86_64-pc-windows-msvc.exe",
            "aarch64" => "vorda-0.1.0-aarch64-unknown-linux-gnu",
            _ => "vorda-0.1.0-x86_64-unknown-linux-gnu",
        };
        fs::write(package.join(name), b"artifact").unwrap();
        let mut checksums = format!("{}  {name}\n", hash(b"artifact"));
        if case == "checksum" {
            checksums.push_str(&format!("{}  BUILD-MANIFEST.json\n", hash(b"old")));
        }
        fs::write(package.join("SHA256SUMS"), checksums).unwrap();
        if case == "manifest" {
            fs::write(package.join("BUILD-MANIFEST.json"), b"old").unwrap();
        }
        let invoke = |attempt: &str| {
            Command::new(env!("CARGO_BIN_EXE_ci_helper"))
                .arg("provenance")
                .arg(package)
                .env("GITHUB_RUN_ATTEMPT", attempt)
                .output()
                .unwrap()
        };
        if case == "repeat" {
            assert!(invoke("1").status.success());
        }
        let before_checksums = fs::read(package.join("SHA256SUMS")).unwrap();
        let before_manifest = fs::read(package.join("BUILD-MANIFEST.json")).ok();
        assert!(!invoke("2").status.success(), "{case}");
        assert_eq!(
            fs::read(package.join("SHA256SUMS")).unwrap(),
            before_checksums,
            "{case}"
        );
        assert_eq!(
            fs::read(package.join("BUILD-MANIFEST.json")).ok(),
            before_manifest,
            "{case}"
        );
        assert_eq!(fs::read(package.join(name)).unwrap(), b"artifact", "{case}");
    }
}
