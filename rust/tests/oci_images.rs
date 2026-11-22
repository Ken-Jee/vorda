//! `--oci` on Debian-family images: tiny synthetic OCI layouts, built here, read offline.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, process::Command};

enum Entry<'a> {
    File(&'a str),
    Link(&'a str),
}

fn tar(entries: &[(&str, Entry)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, entry) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        match entry {
            Entry::File(text) => {
                header.set_size(text.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                builder
                    .append_data(&mut header, path, text.as_bytes())
                    .unwrap();
            }
            Entry::Link(target) => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                builder.append_link(&mut header, path, target).unwrap();
            }
        }
    }
    builder.into_inner().unwrap()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// A one-layer OCI image archive with these root filesystem entries.
fn image(dir: &Path, annotations: Value, root: &[(&str, Entry)]) -> std::path::PathBuf {
    let layer = tar(root);
    let manifest = json!({"schemaVersion":2,"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":format!("sha256:{}",digest(&layer)),"size":layer.len()}]}).to_string();
    let index = json!({"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":format!("sha256:{}",digest(manifest.as_bytes())),"size":manifest.len(),"annotations":annotations}]}).to_string();
    let layer_path = format!("blobs/sha256/{}", digest(&layer));
    let manifest_path = format!("blobs/sha256/{}", digest(manifest.as_bytes()));
    let mut outer = tar::Builder::new(Vec::new());
    for (path, bytes) in [
        ("index.json", index.as_bytes()),
        (manifest_path.as_str(), manifest.as_bytes()),
        (layer_path.as_str(), layer.as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        outer.append_data(&mut header, path, bytes).unwrap();
    }
    let path = dir.join("image.tar");
    std::fs::write(&path, outer.into_inner().unwrap()).unwrap();
    path
}

const DPKG: &str = "Package: libssl3\nStatus: install ok installed\nSource: openssl (3.0.15-1~deb12u1)\nVersion: 3.0.15-1~deb12u1\n\nPackage: zlib1g\nStatus: install ok installed\nSource: zlib\nVersion: 1:1.2.13.dfsg-1\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n";

fn run(args: &[&str], archive: &Path) -> (i32, Value) {
    let state = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .env("HTTPS_PROXY", "http://localhost:9")
        .env("HTTP_PROXY", "http://localhost:9")
        .env("NO_PROXY", "")
        .arg("--state")
        .arg(state.path())
        .args(args)
        .arg("--oci")
        .arg(archive)
        .output()
        .unwrap();
    let result = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), result)
}

fn debian_family(release: &str, annotations: Value) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    // As in the real debian and ubuntu images: /etc/os-release is a link into /usr/lib.
    let path = image(
        dir.path(),
        annotations,
        &[
            ("etc/os-release", Entry::Link("../usr/lib/os-release")),
            ("usr/lib/os-release", Entry::File(release)),
            ("var/lib/dpkg/status", Entry::File(DPKG)),
        ],
    );
    (dir, path)
}

#[test]
fn debian_and_ubuntu_images_name_the_image_and_release() {
    for (release, annotations, name, distro, ecosystem) in [
        (
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
            json!({"io.containerd.image.name":"docker.io/library/debian:12-slim","org.opencontainers.image.ref.name":"12-slim"}),
            "docker.io/library/debian:12-slim",
            "debian 12",
            "Debian:12",
        ),
        (
            "PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nUBUNTU_CODENAME=noble\n",
            json!({"org.opencontainers.image.ref.name":"24.04"}),
            "24.04",
            "ubuntu 24.04",
            "Ubuntu:24.04:LTS",
        ),
    ] {
        let (_dir, archive) = debian_family(release, annotations);
        let (exit, inventory) = run(&["inventory"], &archive);
        assert_eq!(exit, 0, "{inventory:#}");
        assert_eq!(inventory["status"], "complete");
        assert_eq!(
            inventory["image"],
            json!({"name":name,"distro":distro,"ecosystem":ecosystem})
        );
        let packages = inventory["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2, "{packages:#?}");
        assert!(packages.iter().all(|p| p["ecosystem"] == ecosystem));
        let ssl = packages.iter().find(|p| p["name"] == "libssl3").unwrap();
        assert_eq!(ssl["source_name"], "openssl");
        assert_eq!(ssl["source_version"], "3.0.15-1~deb12u1");
        // The scan names the image too; offline, so its verdict is unknown.
        let (exit, scan) = run(&["scan", "--json", "--offline"], &archive);
        assert_eq!(exit, 2);
        assert_eq!(scan["image"]["name"], name);
        assert_eq!(scan["image"]["ecosystem"], ecosystem);
    }
}

#[test]
fn images_whose_distro_cannot_be_read_or_matched_are_unknown() {
    for (root, reason) in [
        (
            vec![("var/lib/dpkg/status", Entry::File(DPKG))],
            "no readable os-release",
        ),
        (
            vec![
                (
                    "usr/lib/os-release",
                    Entry::File("ID=debian\nPRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\n"),
                ),
                ("var/lib/dpkg/status", Entry::File(DPKG)),
            ],
            "debian",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let archive = image(dir.path(), json!({}), &root);
        let (exit, inventory) = run(&["inventory"], &archive);
        assert_eq!(exit, 2, "{inventory:#}");
        assert_eq!(inventory["status"], "unknown");
        let errors = inventory["errors"].to_string();
        assert!(
            errors.contains("no advisory mapping") && errors.contains(reason),
            "{errors}"
        );
    }
}

#[test]
fn image_dpkg_blocks_are_read_by_their_dpkg_state() {
    let release = "ID=debian\nVERSION_ID=\"12\"\n";
    let status = "Package: held\nStatus: hold ok installed\nVersion: 1.0\n\nPackage: unpacked\nStatus: install ok unpacked\nVersion: 2.0\n\nPackage: gone\nStatus: purge ok not-installed\n\nPackage: broken\nStatus: install reinstreq half-installed\n\n";
    let dir = tempfile::tempdir().unwrap();
    let archive = image(
        dir.path(),
        json!({}),
        &[
            ("etc/os-release", Entry::File(release)),
            ("var/lib/dpkg/status", Entry::File(status)),
        ],
    );
    let (exit, inventory) = run(&["inventory"], &archive);
    let mut names: Vec<_> = inventory["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["held", "unpacked"], "{inventory:#}");
    assert_eq!(exit, 2, "{inventory:#}");
    let errors = inventory["errors"].to_string();
    assert!(
        errors.contains("broken") && errors.contains("not checked"),
        "{errors}"
    );
}
