//! `vorda update` against local fake releases. The fixtures in tests/fixtures/update were signed
//! in the minisign prehashed format with a throwaway key whose secret half was never saved:
//! `good` is release 9.9.9, `broken` claims 9.9.8 but its executable reports another version.
#![cfg(target_os = "linux")]
use std::{fs, path::Path, path::PathBuf};
use vorda::update::{install, Outcome};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/update")
}

fn key() -> String {
    fs::read_to_string(fixtures().join("update.pub")).unwrap()
}

/// Serve the files of one fixture release, with `edit` applied to what is read.
fn serve(
    release: &str,
    edit: impl Fn(&str, Vec<u8>) -> Option<Vec<u8>>,
) -> impl Fn(&str) -> vorda::Result<Option<Vec<u8>>> {
    let dir = fixtures().join(release);
    move |name| {
        Ok(fs::read(dir.join(name))
            .ok()
            .and_then(|bytes| edit(name, bytes)))
    }
}

fn as_is(_: &str, bytes: Vec<u8>) -> Option<Vec<u8>> {
    Some(bytes)
}

const RUNNING: &str = "#!/bin/sh\necho 'vorda 0.1.0'\n";

fn installed() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vorda");
    fs::write(&exe, RUNNING).unwrap();
    (dir, exe)
}

fn old(exe: &Path) -> PathBuf {
    exe.with_file_name("vorda.old")
}

fn assert_untouched(dir: &Path, exe: &Path) {
    assert_eq!(fs::read_to_string(exe).unwrap(), RUNNING);
    let names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["vorda"], "no leftover files");
}

#[test]
fn installs_a_newer_signed_release_and_keeps_the_old_one() {
    let (_dir, exe) = installed();
    let outcome = install(&serve("good", as_is), &key(), &exe, "0.1.0", None, false).unwrap();
    assert_eq!(outcome, Outcome::Installed("9.9.9".into()));
    let out = std::process::Command::new(&exe)
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "vorda 9.9.9");
    assert_eq!(fs::read_to_string(old(&exe)).unwrap(), RUNNING);
    // The release signature now sits beside the executable, where verify-self looks.
    let verify = std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("verify-self")
        .arg("--file")
        .arg(&exe)
        .arg("--pubkey")
        .arg(fixtures().join("update.pub"))
        .output()
        .unwrap();
    assert_eq!(verify.status.code(), Some(0), "{verify:?}");
}

#[test]
fn check_and_same_version_change_nothing() {
    let (dir, exe) = installed();
    let check = install(&serve("good", as_is), &key(), &exe, "0.1.0", None, true).unwrap();
    assert_eq!(check, Outcome::Available("9.9.9".into()));
    let same = install(&serve("good", as_is), &key(), &exe, "9.9.9", None, false).unwrap();
    assert_eq!(same, Outcome::Current("9.9.9".into()));
    // An older signed release is never installed unless asked for by version.
    let older = install(&serve("good", as_is), &key(), &exe, "10.0.0", None, false).unwrap();
    assert_eq!(older, Outcome::Current("9.9.9".into()));
    assert_untouched(dir.path(), &exe);
}

#[test]
fn refuses_unsigned_tampered_or_foreign_releases() {
    let foreign = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/release/release.pub"),
    )
    .unwrap();
    let cases: Vec<(&str, Box<vorda::update::Fetch>, String)> = vec![
        (
            "no signature",
            Box::new(serve("good", |n, b| {
                (!n.ends_with(".minisig")).then_some(b)
            })),
            key(),
        ),
        (
            "no executable signature",
            Box::new(serve("good", |n, b| {
                (!(n.starts_with("vorda-") && n.ends_with(".minisig"))).then_some(b)
            })),
            key(),
        ),
        ("no release", Box::new(|_: &str| Ok(None)), key()),
        (
            "edited checksums",
            Box::new(serve("good", |n, mut b| {
                if n == "SHA256SUMS" {
                    b[0] = if b[0] == b'0' { b'1' } else { b'0' };
                }
                Some(b)
            })),
            key(),
        ),
        (
            "edited executable",
            Box::new(serve("good", |n, mut b| {
                if n.starts_with("vorda-") {
                    b.extend_from_slice(b"echo extra\n");
                }
                Some(b)
            })),
            key(),
        ),
        ("another key", Box::new(serve("good", as_is)), foreign),
    ];
    for (case, fetch, key) in cases {
        let (dir, exe) = installed();
        let result = install(&*fetch, &key, &exe, "0.1.0", None, false);
        assert!(result.is_err(), "{case}: {result:?}");
        assert_untouched(dir.path(), &exe);
    }
}

#[test]
fn rolls_back_when_the_new_executable_does_not_run_as_that_version() {
    let (dir, exe) = installed();
    let result = install(&serve("broken", as_is), &key(), &exe, "0.1.0", None, false);
    assert!(result.is_err(), "{result:?}");
    assert_untouched(dir.path(), &exe);
}

#[test]
fn a_requested_version_must_be_the_release_served() {
    let (dir, exe) = installed();
    let result = install(
        &serve("good", as_is),
        &key(),
        &exe,
        "0.1.0",
        Some("9.9.8"),
        false,
    );
    assert!(result.is_err(), "{result:?}");
    assert_untouched(dir.path(), &exe);
    // Asking for a version installs it even when it is not newer.
    let outcome = install(
        &serve("good", as_is),
        &key(),
        &exe,
        "10.0.0",
        Some("9.9.9"),
        false,
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Installed("9.9.9".into()));
}
