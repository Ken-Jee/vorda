// The fixtures were made by the real minisign 0.12 program with a throwaway key whose secret
// half was discarded: payload.minisig is its default prehashed `ED` form, payload.legacy.minisig
// the `-l` legacy `Ed` form, and wrong.pub is a second, unrelated throwaway key.
use serde_json::Value;
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use vorda::release::verify_self;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/release")
        .join(name)
}

fn run(exe: &OsStr, args: &[&OsStr]) -> (Option<i32>, Value) {
    let output = Command::new(exe)
        .arg("verify-self")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("not JSON: {stdout}"));
    (output.status.code(), report)
}

fn check(file: &Path, sig: &Path, key: &str) -> (Option<i32>, Value) {
    let key = fixture(key);
    let args = [
        "--file".as_ref(),
        file.as_os_str(),
        "--sig".as_ref(),
        sig.as_os_str(),
    ];
    let args = [&args[..], &["--pubkey".as_ref(), key.as_os_str()]].concat();
    run(env!("CARGO_BIN_EXE_vorda").as_ref(), &args)
}

#[test]
fn both_minisign_signature_forms_verify() {
    for (sig, comment) in [
        (
            "payload.minisig",
            "timestamp:1794550736\tfile:payload\thashed",
        ),
        (
            "payload.legacy.minisig",
            "timestamp:1794550736\tfile:payload",
        ),
    ] {
        let (code, report) = check(&fixture("payload"), &fixture(sig), "release.pub");
        assert_eq!(code, Some(0), "{sig}: {report}");
        assert_eq!(report["status"], "verified", "{sig}");
        assert_eq!(report["key_id"], "DDEEC8D10D6A85C4", "{sig}");
        assert_eq!(report["trusted_comment"], comment, "{sig}");
        assert_eq!(report["key_source"], "--pubkey", "{sig}");
    }
}

#[test]
fn tampered_artifact_signature_comment_or_wrong_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut changed = fs::read(fixture("payload")).unwrap();
    changed.push(b'!');
    let changed_payload = dir.path().join("payload");
    fs::write(&changed_payload, changed).unwrap();
    for sig in ["payload.minisig", "payload.legacy.minisig"] {
        let text = fs::read_to_string(fixture(sig)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut flipped = lines[1].to_owned();
        let byte = if flipped.as_bytes()[40] == b'A' {
            "B"
        } else {
            "A"
        };
        flipped.replace_range(40..41, byte);
        let bad_signature = dir.path().join("bad-signature.minisig");
        fs::write(
            &bad_signature,
            [lines[0], &flipped, lines[2], lines[3], ""].join("\n"),
        )
        .unwrap();
        let bad_comment = dir.path().join("bad-comment.minisig");
        let comment = lines[2].replace("file:payload", "file:other");
        fs::write(
            &bad_comment,
            [lines[0], lines[1], &comment, lines[3], ""].join("\n"),
        )
        .unwrap();
        let cases = [
            (
                "tampered artifact",
                &changed_payload,
                fixture(sig),
                "release.pub",
            ),
            (
                "tampered signature",
                &fixture("payload"),
                bad_signature,
                "release.pub",
            ),
            (
                "trusted comment mismatch",
                &fixture("payload"),
                bad_comment,
                "release.pub",
            ),
            ("wrong key", &fixture("payload"), fixture(sig), "wrong.pub"),
            (
                "missing signature",
                &fixture("payload"),
                dir.path().join("none"),
                "release.pub",
            ),
        ];
        for (case, file, signature, key) in cases {
            let (code, report) = check(file, &signature, key);
            assert_eq!(code, Some(1), "{sig} {case}: {report}");
            assert_eq!(report["status"], "tampered", "{sig} {case}");
        }
    }
}

// Limit: the real attack is an attacker key beside the binary with a valid attacker signature of
// it. Making one here needs a committed secret key, so this uses a non-matching signature and the
// valid-signature case was proven by hand.
#[test]
fn an_adjacent_key_is_not_trusted_and_a_signature_beside_the_binary_is_checked_with_the_built_in_key(
) {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("vorda");
    fs::copy(env!("CARGO_BIN_EXE_vorda"), &exe).unwrap();
    fs::copy(fixture("release.pub"), dir.path().join("vorda-release.pub")).unwrap();
    let (code, report) = run(exe.as_os_str(), &[]);
    assert_eq!(code, Some(2), "{report}");
    assert_eq!(report["status"], "unsigned", "{report}");
    fs::copy(fixture("payload.minisig"), dir.path().join("vorda.minisig")).unwrap();
    let (code, report) = run(exe.as_os_str(), &[]);
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "tampered", "{report}");
}

#[test]
#[cfg(unix)]
fn a_mistyped_key_or_file_path_is_unverified_not_tampered() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("not-a-key");
    let folder = dir.path().join("a-folder");
    fs::create_dir(&folder).unwrap();
    let locked = dir.path().join("no-read");
    fs::write(&locked, "x").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let mut bad = vec![&missing, &folder];
    // A superuser can read a mode 000 file, so that case only means something otherwise.
    if fs::read(&locked).is_err() {
        bad.push(&locked);
    }
    let key = fixture("release.pub");
    let payload = fixture("payload");
    let sig = fixture("payload.minisig");
    for path in bad {
        let cases: [(&str, Vec<&OsStr>); 2] = [
            (
                "key file",
                vec![
                    "--file".as_ref(),
                    payload.as_os_str(),
                    "--pubkey".as_ref(),
                    path.as_os_str(),
                ],
            ),
            (
                "file",
                vec![
                    "--file".as_ref(),
                    path.as_os_str(),
                    "--sig".as_ref(),
                    sig.as_os_str(),
                    "--pubkey".as_ref(),
                    key.as_os_str(),
                ],
            ),
        ];
        for (what, args) in cases {
            let (code, report) = run(env!("CARGO_BIN_EXE_vorda").as_ref(), &args);
            assert_eq!(code, Some(2), "{what} {}: {report}", path.display());
            assert_eq!(report["status"], "unverified", "{what}: {report}");
            let detail = report["detail"].as_str().unwrap();
            assert!(
                detail.contains(&format!("cannot read the {what} {}", path.display())),
                "{report}"
            );
        }
    }
    let (code, report) = run(
        env!("CARGO_BIN_EXE_vorda").as_ref(),
        &["--pubkey".as_ref(), missing.as_os_str()],
    );
    assert_eq!(code, Some(2), "{report}");
    assert_eq!(report["status"], "unverified", "{report}");
}

#[test]
fn a_signature_needs_a_file_and_a_file_alone_is_checked_with_the_built_in_key() {
    assert!(verify_self(&["--sig".into(), "artifact.minisig".into()]).is_err());
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("artifact");
    let (code, report) = run(
        env!("CARGO_BIN_EXE_vorda").as_ref(),
        &["--file".as_ref(), missing.as_os_str()],
    );
    assert_eq!(code, Some(2), "{report}");
    assert_eq!(report["status"], "unverified", "{report}");
    let payload = fixture("payload");
    let (code, report) = run(
        env!("CARGO_BIN_EXE_vorda").as_ref(),
        &["--file".as_ref(), payload.as_os_str()],
    );
    assert_eq!(code, Some(1), "{report}");
    assert_eq!(report["status"], "tampered", "{report}");
}
