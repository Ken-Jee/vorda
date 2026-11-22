//! `--os-packages` reads every dpkg state honestly: installed packages (held ones too) are
//! checked, removed ones are not reported, and ones whose files may not match the recorded
//! version make the inventory unknown instead of vanishing.
#![cfg(unix)]
use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn every_dpkg_state_is_checked_skipped_or_reported_unknown() {
    let bin = tempfile::tempdir().unwrap();
    let stub = bin.path().join("dpkg-query");
    // Rows in the format Vorda asks for: package, version, source, source version, and
    // dpkg's three-letter status (wanted state, current state, error flag).
    let rows = [
        ("zlib1g", "1:1.3.dfsg-3.1ubuntu2", "ii "),
        ("openssl", "3.0.13-0ubuntu3.1", "hi "),
        ("libssl3t64", "3.0.13-0ubuntu3.1", "ri "),
        ("curl", "8.5.0-2ubuntu10.4", "iU "),
        ("libcurl4t64", "8.5.0-2ubuntu10.4", "iF "),
        ("man-db", "2.12.0-4build2", "it "),
        ("libc-bin", "2.39-0ubuntu8.3", "iW "),
        ("libxml2", "2.9.14+dfsg-1.3ubuntu3", "iH "),
        ("sudo", "1.9.15p5-3ubuntu5", "iiR"),
        ("oldkernel", "6.8.0-31.31", "rc "),
        ("purged", "1.0-1", "pn "),
        // An install cut short during unpack leaves no version.
        ("emptyver", "", "iHR"),
        ("never", "", "un "),
    ];
    let mut body = String::from("#!/bin/sh\n");
    for (name, version, status) in rows {
        body.push_str(&format!(
            "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' '{name}' '{version}' '{name}' '{version}' '{status}'\n"
        ));
    }
    fs::write(&stub, body).unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .env("PATH", bin.path())
        .arg("--state")
        .arg(state.path())
        .args(["inventory", "--os-packages", "--root"])
        .arg(root.path())
        .output()
        .unwrap();
    let result: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    let mut names: Vec<_> = result["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            format!(
                "{} {}",
                p["name"].as_str().unwrap(),
                p["version"].as_str().unwrap()
            )
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "curl 8.5.0-2ubuntu10.4",
            "libc-bin 2.39-0ubuntu8.3",
            "libcurl4t64 8.5.0-2ubuntu10.4",
            "libssl3t64 3.0.13-0ubuntu3.1",
            "man-db 2.12.0-4build2",
            "openssl 3.0.13-0ubuntu3.1",
            "zlib1g 1:1.3.dfsg-3.1ubuntu2",
        ],
        "{result:#}"
    );
    assert_eq!(result["status"], "unknown", "{result:#}");
    let errors: Vec<_> = result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    assert_eq!(errors.len(), 3, "{errors:?}");
    assert!(
        errors[0].contains("sudo apt-get install --reinstall libxml2"),
        "{errors:?}"
    );
    assert!(
        errors[2].contains("emptyver") && errors[2].contains("not checked"),
        "{errors:?}"
    );
    assert!(
        errors[0].contains("libxml2 2.9.14+dfsg-1.3ubuntu3")
            && errors[0].contains("half-installed")
            && errors[0].contains("not checked"),
        "{errors:?}"
    );
    assert!(
        errors[1].contains("sudo 1.9.15p5-3ubuntu5")
            && errors[1].contains("reinstall")
            && errors[1].contains("not checked"),
        "{errors:?}"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !text.contains("oldkernel") && !text.contains("\"purged\""),
        "{text}"
    );
    assert_eq!(output.status.code(), Some(2), "{result:#}");
}
