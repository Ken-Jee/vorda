//! `--tools` findings for distro-packaged binaries are labelled upstream only.
#![cfg(unix)]
use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use vorda::{
    scanner::feeds::{KEV, OSV},
    store::{identity, now},
};

fn script(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn seed(cache: &Path, key: Value, url: &str, data: Value) {
    fs::write(
        cache.join(format!("{}.json", identity(&key).unwrap())),
        json!({"source_url":url,"checked":now(),"fetched_at":"2026-11-13T00:00:00Z","data":data})
            .to_string(),
    )
    .unwrap();
}

#[test]
fn findings_for_distro_packaged_tools_are_upstream_only() {
    let bin = tempfile::tempdir().unwrap();
    // python3 is a link to python3.12, as on Ubuntu: the link belongs to python3-minimal, the
    // binary that runs to python3.12-minimal. node was installed by hand.
    script(bin.path(), "python3.12", "echo 'Python 3.12.3'");
    std::os::unix::fs::symlink("python3.12", bin.path().join("python3")).unwrap();
    script(bin.path(), "node", "echo v22.0.0");
    script(
        bin.path(),
        "dpkg-query",
        r#"case "$1" in
  -S) case "$2" in */python3) echo "python3-minimal: $2";; */python3.12) echo "python3.12-minimal: $2";; *) echo "dpkg-query: no path found matching pattern $2" >&2; exit 1;; esac;;
  -W) case "$3" in python3-minimal) printf '3.12.3-0ubuntu2.1';; *) printf '3.12.3-1ubuntu0.17';; esac;;
esac"#,
    );
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let cache = state.path().join("cache");
    fs::create_dir(&cache).unwrap();
    seed(
        &cache,
        json!([KEV, null]),
        KEV,
        json!({"vulnerabilities":[]}),
    );
    let query = json!({"queries":[{"package":{"name":"node","ecosystem":"Bitnami"},"version":"22.0.0"},{"package":{"name":"python","ecosystem":"Bitnami"},"version":"3.12.3"}]});
    let batch = format!("{OSV}/querybatch");
    seed(
        &cache,
        json!([batch, query]),
        &batch,
        json!({"results":[{"vulns":[{"id":"BIT-node-fixture"}]},{"vulns":[{"id":"BIT-python-fixture"}]}]}),
    );
    for name in ["node", "python"] {
        let url = format!("{OSV}/vulns/BIT-{name}-fixture");
        seed(
            &cache,
            json!([url, null, [["Bitnami", "node"], ["Bitnami", "python"]]]),
            &url,
            json!({"id":format!("BIT-{name}-fixture"),"affected":[{"package":{"ecosystem":"Bitnami","name":name},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"99.0.0"}]}]}]}),
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .env("VORDA_ADVISORIES", "online")
        .env("PATH", bin.path())
        .env("HTTPS_PROXY", "http://localhost:9")
        .env("HTTP_PROXY", "http://localhost:9")
        .env("NO_PROXY", "")
        .arg("--state")
        .arg(state.path())
        .args(["scan", "--json", "--tools", "--root"])
        .arg(root.path())
        .output()
        .unwrap();
    let result: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(output.status.code(), Some(3), "{result:#}");
    let findings = result["findings"].as_array().unwrap();
    let python = findings
        .iter()
        .find(|f| f["package"]["name"] == "python")
        .unwrap();
    assert_eq!(python["upstream_only"], true);
    assert_eq!(
        python["package"]["distro_package"],
        "python3.12-minimal 3.12.3-1ubuntu0.17"
    );
    assert!(python["confidence"]
        .as_str()
        .unwrap()
        .starts_with("upstream only"));
    assert!(python["title"]
        .as_str()
        .unwrap()
        .ends_with("[upstream only]"));
    let node = findings
        .iter()
        .find(|f| f["package"]["name"] == "node")
        .unwrap();
    assert!(node.get("upstream_only").is_none(), "{node:#}");
    assert!(!node["title"].as_str().unwrap().contains("upstream only"));
    let inbox = fs::read_to_string(state.path().join("INBOX.md")).unwrap();
    assert!(
        inbox
            .lines()
            .any(|l| l.contains("python 3.12.3") && l.contains("[upstream only]")),
        "{inbox}"
    );
}
