use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use vorda::{
    scanner::feeds::{KEV, OSV},
    store::{identity, now},
};

fn run(name: &str, text: &str, scan: bool) -> (i32, Value) {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join(name), text).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command.arg("--state").arg(temp.path().join("state"));
    command.arg(if scan { "scan" } else { "inventory" });
    if scan {
        command.args(["--offline", "--json"]);
    }
    let result = command.arg("--root").arg(&project).output().unwrap();
    (
        result.status.code().unwrap(),
        serde_json::from_slice(&result.stdout).unwrap(),
    )
}

fn partial(name: &str, text: &str, good: &str, bad: &str) {
    for scan in [false, true] {
        let (code, data) = run(name, text, scan);
        assert_eq!(code, 2, "{data}");
        assert_eq!(data["status"], "unknown", "{data}");
        let packages = data["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 1, "{data}");
        assert_eq!(packages[0]["name"], good, "{data}");
        let errors = data["errors"].to_string();
        assert!(
            errors.contains(name)
                && errors.contains(bad)
                && errors.contains("Entry-level")
                && errors.contains("Uncheckable"),
            "{errors}"
        );
        assert!(errors.contains("by hand"), "{errors}");
        if scan {
            assert_eq!(data["coverage_evidence"]["status"], "partial", "{data}");
            let incomplete: Vec<_> = data["coverage_evidence"]["observations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|o| o["kind"] == "incomplete-input")
                .collect();
            assert_eq!(incomplete.len(), 1, "{data}");
            assert!(
                incomplete[0]["path"].as_str().unwrap().ends_with(name)
                    && incomplete[0]["reason"]
                        .as_str()
                        .unwrap()
                        .contains("uncheckable"),
                "{data}"
            );
        }
    }
}

#[test]
fn invalid_entries_preserve_healthy_packages_in_every_lockfile_kind() {
    for (name, text) in [
        ("package-lock.json", r#"{"lockfileVersion":3,"packages":{"node_modules/good":{"version":"1.2.3"},"node_modules/bad":{"version":"0.0.x"}}}"#),
        ("package-lock.json", r#"{"lockfileVersion":3,"packages":{"node_modules/good":{"version":"1.2.3"},"node_modules/bad":{"name":{},"version":"1.2.3"}}}"#),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  good@1.2.3: {}\n  bad@0.0.x: {}\n"),
        ("yarn.lock", "# yarn lockfile v1\ngood@1.2.3:\n  version \"1.2.3\"\nbad@0.0.x:\n  version \"0.0.x\"\n"),
        ("bun.lock", r#"{"lockfileVersion":1,"packages":{"good":["good@1.2.3"],"bad":["bad@0.0.x"]}}"#),
        ("uv.lock", "version = 1\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n[[package]]\nname = \"bad\"\nversion = \"0.0.x\"\n"),
        ("poetry.lock", "[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n[[package]]\nname = \"bad\"\nversion = \"0.0.x\"\n[metadata]\nlock-version = '2.1'\n"),
        ("Pipfile.lock", r#"{"_meta":{"pipfile-spec":6},"default":{"good":{"version":"==1.2.3"},"bad":{"version":"==0.0.x"}}}"#),
        ("Pipfile.lock", r#"{"_meta":{"pipfile-spec":6},"default":{"good":{"version":"==1.2.3"},"bad":{"version":"1.2.3"}}}"#),
        ("Cargo.lock", "version = 4\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n[[package]]\nname = \"bad\"\nversion = \"0.0.x\"\n"),
        ("composer.lock", r#"{"packages":[{"name":"vendor/good","version":"1.2.3"},{"name":"vendor/bad","version":"0.0.x"}]}"#),
        ("packages.lock.json", r#"{"version":1,"dependencies":{"net8.0":{"good":{"type":"Direct","resolved":"1.2.3"},"bad":{"type":"Direct","resolved":"0.0.x"}}}}"#),
        ("Gemfile.lock", "GEM\n  specs:\n    good (1.2.3)\n    bad ()\n\nDEPENDENCIES\n  good\n  bad\n"),
        ("go.sum", "example.invalid/good v1.2.3 h1:fixture\nexample.invalid/bad v0.0.x h1:fixture\n"),
        ("requirements.txt", "good==1.2.3\nbad==0.0.x\n"),
    ] {
        let good = match name { "composer.lock" => "vendor/good", "go.sum" => "example.invalid/good", _ => "good" };
        partial(name, text, good, "bad");
    }
}

#[test]
fn identifiable_astra_entries_are_partial_but_broken_collections_refuse_the_file() {
    partial(
        "bun.lock",
        r#"{"lockfileVersion":1,"packages":{"good":["good@1.2.3"],"bad":["https://example.invalid/repo"]}}"#,
        "good",
        "bad",
    );
    partial(
        "Gemfile.lock",
        "GEM\n  specs:\n    good (1.2.3)\n    bad\n\nDEPENDENCIES\n  good\n  bad\n",
        "good",
        "bad",
    );
    for (name, text) in [
        (
            "Pipfile.lock",
            r#"{"_meta":{"pipfile-spec":6},"default":{"good":{"version":"==1.2.3"}},"develop":[{"name":"bad"}]}"#,
        ),
        (
            "bun.lock",
            r#"{"lockfileVersion":1,"packages":[["good@1.2.3"]]}"#,
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/good":{"version":"1.2.3"}}"#,
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '999'\npackages:\n  good@1.2.3: {}\n",
        ),
    ] {
        for scan in [false, true] {
            let (code, data) = run(name, text, scan);
            assert_eq!(code, 2, "{data}");
            assert_eq!(data["status"], "unknown", "{data}");
            assert_eq!(data["packages"], json!([]), "{data}");
            let errors = data["errors"].to_string();
            assert!(
                errors.contains(name)
                    && errors.contains("File-level")
                    && errors.contains("regenerate"),
                "{errors}"
            );
            assert!(!errors.contains("querybatch"), "{errors}");
        }
    }
}

#[test]
fn pnpm_six_source_locators_keep_registry_packages() {
    for entry in [
        "  github.com/user/repo/abc123:\n    resolution: {tarball: https://codeload.example.invalid/repo/abc123}\n    name: repo\n    version: 1.0.0\n",
        "  'file:../local':\n    resolution: {directory: ../local}\n    name: local\n    version: 1.0.0\n",
    ] {
        partial("pnpm-lock.yaml", &format!("lockfileVersion: '6.0'\npackages:\n  /good@1.2.3: {{}}\n{entry}"), "good", if entry.contains("github.com") { "github.com" } else { "file:" });
    }
}

#[test]
fn unmarked_cargo_formats_keep_packages_and_explicit_future_versions_refuse() {
    for suffix in [
        "checksum = \"fixture\"\n",
        "\n[metadata]\n\"checksum good 1.2.3\" = \"fixture\"\n",
    ] {
        let (code, data) = run(
            "Cargo.lock",
            &format!(
                "# generated lockfile\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n{suffix}"
            ),
            false,
        );
        assert_eq!(code, 0, "{data}");
        assert_eq!(data["status"], "complete", "{data}");
        assert_eq!(data["packages"][0]["name"], "good", "{data}");
    }
    for (name, text) in [
        (
            "Cargo.lock",
            "version = 999\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n",
        ),
        (
            "uv.lock",
            "[manifest]\nversion = 1\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n",
        ),
        (
            "Pipfile.lock",
            "{\"_meta\":{\"pipfile-spec\":7},\"default\":{}}",
        ),
        (
            "package-lock.json",
            "{\"lockfileVersion\":\"3\",\"packages\":{}}",
        ),
    ] {
        let (code, data) = run(name, text, false);
        assert_eq!(code, 2, "{data}");
        let errors = data["errors"].to_string();
        assert!(
            errors.contains("File-level") && errors.contains("regenerate"),
            "{errors}"
        );
        assert!(
            !errors.contains("version version") && !errors.contains("/_meta"),
            "{errors}"
        );
        if name == "package-lock.json" {
            assert!(errors.contains("string"), "{errors}");
        }
    }
}

#[test]
fn file_problem_messages_name_marker_and_recovery_without_internal_pointer_or_double_quoting() {
    for (name, text, marker) in [
        (
            "uv.lock",
            "[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n",
            "version",
        ),
        (
            "Pipfile.lock",
            r#"{"_meta":{"pipfile-spec":7},"default":{}}"#,
            "_meta.pipfile-spec",
        ),
        (
            "package-lock.json",
            r#"{"lockfileVersion":"3","packages":{}}"#,
            "lockfileVersion",
        ),
    ] {
        let (code, data) = run(name, text, false);
        assert_eq!(code, 2, "{data}");
        let errors = data["errors"].as_array().unwrap();
        let message = errors[0].as_str().unwrap();
        assert!(
            message.contains(name)
                && message.contains("File-level")
                && message.contains(marker)
                && message.contains("regenerate"),
            "{data}"
        );
        assert!(
            !message.contains("version version")
                && !message.contains("/_meta")
                && !message.contains("\\\""),
            "{data}"
        );
    }
}

#[test]
fn local_workspace_members_are_not_public_registry_packages() {
    // A member inside the project is skipped (never queried, not an error).
    let (code, data) = run(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"":{"workspaces":["packages/*"]},"packages/local":{"name":"ws-a","version":"1.0.0"},"node_modules/ws-a":{"resolved":"packages/local","link":true},"node_modules/good":{"version":"1.2.3"}}}"#,
        false,
    );
    assert_eq!(code, 0, "{data}");
    assert_eq!(data["packages"].as_array().unwrap().len(), 1, "{data}");
    assert_eq!(data["packages"][0]["name"], "good", "{data}");
    // A member outside the project and the link that points at it are one
    // uncheckable dependency: one message.
    partial(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"../local":{"name":"ws-a","version":"1.0.0"},"node_modules/ws-a":{"resolved":"../local","link":true},"node_modules/good":{"version":"1.2.3"}}}"#,
        "good",
        "../local",
    );
    let (_, data) = run(
        "package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"../local":{"name":"ws-a","version":"1.0.0"},"node_modules/ws-a":{"resolved":"../local","link":true},"node_modules/good":{"version":"1.2.3"}}}"#,
        false,
    );
    assert_eq!(data["errors"].as_array().unwrap().len(), 1, "{data}");
}

#[test]
fn selected_nuget_lock_preserves_healthy_entries_with_partial_coverage() {
    let temp = tempfile::tempdir().unwrap();
    let empty = temp.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let lock = temp.path().join("packages.lock.json");
    fs::write(&lock, r#"{"version":1,"dependencies":{"net8.0":{"good":{"type":"Direct","resolved":"1.2.3"},"bad":{"type":"Direct","resolved":"0.0.x"}}}}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(temp.path().join("state"))
        .args(["inventory", "--root"])
        .arg(empty)
        .arg("--installed-root")
        .arg(&lock)
        .output()
        .unwrap();
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2), "{data}");
    assert_eq!(data["packages"].as_array().unwrap().len(), 1, "{data}");
    assert_eq!(data["packages"][0]["name"], "good", "{data}");
    assert_eq!(data["source_outcomes"][0]["outcome"], "partial", "{data}");
    assert!(data["errors"].to_string().contains("Uncheckable"), "{data}");
}

#[test]
fn agentbom_lock_dependencies_keep_healthy_entries_and_mark_partial() {
    for bad in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("project");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("server.js"), "").unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"fixture-server","version":"1.2.3"}"#,
        )
        .unwrap();
        fs::write(
            root.join(".mcp.json"),
            r#"{"mcpServers":{"fixture":{"command":"node","args":["server.js"]}}}"#,
        )
        .unwrap();
        let mut lock =
            json!({"lockfileVersion":3,"packages":{"node_modules/good":{"version":"1.2.3"}}});
        if bad {
            lock["packages"]["node_modules/bad"] = json!({"version":"0.0.x"});
        }
        fs::write(root.join("package-lock.json"), lock.to_string()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(temp.path().join("state"))
            .args(["agentbom", "--home"])
            .arg(temp.path())
            .arg("--root")
            .arg(&root)
            .args(["--offline", "--no-models"])
            .output()
            .unwrap();
        let data: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(2), "{data}");
        let items = data["assets"]["items"].as_array().unwrap();
        assert!(
            items.iter().any(|item| item["record"]["name"] == "good"),
            "{data}"
        );
        assert!(
            !items.iter().any(|item| item["record"]["name"] == "bad"),
            "{data}"
        );
        if bad {
            assert_eq!(data["coverage"]["incomplete"], true, "{data}");
            assert!(data["errors"].to_string().contains("Uncheckable"), "{data}");
        }
    }
}

#[test]
fn a_healthy_finding_survives_an_uncheckable_entry_without_live_requests() {
    // Fresh synthetic caches supply every expected feed response; a local proxy
    // refuses all cache misses, so this CLI check cannot contact a live feed.
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir(&project).unwrap();
    let cache = state.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let advisory = "GHSA-fixture-retained";
    for (key, url, data) in [
        (
            json!([KEV, null]),
            KEV.to_string(),
            json!({"vulnerabilities":[]}),
        ),
        (
            json!([format!("{OSV}/querybatch"), {"queries":[{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}]}]),
            format!("{OSV}/querybatch"),
            json!({"results":[{"vulns":[{"id":advisory}]}]}),
        ),
        (
            json!([format!("{OSV}/vulns/{advisory}"), null, [["npm", "lodash"]]]),
            format!("{OSV}/vulns/{advisory}"),
            json!({"id":advisory,"summary":"Synthetic retained lodash finding","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"versions":["4.17.20"]}]}),
        ),
    ] {
        fs::write(
            cache.join(format!("{}.json", identity(&key).unwrap())),
            json!({"source_url":url,"checked":now(),"fetched_at":"fixture","data":data})
                .to_string(),
        )
        .unwrap();
    }
    let proxy = TcpListener::bind(("localhost", 0)).unwrap();
    proxy.set_nonblocking(true).unwrap();
    let address = format!("http://{}", proxy.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let server = {
        let stop = stop.clone();
        let hits = hits.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = proxy.accept() {
                    hits.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                } else {
                    thread::sleep(Duration::from_millis(5));
                }
            }
        })
    };
    fs::write(project.join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"},"node_modules/bad":{"version":"0.0.x"}}}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .env("VORDA_ADVISORIES", "online")
        .arg("--state")
        .arg(&state)
        .args(["scan", "--json", "--root"])
        .arg(&project)
        .env("HTTPS_PROXY", &address)
        .env("https_proxy", &address)
        .env("HTTP_PROXY", &address)
        .env("http_proxy", &address)
        .env("ALL_PROXY", &address)
        .env("all_proxy", &address)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "unexpected feed request: {data}"
    );
    assert_eq!(output.status.code(), Some(2), "{data}");
    assert_eq!(data["status"], "unknown", "{data}");
    assert_eq!(data["coverage_evidence"]["status"], "partial", "{data}");
    assert_eq!(data["packages"].as_array().unwrap().len(), 1, "{data}");
    assert_eq!(data["packages"][0]["name"], "lodash", "{data}");
    assert!(
        data["findings"].as_array().unwrap().iter().any(
            |finding| finding["advisory"] == advisory && finding["package"]["name"] == "lodash"
        ),
        "{data}"
    );
    assert!(
        data["errors"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["source"] == "inventory"),
        "{data}"
    );
}
