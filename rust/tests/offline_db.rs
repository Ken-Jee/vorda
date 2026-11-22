// The offline advisory database: `vorda db update` builds a local index from OSV export
// zips, and `scan --offline-db` answers from it with every network route dead. Whenever the
// local answer could be wrong the scan says unknown, with the reason.
use serde_json::{json, Value};
use std::{fs, io::Write, process::Command};

const DEAD: &str = "http://127.0.0.1:9";
const KEV: &str = r#"{"vulnerabilities":[{"cveID":"CVE-2099-0001"}]}"#;

fn zip_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, bytes) in entries {
        out.start_file(*name, options).unwrap();
        out.write_all(bytes).unwrap();
    }
    out.finish().unwrap().into_inner()
}

fn record(value: Value) -> Vec<u8> {
    value.to_string().into_bytes()
}

/// An npm advisory for `name` with one range of `events`.
fn npm(id: &str, name: &str, events: Value) -> Value {
    json!({"id":id,"modified":"2099-01-01T00:00:00Z","aliases":[],"affected":[{"package":{"ecosystem":"npm","name":name},"ranges":[{"type":"SEMVER","events":events}]}]})
}

fn good_npm() -> Vec<(&'static str, Vec<u8>)> {
    let mut first = npm(
        "GHSA-test-0001",
        "example",
        json!([{"introduced":"0"},{"fixed":"1.2.4"}]),
    );
    first["aliases"] = json!(["CVE-2099-0001"]);
    first["severity"] =
        json!([{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]);
    let mut withdrawn = npm("GHSA-test-0003", "example", json!([{"introduced":"0"}]));
    withdrawn["withdrawn"] = json!("2099-01-02T00:00:00Z");
    vec![
        ("GHSA-test-0001.json", record(first)),
        (
            "GHSA-test-0002.json",
            record(npm(
                "GHSA-test-0002",
                "other",
                json!([{"introduced":"0"},{"fixed":"2.0.0"}]),
            )),
        ),
        ("GHSA-test-0003.json", record(withdrawn)),
    ]
}

struct World {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    state: std::path::PathBuf,
    db: std::path::PathBuf,
    mirror: std::path::PathBuf,
}

fn world(lock: &str) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("package-lock.json"), lock).unwrap();
    let mirror = tmp.path().join("mirror");
    fs::create_dir_all(mirror.join("npm")).unwrap();
    fs::write(mirror.join("kev.json"), KEV).unwrap();
    World {
        root,
        state: tmp.path().join("state"),
        db: tmp.path().join("cache/advisory-db"),
        mirror,
        _tmp: tmp,
    }
}

fn lock(packages: &[(&str, &str)]) -> String {
    let packages: serde_json::Map<String, Value> = packages
        .iter()
        .map(|(n, v)| (format!("node_modules/{n}"), json!({"version":v})))
        .collect();
    json!({"lockfileVersion":3,"packages":packages}).to_string()
}

fn publish(w: &World, ecosystem: &str, zip: &[u8]) {
    fs::create_dir_all(w.mirror.join(ecosystem)).unwrap();
    fs::write(w.mirror.join(ecosystem).join("all.zip"), zip).unwrap();
}

fn vorda(w: &World, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command.arg("--state").arg(&w.state).args(args);
    // Every network route is dead: any request the command makes fails.
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(var, DEAD);
    }
    command
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .env("VORDA_ADVISORY_DB_DIR", &w.db)
        .env_remove("VORDA_ADVISORIES")
        .env_remove("VORDA_ADVISORY_DB_MAX_AGE_HOURS")
        // Test exports hold a handful of entries, far below a real export's floor.
        .env("VORDA_ADVISORY_DB_MIN_ENTRIES", "1");
    // An empty value removes the variable, so a test can see the built-in default.
    for (k, v) in env {
        if v.is_empty() {
            command.env_remove(k);
        } else {
            command.env(k, v);
        }
    }
    let output = command.output().unwrap();
    (
        output.status.code().unwrap(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn update(w: &World) -> (i32, String, String) {
    let mirror = w.mirror.to_string_lossy().into_owned();
    vorda(
        w,
        &["db", "update", "--ecosystem", "npm", "--from", &mirror],
        &[],
    )
}

fn scan_json(w: &World, extra: &[&str], env: &[(&str, &str)]) -> (i32, Value) {
    let root = w.root.to_string_lossy().into_owned();
    let mut args = vec!["scan", "--root", &root, "--json"];
    args.extend_from_slice(extra);
    let (code, out, err) = vorda(w, &args, env);
    let value = serde_json::from_str(&out).unwrap_or_else(|_| panic!("{out}\n{err}"));
    (code, value)
}

fn errors(result: &Value) -> String {
    result["errors"].to_string()
}

#[test]
fn a_missing_kev_list_asks_for_db_update() {
    let w = world(&lock(&[("example", "1.2.3")]));
    let missing = "the KEV list is not in the local advisory database; run `vorda db update`";
    publish(&w, "npm", &zip_of(&good_npm()));
    assert_eq!(update(&w).0, 0);
    fs::remove_file(w.db.join("kev.json")).unwrap();
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2);
    assert!(errors(&result).contains(missing), "{result}");
}

#[cfg(unix)]
#[test]
fn linked_database_parent_is_ready_but_linked_kev_file_is_refused() {
    let mut w = world(&lock(&[("example", "1.2.3")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    assert_eq!(update(&w).0, 0);
    let real = w.db.clone();
    let linked = w._tmp.path().join("linked-cache");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    w.db = linked;
    let (code, result) = scan_json(&w, &[], &[]);
    assert_eq!(code, 3, "{result}");
    assert!(result["errors"].as_array().unwrap().is_empty(), "{result}");
    let (_, status, _) = vorda(&w, &["db", "status"], &[]);
    assert!(status.contains("KEV: ready"), "{status}");
    let kev = real.join("kev.json");
    fs::rename(&kev, real.join("real-kev.json")).unwrap();
    std::os::unix::fs::symlink(real.join("real-kev.json"), kev).unwrap();
    let (code, result) = scan_json(&w, &[], &[]);
    assert_eq!(code, 2);
    assert!(!errors(&result).contains("not in the local advisory database"));
    assert!(!errors(&result).contains("run `vorda db update`"));
}

#[test]
fn mcp_check_uses_local_database_and_accepts_explicit_advisory_modes() {
    use std::process::Stdio;
    let w = world(&lock(&[("example", "1.2.3")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    assert_eq!(update(&w).0, 0);
    fs::create_dir_all(&w.state).unwrap();
    fs::write(
        w.state.join("config.json"),
        json!({"roots":[w.root]}).to_string(),
    )
    .unwrap();
    let call = |args: Value, configured: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(&w.state)
            .arg("mcp")
            .env("VORDA_ADVISORY_DB_DIR", &w.db)
            .env("VORDA_ADVISORIES", configured)
            .env("HTTPS_PROXY", DEAD)
            .env("HTTP_PROXY", DEAD)
            .env("VORDA_OSV_BATCH_URL", DEAD)
            .env("VORDA_KEV_URL", DEAD)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check","arguments":args}})).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    for args in [json!({}), json!({"offline_db":true})] {
        let response = call(args, "");
        let result: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(result["advisory_source"], "offline-db");
        assert_eq!(result["status"], "vulnerable", "{result}");
        assert!(result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["advisory"] == "CVE-2099-0001"));
    }
    for args in [json!({"online":true}), json!({})] {
        let response = call(args, "online");
        let result: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(result["status"], "unknown");
        assert_ne!(result["advisory_source"], "offline-db");
    }
    for args in [
        json!({"online":true,"offline_db":true}),
        json!({"offline":true,"offline_db":true}),
        json!({"online":true,"offline":true}),
        json!({"online":"yes"}),
    ] {
        let message = call(args, "")["error"]["message"].to_string();
        assert!(
            message.contains("online") || message.contains("offline"),
            "{message}"
        );
        assert!(
            !message.contains("--") && !message.contains("configuration"),
            "{message}"
        );
    }
    fs::rename(&w.db, w._tmp.path().join("saved-db")).unwrap();
    let response = call(json!({}), "");
    let result: Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["advisory_source"], "offline-db");
    assert!(
        errors(&result).contains("the KEV list is not in the local advisory database"),
        "{result}"
    );
    let store = vorda::store::Store::open(&w.state).unwrap();
    assert!(store
        .active()
        .unwrap()
        .iter()
        .any(|f| f.get("kind") == Some(&json!("health"))));
}

#[test]
fn offline_db_scan_finds_advisories_with_every_network_route_dead() {
    let w = world(&lock(&[("example", "1.2.3"), ("other", "2.0.0")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    let (code, out, err) = update(&w);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("npm: updated"), "{out}");
    assert!(out.contains("KEV: updated"), "{out}");

    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 3, "{result}");
    assert_eq!(result["status"], "vulnerable", "{}", errors(&result));
    assert_eq!(result["errors"], json!([]));
    let findings = result["findings"].as_array().unwrap();
    // `other` 2.0.0 is the fixed version and GHSA-test-0003 is withdrawn: one finding.
    assert_eq!(findings.len(), 1, "{findings:?}");
    let f = &findings[0];
    assert_eq!(f["advisory"], "CVE-2099-0001");
    assert_eq!(f["package"]["name"], "example");
    assert_eq!(f["fixed"], json!(["1.2.4"]));
    assert_eq!(f["kev"], true);
    assert_eq!(f["epss"], Value::Null);
    assert_eq!(f["severity"][0]["type"], "CVSS_V3");
    assert_eq!(result["advisory_source"], "offline-db");
    for source in result["sources"].as_array().unwrap() {
        assert!(
            source["source_url"]
                .as_str()
                .unwrap()
                .starts_with("offline-db:"),
            "{source}"
        );
    }

    let root = w.root.to_string_lossy().into_owned();
    let (code, out, _) = vorda(&w, &["scan", "--root", &root, "--offline-db"], &[]);
    assert_eq!(code, 3);
    assert!(
        out.contains("Advisories: local offline database (no network); EPSS not checked."),
        "{out}"
    );
    let (code, out, _) = vorda(&w, &["db", "status"], &[]);
    assert_eq!(code, 2, "PyPI, crates.io and Go have no index yet: {out}");
    assert!(out.contains("npm: ready"), "{out}");
    assert!(
        out.contains("PyPI: unknown: no local advisory database for PyPI"),
        "{out}"
    );
}

#[test]
fn offline_db_reports_unknown_with_a_reason_whenever_it_could_be_wrong() {
    let w = world(&lock(&[("example", "1.2.3"), ("odd", "1.0.0")]));
    fs::write(w.root.join("requirements.txt"), "requests==2.0.0\n").unwrap();

    let mut entries = good_npm();
    entries.push((
        "GHSA-test-0004.json",
        record(npm(
            "GHSA-test-0004",
            "odd",
            json!([{"introduced":"0"},{"fixed":"next"}]),
        )),
    ));
    publish(&w, "npm", &zip_of(&entries));
    assert_eq!(update(&w).0, 0);
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2);
    let text = errors(&result);
    // A range the comparator cannot order makes that package unknown, not clean.
    assert!(
        text.contains("GHSA-test-0004: event version \\\"next\\\" cannot be ordered: 1 package not checked (odd 1.0.0)"),
        "{text}"
    );
    // An ecosystem missing from the index.
    assert!(
        text.contains("no local advisory database for PyPI"),
        "{text}"
    );
    // The finding that could be checked is still reported.
    assert_eq!(result["findings"][0]["advisory"], "CVE-2099-0001");

    // An index older than the limit is not used.
    let (code, result) = scan_json(
        &w,
        &["--offline-db"],
        &[("VORDA_ADVISORY_DB_MAX_AGE_HOURS", "0")],
    );
    assert_eq!(code, 2);
    assert!(
        errors(&result).contains("old, over the limit of 0 hours"),
        "{}",
        errors(&result)
    );
    assert_eq!(result["findings"], json!([]));

    // An index built before package names were stored in their current form.
    rusqlite::Connection::open(w.db.join("npm.sqlite"))
        .unwrap()
        .execute("DELETE FROM meta WHERE key = 'names'", [])
        .unwrap();
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2);
    assert!(
        errors(&result).contains("stores package names in an older form"),
        "{}",
        errors(&result)
    );
    assert_eq!(result["findings"], json!([]));
}

#[test]
fn a_hostile_or_broken_export_never_counts_as_clean_and_a_good_one_recovers() {
    let w = world(&lock(&[("example", "1.2.3")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    assert_eq!(update(&w).0, 0);

    // A truncated download is not a zip: the update fails and scans say unknown.
    let good = zip_of(&good_npm());
    publish(&w, "npm", &good[..good.len() / 2]);
    let (code, out, _) = update(&w);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("npm: unreadable: export is not a zip archive"),
        "{out}"
    );
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2);
    assert!(
        errors(&result).contains("the latest npm export could not be read"),
        "{}",
        errors(&result)
    );

    // An expansion bomb, a deeply nested record and an entry named to escape the folder.
    let mut entries = good_npm();
    entries.push(("bomb.json", vec![b' '; 9 << 20]));
    entries.push((
        "deep.json",
        format!("{}{}", "[".repeat(100), "]".repeat(100)).into_bytes(),
    ));
    entries.push((
        "../../escaped.json",
        record(npm(
            "GHSA-test-0005",
            "example",
            json!([{"introduced":"0"}]),
        )),
    ));
    publish(&w, "npm", &zip_of(&entries));
    let (code, out, _) = update(&w);
    // The update says the export was partly unreadable and exits non-zero.
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains(
            "npm: updated-with-unreadable-records: 2 records in the npm export could not be read"
        ),
        "{out}"
    );
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2);
    assert!(
        errors(&result).contains(
            "2 records in the npm export could not be read (entry 3 expands to 9437184 bytes"
        ),
        "{}",
        errors(&result)
    );
    for dir in [w.db.clone(), w.db.join(".."), w.db.join("../..")] {
        assert!(!dir.join("escaped.json").exists());
    }

    // A good export replaces it and the scan is complete again.
    publish(&w, "npm", &zip_of(&good_npm()));
    assert_eq!(update(&w).0, 0);
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 3, "{}", errors(&result));
    assert_eq!(result["status"], "vulnerable");
}

#[test]
fn the_advisory_source_follows_the_environment_then_config_and_flags_win() {
    let w = world(&lock(&[("example", "1.2.3")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    assert_eq!(update(&w).0, 0);

    let (code, result) = scan_json(&w, &[], &[]);
    assert_eq!(
        (code, &result["advisory_source"]),
        (3, &json!("offline-db"))
    );

    let (code, result) = scan_json(&w, &[], &[("VORDA_ADVISORIES", "offline-db")]);
    assert_eq!(
        (code, &result["advisory_source"]),
        (3, &json!("offline-db"))
    );

    fs::create_dir_all(&w.state).unwrap();
    fs::write(
        w.state.join("config.json"),
        r#"{"advisories":"offline-db"}"#,
    )
    .unwrap();
    let (code, result) = scan_json(&w, &[], &[]);
    assert_eq!(
        (code, &result["advisory_source"]),
        (3, &json!("offline-db"))
    );

    // --online wins over the config; with the network dead it cannot be clean.
    let (code, result) = scan_json(&w, &["--online"], &[]);
    assert_eq!(code, 2);
    assert_eq!(result["advisory_source"], Value::Null);
    assert_eq!(result["status"], "unknown");

    let root = w.root.to_string_lossy().into_owned();
    let (code, _, err) = vorda(
        &w,
        &["scan", "--root", &root],
        &[("VORDA_ADVISORIES", "sometimes")],
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("VORDA_ADVISORIES must be online or offline-db"),
        "{err}"
    );

    // A value that is not text is refused, not read as the default.
    fs::write(w.state.join("config.json"), r#"{"advisories":5}"#).unwrap();
    let (code, _, err) = vorda(&w, &["scan", "--root", &root], &[]);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("in config.json must be online or offline-db, not 5"),
        "{err}"
    );

    // The two flags contradict each other in either order.
    for flags in [["--offline-db", "--online"], ["--online", "--offline-db"]] {
        let mut args = vec!["scan", "--root", &root];
        args.extend(flags);
        let (code, _, err) = vorda(&w, &args, &[]);
        assert_eq!(code, 64, "{flags:?}: {err}");
        assert!(
            err.contains("--offline-db and --online cannot be combined"),
            "{err}"
        );
    }
}

#[test]
fn agentbom_follows_the_offline_db_setting() {
    let w = world(&lock(&[]));
    fs::write(
        w.root.join(".mcp.json"),
        json!({"mcpServers":{"example":{"command":"npx","args":["-y","example@1.2.3"]}}})
            .to_string(),
    )
    .unwrap();
    let mut entries = good_npm();
    let git = json!({"id":"GHSA-test-git","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc"}]}]}]});
    entries.push(("GHSA-test-git.json", record(git)));
    publish(&w, "npm", &zip_of(&entries));
    assert_eq!(update(&w).0, 0);
    let home = w.root.parent().unwrap().join("home");
    fs::create_dir_all(&home).unwrap();
    let (root, home) = (
        w.root.to_string_lossy().into_owned(),
        home.to_string_lossy().into_owned(),
    );
    let args = [
        "agentbom",
        "--root",
        &root,
        "--home",
        &home,
        "--host",
        "fixture",
        "--no-save",
        "--no-models",
    ];
    // Every network route is dead: only the local database can find the advisory.
    let (code, out, err) = vorda(&w, &args, &[("VORDA_ADVISORIES", "offline-db")]);
    let result: Value = serde_json::from_str(&out).unwrap_or_else(|_| panic!("{out}\n{err}"));
    assert_eq!(code, 1, "{result}");
    assert_eq!(result["status"], "vulnerable", "{result}");
    assert!(
        result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["advisory"] == "CVE-2099-0001"),
        "{result}"
    );
    // A record no version can match is named, as `scan` names it.
    assert!(
        result["warnings"]
            .to_string()
            .contains("GHSA-test-git gives only git commit ranges"),
        "{result}"
    );

    let mut offline = args.to_vec();
    offline.push("--offline");
    let (code, _, err) = vorda(&w, &offline, &[("VORDA_ADVISORIES", "offline-db")]);
    assert_eq!(code, 64, "{err}");
    assert!(err.contains("cannot be combined"), "{err}");
}

#[test]
fn offline_db_matches_pypi_crates_and_go_by_their_own_version_rules() {
    let w = world(&lock(&[]));
    fs::remove_file(w.root.join("package-lock.json")).unwrap();
    fs::write(w.root.join("requirements.txt"), "Flask_Cors==3.0.0rc1\n").unwrap();
    fs::write(
        w.root.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"fe0f37c9e8f3c5a4a66ad655a93c74daac4ad00c441533bf5c6e7990bb42604e\"\n\n[[package]]\nname = \"block-buffer\"\nversion = \"0.11.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"deno\"\nversion = \"1.32.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    fs::write(
        w.root.join("go.sum"),
        "golang.org/x/net v0.16.0 h1:7eBu7KsSvFDtSXUIDbh3aqlK4DPsZ1rByC8PFfBThos=\n",
    )
    .unwrap();
    let pypi = json!({"id":"PYSEC-test-1","affected":[{"package":{"ecosystem":"PyPI","name":"flask-cors"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]}]});
    let crates = json!({"id":"RUSTSEC-test-1","affected":[{"package":{"ecosystem":"crates.io","name":"smallvec"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.6.0"},{"last_affected":"1.6.0"}]}]}]});
    // Real OSV records filed under a spelling other than the crate's, trimmed to crates.io.
    let block = json!({"id":"GHSA-qwgh-2vcv-g2f7","affected":[{"package":{"ecosystem":"crates.io","name":"block_buffer"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.11.0"},{"fixed":"0.12.1"}]}]}]});
    let deno = json!({"id":"GHSA-c25x-cm9x-qqgx","aliases":["CVE-2023-28445"],"affected":[{"package":{"ecosystem":"crates.io","name":"Deno"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.32.0"},{"fixed":"1.32.1"}]}]}]});
    let go = json!({"id":"GO-test-1","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"}]}]}]});
    publish(&w, "PyPI", &zip_of(&[("PYSEC-test-1.json", record(pypi))]));
    publish(
        &w,
        "crates.io",
        &zip_of(&[
            ("RUSTSEC-test-1.json", record(crates)),
            ("GHSA-qwgh-2vcv-g2f7.json", record(block)),
            ("GHSA-c25x-cm9x-qqgx.json", record(deno)),
        ]),
    );
    publish(&w, "Go", &zip_of(&[("GO-test-1.json", record(go))]));
    let mirror = w.mirror.to_string_lossy().into_owned();
    let (code, out, err) = vorda(
        &w,
        &[
            "db",
            "update",
            "--ecosystem",
            "PyPI",
            "--ecosystem",
            "crates.io",
            "--ecosystem",
            "Go",
            "--from",
            &mirror,
        ],
        &[],
    );
    assert_eq!(code, 0, "{out}\n{err}");

    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 3, "{}", errors(&result));
    let mut found: Vec<&str> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["advisory"].as_str().unwrap())
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "CVE-2023-28445",
            "GHSA-qwgh-2vcv-g2f7",
            "GO-test-1",
            "PYSEC-test-1",
            "RUSTSEC-test-1"
        ]
    );
}

#[test]
fn records_no_version_can_match_are_warnings_as_online_not_unknown() {
    let w = world(&lock(&[]));
    fs::remove_file(w.root.join("package-lock.json")).unwrap();
    fs::write(
        w.root.join("requirements.txt"),
        "tensorflow==2.4.0\nkeras==2.3.0\ngradio==3.0\napache-airflow==1.10.0\n",
    )
    .unwrap();
    let pypi = |id: &str, name: &str, affected: Value| {
        let mut a = affected;
        a["package"] = json!({"ecosystem":"PyPI","name":name});
        (
            format!("{id}.json"),
            record(json!({"id":id,"modified":"2099-01-01T00:00:00Z","affected":[a]})),
        )
    };
    let entries = [
        // The shapes OSV carries for these packages today.
        pypi(
            "OSV-test-git",
            "tensorflow",
            json!({"ranges":[{"type":"GIT","events":[{"introduced":"0834086910de"},{"fixed":"7677422a56f1"}]}]}),
        ),
        pypi("PYSEC-test-empty", "gradio", json!({})),
        pypi("PYSEC-test-empty2", "keras", json!({})),
        // Ordinary records for the same packages still match.
        pypi(
            "PYSEC-test-tf",
            "tensorflow",
            json!({"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.4.1"}]}]}),
        ),
        pypi(
            "PYSEC-test-af",
            "apache-airflow",
            json!({"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.10.1"}]}]}),
        ),
    ];
    let entries: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    publish(&w, "PyPI", &zip_of(&entries));
    let mirror = w.mirror.to_string_lossy().into_owned();
    let (code, out, err) = vorda(
        &w,
        &["db", "update", "--ecosystem", "PyPI", "--from", &mirror],
        &[],
    );
    assert_eq!(code, 0, "{out}\n{err}");

    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 3, "{}", errors(&result));
    assert_eq!(result["status"], "vulnerable");
    assert_eq!(result["errors"], json!([]));
    let mut found: Vec<&str> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["advisory"].as_str().unwrap())
        .collect();
    found.sort();
    assert_eq!(found, ["PYSEC-test-af", "PYSEC-test-tf"]);
    let warnings = result["warnings"].to_string();
    for expected in [
        "OSV-test-git gives only git commit ranges, so no version can match it (OSV version queries do not match it either): tensorflow 2.4.0",
        "PYSEC-test-empty lists no affected versions or ranges, so no version can match it (OSV version queries do not match it either): gradio 3.0",
        "PYSEC-test-empty2 lists no affected versions or ranges",
    ] {
        assert!(warnings.contains(expected), "{expected}\n{warnings}");
    }
}

#[test]
fn a_range_that_cannot_be_read_stays_unknown_even_when_the_entry_lists_versions() {
    let w = world(&lock(&[]));
    fs::remove_file(w.root.join("package-lock.json")).unwrap();
    let pypi = |id: &str, name: &str, affected: Value| {
        let mut a = affected;
        a["package"] = json!({"ecosystem":"PyPI","name":name});
        (
            format!("{id}.json"),
            record(json!({"id":id,"modified":"2099-01-01T00:00:00Z","affected":[a]})),
        )
    };
    let entries = [
        // A list that stops at the last release when the record was built, plus a
        // `fixed` that is not a PEP 440 version: later releases may still be affected.
        pypi(
            "GHSA-test-bb",
            "buildbot",
            json!({"versions":["0.7.6","0.7.11","2.0.0","4.3.0"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0.7.6"},{"fixed":"0.7.11p3"}]}]}),
        ),
        pypi(
            "PYSEC-test-na",
            "apache-airflow",
            json!({"versions":["2.9.0b1","2.9.0rc1"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.9.0-NA"}]}]}),
        ),
        pypi(
            "PYSEC-test-na2",
            "apache-airflow",
            json!({"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.10.0-NA"}]}]}),
        ),
        pypi(
            "PYSEC-test-evt",
            "example-evt",
            json!({"versions":["1.0.0"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"unfixed":"3.0.0"}]}]}),
        ),
        pypi(
            "PYSEC-test-none",
            "example-none",
            json!({"versions":["1.0.0"],"ranges":[{"type":"ECOSYSTEM","events":[]}]}),
        ),
    ];
    let entries: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    publish(&w, "PyPI", &zip_of(&entries));
    let mirror = w.mirror.to_string_lossy().into_owned();
    let (code, out, err) = vorda(
        &w,
        &["db", "update", "--ecosystem", "PyPI", "--from", &mirror],
        &[],
    );
    assert_eq!(code, 0, "{out}\n{err}");

    for (pin, id) in [
        ("buildbot==4.4.0", "GHSA-test-bb"),
        ("example-evt==2.0.0", "PYSEC-test-evt"),
        ("example-none==2.0.0", "PYSEC-test-none"),
    ] {
        fs::write(w.root.join("requirements.txt"), format!("{pin}\n")).unwrap();
        let (code, result) = scan_json(&w, &["--offline-db"], &[]);
        assert_eq!(code, 2, "{pin}: {result}");
        assert_eq!(result["status"], "unknown", "{pin}");
        assert!(
            errors(&result).contains(&format!("{id}:")),
            "{pin}: {}",
            errors(&result)
        );
    }

    // A listed version is still a finding, and so is one below the event's release.
    for (pin, id, expected) in [
        ("buildbot==4.3.0", "GHSA-test-bb", 3),
        ("apache-airflow==2.9.0rc1", "PYSEC-test-na", 3),
        ("apache-airflow==1.10.0", "PYSEC-test-na", 3),
    ] {
        fs::write(w.root.join("requirements.txt"), format!("{pin}\n")).unwrap();
        let (code, result) = scan_json(&w, &["--offline-db"], &[]);
        assert_eq!(code, expected, "{pin}: {}", errors(&result));
        assert!(
            result["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["advisory"] == id),
            "{pin}: {result}"
        );
    }
}

#[test]
fn an_event_that_cannot_be_ordered_leaves_only_its_own_release_unknown() {
    let w = world(&lock(&[]));
    fs::remove_file(w.root.join("package-lock.json")).unwrap();
    // Real OSV records, trimmed to their ranges.
    let entry = |ecosystem: &str, name: &str, kind: &str, events: Value| json!({"package":{"ecosystem":ecosystem,"name":name},"ranges":[{"type":kind,"events":events}]});
    let torch = |id: &str, events: Value| {
        let affected = [entry("PyPI", "torch", "ECOSYSTEM", events)];
        (
            format!("{id}.json"),
            record(json!({"id":id,"modified":"2099-01-01T00:00:00Z","affected":affected})),
        )
    };
    let pypi = [
        torch(
            "PYSEC-2025-189",
            json!([{"introduced":"0"},{"last_affected":"2.6.0-cu124"}]),
        ),
        torch(
            "PYSEC-2025-210",
            json!([{"introduced":"0"},{"last_affected":"2.5.0-NA"},{"last_affected":"2.7.1-NA"}]),
        ),
    ];
    let redis = "github.com/redis/go-redis/v9";
    let go = json!({"id":"GHSA-92cp-5422-2mw7","modified":"2099-01-01T00:00:00Z","affected":[
        entry("Go", redis, "SEMVER", json!([{"introduced":"9.7.0-beta.1"},{"fixed":"9.7.3"}])),
        entry("Go", redis, "ECOSYSTEM", json!([{"introduced":"9.6.0b1"},{"fixed":"9.6.3"}])),
        entry("Go", redis, "SEMVER", json!([{"introduced":"9.5.1"},{"fixed":"9.5.5"}])),
    ]});
    let pypi: Vec<(&str, Vec<u8>)> = pypi.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
    publish(&w, "PyPI", &zip_of(&pypi));
    publish(
        &w,
        "Go",
        &zip_of(&[("GHSA-92cp-5422-2mw7.json", record(go))]),
    );
    let mirror = w.mirror.to_string_lossy().into_owned();
    let args = [
        "db",
        "update",
        "--ecosystem",
        "PyPI",
        "--ecosystem",
        "Go",
        "--from",
        &mirror,
    ];
    let (code, out, err) = vorda(&w, &args, &[]);
    assert_eq!(code, 0, "{out}\n{err}");

    let pin = |name: &str, version: &str| {
        let (file, text) = match name {
            "torch" => ("requirements.txt", format!("torch=={version}\n")),
            _ => (
                "go.sum",
                format!("{redis} {version} h1:7eBu7KsSvFDtSXUIDbh3aqlK4DPsZ1rByC8PFfBThos=\n"),
            ),
        };
        for other in ["requirements.txt", "go.sum"] {
            let _ = fs::remove_file(w.root.join(other));
        }
        fs::write(w.root.join(file), text).unwrap();
        scan_json(&w, &["--offline-db"], &[])
    };
    // (package, version, exit code, findings)
    for (name, version, code, findings) in [
        ("torch", "2.9.0", 0, 0),
        ("torch", "2.5.1", 3, 2),
        ("torch", "1.13.0", 3, 2),
        (redis, "v9.16.0", 0, 0),
        (redis, "v9.6.2", 3, 1),
    ] {
        let (got, result) = pin(name, version);
        assert_eq!(got, code, "{name} {version}: {}", errors(&result));
        assert_eq!(
            result["findings"].as_array().unwrap().len(),
            findings,
            "{name} {version}"
        );
    }
    // A version of the event's own release could be either side of it, and one below an
    // introduced the OSV service would sort below every version stays unknown.
    let go_why = "GHSA-92cp-5422-2mw7: event version \\\"9.6.0b1\\\" cannot be ordered";
    for (name, version, why) in [
        (
            "torch",
            "2.6.0",
            "PYSEC-2025-189: event version \\\"2.6.0-cu124\\\" cannot be ordered",
        ),
        (redis, "v9.6.0", go_why),
        (redis, "v9.5.0", go_why),
    ] {
        let (got, result) = pin(name, version);
        assert_eq!(got, 2, "{name} {version}: {result}");
        assert!(errors(&result).contains(why), "{}", errors(&result));
    }
}

#[test]
fn a_range_with_several_last_affected_events_matches_up_to_the_highest() {
    let w = world(&lock(&[]));
    fs::remove_file(w.root.join("package-lock.json")).unwrap();
    // The shape of real PyPI records: one introduced, then many last_affected, and a
    // version list that skips some of the versions in between.
    let advisory = json!({"id":"PYSEC-test-la","modified":"2099-01-01T00:00:00Z","affected":[
        {"package":{"ecosystem":"PyPI","name":"example-la"},
         "versions":["1.0.0","3.0.0"],
         "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.0.0"},{"last_affected":"2.0.0"},{"last_affected":"3.0.0"}]}]}]});
    publish(
        &w,
        "PyPI",
        &zip_of(&[("PYSEC-test-la.json", record(advisory))]),
    );
    let mirror = w.mirror.to_string_lossy().into_owned();
    let (code, out, err) = vorda(
        &w,
        &["db", "update", "--ecosystem", "PyPI", "--from", &mirror],
        &[],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    for (pin, expected) in [
        ("example-la==1.5.0", 3),
        ("example-la==2.0.0", 3),
        ("example-la==3.0.0", 3),
        ("example-la==3.0.1", 0),
    ] {
        fs::write(w.root.join("requirements.txt"), format!("{pin}\n")).unwrap();
        let (code, result) = scan_json(&w, &["--offline-db"], &[]);
        assert_eq!(code, expected, "{pin}: {result}");
        let found = result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["advisory"] == "PYSEC-test-la");
        assert_eq!(found, expected == 3, "{pin}: {result}");
    }
}

#[test]
fn events_at_one_version_keep_their_order_and_give_an_answer() {
    let w = world(&lock(&[]));
    fs::remove_file(w.root.join("package-lock.json")).unwrap();
    // Real shapes: `introduced X, fixed X` marks an unaffected branch (RUSTSEC-2024-0399),
    // and `fixed X, introduced X` is affected again from X (PYSEC-2024-258).
    let unaffected = json!({"id":"PYSEC-test-tie1","modified":"2099-01-01T00:00:00Z","affected":[
        {"package":{"ecosystem":"PyPI","name":"example-tie"},
         "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0.23.0"},{"fixed":"0.23.0"},{"introduced":"0.23.13"},{"fixed":"0.23.18"}]}]}]});
    let again = json!({"id":"PYSEC-test-tie2","modified":"2099-01-01T00:00:00Z","affected":[
        {"package":{"ecosystem":"PyPI","name":"example-tie"},
         "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.20.0"},{"introduced":"0.20.0"},{"fixed":"0.23.10"}]}]}]});
    publish(
        &w,
        "PyPI",
        &zip_of(&[
            ("PYSEC-test-tie1.json", record(unaffected)),
            ("PYSEC-test-tie2.json", record(again)),
        ]),
    );
    let mirror = w.mirror.to_string_lossy().into_owned();
    let (code, out, err) = vorda(
        &w,
        &["db", "update", "--ecosystem", "PyPI", "--from", &mirror],
        &[],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    for (pin, ids, code_wanted) in [
        ("example-tie==0.23.5", &["PYSEC-test-tie2"][..], 3),
        ("example-tie==0.23.15", &["PYSEC-test-tie1"][..], 3),
        ("example-tie==0.23.20", &[][..], 0),
    ] {
        fs::write(w.root.join("requirements.txt"), format!("{pin}\n")).unwrap();
        let (code, result) = scan_json(&w, &["--offline-db"], &[]);
        assert_eq!(code, code_wanted, "{pin}: {result}");
        let mut found: Vec<&str> = result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["advisory"].as_str())
            .collect();
        found.sort();
        assert_eq!(found, ids, "{pin}: {result}");
    }
}

#[test]
fn an_advisory_shared_by_two_ecosystems_keeps_each_ecosystems_fixed_versions() {
    let w = world(&lock(&[("shared", "1.0.0")]));
    fs::write(w.root.join("requirements.txt"), "shared==1.0.0\n").unwrap();
    let advisory = json!({"id":"GHSA-test-0010","modified":"2099-01-01T00:00:00Z","affected":[
        {"package":{"ecosystem":"npm","name":"shared"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]},
        {"package":{"ecosystem":"PyPI","name":"shared"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.3.0"}]}]}]});
    for ecosystem in ["npm", "PyPI"] {
        publish(
            &w,
            ecosystem,
            &zip_of(&[("GHSA-test-0010.json", record(advisory.clone()))]),
        );
    }
    let mirror = w.mirror.to_string_lossy().into_owned();
    let args = [
        "db",
        "update",
        "--ecosystem",
        "npm",
        "--ecosystem",
        "PyPI",
        "--from",
        &mirror,
    ];
    let (code, out, err) = vorda(&w, &args, &[]);
    assert_eq!(code, 0, "{out}\n{err}");

    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 3, "{}", errors(&result));
    let mut seen: Vec<(String, Value, Value)> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["package"]["ecosystem"].as_str().unwrap().to_owned(),
                f["fixed"].clone(),
                f["affected_ranges"][0]["events"][1].clone(),
            )
        })
        .collect();
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        seen,
        [
            (
                "PyPI".to_owned(),
                json!(["1.3.0"]),
                json!({"fixed":"1.3.0"})
            ),
            ("npm".to_owned(), json!(["1.2.0"]), json!({"fixed":"1.2.0"})),
        ]
    );
}

/// `ranges` SEMVER ranges of 1,000 events each; version 1.0.0 is affected by the first.
fn many_events(id: &str, name: &str, ranges: usize) -> Vec<u8> {
    let ranges: Vec<Value> = (0..ranges)
        .map(|r| {
            let events: Vec<Value> = (0..1000)
                .map(|i| match i {
                    0 => json!({"introduced":"0"}),
                    i if i % 2 == 1 => json!({"fixed":format!("{}.0.{i}", r + 2)}),
                    i => json!({"introduced":format!("{}.0.{i}", r + 2)}),
                })
                .collect();
            json!({"type":"SEMVER","events":events})
        })
        .collect();
    record(
        json!({"id":id,"modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":name},"ranges":ranges}]}),
    )
}

#[test]
fn range_events_are_bounded_per_package_and_per_scan_across_every_lockfile() {
    let w = world(&lock(&[("wide", "1.0.0")]));
    publish(
        &w,
        "npm",
        &zip_of(&[
            (
                "GHSA-test-0020.json",
                many_events("GHSA-test-0020", "wide", 21),
            ),
            (
                "GHSA-test-0021.json",
                many_events("GHSA-test-0021", "big", 10),
            ),
        ]),
    );
    assert_eq!(update(&w).0, 0);
    // 21,000 events for one package: over the per-package bound.
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2, "{}", errors(&result));
    assert!(
        errors(&result).contains("wide: matched advisories carry more range events than the offline lookup bound (20000 per package, 50000 per scan counting every place a package is installed): 1 package not checked (wide 1.0.0)"),
        "{}",
        errors(&result)
    );

    // 10,000 events copied into each lockfile's finding: four copies fit the scan bound.
    fs::remove_file(w.root.join("package-lock.json")).unwrap();
    for copies in [4, 6] {
        for c in 0..copies {
            let dir = w.root.join(format!("m{c}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("package-lock.json"), lock(&[("big", "1.0.0")])).unwrap();
        }
        let (code, result) = scan_json(&w, &["--offline-db"], &[]);
        if copies == 4 {
            assert_eq!(code, 3, "{}", errors(&result));
            assert_eq!(result["findings"].as_array().unwrap().len(), 4);
        } else {
            // Six copies are 60,000 events: unknown with the reason, never a silent drop.
            assert_eq!(code, 2, "{}", errors(&result));
            assert_eq!(result["findings"], json!([]));
            assert!(
                errors(&result).contains("big: matched advisories carry more range events than the offline lookup bound (20000 per package, 50000 per scan counting every place a package is installed): 1 package not checked (big 1.0.0)"),
                "{}",
                errors(&result)
            );
        }
    }
}

#[test]
fn an_unknown_package_is_never_counted_as_covered() {
    let w = world(&lock(&[("example", "1.2.3"), ("odd", "1.0.0")]));
    let mut entries = good_npm();
    entries.push((
        "GHSA-test-0004.json",
        record(npm(
            "GHSA-test-0004",
            "odd",
            json!([{"introduced":"0"},{"fixed":"next"}]),
        )),
    ));
    publish(&w, "npm", &zip_of(&entries));
    assert_eq!(update(&w).0, 0);
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2, "{}", errors(&result));
    // Only `example` was fully answered; `odd` is unknown and must not retire saved findings.
    assert_eq!(
        result["covered"],
        json!([result["findings"][0]["asset"].clone()])
    );
}

fn age(path: &std::path::Path, hours: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(hours * 3600);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

#[test]
fn a_mirror_is_as_old_as_its_files_not_the_copy() {
    let w = world(&lock(&[("example", "1.2.3")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    age(&w.mirror.join("npm/all.zip"), 100);
    age(&w.mirror.join("kev.json"), 100);
    // The refresh loads the old export but exits non-zero, so a timer notices.
    let (code, out, err) = update(&w);
    assert_eq!(code, 2, "{out}\n{err}");
    assert!(
        out.contains(
            "npm: updated-stale: the npm export is 100 hours old, over the limit of 72 hours"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "KEV: updated-stale: the KEV list is 100 hours old, over the limit of 72 hours"
        ),
        "{out}"
    );
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2, "{}", errors(&result));
    let text = errors(&result);
    assert!(
        text.contains(
            "local advisory database for npm is 100 hours old, over the limit of 72 hours"
        ),
        "{text}"
    );
    assert!(
        text.contains("the local KEV list is 100 hours old"),
        "{text}"
    );
}

#[test]
fn a_mirror_export_much_smaller_than_the_index_is_refused() {
    let w = world(&lock(&[("example", "1.2.3"), ("pkg7", "1.0.0")]));
    let full: Vec<(String, Vec<u8>)> = (0..20)
        .map(|k| {
            let id = format!("GHSA-test-1{k:03}");
            let name = format!("pkg{k}");
            (
                format!("{id}.json"),
                record(npm(
                    &id,
                    &name,
                    json!([{"introduced":"0"},{"fixed":"2.0.0"}]),
                )),
            )
        })
        .collect();
    let named: Vec<(&str, Vec<u8>)> = full.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
    publish(&w, "npm", &zip_of(&named));
    assert_eq!(update(&w).0, 0);

    // A partial export (3 of 20 entries) would hide the pkg7 advisory: keep the full index.
    publish(&w, "npm", &zip_of(&good_npm()));
    let (code, out, _) = update(&w);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("npm: kept-previous: export has 3 entries, fewer than 90% of the 20 this index has held"),
        "{out}"
    );
    let (_, result) = scan_json(&w, &["--offline-db"], &[]);
    let found: Vec<&str> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["advisory"].as_str().unwrap())
        .collect();
    assert_eq!(found, ["GHSA-test-1007"], "{}", errors(&result));
}

/// An npm export of `n` advisories, `GHSA-test-2<k>` for package `pkg<k>`.
fn numbered(n: usize) -> Vec<u8> {
    let entries: Vec<(String, Vec<u8>)> = (0..n)
        .map(|k| {
            let id = format!("GHSA-test-2{k:03}");
            let body = record(npm(
                &id,
                &format!("pkg{k}"),
                json!([{"introduced":"0"},{"fixed":"2.0.0"}]),
            ));
            (format!("{id}.json"), body)
        })
        .collect();
    let named: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    zip_of(&named)
}

fn advisories(w: &World) -> Vec<String> {
    let (_, result) = scan_json(w, &["--offline-db"], &[]);
    result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["advisory"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_mirror_that_shrinks_a_little_each_sync_is_refused_once_it_is_far_below_its_largest() {
    let w = world(&lock(&[("pkg17", "1.0.0")]));
    publish(&w, "npm", &numbered(20));
    assert_eq!(update(&w).0, 0);
    // 18 of 20 is within 10%: accepted.
    publish(&w, "npm", &numbered(18));
    let (code, out, _) = update(&w);
    assert_eq!(code, 0, "{out}");
    // 17 is within 10% of the 18 now loaded, but not of the 20 the index has held.
    publish(&w, "npm", &numbered(17));
    let (code, out, _) = update(&w);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("npm: kept-previous: export has 17 entries, fewer than 90% of the 20 this index has held"),
        "{out}"
    );
    assert_eq!(advisories(&w), ["GHSA-test-2017"]);
}

#[test]
fn an_export_with_unreadable_records_does_not_erase_the_largest_size_held() {
    let w = world(&lock(&[("pkg17", "1.0.0")]));
    publish(&w, "npm", &numbered(20));
    assert_eq!(update(&w).0, 0);
    // The same 20 plus one record nested too deep to read.
    let mut entries: Vec<(String, Vec<u8>)> = (0..20)
        .map(|k| {
            let id = format!("GHSA-test-2{k:03}");
            let body = record(npm(
                &id,
                &format!("pkg{k}"),
                json!([{"introduced":"0"},{"fixed":"2.0.0"}]),
            ));
            (format!("{id}.json"), body)
        })
        .collect();
    entries.push((
        "deep.json".to_owned(),
        format!("{}{}", "[".repeat(100), "]".repeat(100)).into_bytes(),
    ));
    let named: Vec<(&str, Vec<u8>)> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.clone()))
        .collect();
    publish(&w, "npm", &zip_of(&named));
    let (code, out, _) = update(&w);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("npm: updated-with-unreadable-records"),
        "{out}"
    );
    // 5 is far below the 20 the index has held.
    publish(&w, "npm", &numbered(5));
    let (code, out, _) = update(&w);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("npm: kept-previous: export has 5 entries, fewer than 90% of the 20 this index has held"),
        "{out}"
    );
    // The kept index is the partly unreadable one, so the scan stays unknown, never clean.
    let (code, result) = scan_json(&w, &["--offline-db"], &[]);
    assert_eq!(code, 2);
    assert!(
        errors(&result).contains("1 records in the npm export could not be read"),
        "{}",
        errors(&result)
    );
}

#[test]
fn a_first_install_far_smaller_than_a_complete_export_is_refused() {
    let w = world(&lock(&[("example", "1.2.3")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    let mirror = w.mirror.to_string_lossy().into_owned();
    let args = ["db", "update", "--ecosystem", "npm", "--from", &mirror];
    let (code, out, _) = vorda(&w, &args, &[("VORDA_ADVISORY_DB_MIN_ENTRIES", "")]);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("npm: kept-previous: export has 3 entries, fewer than the 115000 a complete npm export holds"),
        "{out}"
    );
    let (code, _, err) = vorda(&w, &["scan", "--offline-db", "--json"], &[]);
    assert_eq!(code, 2);
    let error: Value = serde_json::from_str(&err).unwrap();
    assert_eq!(error["status"], "unknown");
    assert!(error["error"].as_str().unwrap().contains("vorda db update"));
    // A small private mirror sets its own floor.
    let (code, out, _) = vorda(&w, &args, &[("VORDA_ADVISORY_DB_MIN_ENTRIES", "3")]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(advisories(&w), ["CVE-2099-0001"]);
}

#[test]
fn db_help_states_what_update_checks_and_what_it_cannot() {
    let w = world(&lock(&[]));
    let (code, out, _) = vorda(&w, &["db", "--help"], &[]);
    assert_eq!(code, 0);
    assert!(!out.contains("only when the new one is complete"), "{out}");
    for needed in [
        "OSV exports carry no completeness marker",
        "90% of the most entries",
        "VORDA_ADVISORY_DB_MIN_ENTRIES",
        "exits 2",
    ] {
        assert!(out.contains(needed), "missing {needed:?}:\n{out}");
    }
}

#[test]
fn db_update_takes_an_ecosystem_name_in_any_case() {
    let w = world(&lock(&[("example", "1.2.3")]));
    publish(&w, "npm", &zip_of(&good_npm()));
    let mirror = w.mirror.to_string_lossy().into_owned();
    let (code, out, err) = vorda(
        &w,
        &["db", "update", "--ecosystem", "NPM", "--from", &mirror],
        &[],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("npm: updated"), "{out}");
}
