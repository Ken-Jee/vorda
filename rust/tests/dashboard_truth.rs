use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    domain::InventoryOptions,
    scanner,
    store::Store,
    surfaces::dashboard::{data, views},
};

fn lock(root: &Path, relative: &str) {
    let path = root.join(relative).join("package-lock.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
}

fn inventory(root: &Path) -> Value {
    json!(scanner::inventory(&InventoryOptions {
        roots: vec![root.into()],
        ..Default::default()
    })
    .unwrap())
}

#[test]
fn parent_folder_names_do_not_change_project_scope() {
    let temp = tempfile::tempdir().unwrap();
    for name in ["prodapp", "test/myapp", "fixtures/app"] {
        let root = temp.path().join(name);
        lock(&root, "");
        let result = inventory(&root);
        assert_eq!(result["packages"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["packages"][0]["scope"], "reachable-unknown",
            "{name}"
        );
        assert_eq!(
            result["packages"][0]["path"],
            root.join("package-lock.json").to_string_lossy().as_ref()
        );
    }
}

#[test]
fn only_test_and_fixture_folders_inside_the_root_are_dev_only() {
    let temp = tempfile::tempdir().unwrap();
    for folder in ["vendor", "tests", "test", "fixtures"] {
        lock(temp.path(), &format!("{folder}/x"));
    }
    let result = inventory(temp.path());
    let packages = result["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 4);
    for p in packages {
        let vendor = Path::new(p["path"].as_str().unwrap()).starts_with(temp.path().join("vendor"));
        assert_eq!(
            p["scope"],
            if vendor {
                "reachable-unknown"
            } else {
                "likely-dev-only"
            }
        );
    }
}

fn snapshot(findings: &[Value], status: &str) -> Value {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(temp.path()).unwrap();
    store
        .reconcile(
            &findings
                .iter()
                .map(|f| f.as_object().unwrap().clone())
                .collect::<Vec<_>>(),
            &Default::default(),
            &[],
        )
        .unwrap();
    let db = rusqlite::Connection::open(temp.path().join("mail.db")).unwrap();
    db.execute_batch("CREATE TABLE scans(host TEXT,started REAL,finished REAL,status TEXT,seconds REAL,findings INTEGER,errors TEXT)").unwrap();
    db.execute(
        "INSERT INTO scans VALUES('example-host',999,1000,?1,1,?2,'[]')",
        rusqlite::params![status, findings.len()],
    )
    .unwrap();
    data::snapshot(temp.path(), 1001., None).unwrap()
}

fn dev_findings() -> Vec<Value> {
    (0..3).map(|n| json!({"key":format!("finding-{n}"),"host":"example-host","advisory":format!("ADV-{n}"),"package":{"name":"example","version":"1.0.0","ecosystem":"npm","path":"tests/package-lock.json","scope":"likely-dev-only"},"priority":{"level":"critical"},"kev":false})).collect()
}

#[test]
fn dashboard_reports_nonurgent_open_findings_instead_of_all_clear() {
    let snapshot = snapshot(&dev_findings(), "ok");
    let page = views::now_screen(&snapshot);
    assert!(!page.contains("All clear"), "{page}");
    assert!(page.contains("0 urgent"), "{page}");
    assert!(page.contains("3 open"), "{page}");
    assert!(page.contains("test or fixture folders"), "{page}");
    assert!(page.contains("href=\"/findings\""), "{page}");
}

#[test]
fn host_card_does_not_call_nonurgent_open_findings_fine() {
    let snapshot = snapshot(&dev_findings(), "ok");
    let page = views::now_screen(&snapshot);
    assert!(!page.contains(">Fine<"), "{page}");
    assert!(!page.contains("word ok"), "{page}");
}

#[test]
fn dashboard_json_health_warns_about_nonurgent_open_findings() {
    let snapshot = snapshot(&dev_findings(), "ok");
    assert_eq!(snapshot["hosts"][0]["needs"], 0);
    assert_eq!(snapshot["hosts"][0]["health"], "warning");
}

#[test]
fn nonurgent_open_counts_remain_visible_when_scan_is_unknown() {
    let snapshot = snapshot(&dev_findings(), "unknown");
    let page = views::now_screen(&snapshot);
    assert!(!page.contains("All clear"), "{page}");
    assert!(page.contains("0 urgent, 3 open"), "{page}");
    assert!(page.contains("Scan failed"), "{page}");
}

#[test]
fn low_severity_runtime_findings_are_open_without_dev_folder_claims() {
    let mut findings = dev_findings();
    for finding in &mut findings {
        finding["package"]["scope"] = json!("reachable-unknown");
        finding["priority"]["level"] = json!("low");
    }
    let snapshot = snapshot(&findings, "ok");
    let page = views::now_screen(&snapshot);
    assert!(!page.contains("All clear"), "{page}");
    assert!(!page.contains("test or fixture folders"), "{page}");
    assert!(page.contains("0 urgent, 3 open"), "{page}");
    assert_eq!(snapshot["hosts"][0]["health"], "warning");
}

#[test]
fn all_clear_requires_zero_open_findings_and_known_scan_status() {
    let known = snapshot(&[], "ok");
    assert!(views::now_screen(&known).contains("All clear"));
    assert_eq!(known["hosts"][0]["health"], "good");
    let unknown = snapshot(&[], "unknown");
    assert!(!views::now_screen(&unknown).contains("All clear"));
    assert_eq!(unknown["hosts"][0]["health"], "warning");
}

fn offline_snapshot(open: usize) -> Value {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    let state = temp.path().join("state");
    lock(&root, "tests");
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&state)
        .args(["scan", "--json", "--root"])
        .arg(&root)
        .arg("--offline")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let scan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(scan["status"], "unknown");
    assert_eq!(scan["findings"], json!([]));
    assert_eq!(scan["errors"].as_array().unwrap().len(), 2);
    let findings: Vec<_> = (0..open)
        .map(|n| {
            json!({"key":format!("saved-{n}"),"advisory":format!("ADV-{n}"),
            "scan_scope":scan["scan_scope"],"host":vorda::store::hostname().unwrap(),
            "package":{"name":"example","version":"1.0.0","ecosystem":"npm",
                "path":root.join("tests/package-lock.json"),"scope":"likely-dev-only"},
            "priority":{"level":"critical"},"kev":false})
            .as_object()
            .unwrap()
            .clone()
        })
        .collect();
    Store::open(&state)
        .unwrap()
        .reconcile(&findings, &Default::default(), &[])
        .unwrap();
    let snapshot = data::snapshot(&state, vorda::store::now(), None).unwrap();
    assert_eq!(
        snapshot["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["type"] == "health")
            .count(),
        2
    );
    snapshot
}

#[test]
fn offline_feed_errors_are_unknown_instead_of_open_findings() {
    let snapshot = offline_snapshot(0);
    let home = views::now_screen(&snapshot);
    let findings = views::render(&snapshot, "findings", "", "all", "", "", false).unwrap();
    assert!(findings.contains("Open findings</div><div class=\"hero\">0</div>"));
    assert!(home.contains("<span>Can't confirm</span>"), "{home}");
    assert!(!home.contains("0 urgent, 2 open"), "{home}");
    assert!(!home.contains("All clear"), "{home}");
    assert!(!home.contains(">Fine<"), "{home}");
}

#[test]
fn saved_findings_and_offline_errors_have_the_same_open_count_on_both_pages() {
    let snapshot = offline_snapshot(4);
    let home = views::now_screen(&snapshot);
    let findings = views::render(&snapshot, "findings", "", "all", "", "", false).unwrap();
    assert!(
        findings.contains("Open findings</div><div class=\"hero\">4</div>"),
        "{findings}"
    );
    assert!(home.contains("0 urgent, 4 open"), "{home}");
    assert!(home.contains("<span>Can't confirm</span>"), "{home}");
    assert!(!home.contains("6 open"), "{home}");
    assert!(!home.contains("All clear"), "{home}");
}

#[test]
fn grouped_libraries_do_not_promise_a_single_file_edit() {
    let findings: Vec<_> = ["alpha", "beta"]
        .into_iter()
        .map(|name| {
            json!({"key":name,"host":"example-host","advisory":format!("ADV-{name}"),
            "package":{"name":name,"version":"1.0.0","ecosystem":"npm",
                "path":format!("project/{name}.lock"),"scope":"reachable-unknown"},
            "priority":{"level":"critical"},"fixed":["1.0.1"],"kev":false})
        })
        .collect();
    let home = views::now_screen(&snapshot(&findings, "ok"));
    assert!(home.contains("2 libraries"), "{home}");
    assert!(!home.contains("One file edit"), "{home}");
}

fn ubuntu_finding(cve: &str, fixed: &[&str]) -> Value {
    json!({"key":cve,"host":"example-host","advisory":cve,
        "package":{"name":"libc-bin","version":"2.39-0ubuntu8.9","ecosystem":"Ubuntu:24.04:LTS",
            "path":"dpkg-query","scope":"os-package"},
        "priority":{"level":"high"},"fixed":fixed,"kev":false})
}

#[test]
fn system_packages_show_the_update_when_any_finding_names_a_fix() {
    // One finding with a released fix, one without: the update is still worth running.
    let findings = [
        ubuntu_finding("CVE-2026-0001", &["2.39-0ubuntu8.12"]),
        ubuntu_finding("CVE-2026-0002", &[]),
    ];
    let snapshot = snapshot(&findings, "ok");
    let fix = snapshot["issues"][0]["fix"].as_str().unwrap();
    assert_eq!(fix, "Run: sudo apt upgrade", "{:#}", snapshot["issues"]);
    assert!(!views::now_screen(&snapshot).contains("No update yet"));
}

#[test]
fn system_packages_without_a_known_fix_say_it_is_not_known() {
    let snapshot = snapshot(&[ubuntu_finding("CVE-2026-0002", &[])], "ok");
    let fix = snapshot["issues"][0]["fix"].as_str().unwrap();
    assert!(fix.starts_with("Fix not known yet"), "{fix}");
    let page = views::now_screen(&snapshot);
    assert!(!page.contains("No update yet"), "{page}");
}
