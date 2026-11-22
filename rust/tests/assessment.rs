use serde_json::{json, Value};
use std::collections::BTreeSet;
use vorda::{cli, domain::ScanOptions, store::Store};

#[test]
fn assessment_can_be_discarded_before_any_mailbox_or_asset_publication() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("requirements.txt"), "example==1.2.3\n").unwrap();
    let mut store = Store::open(&root.path().join("state")).unwrap();
    let finding = json!({"key":"retained","asset":"retained-asset","title":"Existing advisory","package":{"path":project.join("requirements.txt")}}).as_object().unwrap().clone();
    store.reconcile(&[finding], &BTreeSet::new(), &[]).unwrap();
    let saved = store.root.join("last-scan.json");
    std::fs::write(&saved, "existing scan").unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![project];
    options.offline = true;
    let assessment = cli::assess(&options, &store).unwrap();
    assert_eq!(assessment.result["status"], "unknown");
    assert_eq!(store.active().unwrap().len(), 1);
    let messages: i64 = store
        .db
        .query_row("SELECT count(*) FROM messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(messages, 1);
    assert_eq!(std::fs::read_to_string(&saved).unwrap(), "existing scan");
    let has_assets: bool = store
        .db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='asset_scopes')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!has_assets);
    drop(assessment);
    let lock = store.locked().unwrap();
    let assessment = cli::assess(&options, &store).unwrap();
    let result = cli::commit_assessment(assessment, &mut store).unwrap();
    drop(lock);
    assert_eq!(result["status"], "unknown");
    assert_eq!(
        serde_json::from_str::<Value>(&std::fs::read_to_string(saved).unwrap()).unwrap()["status"],
        "unknown"
    );
    assert!(store
        .active()
        .unwrap()
        .iter()
        .any(|f| f["key"] == "retained"));
    assert!(result["new_messages"].as_u64().unwrap() > 0);
}

#[test]
fn native_rescan_closes_health_from_python_scope_without_new_changed_mail() {
    use vorda::{
        scanner::feeds::{KEV, OSV},
        store::{identity, now},
    };
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let project = project.canonicalize().unwrap();
    std::fs::write(project.join("requirements.txt"), "example==1.2.3\n").unwrap();
    let mut store = Store::open(&temp.path().join("state")).unwrap();
    // Python's on-disk scope contract uses str(None), not an empty path.
    let scope = identity(&json!([[project], false, false, false, "None"])).unwrap();
    let key = format!("health:{scope}:kev");
    let finding = json!({"key":key,"asset":key,"kind":"health","scan_scope":scope,"title":"Feed unavailable","error":"offline"}).as_object().unwrap().clone();
    store.reconcile(&[finding], &BTreeSet::new(), &[]).unwrap();
    let cache = store.root.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(
        cache.join(format!("{}.json", identity(&json!([KEV, null])).unwrap())),
        json!({"source_url":KEV,"checked":now(),"data":{"vulnerabilities":[]}}).to_string(),
    )
    .unwrap();
    let url = format!("{OSV}/querybatch");
    let query =
        json!({"queries":[{"package":{"name":"example","ecosystem":"PyPI"},"version":"1.2.3"}]});
    std::fs::write(
        cache.join(format!("{}.json", identity(&json!([url, query])).unwrap())),
        json!({"source_url":url,"checked":now(),"data":{"results":[{}]}}).to_string(),
    )
    .unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![project];
    let result = cli::check(&options, &mut store).unwrap();
    assert_eq!(result["scan_scope"], scope);
    assert_eq!(result["status"], "no-known-findings");
    assert!(store.active().unwrap().is_empty());
    assert_eq!(result["new_messages"], 0);
    assert_eq!(cli::check(&options, &mut store).unwrap()["new_messages"], 0);
}

#[test]
fn oci_scope_keeps_python_roots_without_scanning_them() {
    use vorda::store::identity;
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("unrelated");
    std::fs::create_dir(&project).unwrap();
    let project = project.canonicalize().unwrap();
    std::fs::write(project.join("requirements.txt"), "unrelated==1.0\n").unwrap();
    let archive = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/scanner/fixtures/oci/normal.tar.gz")
        .canonicalize()
        .unwrap();
    let store = Store::open(&temp.path().join("state")).unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![project.clone()];
    options.inventory.oci = Some(archive.clone());
    options.offline = true;
    let result = cli::assess(&options, &store).unwrap().result;
    let expected = identity(&json!([
        [project],
        false,
        false,
        false,
        "None",
        "oci",
        archive
    ]))
    .unwrap();
    assert_eq!(result["scan_scope"], expected);
    assert!(!result["packages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "unrelated"));
    options.inventory.roots.clear();
    let result = cli::assess(&options, &store).unwrap().result;
    let cwd = std::env::current_dir().unwrap();
    let expected = identity(&json!([[cwd], false, false, false, "None", "oci", archive])).unwrap();
    assert_eq!(result["scan_scope"], expected);
}

#[cfg(windows)]
#[test]
fn windows_scope_does_not_add_a_verbatim_prefix_to_python_paths() {
    use vorda::store::identity;
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let store = Store::open(&temp.path().join("state")).unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![project.clone()];
    options.offline = true;
    let result = cli::assess(&options, &store).unwrap().result;
    assert_eq!(
        result["scan_scope"],
        identity(&json!([[project], false, false, false, "None"])).unwrap()
    );
    let explicit = project.canonicalize().unwrap();
    options.inventory.roots = vec![explicit.clone()];
    let result = cli::assess(&options, &store).unwrap().result;
    assert_eq!(
        result["scan_scope"],
        identity(&json!([[explicit], false, false, false, "None"])).unwrap()
    );
}

#[test]
fn failed_assessment_publication_rolls_back_mail_assets_and_scan_metadata() {
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    let prior = json!({"key":"prior","asset":"prior","title":"existing"})
        .as_object()
        .unwrap()
        .clone();
    store
        .reconcile(std::slice::from_ref(&prior), &BTreeSet::new(), &[])
        .unwrap();
    store.db.execute_batch("CREATE TABLE scans(host TEXT,started REAL,finished REAL,status TEXT,seconds REAL,findings INTEGER,errors TEXT,scan_scope TEXT); CREATE TRIGGER reject_scan BEFORE INSERT ON scans BEGIN SELECT RAISE(ABORT,'synthetic storage rejection'); END;").unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![t.path().join("missing")];
    options.offline = true;
    let assessment = cli::assess(&options, &store).unwrap();
    assert!(cli::commit_assessment(assessment, &mut store).is_err());
    drop(store);
    let mut reopened = Store::open(t.path()).unwrap();
    assert_eq!(reopened.active().unwrap(), vec![prior]);
    assert_eq!(
        reopened
            .mail("test", "list", &0.into(), &0.into())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vorda::assets::summary(&reopened.db, None, None).unwrap()["total"],
        0
    );
}

#[test]
fn a_storage_failure_that_ends_the_transaction_keeps_its_own_error() {
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    store.db.execute_batch("CREATE TABLE scans(host TEXT,started REAL,finished REAL,status TEXT,seconds REAL,findings INTEGER,errors TEXT,scan_scope TEXT); CREATE TRIGGER reject_scan BEFORE INSERT ON scans BEGIN SELECT RAISE(ROLLBACK,'synthetic storage rejection'); END;").unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![t.path().join("missing")];
    options.offline = true;
    let assessment = cli::assess(&options, &store).unwrap();
    let error = cli::commit_assessment(assessment, &mut store).unwrap_err();
    assert!(
        error.to_string().contains("synthetic storage rejection"),
        "{error}"
    );
}
