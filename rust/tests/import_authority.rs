use serde_json::json;
use std::collections::BTreeSet;
use vorda::{
    cli,
    domain::{Package, ScanOptions},
    store::{asset, identity, now, Store},
};

#[test]
fn imported_partial_or_stale_evidence_retains_omitted_findings_and_original_age() {
    for (status, age, error, different_path, unknown, retain) in [
        ("unknown", 0.0, false, true, false, true),
        ("complete", 259200.0, false, true, false, true),
        ("complete", -86400.0, false, true, false, true),
        ("complete", 0.0, true, true, false, true),
        ("complete", 169200.0, false, false, false, false),
        ("complete", 0.0, false, true, false, false),
        ("complete", 0.0, false, false, true, true),
    ] {
        let t = tempfile::tempdir().unwrap();
        let project = t.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let file = t.path().join("inventory.json");
        let path = project.join("requirements.txt");
        let old: Package = serde_json::from_value(json!({"name":"old-example","version":"1.0","ecosystem":"PyPI","path":path,"scope":"runtime"})).unwrap();
        let mut safe = old.clone();
        safe.name = "safe-example".into();
        if different_path {
            safe.path = project.join("other.txt").to_string_lossy().into();
        }
        if unknown {
            safe.ecosystem = "Unmapped".into();
        }
        let mut store = Store::open(&t.path().join("state")).unwrap();
        let scope = identity(&json!([[project], false, false, false, file])).unwrap();
        store.reconcile(&[json!({"key":"prior","asset":asset(&old).unwrap(),"scan_scope":scope,"package":old,"title":"prior"}).as_object().unwrap().clone()], &BTreeSet::new(), &[]).unwrap();
        let observed = now() - age;
        std::fs::write(&file,json!({"status":status,"observed":observed,"errors":if error {vec!["producer failed"]} else {vec![]},"packages":[safe]}).to_string()).unwrap();
        let cache = store.root.join("cache");
        std::fs::create_dir(&cache).unwrap();
        for (url, body, data) in [
            (
                vorda::scanner::feeds::KEV,
                json!(null),
                json!({"vulnerabilities":[]}),
            ),
            (
                "https://api.osv.dev/v1/querybatch",
                json!({"queries":[{"package":{"name":"safe-example","ecosystem":"PyPI"},"version":"1.0"}]}),
                json!({"results":[{}]}),
            ),
        ] {
            std::fs::write(
                cache.join(format!("{}.json", identity(&json!([url, body])).unwrap())),
                json!({"source_url":url,"checked":now(),"data":data}).to_string(),
            )
            .unwrap();
        }
        let mut options = ScanOptions::default();
        options.inventory.roots = vec![project];
        options.inventory_file = Some(file);
        let result = cli::check(&options, &mut store).unwrap();
        assert_eq!(
            store.active().unwrap().iter().any(|f| f["key"] == "prior"),
            retain,
            "{status} {age} {error}"
        );
        assert_eq!(
            result["assets"]["items"][0]["observed"],
            json!(if age < 0.0 { 0.0 } else { observed })
        );
    }
}

#[test]
fn assessment_preserves_quiet_scope_history_beyond_256_rows() {
    let t = tempfile::tempdir().unwrap();
    let project = t.path().join("empty-project");
    std::fs::create_dir(&project).unwrap();
    let mut store = Store::open(&t.path().join("state")).unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![project];
    options.offline = true;
    cli::check(&options, &mut store).unwrap();
    store.db.execute("INSERT INTO scans(host,started,finished,status,seconds,findings,errors,scan_scope) VALUES('test',0,0,'complete',0,0,'[]','quiet')", []).unwrap();
    store.db.execute_batch("BEGIN").unwrap();
    for i in 1..=256 {
        store.db.execute("INSERT INTO scans(host,started,finished,status,seconds,findings,errors,scan_scope) VALUES('test',?1,?1,'complete',0,0,'[]','busy')", [i]).unwrap();
    }
    store.db.execute_batch("COMMIT").unwrap();
    cli::check(&options, &mut store).unwrap();
    let quiet: i64 = store
        .db
        .query_row(
            "SELECT count(*) FROM scans WHERE scan_scope='quiet'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let total: i64 = store
        .db
        .query_row("SELECT count(*) FROM scans", [], |r| r.get(0))
        .unwrap();
    assert_eq!(quiet, 1);
    assert_eq!(total, 259);
}

#[test]
fn empty_import_and_unknown_empty_syft_have_distinct_cli_removal_authority() {
    for mode in ["complete", "unknown", "syft"] {
        let t = tempfile::tempdir().unwrap();
        let project = t.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let file = t.path().join(if mode == "syft" {
            "syft.json"
        } else {
            "inventory.json"
        });
        let scope_parts = if mode == "syft" {
            json!([
                [project],
                false,
                false,
                false,
                "None",
                "installed",
                false,
                [file]
            ])
        } else {
            json!([[project], false, false, false, file])
        };
        let scope = identity(&scope_parts).unwrap();
        let state = t.path().join("state");
        let mut store = Store::open(&state).unwrap();
        let p: Package = serde_json::from_value(
            json!({"name":"prior","version":"1","ecosystem":"npm","path":file,"scope":"runtime"}),
        )
        .unwrap();
        store.reconcile(&[json!({"key":"prior","asset":asset(&p).unwrap(),"scan_scope":scope,"package":p,"title":"prior"}).as_object().unwrap().clone()],&BTreeSet::new(),&[]).unwrap();
        drop(store);
        std::fs::write(
            &file,
            if mode == "syft" {
                json!({"artifacts":[]})
            } else {
                json!({"status":mode,"observed":now(),"packages":[]})
            }
            .to_string(),
        )
        .unwrap();
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vorda"));
        command.env("VORDA_ADVISORIES", "online");
        command
            .arg("--state")
            .arg(&state)
            .args(["scan", "--json"])
            .arg("--root")
            .arg(&project);
        command
            .arg(if mode == "syft" {
                "--installed-root"
            } else {
                "--inventory-file"
            })
            .arg(&file);
        let output = command.output().unwrap();
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            output.status.code(),
            Some(if mode == "complete" { 0 } else { 2 }),
            "{mode}: {result}"
        );
        let store = Store::open(&state).unwrap();
        assert_eq!(
            store.active().unwrap().iter().any(|f| f["key"] == "prior"),
            mode != "complete",
            "{mode}"
        );
    }
}

#[test]
fn complete_import_closes_only_its_own_lists_findings_at_a_shared_path() {
    let t = tempfile::tempdir().unwrap();
    let project = t.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let path = t.path().join("app").join("requirements.txt");
    let (list_a, list_b) = (t.path().join("a.json"), t.path().join("b.json"));
    let old: Package = serde_json::from_value(json!({"name":"old-example","version":"1.0","ecosystem":"PyPI","path":path,"scope":"runtime"})).unwrap();
    let mut other = old.clone();
    other.name = "other-example".into();
    let mut store = Store::open(&t.path().join("state")).unwrap();
    let scope_b = identity(&json!([[&project], false, false, false, list_b])).unwrap();
    store.reconcile(&[json!({"key":"prior","asset":asset(&old).unwrap(),"scan_scope":scope_b,"package":old,"title":"prior"}).as_object().unwrap().clone()], &BTreeSet::new(), &[]).unwrap();
    let cache = store.root.join("cache");
    std::fs::create_dir(&cache).unwrap();
    for (url, body, data) in [
        (
            vorda::scanner::feeds::KEV,
            json!(null),
            json!({"vulnerabilities":[]}),
        ),
        (
            "https://api.osv.dev/v1/querybatch",
            json!({"queries":[{"package":{"name":"other-example","ecosystem":"PyPI"},"version":"1.0"}]}),
            json!({"results":[{}]}),
        ),
    ] {
        std::fs::write(
            cache.join(format!("{}.json", identity(&json!([url, body])).unwrap())),
            json!({"source_url":url,"checked":now(),"data":data}).to_string(),
        )
        .unwrap();
    }
    for (file, closed) in [(&list_a, false), (&list_b, true)] {
        std::fs::write(
            file,
            json!({"status":"complete","observed":now(),"packages":[other]}).to_string(),
        )
        .unwrap();
        let mut options = ScanOptions::default();
        options.inventory.roots = vec![project.clone()];
        options.inventory_file = Some(file.clone());
        cli::check(&options, &mut store).unwrap();
        assert_eq!(
            store.active().unwrap().iter().any(|f| f["key"] == "prior"),
            !closed,
            "{}",
            file.display()
        );
    }
}
