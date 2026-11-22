use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, Write},
    process::{Command, Stdio},
    time::Duration,
};
use vorda::store::{self, Store};
fn finding(key: &str, scope: &str, text: String) -> vorda::domain::Record {
    json!({"key":key,"asset":key,"title":text,"scan_scope":scope})
        .as_object()
        .unwrap()
        .clone()
}
#[test]
fn pressure_refuses_growth_without_deleting_unresolved_evidence_or_scope_checkpoints() {
    let t = tempfile::tempdir().unwrap();
    let mut s = Store::open(t.path()).unwrap();
    s.reconcile(
        &[finding("a", "A", "evidence".into())],
        &BTreeSet::new(),
        &["webhook".into()],
    )
    .unwrap();
    for scope in ["A", "B"] {
        s.persist_assessment(scope, &json!({"scope":scope}))
            .unwrap();
    }
    fs::create_dir(t.path().join("cache")).unwrap();
    fs::write(t.path().join("cache/data"), [0; 1024]).unwrap();
    for category in ["drafts", "evidence"] {
        fs::create_dir(t.path().join(category)).unwrap();
        fs::write(t.path().join(category).join("retained"), [1; 1024]).unwrap();
    }
    let before = store::storage_report(t.path()).unwrap();
    assert_eq!(before["categories"]["cache"], 1024);
    assert_eq!(before["categories"]["drafts"], 1024);
    assert_eq!(before["categories"]["evidence"], 1024);
    fs::write(
        t.path().join("storage-policy.json"),
        json!({"max_bytes": before["bytes"].as_u64().unwrap()+100,"max_file_bytes":64}).to_string(),
    )
    .unwrap();
    let retained = fs::read(t.path().join("cache/data")).unwrap();
    assert!(store::storage_admit(t.path(), 1024).is_err());
    assert!(store::atomic(&t.path().join("evidence"), &"x".repeat(65)).is_err());
    assert!(s
        .reconcile(&[finding("b", "B", "new".into())], &BTreeSet::new(), &[])
        .is_err());
    assert_eq!(s.active().unwrap()[0]["key"], "a");
    assert_eq!(
        s.db.query_row("SELECT COUNT(*) FROM outbox WHERE delivered=0", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        1
    );
    for category in ["drafts", "evidence"] {
        assert_eq!(
            fs::read(t.path().join(category).join("retained")).unwrap(),
            vec![1; 1024]
        );
    }
    assert_eq!(
        s.db.query_row("SELECT COUNT(*) FROM assessment_checkpoints", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(fs::read(t.path().join("cache/data")).unwrap(), retained);
    drop(s);
    assert_eq!(Store::open(t.path()).unwrap().active().unwrap().len(), 1);
    let response = vorda::surfaces::mcp::call(
        t.path(),
        &json!({"method":"tools/call","params":{"name":"storage","arguments":{}}}),
        None,
        None,
    )
    .unwrap();
    let report: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(report["dry_run"], true);
}
#[test]
fn attention_bounds_candidate_work_and_full_escaped_envelope() {
    let t = tempfile::tempdir().unwrap();
    let mut s = Store::open(t.path()).unwrap();
    let findings = (0..600)
        .map(|i| finding(&format!("b{i}"), "B", "irrelevant".into()))
        .chain([
            finding("target", "A", "quoted \" ".repeat(100_000)),
            finding("target2", "A", "quoted \" ".repeat(100_000)),
        ])
        .collect::<Vec<_>>();
    s.reconcile(&findings, &BTreeSet::new(), &[]).unwrap();
    let first = s.attention("r", "current", Some("A"), 0, 100).unwrap();
    assert_eq!(first["items"], json!([]));
    assert_eq!(first["examined"], 512);
    assert_eq!(first["next_cursor"], 512);
    let req = json!({"method":"tools/call","params":{"name":"attention","arguments":{"reader":"r","mode":"current","scope":"A","after":512,"limit":100}}});
    let response = vorda::surfaces::mcp::call(t.path(), &req, None, None).unwrap();
    assert!(serde_json::to_vec(&response).unwrap().len() <= 2_000_000);
    let data: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(data["items"].as_array().unwrap().len(), 1);
    assert_eq!(data["items"][0]["key"], "target");
    let next = s
        .attention(
            "r",
            "current",
            Some("A"),
            data["next_cursor"].as_i64().unwrap(),
            100,
        )
        .unwrap();
    assert_eq!(next["items"][0]["key"], "target2");
}
#[test]
fn crash_child() {
    let Ok(root) = std::env::var("VORDA_TEST_CRASH_ROOT") else {
        return;
    };
    let mut s = Store::open(std::path::Path::new(&root)).unwrap();
    s.db.execute_batch("SAVEPOINT assessment").unwrap();
    s.reconcile(
        &[finding("durable", "A", "retained".into())],
        &BTreeSet::new(),
        &[],
    )
    .unwrap();
    s.persist_assessment("A", &json!({"checkpoint":"durable"}))
        .unwrap();
    if std::env::var("VORDA_TEST_COMMIT").unwrap() == "yes" {
        s.db.execute_batch("RELEASE assessment").unwrap();
    }
    println!("CRASH_READY");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(20));
    panic!("parent did not terminate child");
}
#[test]
fn killed_publication_recovers_commit_and_rolls_back_uncommitted_state() {
    for commit in ["yes", "no"] {
        let t = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--nocapture"])
            .env("VORDA_TEST_CRASH_ROOT", t.path())
            .env("VORDA_TEST_COMMIT", commit)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if line.unwrap().contains("CRASH_READY") {
                    let _ = send.send(());
                    break;
                }
            }
        });
        let ready = receive.recv_timeout(Duration::from_secs(10));
        child.kill().unwrap();
        child.wait().unwrap();
        reader.join().unwrap();
        ready.unwrap();
        let s = Store::open(t.path()).unwrap();
        assert_eq!(
            s.active().unwrap().len(),
            if commit == "yes" { 1 } else { 0 }
        );
        if commit == "yes" {
            let last: Value =
                serde_json::from_slice(&fs::read(t.path().join("last-scan.json")).unwrap())
                    .unwrap();
            assert_eq!(last["checkpoint"], "durable");
            assert!(fs::read_to_string(t.path().join("inbox.jsonl"))
                .unwrap()
                .contains("durable"));
        } else {
            assert!(!t.path().join("last-scan.json").exists());
        }
    }
}

#[test]
fn matching_generation_recovers_missing_last_scan_without_losing_database() {
    let t = tempfile::tempdir().unwrap();
    let mut s = Store::open(t.path()).unwrap();
    s.reconcile(
        &[finding("kept", "A", "evidence".into())],
        &BTreeSet::new(),
        &[],
    )
    .unwrap();
    s.persist_assessment("A", &json!({"scope":"A","checkpoint":"latest"}))
        .unwrap();
    s.recover_exports().unwrap();
    let expected = fs::read(t.path().join("last-scan.json")).unwrap();
    let marker = fs::read(t.path().join("exports-generation")).unwrap();
    drop(s);
    fs::remove_file(t.path().join("last-scan.json")).unwrap();
    let s = Store::open(t.path()).unwrap();
    assert_eq!(s.active().unwrap()[0]["key"], "kept");
    assert_eq!(fs::read(t.path().join("last-scan.json")).unwrap(), expected);
    assert_eq!(
        fs::read(t.path().join("exports-generation")).unwrap(),
        marker
    );
}

#[test]
fn oversized_legacy_database_migrates_and_reopens_without_pruning() {
    let t = tempfile::tempdir().unwrap();
    let mut s = Store::open(t.path()).unwrap();
    s.reconcile(
        &[finding("kept", "A", "evidence".into())],
        &BTreeSet::new(),
        &["webhook".into()],
    )
    .unwrap();
    s.mail("reader", "ack", &1.into(), &0.into()).unwrap();
    s.persist_assessment("A", &json!({"checkpoint":"retained"}))
        .unwrap();
    s.db.pragma_update(None, "max_page_count", 1000000).unwrap();
    s.db.execute_batch("CREATE TABLE retained_history(payload BLOB); INSERT INTO retained_history VALUES(zeroblob(269484032)); PRAGMA wal_checkpoint(TRUNCATE); DROP INDEX messages_key_id; PRAGMA user_version=2;").unwrap();
    drop(s);
    assert!(fs::metadata(t.path().join("mail.db")).unwrap().len() > 256 * 1024 * 1024);
    for _ in 0..2 {
        let s = Store::open(t.path()).unwrap();
        assert_eq!(s.active().unwrap()[0]["key"], "kept");
        assert_eq!(
            s.attention("reader", "pending", Some("A"), 0, 10).unwrap()["items"],
            json!([])
        );
        for (sql, expected) in [
            ("SELECT length(payload) FROM retained_history", 269484032),
            (
                "SELECT ack FROM receipts WHERE reader='reader' AND message=1",
                1,
            ),
            ("SELECT COUNT(*) FROM outbox WHERE delivered=0", 1),
            (
                "SELECT COUNT(*) FROM assessment_checkpoints WHERE payload LIKE '%retained%'",
                1,
            ),
        ] {
            assert_eq!(
                s.db.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap(),
                expected
            );
        }
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(t.path().join("last-scan.json")).unwrap())
                .unwrap()["checkpoint"],
            "retained"
        );
    }
}
