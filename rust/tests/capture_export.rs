use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};
use vorda::{
    snapshot::read,
    store::{
        capture::{self, full_grant},
        Store,
    },
};
const L1: &str = include_str!("fixtures/capture/L1.json");
const L2: &str = include_str!("fixtures/capture/L2.json");
const L3: &str = include_str!("fixtures/capture/L3.json");
struct Lane {
    tmp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
}
impl Lane {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let state = tmp.path().join("state");
        fs::create_dir(&root).unwrap();
        let lane = Self { tmp, root, state };
        lane.put("one", L1);
        lane.put("two", L1);
        lane.put("three", L3);
        lane
    }
    fn put(&self, dir: &str, bytes: &str) {
        fs::create_dir_all(self.root.join(dir)).unwrap();
        fs::write(self.root.join(dir).join("package-lock.json"), bytes).unwrap();
    }
    fn request(&self, token: &str, inputs: &[&str]) -> Value {
        json!({"token":token,"binding":{"tenant":"t","site":"s","device":"dev-a","generation":"gen-1","scope":"scope-a","source":"npm-a"},"root":self.root,"inputs":inputs.iter().map(|s|format!("{s}/package-lock.json")).collect::<Vec<_>>(),"observed_at":"1793898285.4219873","completed_at":"1793898285.5764945"})
    }
    fn run(&self, request: &Value) -> std::process::Output {
        let path = self.tmp.path().join("request.json");
        fs::write(&path, request.to_string()).unwrap();
        Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(&self.state)
            .arg("capture")
            .arg(path)
            .output()
            .unwrap()
    }
    fn cap(&self, request: &Value) -> Value {
        let out = self.run(request);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    fn export(&self, outcome: &Value) -> Vec<u8> {
        let path = self.tmp.path().join("export.json");
        let result = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(&self.state)
            .arg("capture-export")
            .arg(outcome["snapshot_id"].as_str().unwrap())
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::read(path).unwrap()
    }
    fn db(&self) -> Connection {
        Connection::open(self.state.join("mail.db")).unwrap()
    }
}
fn response(bytes: &[u8], query: Value) -> Value {
    let v: Value = serde_json::from_slice(bytes).unwrap();
    serde_json::to_value(
        read(
            bytes,
            full_grant(&v).to_string().as_bytes(),
            query.to_string().as_bytes(),
            "1793898330",
        )
        .unwrap(),
    )
    .unwrap()
}
fn snapshot(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
fn named<'a>(v: &'a Value, name: &str, version: &str) -> Vec<&'a Value> {
    v["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["package"]["name"] == name && r["package"]["version"] == version)
        .collect()
}
fn baseline(l: &Lane) -> (Value, Vec<u8>) {
    let out = l.cap(&l.request("cap1", &["one", "two", "three"]));
    let bytes = l.export(&out);
    (out, bytes)
}
fn assert_old_time(bytes: &[u8], id: &Value) {
    let detail = response(bytes, json!({"op":"detail","id":id}));
    assert_eq!(detail["observed_at"]["value"], "1793898285.4219873");
    assert_eq!(detail["age_seconds"], "44.5780127");
}
fn partial(l: &Lane) -> Value {
    fs::remove_file(l.root.join("two/package-lock.json")).unwrap();
    let mut r = l.request("cap2", &["one", "two"]);
    r["observed_at"] = json!("1793898300.125");
    r["completed_at"] = json!("1793898300.5");
    r["provider"] = json!({"name":"osv","request":"synthetic-request-A2","status":"unavailable","checked_at":"1793898300.25","response_utf8":include_str!("fixtures/capture/P2.json")});
    r
}
#[test]
fn cases_1_to_4_persist_reopen_partial_version_and_scope() {
    let l = Lane::new();
    let (a1, b1) = baseline(&l);
    let s1 = snapshot(&b1);
    let count = response(&b1, json!({"op":"count"}));
    assert_eq!(
        count["counts"],
        json!({"records":3,"components":3,"packages":2,"devices":1,"evidence":1})
    );
    let filtered = response(
        &b1,
        json!({"op":"list","package":{"ecosystem":"npm","name":"samepackage"}}),
    );
    assert_eq!(filtered["counts"]["records"], 2);
    for r in s1["records"].as_array().unwrap() {
        assert_old_time(&b1, &r["record_id"]);
    }
    let e = &s1["evidence"][0];
    assert_ne!(
        e["source_sha256"],
        "b9125d1f026724b245f2250c4ec13a005acf8b5941cbe028ac16d28ace7dd9c4"
    );
    assert_eq!(l.export(&a1), b1);
    let mut b = l.request("scope-b-cap", &["one", "two", "three"]);
    b["binding"]["scope"] = json!("scope-b");
    b["binding"]["source"] = json!("npm-b");
    let sb = l.cap(&b);
    let bb = l.export(&sb);
    let request = partial(&l);
    let a2 = l.cap(&request);
    assert_eq!(a2["revision"], 2);
    let b2 = l.export(&a2);
    let s2 = snapshot(&b2);
    assert_eq!(l.export(&a1), b1);
    assert_eq!(l.export(&sb), bb);
    assert_eq!(
        response(&b2, json!({"op":"count"}))["counts"],
        json!({"records":3,"components":3,"packages":2,"devices":1,"evidence":2})
    );
    let retained: Vec<_> = s2["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["assessment_id"] == a1["assessment_id"])
        .collect();
    assert_eq!(retained.len(), 2);
    for r in retained {
        assert_old_time(&b2, &r["record_id"]);
        assert!(s1["records"].as_array().unwrap().contains(r));
    }
    let fresh = s2["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["assessment_id"] == a2["assessment_id"])
        .unwrap();
    assert_eq!(
        response(&b2, json!({"op":"detail","id":fresh["record_id"]}))["age_seconds"],
        "29.875"
    );
    assert_eq!(l.cap(&request), a2);
    let mut conflict = request.clone();
    conflict["completed_at"] = json!("1793898300.6");
    assert!(!l.run(&conflict).status.success());
    l.put("one", L2);
    let mut r = l.request("cap3", &["one"]);
    r["observed_at"] = json!("1793898310.125");
    r["completed_at"] = json!("1793898310.5");
    let a3 = l.cap(&r);
    assert_eq!(a3["revision"], 3);
    let b3 = l.export(&a3);
    let s3 = snapshot(&b3);
    let changed = named(&s3, "samepackage", "2.0.0")[0];
    assert_eq!(changed["component_id"], fresh["component_id"]);
    assert_eq!(changed["location_ref"], fresh["location_ref"]);
    assert_ne!(changed["record_id"], fresh["record_id"]);
    assert_eq!(
        response(&b3, json!({"op":"detail","id":changed["record_id"]}))["age_seconds"],
        "19.875"
    );
    assert_eq!(
        response(&b3, json!({"op":"count"}))["counts"]["packages"],
        3
    );
    assert!(read(
        &b2,
        full_grant(&s1).to_string().as_bytes(),
        br#"{"op":"list"}"#,
        "1793898330"
    )
    .is_err());
    l.put("moved", L2);
    let moved = l.cap(&l.request("moved", &["moved"]));
    let sm = snapshot(&l.export(&moved));
    let moved_record = sm["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["assessment_id"] == moved["assessment_id"])
        .unwrap();
    assert_ne!(moved_record["component_id"], changed["component_id"]);
    println!("PASS cases1-4 including scope-b, replay/conflict, delayed export and moved location");
}
#[test]
fn case_5_legacy_nulls_and_binding_refusal() {
    let l = Lane::new();
    let mut r = l.request("legacy", &["one"]);
    r["legacy_import"] = json!(true);
    r["observed_at"] = Value::Null;
    r["completed_at"] = Value::Null;
    let out = l.cap(&r);
    let bytes = l.export(&out);
    let s = snapshot(&bytes);
    let row = &s["records"][0];
    let d = response(&bytes, json!({"op":"detail","id":row["record_id"]}));
    assert_eq!(d["age_seconds"], Value::Null);
    assert_eq!(d["freshness"], "unknown");
    assert_eq!(
        row["times"]["observed_at"],
        json!({"value":null,"null_reason":"legacy_observation_time_unavailable"})
    );
    for k in [
        "assessment_completed_at",
        "advisory_checked_at",
        "received_at",
    ] {
        assert_eq!(
            row["times"][k],
            json!({"value":null,"null_reason":"producer_time_unavailable"})
        );
    }
    assert_eq!(row["coverage"]["inventory"]["state"], "unknown");
    r["binding"].as_object_mut().unwrap().remove("generation");
    assert!(!l.run(&r).status.success());
    println!("PASS case5");
}
#[test]
fn case_6_atomic_failure_retry_and_postcommit_export() {
    let l = Lane::new();
    let (a1, b1) = baseline(&l);
    let r = partial(&l);
    l.db().execute_batch("CREATE TRIGGER fail_capture BEFORE INSERT ON capture_attempts WHEN NEW.token='cap2' BEGIN SELECT RAISE(ABORT,'injected_storage_failure'); END").unwrap();
    assert!(!l.run(&r).status.success());
    assert_eq!(l.export(&a1), b1);
    assert_eq!(
        l.db()
            .query_row("SELECT count(*) FROM capture_artifacts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    l.db().execute_batch("DROP TRIGGER fail_capture").unwrap();
    let out = l.cap(&r);
    assert_eq!(out["revision"], 2);
    let b2 = l.export(&out);
    assert_eq!(l.cap(&r), out);
    assert_eq!(l.export(&out), b2);
    assert_eq!(l.export(&a1), b1);
    let dest = l.tmp.path().join("blocked");
    fs::create_dir(&dest).unwrap();
    assert!(capture::export(
        &mut Store::open(&l.state).unwrap(),
        out["snapshot_id"].as_str().unwrap(),
        &dest
    )
    .is_err());
    assert_eq!(l.export(&out), b2);
    println!("PASS case6");
}
#[test]
fn case_7_v1_pending_and_ack_invariants() {
    let l = Lane::new();
    fs::create_dir_all(&l.state).unwrap();
    let path = l.state.join("outbox.db");
    let outbox = vorda::link::client::Outbox::open(&path).unwrap();
    outbox.bind("dev-a", "gen-1").unwrap();
    let db = Connection::open(&path).unwrap();
    let raw = include_bytes!("fixtures/capture/V1.json");
    db.execute(
        "INSERT INTO pending(sequence,payload,attempts,due) VALUES(7,?,2,1793898400)",
        [raw.as_slice()],
    )
    .unwrap();
    db.execute("UPDATE identity SET sequence=7", []).unwrap();
    let batch: Value = serde_json::from_slice(raw).unwrap();
    let digest = vorda::link::digest(&batch).unwrap();
    for _ in 0..2 {
        let (a1, _) = baseline(&l);
        l.export(&a1);
        let row: (Vec<u8>, i64, f64) = db
            .query_row(
                "SELECT payload,attempts,due FROM pending WHERE sequence=7",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (raw.to_vec(), 2, 1793898400.0));
        assert_eq!(outbox.identity().unwrap().unwrap()["sequence"], 7);
        let ack = json!({"device":"dev-a","generation":"gen-1","sequence":7,"digest":digest});
        vorda::link::client::validate_ack(&batch, &ack).unwrap();
        for (k, v) in [
            ("digest", json!("0".repeat(64))),
            ("sequence", json!(8)),
            ("generation", json!("gen-2")),
        ] {
            let mut bad = ack.clone();
            bad[k] = v;
            assert!(vorda::link::client::validate_ack(&batch, &bad).is_err());
        }
    }
    println!("PASS case7");
}
#[test]
fn cases_8_and_10_durable_unsuccessful_attempts_and_strict_grammar() {
    let l = Lane::new();
    let (a1, b1) = baseline(&l);
    for (name, bytes, error) in [
        (
            "empty",
            include_str!("fixtures/capture/empty.json"),
            "unsupported_empty_input",
        ),
        (
            "duplicate",
            r#"{"lockfileVersion":3,"packages":{"node_modules/samepackage":{"version":"1","version":"2"}}}"#,
            "duplicate_input_key",
        ),
    ] {
        l.put("bad", bytes);
        let r = l.request(name, &["one", "bad"]);
        let out = l.cap(&r);
        assert_eq!(out["status"], "unsuccessful");
        assert!(out.to_string().contains(error), "{out}");
        assert_eq!(l.cap(&r), out);
        let fetched = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(&l.state)
            .args(["capture-attempt", name])
            .output()
            .unwrap();
        assert!(fetched.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&fetched.stdout).unwrap(),
            out
        );
        assert_eq!(l.export(&a1), b1);
    }
    let out = l.cap(&l.request("missing", &["absent"]));
    assert_eq!(out["status"], "unsuccessful");
    assert_eq!(out["coverage"], "partial");
    assert_eq!(l.export(&a1), b1);
    let mut traversal = l.request("traversal", &["one"]);
    traversal["inputs"] = json!(["../one/package-lock.json"]);
    assert!(!l.run(&traversal).status.success());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(l.root.join("one"), l.root.join("linked")).unwrap();
        let out = l.cap(&l.request("symlink", &["linked"]));
        assert_eq!(out["status"], "unsuccessful");
    }
    l.put(
        "one",
        include_str!("fixtures/capture/optional-control.json"),
    );
    let out = l.cap(&l.request("optional", &["one"]));
    assert_eq!(out["revision"], 2);
    let v = snapshot(&l.export(&out));
    let raw = v["retained_payload_utf8"]
        .as_object()
        .unwrap()
        .values()
        .find(|v| v.as_str().unwrap().contains("optional"))
        .unwrap();
    let artifact: Value = serde_json::from_str(raw.as_str().unwrap()).unwrap();
    assert_ne!(
        artifact["inputs"][0]["sha256"],
        "b9125d1f026724b245f2250c4ec13a005acf8b5941cbe028ac16d28ace7dd9c4"
    );
    println!("PASS cases8/10 including mixed unsupported, zero fresh, duplicate/traversal/symlink, optional digest");
}
/// A number is not a valid value for any capture request field. Whatever its spelling it is refused
/// with the one fixed code, writes nothing, and never reaches the stored data as a number object.
#[test]
fn numbers_in_request_fields_are_refused_cleanly_with_a_fixed_code() {
    let l = Lane::new();
    let (a1, b1) = baseline(&l);
    let paths = [
        "token",
        "observed_at",
        "legacy_import",
        "binding/tenant",
        "inputs/0",
        "extra",
    ];
    for number in ["1.5", "1e2", "-0", "18446744073709551616", "7"] {
        for path in paths {
            let mut r = l.request("numeric", &["one"]);
            let marker = json!("@@number@@");
            match path.split_once('/') {
                Some(("inputs", _)) => r["inputs"][0] = marker,
                Some((a, b)) => r[a][b] = marker,
                None => r[path] = marker,
            }
            let file = l.tmp.path().join("raw-request.json");
            fs::write(&file, r.to_string().replace("\"@@number@@\"", number)).unwrap();
            let out = Command::new(env!("CARGO_BIN_EXE_vorda"))
                .arg("--state")
                .arg(&l.state)
                .arg("capture")
                .arg(&file)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "{path}={number} was accepted");
            assert!(
                stderr.contains("invalid_number"),
                "{path}={number}: {stderr}"
            );
            assert!(
                !stderr.contains("panicked") && !stderr.contains("private"),
                "{stderr}"
            );
        }
    }
    assert_eq!(l.export(&a1), b1, "a refused request wrote nothing");
}

/// Numbers inside a lockfile are not capture request fields: valid integers and fractions there stay readable.
#[test]
fn numbers_inside_a_lockfile_are_still_captured() {
    let l = Lane::new();
    l.put(
        "one",
        r#"{"lockfileVersion":3,"extra":[1,1.5,1e2,-0,18446744073709551616],"packages":{"node_modules/synthetic-pkg":{"version":"1.0.0"}}}"#,
    );
    let out = l.cap(&l.request("lockfile-numbers", &["one"]));
    assert_eq!(out["status"], "committed", "{out}");
    let v = snapshot(&l.export(&out));
    let rows = v["records"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{v}");
    assert!(rows[0].to_string().contains("synthetic-pkg"), "{v}");
}

/// Ordinary lockfile content the restricted grammar used to refuse is now read like the scanner reads it.
#[test]
fn ordinary_lockfile_fields_and_extra_packages_are_captured() {
    let l = Lane::new();
    let (a1, b1) = baseline(&l);
    for (name, bytes, packages) in [
        ("top", include_str!("fixtures/capture/top-name.json"), 1),
        ("root", include_str!("fixtures/capture/root-name.json"), 1),
        (
            "resolved",
            include_str!("fixtures/capture/resolved.json"),
            1,
        ),
        (
            "integrity",
            include_str!("fixtures/capture/integrity.json"),
            1,
        ),
        (
            "deps",
            include_str!("fixtures/capture/dependencies.json"),
            1,
        ),
        ("dev", include_str!("fixtures/capture/dev-true.json"), 1),
        (
            "second",
            include_str!("fixtures/capture/second-leaf.json"),
            2,
        ),
        (
            "v2",
            r#"{"lockfileVersion":2,"packages":{"node_modules/samepackage":{"version":"1.0.0"}}}"#,
            1,
        ),
        (
            "linked",
            r#"{"lockfileVersion":3,"packages":{"node_modules/samepackage":{"version":"1.0.0","link":true}}}"#,
            1,
        ),
        (
            "workspace",
            r#"{"lockfileVersion":3,"packages":{"node_modules/samepackage":{"version":"1.0.0","workspaces":[]}}}"#,
            1,
        ),
    ] {
        l.put("bad", bytes);
        let out = l.cap(&l.request(name, &["one", "bad"]));
        assert_eq!(out["status"], "committed", "{name}: {out}");
        let v = snapshot(&l.export(&out));
        // `one`, `two` and `three` hold one row each from the baseline; `bad` adds its own packages.
        let rows = v["records"].as_array().unwrap();
        assert_eq!(rows.len(), 3 + packages, "{name}");
        assert_eq!(l.export(&a1), b1);
    }
}
#[test]
fn case_9_producer_refuses_forged_saved_view() {
    let l = Lane::new();
    let (out, bytes) = baseline(&l);
    let original = snapshot(&bytes);
    for forged in [true, false] {
        let mut v = original.clone();
        if forged {
            v["records"][0]["record_id"] = json!("invented");
        } else {
            v["records"][0]["times"]["observed_at"]["value"] = json!("1793898300.125");
        }
        l.db()
            .execute(
                "UPDATE capture_views SET payload=? WHERE snapshot=?",
                params![v.to_string(), out["snapshot_id"].as_str()],
            )
            .unwrap();
        let result = capture::export(
            &mut Store::open(&l.state).unwrap(),
            out["snapshot_id"].as_str().unwrap(),
            &l.tmp.path().join("forged.json"),
        );
        assert!(result.unwrap_err().to_string().contains(if forged {
            "captured_member_mismatch"
        } else {
            "captured_observation_mismatch"
        }));
        assert!(!l.tmp.path().join("forged.json").exists());
    }
    println!("PASS case9");
}
#[test]
fn revisions_serialize_same_authority() {
    let l = Lane::new();
    baseline(&l);
    let r2 = l.request("concurrent2", &["one"]);
    let r3 = l.request("concurrent3", &["one"]);
    let root = l.state.clone();
    let join = std::thread::spawn(move || {
        capture::capture(&mut Store::open(&root).unwrap(), r2.to_string().as_bytes()).unwrap()
    });
    let b = capture::capture(
        &mut Store::open(&l.state).unwrap(),
        r3.to_string().as_bytes(),
    )
    .unwrap();
    let a = join.join().unwrap();
    let mut revisions = [
        a["revision"].as_u64().unwrap(),
        b["revision"].as_u64().unwrap(),
    ];
    revisions.sort();
    assert_eq!(revisions, [2, 3]);
}
#[test]
fn native_version_replacement_preserves_unselected_rows() {
    let l = Lane::new();
    baseline(&l);
    let db = l.db();
    let prior:(String,f64,i64)=db.query_row("SELECT payload,observed,complete FROM asset_observations WHERE json_extract(payload,'$.record.path') LIKE '%/two/package-lock.json'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    let request = partial(&l);
    l.cap(&request);
    let after:(String,f64,i64)=db.query_row("SELECT payload,observed,complete FROM asset_observations WHERE json_extract(payload,'$.record.path') LIKE '%/two/package-lock.json'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(after, prior);
    l.put("one", L2);
    l.cap(&l.request("version2", &["one"]));
    let versions:Vec<String>=db.prepare("SELECT json_extract(payload,'$.record.version') FROM asset_observations WHERE json_extract(payload,'$.record.path') LIKE '%/one/package-lock.json'").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<Result<_,_>>().unwrap();
    assert_eq!(versions, vec!["2.0.0"]);
}

#[test]
fn remaining_original_refusals_and_v1_across_partial_and_rollback() {
    let l = Lane::new();
    fs::create_dir_all(&l.state).unwrap();
    let pending_path = l.state.join("pending.db");
    let outbox = vorda::link::client::Outbox::open(&pending_path).unwrap();
    outbox.bind("dev-a", "gen-1").unwrap();
    let db = Connection::open(pending_path).unwrap();
    let raw = include_bytes!("fixtures/capture/V1.json");
    db.execute(
        "INSERT INTO pending(sequence,payload,attempts,due) VALUES(7,?,2,1793898400)",
        [raw.as_slice()],
    )
    .unwrap();
    db.execute("UPDATE identity SET sequence=7", []).unwrap();
    let unchanged = || {
        let value: (Vec<u8>, i64, f64) = db
            .query_row(
                "SELECT payload,attempts,due FROM pending WHERE sequence=7",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(value, (raw.to_vec(), 2, 1793898400.0));
        assert_eq!(outbox.identity().unwrap().unwrap()["sequence"], 7);
    };
    let (a1, b1) = baseline(&l);
    unchanged();
    let r = partial(&l);
    l.db().execute_batch("CREATE TRIGGER fail_capture BEFORE INSERT ON capture_attempts WHEN NEW.token='cap2' BEGIN SELECT RAISE(ABORT,'injected_storage_failure'); END").unwrap();
    assert!(!l.run(&r).status.success());
    unchanged();
    assert_eq!(l.export(&a1), b1);
    unchanged();
    l.db().execute_batch("DROP TRIGGER fail_capture").unwrap();
    let a2 = l.cap(&r);
    l.export(&a2);
    unchanged();
    assert_eq!(l.cap(&r), a2);
    unchanged();
    l.put("one", L2);
    let a3 = l.cap(&l.request("cap3", &["one"]));
    l.export(&a3);
    unchanged();
    let mut binding = l.request("source-change", &["one"]);
    binding["binding"]["source"] = json!("different-source");
    assert!(!l.run(&binding).status.success());
    unchanged();
}

#[test]
fn caller_transaction_cannot_publish_uncommitted_capture_or_view() {
    let l = Lane::new();
    let (a1, b1) = baseline(&l);
    let mut store = Store::open(&l.state).unwrap();
    store.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(capture::capture(
        &mut store,
        l.request("nested", &["one"]).to_string().as_bytes()
    )
    .unwrap_err()
    .to_string()
    .contains("capture_requires_outer_transaction"));
    let dest = l.tmp.path().join("uncommitted.json");
    assert!(capture::export(&mut store, a1["snapshot_id"].as_str().unwrap(), &dest).is_err());
    assert!(!dest.exists());
    store.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(l.export(&a1), b1);
}
