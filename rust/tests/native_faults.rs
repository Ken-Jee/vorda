//! Crash and fault matrix for the native v2 upgrade and admission (matrix rows P3, P4).
//!
//! A fault point kills a child process (exit 86) at a named step, as a power
//! cut would. The tests then assert what an operator or a retrying sender can observe: the legacy
//! rows, the v1 acknowledgements and the v1 queue are untouched, a rerun finishes the upgrade, and a
//! replayed delivery gets the one acknowledgement the hub stored. Needs the `native-admission-test`
//! feature and a Unix host; synthetic fixtures only.
#![cfg(all(unix, feature = "native-admission-test"))]
mod common;
use common::*;
use rusqlite::{types::ValueRef, Connection};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use vorda::link::{
    client::Outbox,
    native::{self, Admission, TrustedCapture},
};

const FAULT_EXIT: i32 = 86;
const MIGRATION_POINTS: [&str; 6] = [
    "before-backup-verified",
    "after-backup-before-begin",
    "after-first-create",
    "after-all-create",
    "after-version-before-commit",
    "after-commit-before-verification",
];
/// The steps of the schema 2 -> 3 upgrade, in order.
const LOG_POINTS: [&str; 7] = [
    "log-before-backup-verified",
    "log-after-backup-before-begin",
    "log-after-first-create",
    "log-after-all-create",
    "log-after-rows",
    "log-after-version-before-commit",
    "log-after-commit-before-verification",
];
const LEGACY_TABLES: [&str; 8] = [
    "invites",
    "devices",
    "credentials",
    "batches",
    "scans",
    "findings",
    "coverage",
    "audit",
];
const V2_TABLES: [&str; 7] = [
    "v2_authorities",
    "v2_assessments",
    "v2_observations",
    "v2_current",
    "v2_coverage",
    "v2_deliveries",
    "v2_views",
];
const L2: &[u8] = include_bytes!("fixtures/capture/L2.json");
const L3: &[u8] = include_bytes!("fixtures/capture/L3.json");

/// The faults end the process, so each step runs in a child: this same test binary, re-entered at
/// `child_entry` with the query in the environment. (The example binary is not built when a single
/// test target is selected, so it is not relied on here.)
struct Run {
    code: Option<i32>,
    out: Value,
}
fn run(query: Value, fault: Option<&str>) -> Run {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("VORDA_FAULT_QUERY", query.to_string())
        .env_remove("VORDA_NATIVE_FAULT")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    if let Some(point) = fault {
        cmd.env("VORDA_NATIVE_FAULT", point);
    }
    let done = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&done.stdout);
    let out = stdout
        .lines()
        .find_map(|l| l.split_once("RESULT:").map(|(_, r)| r))
        .map_or(Value::Null, |l| serde_json::from_str(l).unwrap());
    Run {
        code: done.status.code(),
        out,
    }
}
#[test]
fn child_entry() {
    let Ok(query) = std::env::var("VORDA_FAULT_QUERY") else {
        return;
    };
    let q: Value = serde_json::from_str(&query).unwrap();
    let path = PathBuf::from(q["path"].as_str().unwrap());
    let result = match q["op"].as_str().unwrap() {
        "migrate" => native::migrate(&path).map(|_| json!(true)),
        "restore" => native::restore(&path).map(|_| json!(true)),
        "migrate-log" => native::migrate_change_log(&path).map(|_| json!(true)),
        "restore-log" => native::restore_change_log(&path).map(|_| json!(true)),
        _ => {
            let captures = q["captures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| TrustedCapture {
                    binding: c["binding"].clone(),
                    evidence_id: c["evidence_id"].as_str().unwrap().into(),
                    artifact_utf8: c["artifact_utf8"].as_str().unwrap().into(),
                })
                .collect();
            Admission::open(&path, captures).and_then(|a| {
                a.admit_at(
                    q["request"].as_str().unwrap().as_bytes(),
                    q["clock"].as_str().unwrap(),
                )
                .map(|b| json!(String::from_utf8(b).unwrap()))
            })
        }
    };
    let line = match result {
        Ok(v) => json!({"ok":v}),
        Err(e) => json!({"error":e.message,"status":e.http_status}),
    };
    println!("RESULT:{line}");
}

fn op(path: &Path, name: &str, fault: Option<&str>) -> Run {
    run(json!({"path":path,"op":name,"captures":[]}), fault)
}

/// Every legacy table, row by row, with the storage type of each value.
fn legacy_rows(path: &Path) -> Value {
    let db = Connection::open(path).unwrap();
    let mut out = serde_json::Map::new();
    for table in LEGACY_TABLES {
        let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let n = statement.column_count();
        let mut rows: Vec<String> = statement
            .query_map([], |r| {
                Ok((0..n)
                    .map(|i| match r.get_ref(i).unwrap() {
                        ValueRef::Null => "null".to_string(),
                        ValueRef::Integer(v) => format!("i{v}"),
                        ValueRef::Real(v) => format!("r{}", v.to_bits()),
                        ValueRef::Text(b) => format!("t{}", hash(b)),
                        ValueRef::Blob(b) => format!("b{}", hash(b)),
                    })
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        rows.sort();
        out.insert(table.to_string(), json!(rows));
    }
    Value::Object(out)
}
fn v2_row_counts(path: &Path) -> Vec<i64> {
    let db = Connection::open(path).unwrap();
    V2_TABLES
        .iter()
        .map(|t| {
            db.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        })
        .collect()
}
fn user_version(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}
/// A schema-1 hub with legacy rows and a v1 sender queue holding sequence 7, not yet upgraded.
struct Legacy {
    w: World,
    outbox: PathBuf,
}
impl Legacy {
    fn new() -> Self {
        let w = world_at(false);
        let outbox = w.tmp.path().join("sender.db");
        let out = Outbox::open(&outbox).unwrap();
        out.bind(&w.a1, "generation-synthetic").unwrap();
        out.database
            .connect()
            .unwrap()
            .execute("UPDATE identity SET sequence=6", [])
            .unwrap();
        let mut batch: Value =
            serde_json::from_str(include_str!("fixtures/capture/V1.json")).unwrap();
        batch["device"] = json!(w.a1);
        batch["generation"] = json!("generation-synthetic");
        assert_eq!(out.enqueue(&batch).unwrap()["sequence"], 7);
        drop(out);
        assert_eq!(user_version(&w.db), 1);
        Self { w, outbox }
    }
    /// What the upgrade must never change: legacy rows and the v1 queue file.
    fn intact_state(&self) -> (Value, Vec<u8>) {
        (legacy_rows(&self.w.db), fs::read(&self.outbox).unwrap())
    }
}

fn assert_upgraded_and_untouched(l: &Legacy, before: &(Value, Vec<u8>), what: &str) {
    assert_eq!(user_version(&l.w.db), 2, "{what}: not upgraded");
    assert_eq!(&l.intact_state(), before, "{what}: legacy state changed");
    assert_eq!(
        v2_row_counts(&l.w.db),
        vec![0; 7],
        "{what}: v2 rows appeared"
    );
}

#[test]
fn an_upgrade_killed_at_any_step_finishes_on_rerun_and_keeps_the_v1_state() {
    for point in MIGRATION_POINTS {
        let l = Legacy::new();
        let before = l.intact_state();

        let killed = op(&l.w.db, "migrate", Some(point));
        assert_eq!(killed.code, Some(FAULT_EXIT), "{point}: fault did not fire");
        assert_eq!(l.intact_state().1, before.1, "{point}: queue changed");

        let rerun = op(&l.w.db, "migrate", None);
        assert_eq!(rerun.out, json!({"ok":true}), "{point}: rerun failed");
        assert_upgraded_and_untouched(&l, &before, point);

        // The finished upgrade serves: a v2 delivery is acknowledged.
        let (b, e, raw, wire) = l.w.v2_request(&delivery(&l.w), 1, L1);
        let adm = Admission::open(
            &l.w.db,
            vec![TrustedCapture {
                binding: b,
                evidence_id: e,
                artifact_utf8: raw,
            }],
        )
        .unwrap();
        let ack: Value =
            serde_json::from_slice(&adm.admit_at(&wire, "1793898320").unwrap()).unwrap();
        assert_eq!(ack["result"], "published", "{point}");
    }
}

#[test]
fn restore_after_a_killed_upgrade_returns_the_v1_hub_or_refuses_without_harm() {
    // (point, error code when restore refuses). Before the backup exists there is nothing to restore
    // from; once the backup and receipt are written but nothing else, restore puts v1 back; a hot
    // journal from an interrupted upgrade transaction is refused for the operator to look at.
    let expected: [(&str, Option<&str>); 6] = [
        ("before-backup-verified", None),
        ("after-backup-before-begin", Some("restored")),
        ("after-first-create", Some("migration_recovery_required")),
        ("after-all-create", Some("migration_recovery_required")),
        (
            "after-version-before-commit",
            Some("migration_recovery_required"),
        ),
        (
            "after-commit-before-verification",
            Some("migration_recovery_required"),
        ),
    ];
    assert_eq!(expected.map(|e| e.0), MIGRATION_POINTS);
    for (point, outcome) in expected {
        let l = Legacy::new();
        let before = l.intact_state();
        assert_eq!(
            op(&l.w.db, "migrate", Some(point)).code,
            Some(FAULT_EXIT),
            "{point}"
        );
        let restored = op(&l.w.db, "restore", None);
        match outcome {
            Some("restored") => {
                assert_eq!(restored.out, json!({"ok":true}), "{point}");
                assert_eq!(user_version(&l.w.db), 1, "{point}: not back on schema 1");
                assert_eq!(
                    l.intact_state(),
                    before,
                    "{point}: restore changed v1 state"
                );
            }
            refused => {
                assert!(
                    restored.out.get("error").is_some(),
                    "{point}: {}",
                    restored.out
                );
                if let Some(code) = refused {
                    assert_eq!(restored.out["error"], code, "{point}");
                }
                assert_eq!(l.intact_state().1, before.1, "{point}: queue changed");
            }
        }
        // Either way the upgrade still completes afterwards and nothing legacy is lost.
        assert_eq!(
            op(&l.w.db, "migrate", None).out,
            json!({"ok":true}),
            "{point}"
        );
        assert_upgraded_and_untouched(&l, &before, point);
    }
}

fn delivery(w: &World) -> Delivery<'_> {
    Delivery {
        device: &w.a1,
        org: ORG,
        site: "site-a",
        scope: "scope-1",
        source: "npm-a",
        observed: Some(vorda::store::now().floor() - 3600.0),
        inputs: &["one"],
    }
}

/// Two revisions of one authority; revision 1 is already published through the library.
struct Published {
    w: World,
    captures: Vec<Value>,
    second: Vec<u8>,
    adm: Admission,
}
fn published() -> Published {
    published_at(false)
}
/// Like `published`, on a hub that has been upgraded to schema 3 when `logged`.
fn published_at(logged: bool) -> Published {
    let w = world();
    if logged {
        native::migrate_change_log(&w.db).unwrap();
    }
    let (b1, e1, raw1, wire1) = w.v2_request(&delivery(&w), 1, L1);
    let (b2, e2, raw2, wire2) = w.v2_request(&delivery(&w), 2, L2);
    let captures = vec![
        json!({"binding":b1,"evidence_id":e1,"artifact_utf8":raw1}),
        json!({"binding":b2,"evidence_id":e2,"artifact_utf8":raw2}),
    ];
    let adm = Admission::open(
        &w.db,
        vec![
            TrustedCapture {
                binding: b1,
                evidence_id: e1,
                artifact_utf8: raw1,
            },
            TrustedCapture {
                binding: b2,
                evidence_id: e2,
                artifact_utf8: raw2,
            },
        ],
    )
    .unwrap();
    let first: Value =
        serde_json::from_slice(&adm.admit_at(&wire1, "1793898320").unwrap()).unwrap();
    assert_eq!(first["result"], "published");
    Published {
        w,
        captures,
        second: wire2,
        adm,
    }
}
impl Published {
    fn send_second(&self, clock: &str, fault: Option<&str>) -> Run {
        run(
            json!({"path":self.w.db,"op":"admit","captures":self.captures,
                "request":String::from_utf8(self.second.clone()).unwrap(),"clock":clock}),
            fault,
        )
    }
    fn view(&self) -> Value {
        let binding = &self.captures[0]["binding"];
        serde_json::from_slice(&self.adm.saved_view(binding).unwrap()).unwrap()
    }
    fn stored_ack(&self) -> Option<Vec<u8>> {
        Connection::open(&self.w.db)
            .unwrap()
            .query_row("SELECT ack FROM v2_deliveries WHERE sequence=2", [], |r| {
                r.get(0)
            })
            .ok()
    }
}

#[test]
fn a_kill_before_commit_leaves_no_trace_and_the_resend_publishes_at_the_new_time() {
    let p = published();
    let view_before = p.view();
    let rows_before = v2_row_counts(&p.w.db);

    let killed = p.send_second("1793898400", Some("before-commit"));
    assert_eq!(killed.code, Some(FAULT_EXIT));
    assert_eq!(p.view(), view_before, "a half-written view is visible");
    assert_eq!(v2_row_counts(&p.w.db), rows_before, "rows were published");
    assert!(p.stored_ack().is_none(), "an ack was stored");

    let resend = p.send_second("1793898500", None);
    let ack: Value = serde_json::from_str(resend.out["ok"].as_str().unwrap()).unwrap();
    assert_eq!(
        (ack["result"].as_str(), ack["revision"].as_i64()),
        (Some("published"), Some(2))
    );
    assert_eq!(
        ack["received_at"], "1793898500",
        "stamped at the successful receipt"
    );
    assert_eq!(p.view()["header"]["snapshot_revision"], 2);
}

#[test]
fn a_kill_after_commit_replays_the_one_stored_ack_and_changes_nothing() {
    let p = published();

    let killed = p.send_second("1793898400", Some("after-commit-before-response"));
    assert_eq!(killed.code, Some(FAULT_EXIT));
    let view_after_kill = p.view();
    assert_eq!(
        view_after_kill["header"]["snapshot_revision"], 2,
        "commit lost"
    );
    let stored = p.stored_ack().expect("the committed delivery has an ack");
    let rows = v2_row_counts(&p.w.db);

    // The sender never saw the response; resending later gets the stored ack, byte for byte,
    // stamped with the original receipt time, not the resend's.
    for later in ["1793898500", "1793899999"] {
        let resend = p.send_second(later, None);
        assert_eq!(
            resend.out["ok"].as_str().unwrap().as_bytes(),
            &stored[..],
            "replay at {later} differs from the stored ack"
        );
    }
    let ack: Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(ack["received_at"], "1793898400");
    assert_eq!(p.view(), view_after_kill);
    assert_eq!(v2_row_counts(&p.w.db), rows);
}

#[test]
fn a_kill_before_commit_on_a_schema_3_hub_leaves_the_log_as_it_was_and_the_resend_extends_it() {
    let p = published_at(true);
    let rows = assert_log_equals_replay(&p.w.db);
    let killed = p.send_second("1793898400", Some("before-commit"));
    assert_eq!(killed.code, Some(FAULT_EXIT));
    assert_eq!(
        assert_log_equals_replay(&p.w.db),
        rows,
        "a log row survived the kill"
    );
    let resend = p.send_second("1793898500", None);
    assert!(resend.out["ok"].is_string(), "{}", resend.out);
    assert_eq!(assert_log_equals_replay(&p.w.db), rows + 1);
}

#[test]
fn a_kill_after_commit_on_a_schema_3_hub_keeps_the_log_and_a_resend_adds_nothing() {
    let p = published_at(true);
    let rows = assert_log_equals_replay(&p.w.db);
    let killed = p.send_second("1793898400", Some("after-commit-before-response"));
    assert_eq!(killed.code, Some(FAULT_EXIT));
    assert_eq!(assert_log_equals_replay(&p.w.db), rows + 1);
    let resend = p.send_second("1793898500", None);
    assert!(resend.out["ok"].is_string(), "{}", resend.out);
    assert_eq!(assert_log_equals_replay(&p.w.db), rows + 1);
}

/// A schema 2 hub with two authorities, one of which also holds a late assessment.
fn two_authorities() -> World {
    let w = world();
    let neighbour = Delivery {
        scope: "scope-2",
        ..delivery(&w)
    };
    for (n, lock) in [L1, L2, L3].into_iter().enumerate() {
        w.deliver_lock(&neighbour, n as i64 + 1, lock).unwrap();
    }
    let one = delivery(&w);
    let requests = [
        w.v2_request(&one, 1, L1),
        w.v2_request(&one, 3, L2),
        w.v2_request(&one, 2, L3),
    ];
    for i in [0, 2, 1] {
        let (binding, evidence, raw, wire) = &requests[i];
        Admission::open(
            &w.db,
            vec![TrustedCapture {
                binding: binding.clone(),
                evidence_id: evidence.clone(),
                artifact_utf8: raw.clone(),
            }],
        )
        .unwrap()
        .admit(wire)
        .unwrap();
    }
    w
}

#[test]
fn a_log_upgrade_killed_at_any_step_finishes_on_rerun_and_keeps_every_schema_2_row() {
    for point in LOG_POINTS {
        let w = two_authorities();
        let before = dump_digest(&w.db);
        let killed = op(&w.db, "migrate-log", Some(point));
        assert_eq!(killed.code, Some(FAULT_EXIT), "{point}: fault did not fire");

        let rerun = op(&w.db, "migrate-log", None);
        assert_eq!(rerun.out, json!({"ok":true}), "{point}: rerun failed");
        assert_eq!(user_version(&w.db), 3, "{point}");
        assert_eq!(assert_log_equals_replay(&w.db), 8, "{point}");
        assert_eq!(
            dump_digest(&w.db),
            before,
            "{point}: a schema 2 row changed"
        );
    }
}

#[test]
fn restore_after_a_killed_log_upgrade_returns_schema_2_or_refuses_without_harm() {
    // Only a kill after the commit leaves a schema 3 hub to restore. Before it the transaction
    // rolled back, the hub is schema 2 and there is no log to drop.
    for point in LOG_POINTS {
        let w = two_authorities();
        let before = dump_digest(&w.db);
        assert_eq!(
            op(&w.db, "migrate-log", Some(point)).code,
            Some(FAULT_EXIT),
            "{point}"
        );
        let restored = op(&w.db, "restore-log", None);
        if point == "log-after-commit-before-verification" {
            assert_eq!(restored.out, json!({"ok":true}), "{point}");
            // An operator archives the backup and receipt of a restored upgrade before the next.
            for suffix in [".v2-backup", ".v3-operation"] {
                fs::remove_file(format!("{}{suffix}", w.db.display())).unwrap();
            }
        } else {
            assert_eq!(restored.out["error"], "unsupported_link_schema", "{point}");
        }
        assert_eq!(user_version(&w.db), 2, "{point}");
        assert_eq!(
            dump_digest(&w.db),
            before,
            "{point}: a schema 2 row changed"
        );

        let rerun = op(&w.db, "migrate-log", None);
        assert_eq!(
            rerun.out,
            json!({"ok":true}),
            "{point}: upgrade after restore"
        );
        assert_eq!(assert_log_equals_replay(&w.db), 8, "{point}");
    }
}

#[test]
fn a_log_restore_killed_at_either_step_finishes_and_keeps_every_schema_2_row() {
    for point in ["log-restore-before-version", "log-restore-after-commit"] {
        let w = two_authorities();
        native::migrate_change_log(&w.db).unwrap();
        let before = dump_digest(&w.db);
        assert_eq!(
            op(&w.db, "restore-log", Some(point)).code,
            Some(FAULT_EXIT),
            "{point}"
        );
        let rerun = op(&w.db, "restore-log", None);
        if point == "log-restore-before-version" {
            assert_eq!(rerun.out, json!({"ok":true}), "{point}");
        } else {
            assert_eq!(rerun.out["error"], "unsupported_link_schema", "{point}");
        }
        assert_eq!(user_version(&w.db), 2, "{point}");
        assert_eq!(
            dump_digest(&w.db),
            before,
            "{point}: a schema 2 row changed"
        );
        let tables: i64 = Connection::open(&w.db)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'v2\\_change%' ESCAPE '\\'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "{point}");
    }
}
