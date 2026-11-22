//! The schema 3 change log: written at admission, built and checked by `migrate`, dropped losslessly
//! by `restore`. The oracle is the in-memory replay (`change_log::replayed`): a stored log must equal
//! it row for row. Synthetic fixtures only.
mod common;
use common::*;
use rusqlite::Connection;
use serde_json::Value;
use std::fs;
use vorda::link::{
    change_log::stored,
    native::{self, Admission, TrustedCapture},
};

const L2: &[u8] = include_bytes!("fixtures/capture/L2.json"); // samepackage 2.0.0
const L3: &[u8] = include_bytes!("fixtures/capture/L3.json"); // unaffectedpackage 1.0.0

fn on<'a>(device: &'a str, scope: &'a str) -> Delivery<'a> {
    Delivery {
        device,
        org: ORG,
        site: "site-a",
        scope,
        source: "npm-a",
        observed: Some(vorda::store::now() - 3600.0),
        inputs: &["one"],
    }
}
/// add, upgrade, replace, return: six changes over four assessments.
fn history(w: &World, d: &Delivery) {
    for (n, lock) in [L1, L2, L3, L1].into_iter().enumerate() {
        w.deliver_lock(d, n as i64 + 1, lock).unwrap();
    }
}
fn admit(w: &World, request: &(Value, String, String, Vec<u8>)) -> Value {
    let (binding, evidence, raw, wire) = request;
    let ack = Admission::open(
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
    serde_json::from_slice(&ack).unwrap()
}
fn authority_of(c: &Connection, scope: &str) -> String {
    c.query_row(
        "SELECT authority FROM v2_authorities WHERE json_extract(authority,'$[4]')=?",
        [scope],
        |r| r.get(0),
    )
    .unwrap()
}
fn user_version(db: &std::path::Path) -> i64 {
    native::schema_version(db).unwrap()
}
fn log_tables(db: &std::path::Path) -> i64 {
    Connection::open(db)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'v2\\_change%' ESCAPE '\\'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
/// Two authorities, one with a late assessment: a1/scope-1 gets revisions 1 and 3 and then the late 2.
fn busy(w: &World) {
    history(w, &on(&w.a2, "scope-1"));
    let one = on(&w.a1, "scope-1");
    let first = w.v2_request(&one, 1, L1);
    let second = w.v2_request(&one, 3, L2);
    let third = w.v2_request(&one, 2, L3);
    admit(w, &first);
    admit(w, &third);
    assert_eq!(admit(w, &second)["result"], "historical_only");
}

#[test]
fn every_in_order_admission_extends_the_stored_log_to_equal_the_replay() {
    let w = world_logged();
    let (one, two) = (on(&w.a1, "scope-1"), on(&w.a2, "scope-1"));
    let mut seen = 0;
    for (n, lock) in [L1, L2, L3, L1].into_iter().enumerate() {
        w.deliver_lock(&one, n as i64 + 1, lock).unwrap();
        let rows = assert_log_equals_replay(&w.db);
        assert!(rows > seen, "revision {} added no rows", n + 1);
        seen = rows;
        // A second authority interleaves; neither disturbs the other.
        w.deliver_lock(&two, n as i64 + 1, lock).unwrap();
        let rows = assert_log_equals_replay(&w.db);
        assert!(rows > seen);
        seen = rows;
    }
    let c = Connection::open(&w.db).unwrap();
    let log = stored(&c, &authority_of(&c, "scope-1")).unwrap();
    let kinds: Vec<_> = log.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["added", "changed", "resolved", "added", "resolved", "reopened"]
    );
    assert_eq!(
        log.iter().map(|r| r.ordinal).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5]
    );
    assert_eq!(
        log.iter().map(|r| r.revision).collect::<Vec<_>>(),
        [1, 2, 3, 3, 4, 4]
    );
    assert_eq!(
        log.iter().map(|r| r.previous_revision).collect::<Vec<_>>(),
        [None, Some(1), Some(2), Some(2), Some(3), Some(3)]
    );
    assert!(log.iter().all(|r| !r.late && r.received_real.is_some()));
}

#[test]
fn a_late_assessment_recomputes_only_its_own_authority() {
    let w = world_logged();
    let neighbour = on(&w.a2, "scope-2");
    w.deliver_lock(&neighbour, 1, L1).unwrap();
    w.deliver_lock(&neighbour, 2, L2).unwrap();
    let c = Connection::open(&w.db).unwrap();
    let rows_of = |authority: &str| -> Vec<(i64, i64, Vec<u8>)> {
        c.prepare("SELECT rowid,ordinal,row FROM v2_changes WHERE authority=? ORDER BY ordinal")
            .unwrap()
            .query_map([authority], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let neighbour_rows = rows_of(&authority_of(&c, "scope-2"));
    assert_eq!(neighbour_rows.len(), 2);

    let one = on(&w.a1, "scope-1");
    let first = w.v2_request(&one, 1, L1);
    let second = w.v2_request(&one, 3, L2);
    let third = w.v2_request(&one, 2, L3);
    assert_eq!(admit(&w, &first)["result"], "published");
    assert_eq!(admit(&w, &third)["result"], "published");
    assert_log_equals_replay(&w.db);
    let own = authority_of(&c, "scope-1");
    let before = stored(&c, &own).unwrap();
    assert!(before.iter().all(|r| !r.late && r.revision != 2));

    assert_eq!(admit(&w, &second)["result"], "historical_only");
    assert_log_equals_replay(&w.db);
    let after = stored(&c, &own).unwrap();
    assert_ne!(
        after, before,
        "the late assessment changed this authority's log"
    );
    let late: Vec<_> = after
        .iter()
        .filter(|r| r.late)
        .map(|r| r.revision)
        .collect();
    assert!(!late.is_empty() && late.iter().all(|r| *r == 2), "{late:?}");
    // The assessment after the late one now follows it.
    assert!(after
        .iter()
        .filter(|r| r.revision == 3)
        .all(|r| r.previous_revision == Some(2)));
    assert_eq!(
        rows_of(&authority_of(&c, "scope-2")),
        neighbour_rows,
        "another authority's rows are not rewritten"
    );
}

#[test]
fn migrate_builds_a_log_equal_to_the_replay_and_restore_returns_schema_2_byte_identical() {
    let w = world();
    busy(&w);
    history(&w, &on(&w.a2, "scope-2"));
    let before = dump_digest(&w.db);
    assert_eq!(user_version(&w.db), 2);
    assert_eq!(log_tables(&w.db), 0);

    native::migrate_change_log(&w.db).unwrap();
    assert_eq!(user_version(&w.db), 3);
    assert!(assert_log_equals_replay(&w.db) >= 12);
    assert_eq!(
        dump_digest(&w.db),
        before,
        "the upgrade changed a schema 2 table"
    );
    let side = |suffix: &str| std::path::PathBuf::from(format!("{}{suffix}", w.db.display()));
    assert!(side(".v2-backup").exists() && side(".v3-operation").exists());

    // On an upgraded hub it only verifies.
    let bytes = fs::read(&w.db).unwrap();
    native::migrate_change_log(&w.db).unwrap();
    assert_eq!(fs::read(&w.db).unwrap(), bytes);

    native::restore_change_log(&w.db).unwrap();
    assert_eq!(user_version(&w.db), 2);
    assert_eq!(log_tables(&w.db), 0);
    assert_eq!(
        dump_digest(&w.db),
        before,
        "restore changed a schema 2 table"
    );
    let again = native::restore_change_log(&w.db).unwrap_err();
    assert_eq!(again.message, "unsupported_link_schema");
}

#[test]
fn restore_after_schema_3_admissions_loses_nothing() {
    let w = world_logged();
    history(&w, &on(&w.a1, "scope-1"));
    let digest = dump_digest(&w.db);
    native::restore_change_log(&w.db).unwrap();
    assert_eq!(user_version(&w.db), 2);
    assert_eq!(dump_digest(&w.db), digest, "an admission was lost");
    let count = |sql: &str| -> i64 {
        Connection::open(&w.db)
            .unwrap()
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(count("SELECT count(*) FROM v2_assessments"), 4);
    // The schema 2 hub keeps admitting, with no log to extend.
    w.deliver_lock(&on(&w.a1, "scope-1"), 5, L2).unwrap();
    assert_eq!(count("SELECT count(*) FROM v2_assessments"), 5);
    assert_eq!(log_tables(&w.db), 0);
}

#[test]
fn a_schema_2_hub_keeps_admitting_without_a_log() {
    let w = world();
    history(&w, &on(&w.a1, "scope-1"));
    assert_eq!(user_version(&w.db), 2);
    assert_eq!(log_tables(&w.db), 0);
}

/// Make an authority's stored replay state look like one saved under other rules: drop the version
/// and empty what it holds, so appending from it would write wrong rows.
fn age_state(db: &std::path::Path) {
    let n = Connection::open(db)
        .unwrap()
        .execute(
            "UPDATE v2_change_state SET state=CAST(json_remove(json_set(CAST(state AS TEXT),'$.current',json('{}')),'$.replay_version') AS BLOB)",
            [],
        )
        .unwrap();
    assert!(n > 0);
}

#[test]
fn a_state_saved_under_older_replay_rules_is_rebuilt_at_admission_and_refused_by_verify() {
    let w = world_logged();
    let one = on(&w.a1, "scope-1");
    for (n, lock) in [L1, L2, L3, L1].into_iter().enumerate() {
        w.deliver_lock(&one, n as i64 + 1, lock).unwrap();
    }
    assert_log_equals_replay(&w.db);
    age_state(&w.db);
    let refused = native::verify_change_log(&w.db).unwrap_err();
    assert_eq!(
        (refused.http_status, refused.message.as_str()),
        (Some(503), "change_log_replay_version")
    );
    // The next admission does not append from the old state: it recomputes that authority.
    w.deliver_lock(&one, 5, L2).unwrap();
    assert_log_equals_replay(&w.db);
    let c = Connection::open(&w.db).unwrap();
    assert!(stored(&c, &authority_of(&c, "scope-1")).unwrap().len() > 6);
}

#[test]
fn migrate_refuses_before_writing_when_the_ceiling_cannot_hold_the_log() {
    let w = world();
    busy(&w);
    let bytes = fs::read(&w.db).unwrap();
    let refused =
        native::migrate_change_log_with_limit(&w.db, bytes.len() as u64 + 4096).unwrap_err();
    assert_eq!(
        (refused.http_status, refused.message.as_str()),
        (Some(503), "migration_storage_failure")
    );
    assert_eq!(fs::read(&w.db).unwrap(), bytes, "a refused upgrade wrote");
    for suffix in [".v2-backup", ".v3-operation", "-journal"] {
        assert!(
            !std::path::Path::new(&format!("{}{suffix}", w.db.display())).exists(),
            "{suffix}"
        );
    }
    // A ceiling that holds it succeeds.
    native::migrate_change_log_with_limit(&w.db, bytes.len() as u64 * 4).unwrap();
    assert_eq!(user_version(&w.db), 3);
}

#[test]
fn migrate_refuses_a_hub_that_is_not_at_schema_2() {
    let w = world_at(false);
    let refused = native::migrate_change_log(&w.db).unwrap_err();
    assert_eq!(refused.message, "unsupported_link_schema");
    assert_eq!(user_version(&w.db), 1);
}

#[test]
fn a_full_database_refuses_an_admission_and_keeps_the_log() {
    let w = world_logged();
    let one = on(&w.a1, "scope-1");
    w.deliver_lock(&one, 1, L1).unwrap();
    let digest = dump_digest(&w.db);
    let size = fs::metadata(&w.db).unwrap().len();
    let log_before = assert_log_equals_replay(&w.db);
    let (binding, evidence, raw, wire) = w.v2_request(&one, 2, L2);
    let full = Admission::open_with_limit(
        &w.db,
        vec![TrustedCapture {
            binding,
            evidence_id: evidence,
            artifact_utf8: raw,
        }],
        size,
    )
    .unwrap();
    let refused = full.admit(&wire).unwrap_err();
    assert_eq!(
        (refused.http_status, refused.message.as_str()),
        (Some(503), "storage_failure")
    );
    assert_eq!(dump_digest(&w.db), digest);
    assert_eq!(assert_log_equals_replay(&w.db), log_before);
}

#[test]
fn a_schema_3_hub_opens_for_the_hub_commands() {
    let w = world_logged();
    vorda::link::storage::Hub::open(&w.db).unwrap();
}
