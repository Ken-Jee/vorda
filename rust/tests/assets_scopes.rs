use serde_json::{json, Value};
use std::collections::BTreeSet;
use vorda::{
    assets,
    domain::{Package, Record},
    store::{asset, Store},
};

fn package(path: &str, origin: Option<&str>) -> Package {
    let mut extra = Record::new();
    if let Some(origin) = origin {
        extra.insert("origin".into(), json!(origin));
    }
    Package {
        name: "example".into(),
        version: "1".into(),
        ecosystem: "npm".into(),
        path: path.into(),
        scope: "reachable-unknown".into(),
        extra,
    }
}

#[test]
fn selected_scope_and_partial_observations_do_not_invent_healthy_assets() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::open(tmp.path()).unwrap();
    let p = package("/selected/package-lock.json", Some("project"));
    let other = package("/other/package-lock.json", Some("project"));
    let rows = assets::observations(std::slice::from_ref(&p), &[], Some("test-host")).unwrap();
    assets::save(
        &mut store,
        "selected",
        &rows,
        &BTreeSet::from([asset(&p).unwrap()]),
        true,
        Some(100.0),
    )
    .unwrap();
    assets::save(
        &mut store,
        "other",
        &assets::observations(&[other], &[], Some("test-host")).unwrap(),
        &BTreeSet::new(),
        false,
        Some(101.0),
    )
    .unwrap();
    let selected = BTreeSet::from(["selected".into()]);
    let result = assets::summary(&store.db, Some(101.0), Some(&selected)).unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["healthy"], 1);
    assert_eq!(result["items"][0]["evidence"], "selected");
    assets::save(
        &mut store,
        "selected",
        &[],
        &BTreeSet::new(),
        false,
        Some(102.0),
    )
    .unwrap();
    let result = assets::summary(&store.db, Some(102.0), Some(&selected)).unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["healthy"], 0);
    assert_eq!(result["needs_review"], 1);
    assets::save(
        &mut store,
        "selected",
        &[],
        &BTreeSet::new(),
        true,
        Some(103.0),
    )
    .unwrap();
    assert_eq!(
        assets::summary(&store.db, Some(103.0), Some(&selected)).unwrap()["total"],
        0
    );
}

#[test]
fn unknown_origin_stale_data_and_unselected_messages_remain_distinct() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::open(tmp.path()).unwrap();
    let p = package("/selected/package-lock.json", None);
    let aliases = BTreeSet::from([asset(&p).unwrap()]);
    let rows = assets::observations(&[p], &[], Some("test-host")).unwrap();
    assets::save(&mut store, "selected", &rows, &aliases, true, Some(0.0)).unwrap();
    let f = json!({"key":"selected","asset":aliases.first().unwrap(),"host":"test-host","scan_scope":"selected","title":"selected finding"}).as_object().unwrap().clone();
    let other = json!({"key":"other","asset":"unrelated","host":"test-host","scan_scope":"other","title":"other finding"}).as_object().unwrap().clone();
    store.reconcile(&[f, other], &BTreeSet::new(), &[]).unwrap();
    let result = assets::summary(
        &store.db,
        Some(200000.0),
        Some(&BTreeSet::from(["selected".into()])),
    )
    .unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["items_scanned"], 0);
    assert_eq!(result["items"][0]["known"], false);
    assert_eq!(result["items"][0]["stale"], true);
    assert_eq!(result["finding_count"], 1);
    assets::restrict(&store.db, &result).unwrap();
    let keys: Vec<String> = store
        .db
        .prepare("SELECT key FROM findings")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(keys, vec!["selected"]);
    let payload: String = store
        .db
        .query_row("SELECT payload FROM messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap()["key"],
        "selected"
    );
    let original: i64 = store
        .db
        .query_row("SELECT count(*) FROM main.findings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(original, 2);
}

#[test]
fn selected_snapshot_keeps_only_attributed_scans_and_relevant_reader_receipts() {
    use vorda::surfaces::dashboard::data::snapshot;
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    for (scope, at) in [("A", 100.0), ("B", 200.0)] {
        let p = package(&format!("/{scope}/package-lock.json"), Some("project"));
        assets::save(
            &mut store,
            scope,
            &assets::observations(std::slice::from_ref(&p), &[], None).unwrap(),
            &BTreeSet::new(),
            false,
            Some(at),
        )
        .unwrap();
        let f=json!({"key":scope,"asset":asset(&p).unwrap(),"scan_scope":scope,"title":scope,"package":p}).as_object().unwrap().clone();
        let mut all = store.active().unwrap();
        all.push(f);
        store.reconcile(&all, &BTreeSet::new(), &[]).unwrap();
    }
    store.mail("reader", "read", &0.into(), &0.into()).unwrap();
    store.mail("reader", "ack", &1.into(), &0.into()).unwrap();
    store.db.execute_batch("CREATE TABLE scans(host TEXT,started REAL,finished REAL,status TEXT,seconds REAL,findings INTEGER,errors TEXT,scan_scope TEXT);").unwrap();
    let host = vorda::store::hostname().unwrap();
    for (scope, at) in [("A", 100.0), ("B", 200.0)] {
        store
            .db
            .execute(
                "INSERT INTO scans VALUES(?,?,?,'unknown',1,1,'[]',?)",
                rusqlite::params![host, at - 1.0, at, scope],
            )
            .unwrap();
    }
    for scopes in [
        BTreeSet::from(["A".into()]),
        BTreeSet::from(["B".into()]),
        BTreeSet::from(["A".into(), "B".into()]),
        BTreeSet::new(),
        BTreeSet::from(["unknown".into()]),
    ] {
        let result = snapshot(t.path(), 201.0, Some(&scopes)).unwrap();
        assert_eq!(
            result["assets"]["total"].as_u64().unwrap(),
            scopes
                .iter()
                .filter(|s| ["A", "B"].contains(&s.as_str()))
                .count() as u64
        );
        if scopes.contains("A") && !scopes.contains("B") {
            assert_eq!(result["hosts"][0]["last"]["finished"], 100.0);
            assert_eq!(result["readers"][0]["acked"], 1);
            assert!(result["readers"][0]["last_read"].is_null());
        }
        if !scopes.contains("A") && !scopes.contains("B") {
            assert_eq!(result["hosts"], json!([]));
            assert_eq!(result["readers"], json!([]));
        }
    }
}

#[test]
fn completed_source_absence_retires_only_its_absent_metadata() {
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    let p = package("windows-uninstall:HKCU:64/removed", Some("installed"));
    let q = package("windows-uninstall:HKLM:64/retained", Some("installed"));
    assets::save(
        &mut store,
        "selected",
        &assets::observations(&[p, q.clone()], &[], None).unwrap(),
        &BTreeSet::new(),
        false,
        None,
    )
    .unwrap();
    assets::retire_absent_sources(&mut store,"selected",&[q],&[json!({"source":"windows-uninstall","path":"windows-uninstall:HKCU:64","outcome":"complete"})]).unwrap();
    let result =
        assets::summary(&store.db, None, Some(&BTreeSet::from(["selected".into()]))).unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(
        result["items"][0]["record"]["path"],
        "windows-uninstall:HKLM:64/retained"
    );
}
