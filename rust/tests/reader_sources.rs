//! The source dimension of a grant: a reader limited to some collectors sees only the devices and
//! evidence of those sources, and none of the version 1 evidence, which has no source.
//! Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use vorda::{
    fleet::{
        coverage::{fleet_status, visible_devices, visible_sources, FreshnessPolicy, SourceFilter},
        query::{device_detail, visible_findings, DeviceFilter, FindingFilter, PageRequest},
    },
    link::native,
};

const POLICY: FreshnessPolicy = FreshnessPolicy {
    fresh_for_secs: 36 * 3600,
};
fn now() -> f64 {
    vorda::store::now()
}
fn store_path(w: &World) -> String {
    format!("{}.readers", w.db.display())
}
fn devices(w: &World, scope: &vorda::fleet::auth::AuthorizedScope) -> Value {
    visible_devices(
        &w.hub,
        scope,
        &DeviceFilter::default(),
        &PageRequest::default(),
        now(),
    )
    .unwrap()
}
fn findings_total(w: &World, scope: &vorda::fleet::auth::AuthorizedScope) -> Value {
    visible_findings(
        &w.hub,
        scope,
        &FindingFilter::default(),
        &PageRequest::default(),
        now(),
    )
    .unwrap()["total"]
        .clone()
}
fn source_rows(
    w: &World,
    scope: &vorda::fleet::auth::AuthorizedScope,
    filter: &SourceFilter,
) -> i64 {
    visible_sources(
        &w.hub,
        scope,
        filter,
        &POLICY,
        &PageRequest::default(),
        now(),
    )
    .unwrap()["total"]
        .as_i64()
        .unwrap()
}

#[test]
fn a_source_restricted_grant_sees_only_devices_and_evidence_of_its_sources() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    let all = authorize(&w, READER_A).unwrap();
    let narrow = authorize(&w, READER_B).unwrap();

    let mut both = vec![w.a1.clone(), w.a2.clone()];
    both.sort();
    assert_eq!(device_ids(&devices(&w, &all)), both);
    assert_eq!(all.sources(), None);
    assert_eq!(
        devices(&w, &all)["effective_scope"]["sources"],
        "all",
        "an unrestricted grant says so"
    );

    let view = devices(&w, &narrow);
    assert_eq!(
        device_ids(&view),
        vec![w.a1.clone()],
        "only a1 has a pip-a authority"
    );
    assert_eq!(view["total"], 1);
    assert_eq!(view["effective_scope"]["sources"][0], "pip-a");
    // Version 1 evidence has no source, so a source-restricted reader gets none of it.
    assert!(view["devices"][0]["finding_count"].is_null());
    assert!(view["devices"][0]["received"].is_null());
    assert_eq!(
        device_detail(&w.hub, &narrow, &w.a2)
            .unwrap_err()
            .http_status,
        Some(404)
    );
    assert!(device_detail(&w.hub, &narrow, &w.a1).unwrap()["findings"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(findings_total(&w, &narrow), 0);
    assert_eq!(
        findings_total(&w, &all),
        3,
        "the same hub still answers the unrestricted reader"
    );

    // Sources: the grant's sources only, and a filter cannot widen them.
    assert_eq!(source_rows(&w, &narrow, &SourceFilter::default()), 1);
    let ask_npm = SourceFilter {
        sources: vec!["npm-a".into()],
        ..Default::default()
    };
    assert_eq!(source_rows(&w, &narrow, &ask_npm), 0);
    assert_eq!(source_rows(&w, &all, &ask_npm), 2);
    let status = fleet_status(&w.hub, &narrow, &DeviceFilter::default(), &POLICY, now()).unwrap();
    assert_eq!(status["sources"]["total"], 1);

    // A version 1 receipt dated ahead of the clock counts as a check-in only for a reader who may
    // see version 1 evidence.
    rusqlite::Connection::open(&w.db)
        .unwrap()
        .execute(
            "UPDATE devices SET received=? WHERE id=?",
            rusqlite::params![now() + 3600.0, w.a1],
        )
        .unwrap();
    let checkins = |scope| {
        fleet_status(&w.hub, scope, &DeviceFilter::default(), &POLICY, now()).unwrap()["devices"]
            .clone()
    };
    assert_eq!(checkins(&all)["checked_in_clock_ahead"], 1);
    assert_eq!(checkins(&narrow)["checked_in_clock_ahead"], 0);
    assert_eq!(checkins(&narrow)["checked_in_fresh"], 1);
}

#[test]
fn a_grant_for_a_source_the_hub_has_never_seen_in_those_sites_is_refused() {
    let w = world();
    standard_deliveries(&w);
    let listed = ["pip-a".to_string()];
    let refused = try_grant_sources(
        &w,
        READER_A,
        &sites(&[(ORG, "site-b")]),
        None,
        Some(&listed),
        60.0,
    )
    .unwrap_err();
    assert_eq!(
        refused.http_status,
        Some(400),
        "pip-a exists, but not at site-b"
    );
    let none: [String; 0] = [];
    let empty = try_grant_sources(
        &w,
        READER_A,
        &sites(&[(ORG, "site-a")]),
        None,
        Some(&none),
        60.0,
    )
    .unwrap_err();
    assert_eq!(
        empty.http_status,
        Some(400),
        "an empty list is not a wildcard"
    );
}

#[test]
fn the_owner_cli_grants_a_source_restricted_reader() {
    let w = world();
    standard_deliveries(&w);
    let run = |source: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
            .args(["link", "--db", w.db.to_str().unwrap(), "reader-grant"])
            .args([
                "--reader-env",
                "SYNTHETIC_READER",
                "--label",
                "cli",
                "--org",
                ORG,
            ])
            .args(["--site", "site-a", "--source", source, "--ttl", "3600"])
            .env("SYNTHETIC_READER", READER_A)
            .output()
            .unwrap()
    };
    assert!(!run("typo-source").status.success());
    assert!(run("pip-a").status.success());
    let scope = authorize(&w, READER_A).unwrap();
    assert_eq!(device_ids(&devices(&w, &scope)), vec![w.a1.clone()]);
}

#[test]
fn a_source_restricted_reader_on_a_hub_restored_to_version_1_sees_nothing_not_an_error() {
    let w = world();
    standard_deliveries(&w);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    let scope = authorize(&w, READER_B).unwrap();
    assert_eq!(devices(&w, &scope)["total"], 1);

    native::restore(&w.db).unwrap(); // the M2 rollback: the v2 tables are gone
    assert_eq!(devices(&w, &scope)["total"], 0);
    assert_eq!(
        device_detail(&w.hub, &scope, &w.a1)
            .unwrap_err()
            .http_status,
        Some(404)
    );
    assert_eq!(source_rows(&w, &scope, &SourceFilter::default()), 0);
    let status = fleet_status(&w.hub, &scope, &DeviceFilter::default(), &POLICY, now()).unwrap();
    assert_eq!(status["devices"]["enrolled"], 0);
    assert_eq!(findings_total(&w, &scope), 0);
}

#[test]
fn a_source_restricted_grant_that_lost_its_source_rows_sees_nothing_not_every_source() {
    let w = world();
    standard_deliveries(&w);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    assert_eq!(authorize(&w, READER_B).unwrap().sources().unwrap().len(), 1);

    let store = rusqlite::Connection::open(store_path(&w)).unwrap();
    store.execute("DELETE FROM reader_sources", []).unwrap();
    drop(store);

    let scope = authorize(&w, READER_B).unwrap();
    assert!(
        scope.sources().is_some_and(|s| s.is_empty()),
        "a lost row narrows the grant to nothing"
    );
    let view = devices(&w, &scope);
    assert_eq!(view["total"], 0);
    assert_eq!(view["effective_scope"]["sources"], json!([]));
    assert_eq!(findings_total(&w, &scope), 0);
    assert_eq!(source_rows(&w, &scope, &SourceFilter::default()), 0);
}

#[test]
fn a_cursor_dies_when_the_grants_sources_change_though_nothing_it_shows_does() {
    let w = world();
    // Devices without version 1 evidence, so that only the shape of the grant differs afterwards.
    let t = now();
    let (n1, n2) = (
        enroll_without_evidence(&w, "site-n", "n1"),
        enroll_without_evidence(&w, "site-n", "n2"),
    );
    for (device, source) in [(&n1, "npm-a"), (&n2, "pip-a")] {
        let delivery = Delivery {
            device,
            org: ORG,
            site: "site-n",
            scope: "scope-1",
            source,
            observed: Some(t - 60.0),
            inputs: &["one"],
        };
        w.deliver(&delivery, 1).unwrap();
    }
    let reader = grant(&w, READER_A, &["site-n"], &[], 3600.0);
    let walk = |scope, cursor: Option<&str>| {
        visible_sources(
            &w.hub,
            scope,
            &SourceFilter::default(),
            &POLICY,
            &PageRequest {
                limit: Some(1),
                cursor,
            },
            t,
        )
    };
    let all = authorize(&w, READER_A).unwrap();
    let cursor = walk(&all, None).unwrap()["next_cursor"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(walk(&all, Some(&cursor)).is_ok());

    // The store now lists every source that reports at the site: the same devices, sources and
    // evidence, a differently shaped grant.
    let store = rusqlite::Connection::open(store_path(&w)).unwrap();
    store
        .execute(
            "UPDATE readers SET source_mode='listed' WHERE id=?",
            [&reader],
        )
        .unwrap();
    for source in ["npm-a", "pip-a"] {
        store
            .execute(
                "INSERT INTO reader_sources VALUES(?,?)",
                rusqlite::params![reader, source],
            )
            .unwrap();
    }
    drop(store);
    let listed = authorize(&w, READER_A).unwrap();
    assert_eq!(listed.sources().unwrap().len(), 2);
    let invented = walk(&listed, Some("AAAA")).unwrap_err();
    let replayed = walk(&listed, Some(&cursor)).unwrap_err();
    assert_eq!(
        (replayed.http_status, replayed.message),
        (invented.http_status, invented.message)
    );
    assert_eq!(walk(&listed, None).unwrap()["total"], 2);
}

#[test]
fn version_1_ingest_moves_the_revision_only_for_readers_who_may_see_version_1_evidence() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    let (all, narrow) = (
        authorize(&w, READER_A).unwrap(),
        authorize(&w, READER_B).unwrap(),
    );
    let revisions = || {
        [
            devices(&w, &all)["revision"].clone(),
            devices(&w, &narrow)["revision"].clone(),
            fleet_status(&w.hub, &narrow, &DeviceFilter::default(), &POLICY, now()).unwrap()
                ["revision"]
                .clone(),
            visible_sources(
                &w.hub,
                &narrow,
                &SourceFilter::default(),
                &POLICY,
                &PageRequest::default(),
                now(),
            )
            .unwrap()["revision"]
                .clone(),
        ]
    };
    let before = revisions();
    // A version 1 batch lands for a1: its sequence and receipt time move.
    rusqlite::Connection::open(&w.db)
        .unwrap()
        .execute(
            "UPDATE devices SET sequence=sequence+1,received=received+7 WHERE id=?",
            [&w.a1],
        )
        .unwrap();
    let after = revisions();
    assert_ne!(
        before[0], after[0],
        "version 1 evidence is part of its view"
    );
    assert_eq!(
        before[1..],
        after[1..],
        "a source-restricted reader learns nothing of version 1 activity"
    );
}
