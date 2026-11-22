//! Sources, coverage, freshness and status over the hub's v2 tables, inside a reader grant.
//! Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use vorda::{
    fleet::{
        auth::{AuthorizedScope, ReaderStore},
        coverage::{
            fleet_status as fleet_status_at, visible_devices as visible_devices_at,
            visible_inventory, visible_sources as visible_sources_at, FreshnessPolicy,
            InventoryFilter, SourceFilter,
        },
        history::{fleet_changes, ChangeFilter, Since},
        query::{DeviceFilter, PageRequest},
    },
    link::{
        native::{Admission, TrustedCapture},
        storage::Hub,
    },
};

const POLICY: FreshnessPolicy = FreshnessPolicy {
    fresh_for_secs: 36 * 3600,
};
fn now() -> f64 {
    vorda::store::now()
}
// The same queries at the real clock.
fn visible_sources(
    h: &Hub,
    s: &AuthorizedScope,
    f: &SourceFilter,
    p: &FreshnessPolicy,
    page: &PageRequest,
) -> vorda::Result<Value> {
    visible_sources_at(h, s, f, p, page, now())
}
fn fleet_status(
    h: &Hub,
    s: &AuthorizedScope,
    f: &DeviceFilter,
    p: &FreshnessPolicy,
) -> vorda::Result<Value> {
    fleet_status_at(h, s, f, p, now())
}
fn visible_devices(
    h: &Hub,
    s: &AuthorizedScope,
    f: &DeviceFilter,
    page: &PageRequest,
) -> vorda::Result<Value> {
    visible_devices_at(h, s, f, page, now())
}
fn sources(w: &World, scope: &AuthorizedScope, filter: &SourceFilter) -> Value {
    visible_sources(&w.hub, scope, filter, &POLICY, &PageRequest::default()).unwrap()
}
fn text(v: &Value) -> String {
    v.to_string()
}

fn delivery<'a>(
    device: &'a str,
    org: &'a str,
    site: &'a str,
    scope: &'a str,
    source: &'a str,
    observed: f64,
    inputs: &'a [&'a str],
) -> Delivery<'a> {
    Delivery {
        device,
        org,
        site,
        scope,
        source,
        observed: Some(observed),
        inputs,
    }
}

fn list(view: &Value, field: &str) -> Vec<Value> {
    view[field].as_array().unwrap().clone()
}
/// A request together with the clock a test wants it evaluated at (the requests themselves carry none).
fn page_at(now: f64, cursor: Option<&str>, limit: usize) -> (PageRequest<'_>, f64) {
    (
        PageRequest {
            limit: Some(limit),
            cursor,
        },
        now,
    )
}

fn sources_at(
    h: &Hub,
    s: &AuthorizedScope,
    f: &SourceFilter,
    p: &FreshnessPolicy,
    at: &(PageRequest, f64),
) -> vorda::Result<Value> {
    visible_sources_at(h, s, f, p, &at.0, at.1)
}

#[test]
fn sources_never_cross_sites_organizations_or_devices() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let all = authorize(&w, READER_A).unwrap();

    let view = sources(&w, &all, &SourceFilter::default());
    assert_eq!(
        view["total"], 3,
        "a1 twice and a2 once; not b1, not the other organization's x1"
    );
    let devices: Vec<_> = list(&view, "sources")
        .iter()
        .map(|r| r["device"].as_str().unwrap().to_string())
        .collect();
    assert!(!devices.contains(&w.b1) && !devices.contains(&w.x1));
    for hidden in ["site-b", "org-other", w.b1.as_str(), w.x1.as_str()] {
        assert!(!text(&view).contains(hidden), "{hidden} leaked");
    }

    // Filters only narrow: other sites, devices and sources match nothing, never more.
    let ask = |sites: &[&str], devs: &[&str], srcs: &[&str]| SourceFilter {
        sites: sites.iter().map(|s| s.to_string()).collect(),
        devices: devs.iter().map(|s| s.to_string()).collect(),
        sources: srcs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    for f in [
        ask(&["site-b"], &[], &[]),
        ask(&[], &[&w.b1], &[]),
        ask(&[], &[&w.x1], &[]),
    ] {
        assert_eq!(sources(&w, &all, &f)["total"], 0);
    }
    assert_eq!(
        sources(
            &w,
            &all,
            &ask(&["site-a", "site-b"], &[&w.a1, &w.b1], &["npm-a"])
        )["total"],
        1
    );

    // A device-restricted grant stays inside its device in the v2 tables too.
    grant(&w, READER_B, &["site-a"], &[&w.a2], 60.0);
    let scope = authorize(&w, READER_B).unwrap();
    assert_eq!(sources(&w, &scope, &SourceFilter::default())["total"], 1);
}

#[test]
fn freshness_is_computed_at_query_time_under_a_declared_policy_per_source() {
    let w = world();
    let t = vorda::store::now();
    for (device, scope, observed) in [
        (&w.a1, "fresh-scope", t - 60.0),
        (&w.a1, "stale-scope", t - 5.0 * 86400.0),
        (&w.a2, "future-scope", t + 10.0 * 86400.0),
    ] {
        w.deliver(
            &delivery(device, ORG, "site-a", scope, "npm-a", observed, &["one"]),
            1,
        )
        .unwrap();
    }
    // Site B is stale while site A stays fresh: the grant for A never sees B's staleness either way.
    w.deliver(
        &delivery(
            &w.b1,
            ORG,
            "site-b",
            "stale-scope",
            "npm-a",
            t - 9.0 * 86400.0,
            &["one"],
        ),
        1,
    )
    .unwrap();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let view = sources(&w, &scope, &SourceFilter::default());
    let by_scope = |name: &str| {
        list(&view, "sources")
            .into_iter()
            .find(|r| r["scope"] == name)
            .unwrap()
    };
    assert_eq!(by_scope("fresh-scope")["freshness"], "fresh");
    assert_eq!(by_scope("stale-scope")["freshness"], "stale");
    assert_eq!(
        by_scope("future-scope")["freshness"],
        "future",
        "a future timestamp is never fresh"
    );
    assert_eq!(view["freshness_policy"]["fresh_for_seconds"], 36 * 3600);
    let stale_only = SourceFilter {
        freshness: Some("stale".into()),
        ..Default::default()
    };
    assert_eq!(sources(&w, &scope, &stale_only)["total"], 1);

    // The policy is the caller's, bounded and declared; the stored times do not change.
    let week = FreshnessPolicy {
        fresh_for_secs: 7 * 86400,
    };
    let relaxed = visible_sources(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &week,
        &PageRequest::default(),
    )
    .unwrap();
    assert_eq!(relaxed["freshness_policy"]["fresh_for_seconds"], 7 * 86400);
    let stale_scope = list(&relaxed, "sources")
        .into_iter()
        .find(|r| r["scope"] == "stale-scope")
        .unwrap();
    assert_eq!(stale_scope["freshness"], "fresh");
    assert_eq!(
        stale_scope["observed_at"],
        by_scope("stale-scope")["observed_at"]
    );
    for bad in [0, 59, 91 * 86400] {
        let policy = FreshnessPolicy {
            fresh_for_secs: bad,
        };
        let got = visible_sources(
            &w.hub,
            &scope,
            &SourceFilter::default(),
            &policy,
            &PageRequest::default(),
        );
        assert_eq!(got.unwrap_err().http_status, Some(400));
    }
    // Time moves on without any new evidence: the same rows age.
    let later = sources_at(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &page_at(t + 3.0 * 86400.0, None, 50),
    )
    .unwrap();
    let aged = list(&later, "sources")
        .into_iter()
        .find(|r| r["scope"] == "fresh-scope")
        .unwrap();
    assert_eq!(aged["freshness"], "stale");
}

#[test]
fn partial_collections_stay_visible_and_an_empty_answer_is_not_clean() {
    let w = world();
    let t = vorda::store::now() - 60.0;
    for (scope, source, inputs) in [
        ("complete", "npm-c", &["one"][..]),
        ("partial", "npm-p", &["one", "absent"][..]),
    ] {
        w.deliver(&delivery(&w.a1, ORG, "site-a", scope, source, t, inputs), 1)
            .unwrap();
    }
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let view = sources(&w, &scope, &SourceFilter::default());
    let row = |name: &str| {
        list(&view, "sources")
            .into_iter()
            .find(|r| r["scope"] == name)
            .unwrap()
    };
    assert_eq!(
        row("complete")["coverage"]["inventory"]["state"],
        "complete"
    );
    assert_eq!(
        row("complete")["coverage"]["inputs"],
        json!({"complete":1,"failed":0})
    );
    assert_eq!(
        row("complete")["coverage"]["advisories"]["state"],
        "not_requested",
        "advisory lookups were not asked for, which is not the same as unknown"
    );
    assert_eq!(row("partial")["coverage"]["inventory"]["state"], "partial");
    assert_eq!(
        row("partial")["coverage"]["inventory"]["reason"]["quoted"],
        "input_read_failed"
    );
    assert_eq!(
        row("partial")["coverage"]["inputs"],
        json!({"complete":1,"failed":1})
    );
    let partial = SourceFilter {
        inventory_state: Some("partial".into()),
        ..Default::default()
    };
    assert_eq!(sources(&w, &scope, &partial)["total"], 1);

    // Counts state what they count.
    let status = fleet_status(&w.hub, &scope, &DeviceFilter::default(), &POLICY).unwrap();
    assert_eq!(status["sources"]["total"], 2);
    assert_eq!(
        status["sources"]["by_inventory_state"],
        json!({"complete":1,"partial":1})
    );
    assert_eq!(status["sources"]["with_failed_inputs"], 1);
    assert!(status["counting"]["sources"]
        .as_str()
        .unwrap()
        .contains("authorities"));
}

#[test]
fn status_counts_checkins_by_the_declared_policy_and_keeps_revoked_devices_apart() {
    let w = world();
    standard_deliveries(&w);
    let never = enroll_without_evidence(&w, "site-a", "n1");
    w.hub.revoke(&w.b1).unwrap();
    grant(&w, READER_A, &["site-a", "site-b"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let t = vorda::store::now();
    let status = |window: u64, now: f64| {
        fleet_status_at(
            &w.hub,
            &scope,
            &DeviceFilter::default(),
            &FreshnessPolicy {
                fresh_for_secs: window,
            },
            now,
        )
        .unwrap()
    };

    let fresh = status(3600, t + 60.0);
    assert_eq!(
        fresh["devices"],
        json!({"enrolled":4,"revoked":1,"expected_to_check_in":3,
        "checked_in_fresh":2,"checked_in_stale":0,"checked_in_clock_ahead":0,"never_checked_in":1})
    );
    assert_eq!(fresh["sources"]["from_revoked_devices"], 1);
    let stale = status(3600, t + 7200.0);
    assert_eq!(stale["devices"]["checked_in_stale"], 2);
    assert_eq!(stale["devices"]["checked_in_fresh"], 0);
    assert_eq!(
        stale["devices"]["never_checked_in"], 1,
        "silence is not staleness"
    );
    assert!(stale["counting"]["checkin"]
        .as_str()
        .unwrap()
        .contains("not an observation time"));
    assert_eq!(stale["freshness_policy"]["fresh_for_seconds"], 3600);

    // A site-restricted reader's counts exclude the other site entirely.
    grant(&w, READER_B, &["site-a"], &[], 3600.0);
    let a_only = fleet_status(
        &w.hub,
        &authorize(&w, READER_B).unwrap(),
        &DeviceFilter::default(),
        &POLICY,
    )
    .unwrap();
    assert_eq!(a_only["devices"]["enrolled"], 3);
    assert_eq!(a_only["devices"]["revoked"], 0);
    // The device that never delivered is listed, and is the one counted as never checked in.
    let listed = visible_devices(
        &w.hub,
        &authorize(&w, READER_B).unwrap(),
        &DeviceFilter::default(),
        &PageRequest::default(),
    )
    .unwrap();
    assert!(device_ids(&listed).contains(&never));
    assert_eq!(a_only["devices"]["never_checked_in"], 1);
}

#[test]
fn list_cursors_are_bound_to_their_list_walk_time_and_snapshot() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let t = vorda::store::now();
    let first = sources_at(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &page_at(t, None, 1),
    )
    .unwrap();
    assert_eq!(
        (first["page_end"].as_str(), list(&first, "sources").len()),
        (Some("limit"), 1)
    );
    let cursor = first["next_cursor"].as_str().unwrap().to_string();

    // Pages of one walk agree on the time they were evaluated at.
    let second = sources_at(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &page_at(t + 1800.0, Some(&cursor), 1),
    )
    .unwrap();
    assert_eq!(second["as_of"], first["as_of"]);

    let mut seen = vec![];
    let mut next = None::<String>;
    for _ in 0..1000 {
        let view = sources_at(
            &w.hub,
            &scope,
            &SourceFilter::default(),
            &POLICY,
            &page_at(t, next.as_deref(), 1),
        )
        .unwrap();
        seen.extend(
            list(&view, "sources")
                .iter()
                .map(|r| (r["device"].clone(), r["scope"].clone(), r["source"].clone())),
        );
        next = view["next_cursor"].as_str().map(str::to_string);
        if next.is_none() {
            break;
        }
    }
    assert!(
        next.is_none(),
        "the sources walk did not end within 1000 pages ({} rows); last cursor {next:?}",
        seen.len()
    );
    assert_eq!(seen.len(), 3, "every source exactly once");

    // The same cursor fails on another list, another filter, an hour later, and after new evidence,
    // always exactly like an invented one.
    let invented = sources_at(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &page_at(t, Some("AAAA"), 1),
    )
    .unwrap_err();
    let same = |e: vorda::Error| {
        (e.http_status, e.message) == (invented.http_status, invented.message.clone())
    };
    let other_list = visible_devices_at(
        &w.hub,
        &scope,
        &DeviceFilter::default(),
        &PageRequest {
            limit: Some(1),
            cursor: Some(&cursor),
        },
        t,
    );
    assert!(same(other_list.unwrap_err()));
    let other_filter = SourceFilter {
        freshness: Some("fresh".into()),
        ..Default::default()
    };
    assert!(same(
        sources_at(
            &w.hub,
            &scope,
            &other_filter,
            &POLICY,
            &page_at(t, Some(&cursor), 1)
        )
        .unwrap_err()
    ));
    let other_policy = FreshnessPolicy {
        fresh_for_secs: 3600,
    };
    assert!(same(
        sources_at(
            &w.hub,
            &scope,
            &SourceFilter::default(),
            &other_policy,
            &page_at(t, Some(&cursor), 1)
        )
        .unwrap_err()
    ));
    assert!(same(
        sources_at(
            &w.hub,
            &scope,
            &SourceFilter::default(),
            &POLICY,
            &page_at(t + 3700.0, Some(&cursor), 1)
        )
        .unwrap_err()
    ));
    w.deliver(
        &delivery(&w.a2, ORG, "site-a", "scope-1", "npm-a", t, &["one"]),
        2,
    )
    .unwrap();
    assert!(same(
        sources_at(
            &w.hub,
            &scope,
            &SourceFilter::default(),
            &POLICY,
            &page_at(t, Some(&cursor), 1)
        )
        .unwrap_err()
    ));
}

#[test]
fn held_scopes_are_refused_by_every_v2_query_after_revocation() {
    let w = world();
    standard_deliveries(&w);
    let reader = grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let held = authorize(&w, READER_A).unwrap();
    ReaderStore::open(&w.db).unwrap().revoke(&reader).unwrap();
    let statuses = [
        visible_sources(
            &w.hub,
            &held,
            &SourceFilter::default(),
            &POLICY,
            &PageRequest::default(),
        )
        .unwrap_err()
        .http_status,
        visible_devices(
            &w.hub,
            &held,
            &DeviceFilter::default(),
            &PageRequest::default(),
        )
        .unwrap_err()
        .http_status,
        fleet_status(&w.hub, &held, &DeviceFilter::default(), &POLICY)
            .unwrap_err()
            .http_status,
    ];
    assert_eq!(statuses, [Some(401); 3]);
}

#[test]
fn a_version_1_hub_answers_with_empty_v2_views_rather_than_errors() {
    let w = world_at(false);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    assert_eq!(sources(&w, &scope, &SourceFilter::default())["total"], 0);
    let status = fleet_status(&w.hub, &scope, &DeviceFilter::default(), &POLICY).unwrap();
    assert_eq!(status["devices"]["enrolled"], 2);
    assert_eq!(status["sources"]["total"], 0);
}

#[test]
fn a_checkin_dated_after_the_clock_is_counted_apart_and_never_as_fresh() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let t = vorda::store::now();
    // The hub's clock stepped back an hour behind the receipts it already holds.
    let status = fleet_status_at(
        &w.hub,
        &scope,
        &DeviceFilter::default(),
        &POLICY,
        t - 3600.0,
    )
    .unwrap();
    assert_eq!(status["devices"]["checked_in_fresh"], 0);
    assert_eq!(status["devices"]["checked_in_clock_ahead"], 2);
    assert_eq!(status["devices"]["expected_to_check_in"], 2);
}

#[test]
fn non_finite_observation_times_are_unknown_not_stale_or_future() {
    let w = world();
    let t = vorda::store::now();
    for (scope, source) in [("nan-scope", "npm-a"), ("inf-scope", "npm-b")] {
        w.deliver(
            &delivery(&w.a1, ORG, "site-a", scope, source, t - 60.0, &["one"]),
            1,
        )
        .unwrap();
    }
    // Admission stores only plain decimals; rows already stored are still never trusted as times.
    let db = rusqlite::Connection::open(&w.db).unwrap();
    for (source, bad) in [("npm-a", "NaN"), ("npm-b", "inf")] {
        let (authority, raw): (String, Vec<u8>) = db
            .query_row(
                "SELECT s.authority,s.artifact FROM v2_assessments s JOIN v2_authorities a ON a.authority=s.authority WHERE a.source=?",
                [source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let mut artifact: Value = serde_json::from_slice(&raw).unwrap();
        artifact["times"]["observed_at"]["value"] = json!(bad);
        db.execute(
            "UPDATE v2_assessments SET artifact=? WHERE authority=?",
            rusqlite::params![serde_json::to_vec(&artifact).unwrap(), authority],
        )
        .unwrap();
    }
    drop(db);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let view = sources(&w, &scope, &SourceFilter::default());
    for row in list(&view, "sources") {
        assert_eq!(row["freshness"], "unknown", "{row}");
        assert!(row["age_seconds"].is_null());
    }
    assert_eq!(
        fleet_status(&w.hub, &scope, &DeviceFilter::default(), &POLICY).unwrap()["sources"]
            ["by_observation_freshness"],
        json!({"unknown":2})
    );
}

#[test]
fn one_query_never_works_through_more_than_the_authority_cap() {
    let w = world();
    standard_deliveries(&w);
    // A compromised endpoint can open many (scope, source) pairs. Simulate the rows it would leave.
    let db = rusqlite::Connection::open(&w.db).unwrap();
    for i in 0..=vorda::fleet::coverage::MAX_AUTHORITIES {
        let authority =
            json!([ORG, "site-a", w.a1, "generation", format!("scope-{i}")]).to_string();
        db.execute(
            "INSERT INTO v2_authorities VALUES(?,?,0,0,0,NULL)",
            rusqlite::params![authority, "npm-a"],
        )
        .unwrap();
    }
    drop(db);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let refused = [
        visible_sources(
            &w.hub,
            &scope,
            &SourceFilter::default(),
            &POLICY,
            &PageRequest::default(),
        ),
        fleet_status(&w.hub, &scope, &DeviceFilter::default(), &POLICY),
    ];
    for result in refused {
        let error = result.unwrap_err();
        assert_eq!(error.http_status, Some(413));
        assert!(error.message.contains("narrow"), "{}", error.message);
    }
    // The device list never shows authorities, so a view over the cap still lists every device.
    let listed = visible_devices(
        &w.hub,
        &scope,
        &DeviceFilter::default(),
        &PageRequest::default(),
    )
    .unwrap();
    let mut both = vec![w.a1.clone(), w.a2.clone()];
    both.sort();
    assert_eq!(
        (listed["total"].as_i64(), device_ids(&listed)),
        (Some(2), both)
    );
    // Narrowing the view to another device brings the other lists back under the cap.
    let narrowed = SourceFilter {
        devices: vec![w.a2.clone()],
        ..Default::default()
    };
    assert_eq!(sources(&w, &scope, &narrowed)["total"], 1);
}

#[test]
fn the_devices_list_has_the_standard_envelope_and_pages_with_bound_cursors() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a", "site-b"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let ask = |cursor: Option<&str>| {
        visible_devices(
            &w.hub,
            &scope,
            &DeviceFilter::default(),
            &PageRequest {
                limit: Some(2),
                cursor,
            },
        )
    };

    let first = ask(None).unwrap();
    assert_eq!(first["contract_version"], "m3-fleet-1");
    assert!(first["as_of"].is_number() && first["revision"].is_string());
    assert_eq!(
        (first["total"].as_i64(), first["page_end"].as_str()),
        (Some(3), Some("limit"))
    );
    let cursor = first["next_cursor"].as_str().unwrap().to_string();
    let second = ask(Some(&cursor)).unwrap();
    assert_eq!(
        (second["page_end"].as_str(), second["next_cursor"].is_null()),
        (Some("last"), true)
    );

    let mut seen = device_ids(&first);
    seen.extend(device_ids(&second));
    let mut expected = vec![w.a1.clone(), w.a2.clone(), w.b1.clone()];
    expected.sort();
    assert_eq!(
        seen, expected,
        "every device exactly once, none from the other organization"
    );
    assert!(!first.to_string().contains(&w.x1) && !second.to_string().contains(&w.x1));

    // The cursor belongs to this list: another list and another filter refuse it like a made-up one.
    let invented = ask(Some("AAAA")).unwrap_err();
    let other_list = visible_sources(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &PageRequest {
            limit: Some(2),
            cursor: Some(&cursor),
        },
    )
    .unwrap_err();
    assert_eq!(
        (other_list.http_status, other_list.message),
        (invented.http_status, invented.message.clone())
    );
    let narrowed = visible_devices(
        &w.hub,
        &scope,
        &DeviceFilter {
            sites: vec!["site-a".into()],
            devices: vec![],
        },
        &PageRequest {
            limit: Some(2),
            cursor: Some(&cursor),
        },
    )
    .unwrap_err();
    assert_eq!(narrowed.message, invented.message);
}

#[test]
fn the_devices_list_defaults_to_fifty_caps_at_one_hundred_and_walks_every_device_once() {
    let w = world();
    for i in 0..120 {
        enroll(&w.hub, ORG, "site-b", &format!("bulk{i}"), &[]);
    }
    grant(&w, READER_A, &["site-b"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let ask = |limit: Option<usize>, cursor: Option<&str>| {
        visible_devices(
            &w.hub,
            &scope,
            &DeviceFilter::default(),
            &PageRequest { limit, cursor },
        )
        .unwrap()
    };
    assert_eq!(device_ids(&ask(None, None)).len(), 50);
    assert_eq!(device_ids(&ask(Some(1000), None)).len(), 100);
    assert_eq!(ask(None, None)["total"], 121, "site-b also holds b1");

    let mut seen = vec![];
    let mut cursor: Option<String> = None;
    for _ in 0..1000 {
        let page = ask(Some(100), cursor.as_deref());
        seen.extend(device_ids(&page));
        cursor = page["next_cursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    assert!(
        cursor.is_none(),
        "the devices walk did not end within 1000 pages ({} rows); last cursor {cursor:?}",
        seen.len()
    );
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 121);
}

fn names(n: usize, tag: &str) -> Vec<String> {
    (0..n).map(|i| format!("{tag}-{i}")).collect()
}
fn status_code(r: vorda::Result<Value>) -> Option<u16> {
    r.err().and_then(|e| e.http_status)
}

#[test]
fn oversized_or_unknown_filter_values_are_refused_by_every_view_and_the_bounds_are_accepted() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let every_view = |sites: Vec<String>, devices: Vec<String>| {
        [
            visible_sources(
                &w.hub,
                &scope,
                &SourceFilter {
                    sites: sites.clone(),
                    devices: devices.clone(),
                    ..Default::default()
                },
                &POLICY,
                &PageRequest::default(),
            ),
            visible_devices(
                &w.hub,
                &scope,
                &DeviceFilter {
                    sites: sites.clone(),
                    devices: devices.clone(),
                },
                &PageRequest::default(),
            ),
            fleet_status(&w.hub, &scope, &DeviceFilter { sites, devices }, &POLICY),
        ]
    };
    for result in every_view(names(65, "site"), vec![]) {
        assert_eq!(status_code(result), Some(400));
    }
    for result in every_view(vec![], names(257, "device")) {
        assert_eq!(status_code(result), Some(400));
    }
    for result in every_view(names(64, "site"), names(256, "device")) {
        assert!(result.is_ok());
    }

    let sources =
        |f: SourceFilter| visible_sources(&w.hub, &scope, &f, &POLICY, &PageRequest::default());
    let with_sources = |sources: Vec<String>| SourceFilter {
        sources,
        ..Default::default()
    };
    assert_eq!(
        status_code(sources(with_sources(names(65, "src")))),
        Some(400)
    );
    assert!(sources(with_sources(names(64, "src"))).is_ok());
    assert_eq!(
        status_code(sources(with_sources(vec!["s".repeat(257)]))),
        Some(400)
    );
    assert!(sources(with_sources(vec!["s".repeat(256)])).is_ok());

    // A state outside the closed lists is refused: an empty answer must not read as "none of those".
    for bad in ["stalee", "Fresh", "", "failed"] {
        let f = SourceFilter {
            freshness: Some(bad.into()),
            ..Default::default()
        };
        assert_eq!(status_code(sources(f)), Some(400), "freshness {bad:?}");
    }
    for bad in ["failed", "Partial", "", "completed"] {
        let f = SourceFilter {
            inventory_state: Some(bad.into()),
            ..Default::default()
        };
        assert_eq!(status_code(sources(f)), Some(400), "inventory {bad:?}");
    }
    for good in ["fresh", "stale", "unknown", "future"] {
        let f = SourceFilter {
            freshness: Some(good.into()),
            ..Default::default()
        };
        assert!(sources(f).is_ok(), "freshness {good}");
    }
    for good in ["complete", "partial", "not_requested", "unknown"] {
        let f = SourceFilter {
            inventory_state: Some(good.into()),
            ..Default::default()
        };
        assert!(sources(f).is_ok(), "inventory {good}");
    }

    // The status view checks the window like the sources view does.
    for bad in [0, 59, 91 * 86400] {
        let policy = FreshnessPolicy {
            fresh_for_secs: bad,
        };
        let got = fleet_status(&w.hub, &scope, &DeviceFilter::default(), &policy);
        assert_eq!(status_code(got), Some(400), "window {bad}");
    }
}

#[test]
fn a_cursor_is_refused_on_a_view_the_grant_and_filter_leave_empty() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let t = vorda::store::now();
    let walk = sources_at(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &page_at(t, None, 1),
    )
    .unwrap();
    let cursor = walk["next_cursor"].as_str().unwrap().to_string();
    let other_site = SourceFilter {
        sites: vec!["site-b".into()],
        ..Default::default()
    };
    let invented = sources_at(
        &w.hub,
        &scope,
        &other_site,
        &POLICY,
        &page_at(t, Some("AAAA"), 1),
    )
    .unwrap_err();
    let with_cursor = sources_at(
        &w.hub,
        &scope,
        &other_site,
        &POLICY,
        &page_at(t, Some(&cursor), 1),
    )
    .unwrap_err();
    assert_eq!(
        (with_cursor.http_status, with_cursor.message),
        (invented.http_status, invented.message)
    );
    // Without a cursor the same empty view is a plain empty answer.
    assert_eq!(
        sources_at(&w.hub, &scope, &other_site, &POLICY, &page_at(t, None, 1)).unwrap()["total"],
        0
    );
    let devices = |cursor: Option<&str>| {
        visible_devices_at(
            &w.hub,
            &scope,
            &DeviceFilter {
                sites: vec!["site-b".into()],
                devices: vec![],
            },
            &PageRequest {
                limit: Some(1),
                cursor,
            },
            t,
        )
    };
    assert!(devices(None).is_ok());
    assert_eq!(devices(Some(&cursor)).unwrap_err().http_status, Some(400));
}

#[test]
fn a_cursor_past_the_end_of_a_view_that_shrank_under_it_is_refused() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let t = vorda::store::now();
    let fresh = SourceFilter {
        freshness: Some("fresh".into()),
        ..Default::default()
    };
    let first = sources_at(&w.hub, &scope, &fresh, &POLICY, &page_at(t, None, 1)).unwrap();
    assert_eq!(first["total"], 3);
    let cursor = first["next_cursor"].as_str().unwrap().to_string();

    // The stored times become unreadable while the evidence revisions stay the same: the snapshot
    // is unchanged, but the rows the freshness filter keeps are not.
    let db = rusqlite::Connection::open(&w.db).unwrap();
    let rows: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT authority,artifact FROM v2_assessments")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (authority, raw) in rows {
        let mut artifact: Value = serde_json::from_slice(&raw).unwrap();
        artifact["times"]["observed_at"]["value"] = json!("NaN");
        db.execute(
            "UPDATE v2_assessments SET artifact=? WHERE authority=?",
            rusqlite::params![serde_json::to_vec(&artifact).unwrap(), authority],
        )
        .unwrap();
    }
    drop(db);
    assert_eq!(
        sources_at(&w.hub, &scope, &fresh, &POLICY, &page_at(t, None, 1)).unwrap()["total"],
        0
    );
    let refused = sources_at(
        &w.hub,
        &scope,
        &fresh,
        &POLICY,
        &page_at(t, Some(&cursor), 1),
    )
    .unwrap_err();
    let invented = sources_at(
        &w.hub,
        &scope,
        &fresh,
        &POLICY,
        &page_at(t, Some("AAAA"), 1),
    )
    .unwrap_err();
    assert_eq!(
        (refused.http_status, refused.message),
        (invented.http_status, invented.message)
    );
}

#[test]
fn an_observation_is_future_only_beyond_three_hundred_seconds_ahead_of_the_clock() {
    let w = world();
    let t = vorda::store::now().floor();
    for (scope, ahead) in [("s299", 299.0), ("s300", 300.0), ("s301", 301.0)] {
        w.deliver(
            &delivery(&w.a1, ORG, "site-a", scope, "npm-a", t + ahead, &["one"]),
            1,
        )
        .unwrap();
    }
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let view = sources_at(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &page_at(t, None, 50),
    )
    .unwrap();
    let label = |name: &str| {
        list(&view, "sources")
            .into_iter()
            .find(|r| r["scope"] == name)
            .unwrap()["freshness"]
            .clone()
    };
    assert_eq!(
        [label("s299"), label("s300"), label("s301")],
        ["fresh", "fresh", "future"]
    );

    // A check-in is held to the same limit.
    let received = list(&view, "sources")
        .iter()
        .map(|r| r["last_received"].as_f64().unwrap())
        .fold(f64::MIN, f64::max);
    let ahead_by = |secs: f64| {
        fleet_status_at(
            &w.hub,
            &scope,
            &DeviceFilter {
                devices: vec![w.a1.clone()],
                ..Default::default()
            },
            &POLICY,
            received - secs,
        )
        .unwrap()["devices"]["checked_in_clock_ahead"]
            .clone()
    };
    assert_eq!([ahead_by(299.0), ahead_by(301.0)], [0, 1]);
}

#[test]
fn every_page_of_a_walk_is_labelled_at_the_time_the_walk_started() {
    let w = world();
    standard_deliveries(&w);
    let t = vorda::store::now().floor();
    // Fresh when the walk starts, and stale if a later page were evaluated half an hour on.
    let window = POLICY.fresh_for_secs as f64;
    let db = rusqlite::Connection::open(&w.db).unwrap();
    let rows: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT authority,artifact FROM v2_assessments")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (authority, raw) in rows {
        let mut artifact: Value = serde_json::from_slice(&raw).unwrap();
        artifact["times"]["observed_at"]["value"] = json!(format!("{}", t - window + 600.0));
        db.execute(
            "UPDATE v2_assessments SET artifact=? WHERE authority=?",
            rusqlite::params![serde_json::to_vec(&artifact).unwrap(), authority],
        )
        .unwrap();
    }
    drop(db);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let mut labels = vec![];
    let mut cursor: Option<String> = None;
    let mut at = t;
    for _ in 0..1000 {
        let page = sources_at(
            &w.hub,
            &scope,
            &SourceFilter::default(),
            &POLICY,
            &page_at(at, cursor.as_deref(), 1),
        )
        .unwrap();
        assert_eq!(page["as_of"], t);
        labels.extend(
            list(&page, "sources")
                .iter()
                .map(|r| r["freshness"].clone()),
        );
        cursor = page["next_cursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
        at = t + 1800.0;
    }
    assert!(
        cursor.is_none(),
        "the freshness walk did not end within 1000 pages ({} rows); last cursor {cursor:?}",
        labels.len()
    );
    assert_eq!(labels, ["fresh", "fresh", "fresh"]);
}

#[test]
fn sources_of_revoked_devices_are_marked_and_an_empty_status_has_the_shape_of_a_full_one() {
    let w = world();
    standard_deliveries(&w);
    w.hub.revoke(&w.a2).unwrap();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let view = sources(&w, &scope, &SourceFilter::default());
    let marks: Vec<_> = list(&view, "sources")
        .iter()
        .map(|r| {
            (
                r["device"].as_str().unwrap().to_string(),
                r["revoked"].clone(),
            )
        })
        .collect();
    assert_eq!(marks.len(), 3);
    for (device, revoked) in marks {
        assert_eq!(revoked, (device == w.a2), "{device}");
    }

    let full = fleet_status(&w.hub, &scope, &DeviceFilter::default(), &POLICY).unwrap();
    assert!(full["counting"]["sources"]
        .as_str()
        .unwrap()
        .contains("revoked"));
    let empty = fleet_status(
        &w.hub,
        &scope,
        &DeviceFilter {
            sites: vec!["site-b".into()],
            devices: vec![],
        },
        &POLICY,
    )
    .unwrap();
    let keys = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
    assert_eq!(keys(&empty), keys(&full));
    for part in ["devices", "sources", "counting"] {
        assert_eq!(keys(&empty[part]), keys(&full[part]), "{part}");
    }
    assert_eq!(empty["devices"]["enrolled"], 0);
    assert_eq!(empty["sources"]["total"], 0);
}

// ---- what the reader is told about coverage that the hub cannot represent (D3) ----

const L2: &[u8] = include_bytes!("fixtures/capture/L2.json"); // samepackage 2.0.0

/// A v2 request for `d` whose artifact `edit` has rewritten, and an admission that trusts exactly
/// that artifact, so that only the edit stands between the request and the hub.
fn forged(
    w: &World,
    d: &Delivery,
    sequence: i64,
    lock: &[u8],
    edit: impl FnOnce(&mut Value),
) -> (Admission, Vec<u8>) {
    let (binding, evidence, raw, wire) = w.v2_request(d, sequence, lock);
    let mut artifact: Value = serde_json::from_str(&raw).unwrap();
    edit(&mut artifact);
    let raw = String::from_utf8(canonical(&artifact)).unwrap();
    let mut request: Value = serde_json::from_slice(&wire).unwrap();
    request["artifact_utf8"] = json!(raw);
    request["artifact_sha256"] = json!(hash(raw.as_bytes()));
    request["artifact_byte_length"] = json!(raw.len());
    let admission = Admission::open(
        &w.db,
        vec![TrustedCapture {
            binding,
            evidence_id: evidence,
            artifact_utf8: raw,
        }],
    )
    .unwrap();
    (admission, canonical(&request))
}
fn refused(r: vorda::Result<Vec<u8>>) -> (Option<u16>, String) {
    let e = r.expect_err("the hub took a request it must refuse");
    (e.http_status, e.message)
}

#[test]
fn an_input_the_scanner_does_not_support_is_refused_and_never_reads_as_a_failed_read() {
    let w = world();
    let t = now() - 60.0;
    // A read that failed is a partial source with a failed input, and the reader sees it.
    w.deliver(
        &delivery(
            &w.a1,
            ORG,
            "site-a",
            "failed",
            "npm-f",
            t,
            &["one", "absent"],
        ),
        1,
    )
    .unwrap();
    // An input of a kind the scanner does not support is not representable: the hub refuses the
    // assessment, so the source does not appear at all, least of all as a failed one.
    let d = delivery(
        &w.a1,
        ORG,
        "site-a",
        "unsupported",
        "npm-u",
        t,
        &["one", "two"],
    );
    let (admission, wire) = forged(&w, &d, 2, L1, |a| {
        let path = a["inputs"][1]["path"].clone();
        a["inputs"][1] =
            json!({"path":path,"sha256":null,"bytes_utf8":null,"error":"unsupported_input_field"});
        a["records"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["input_path"] != path);
        a["coverage"]["inventory"] = json!({"state":"partial","reason":"input_read_failed"});
    });
    assert_eq!(
        refused(admission.admit(&wire)),
        (Some(422), "unsupported_input".to_string())
    );

    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let view = sources(&w, &scope, &SourceFilter::default());
    let rows = list(&view, "sources");
    assert_eq!(rows.len(), 1, "{view}");
    assert_eq!(rows[0]["scope"], "failed");
    assert_eq!(rows[0]["coverage"]["inventory"]["state"], "partial");
    assert_eq!(
        rows[0]["coverage"]["inputs"],
        json!({"complete":1,"failed":1})
    );
    assert!(!text(&view).contains("unsupported"), "{view}");
}

#[test]
fn an_advisory_result_cannot_be_delivered_so_the_reader_keeps_not_requested() {
    let w = world();
    let t = now().floor();
    let d = delivery(
        &w.a1,
        ORG,
        "site-a",
        "scope-1",
        "npm-a",
        t - 3600.0,
        &["one"],
    );
    w.deliver(&d, 1).unwrap();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let clock = page_at(t, None, 100);
    let read = || sources_at(&w.hub, &scope, &SourceFilter::default(), &POLICY, &clock).unwrap();
    let before = read();

    // Alpha limitation: "inventory complete, advisory assessment unavailable" cannot be said.
    // A producer that claims an advisory result is refused, whole, and the reader's answer for
    // the source is exactly what it was.
    let newer = delivery(&w.a1, ORG, "site-a", "scope-1", "npm-a", t - 60.0, &["one"]);
    let (admission, wire) = forged(&w, &newer, 2, L2, |a| {
        a["coverage"]["advisories"] = json!({"state":"complete","reason":null});
    });
    assert_eq!(
        refused(admission.admit(&wire)),
        (Some(422), "unsupported_coverage".to_string())
    );

    let after = read();
    assert_eq!(after["sources"], before["sources"]);
    let row = &list(&after, "sources")[0];
    assert_eq!(row["assessment_revision"], 1);
    assert_eq!(row["coverage"]["advisories"]["state"], "not_requested");
}

#[test]
fn a_source_that_stops_reporting_ages_to_stale_but_is_not_retired_or_resolved() {
    let w = world();
    let t = now().floor();
    let quiet = delivery(&w.a1, ORG, "site-a", "quiet", "npm-q", t - 3600.0, &["one"]);
    let live = delivery(&w.a1, ORG, "site-a", "live", "npm-l", t - 3600.0, &["one"]);
    w.deliver(&quiet, 1).unwrap();
    w.deliver(&live, 2).unwrap();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let page = PageRequest::default();
    let day = 86400.0;
    let freshness = |at: f64| -> Vec<(String, String)> {
        let view = visible_sources_at(&w.hub, &scope, &SourceFilter::default(), &POLICY, &page, at)
            .unwrap();
        list(&view, "sources")
            .iter()
            .map(|r| {
                (
                    r["scope"].as_str().unwrap().to_string(),
                    r["freshness"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let fresh = |s: &str| (s.to_string(), "fresh".to_string());
    let stale = |s: &str| (s.to_string(), "stale".to_string());
    let mut rows = freshness(t);
    rows.sort();
    assert_eq!(rows, [fresh("live"), fresh("quiet")]);

    // Forty days on, "quiet" has said nothing and "live" has said nothing either: both are stale,
    // by age, and still listed.
    let later = t + 40.0 * day;
    let mut rows = freshness(later);
    rows.sort();
    assert_eq!(rows, [stale("live"), stale("quiet")]);

    // A source that keeps reporting is fresh again; the silent one is still only stale.
    w.deliver(
        &delivery(
            &w.a1,
            ORG,
            "site-a",
            "live",
            "npm-l",
            later - 60.0,
            &["one"],
        ),
        3,
    )
    .unwrap();
    let mut rows = freshness(later);
    rows.sort();
    assert_eq!(rows, [fresh("live"), stale("quiet")]);

    // Nothing was retired or resolved on the way: the silent source's component is still in the
    // inventory, marked stale, and its history reads back with no resolution.
    let inventory = visible_inventory(
        &w.hub,
        &scope,
        &InventoryFilter {
            sources: vec!["npm-q".into()],
            ..Default::default()
        },
        &POLICY,
        &page,
        later,
    )
    .unwrap();
    let components = list(&inventory, "inventory");
    assert_eq!(components.len(), 1, "{inventory}");
    assert_eq!(components[0]["freshness"], "stale");
    for at in [t, later] {
        let changes = fleet_changes(
            &w.hub,
            &scope,
            &ChangeFilter::default(),
            &Since::Start,
            &PageRequest {
                limit: Some(100),
                cursor: None,
            },
            at,
        )
        .unwrap();
        let kinds: Vec<_> = list(&changes, "changes")
            .iter()
            .map(|c| c["kind"].as_str().unwrap().to_string())
            .collect();
        assert!(
            !kinds.is_empty() && kinds.iter().all(|k| k == "added"),
            "{kinds:?}"
        );
    }
}
