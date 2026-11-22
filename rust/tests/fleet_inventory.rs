//! The inventory: components observed in a reader's grant, including ones with no finding, and the
//! per-device bound on what one endpoint may open at the hub. Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use vorda::fleet::{
    auth::AuthorizedScope,
    coverage::{
        visible_inventory, visible_sources, FreshnessPolicy, InventoryFilter, SourceFilter,
    },
    query::PageRequest,
};

const POLICY: FreshnessPolicy = FreshnessPolicy {
    fresh_for_secs: 36 * 3600,
};
fn now() -> f64 {
    vorda::store::now()
}
fn inventory(w: &World, scope: &AuthorizedScope, filter: &InventoryFilter) -> Value {
    visible_inventory(
        &w.hub,
        scope,
        filter,
        &POLICY,
        &PageRequest::default(),
        now(),
    )
    .unwrap()
}
fn delivery<'a>(device: &'a str, scope: &'a str, source: &'a str, t: f64) -> Delivery<'a> {
    Delivery {
        device,
        org: ORG,
        site: "site-a",
        scope,
        source,
        observed: Some(t),
        inputs: &["one"],
    }
}

#[test]
fn the_inventory_never_crosses_sites_organizations_or_sources() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    let all = authorize(&w, READER_A).unwrap();
    let narrow = authorize(&w, READER_B).unwrap();

    let inv = inventory(&w, &all, &InventoryFilter::default());
    assert_eq!(
        inv["total"], 3,
        "a1 twice and a2 once; not b1, not the other organization's x1"
    );
    for hidden in ["site-b", "org-other", w.b1.as_str(), w.x1.as_str()] {
        assert!(!inv.to_string().contains(hidden), "{hidden} leaked");
    }
    // The inventory carries an opaque location reference, never a path.
    assert!(inv["inventory"][0]["location_ref"].is_string());
    assert!(!inv.to_string().contains("package-lock.json"));

    assert_eq!(
        inventory(&w, &narrow, &InventoryFilter::default())["total"],
        1,
        "a source-restricted grant sees its source only"
    );
    let by_package = InventoryFilter {
        name: Some("samepackage".into()),
        ecosystem: Some("npm".into()),
        ..Default::default()
    };
    assert_eq!(inventory(&w, &all, &by_package)["total"], 3);
    for (field, miss) in [
        ("name", "other"),
        ("ecosystem", "pypi"),
        ("version", "9.9.9"),
    ] {
        let mut filter = InventoryFilter::default();
        match field {
            "name" => filter.name = Some(miss.into()),
            "ecosystem" => filter.ecosystem = Some(miss.into()),
            _ => filter.version = Some(miss.into()),
        }
        assert_eq!(inventory(&w, &all, &filter)["total"], 0, "{field} filter");
    }
    let other_source = InventoryFilter {
        sources: vec!["npm-a".into()],
        ..Default::default()
    };
    assert_eq!(
        inventory(&w, &narrow, &other_source)["total"],
        0,
        "a filter cannot widen the grant's sources"
    );

    // A device-restricted grant stays inside its device in the v2 tables too.
    grant(
        &w,
        "synthetic-reader-d-tests-only-000000",
        &["site-a"],
        &[&w.a2],
        60.0,
    );
    let one = authorize(&w, "synthetic-reader-d-tests-only-000000").unwrap();
    assert_eq!(inventory(&w, &one, &InventoryFilter::default())["total"], 1);
}

#[test]
fn a_miss_in_a_partially_collected_source_says_so() {
    let w = world();
    let t = now() - 60.0;
    for (scope, source, inputs) in [
        ("complete", "npm-c", &["one"][..]),
        ("partial", "npm-p", &["one", "absent"][..]),
    ] {
        let d = Delivery {
            inputs,
            ..delivery(&w.a1, scope, source, t)
        };
        w.deliver(&d, 1).unwrap();
    }
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let miss = |source: &str| InventoryFilter {
        sources: vec![source.to_string()],
        name: Some("no-such-package".into()),
        ..Default::default()
    };
    let complete_miss = inventory(&w, &scope, &miss("npm-c"));
    let partial_miss = inventory(&w, &scope, &miss("npm-p"));
    assert_eq!(
        (
            complete_miss["total"].as_i64(),
            partial_miss["total"].as_i64()
        ),
        (Some(0), Some(0))
    );
    assert_eq!(complete_miss["view_coverage"]["sources"], 1);
    assert_eq!(
        complete_miss["view_coverage"]["inventory_states"],
        json!({"complete":1})
    );
    assert_eq!(
        partial_miss["view_coverage"]["inventory_states"],
        json!({"partial":1})
    );
}

#[test]
fn a_cursor_from_the_sources_list_does_not_open_the_inventory() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    fn page(cursor: Option<&str>) -> PageRequest<'_> {
        PageRequest {
            limit: Some(1),
            cursor,
        }
    }
    let first = visible_sources(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &page(None),
        now(),
    )
    .unwrap();
    let cursor = first["next_cursor"].as_str().unwrap().to_string();
    let invented = visible_inventory(
        &w.hub,
        &scope,
        &InventoryFilter::default(),
        &POLICY,
        &page(Some("AAAA")),
        now(),
    )
    .unwrap_err();
    let moved = visible_inventory(
        &w.hub,
        &scope,
        &InventoryFilter::default(),
        &POLICY,
        &page(Some(&cursor)),
        now(),
    )
    .unwrap_err();
    assert_eq!(
        (moved.http_status, moved.message),
        (invented.http_status, invented.message)
    );
}

#[test]
fn a_held_scope_is_refused_by_the_inventory_after_revocation() {
    let w = world();
    standard_deliveries(&w);
    let reader = grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let held = authorize(&w, READER_A).unwrap();
    vorda::fleet::auth::ReaderStore::open(&w.db)
        .unwrap()
        .revoke(&reader)
        .unwrap();
    let refused = visible_inventory(
        &w.hub,
        &held,
        &InventoryFilter::default(),
        &POLICY,
        &PageRequest::default(),
        now(),
    )
    .unwrap_err();
    assert_eq!(refused.http_status, Some(401));
}

#[test]
fn a_version_1_hub_has_an_empty_inventory_not_an_error() {
    let w = world_at(false);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    assert_eq!(
        inventory(&w, &scope, &InventoryFilter::default())["total"],
        0
    );
}

#[test]
fn a_view_over_the_authority_cap_is_refused_by_the_inventory_too() {
    let w = world();
    standard_deliveries(&w);
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
    let refused = visible_inventory(
        &w.hub,
        &scope,
        &InventoryFilter::default(),
        &POLICY,
        &PageRequest::default(),
        now(),
    )
    .unwrap_err();
    assert_eq!(refused.http_status, Some(413));
    assert!(refused.message.contains("narrow"));
}

#[test]
fn the_source_filter_applies_before_the_authority_cap() {
    let w = world();
    standard_deliveries(&w);
    // One source has opened more authorities than a query will work through (the rows it would leave).
    let db = rusqlite::Connection::open(&w.db).unwrap();
    for i in 0..=vorda::fleet::coverage::MAX_AUTHORITIES {
        let authority =
            json!([ORG, "site-a", w.a1, "generation", format!("scope-{i}")]).to_string();
        db.execute(
            "INSERT INTO v2_authorities VALUES(?,?,0,0,0,NULL)",
            rusqlite::params![authority, "flooded"],
        )
        .unwrap();
    }
    drop(db);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let ask = |source: &str| {
        let sources = vec![source.to_string()];
        (
            visible_inventory(
                &w.hub,
                &scope,
                &InventoryFilter {
                    sources: sources.clone(),
                    ..Default::default()
                },
                &POLICY,
                &PageRequest::default(),
                now(),
            ),
            visible_sources(
                &w.hub,
                &scope,
                &SourceFilter {
                    sources,
                    ..Default::default()
                },
                &POLICY,
                &PageRequest::default(),
                now(),
            ),
        )
    };
    // Narrowing by source does what the refusal advises: the other sources are answerable.
    let (inventory, sources) = ask("pip-a");
    assert_eq!(inventory.unwrap()["total"], 1);
    assert_eq!(sources.unwrap()["total"], 1);
    // The flooded source on its own is still too much, and says so.
    let (inventory, sources) = ask("flooded");
    assert_eq!(inventory.unwrap_err().http_status, Some(413));
    assert_eq!(sources.unwrap_err().http_status, Some(413));
}

#[test]
fn a_component_kept_from_an_older_assessment_keeps_that_assessments_time() {
    let w = world();
    let t = now();
    let old = t - 40.0 * 86400.0;
    let both = |observed| Delivery {
        inputs: &["one", "two"],
        ..delivery(&w.a1, "kept", "npm-a", observed)
    };
    w.deliver(&both(old), 1).unwrap();
    // The device scans again, but input `one` fails to read this time: its component stays current
    // from the old assessment, while `two` is replaced by the new one.
    w.deliver_inputs(&both(t - 60.0), 2, L1, &[("one", b"")])
        .unwrap();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let inv = inventory(&w, &scope, &InventoryFilter::default());
    assert_eq!(inv["total"], 2);
    let rows = inv["inventory"].as_array().unwrap();
    let observed = |row: &Value| row["observed_at"]["value"].as_f64().unwrap();
    let kept = rows.iter().find(|r| r["freshness"] == "stale").unwrap();
    let replaced = rows.iter().find(|r| r["freshness"] == "fresh").unwrap();
    assert!((observed(kept) - old).abs() < 1.0, "{kept}");
    assert!(kept["age_seconds"].as_f64().unwrap() > 39.0 * 86400.0);
    assert!((observed(replaced) - (t - 60.0)).abs() < 1.0, "{replaced}");
    assert_eq!(kept["inventory_coverage"]["state"], "partial");
    // The source itself was observed a minute ago; only the kept component is old.
    let sources = visible_sources(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &PageRequest::default(),
        t,
    )
    .unwrap();
    assert_eq!(sources["sources"][0]["freshness"], "fresh");
}

#[test]
fn package_text_and_references_that_hide_characters_are_shown_as_data() {
    let w = world();
    w.deliver(&delivery(&w.a1, "hidden", "npm-a", now() - 60.0), 1)
        .unwrap();
    // Capture accepts only plain package names, so the stored component is edited the way a
    // damaged or hostile row could read: hidden characters in text and in a reference, and a very
    // long version.
    let db = rusqlite::Connection::open(&w.db).unwrap();
    let (authority, record, payload): (String, String, Vec<u8>) = db
        .query_row(
            "SELECT authority,record,payload FROM v2_observations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let mut observed: Value = serde_json::from_slice(&payload).unwrap();
    observed["package"]["name"] = json!("bad\u{202e}name");
    observed["package"]["version"] = json!("9".repeat(300));
    observed["location_ref"] = json!("ref\u{202e}tail");
    db.execute(
        "UPDATE v2_observations SET payload=? WHERE authority=? AND record=?",
        rusqlite::params![serde_json::to_vec(&observed).unwrap(), authority, record],
    )
    .unwrap();
    drop(db);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let inv = inventory(&w, &scope, &InventoryFilter::default());
    let row = &inv["inventory"][0];
    assert_eq!(row["package"]["name"]["neutralised"], 1, "{row}");
    assert_eq!(row["package"]["name"]["quoted"], "bad<U+202E>name");
    assert_eq!(row["package"]["version"]["chars"], 300);
    assert_eq!(row["package"]["version"]["truncated"], true);
    assert_eq!(
        row["package"]["version"]["quoted"].as_str().unwrap().len(),
        256
    );
    assert_eq!(row["location_ref"]["neutralised"], 1, "{row}");
    assert_eq!(row["location_ref"]["quoted"], "ref<U+202E>tail");
    assert!(!inv.to_string().contains('\u{202e}'));
    assert!(!inv.to_string().contains(&"9".repeat(257)));
}

#[test]
fn an_inventory_cursor_is_refused_under_any_other_filter_policy_or_window() {
    let w = world();
    standard_deliveries(&w);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let t = now();
    let walk = |filter: &InventoryFilter, policy: &FreshnessPolicy, cursor: Option<&str>| {
        visible_inventory(
            &w.hub,
            &scope,
            filter,
            policy,
            &PageRequest {
                limit: Some(1),
                cursor,
            },
            t,
        )
    };
    let none = InventoryFilter::default();
    let first = walk(&none, &POLICY, None).unwrap();
    assert_eq!(first["total"], 3);
    let cursor = first["next_cursor"].as_str().unwrap().to_string();
    assert!(walk(&none, &POLICY, Some(&cursor)).is_ok());
    let invented = walk(&none, &POLICY, Some("AAAA")).unwrap_err();

    // Each of these views holds the same rows as the first, or at least the rows before the cursor,
    // and so has the same revision where it can: only the cursor's own binding can refuse it.
    let same = |sites: &[&str], devices: &[&str], sources: &[&str]| InventoryFilter {
        sites: sites.iter().map(|s| s.to_string()).collect(),
        devices: devices.iter().map(|s| s.to_string()).collect(),
        sources: sources.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    let others = [
        same(&["site-a"], &[], &[]),
        same(&[], &[&w.a1, &w.a2], &[]),
        same(&[], &[], &["npm-a", "pip-a"]),
        InventoryFilter {
            ecosystem: Some("npm".into()),
            ..Default::default()
        },
        InventoryFilter {
            name: Some("samepackage".into()),
            ..Default::default()
        },
        InventoryFilter {
            version: Some("1.0.0".into()),
            ..Default::default()
        },
    ];
    for other in &others {
        let refused = walk(other, &POLICY, Some(&cursor)).unwrap_err();
        assert_eq!(
            (refused.http_status, refused.message),
            (invented.http_status, invented.message.clone())
        );
    }
    let longer = FreshnessPolicy {
        fresh_for_secs: 48 * 3600,
    };
    assert!(walk(&none, &longer, Some(&cursor)).is_err());
}

#[test]
fn inventory_rows_of_revoked_devices_say_so() {
    let w = world();
    standard_deliveries(&w);
    w.hub.revoke(&w.a2).unwrap();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let inv = inventory(&w, &scope, &InventoryFilter::default());
    let rows = inv["inventory"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        assert_eq!(row["revoked"], (row["device"] == w.a2.as_str()), "{row}");
    }
}

#[test]
fn inventory_filters_beyond_their_bounds_are_refused_and_the_bounds_are_accepted() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let ask = |filter: InventoryFilter| {
        visible_inventory(
            &w.hub,
            &scope,
            &filter,
            &POLICY,
            &PageRequest::default(),
            now(),
        )
    };
    let sources = |n: usize| (0..n).map(|i| format!("source-{i}")).collect::<Vec<_>>();
    let long = |n: usize| Some("n".repeat(n));
    for refused in [
        InventoryFilter {
            sources: sources(65),
            ..Default::default()
        },
        InventoryFilter {
            ecosystem: long(257),
            ..Default::default()
        },
        InventoryFilter {
            name: long(257),
            ..Default::default()
        },
        InventoryFilter {
            version: long(257),
            ..Default::default()
        },
    ] {
        assert_eq!(ask(refused).unwrap_err().http_status, Some(400));
    }
    let at_bound = InventoryFilter {
        sources: sources(64),
        ecosystem: long(256),
        name: long(256),
        version: long(256),
        ..Default::default()
    };
    assert_eq!(ask(at_bound).unwrap()["total"], 0);
}

#[test]
fn earlier_generations_do_not_count_toward_the_per_device_authority_cap() {
    let w = world();
    let t = now() - 60.0;
    w.deliver(&delivery(&w.a1, "real", "npm-a", t), 1).unwrap();
    let db = rusqlite::Connection::open(&w.db).unwrap();
    for i in 0..vorda::link::native::MAX_AUTHORITIES_PER_DEVICE {
        let authority =
            json!([ORG, "site-a", w.a1, "old-generation", format!("filler-{i}")]).to_string();
        db.execute(
            "INSERT INTO v2_authorities VALUES(?,?,0,0,0,NULL)",
            rusqlite::params![authority, "npm-a"],
        )
        .unwrap();
    }
    drop(db);
    w.deliver(&delivery(&w.a1, "fresh", "npm-a", t), 1).unwrap();
}

#[test]
fn a_device_cannot_open_more_authorities_than_the_per_device_cap() {
    let w = world();
    let t = now() - 60.0;
    w.deliver(&delivery(&w.a1, "real", "npm-a", t), 1).unwrap();
    // The endpoint has opened as many pairs as it may (simulated by the rows it would leave).
    let db = rusqlite::Connection::open(&w.db).unwrap();
    let generation: String = db
        .query_row("SELECT generation FROM devices WHERE id=?", [&w.a1], |r| {
            r.get(0)
        })
        .unwrap();
    let held: usize = db
        .query_row(
            "SELECT count(*) FROM v2_authorities WHERE json_extract(authority,'$[2]')=? AND json_extract(authority,'$[3]')=?",
            [&w.a1, &generation],
            |r| r.get(0),
        )
        .unwrap();
    for i in held..vorda::link::native::MAX_AUTHORITIES_PER_DEVICE {
        let authority = json!([ORG, "site-a", w.a1, generation, format!("filler-{i}")]).to_string();
        db.execute(
            "INSERT INTO v2_authorities VALUES(?,?,0,0,0,NULL)",
            rusqlite::params![authority, "npm-a"],
        )
        .unwrap();
    }
    drop(db);

    let refused = w
        .deliver(&delivery(&w.a1, "one-too-many", "npm-a", t), 1)
        .unwrap_err();
    assert_eq!(
        (refused.http_status, refused.message.as_str()),
        (Some(413), "device_authority_limit")
    );
    // An authority it already has keeps working, and another device is not affected.
    w.deliver(&delivery(&w.a1, "real", "npm-a", t), 2).unwrap();
    w.deliver(&delivery(&w.a2, "one-too-many", "npm-a", t), 1)
        .unwrap();

    // Readers of the site still get answers: the cap keeps one device from making a view too large.
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    assert!(visible_sources(
        &w.hub,
        &scope,
        &SourceFilter::default(),
        &POLICY,
        &PageRequest::default(),
        now(),
    )
    .is_ok());
}
