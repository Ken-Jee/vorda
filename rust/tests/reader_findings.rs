//! The findings list inside a reader grant: scope before counts, opaque cursors bound to reader,
//! grant, query and snapshot, and bounded pages. Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use vorda::fleet::{
    auth::{AuthorizedScope, ReaderStore},
    query::{visible_findings, FindingFilter, PageRequest},
};

const READER_C: &str = "synthetic-reader-c-tests-only-000000";

fn store_path(w: &World) -> String {
    format!("{}.readers", w.db.display())
}

// ---- findings list: scope before counts, opaque bound cursors, page bounds ----

fn page(
    w: &World,
    scope: &AuthorizedScope,
    filter: &FindingFilter,
    limit: Option<usize>,
    cursor: Option<&str>,
) -> vorda::Result<Value> {
    visible_findings(
        &w.hub,
        scope,
        filter,
        &PageRequest { limit, cursor },
        vorda::store::now(),
    )
}
fn keys(view: &Value) -> Vec<String> {
    view["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            // A long key comes back as quoted data rather than a bare string.
            let key = &f["key"];
            key.as_str()
                .unwrap_or_else(|| key["quoted"].as_str().unwrap())
                .to_string()
        })
        .collect()
}
fn next(view: &Value) -> Option<String> {
    view["next_cursor"].as_str().map(str::to_string)
}
/// Every finding the reader can walk to, page by page.
fn walk(w: &World, scope: &AuthorizedScope, filter: &FindingFilter, limit: usize) -> Vec<String> {
    let mut all = vec![];
    let mut cursor: Option<String> = None;
    for _ in 0..1000 {
        let view = page(w, scope, filter, Some(limit), cursor.as_deref()).unwrap();
        all.extend(keys(&view));
        cursor = next(&view);
        if cursor.is_none() {
            return all;
        }
    }
    panic!(
        "the findings walk did not end within 1000 pages ({} rows); last cursor {cursor:?}",
        all.len()
    );
}
fn refusal(e: vorda::Error) -> (Option<u16>, String) {
    (e.http_status, e.message)
}
fn no_filter() -> FindingFilter {
    FindingFilter::default()
}

#[test]
fn the_findings_list_counts_and_pages_only_what_the_grant_covers() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let first = page(&w, &scope, &no_filter(), Some(2), None).unwrap();
    assert_eq!(
        first["total"], 3,
        "the total is the authorized view, not the hub"
    );
    assert_eq!(keys(&first).len(), 2);
    let second = page(&w, &scope, &no_filter(), Some(2), next(&first).as_deref()).unwrap();
    assert_eq!(second["total"], 3);
    assert!(next(&second).is_none());

    let mut seen = keys(&first);
    seen.extend(keys(&second));
    seen.sort();
    assert_eq!(seen, ["finding-a1-x", "finding-a1-y", "finding-a2-x"]);

    let everything = format!("{first}{second}");
    for secret in [
        "site-b",
        "org-other",
        "finding-b1",
        "finding-x1",
        w.b1.as_str(),
        w.x1.as_str(),
    ] {
        assert!(!everything.contains(secret), "{secret} leaked");
    }
    // The cursor carries no id of the data it points into.
    let cursor = next(&first).unwrap();
    for id in [&w.a1, &w.a2, &w.b1] {
        assert!(!cursor.contains(id.as_str()));
    }
    assert!(!cursor.contains("finding-"));
}

#[test]
fn filters_and_paging_cannot_widen_the_findings_a_reader_sees() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let ask = |sites: &[&str], devices: &[&str]| FindingFilter {
        sites: sites.iter().map(|s| s.to_string()).collect(),
        devices: devices.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    for filter in [
        ask(&["site-b"], &[]),
        ask(&[], &[&w.b1]),
        ask(&[], &[&w.x1]),
    ] {
        let view = page(&w, &scope, &filter, None, None).unwrap();
        assert_eq!((view["total"].as_i64(), keys(&view).len()), (Some(0), 0));
    }
    let mixed = page(
        &w,
        &scope,
        &ask(&["site-a", "site-b"], &[&w.a1, &w.b1]),
        None,
        None,
    )
    .unwrap();
    assert_eq!(mixed["total"], 2);
    assert_eq!(keys(&mixed), ["finding-a1-x", "finding-a1-y"]);

    // Walking every page of every query never reaches another site's finding.
    for limit in [1, 2, 5] {
        let all = walk(&w, &scope, &no_filter(), limit);
        assert_eq!(all.len(), 3, "limit {limit}: every finding exactly once");
        assert!(all.iter().all(|k| k.starts_with("finding-a")));
    }
    // A device-restricted grant stays inside its device whatever the filter says.
    grant(&w, READER_B, &["site-a"], &[&w.a1], 3600.0);
    let narrow = authorize(&w, READER_B).unwrap();
    assert_eq!(
        page(&w, &narrow, &no_filter(), None, None).unwrap()["total"],
        2
    );
    assert_eq!(
        page(&w, &narrow, &ask(&[], &[&w.a2]), None, None).unwrap()["total"],
        0
    );
}

#[test]
fn field_filters_narrow_the_authorized_view_before_it_is_counted() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let by_name = FindingFilter {
        name: Some("package-of-finding-a2-x".into()),
        ..Default::default()
    };
    let view = page(&w, &scope, &by_name, None, None).unwrap();
    assert_eq!(
        (view["total"].as_i64(), keys(&view)),
        (Some(1), vec!["finding-a2-x".to_string()])
    );
    // The same name in a site the reader cannot see does not exist for it.
    let hidden = FindingFilter {
        name: Some("package-of-finding-b1-x".into()),
        ..Default::default()
    };
    assert_eq!(page(&w, &scope, &hidden, None, None).unwrap()["total"], 0);
    let fixture_alias = FindingFilter {
        advisory: Some("CVE-2026-0001".into()),
        ..Default::default()
    };
    assert_eq!(
        page(&w, &scope, &fixture_alias, None, None).unwrap()["total"],
        3
    );
}

#[test]
fn a_tampered_or_invented_cursor_fails_exactly_like_a_nonexistent_one() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let cursor = next(&page(&w, &scope, &no_filter(), Some(1), None).unwrap()).unwrap();
    assert!(page(&w, &scope, &no_filter(), Some(1), Some(&cursor)).is_ok());

    let invented = refusal(page(&w, &scope, &no_filter(), Some(1), Some("AAAA")).unwrap_err());
    assert_eq!(invented.0, Some(400));
    let mut variants = vec![
        String::new(),
        "not a cursor at all".to_string(),
        cursor[..cursor.len() - 1].to_string(),
        format!("{cursor}0"),
        cursor.replace('.', ""),
        cursor.to_uppercase(),
        format!("{}.{}", cursor.split('.').next().unwrap(), "0".repeat(64)),
        "\u{0}".to_string(),
        "x".repeat(5000),
    ];
    for i in 0..cursor.len() {
        let mut flipped = cursor.clone().into_bytes();
        flipped[i] = if flipped[i] == b'0' { b'1' } else { b'0' };
        variants.push(String::from_utf8(flipped).unwrap());
    }
    for bad in variants.iter().filter(|v| **v != cursor) {
        let got = refusal(page(&w, &scope, &no_filter(), Some(1), Some(bad)).unwrap_err());
        assert_eq!(got, invented, "{bad:?}");
    }
}

#[test]
fn a_cursor_cannot_be_moved_to_another_reader_or_another_query() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    grant(&w, READER_B, &["site-a"], &[], 3600.0); // an identical grant, a different principal
    let other_site = READER_C;
    grant(&w, other_site, &["site-b"], &[], 3600.0);
    let a = authorize(&w, READER_A).unwrap();
    let b = authorize(&w, READER_B).unwrap();
    let c = authorize(&w, other_site).unwrap();

    let cursor = next(&page(&w, &a, &no_filter(), Some(1), None).unwrap()).unwrap();
    let invented = refusal(page(&w, &a, &no_filter(), Some(1), Some("AAAA")).unwrap_err());
    for stranger in [&b, &c] {
        let got = refusal(page(&w, stranger, &no_filter(), Some(1), Some(&cursor)).unwrap_err());
        assert_eq!(got, invented);
    }
    // Another query: a different filter, with or without the same grant.
    for filter in [
        FindingFilter {
            devices: vec![w.a1.clone()],
            ..Default::default()
        },
        FindingFilter {
            sites: vec!["site-a".into()],
            ..Default::default()
        },
        FindingFilter {
            name: Some("package-of-finding-a1-x".into()),
            ..Default::default()
        },
    ] {
        let got = refusal(page(&w, &a, &filter, Some(1), Some(&cursor)).unwrap_err());
        assert_eq!(got, invented);
    }
    // The page size is not part of the query: asking for a different size continues the walk.
    assert!(page(&w, &a, &no_filter(), Some(2), Some(&cursor)).is_ok());
}

#[test]
fn a_cursor_dies_with_its_snapshot_its_reader_and_its_grant() {
    let w = world();
    let reader = grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let cursor = next(&page(&w, &scope, &no_filter(), Some(1), None).unwrap()).unwrap();
    let invented = refusal(page(&w, &scope, &no_filter(), Some(1), Some("AAAA")).unwrap_err());

    // New evidence from another site is not a signal to this reader: the cursor stays valid.
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/link-v1.json")).unwrap();
    let b = w.hub.snapshot(&w.b1).unwrap();
    batch["device"] = b["device"]["id"].clone();
    batch["generation"] = b["device"]["generation"].clone();
    batch["sequence"] = json!(2);
    batch["scan"] = json!(uuid::Uuid::new_v4().to_string());
    batch["observed"] = json!(vorda::store::now());
    w.hub.ingest(&ingest_secret("b1"), &batch).unwrap();
    assert!(page(&w, &scope, &no_filter(), Some(1), Some(&cursor)).is_ok());

    // New evidence inside the reader's view ends the snapshot: restart the query.
    let a = w.hub.snapshot(&w.a1).unwrap();
    batch["device"] = a["device"]["id"].clone();
    batch["generation"] = a["device"]["generation"].clone();
    batch["sequence"] = json!(2);
    batch["scan"] = json!(uuid::Uuid::new_v4().to_string());
    w.hub.ingest(&ingest_secret("a1"), &batch).unwrap();
    assert_eq!(
        refusal(page(&w, &scope, &no_filter(), Some(1), Some(&cursor)).unwrap_err()),
        invented
    );

    // A cursor from the new snapshot, then the grant narrows (rows removed from the store).
    let fresh = next(&page(&w, &scope, &no_filter(), Some(1), None).unwrap()).unwrap();
    assert!(page(&w, &scope, &no_filter(), Some(1), Some(&fresh)).is_ok());
    let store = rusqlite::Connection::open(store_path(&w)).unwrap();
    store
        .execute(
            "UPDATE readers SET device_mode='listed' WHERE id=?",
            [&reader],
        )
        .unwrap();
    // Same devices and so the same snapshot, but a differently shaped grant (listed, not "all").
    for device in [&w.a1, &w.a2] {
        store
            .execute(
                "INSERT INTO reader_devices VALUES(?,?)",
                rusqlite::params![reader, device],
            )
            .unwrap();
    }
    drop(store);
    let narrowed = authorize(&w, READER_A).unwrap();
    assert_eq!(
        refusal(page(&w, &narrowed, &no_filter(), Some(1), Some(&fresh)).unwrap_err()),
        invented
    );
    assert_eq!(
        page(&w, &narrowed, &no_filter(), Some(1), None).unwrap()["total"],
        2
    );

    // A revoked reader gets the reader refusal for every cursor, real or invented, and nothing more.
    ReaderStore::open(&w.db).unwrap().revoke(&reader).unwrap();
    let real = refusal(page(&w, &narrowed, &no_filter(), Some(1), Some(&fresh)).unwrap_err());
    let fake = refusal(page(&w, &narrowed, &no_filter(), Some(1), Some("AAAA")).unwrap_err());
    assert_eq!(real, fake);
    assert_eq!(real.0, Some(401));
}

#[test]
fn page_size_defaults_to_fifty_is_capped_at_one_hundred_and_has_a_byte_budget() {
    let w = world();
    let big = |tag: &str, n: usize, pad: usize| -> Vec<String> {
        (0..n)
            .map(|i| format!("{tag}-{i:04}{}", "k".repeat(pad)))
            .collect()
    };
    let owned = big("bulk", 130, 0);
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    enroll(&w.hub, ORG, "site-c", "bulk", &refs);
    grant(&w, READER_A, &["site-c"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();

    let default = page(&w, &scope, &no_filter(), None, None).unwrap();
    assert_eq!(
        (keys(&default).len(), default["total"].as_i64()),
        (50, Some(130))
    );
    assert_eq!(
        page(&w, &scope, &no_filter(), Some(1000), None).unwrap()["findings"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    assert_eq!(
        page(&w, &scope, &no_filter(), Some(0), None)
            .unwrap_err()
            .http_status,
        Some(400)
    );
    assert_eq!(walk(&w, &scope, &no_filter(), 100).len(), 130);

    // Long fields: a page ends at the byte budget, nothing is dropped, and the walk still completes.
    let fat_names = big("fat", 120, 200);
    let fat: Vec<&str> = fat_names.iter().map(String::as_str).collect();
    enroll(&w.hub, ORG, "site-d", "fat", &fat);
    grant(&w, READER_B, &["site-d"], &[], 3600.0);
    let scope = authorize(&w, READER_B).unwrap();
    let first = page(&w, &scope, &no_filter(), Some(100), None).unwrap();
    assert!(
        keys(&first).len() < 100,
        "the byte budget ended the page early"
    );
    assert!(next(&first).is_some());
    assert!(first.to_string().len() <= 64 * 1024);
    let all = walk(&w, &scope, &no_filter(), 100);
    let mut unique = all.clone();
    unique.sort();
    unique.dedup();
    assert_eq!((all.len(), unique.len()), (120, 120));
}

fn ingest_at(w: &World, credential: &str, device: &str, sequence: i64) {
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/link-v1.json")).unwrap();
    let snapshot = w.hub.snapshot(device).unwrap();
    batch["device"] = snapshot["device"]["id"].clone();
    batch["generation"] = snapshot["device"]["generation"].clone();
    batch["sequence"] = json!(sequence);
    batch["scan"] = json!(uuid::Uuid::new_v4().to_string());
    batch["observed"] = json!(vorda::store::now());
    w.hub.ingest(credential, &batch).unwrap();
}

#[test]
fn a_device_sequence_at_the_64_bit_maximum_does_not_break_the_list_and_changes_stay_visible() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let before = page(&w, &scope, &no_filter(), Some(2), None).unwrap();

    // An enrolled device may choose any positive sequence. Two devices in one view must still list.
    ingest_at(&w, &ingest_secret("a1"), &w.a1, i64::MAX);
    ingest_at(&w, &ingest_secret("a2"), &w.a2, 5);
    let after = page(&w, &scope, &no_filter(), Some(2), None).unwrap();
    assert_eq!(after["total"], 2);
    assert_ne!(
        before["revision"], after["revision"],
        "a change inside the view moves the revision"
    );
    assert_eq!(
        after["revision"],
        page(&w, &scope, &no_filter(), Some(2), None).unwrap()["revision"],
        "and nothing else does"
    );
    assert_eq!(walk(&w, &scope, &no_filter(), 1).len(), 2);
}

#[test]
fn the_page_says_why_it_ended_and_counts_its_envelope_in_the_byte_budget() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let limited = page(&w, &scope, &no_filter(), Some(2), None).unwrap();
    assert_eq!(limited["page_end"], "limit");
    let last = page(&w, &scope, &no_filter(), Some(2), next(&limited).as_deref()).unwrap();
    assert_eq!(last["page_end"], "last");
    assert_eq!(
        page(&w, &scope, &no_filter(), Some(100), None).unwrap()["page_end"],
        "last"
    );

    let fat_names: Vec<String> = (0..120)
        .map(|i| format!("fat-{i:04}{}", "k".repeat(200)))
        .collect();
    let fat: Vec<&str> = fat_names.iter().map(String::as_str).collect();
    enroll(&w.hub, ORG, "site-d", "fat", &fat);
    grant(&w, READER_B, &["site-d"], &[], 3600.0);
    let scope = authorize(&w, READER_B).unwrap();
    let first = page(&w, &scope, &no_filter(), Some(100), None).unwrap();
    assert_eq!(first["page_end"], "bytes");
    assert!(
        first.to_string().len() <= 64 * 1024,
        "the whole response fits the budget"
    );
}

#[test]
fn filter_lists_are_bounded_and_empty_values_match_nothing() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let many = |n: usize| (0..n).map(|i| format!("device-{i}")).collect::<Vec<_>>();
    let too_many_devices = FindingFilter {
        devices: many(257),
        ..Default::default()
    };
    assert_eq!(
        page(&w, &scope, &too_many_devices, None, None)
            .unwrap_err()
            .http_status,
        Some(400)
    );
    let too_many_sites = FindingFilter {
        sites: many(65),
        ..Default::default()
    };
    assert_eq!(
        page(&w, &scope, &too_many_sites, None, None)
            .unwrap_err()
            .http_status,
        Some(400)
    );
    let at_the_limit = FindingFilter {
        devices: many(256),
        ..Default::default()
    };
    assert_eq!(
        page(&w, &scope, &at_the_limit, None, None).unwrap()["total"],
        0
    );

    for filter in [
        FindingFilter {
            name: Some(String::new()),
            ..Default::default()
        },
        FindingFilter {
            advisory: Some(String::new()),
            ..Default::default()
        },
    ] {
        assert_eq!(page(&w, &scope, &filter, None, None).unwrap()["total"], 0);
    }
    // The advisory filter says what it matches, so a zero is not read as "unaffected".
    let by_alias = FindingFilter {
        advisory: Some("GHSA-0000-0000-0000".into()),
        ..Default::default()
    };
    let view = page(&w, &scope, &by_alias, None, None).unwrap();
    assert_eq!(view["total"], 0);
    assert!(view["filter_semantics"]["advisory"]
        .as_str()
        .unwrap()
        .contains("stored advisory field"));
}

#[test]
fn a_cursor_expires_after_an_hour_and_is_not_accepted_from_the_future() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let scope = authorize(&w, READER_A).unwrap();
    let t = vorda::store::now();
    let at = |now: f64, cursor: Option<&str>| {
        visible_findings(
            &w.hub,
            &scope,
            &no_filter(),
            &PageRequest {
                limit: Some(1),
                cursor,
            },
            now,
        )
    };
    let cursor = next(&at(t, None).unwrap()).unwrap();
    let invented = refusal(at(t, Some("AAAA")).unwrap_err());
    assert!(at(t + 3000.0, Some(&cursor)).is_ok(), "within the hour");
    assert_eq!(
        refusal(at(t + 3700.0, Some(&cursor)).unwrap_err()),
        invented,
        "an old cursor"
    );
    assert_eq!(
        refusal(at(t - 1000.0, Some(&cursor)).unwrap_err()),
        invented,
        "a cursor from the future"
    );
}
