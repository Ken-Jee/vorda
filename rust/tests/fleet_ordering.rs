//! Ordering and re-export at the v2 hub: an older revision arriving late, the same assessment sent
//! again, and an observation time far ahead of the clock. What a reader sees is asserted, not the
//! tables. Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use vorda::{
    fleet::{
        auth::AuthorizedScope,
        coverage::{
            visible_inventory, visible_sources, FreshnessPolicy, InventoryFilter, SourceFilter,
        },
        history::{fleet_changes, ChangeFilter, Since},
        query::PageRequest,
    },
    link::native::{Admission, TrustedCapture},
};

const POLICY: FreshnessPolicy = FreshnessPolicy {
    fresh_for_secs: 36 * 3600,
};
const L2: &[u8] = include_bytes!("fixtures/capture/L2.json"); // samepackage 2.0.0
const PAGE: PageRequest = PageRequest {
    limit: Some(100),
    cursor: None,
};

fn on_a1<'a>(w: &'a World, t: f64) -> Delivery<'a> {
    Delivery {
        device: &w.a1,
        org: ORG,
        site: "site-a",
        scope: "scope-1",
        source: "npm-a",
        observed: Some(t),
        inputs: &["one"],
    }
}
fn reader(w: &World) -> AuthorizedScope {
    grant(w, READER_A, &["site-a"], &[], 3600.0);
    authorize(w, READER_A).unwrap()
}
/// What a reader of site-a sees at `at`: the source row of a1/scope-1, the inventory and the changes.
struct Seen {
    source: Value,
    inventory: Value,
    changes: Value,
}
fn seen(w: &World, scope: &AuthorizedScope, at: f64) -> Seen {
    let sources =
        visible_sources(&w.hub, scope, &SourceFilter::default(), &POLICY, &PAGE, at).unwrap();
    let source = sources["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["scope"] == "scope-1" && r["device"] == w.a1.as_str())
        .unwrap_or_else(|| panic!("no source row: {sources}"))
        .clone();
    Seen {
        source,
        inventory: visible_inventory(
            &w.hub,
            scope,
            &InventoryFilter::default(),
            &POLICY,
            &PAGE,
            at,
        )
        .unwrap(),
        changes: fleet_changes(
            &w.hub,
            scope,
            &ChangeFilter::default(),
            &Since::Start,
            &PAGE,
            at,
        )
        .unwrap(),
    }
}
fn versions(inventory: &Value) -> Vec<String> {
    let mut v: Vec<String> = inventory["inventory"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["package"]["name"]["quoted"] == "samepackage")
        .map(|r| {
            r["package"]["version"]["quoted"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    v.sort();
    v
}
fn received(t: f64) -> String {
    format!("{t:.9}")
}
fn ack(bytes: Vec<u8>) -> Value {
    serde_json::from_slice(&bytes).unwrap()
}
fn with_sequence(wire: &[u8], sequence: i64) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(wire).unwrap();
    v["sequence"] = json!(sequence);
    canonical(&v)
}

#[test]
fn an_older_revision_arriving_after_a_newer_one_cannot_erase_the_current_state() {
    let w = world();
    let t = vorda::store::now().floor();
    // The producer captured revision 1 (samepackage 1.0.0), then revision 2 (2.0.0); the hub is
    // sent revision 2 first, so revision 1 reaches it at a later delivery sequence.
    let (b1, e1, raw1, wire1) = w.v2_request(&on_a1(&w, t - 7200.0), 2, L1);
    let (b2, e2, raw2, wire2) = w.v2_request(&on_a1(&w, t - 3600.0), 1, L2);
    let admission = Admission::open(
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
    let scope = reader(&w);
    let at = t;

    let newer = ack(admission.admit_at(&wire2, &received(t - 600.0)).unwrap());
    assert_eq!(
        (newer["result"].as_str(), newer["revision"].as_i64()),
        (Some("published"), Some(2))
    );
    let before = seen(&w, &scope, at);
    assert_eq!(versions(&before.inventory), ["2.0.0"]);

    let older = ack(admission.admit_at(&wire1, &received(t - 300.0)).unwrap());
    assert_eq!(
        (older["result"].as_str(), older["revision"].as_i64()),
        (Some("historical_only"), Some(1)),
        "{older}"
    );
    // The ack names the snapshot the reader still sees, not a new one.
    assert_eq!(older["snapshot_id"], newer["snapshot_id"]);
    assert_eq!(older["snapshot_revision"], newer["snapshot_revision"]);

    let after = seen(&w, &scope, at);
    assert_eq!(
        versions(&after.inventory),
        ["2.0.0"],
        "the old version came back"
    );
    assert_eq!(after.inventory["inventory"], before.inventory["inventory"]);
    for field in [
        "assessment_revision",
        "observed_at",
        "age_seconds",
        "freshness",
        "coverage",
        "records",
    ] {
        assert_eq!(
            after.source[field], before.source[field],
            "source {field} changed"
        );
    }
    assert_eq!(after.source["assessment_revision"], 2);
}

#[test]
fn a_late_older_revision_is_part_of_the_change_history_not_a_false_addition() {
    let w = world();
    let t = vorda::store::now().floor();
    let (b1, e1, raw1, wire1) = w.v2_request(&on_a1(&w, t - 7200.0), 2, L1);
    let (b2, e2, raw2, wire2) = w.v2_request(&on_a1(&w, t - 3600.0), 1, L2);
    let admission = Admission::open(
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
    let scope = reader(&w);
    admission.admit_at(&wire2, &received(t - 600.0)).unwrap();
    let before = seen(&w, &scope, t);
    admission.admit_at(&wire1, &received(t - 300.0)).unwrap();
    let after = seen(&w, &scope, t);
    assert_eq!(before.changes["window"]["unavailable_total"], 1);
    // The true history is 1.0.0 then 2.0.0: the late revision is in the walk, so revision 2 is an
    // upgrade of what revision 1 held and is never reported as new.
    let rows = after.changes["changes"].as_array().unwrap();
    let version = |c: &Value| {
        c["package"]["version"]["quoted"]
            .as_str()
            .map(str::to_string)
    };
    assert!(
        !rows
            .iter()
            .any(|c| c["kind"] == "added" && version(c).as_deref() == Some("2.0.0")),
        "{rows:?}"
    );
    let upgrade = rows
        .iter()
        .find(|c| version(c).as_deref() == Some("2.0.0"))
        .unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!(upgrade["previous_assessment_revision"], 1, "{upgrade}");
    assert_eq!(upgrade["previous_version"]["quoted"], "1.0.0", "{upgrade}");
    assert_eq!(upgrade["assessment_revision"], 2);
    assert_eq!(after.changes["window"]["unavailable_total"], 0);
    // The late row says so; the row of the in-order revision does not.
    assert_eq!(upgrade["late"], false, "{upgrade}");
    let added = rows
        .iter()
        .find(|c| version(c).as_deref() == Some("1.0.0"))
        .unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!(added["late"], true, "{added}");
    assert_eq!(after.changes["retention"]["late_assessments"], 1);
    assert!(after.changes["retention"]
        .get("historical_only_assessments_not_compared")
        .is_none());
    // Windowed by receipt time, the late row shows alone and is marked, so a client polling by
    // `since` can tell it is not the newest state.
    let window = fleet_changes(
        &w.hub,
        &scope,
        &ChangeFilter::default(),
        &Since::Time(t - 450.0),
        &PAGE,
        t,
    )
    .unwrap();
    let only = window["changes"].as_array().unwrap();
    assert_eq!(only.len(), 1, "{window}");
    assert_eq!(only[0]["assessment_revision"], 1);
    assert_eq!(only[0]["late"], true);
}

#[test]
fn the_same_assessment_sent_again_under_a_newer_sequence_keeps_its_observation_time() {
    let w = world();
    let t = vorda::store::now().floor();
    let old = t - 40.0 * 86400.0;
    let (binding, evidence, raw, wire) = w.v2_request(&on_a1(&w, old), 1, L1);
    let admission = Admission::open(
        &w.db,
        vec![TrustedCapture {
            binding,
            evidence_id: evidence,
            artifact_utf8: raw,
        }],
    )
    .unwrap();
    let scope = reader(&w);

    let first = ack(admission.admit_at(&wire, &received(t - 1000.0)).unwrap());
    let before = seen(&w, &scope, t);
    assert_eq!(before.source["freshness"], "stale");

    let again = ack(admission
        .admit_at(&with_sequence(&wire, 2), &received(t - 10.0))
        .unwrap());
    // One assessment, delivered twice: the same acknowledged result, at the new sequence.
    assert_eq!(again["sequence"], 2);
    for field in [
        "assessment_id",
        "revision",
        "result",
        "snapshot_id",
        "received_at",
    ] {
        assert_eq!(again[field], first[field], "{field}");
    }
    let after = seen(&w, &scope, t);
    for field in [
        "observed_at",
        "age_seconds",
        "freshness",
        "assessment_revision",
    ] {
        assert_eq!(after.source[field], before.source[field], "{field}");
    }
    assert_eq!(
        after.source["freshness"], "stale",
        "a re-sent old result is not fresh"
    );
    assert_eq!(after.inventory["inventory"], before.inventory["inventory"]);
    assert_eq!(after.changes["changes"], before.changes["changes"]);
}

#[test]
fn a_new_assessment_of_an_old_observation_is_received_now_but_stays_stale() {
    let w = world();
    let t = vorda::store::now().floor();
    let old = t - 40.0 * 86400.0;
    let (b1, e1, raw1, wire1) = w.v2_request(&on_a1(&w, old), 1, L1);
    // The same old observation time, re-captured and delivered later: a new assessment (and the
    // known limit of the v1 export, which takes a file's modification time as observation time).
    let (b2, e2, raw2, wire2) = w.v2_request(&on_a1(&w, old), 2, L2);
    let admission = Admission::open(
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
    let scope = reader(&w);

    admission.admit_at(&wire1, &received(t - 1000.0)).unwrap();
    let before = seen(&w, &scope, t);
    admission.admit_at(&wire2, &received(t - 10.0)).unwrap();
    let after = seen(&w, &scope, t);

    assert_eq!(after.source["assessment_revision"], 2);
    assert_eq!(after.source["observed_at"], before.source["observed_at"]);
    assert_eq!(after.source["freshness"], "stale", "{}", after.source);
    assert!(after.source["age_seconds"].as_f64().unwrap() > 39.0 * 86400.0);
    assert_eq!(
        after.source["last_received"].as_f64().unwrap(),
        t - 10.0,
        "the hub's receipt time moves; the observation time does not"
    );
    assert!(before.source["last_received"].as_f64().unwrap() < t - 10.0);
    assert_eq!(versions(&after.inventory), ["2.0.0"]);
}

#[test]
fn an_observation_far_ahead_of_the_clock_is_read_as_future_and_never_fresh() {
    let w = world();
    let t = vorda::store::now().floor();
    let year = 365.0 * 86400.0;
    w.deliver(&on_a1(&w, t + year), 1).unwrap();
    let scope = reader(&w);
    let seen_now = seen(&w, &scope, t);
    assert_eq!(
        seen_now.source["freshness"], "future",
        "{}",
        seen_now.source
    );
    let components = seen_now.inventory["inventory"].as_array().unwrap();
    assert!(!components.is_empty());
    for c in components
        .iter()
        .filter(|c| c["package"]["name"]["quoted"] == "samepackage")
    {
        assert_eq!(c["freshness"], "future", "{c}");
    }
    // Only the clock catching up makes it fresh; a filter for fresh sources does not list it.
    let fresh = visible_sources(
        &w.hub,
        &scope,
        &SourceFilter {
            freshness: Some("fresh".into()),
            ..Default::default()
        },
        &POLICY,
        &PAGE,
        t,
    )
    .unwrap();
    assert!(
        fresh["sources"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["scope"] != "scope-1"),
        "{fresh}"
    );
}
