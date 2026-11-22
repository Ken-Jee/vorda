use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use vorda::{
    scanner::{feeds::KEV, priority},
    store::identity,
    surfaces::dashboard::feed,
};
#[test]
fn public_feed_has_dates_limits_and_private_local_matching() {
    let t = tempfile::tempdir().unwrap();
    let now = vorda::store::now();
    assert_eq!(
        feed::saved(t.path(), now, &BTreeMap::new()).unwrap()["status"],
        "unavailable"
    );
    std::fs::create_dir(t.path().join("cache")).unwrap();
    let path = t
        .path()
        .join("cache")
        .join(format!("{}.json", identity(&json!([KEV, null])).unwrap()));
    std::fs::write(path,json!({"checked":now-172800.0,"data":{"vulnerabilities":[{"cveID":"CVE-FIXTURE-A","vulnerabilityName":"General update","dateAdded":"2026-11-03"},{"cveID":"CVE-FIXTURE-B","vulnerabilityName":"Matched update","dateAdded":"2026-11-04"}]}}).to_string()).unwrap();
    let feed = feed::saved(
        t.path(),
        now,
        &BTreeMap::from([(
            "CVE-FIXTURE-B".into(),
            BTreeSet::from(["selected-host".into()]),
        )]),
    )
    .unwrap();
    assert_eq!(feed["status"], "stale");
    assert_eq!(feed["items"][0]["mine"], true);
    assert_eq!(feed["items"][1]["mine"], false);
    assert_eq!(feed["items"][1]["published"], "2026-11-03");
}
#[test]
fn unsupported_scoring_keeps_evidence_and_does_not_turn_low_epss_into_low_severity() {
    let result = priority::priority(
        &json!({"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N"}],"epss":0.001,"kev":null}),
    );
    assert_eq!(result["level"], "unknown");
    assert_eq!(
        result["scoring_reason"],
        "unsupported-or-invalid-severity-vector"
    );
    assert_eq!(result["kev"], json!(null));
    assert_eq!(result["severity_evidence"][0]["type"], "CVSS_V4");
    assert_eq!(
        priority::priority(&json!({"severity":[],"kev":true}))["level"],
        "critical"
    );
}

#[test]
fn alias_feed_matching_uses_only_selected_saved_findings() {
    let t = tempfile::tempdir().unwrap();
    let mut store = vorda::store::Store::open(t.path()).unwrap();
    let now = vorda::store::now();
    std::fs::create_dir_all(t.path().join("cache")).unwrap();
    std::fs::write(t.path().join("cache").join(format!("{}.json",identity(&json!([KEV,null])).unwrap())),json!({"checked":now,"data":{"vulnerabilities":[{"cveID":"CVE-FIXTURE-ALIAS","dateAdded":"2026-11-04"}]}}).to_string()).unwrap();
    store.reconcile(&[json!({"key":"one","asset":"asset","scan_scope":"selected","host":"local","title":"example","advisory":"GHSA-fixture","aliases":["CVE-FIXTURE-ALIAS"],"package":{"name":"example","version":"1","ecosystem":"npm","path":"/selected/package-lock.json"}}).as_object().unwrap().clone()],&BTreeSet::new(),&[]).unwrap();
    let package = serde_json::from_value(json!({"name":"example","version":"1","ecosystem":"npm","path":"/selected/package-lock.json","scope":"runtime"})).unwrap();
    let asset = vorda::store::asset(&package).unwrap();
    let rows = vorda::assets::observations(&[package], &[], Some("local")).unwrap();
    vorda::assets::save(
        &mut store,
        "selected",
        &rows,
        &BTreeSet::from([asset.clone()]),
        true,
        Some(now),
    )
    .unwrap();
    store
        .db
        .execute(
            "UPDATE findings SET payload=json_set(payload,'$.asset',?1)",
            [asset],
        )
        .unwrap();
    let selected = feed_snapshot(t.path(), now, "selected");
    assert_eq!(selected["news"][0]["mine"], true, "{selected}");
    let unrelated = feed_snapshot(t.path(), now, "other");
    assert_eq!(unrelated["news"][0]["mine"], false);
}
#[test]
fn unreadable_feed_cache_is_refetched_and_replaced() {
    use std::io::{Read, Write};
    use vorda::scanner::feeds::{FeedSource, Fetch};
    for hard_linked in [false, true] {
        let t = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/feed.json", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let body = r#"{"fresh":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let cache = t
            .path()
            .join(format!("{}.json", identity(&json!([url, null])).unwrap()));
        let other = t.path().join("other.json");
        if hard_linked {
            std::fs::write(&other, r#"{"stale":true}"#).unwrap();
            std::fs::hard_link(&other, &cache).unwrap();
        } else {
            std::fs::write(&cache, "{\"truncated").unwrap();
        }
        let fetched = Fetch::new(t.path(), false).get(&url, None).unwrap();
        server.join().unwrap();
        assert_eq!(fetched["data"], json!({"fresh":true}), "{hard_linked}");
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
        assert_eq!(saved["data"], json!({"fresh":true}), "{hard_linked}");
        if hard_linked {
            assert_eq!(
                std::fs::read_to_string(&other).unwrap(),
                r#"{"stale":true}"#
            );
        }
    }
}
fn feed_snapshot(path: &std::path::Path, now: f64, scope: &str) -> serde_json::Value {
    vorda::surfaces::dashboard::data::snapshot(path, now, Some(&BTreeSet::from([scope.into()])))
        .unwrap()
}
