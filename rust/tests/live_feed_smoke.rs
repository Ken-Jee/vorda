//! Live-feed smoke test. Ignored by default: it needs network access to the
//! public OSV, KEV and EPSS feeds and never mocks them. Run it explicitly:
//!
//! ```text
//! cargo nextest run --test live_feed_smoke --run-ignored only
//! # or: cargo test --test live_feed_smoke -- --ignored
//! ```
//!
//! On a feed outage the test fails; retry later rather than faking the feed.
use serde_json::{json, Value};
use std::fs;
use vorda::{cli, domain::ScanOptions, scanner::outputs::timestamp_at, store::Store};

#[test]
#[ignore = "needs network access to the live OSV feed"]
fn live_osv_feed_reports_minimist_prototype_pollution() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("synthetic-project");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("package.json"),
        json!({"name":"synthetic-live-feed","version":"1.0.0","dependencies":{"minimist":"1.2.5"}})
            .to_string(),
    )
    .unwrap();
    let lock = root.join("package-lock.json");
    fs::write(
        &lock,
        json!({
            "name": "synthetic-live-feed",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {"name": "synthetic-live-feed", "version": "1.0.0", "dependencies": {"minimist": "1.2.5"}},
                "node_modules/minimist": {"version": "1.2.5"}
            }
        })
        .to_string(),
    )
    .unwrap();
    let mut store = Store::open(&t.path().join("state")).unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![lock];
    assert!(!options.offline, "this test must reach the live feed");

    let result = cli::check(&options, &mut store).unwrap();
    assert!(
        result["errors"].as_array().unwrap().is_empty(),
        "live feed unavailable or invalid (retry later, do not fake): {result:?}"
    );

    let finding = store
        .active()
        .unwrap()
        .into_iter()
        .map(Value::Object)
        .find(|f| {
            f["package"]["name"] == "minimist"
                && (f["advisory"] == "CVE-2021-44906"
                    || f["aliases"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|x| x == "CVE-2021-44906")))
        })
        .unwrap_or_else(|| panic!("no CVE-2021-44906 finding for minimist 1.2.5: {result:?}"));

    let sources = finding["source_url"].as_array().expect("source_url list");
    assert!(
        sources.iter().any(|s| s
            .as_str()
            .is_some_and(|s| s.starts_with("https://api.osv.dev/v1/vulns/"))),
        "finding is not sourced from the live OSV feed: {finding}"
    );
    let fetched = finding["fetched_at"].as_str().unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    // Fixed-width UTC timestamps order the same as the instants they name.
    let (oldest, newest) = (timestamp_at(now - 86_400.0), timestamp_at(now + 300.0));
    assert!(
        fetched.len() == 20 && fetched >= oldest.as_str() && fetched <= newest.as_str(),
        "feed timestamp is missing or not from the last day: {}",
        finding["fetched_at"]
    );
}
