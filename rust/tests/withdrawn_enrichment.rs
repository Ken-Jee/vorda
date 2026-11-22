use serde_json::{json, Value};
use vorda::{
    domain::Package,
    scanner::feeds::{self, FeedSource},
    Result,
};

struct Feed {
    live_cve: bool,
    epss: bool,
}
impl FeedSource for Feed {
    fn get(&mut self, url: &str, _: Option<&Value>) -> Result<Value> {
        let data = if url == feeds::KEV {
            json!({"vulnerabilities":if self.epss {vec![]} else {vec![json!({"cveID":"CVE-2026-0001"})]}})
        } else if url.starts_with(feeds::EPSS) {
            json!({"data":if self.epss {vec![json!({"cve":"CVE-2026-0001","epss":"0.9"})]} else {vec![]}})
        } else if url.ends_with("/querybatch") {
            json!({"results":[{"vulns":[{"id":"GHSA-a"},{"id":"GHSA-b"}]}]})
        } else if url.ends_with("/vulns/GHSA-a") {
            json!({"id":"GHSA-a","aliases":["CVE-2026-0001"],"withdrawn":"2026-11-04T00:00:00Z","affected":[]})
        } else if url.ends_with("/vulns/GHSA-b") {
            json!({"id":"GHSA-b","aliases":if self.live_cve {vec!["CVE-2026-0001"]} else {vec![]},"upstream":["GHSA-a"],"affected":[{"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]}]})
        } else {
            panic!("unexpected feed route: {url}");
        };
        Ok(json!({"data":data,"source_url":url,"fetched_at":"2026-11-05T00:00:00Z"}))
    }
}
#[test]
fn withdrawn_only_identifiers_do_not_enrich_live_finding() {
    for live_cve in [false, true] {
        for epss in [false, true] {
            let package: Package = serde_json::from_value(json!({"name":"example","version":"1.1.0","ecosystem":"npm","path":"/selected/package-lock.json","scope":"runtime"})).unwrap();
            let result = feeds::scan(&[package], &mut Feed { live_cve, epss }).unwrap();
            assert_eq!(result["errors"], json!([]));
            let findings = result["findings"].as_array().unwrap();
            assert_eq!(findings.len(), 1);
            let f = &findings[0];
            assert_eq!(f["aliases"], json!(["CVE-2026-0001", "GHSA-a", "GHSA-b"]));
            assert_eq!(f["fixed"], json!(["1.2.0"]));
            assert_eq!(f["affected_ranges"].as_array().unwrap().len(), 1);
            let provenance = f["alias_provenance"].as_array().unwrap();
            assert_eq!(provenance.len(), 2);
            assert!(provenance
                .iter()
                .any(|p| p["id"] == "GHSA-a" && p["withdrawn"] == "2026-11-04T00:00:00Z"));
            assert!(provenance
                .iter()
                .any(|p| p["id"] == "GHSA-b" && p["withdrawn"].is_null()));
            if epss {
                assert_eq!(f["kev"], false);
                assert_eq!(f["epss"], if live_cve { json!(0.9) } else { Value::Null });
                assert_eq!(
                    f["priority"]["level"],
                    if live_cve { "high" } else { "unknown" }
                );
            } else {
                assert_eq!(f["kev"], live_cve);
                assert_eq!(f["epss"], Value::Null);
                assert_eq!(
                    f["priority"]["level"],
                    if live_cve { "critical" } else { "unknown" }
                );
            }
        }
    }
}
