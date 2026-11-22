use serde_json::{json, Value};
use vorda::{
    domain::Package,
    scanner::feeds::{self, FeedSource},
    Result,
};
struct Feed {
    withdrawn_a: bool,
    withdrawn_b: bool,
}
impl FeedSource for Feed {
    fn get(&mut self, url: &str, _: Option<&Value>) -> Result<Value> {
        let data = if url == feeds::KEV {
            json!({"vulnerabilities":[]})
        } else if url.starts_with(feeds::EPSS) {
            json!({"data":[]})
        } else if url.ends_with("/querybatch") {
            json!({"results":[{"vulns":[{"id":"GHSA-a"},{"id":"GHSA-b"}]}]})
        } else {
            let a = url.ends_with("GHSA-a");
            json!({"id":if a {"GHSA-a"}else{"GHSA-b"},"aliases":["CVE-FIXTURE-BRIDGE"],"withdrawn":if if a {self.withdrawn_a}else{self.withdrawn_b} {json!("2026-11-04T00:00:00Z")}else{Value::Null},"affected":[{"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":if a {"1.0.0"}else{"2.0.0"}},{"fixed":if a {"1.2.0"}else{"2.4.0"}}]}]}]})
        };
        Ok(json!({"data":data,"source_url":url,"fetched_at":"2026-11-04T00:00:00Z"}))
    }
}
#[test]
fn withdrawn_alias_bridges_preserve_only_live_candidate_branches() {
    for (a, b) in [(false, false), (true, false), (false, true), (true, true)] {
        let package: Package=serde_json::from_value(json!({"name":"example","version":"1.1.0","ecosystem":"npm","path":"/selected/package-lock.json","scope":"runtime"})).unwrap();
        let result = feeds::scan(
            &[package],
            &mut Feed {
                withdrawn_a: a,
                withdrawn_b: b,
            },
        )
        .unwrap();
        assert_eq!(result["errors"], json!([]));
        let findings = result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), usize::from(!(a && b)));
        if let Some(f) = findings.first() {
            let fixed = f["fixed"].as_array().unwrap();
            assert_eq!(fixed.contains(&json!("1.2.0")), !a);
            assert_eq!(fixed.contains(&json!("2.4.0")), !b);
            assert_eq!(
                f["affected_ranges"].as_array().unwrap().len(),
                usize::from(!a) + usize::from(!b)
            );
            assert_eq!(f["alias_provenance"].as_array().unwrap().len(), 2);
            assert_eq!(
                f["fixed_applicability"],
                "candidate-versions-require-compatible-branch-and-rescan"
            );
        }
    }
}
