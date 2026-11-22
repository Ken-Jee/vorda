use serde_json::{json, Value};
use std::collections::BTreeSet;
use vorda::{
    domain::Package,
    scanner::{browsers, feeds::FeedSource},
    Result,
};
struct Feed(u8);
impl FeedSource for Feed {
    fn nvd_pause(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    fn get(&mut self, _: &str, _: Option<&Value>) -> Result<Value> {
        let count = 20;
        let mut response = json!({"data":{"vulnerabilities":(0..count).map(|n|json!({"cve":{"id":format!("CVE-FIXTURE-{n}"),"configurations":[{"nodes":[{"operator":if self.0==1 {"AND"}else{"OR"},"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionStartIncluding":"105.0.0.0","versionEndExcluding":if self.0 == 6 && n == 0 {"108.0.0.0"}else{"110.0.0.0"}}]}]}]}})).collect::<Vec<_>>(),"resultsPerPage":count,"totalResults":count}});
        for (n, entry) in response["data"]["vulnerabilities"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            let node = &mut entry["cve"]["configurations"][0]["nodes"][0];
            match self.0 {
                2 => node["negate"] = json!(true),
                3 => node["nodes"] = json!([{"operator":"OR"}]),
                4 => node["cpeMatch"][0]["vulnerable"] = json!(false),
                5 => {
                    node["cpeMatch"][0]["criteria"] =
                        json!("cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*")
                }
                6 if n > 1 => {
                    node["cpeMatch"][0]["criteria"] =
                        json!("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*")
                }
                _ => {}
            }
        }
        Ok(response)
    }
}
#[test]
fn each_chrome_advisory_reports_its_own_fixed_version() {
    for (version, expected) in [
        ("104.0.0.0", vec![]),
        (
            "105.0.0.0",
            vec![
                ("CVE-FIXTURE-0", "108.0.0.0"),
                ("CVE-FIXTURE-1", "110.0.0.0"),
            ],
        ),
        (
            "107.0.0.0",
            vec![
                ("CVE-FIXTURE-0", "108.0.0.0"),
                ("CVE-FIXTURE-1", "110.0.0.0"),
            ],
        ),
        ("108.0.0.0", vec![("CVE-FIXTURE-1", "110.0.0.0")]),
        ("110.0.0.0", vec![]),
    ] {
        let p: Package = serde_json::from_value(json!({"name":"chrome","version":version,"ecosystem":"Chromium","path":"/selected/chrome","scope":"runtime"})).unwrap();
        let mut findings = vec![];
        browsers::advisories(
            &[p],
            &mut Feed(6),
            &BTreeSet::new(),
            true,
            &mut findings,
            &mut BTreeSet::new(),
            &mut vec![],
            &mut vec![],
            &mut vec![],
        )
        .unwrap();
        let actual: Vec<_> = findings
            .iter()
            .map(|f| {
                (
                    f["advisory"].as_str().unwrap(),
                    f["fixed"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(actual, expected, "installed {version}");
    }
}
#[test]
fn chromium_ranges_and_limited_history_are_explicit() {
    for (version, unsupported, expected) in [
        ("100.0.0.0", 0, 0),
        ("107.0.0.0", 0, 20),
        ("110.0.0.0", 0, 0),
        ("107.0.0.0", 1, 0),
        ("107.0.0.0", 2, 0),
        ("107.0.0.0", 3, 0),
        ("107.0.0.0", 4, 0),
        ("107.0.0.0", 5, 0),
    ] {
        let p:Package=serde_json::from_value(json!({"name":"chrome","version":version,"ecosystem":"Chromium","path":"/selected/chrome","scope":"runtime"})).unwrap();
        let (mut findings, mut covered, mut errors, mut sources) =
            (vec![], BTreeSet::new(), vec![], vec![]);
        browsers::advisories(
            &[p],
            &mut Feed(unsupported),
            &BTreeSet::new(),
            true,
            &mut findings,
            &mut covered,
            &mut vec![],
            &mut errors,
            &mut sources,
        )
        .unwrap();
        assert_eq!(
            findings.len(),
            expected,
            "{version} unsupported={unsupported}"
        );
        assert!(
            covered.is_empty(),
            "119 publication days is not full history"
        );
        assert!(errors.iter().any(|e| e["coverage"] == "limited-history"));
    }
}
