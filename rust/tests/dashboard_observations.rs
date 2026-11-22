use serde_json::json;
use vorda::{store::Store, surfaces::dashboard::data};

#[test]
fn saved_static_observations_keep_item_identity_without_advisory_guidance() {
    for kind in ["mcp", "skill", "cli"] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let mut findings = Vec::new();
        for (key, asset, item, source) in [
            ("alpha-first", "alpha", "alpha", "/tools/config.json"),
            ("alpha-repeat", "alpha", "alpha", "/tools/config.json"),
            ("beta", "beta", "beta", "/tools/config.json"),
            ("other-source", "", "alpha", "/other/config.json"),
            ("no-asset", "", "alpha", "/tools/config.json"),
        ] {
            findings.push(
                json!({
                    "key":key,"asset":asset,"kind":kind,"host":"fixture-host",
                    "source":"agentbom","source_file":source,"path":source,"item":item,
                    "rule":"AB-P1","evidence_basis":"static-text-pattern",
                    "title":format!("{kind} {item}: Hides actions from the user"),
                    "why":"Text an agent reads tells it to keep something from you.",
                    "evidence":"never tell the user"
                })
                .as_object()
                .unwrap()
                .clone(),
            );
        }
        store
            .reconcile(&findings, &Default::default(), &[])
            .unwrap();
        let snapshot = data::snapshot(temp.path(), 1000., None).unwrap();
        let issues = snapshot["issues"].as_array().unwrap();
        assert_eq!(issues.len(), 4, "{kind}: {issues:#?}");
        let repeated = issues.iter().find(|i| i["count"] == 2).unwrap();
        assert_eq!(repeated["keys"], json!(["alpha-first", "alpha-repeat"]));
        for issue in issues {
            let title = issue["title"].as_str().unwrap();
            assert!(title.contains("alpha") || title.contains("beta"));
            assert!(title.contains("Hides actions from the user"));
            assert!(issue["why"]
                .as_str()
                .unwrap()
                .contains("keep something from you"));
            assert!(issue["path"].as_str().unwrap().ends_with("config.json"));
            assert_eq!(issue["advisories"], json!([]));
            assert_eq!(issue["installed"], "");
            assert_eq!(issue["target"], "");
            assert!(!issue.to_string().contains("known flaw"));
            assert!(!issue["fix"].as_str().unwrap().contains("fix ships"));
            assert!(issue["fix"].as_str().unwrap().contains("Review"));
        }
    }
}

#[test]
fn saved_agent_package_advisories_keep_grouping_and_fixed_version_guidance() {
    for kind in ["mcp", "skill", "cli"] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let findings: Vec<_> = ["GHSA-fixture-a", "GHSA-fixture-b"].into_iter().map(|advisory| {
            json!({"key":advisory,"asset":"package-asset","kind":kind,"host":"fixture-host",
                "advisory":advisory,"title":"Package advisory",
                "package":{"name":"example-tool","version":"1.0.0","path":"/tools/package.json","ecosystem":"npm"},
                "fixed":["1.2.0"],"severity":[],"kev":true})
                .as_object().unwrap().clone()
        }).collect();
        store
            .reconcile(&findings, &Default::default(), &[])
            .unwrap();
        let snapshot = data::snapshot(temp.path(), 1000., None).unwrap();
        let issues = snapshot["issues"].as_array().unwrap();
        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue["count"], 2);
        assert!(issue["title"]
            .as_str()
            .unwrap()
            .contains("example-tool has 2 known flaws"));
        assert_eq!(issue["fix"], "Update example-tool to 1.2.0");
        assert_eq!(issue["installed"], "1.0.0");
        assert_eq!(issue["target"], "1.2.0");
        assert_eq!(issue["advisories"].as_array().unwrap().len(), 2);
        assert_eq!(issue["path"], "/tools/package.json");
        assert_eq!(issue["kev"], true);
    }
}
