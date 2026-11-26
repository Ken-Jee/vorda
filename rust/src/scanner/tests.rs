use crate::{domain::InventoryOptions, scanner};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "vorda-scanner-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/scanner/fixtures")
}
fn load_agent_fixture(root: &Path) {
    use base64::Engine;
    let files: Value = serde_json::from_str(include_str!("fixtures/agentbom-files.json")).unwrap();
    for file in files.as_array().unwrap() {
        let path = root.join(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        if file["directory"] == true {
            fs::create_dir_all(&path).unwrap();
            continue;
        }
        if file["fifo"] == true {
            #[cfg(unix)]
            {
                use std::{ffi::CString, os::unix::ffi::OsStrExt};
                let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            continue;
        }
        let bytes = if let Some(text) = file["text"].as_str() {
            text.replace("${ROOT}", &root.to_string_lossy().replace('\\', "/"))
                .into_bytes()
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(file["base64"].as_str().unwrap())
                .unwrap()
        };
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(file["mode"].as_u64().unwrap() as u32),
            )
            .unwrap();
        }
    }
}

#[test]
fn actual_lockfile_fixtures_match_expected_inventory() {
    let fixtures = fixtures().join("locks");
    let expected: Value = serde_json::from_str(include_str!("fixtures/locks.json")).unwrap();
    for (name, expected) in expected.as_object().unwrap() {
        let mut actual = scanner::inventory::lockfile(
            &fixtures.join(name),
            Some(Path::new(env!("CARGO_MANIFEST_DIR"))),
        )
        .unwrap();
        for p in &mut actual {
            p.path = name.clone();
        }
        assert_eq!(serde_json::to_value(actual).unwrap(), *expected, "{name}");
    }
}
#[test]
fn unresolved_directives_and_missing_roots_never_attest_complete() {
    let fixture = Fixture::new();
    let requirements = fixture.0.join("requirements.txt");
    fs::write(&requirements, "-r private.txt\nrequests==2.0.0\n").unwrap();
    let result = scanner::inventory(&InventoryOptions {
        roots: vec![fixture.0.clone()],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["input_evidence"]["status"], "partial");
    assert_eq!(result["packages"], json!([]));
    assert_eq!(result["completed_paths"], json!([]));
    fs::remove_file(&requirements).unwrap();
    fs::remove_dir(&fixture.0).unwrap();
    let result = scanner::inventory(&InventoryOptions {
        roots: vec![fixture.0.clone()],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["input_evidence"]["observations"], json!([]));
}
#[cfg(unix)]
#[test]
fn links_are_refused_without_reading_target() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let outside = Fixture::new();
    let target = outside.0.join("requirements.txt");
    fs::write(&target, "requests==2.0.0").unwrap();
    let link = fixture.0.join("requirements.txt");
    symlink(&target, &link).unwrap();
    assert!(scanner::inventory::lockfile(&link, None).is_err());
    let result = scanner::inventory(&InventoryOptions {
        roots: vec![fixture.0.clone()],
        ..Default::default()
    })
    .unwrap();
    assert_eq!(result["packages"], json!([]));
    assert_eq!(result["status"], "unknown");
    assert!(result["errors"].to_string().contains("requirements.txt"));
    assert!(result["errors"].to_string().contains("symbolic link"));
    let hard = fixture.0.join("other.txt");
    fs::hard_link(&target, &hard).unwrap();
    assert!(scanner::input::read_regular(&hard, None, 100, false).is_err());
}
#[test]
fn actual_agentbom_fixture_is_scanned_without_execution() {
    let fixture = Fixture::new();
    load_agent_fixture(&fixture.0);
    let expected: Value = serde_json::from_str(include_str!("fixtures/agentbom.json")).unwrap();
    let system = fixture.0.join("system");
    fs::create_dir(&system).unwrap();
    let bom = scanner::agentbom::collect_under(
        &system,
        &fixture.0.join("home"),
        &[fixture.0.join("proj")],
        "fixture",
        true,
    )
    .unwrap();
    assert!(bom.errors.is_empty(), "{:?}", bom.errors);
    let root = fixture.0.to_string_lossy();
    assert!(
        bom.read_files.iter().all(|f| f.starts_with(&*root)),
        "{:?}",
        bom.read_files
    );
    let raw = serde_json::to_string(&bom).unwrap();
    for credential in [
        "Zq8vK2mX9pL4rT7w",
        "Qm7Rt2Zx9Lp4Vb8Nc3Kd",
        "ghp_exampleexampleexampleexampleexampleexample",
        "sk-proj-exampleexampleexampleexampleexampleexample",
    ] {
        assert!(!raw.contains(credential));
    }
    let rules: std::collections::BTreeSet<_> = bom
        .findings
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["item"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(json!(rules), expected["rules"]);
    let packages: std::collections::BTreeSet<_> = bom
        .packages
        .iter()
        .map(|p| (&p.name, &p.version, &p.ecosystem))
        .collect();
    assert_eq!(json!(packages), expected["packages"]);
    let kinds: std::collections::BTreeSet<_> = bom
        .items
        .iter()
        .map(|i| i["kind"].as_str().unwrap())
        .collect();
    assert_eq!(json!(kinds), expected["kinds"]);
    assert!(!fixture.0.join("EXECUTED").exists());
}
#[test]
fn upstream_native_authority_retains_unknown_and_drops_only_fixed() {
    struct Feed(Value);
    impl scanner::feeds::FeedSource for Feed {
        fn get(&mut self, _: &str, _: Option<&Value>) -> crate::Result<Value> {
            Ok(json!({"data":self.0}))
        }
    }
    let p = crate::domain::Package {
        name: "busybox".into(),
        version: "1.36.1-r0".into(),
        ecosystem: "Alpine:v3.18".into(),
        path: "image".into(),
        scope: "reachable-unknown".into(),
        extra: Default::default(),
    };
    let aid = crate::store::asset(&p).unwrap();
    let f = json!({"key":"prior","asset":aid,"title":"busybox CVE","package":p,"advisory":"CVE-2022-48174","confidence":"upstream-version"});
    let mut feed = Feed(
        json!({"packages":[{"pkg":{"name":"busybox","secfixes":{"1.36.1-r1":["CVE-2022-48174"]}}}]}),
    );
    let (positive, audit, errors) =
        scanner::cpe::authoritative(std::slice::from_ref(&f), &mut feed).unwrap();
    assert_eq!(positive.len(), 1);
    assert!(audit.is_empty() && errors.is_empty());
    let mut updated = f.clone();
    updated["package"]["version"] = json!("1.36.1-r1");
    let (positive, audit, _) = scanner::cpe::authoritative(&[updated], &mut feed).unwrap();
    assert!(positive.is_empty());
    assert_eq!(audit[0]["reason"], "drop");
    feed.0 = json!({});
    let (positive, audit, errors) = scanner::cpe::authoritative(&[f], &mut feed).unwrap();
    let (_, covered, _) =
        scanner::cpe::resolve(positive, &audit, [aid].into_iter().collect(), errors);
    assert!(covered.is_empty());
}

#[test]
fn actual_oci_fixture_layers_and_rejections() {
    let expected: Value = serde_json::from_str(include_str!("fixtures/oci.json")).unwrap();
    for (name, expected) in expected.as_object().unwrap() {
        let filename = format!("{name}.tar.gz");
        let mut result = scanner::container::inventory(
            &fixtures().join("oci").join(&filename),
            scanner::container::Limits::default(),
        );
        result.source = filename.clone();
        for p in &mut result.packages {
            p.path = filename.clone();
        }
        assert_eq!(serde_json::to_value(result).unwrap(), *expected, "{name}");
        let unrelated = Fixture::new();
        fs::write(unrelated.0.join("requirements.txt"), "unrelated==1.0\n").unwrap();
        let archive = fixtures().join("oci").join(&filename);
        let selected = scanner::inventory(&InventoryOptions {
            roots: vec![unrelated.0.clone()],
            oci: Some(archive.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(selected["source"], archive.to_string_lossy().as_ref());
        assert_eq!(selected["coverage"], expected["coverage"]);
        assert_eq!(
            selected["packages"].as_array().unwrap().len(),
            expected["packages"].as_array().unwrap().len()
        );
        assert!(!selected["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "unrelated"));
    }
}

#[test]
fn paginated_aliases_and_nested_versions_match_actual_feed_behavior() {
    struct Feed;
    impl scanner::feeds::FeedSource for Feed {
        fn get(&mut self, url: &str, body: Option<&Value>) -> crate::Result<Value> {
            let data = if url == scanner::feeds::KEV {
                json!({"vulnerabilities":[{"cveID":"CVE-2026-0001"}]})
            } else if url.starts_with(scanner::feeds::EPSS) {
                json!({"data":[{"cve":"CVE-2026-0001","epss":".1"}]})
            } else if url.ends_with("/querybatch") {
                let body = body.unwrap();
                assert!(!body.to_string().contains("private-project"));
                json!({"results":body["queries"].as_array().unwrap().iter().map(|q|if q.get("page_token").is_some(){json!({"vulns":[{"id":"DEBIAN-test"}]})}else{json!({"vulns":[{"id":"DSA-test"}],"next_page_token":"next"})}).collect::<Vec<_>>()})
            } else {
                let id = url.rsplit('/').next().unwrap();
                json!({"id":id,"upstream":["CVE-2026-0001"],"affected":[{"package":{"name":"test","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":if id=="DEBIAN-test"{"2.1.0"}else{"2.0.0"}}]}]}]})
            };
            Ok(json!({"data":data,"source_url":url,"fetched_at":"2026-11-03T00:00:00Z"}))
        }
    }
    let expected: Value = serde_json::from_str(include_str!("fixtures/feeds.json")).unwrap();
    let packages = vec!["1.0.0", "1.1.0"]
        .into_iter()
        .map(|v| {
            super::package(
                "test",
                v,
                "npm",
                "/private-project/package-lock.json",
                false,
                "project",
            )
        })
        .collect::<Vec<_>>();
    let mut result = scanner::feeds::scan(&packages, &mut Feed).unwrap();
    for finding in result["findings"].as_array_mut().unwrap() {
        assert_eq!(finding["alias_provenance"].as_array().unwrap().len(), 2);
        assert_eq!(
            finding["fixed_applicability"],
            "candidate-versions-require-compatible-branch-and-rescan"
        );
        let f = finding.as_object_mut().unwrap();
        f.remove("alias_provenance");
        f.remove("fixed_applicability");
        let priority = f["priority"].as_object_mut().unwrap();
        priority.remove("scoring_reason");
        priority.remove("severity_evidence");
    }
    assert_eq!(result["findings"], expected["findings"]);
    assert_eq!(result["covered"], expected["covered"]);
    assert_eq!(result["errors"], expected["errors"]);
}

#[test]
fn nvd_requests_keep_the_public_rate_limit_pause() {
    assert_eq!(
        scanner::feeds::nvd_pause(false),
        std::time::Duration::from_millis(6500)
    );
    assert_eq!(
        scanner::feeds::nvd_pause(true),
        std::time::Duration::from_millis(1000)
    );
    struct Feed;
    impl scanner::feeds::FeedSource for Feed {
        fn get(&mut self, _: &str, _: Option<&Value>) -> crate::Result<Value> {
            unreachable!()
        }
    }
    assert!(scanner::feeds::FeedSource::nvd_pause(&Feed) >= std::time::Duration::from_millis(1000));
}

#[test]
fn debian_tracker_is_cut_to_the_selected_source_packages_before_it_is_cached() {
    // The full tracker is larger than the state store's per-file budget, so the cached copy
    // keeps only the scanned source packages (and the names the native check looks up).
    let mut tracker = json!({"openssl":{"CVE-1":{}},"zlib":{"CVE-2":{}},"linux":{"CVE-3":{}},"glibc":{"CVE-4":{}}});
    let packages = [
        ("Debian:13", "openssl"),
        ("Debian:13", "zlib1g"),
        ("npm", "glibc"),
    ]
    .iter()
    .map(|(e, n)| (e.to_string(), n.to_string()))
    .collect();
    scanner::feeds::select_debian_sources(&mut tracker, &packages);
    assert_eq!(tracker, json!({"openssl":{"CVE-1":{}},"zlib":{"CVE-2":{}}}));
}

#[test]
fn only_a_binary_in_the_store_alias_folder_is_a_store_alias() {
    use scanner::inventory::store_alias;
    let local: PathBuf = ["C:", "Users", "u", "AppData", "Local"].iter().collect();
    let under = |parts: &[&str]| parts.iter().fold(local.clone(), |p, s| p.join(s));
    let l = Some(local.as_os_str());
    let alias = under(&["microsoft", "WINDOWSAPPS", "python3.exe"]);
    assert!(store_alias(&alias, l));
    assert!(!store_alias(&alias, None));
    assert!(!store_alias(
        &under(&["Programs", "Python", "python3.exe"]),
        l
    ));
    let nested = under(&[
        "Microsoft",
        "WindowsApps",
        "PythonSoftwareFoundation",
        "python3.exe",
    ]);
    assert!(!store_alias(&nested, l));
}
