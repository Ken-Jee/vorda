//! OS-package scans on Ubuntu: decided from bulk distro data, bounded in time.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    domain::Package,
    scanner::feeds::{self, FeedSource, KEV, OSV},
    store::{identity, now},
    Error, Result,
};

const OVAL: &str = "https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2";

/// Recorded responses for one Ubuntu 24.04 source package with many open CVEs, the shape a
/// real `linux` source package has. The per-CVE ubuntu.com pages answer 504, as they did
/// when this was recorded.
struct Ubuntu {
    cves: Vec<String>,
    requests: Vec<String>,
    /// How many Canonical record lookups answer before OSV starts failing with 503.
    records_ok: usize,
    answered: Vec<String>,
}
impl FeedSource for Ubuntu {
    fn get(&mut self, url: &str, body: Option<&Value>) -> Result<Value> {
        self.requests.push(url.into());
        let data = if url == KEV {
            json!({"vulnerabilities":[]})
        } else if url.starts_with(feeds::EPSS) {
            json!({"data":[]})
        } else if url.ends_with("/querybatch") {
            let queries = body.unwrap()["queries"].as_array().unwrap().len();
            assert_eq!(queries, 1);
            json!({"results":[{"vulns":self.cves.iter().map(|c|json!({"id":format!("UBUNTU-{c}")})).collect::<Vec<_>>()}]})
        } else if url == OVAL {
            json!([{"name":"linux","release":"noble","cves":["CVE-2024-1000"],"fixed":"6.8.0-41.41","severity":"high"}])
        } else if let Some(cve) = url.strip_prefix(&format!("{OSV}/vulns/UBUNTU-")) {
            if self.answered.len() == self.records_ok {
                return Err(Error::new(format!("HTTP Error 503: {url}")));
            }
            self.answered.push(cve.into());
            // OSV's copy of the Canonical record: CVE-2024-1001 names a fix and a priority,
            // the others list the release as affected with no fix and no priority.
            let events = if cve == "CVE-2024-1001" {
                json!([{"introduced":"0"},{"fixed":"6.8.0-45.45"}])
            } else {
                json!([{"introduced":"0"}])
            };
            let severity = if cve == "CVE-2024-1001" {
                json!([{"type":"Ubuntu","score":"high"}])
            } else {
                json!([])
            };
            json!({"id":format!("UBUNTU-{cve}"),"severity":severity,"affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":events}]}]})
        } else if url.starts_with("https://ubuntu.com/security/cves/") {
            return Err(Error::new(format!("HTTP Error 504: {url}")));
        } else {
            panic!("unexpected request {url}");
        };
        Ok(json!({"data":data,"source_url":url,"fetched_at":"2026-11-13T00:00:00Z"}))
    }
}

#[test]
fn unreadable_canonical_records_leave_the_fix_unchecked_and_the_scan_unknown() {
    // OSV answers the batch lookup, then the record lookups stop answering: after the
    // first one, and from the start.
    for records_ok in [1, 0] {
        let cves: Vec<_> = (1000..1010).map(|n| format!("CVE-2024-{n}")).collect();
        let mut feed = Ubuntu {
            cves: cves.clone(),
            requests: vec![],
            records_ok,
            answered: vec![],
        };
        let result = feeds::scan(&[kernel_headers()], &mut feed).unwrap();
        let errors = result["errors"].as_array().unwrap();
        let unread = cves.len() - feed.answered.len();
        assert!(
            errors.iter().any(|e| e["error"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{unread} Canonical records could not be read"))),
            "{errors:#?}"
        );
        // Not complete: the package is not counted as checked.
        assert_eq!(result["covered"], json!([]), "{records_ok}");
        let findings = result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), cves.len());
        for f in findings {
            let cve = f["advisory"].as_str().unwrap();
            if cve == "CVE-2024-1000" || feed.answered.iter().any(|a| a == cve) {
                continue;
            }
            assert_eq!(f["confidence"], "distro: affected", "{f:#}");
            assert_eq!(f["fixed"], json!([]), "{f:#}");
        }
    }
}

fn kernel_headers() -> Package {
    serde_json::from_value(json!({"name":"linux-libc-dev","version":"6.8.0-40.40","ecosystem":"Ubuntu:24.04:LTS","path":"dpkg","scope":"os-package","source_name":"linux","source_version":"6.8.0-40.40"})).unwrap()
}

#[test]
fn ubuntu_findings_carry_the_canonical_fix_and_priority_without_ubuntu_com_pages() {
    let cves: Vec<_> = (1000..1400).map(|n| format!("CVE-2024-{n}")).collect();
    let mut feed = Ubuntu {
        cves: cves.clone(),
        requests: vec![],
        records_ok: usize::MAX,
        answered: vec![],
    };
    let result = feeds::scan(&[kernel_headers()], &mut feed).unwrap();
    assert_eq!(result["errors"], json!([]), "{:#}", result["errors"]);
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), cves.len());
    assert_eq!(result["covered"].as_array().unwrap().len(), 1);
    // One OSV record per CVE, no per-CVE ubuntu.com page.
    assert!(
        !feed.requests.iter().any(|u| u.contains("ubuntu.com")),
        "{:?}",
        feed.requests
    );
    let advisory = |cve: &str| findings.iter().find(|f| f["advisory"] == cve).unwrap();
    let oval = advisory("CVE-2024-1000");
    assert_eq!(oval["fixed"], json!(["6.8.0-41.41"]));
    assert_eq!(oval["confidence"], "distro: fix available 6.8.0-41.41");
    // The record's fix and priority reach the finding.
    let fixed = advisory("CVE-2024-1001");
    assert_eq!(fixed["fixed"], json!(["6.8.0-45.45"]), "{fixed:#}");
    assert_eq!(fixed["native_verdict"]["fixed"], "6.8.0-45.45");
    assert_eq!(fixed["confidence"], "distro: fix available 6.8.0-45.45");
    assert_eq!(fixed["priority"]["level"], "high");
    // No fix and no priority in the record: both are said to be not known, never "none".
    let open = advisory("CVE-2024-1002");
    assert_eq!(open["fixed"], json!([]));
    assert_eq!(open["confidence"], "distro: fix not known yet");
    assert_eq!(open["priority"]["level"], "unknown");
    for f in findings {
        assert!(f["native_source"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{OSV}/vulns/UBUNTU-CVE-")));
    }
}

/// Recorded responses for upstream (NVD) openssl matches on Ubuntu 24.04: OSV's copies of the
/// Canonical records answer, ubuntu.com answers 504.
struct Upstream(Vec<String>);
impl FeedSource for Upstream {
    fn get(&mut self, url: &str, _: Option<&Value>) -> Result<Value> {
        self.0.push(url.into());
        let record = |fixed: &str| json!({"id":"x","affected":[{"package":{"name":"openssl","ecosystem":"Ubuntu:24.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":fixed}]}]}]});
        let data = if url.ends_with("/UBUNTU-CVE-2024-0001") {
            record("3.0.13-0ubuntu3.2")
        } else if url.ends_with("/UBUNTU-CVE-2024-0002") {
            record("3.0.13-0ubuntu3.20")
        } else if url.ends_with("/UBUNTU-CVE-2024-0003") {
            return Err(Error::new(format!("HTTP Error 404: {url}")));
        } else {
            return Err(Error::new(format!("HTTP Error 504: {url}")));
        };
        Ok(json!({"data":data,"source_url":url,"fetched_at":"2026-11-13T00:00:00Z"}))
    }
}

#[test]
fn upstream_ubuntu_matches_are_decided_by_the_canonical_fixed_version() {
    let p: Package = serde_json::from_value(json!({"name":"libssl3t64","version":"3.0.13-0ubuntu3.16","ecosystem":"Ubuntu:24.04:LTS","path":"dpkg","scope":"os-package","source_name":"openssl","source_version":"3.0.13-0ubuntu3.16"})).unwrap();
    let asset = identity(&json!(["fixture"])).unwrap();
    let findings: Vec<_> = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
        .iter()
        .map(|cve| json!({"key":cve,"asset":asset,"package":p,"advisory":cve,"aliases":[cve],"confidence":"upstream-version"}))
        .collect();
    let mut feed = Upstream(vec![]);
    let (confirmed, audit, errors) =
        vorda::scanner::cpe::authoritative(&findings, &mut feed).unwrap();
    // Fixed at or below the installed version: closed. Fixed later: open, with the distro fix.
    assert_eq!(confirmed.len(), 1, "{confirmed:#?}");
    assert_eq!(confirmed[0]["advisory"], "CVE-2024-0002");
    assert_eq!(
        confirmed[0]["native_verdict"]["fixed"],
        "3.0.13-0ubuntu3.20"
    );
    assert!(audit
        .iter()
        .any(|a| a["finding"]["advisory"] == "CVE-2024-0001" && a["reason"] == "drop"));
    // No Canonical record and no ubuntu.com page: still uncertain, never clean.
    assert_eq!(errors.len(), 1, "{errors:#?}");
    assert!(errors[0]["error"]
        .as_str()
        .unwrap()
        .contains("CVE-2024-0003"));
    for cve in ["CVE-2024-0001", "CVE-2024-0002"] {
        assert!(!feed
            .0
            .iter()
            .any(|u| u.contains("ubuntu.com") && u.contains(cve)));
    }
}

#[test]
fn an_unavailable_debian_tracker_is_requested_once_per_scan() {
    struct Down(usize);
    impl FeedSource for Down {
        fn get(&mut self, url: &str, _: Option<&Value>) -> Result<Value> {
            assert_eq!(url, feeds::DEBIAN);
            self.0 += 1;
            Err(Error::new("fixture tracker unavailable"))
        }
    }
    let findings: Vec<_> = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
        .iter()
        .map(|cve| json!({"key":cve,"asset":"a","package":{"name":"libssl3t64","version":"3.5.1-1","ecosystem":"Debian:13","path":"image","scope":"reachable-unknown","source_name":"openssl"},"advisory":cve,"aliases":[cve]}))
        .collect();
    let mut feed = Down(0);
    let (confirmed, audit, errors) =
        vorda::scanner::cpe::authoritative(&findings, &mut feed).unwrap();
    assert_eq!(feed.0, 1);
    assert!(confirmed.is_empty());
    assert_eq!(audit.len(), 3);
    assert_eq!(errors.len(), 3);
}

const LOCK: &str = r#"{"lockfileVersion":3,"packages":{"node_modules/one":{"version":"1.0.0"},"node_modules/two":{"version":"2.0.0"}}}"#;

fn seed(cache: &Path, url: &str, body: Value, data: Value) {
    fs::write(
        cache.join(format!("{}.json", identity(&json!([url, body])).unwrap())),
        json!({"source_url":url,"checked":now(),"data":data}).to_string(),
    )
    .unwrap();
}

#[test]
fn an_exhausted_feed_budget_is_unknown_and_names_the_packages_not_checked() {
    let state = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join("package-lock.json"), LOCK).unwrap();
    let cache = state.path().join("cache");
    fs::create_dir(&cache).unwrap();
    seed(&cache, KEV, Value::Null, json!({"vulnerabilities":[]}));
    let query = json!({"queries":[{"package":{"name":"one","ecosystem":"npm"},"version":"1.0.0"},{"package":{"name":"two","ecosystem":"npm"},"version":"2.0.0"}]});
    seed(
        &cache,
        &format!("{OSV}/querybatch"),
        query,
        json!({"results":[{"vulns":[{"id":"GHSA-fixture-one"}]},{"vulns":[{"id":"GHSA-fixture-two"}]}]}),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .env("VORDA_ADVISORIES", "online")
        .env("HTTPS_PROXY", "http://localhost:9")
        .env("HTTP_PROXY", "http://localhost:9")
        .env("NO_PROXY", "")
        .env("VORDA_FEED_BUDGET_SECONDS", "0")
        .arg("--state")
        .arg(state.path())
        .args(["scan", "--json", "--root"])
        .arg(project.path())
        .output()
        .unwrap();
    let result: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(output.status.code(), Some(2), "{result:#}");
    assert_eq!(result["status"], "unknown");
    let errors = result["errors"].to_string();
    assert!(
        errors.contains("time budget") && errors.contains("2 of 2 packages were not fully checked"),
        "{errors}"
    );
}

fn scan_os_inventory(ecosystem: &str) -> (Value, String) {
    let output = run_os_scan(ecosystem, &["--json"]);
    let result: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (result, String::from_utf8_lossy(&output.stderr).into())
}

fn run_os_scan(ecosystem: &str, extra: &[&str]) -> std::process::Output {
    let state = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let file = project.path().join("inventory.json");
    fs::write(
        &file,
        json!({"status":"complete","observed":now(),"packages":[{"name":"libc-bin","version":"2.39-0ubuntu8.9","ecosystem":ecosystem,"path":"dpkg-query","scope":"os-package","source_name":"glibc","source_version":"2.39-0ubuntu8.9"}]}).to_string(),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_vorda"))
        .env("VORDA_ADVISORIES", "online")
        .env("HTTPS_PROXY", "http://localhost:9")
        .env("HTTP_PROXY", "http://localhost:9")
        .env("NO_PROXY", "")
        .env("VORDA_FEED_BUDGET_SECONDS", "0")
        .arg("--state")
        .arg(state.path())
        .arg("scan")
        .args(extra)
        .arg("--root")
        .arg(project.path())
        .arg("--inventory-file")
        .arg(&file)
        .output()
        .unwrap()
}

#[test]
fn the_ubuntu_summary_leads_with_the_experimental_note_once() {
    let output = run_os_scan("Ubuntu:24.04:LTS", &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.starts_with("Experimental: os-packages on Ubuntu"),
        "{stdout}"
    );
    let note = stdout.lines().next().unwrap();
    assert!(note.contains("false alarms"), "{note}");
    assert!(stdout.contains("\nVorda scan: "), "{stdout}");
    assert!(!stderr.contains("Experimental"), "{stderr}");
    let output = run_os_scan("Debian:12", &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("Vorda scan: "), "{stdout}");
}

#[test]
fn ubuntu_os_package_scans_are_labelled_experimental() {
    let (result, stderr) = scan_os_inventory("Ubuntu:24.04:LTS");
    let note = result["experimental"][0]
        .as_str()
        .unwrap_or_else(|| panic!("{result:#}"));
    assert!(note.starts_with("os-packages on Ubuntu"), "{note}");
    assert!(
        note.contains("false alarms") && note.contains("linux-libc-dev"),
        "{note}"
    );
    assert!(
        stderr.contains("Experimental: os-packages on Ubuntu"),
        "{stderr}"
    );
    let (result, stderr) = scan_os_inventory("Debian:12");
    assert!(result.get("experimental").is_none(), "{result:#}");
    assert!(!stderr.contains("Experimental"), "{stderr}");
    let help = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args(["scan", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("--os-packages on Ubuntu (host or --oci image) is experimental"),
        "{help}"
    );
}
