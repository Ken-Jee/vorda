use serde_json::{json, Value};
use vorda::{
    scanner::{cpe, feeds::FeedSource},
    Error, Result,
};

struct Tracker {
    available: bool,
    retired: bool,
}
impl FeedSource for Tracker {
    fn get(&mut self, url: &str, _: Option<&Value>) -> Result<Value> {
        if self.available
            && url.contains("ubuntu-cve-tracker/plain/")
            && url.contains(if self.retired {
                "/retired/"
            } else {
                "/active/"
            })
        {
            return Ok(json!({"data":include_str!("fixtures/ubuntu-status/CVE-2025-9232.txt")}));
        }
        Err(Error::new(format!("HTTP Error 404: {url}")))
    }
}

fn finding(ecosystem: &str, version: &str) -> Value {
    json!({"key":"openssl-cve","asset":"openssl","advisory":"CVE-2025-9232","aliases":["CVE-2025-9232"],"confidence":"upstream-version","package":{"name":"libssl3t64","version":version,"ecosystem":ecosystem,"scope":"os-package","path":"dpkg","source_name":"openssl","source_version":version}})
}

#[test]
fn canonical_status_resolves_missing_osv_release_without_ubuntu_com() {
    for retired in [false, true] {
        let (confirmed, audit, errors) = cpe::authoritative(
            &[finding("Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.16")],
            &mut Tracker {
                available: true,
                retired,
            },
        )
        .unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(confirmed.is_empty());
        assert_eq!(audit[0]["reason"], "drop");
    }
}

#[test]
fn canonical_released_build_uses_dpkg_order_and_exposes_fix() {
    for (installed, affected) in [
        ("3.5.3-1ubuntu1", true),
        ("3.5.3-1ubuntu2", false),
        ("3.5.3-1ubuntu10", false),
        ("1:3.5.3-1ubuntu1", false),
        ("3.5.3-1ubuntu2~test1", true),
    ] {
        let (confirmed, audit, errors) = cpe::authoritative(
            &[finding("Ubuntu:26.04:LTS", installed)],
            &mut Tracker {
                available: true,
                retired: false,
            },
        )
        .unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(confirmed.len(), usize::from(affected), "{installed}");
        if affected {
            assert_eq!(confirmed[0]["fixed"], json!(["3.5.3-1ubuntu2"]));
        } else {
            assert_eq!(audit[0]["reason"], "drop");
        }
    }
}

#[test]
fn absent_status_or_unavailable_tracker_remains_unknown() {
    for (available, ecosystem) in [(false, "Ubuntu:24.04:LTS"), (true, "Ubuntu:99.04")] {
        let f = finding(ecosystem, "3.0.13-0ubuntu3.16");
        let (confirmed, audit, errors) = cpe::authoritative(
            &[f],
            &mut Tracker {
                available,
                retired: false,
            },
        )
        .unwrap();
        let (_, covered, resolved_errors) =
            cpe::resolve(confirmed, &audit, ["openssl".into()].into(), errors);
        assert!(covered.is_empty());
        assert!(!resolved_errors.is_empty());
    }
}

#[test]
fn malformed_release_status_never_closes_a_finding() {
    struct Raw(String);
    impl FeedSource for Raw {
        fn get(&mut self, url: &str, _: Option<&Value>) -> Result<Value> {
            if url.contains("ubuntu-cve-tracker/plain/") {
                Ok(json!({"data":self.0}))
            } else {
                Err(Error::new(format!("HTTP Error 404: {url}")))
            }
        }
    }
    let text = include_str!("fixtures/ubuntu-status/CVE-2025-9232.txt");
    for broken in [
        text.replace(
            "noble_openssl: not-affected (code not present)",
            "noble_openssl: released (unknown)",
        ),
        text.replace(
            "noble_openssl: not-affected (code not present)",
            "noble_openssl: not-affected (code not present",
        ),
        text.replace("Candidate: CVE-2025-9232", "Candidate: CVE-2025-9999"),
        format!("{text}\nnoble_openssl: not-affected\n"),
    ] {
        let (confirmed, audit, errors) = cpe::authoritative(
            &[finding("Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.16")],
            &mut Raw(broken),
        )
        .unwrap();
        let (_, covered, errors) =
            cpe::resolve(confirmed, &audit, ["openssl".into()].into(), errors);
        assert!(covered.is_empty());
        assert!(!errors.is_empty());
    }
}
