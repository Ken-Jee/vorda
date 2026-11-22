// The accuracy corpus: small real projects for every supported lockfile, plus files Vorda must
// refuse, scanned offline against recorded feed answers (fixtures/corpus/feeds.json, trimmed to
// the fields the scanner reads). Each case's "osv_groups" is osv-scanner's advisory group count
// for the same project, checked below. fixtures/corpus/record.py re-records answers and verdicts.
use serde_json::{json, Map, Value};
use std::{fs, path::Path, process::Command};
use vorda::store::now;

const DEAD: &str = "http://127.0.0.1:9";

fn load(path: &Path) -> Map<String, Value> {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// Scan one project with only the recorded answers in a fresh cache; any request they do not
/// cover goes to a dead proxy and fails.
fn scan(root: &Path, feeds: &Map<String, Value>) -> (i32, Value) {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let cache = state.join("cache");
    fs::create_dir_all(&cache).unwrap();
    for (name, entry) in feeds {
        let mut entry = entry.clone();
        entry["checked"] = json!(now());
        entry["fetched_at"] = json!("recorded");
        fs::write(cache.join(name), entry.to_string()).unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command.env("VORDA_ADVISORIES", "online");
    command
        .arg("--state")
        .arg(&state)
        .args(["scan", "--json", "--root"])
        .arg(root);
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(var, DEAD);
    }
    let output = command
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

/// One finding as record.py writes it: package, advisory, severity, KEV and EPSS.
fn finding(f: &Value) -> String {
    let p = &f["package"];
    let severity = match &f["severity"] {
        Value::Array(scores) => {
            let mut scores: Vec<_> = scores
                .iter()
                .map(|s| s["score"].as_str().unwrap_or(""))
                .collect();
            scores.sort();
            scores.join(",")
        }
        Value::String(s) => s.clone(),
        _ => String::new(),
    };
    let mut text = format!(
        "{}@{} {} {}",
        p["name"].as_str().unwrap(),
        p["version"].as_str().unwrap(),
        f["advisory"].as_str().unwrap(),
        if severity.is_empty() {
            "no-severity"
        } else {
            &severity
        }
    );
    if f["kev"] == true {
        text += " kev";
    }
    if !f["epss"].is_null() {
        text += &format!(" epss={}", f["epss"]);
    }
    text
}

#[test]
fn every_corpus_project_gets_its_recorded_verdict_offline() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus");
    let feeds = load(&corpus.join("feeds.json"));
    let expected = load(&corpus.join("expected.json"));
    let projects: Vec<_> = fs::read_dir(corpus.join("projects"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        projects.len(),
        expected.len(),
        "every project has a verdict"
    );
    let failures: Vec<_> = std::thread::scope(|s| {
        let runs: Vec<_> = expected
            .iter()
            .map(|(case, want)| {
                let (root, feeds) = (corpus.join("projects").join(case), &feeds);
                assert!(root.is_dir(), "{case} has a project folder");
                s.spawn(move || {
                    let (code, result) = scan(&root, feeds);
                    let mut findings: Vec<_> = result["findings"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(finding)
                        .collect();
                    findings.sort();
                    // Which file was refused and why, as the user reads it (first sentence).
                    let prefix = format!("{}/", root.display());
                    let mut refused = Vec::new();
                    let mut feed_errors = Vec::new();
                    for e in result["errors"].as_array().unwrap() {
                        if e["source"] != "inventory" {
                            // A feed error here means a missing recording, not a verdict.
                            feed_errors.push(e.clone());
                            continue;
                        }
                        let text = e["error"].as_str().unwrap();
                        let text = text.strip_prefix(&prefix).unwrap_or(text);
                        refused.push(text.split(". ").next().unwrap().to_string());
                    }
                    refused.sort();
                    let mut got = json!({
                        "exit": code,
                        "status": result["status"],
                        "findings": findings,
                        "refused": refused,
                    });
                    for key in ["osv_groups", "beyond_osv"] {
                        if let Some(v) = want.get(key) {
                            got[key] = v.clone();
                        }
                    }
                    // osv-scanner's count, less the packages Vorda reports by design and it
                    // does not: equal for a finished scan, at most that for an unknown one.
                    let beyond = want.get("beyond_osv").and_then(Value::as_array);
                    let counted = result["findings"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|f| beyond.is_none_or(|b| !b.contains(&f["package"]["name"])))
                        .count() as u64;
                    let osv_disagrees = want.get("osv_groups").is_some_and(|osv| {
                        let osv = osv.as_u64().unwrap();
                        if code == 2 {
                            counted > osv
                        } else {
                            counted != osv
                        }
                    });
                    (got != *want || !feed_errors.is_empty() || osv_disagrees).then(|| {
                        json!({"case": case, "want": want, "got": got, "counted_for_osv": counted, "feed_errors": feed_errors})
                    })
                })
            })
            .collect();
        runs.into_iter().filter_map(|r| r.join().unwrap()).collect()
    });
    assert!(failures.is_empty(), "{failures:#?}");
}
