// What a new user sees first: the version, a readable scan summary, and mailbox
// listings that stay small enough for a terminal or an agent's context.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    scanner::feeds::{KEV, OSV},
    store::{identity, now},
    surfaces::mcp,
};

const DEAD: &str = "http://127.0.0.1:9";
const LOCK: &str =
    r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.2.3"}}}"#;

/// A project with one npm package and `advisories` synthetic advisories served
/// from a seeded feed cache behind a dead proxy.
fn project(temp: &Path, advisories: usize) -> (std::path::PathBuf, std::path::PathBuf) {
    project_fixed_in(temp, &vec!["1.2.4"; advisories])
}

/// As `project`, one advisory per entry of `fixed`, each naming that fixed version.
fn project_fixed_in(temp: &Path, fixed: &[&str]) -> (std::path::PathBuf, std::path::PathBuf) {
    let advisories = fixed.len();
    let root = temp.join("project");
    let state = temp.join("state");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("package-lock.json"), LOCK).unwrap();
    let cache = state.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let ids: Vec<String> = (1..=advisories)
        .map(|n| format!("GHSA-test-{n:04}"))
        .collect();
    let mut rows = vec![
        (
            json!([KEV, null]),
            KEV.to_string(),
            json!({"vulnerabilities":[]}),
        ),
        (
            json!([format!("{OSV}/querybatch"), {"queries":[{"package":{"name":"example","ecosystem":"npm"},"version":"1.2.3"}]}]),
            format!("{OSV}/querybatch"),
            json!({"results":[if ids.is_empty() { json!({}) } else { json!({"vulns":ids.iter().map(|id| json!({"id":id})).collect::<Vec<_>>()}) }]}),
        ),
    ];
    for (id, fixed) in ids.iter().zip(fixed) {
        rows.push((
            json!([format!("{OSV}/vulns/{id}"), null, [["npm", "example"]]]),
            format!("{OSV}/vulns/{id}"),
            json!({"id":id,"summary":"Synthetic finding","affected":[{"package":{"name":"example","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":fixed}]}]}]}),
        ));
    }
    for (key, url, data) in rows {
        fs::write(
            cache.join(format!("{}.json", identity(&key).unwrap())),
            json!({"source_url":url,"checked":now(),"fetched_at":"fixture","data":data})
                .to_string(),
        )
        .unwrap();
    }
    (root, state)
}

fn vorda(state: &Path, args: &[&str]) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command.arg("--state").arg(state).args(args);
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
        .env("VORDA_ADVISORIES", "online")
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn version_flag_prints_the_crate_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("vorda {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_and_version_answer_as_words_and_flags() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path();
    let (exit, help, _) = vorda(state, &["--help"]);
    assert_eq!(exit, 0);
    assert!(
        help.contains("scan          Check lockfiles and pinned requirements"),
        "{help}"
    );
    assert_eq!(vorda(state, &["help"]), (0, help, String::new()));
    let (exit, scan_help, _) = vorda(state, &["help", "scan"]);
    assert_eq!(exit, 0);
    assert!(
        scan_help.contains("--offline makes no network request"),
        "{scan_help}"
    );
    assert_eq!(
        vorda(state, &["help", "scan"]),
        vorda(state, &["scan", "--help"])
    );
    assert_eq!(vorda(state, &["help", "version"]).0, 0);
    let (exit, version, _) = vorda(state, &["version"]);
    assert_eq!(exit, 0);
    assert_eq!(version, format!("vorda {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn a_bare_scan_path_is_answered_with_the_root_flag() {
    let temp = tempfile::tempdir().unwrap();
    let (exit, _, stderr) = vorda(temp.path(), &["scan", "tests/fixtures"]);
    assert_eq!(exit, 64);
    assert!(stderr.contains("pass --root tests/fixtures"), "{stderr}");
}

#[test]
fn a_missing_root_is_refused_and_never_saved_as_a_project() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let typo = temp.path().join("typo");
    let (exit, _, stderr) = vorda(&state, &["scan", "--root", typo.to_str().unwrap()]);
    assert_eq!(exit, 2);
    assert!(stderr.contains("no such folder or file"), "{stderr}");
    let (_, mail, _) = vorda(
        &state,
        &["mail", "list", "--reader", "me", "--limit", "100"],
    );
    assert!(!mail.contains("typo"), "{mail}");
}

#[test]
fn docs_cli_md_shows_each_commands_own_help() {
    let docs = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/cli.md")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    for command in [
        "",
        "scan",
        "db",
        "inventory",
        "mail",
        "mcp",
        "dashboard",
        "hook",
        "snippet",
        "watch",
        "fix",
        "repair",
        "repair-mcp",
        "connect",
        "mode",
        "can",
        "agentbom",
        "link",
        "hub-mcp",
        "snapshot-read",
        "verify-self",
        "licenses",
    ] {
        let args: Vec<&str> = [command, "--help"]
            .into_iter()
            .filter(|a| !a.is_empty())
            .collect();
        let (exit, help, stderr) = vorda(temp.path(), &args);
        assert_eq!(exit, 0, "{command}: {stderr}");
        assert!(
            docs.contains(&format!("```text\n{help}```")),
            "docs/cli.md is out of date for `vorda {command} --help`:\n{help}"
        );
    }
}

#[test]
fn scan_prints_a_short_summary_and_json_on_request() {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = project(temp.path(), 2);
    let root = root.to_str().unwrap();
    let (exit, text, stderr) = vorda(&state, &["scan", "--root", root]);
    assert_eq!(exit, 3, "{stderr}");
    assert!(serde_json::from_str::<Value>(&text).is_err(), "{text}");
    assert!(text.lines().count() <= 12, "{text}");
    assert!(text.contains("vulnerable"), "{text}");
    assert!(text.contains("example 1.2.3"), "{text}");
    assert!(text.contains("2 advisories"), "{text}");
    assert!(text.contains("1.2.4"), "{text}");
    assert!(text.contains("--json"), "{text}");
    let (exit, json, _) = vorda(&state, &["check", "--json", "--root", root]);
    assert_eq!(exit, 3);
    let json: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["status"], "vulnerable");
    assert_eq!(json["findings"].as_array().unwrap().len(), 2);
}

#[test]
fn unknown_scan_summary_never_reads_as_clean() {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = project(temp.path(), 0);
    let root = root.to_str().unwrap();
    let (exit, text, _) = vorda(&state, &["scan", "--offline", "--root", root]);
    assert_eq!(exit, 2);
    assert!(text.contains("unknown"), "{text}");
    assert!(text.contains("not a clean result"), "{text}");
    assert!(!text.contains("No known vulnerabilities"), "{text}");
    let (exit, json, _) = vorda(&state, &["scan", "--offline", "--json", "--root", root]);
    assert_eq!(exit, 2);
    let json: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["status"], "unknown");
}

#[test]
fn mail_list_is_bounded_and_says_how_many_more() {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = project(temp.path(), 25);
    let (exit, _, stderr) = vorda(&state, &["scan", "--root", root.to_str().unwrap()]);
    assert_eq!(exit, 3, "{stderr}");
    let (exit, out, stderr) = vorda(&state, &["mail", "list", "--reader", "me"]);
    assert_eq!(exit, 0, "{stderr}");
    let shown: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(shown.as_array().unwrap().len(), 20);
    assert!(stderr.contains("5 more"), "{stderr}");
    assert!(stderr.contains("--limit"), "{stderr}");
    let (exit, out, stderr) = vorda(&state, &["mail", "list", "--reader", "me", "--limit", "30"]);
    assert_eq!(exit, 0, "{stderr}");
    let all: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(all.as_array().unwrap().len(), 25);
    assert!(!stderr.contains("more"), "{stderr}");
    let (exit, _, _) = vorda(&state, &["mail", "list", "--reader", "me", "--limit", "0"]);
    assert_eq!(exit, 64);
    let (exit, _, stderr) = vorda(&state, &["mail", "list", "--reader", "me", "--limit", "1"]);
    assert_eq!(exit, 0, "{stderr}");
    assert!(
        stderr.contains("Showing 1 unread message; 24 more"),
        "{stderr}"
    );
    let (exit, out, _) = vorda(&state, &["mail", "list", "--reader", "me", "--limit", "+5"]);
    assert_eq!((exit, out.as_str()), (64, ""));
}

#[test]
fn summary_never_prints_terminal_control_or_invisible_characters() {
    let temp = tempfile::tempdir().unwrap();
    let hostile =
        "9.9.9\u{1b}[2J\u{7}\r\n\u{7f}\u{9b}31m\u{202e}\u{2066}\u{2028}\u{2029}\u{200b}\u{feff}\u{ad}\u{180e}\u{206a}\u{206f}\u{fff9}\u{fffb}\u{e0001}\u{e0041}\u{e007f}";
    let long = "1".repeat(400);
    let (root, state) = project_fixed_in(temp.path(), &[hostile, &long]);
    let (exit, text, stderr) = vorda(&state, &["scan", "--root", root.to_str().unwrap()]);
    assert_eq!(exit, 3, "{stderr}");
    let bad = |c: char| {
        (c.is_control() && c != '\n')
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
            || matches!(c, '\u{ad}' | '\u{180e}' | '\u{fff9}'..='\u{fffb}' | '\u{e0000}'..='\u{e007f}')
    };
    assert!(!text.chars().any(bad), "{text:?}");
    let line = text.lines().find(|l| l.contains("fixed in")).expect(&text);
    assert!(line.contains("9.9.9?[2J"), "{line:?}");
    assert!(line.chars().count() < 300, "{line:?}");
    assert!(text.lines().count() <= 12, "{text:?}");
}

#[test]
fn a_reader_that_closes_the_pipe_early_gets_no_panic() {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = project(temp.path(), 2);
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
        command
            .arg("--state")
            .arg(&state)
            .args(["scan", "--root", root.to_str().unwrap()]);
        for var in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            command.env(var, DEAD);
        }
        command
            .env("ALL_PROXY", DEAD)
            .env("VORDA_ADVISORIES", "online")
            .env("NO_PROXY", "")
            .env("no_proxy", "");
        if json {
            command.arg("--json");
        }
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
            "{stderr}"
        );
        // The scan's own answer (vulnerable), not the generic error exit.
        assert_eq!(output.status.code(), Some(3), "{stderr}");
    }
    // `vorda licenses | head`: a long listing read only in part.
    let mut child = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("licenses")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_eq!(output.status.code(), Some(0), "{stderr}");
}

#[test]
fn summary_keeps_every_fixed_version_unsorted() {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = project_fixed_in(temp.path(), &["1.0.0", "1.0.0-rc.1", "0.9.0"]);
    let (exit, text, stderr) = vorda(&state, &["scan", "--root", root.to_str().unwrap()]);
    assert_eq!(exit, 3, "{stderr}");
    let line = text.lines().find(|l| l.contains("fixed in ")).expect(&text);
    let mut shown: Vec<&str> = line
        .split("fixed in ")
        .nth(1)
        .unwrap()
        .split(", ")
        .collect();
    shown.sort_unstable();
    assert_eq!(shown, ["0.9.0", "1.0.0", "1.0.0-rc.1"], "{text}");
}

#[test]
fn summary_names_a_package_version_once_across_lockfiles() {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = project(temp.path(), 2);
    for sub in ["web", "api"] {
        fs::create_dir_all(root.join(sub)).unwrap();
        fs::write(root.join(sub).join("package-lock.json"), LOCK).unwrap();
    }
    let (exit, text, stderr) = vorda(&state, &["scan", "--root", root.to_str().unwrap()]);
    assert_eq!(exit, 3, "{stderr}");
    assert_eq!(text.matches("example 1.2.3").count(), 1, "{text}");
    assert!(text.contains("in 1 package:"), "{text}");
    assert!(text.contains("and 2 others): 2 advisories"), "{text}");
}

#[test]
fn mcp_list_is_bounded_and_pages_with_after() {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = project(temp.path(), 25);
    let (exit, _, stderr) = vorda(&state, &["scan", "--root", root.to_str().unwrap()]);
    assert_eq!(exit, 3, "{stderr}");
    let list = |args: Value| {
        let request = json!({"method":"tools/call","params":{"name":"list","arguments":args}});
        mcp::call(&state, &request, None, None).unwrap()["content"].clone()
    };
    let first = list(json!({"reader":"agent"}));
    let page: Value = serde_json::from_str(first[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(page.as_array().unwrap().len(), 20);
    let marker: Value = serde_json::from_str(first[1]["text"].as_str().unwrap()).unwrap();
    assert_eq!(marker["truncated"], true);
    assert_eq!(marker["remaining"], 5);
    assert_eq!(marker["next_after"], page[19]["id"]);
    let rest = list(json!({"reader":"agent","after":marker["next_after"]}));
    assert_eq!(rest.as_array().unwrap().len(), 1);
    let rest: Value = serde_json::from_str(rest[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(rest.as_array().unwrap().len(), 5);
    let all = list(json!({"reader":"agent","limit":100}));
    assert_eq!(all.as_array().unwrap().len(), 1);
    let request = json!({"method":"tools/call","params":{"name":"list","arguments":{"reader":"agent","limit":0}}});
    assert!(mcp::call(&state, &request, None, None).is_err());
}
