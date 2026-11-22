use serde_json::{json, Value};
use std::{fs, process::Command};

fn run(name: &str, text: &str, scan: bool) -> (i32, Value) {
    run_files(&[(name, text)], scan)
}

/// A manifest beside `lock` that declares no dependencies.
fn bare_manifest(lock: &str) -> (&'static str, &'static str) {
    match lock {
        "uv.lock" | "poetry.lock" => (
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        ),
        _ => ("package.json", r#"{"name":"demo"}"#),
    }
}

fn run_files(files: &[(&str, &str)], scan: bool) -> (i32, Value) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    for (name, text) in files {
        fs::write(root.join(name), text).unwrap();
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vorda"));
    cmd.arg("--state").arg(temp.path().join("state"));
    cmd.arg(if scan { "scan" } else { "inventory" });
    if scan {
        cmd.args(["--offline", "--json"]);
    }
    let out = cmd.arg("--root").arg(root).output().unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap(),
    )
}

fn refused(name: &str, text: &str, detail: &str) {
    for scan in [false, true] {
        let (code, d) = run(name, text, scan);
        assert_eq!(code, 2, "{name}: {d}");
        assert_eq!(d["status"], "unknown", "{d}");
        assert_eq!(d["packages"], json!([]), "{d}");
        let errors = d["errors"].to_string();
        assert!(errors.contains(name) && errors.contains(detail), "{errors}");
        assert!(
            !errors.contains("querybatch"),
            "refused file reached feed: {d}"
        );
    }
}

fn complete(name: &str, text: &str, count: usize) -> Value {
    if count == 0 {
        // A declared-empty file beside a manifest that declares nothing: a project with no
        // dependencies.
        let (code, d) = run_files(&[(name, text), bare_manifest(name)], false);
        assert_eq!(code, 0, "{name}: {d}");
        assert_eq!(d["status"], "complete", "{d}");
        assert_eq!(d["packages"], json!([]), "{d}");
        assert_eq!(d["errors"], json!([]), "{d}");
        assert!(
            d["completed_paths"][0].as_str().unwrap().ends_with(name),
            "{d}"
        );
        return d;
    }
    let (code, d) = run(name, text, false);
    assert_eq!(code, 0, "{name}: {d}");
    assert_eq!(d["status"], "complete", "{d}");
    assert_eq!(d["packages"].as_array().unwrap().len(), count, "{d}");
    d
}

fn uncheckable(name: &str, text: &str, good: &str, detail: &str) {
    for scan in [false, true] {
        let (code, data) = run(name, text, scan);
        assert_eq!(code, 2, "{data}");
        assert_eq!(data["status"], "unknown", "{data}");
        assert_eq!(data["packages"].as_array().unwrap().len(), 1, "{data}");
        assert_eq!(data["packages"][0]["name"], good, "{data}");
        let errors = data["errors"].to_string();
        assert!(
            errors.contains(name) && errors.contains(detail) && errors.contains("Uncheckable"),
            "{errors}"
        );
    }
}

#[test]
fn major1_bun_malformed_tuple_cannot_disappear() {
    uncheckable(
        "bun.lock",
        r#"{"lockfileVersion":1,"packages":{"good":["good@1.2.3"],"bad":["https://example.invalid/repo"]}}"#,
        "good",
        "bad",
    );
}

#[test]
fn major1_gem_spec_without_version_cannot_disappear() {
    uncheckable(
        "Gemfile.lock",
        "GEM\n  specs:\n    good (1.2.3)\n    bad\n\nDEPENDENCIES\n  good\n  bad\n",
        "good",
        "bad",
    );
}

#[test]
fn major1_pipfile_malformed_group_cannot_disappear() {
    refused(
        "Pipfile.lock",
        r#"{"_meta":{"pipfile-spec":6},"default":{"good":{"version":"==1.2.3"}},"develop":[{"name":"bad"}]}"#,
        "develop",
    );
}

#[test]
fn major2_wildcards_are_not_exact_versions() {
    for version in ["1.2.x", "1.2.X", "release1"] {
        refused("Pipfile.lock", &json!({"_meta":{"pipfile-spec":6},"default":{"demo":{"version":format!("=={version}")}}}).to_string(), "entry");
    }
    for version in ["1.x", "v1.x", "1.2.X", "release1"] {
        refused(
            "composer.lock",
            &json!({"packages":[{"name":"vendor/demo","version":version}]}).to_string(),
            "entry",
        );
    }
}

#[test]
fn major3_uv_comment_cannot_declare_empty_packages() {
    refused(
        "uv.lock",
        "version = 1\n# package = []\nthis_is_not_a_package = true\n",
        "package",
    );
}

#[test]
fn major3_bun_nested_object_cannot_declare_empty_packages() {
    refused(
        "bun.lock",
        r#"{"lockfileVersion":1,"workspaces":{"packages":{}},"packages":{"bad":[]}}"#,
        "bad",
    );
}

#[test]
fn major4_root_markers_cannot_come_from_named_tables() {
    refused(
        "uv.lock",
        "[manifest]\nversion = 1\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n",
        "missing",
    );
    refused(
        "uv.lock",
        "version = 1 future\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n",
        "future",
    );
}

#[test]
fn major5_empty_pnpm_importer_is_complete_but_unread_dependencies_are_not() {
    complete(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\nimporters:\n  .: {}\n",
        0,
    );
    refused("pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      demo:\n        version: 1.2.3\n", "package");
    refused(
        "pnpm-lock.yaml",
        "lockfileVersion: '999'\nimporters:\n  .: {}\n",
        "999",
    );
    refused(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages: []\n",
        "package",
    );
}

#[test]
fn minor6_supported_syntax_keeps_hostile_controls_refused() {
    complete(
        "poetry.lock",
        "[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n[metadata]\nlock-version = '2.1'\n",
        1,
    );
    refused(
        "poetry.lock",
        "[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n[metadata]\nlock-version = '999'\n",
        "999",
    );
    refused(
        "poetry.lock",
        "[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n[metadata]\nlock-version = '2.1\"\n",
        "invalid TOML",
    );
    complete(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages: # resolved packages\n  demo@1.2.3: {}\n",
        1,
    );
    refused(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages: # resolved packages\n  demo@1.2.x: {}\n",
        "entry",
    );
}

#[test]
fn empty_controls_and_numeric_marker_controls_remain_distinct_from_garbage() {
    for (name, text) in [
        ("uv.lock", "version = 1\npackage = []\n"),
        (
            "poetry.lock",
            "package = []\n[metadata]\nlock-version = \"2.1\"\n",
        ),
        ("bun.lock", "{\"lockfileVersion\":1,\"packages\":{}}"),
    ] {
        complete(name, text, 0);
    }
    for (name, version) in [("uv.lock", 1), ("Cargo.lock", 4)] {
        complete(
            name,
            &format!("version = {version}\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n"),
            1,
        );
        refused(
            name,
            "version = 999\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n",
            "999",
        );
    }
}

#[test]
fn legitimate_odd_versions_and_source_metadata_keep_their_exact_identity() {
    for v in ["1!2.0", "2.0+local.x", "1.0rc1.post2.dev3", "v1.0-1"] {
        let d = complete("Pipfile.lock", &json!({"_meta":{"pipfile-spec":6},"default":{"Upper.Name_test":{"version":format!("=={v}")}}}).to_string(), 1);
        assert_eq!(d["packages"][0]["version"], v);
    }
    for v in ["dev-main", "1.x-dev", "dev-feature/one", "v1.2.3-RC1"] {
        complete(
            "composer.lock",
            &json!({"packages":[{"name":"vendor/demo","version":v}]}).to_string(),
            1,
        );
    }
    for source in [
        "git+https://example.invalid/repo#abc",
        "https://example.invalid/a.tgz",
        "file:../local",
        "workspace:*",
    ] {
        let d = complete("package-lock.json", &json!({"lockfileVersion":3,"packages":{"node_modules/Upper.Name_test":{"version":"1.2.3+build","resolved":source}}}).to_string(), 1);
        assert_eq!(d["packages"][0]["name"], "Upper.Name_test");
        complete("package-lock.json", &json!({"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.2.3","resolved":source,"link":true}}}).to_string(), 1);
        complete(
            "yarn.lock",
            &format!("\"demo@{source}\":\n  version \"1.2.3\"\n"),
            1,
        );
    }
}

#[test]
fn source_only_entries_are_named_uncheckable_while_good_packages_remain() {
    uncheckable(
        "package-lock.json",
        &json!({"lockfileVersion":3,"packages":{"node_modules/good":{"version":"1.2.3"},"node_modules/local":{"name":"bad\nname","version":"https://example.invalid/repo"}}}).to_string(),
        "good",
        "entry",
    );
    for source in [
        "git+https://example.invalid/repo#abc",
        "git+ssh://git@example.invalid/repo",
        "https://example.invalid/a.tgz",
        "file:../local",
        "../x",
        "workspace:*",
    ] {
        for (name, text) in [
            ("package-lock.json", json!({"lockfileVersion":3,"packages":{"node_modules/good":{"version":"1.2.3"},"node_modules/local":{"version":source}}}).to_string()),
            ("pnpm-lock.yaml", format!("lockfileVersion: '9.0'\npackages:\n  good@1.2.3: {{}}\n  'local@{source}': {{}}\n")),
        ] {
            for scan in [false, true] {
                let (code, d) = run(name, &text, scan);
                assert_eq!(code, 2, "{d}");
                assert_eq!(d["status"], "unknown", "{d}");
                let p = d["packages"].as_array().unwrap();
                assert_eq!(p.len(), 1, "{d}");
                assert_eq!(p[0]["name"], "good", "{d}");
                let errors = d["errors"].to_string();
                assert!(errors.contains(name) && errors.contains("local") && errors.contains("Uncheckable"), "{d}");
            }
        }
    }
}
