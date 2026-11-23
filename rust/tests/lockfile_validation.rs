use serde_json::{json, Value};
use std::{fs, process::Command};

fn inventory(name: &str, text: &str) -> (i32, Value) {
    inventory_files(&[(name, text)])
}

fn inventory_files(files: &[(&str, &str)]) -> (i32, Value) {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("project");
    fs::create_dir(&root).unwrap();
    for (name, text) in files {
        fs::write(root.join(name), text).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(t.path().join("state"))
        .args(["inventory", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), value)
}

fn accepted() -> Vec<(&'static str, String)> {
    let mut cases = vec![];
    for v in [1, 2, 3] {
        let lock = if v == 1 {
            json!({"lockfileVersion":v,"dependencies":{"lodash":{"version":"4.17.20"}}})
        } else {
            json!({"lockfileVersion":v,"packages":{"node_modules/lodash":{"version":"4.17.20"}}})
        };
        cases.push(("package-lock.json", lock.to_string()));
    }
    for v in ["6.0", "9.0"] {
        let prefix = if v == "6.0" { "/" } else { "" };
        cases.push(("pnpm-lock.yaml", format!("lockfileVersion: '{v}'\ndependencies:\n  '@babel/traverse':\n    version: 7.23.0\npackages:\n  '{prefix}@babel/traverse@7.23.0':\n    resolution: {{integrity: fixture}}\n")));
    }
    cases.push((
        "yarn.lock",
        "# yarn lockfile v1\nlodash@4.17.20:\n  version \"4.17.20\"\n".into(),
    ));
    for v in [8, 10] {
        cases.push((
            "yarn.lock",
            format!("__metadata:\n  version: {v}\n\"lodash@npm:4.17.20\":\n  version: 4.17.20\n"),
        ));
    }
    for v in [0, 1, 2] {
        cases.push(("bun.lock", format!("{{\"lockfileVersion\":{v},\"packages\":{{\"lodash\":[\"lodash@4.17.20\",\"\",{{}},\"fixture\"]}}}}")));
    }
    cases.push((
        "uv.lock",
        "version = 1\n[[package]]\nname = \"django\"\nversion = \"2.2.0\"\n".into(),
    ));
    for v in ["1.0", "1.1", "2.0", "2.1"] {
        cases.push(("poetry.lock", format!("[[package]]\nname = \"django\"\nversion = \"2.2.0\"\n[metadata]\nlock-version = \"{v}\"\n")));
    }
    cases.push((
        "Pipfile.lock",
        json!({"_meta":{"pipfile-spec":6},"default":{"django":{"version":"==2.2.0"}}}).to_string(),
    ));
    for v in [1, 2, 3, 4] {
        cases.push((
            "Cargo.lock",
            format!("version = {v}\n[[package]]\nname = \"time\"\nversion = \"0.1.44\"\n"),
        ));
    }
    for v in [1, 2] {
        cases.push(("packages.lock.json", json!({"version":v,"dependencies":{"net8.0":{"Example.Package":{"type":"Direct","resolved":"1.2.3"}}}}).to_string()));
    }
    for name in [
        "composer.lock",
        "Gemfile.lock",
        "go.sum",
        "requirements.txt",
    ] {
        cases.push((
            name,
            fs::read_to_string(format!(
                "{}/src/scanner/fixtures/locks/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        ));
    }
    cases
}

#[test]
fn accepted_lockfile_versions_keep_exact_packages() {
    for (name, text) in accepted() {
        let (code, d) = inventory(name, &text);
        assert_eq!(code, 0, "{name}: {text}: {d}");
        assert_eq!(d["status"], "complete", "{d}");
        assert_eq!(d["packages"].as_array().unwrap().len(), 1, "{name}: {d}");
        let (package, version, ecosystem) = match name {
            "pnpm-lock.yaml" => ("@babel/traverse", "7.23.0", "npm"),
            "Cargo.lock" => ("time", "0.1.44", "crates.io"),
            "uv.lock" | "poetry.lock" | "Pipfile.lock" | "requirements.txt" => {
                ("django", "2.2.0", "PyPI")
            }
            "packages.lock.json" => ("Example.Package", "1.2.3", "NuGet"),
            "composer.lock" => ("symfony/http-foundation", "2.7.0", "Packagist"),
            "Gemfile.lock" => ("rack", "2.0.0", "RubyGems"),
            "go.sum" => (
                "golang.org/x/crypto",
                "v0.0.0-20200128174031-69ecbb4d6d5d",
                "Go",
            ),
            _ => ("lodash", "4.17.20", "npm"),
        };
        assert_eq!(d["packages"][0]["name"], package, "{d}");
        assert_eq!(d["packages"][0]["version"], version, "{d}");
        assert_eq!(d["packages"][0]["ecosystem"], ecosystem, "{d}");
    }
}

#[test]
fn unsupported_and_missing_format_versions_are_unknown() {
    let berry_version = regex::Regex::new(r"(?m)^  version: (8|10)$").unwrap();
    for (name, text) in accepted() {
        let (marker, old) = match name {
            "package-lock.json" | "bun.lock" => ("lockfileVersion", ":"),
            "Pipfile.lock" => ("pipfile-spec", ":"),
            "packages.lock.json" => ("version", ":"),
            "pnpm-lock.yaml" => ("lockfileVersion", ":"),
            "uv.lock" | "Cargo.lock" => ("version", "="),
            "poetry.lock" => ("lock-version", "="),
            "yarn.lock" => {
                let future = if text.starts_with('#') {
                    text.replace("v1", "v999")
                } else {
                    berry_version.replace(&text, "  version: 999").into_owned()
                };
                let (code, d) = inventory(name, &future);
                assert_unknown(code, &d, name, "999");
                if !text.starts_with('#') {
                    let quoted = future.replace("__metadata:", "\"__metadata\":");
                    let (code, d) = inventory(name, &quoted);
                    assert_unknown(code, &d, name, "999");
                }
                continue;
            }
            _ => continue,
        };
        let pattern = format!(r#"["']?{marker}["']?\s*{old}\s*["']?[^\s,}}"'\n]+["']?"#);
        let re = regex::Regex::new(&pattern).unwrap();
        let value = if name == "poetry.lock" {
            "\"999\""
        } else {
            "999"
        };
        let future = re
            .replacen(&text, 1, format!("\"{marker}\"{old}{value}"))
            .to_string();
        let future = if old == "=" || name == "pnpm-lock.yaml" {
            future.replace(&format!("\"{marker}\""), marker)
        } else {
            future
        };
        let (code, d) = inventory(name, &future);
        assert_unknown(code, &d, name, "999");
        let missing = re
            .replacen(&text, 1, format!("\"unrelated\"{old}1"))
            .to_string();
        let (code, d) = inventory(name, &missing);
        if name == "Cargo.lock" {
            assert_eq!(code, 0, "{d}");
            assert_eq!(d["packages"].as_array().unwrap().len(), 1, "{d}");
        } else {
            assert_unknown(code, &d, name, "missing");
        }
    }
}

fn assert_unknown(code: i32, d: &Value, name: &str, detail: &str) {
    assert_eq!(code, 2, "{name}: {d}");
    assert_eq!(d["status"], "unknown", "{d}");
    assert_eq!(d["packages"], json!([]), "{d}");
    let errors = d["errors"].to_string();
    assert!(errors.contains(name) && errors.contains(detail), "{errors}");
}

fn assert_uncheckable(code: i32, d: &Value, name: &str, good: &str) {
    assert_eq!(code, 2, "{d}");
    assert_eq!(d["status"], "unknown", "{d}");
    assert_eq!(d["packages"].as_array().unwrap().len(), 1, "{d}");
    assert_eq!(d["packages"][0]["name"], good, "{d}");
    let errors = d["errors"].to_string();
    assert!(
        errors.contains(name) && errors.contains("Uncheckable"),
        "{errors}"
    );
}

#[test]
fn pnpm_five_scoped_package_is_unknown() {
    let (code, d) = inventory("pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /@babel/traverse/7.23.0:\n    resolution: {integrity: fixture}\n");
    assert_unknown(code, &d, "pnpm-lock.yaml", "5.4");
    assert!(d["errors"].to_string().contains("supported"));
}

#[test]
fn hostile_entries_are_unknown_and_diagnostics_are_bounded() {
    for (name, version) in [
        ("/", "1.0.0"),
        ("", "1.0.0"),
        ("bad\nname", "1.0.0"),
        ("../x", "1.0.0"),
        ("@scope", "1.0.0"),
        ("good", ""),
        ("good", "1\n2"),
        ("good", "^1.0.0"),
        ("good", "1.2.x"),
        ("good", "1.2"),
        (&"x".repeat(10_000), "1.0.0"),
        ("good", &"1".repeat(10_000)),
    ] {
        let text = json!({"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"},"node_modules/example":{"name":name,"version":version}}}).to_string();
        let (code, d) = inventory("package-lock.json", &text);
        assert_uncheckable(code, &d, "package-lock.json", "a");
        let errors = d["errors"][0].as_str().unwrap();
        assert!(errors.len() < 1000, "diagnostic too long: {}", errors.len());
        assert!(!errors.chars().any(char::is_control), "{errors:?}");
    }
}

#[test]
fn exact_versions_are_not_truncated_before_validation() {
    for (name, text) in [
        ("yarn.lock", "# yarn lockfile v1\nexample@1.0.0:\n  version \"1.0.0 bad\"\n"),
        ("bun.lock", "{\"lockfileVersion\":1,\"packages\":{\"example\":[\"example@1.0.0 bad\"]}}"),
        ("uv.lock", "version = 1\n[[package]]\nname = \"example\"\nversion = \"https://example.invalid/1\"\n"),
        ("packages.lock.json", "{\"version\":1,\"dependencies\":{\"net8.0\":{\"../x\":{\"type\":\"Direct\",\"resolved\":\"1.0.0\"}}}}"),
    ] {
        let (code, d) = inventory(name, text);
        assert_unknown(code, &d, name, "entry");
    }
}

#[test]
fn content_without_readable_packages_is_unknown_but_declared_empty_is_complete() {
    for text in [
        r#"{"lockfileVersion":3,"packages":{"node_modules/example":{}}}"#,
        r#"{"lockfileVersion":3,"unexpected":{"example":"1.0.0"}}"#,
    ] {
        let (code, d) = inventory("package-lock.json", text);
        assert_unknown(code, &d, "package-lock.json", "package");
    }
    let (code, d) = inventory_files(&[
        (
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"name":"empty-project","version":"1.0.0"}}}"#,
        ),
        (
            "package.json",
            r#"{"name":"empty-project","version":"1.0.0"}"#,
        ),
    ]);
    // Read without a file error, and neither file declares anything: no dependencies.
    assert_eq!(code, 0, "{d}");
    assert_eq!(d["status"], "complete", "{d}");
    assert_eq!(d["packages"], json!([]));
    assert_eq!(d["errors"], json!([]), "{d}");
}

/// pnpm 11 and later write the package manager's own lock as a first YAML document.
const PNPM_MULTI_DOCUMENT: &str = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies: {}\n    packageManagerDependencies:\n      pnpm:\n        specifier: 12.21.0\n        version: 12.21.0\n\npackages:\n\n  pnpm@12.21.0:\n    resolution: {integrity: fixture}\n\n  lodash@4.17.20:\n    resolution: {integrity: fixture}\n\n---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: 4.17.20\n        version: 4.17.20\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: fixture}\n\n  '@babel/traverse@7.23.0':\n    resolution: {integrity: fixture}\n";

#[test]
fn pnpm_multi_document_lock_reads_every_document_once() {
    let (code, d) = inventory("pnpm-lock.yaml", PNPM_MULTI_DOCUMENT);
    assert_eq!(code, 0, "{d}");
    assert_eq!(d["status"], "complete", "{d}");
    let mut found: Vec<_> = d["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            format!(
                "{}@{}",
                p["name"].as_str().unwrap(),
                p["version"].as_str().unwrap()
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        ["@babel/traverse@7.23.0", "lodash@4.17.20", "pnpm@12.21.0"],
        "{d}"
    );
}

#[test]
fn pnpm_later_document_with_unsupported_version_is_unknown() {
    let (head, tail) = PNPM_MULTI_DOCUMENT
        .rsplit_once("lockfileVersion: '9.0'")
        .unwrap();
    let future = format!("{head}lockfileVersion: '999.0'{tail}");
    let (code, d) = inventory("pnpm-lock.yaml", &future);
    assert_unknown(code, &d, "pnpm-lock.yaml", "999.0");
}

#[test]
fn future_uv_revision_is_unknown() {
    let (code, d) = inventory(
        "uv.lock",
        "version = 1\nrevision = 999\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\n",
    );
    assert_unknown(code, &d, "uv.lock", "999");
}

#[test]
fn future_bun_config_version_is_unknown() {
    let (code, d) = inventory(
        "bun.lock",
        r#"{"lockfileVersion":2,"configVersion":999,"packages":{"example":["example@1.0.0"]}}"#,
    );
    assert_unknown(code, &d, "bun.lock", "999");
}

#[test]
fn supported_secondary_markers_preserve_packages() {
    for revision in [1, 2, 3, 4, 5] {
        let (code, d) = inventory("uv.lock", &format!("version = 1\nrevision = {revision}\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\n"));
        assert_eq!(code, 0, "{d}");
        assert_eq!(d["packages"][0]["name"], "example");
        assert_eq!(d["packages"][0]["version"], "1.0.0");
    }
    let (code, d) = inventory(
        "bun.lock",
        r#"{"lockfileVersion":2,"configVersion":1,"packages":{"example":["example@1.0.0"]}}"#,
    );
    assert_eq!(code, 0, "{d}");
    assert_eq!(d["packages"][0]["name"], "example");
    assert_eq!(d["packages"][0]["version"], "1.0.0");
}

#[test]
fn bun_does_not_drop_an_empty_name_beside_a_valid_package() {
    let (code, d) = inventory(
        "bun.lock",
        r#"{"lockfileVersion":2,"packages":{"good":["good@1.0.0"],"":["@1.0.0"]}}"#,
    );
    assert_uncheckable(code, &d, "bun.lock", "good");
}

#[test]
fn yarn_does_not_drop_an_empty_name_beside_a_valid_package() {
    let (code, d) = inventory(
        "yarn.lock",
        "# yarn lockfile v1\ngood@1.0.0:\n  version \"1.0.0\"\n@1.0.0:\n  version \"1.0.0\"\n",
    );
    assert_uncheckable(code, &d, "yarn.lock", "good");
}

#[test]
fn pnpm_does_not_drop_an_empty_name_beside_a_valid_package() {
    let (code, d) = inventory("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  good@1.0.0:\n    resolution: {integrity: fixture}\n  '@1.0.0':\n    resolution: {integrity: fixture}\n");
    assert_uncheckable(code, &d, "pnpm-lock.yaml", "good");
}

#[test]
fn bundler_does_not_drop_an_empty_name_beside_a_valid_package() {
    let (code, d) = inventory(
        "Gemfile.lock",
        "GEM\n  specs:\n    good (1.0.0)\n     (1.0.0)\n",
    );
    assert_uncheckable(code, &d, "Gemfile.lock", "good");
}

#[test]
fn go_sum_does_not_drop_a_missing_name_beside_a_valid_package() {
    let (code, d) = inventory(
        "go.sum",
        "example.invalid/good v1.0.0 h1:fixture\n v1.0.0 h1:fixture\n",
    );
    assert_uncheckable(code, &d, "go.sum", "example.invalid/good");
}

#[test]
fn bun_format_markers_are_read_from_the_root_object() {
    for text in [
        r#"{"packages":{"good":["good@1.0.0","",{"lockfileVersion":2}]},"lockfileVersion":999}"#,
        r#"{"lockfileVersion":2,"packages":{"good":["good@1.0.0","",{"configVersion":1}]},"configVersion":999}"#,
    ] {
        let (code, d) = inventory("bun.lock", text);
        assert_unknown(code, &d, "bun.lock", "999");
    }
}

#[test]
fn poetry_format_version_is_read_from_metadata() {
    let (code, d) = inventory("poetry.lock", "[[package]]\nname = \"good\"\nversion = \"1.0.0\"\nlock-version = \"2.0\"\n[metadata]\nlock-version = \"999\"\n");
    assert_unknown(code, &d, "poetry.lock", "999");
}

#[test]
fn bun_comments_do_not_declare_format_versions() {
    let (code, d) = inventory("bun.lock", "{\n// \"lockfileVersion\": 999\n\"lockfileVersion\":2,\n\"packages\":{\"good\":[\"good@1.0.0\"]},\n}\n");
    assert_eq!(code, 0, "{d}");
    assert_eq!(d["status"], "complete");
    assert_eq!(d["packages"][0]["name"], "good");
    assert_eq!(d["packages"][0]["version"], "1.0.0");
}

#[test]
fn pnpm_format_version_is_not_truncated_at_whitespace() {
    let (code, d) = inventory("pnpm-lock.yaml", "lockfileVersion: '9.0 future'\npackages:\n  good@1.0.0:\n    resolution: {integrity: fixture}\n");
    assert_unknown(code, &d, "pnpm-lock.yaml", "future");
}

#[test]
fn yarn_format_version_is_not_truncated_at_whitespace() {
    let (code, d) = inventory(
        "yarn.lock",
        "__metadata:\n  version: '8 future'\ngood@1.0.0:\n  version: 1.0.0\n",
    );
    assert_unknown(code, &d, "yarn.lock", "future");
}

#[test]
fn pnpm_does_not_drop_an_empty_version_beside_a_valid_package() {
    let (code, d) = inventory(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  good@1.0.0: {}\n  'bad@': {}\n",
    );
    assert_uncheckable(code, &d, "pnpm-lock.yaml", "good");
}

#[test]
fn pnpm_does_not_drop_whitespace_in_a_version_beside_a_valid_package() {
    let (code, d) = inventory(
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  good@1.0.0: {}\n  'bad@1.0.0 bad': {}\n",
    );
    assert_uncheckable(code, &d, "pnpm-lock.yaml", "good");
}
