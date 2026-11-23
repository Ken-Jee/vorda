use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    scanner::feeds::{KEV, OSV},
    store::{identity, now},
};

const LOCK: &str =
    r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.2.3"}}}"#;

fn scan(root: &Path, ecosystem: &str) -> (i32, Value) {
    scan_named(root, ecosystem, "example")
}

fn scan_named(root: &Path, ecosystem: &str, name: &str) -> (i32, Value) {
    scan_version(root, ecosystem, name, "1.2.3")
}

fn scan_version(root: &Path, ecosystem: &str, name: &str, version: &str) -> (i32, Value) {
    let state = tempfile::tempdir().unwrap();
    let cache = state.path().join("cache");
    fs::create_dir(&cache).unwrap();
    let query =
        json!({"queries":[{"package":{"name":name,"ecosystem":ecosystem},"version":version}]});
    for (url, body, data) in [
        (KEV.to_string(), Value::Null, json!({"vulnerabilities":[]})),
        (format!("{OSV}/querybatch"), query, json!({"results":[{}]})),
    ] {
        fs::write(
            cache.join(format!("{}.json", identity(&json!([url, body])).unwrap())),
            json!({"source_url":url,"checked":now(),"data":data}).to_string(),
        )
        .unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .env("VORDA_ADVISORIES", "online")
        .env("HTTPS_PROXY", "http://localhost:9")
        .env("HTTP_PROXY", "http://localhost:9")
        .env("NO_PROXY", "")
        .arg("--state")
        .arg(state.path())
        .args(["scan", "--json", "--root"])
        .arg(root)
        .output()
        .unwrap();
    let result = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), result)
}

fn unknown(root: &Path, names: &[&str]) -> Value {
    let (exit, result) = scan(root, "PyPI");
    assert_eq!(exit, 2, "{result}");
    assert_eq!(result["status"], "unknown", "{result}");
    assert_ne!(
        result["coverage_evidence"]["status"], "complete",
        "{result}"
    );
    assert!(
        result["coverage_evidence"]["observations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["kind"] == "incomplete-input"),
        "{result}"
    );
    let errors = result["errors"].to_string();
    for name in names {
        assert!(errors.contains(name), "missing {name}: {result}");
    }
    result
}

#[test]
fn an_unpinned_requirement_is_named_without_its_line_or_comment() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("requirements.txt"),
        "example==1.2.3\nhttpx            # REST adapters\nfastapi>=0.115\n",
    )
    .unwrap();
    let result = unknown(root.path(), &["httpx==VERSION", "fastapi==VERSION"]);
    let errors = result["errors"].as_array().unwrap();
    assert!(errors.iter().all(|e| e["not_covered"] == true), "{result}");
    assert!(
        !result["errors"].to_string().contains("REST adapters"),
        "{result}"
    );
}

/// A file of requirement lines in a requirements folder is read like requirements.txt: option
/// lines are skipped, exact pins are checked, and anything else leaves the scan unknown.
#[test]
fn requirements_folder_files_are_read_like_requirements_txt() {
    for options in [
        "-i https://example.invalid/simple",
        "--index-url https://example.invalid/simple\n--trusted-host example.invalid",
        "--extra-index-url https://example.invalid/simple",
        "--pre",
        "--no-binary :all:",
        "--only-binary :all:",
        "--prefer-binary",
        "--require-hashes",
        "-f ./wheels",
        "--find-links ./wheels",
        "-c constraints.txt",
        "# generated input",
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("requirements")).unwrap();
        fs::write(
            root.path().join("requirements/prod.txt"),
            format!("{options}\nexample==1.2.3 # keep pinned\n"),
        )
        .unwrap();
        let (exit, result) = scan(root.path(), "PyPI");
        assert_eq!(exit, 0, "{options}: {result}");
        assert_eq!(
            result["coverage_evidence"]["status"], "complete",
            "{result}"
        );
    }
    for text in [
        "-r shared.txt\nDjango==2.2\n",
        "-e ./local\nDjango==2.2\n",
        "requests [security] == 2.19.0\n",
        "Django (==2.2)\n",
        "We pin these:\nDjango==2.2\n",
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        fs::create_dir(root.path().join("requirements")).unwrap();
        fs::write(root.path().join("requirements/prod.txt"), text).unwrap();
        unknown(root.path(), &["prod.txt"]);
    }
}

macro_rules! pyproject_declaration_case {
    ($test:ident, $text:literal) => {
        #[test]
        fn $test() {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
            fs::create_dir(root.path().join("member")).unwrap();
            fs::write(root.path().join("member/pyproject.toml"), $text).unwrap();
            unknown(root.path(), &["member/pyproject.toml"]);
        }
    };
}
pyproject_declaration_case!(
    uv_dev_dependencies_are_unread,
    "[tool.uv]\ndev-dependencies=['Django==2.2']\n"
);
pyproject_declaration_case!(
    hatch_environment_dependencies_are_unread,
    "[tool.hatch.envs.default]\ndependencies=['Django==2.2']\n"
);
pyproject_declaration_case!(
    pixi_dependencies_are_unread,
    "[tool.pixi.dependencies]\npython='3.12'\n"
);
pyproject_declaration_case!(
    flit_legacy_requires_are_unread,
    "[tool.flit.metadata]\nrequires=['Django==2.2']\n"
);

#[test]
fn pipfile_needs_adjacent_pipfile_lock() {
    for (manifest, lock) in [
        ("Pipfile", "poetry.lock"),
        ("member/Pipfile", "uv.lock"),
        ("member/Pipfile", "Pipfile.lock"),
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        let path = root.path().join(manifest);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "[packages]\nDjango='==2.2'\n").unwrap();
        fs::write(
            root.path().join(lock),
            if lock == "Pipfile.lock" {
                "{\"default\":{\"example\":{\"version\":\"==1.2.3\"}}}"
            } else {
                "[[package]]\nname='example'\nversion='1.2.3'\n"
            },
        )
        .unwrap();
        unknown(root.path(), &[manifest]);
    }
}

#[test]
fn central_nuget_versions_use_discovered_project_locks() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Directory.Packages.props"), "<Project><ItemGroup><PackageVersion Include=\"example\" Version=\"1.2.3\"/></ItemGroup></Project>").unwrap();
    fs::create_dir(root.path().join("App")).unwrap();
    fs::write(root.path().join("App/App.csproj"), "<Project/>").unwrap();
    fs::write(root.path().join("App/packages.lock.json"), r#"{"version":1,"dependencies":{"net8.0":{"example":{"type":"Direct","resolved":"1.2.3"}}}}"#).unwrap();
    let (exit, result) = scan(root.path(), "NuGet");
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["status"], "no-known-findings");
    assert_eq!(result["coverage_evidence"]["status"], "complete");
    assert_eq!(result["errors"], json!([]));
}

#[test]
fn central_nuget_versions_are_not_covered_by_ignored_locks() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    fs::write(root.path().join("Directory.Packages.props"), "<Project/>").unwrap();
    fs::create_dir(root.path().join("node_modules")).unwrap();
    fs::write(root.path().join("node_modules/packages.lock.json"), "{}").unwrap();
    unknown(root.path(), &["Directory.Packages.props"]);
}

#[test]
fn gems_rb_reports_its_unread_lock_format() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("gems.rb"), "gem 'example'\n").unwrap();
    let result = unknown(root.path(), &["gems.rb"]);
    assert!(result["errors"]
        .to_string()
        .contains("does not read gems.locked"));
}

#[test]
fn non_utf8_pyproject_explains_unknown_coverage() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    fs::create_dir(root.path().join("member")).unwrap();
    fs::write(
        root.path().join("member/pyproject.toml"),
        b"[project]\nname='\xff'\n",
    )
    .unwrap();
    let result = unknown(root.path(), &["pyproject.toml"]);
    assert!(result["errors"].to_string().contains("coverage is unknown"));
}

#[test]
fn unread_manifests_cannot_hide_beside_clean_requirements() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    for (name, text) in [
        ("pom.xml", "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>"),
        ("package.json", r#"{"dependencies":{"lodash":"4.17.20","minimist":"0.0.8"}}"#),
    ] {
        fs::write(root.path().join(name), text).unwrap();
    }
    let result = unknown(root.path(), &["pom.xml", "package.json"]);
    assert!(result["errors"].to_string().contains("not supported"));
}

macro_rules! unread_case {
    ($test:ident, $name:literal) => {
        #[test]
        fn $test() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join($name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                &path,
                if $name == "pyproject.toml" {
                    "[project]\ndependencies = ['example==1.2.3']\n"
                } else {
                    "example==1.2.3\n"
                },
            )
            .unwrap();
            let result = unknown(root.path(), &[path.file_name().unwrap().to_str().unwrap()]);
            let errors = result["errors"].to_string();
            assert!(errors.contains("not supported") || errors.contains("No supported lockfile"));
        }
    };
}

unread_case!(lockless_package_is_unknown, "package.json");
unread_case!(shrinkwrap_is_unknown, "npm-shrinkwrap.json");
unread_case!(gradle_build_is_unknown, "build.gradle");
unread_case!(gradle_kotlin_is_unknown, "build.gradle.kts");
unread_case!(gradle_lock_is_unknown, "gradle.lockfile");
unread_case!(pyproject_is_unknown, "pyproject.toml");
unread_case!(pipfile_is_unknown, "Pipfile");
unread_case!(pdm_is_unknown, "pdm.lock");
unread_case!(mix_is_unknown, "mix.lock");
unread_case!(pubspec_is_unknown, "pubspec.lock");
unread_case!(deno_is_unknown, "deno.lock");
unread_case!(reversed_requirements_is_unknown, "dev-requirements.txt");
unread_case!(setup_script_is_unknown, "setup.py");
unread_case!(setup_config_is_unknown, "setup.cfg");

#[cfg(unix)]
fn skipped_link(symbolic: bool) {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    let target = root.path().join("source.json");
    fs::write(&target, LOCK).unwrap();
    let path = root.path().join("package-lock.json");
    if symbolic {
        std::os::unix::fs::symlink(&target, path).unwrap();
    } else {
        fs::hard_link(&target, path).unwrap();
    }
    unknown(
        root.path(),
        &[
            "package-lock.json",
            if symbolic {
                "symbolic link"
            } else {
                "hard-linked"
            },
        ],
    );
}

#[cfg(unix)]
#[test]
fn skipped_symlink_is_unknown() {
    skipped_link(true);
}

#[cfg(unix)]
#[test]
fn skipped_hard_link_is_unknown() {
    skipped_link(false);
}

#[cfg(unix)]
#[test]
fn test_and_example_files_vorda_cannot_check_are_listed_not_unknown() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    let fixtures = [
        ("tests/fixtures/app/Pipfile", "[packages]\nDjango='==2.2'\n"),
        ("Examples/demo/pom.xml", "<project/>"),
        ("web/__tests__/broken/package-lock.json", "{"),
    ];
    for (path, text) in fixtures {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let (exit, result) = scan(root.path(), "PyPI");
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["status"], "no-known-findings", "{result}");
    assert_eq!(result["coverage_evidence"]["status"], "partial", "{result}");
    let skipped: Vec<&str> = result["coverage_evidence"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["kind"] == "not-covered-test-data")
        .map(|o| o["path"].as_str().unwrap())
        .collect();
    for (path, _) in fixtures {
        assert!(
            skipped.iter().any(|s| s.ends_with(path)),
            "{path}: {result}"
        );
        assert!(result["warnings"].to_string().contains(path), "{result}");
    }
    // Outside a test folder, or as the scan root itself, the same file still means unknown.
    unknown(&root.path().join("tests/fixtures/app"), &["Pipfile"]);
    let app = root.path().join("app");
    fs::create_dir(&app).unwrap();
    fs::write(app.join("Pipfile"), "[packages]\nDjango='==2.2'\n").unwrap();
    unknown(root.path(), &["app/Pipfile"]);
}

#[cfg(unix)]
#[test]
fn unreadable_lockfile_is_unknown() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    let path = root.path().join("package-lock.json");
    fs::write(&path, LOCK).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
    let result = unknown(root.path(), &["package-lock.json", "Permission denied"]);
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(result["status"], "unknown");
}

#[test]
fn supported_workspaces_and_ignored_manifests_stay_clean() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"workspaces":["packages/*"]},"packages/member":{},"node_modules/example":{"version":"1.2.3"}}}"#,
    )
    .unwrap();
    for name in [
        "package.json",
        "packages/member/package.json",
        "node_modules/dependency/pom.xml",
        ".git/hidden/pom.xml",
    ] {
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "{}").unwrap();
    }
    let (exit, result) = scan(root.path(), "npm");
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["status"], "no-known-findings");
    assert_eq!(result["errors"], json!([]));
    assert_eq!(result["coverage_evidence"]["status"], "complete");
}

#[test]
fn a_lockfile_outside_the_root_does_not_cover_a_manifest() {
    let outer = tempfile::tempdir().unwrap();
    fs::write(outer.path().join("package-lock.json"), LOCK).unwrap();
    let root = outer.path().join("member");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("package.json"), "{}").unwrap();
    unknown(&root, &["package.json"]);
}

#[test]
fn python_manifest_with_adjacent_requirements_stays_clean() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("pyproject.toml"),
        "[project]\nname = 'example'\n",
    )
    .unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    let (exit, result) = scan(root.path(), "PyPI");
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["status"], "no-known-findings");
}

macro_rules! mixed_unread_case {
    ($test:ident, $name:literal, $text:literal) => {
        #[test]
        fn $test() {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
            let path = root.path().join($name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, $text).unwrap();
            let result = unknown(root.path(), &[path.file_name().unwrap().to_str().unwrap()]);
            let errors = result["errors"].to_string();
            assert!(errors.contains("not supported") || errors.contains("No supported lockfile"));
        }
    };
}

mixed_unread_case!(
    underscore_requirements_cannot_hide,
    "dev_requirements.txt",
    "Django==2.2\n"
);
mixed_unread_case!(
    underscore_requirements_input_cannot_hide,
    "dev_requirements.in",
    "Django==2.2\n"
);
mixed_unread_case!(
    lockless_cargo_cannot_hide,
    "Cargo.toml",
    "[package]\nname = 'fixture'\nversion = '0.1.0'\n[dependencies]\nchrono = '=0.4.19'\n"
);
mixed_unread_case!(
    lockless_gemfile_cannot_hide,
    "Gemfile",
    "source 'https://rubygems.org'\ngem 'nokogiri', '1.10.10'\n"
);
mixed_unread_case!(
    lockless_composer_cannot_hide,
    "composer.json",
    r#"{"require":{"guzzlehttp/guzzle":"6.5.0"}}"#
);
mixed_unread_case!(
    deno_manifest_cannot_hide,
    "deno.json",
    r#"{"imports":{"lodash":"npm:lodash@4.17.20"}}"#
);
mixed_unread_case!(
    deno_jsonc_cannot_hide,
    "deno.jsonc",
    "{\n// dependencies\n\"imports\":{\"lodash\":\"npm:lodash@4.17.20\"}\n}\n"
);
mixed_unread_case!(
    pubspec_manifest_cannot_hide,
    "pubspec.yaml",
    "name: fixture\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  http: 0.13.0\n"
);
mixed_unread_case!(mix_manifest_cannot_hide, "mix.exs", "defmodule Fixture.MixProject do\n  use Mix.Project\n  def project, do: [app: :fixture, version: \"0.1.0\", deps: [{:plug, \"~> 1.0\"}]]\nend\n");

#[test]
fn constraints_do_not_add_dependencies_or_make_exact_pins_unknown() {
    for name in [
        "constraints.txt",
        "constraints-dev.in",
        "requirements/production/constraints.txt",
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("requirements.txt"),
            format!("-c {name}\nexample==1.2.3\n"),
        )
        .unwrap();
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "Django==2.2\n").unwrap();
        let (exit, result) = scan(root.path(), "PyPI");
        assert_eq!(exit, 0, "{result}");
        assert_eq!(result["status"], "no-known-findings");
        assert_eq!(result["coverage_evidence"]["status"], "complete");
        assert_eq!(result["errors"], json!([]));
        assert_eq!(result["packages"].as_array().unwrap().len(), 1);
        assert_eq!(result["packages"][0]["name"], "example");
    }
}

macro_rules! covered_manifest_case {
    ($test:ident, $manifest:literal, $text:literal, $lock:literal, $locked:literal, $ecosystem:literal, $package:literal) => {
        #[test]
        fn $test() {
            let root = tempfile::tempdir().unwrap();
            let manifest = root.path().join($manifest);
            fs::create_dir_all(manifest.parent().unwrap()).unwrap();
            fs::write(manifest, $text).unwrap();
            fs::write(root.path().join($lock), $locked).unwrap();
            let (exit, result) = scan_named(root.path(), $ecosystem, $package);
            assert_eq!(exit, 0, "{result}");
            assert_eq!(result["status"], "no-known-findings");
            assert_eq!(result["coverage_evidence"]["status"], "complete");
            assert_eq!(result["errors"], json!([]));
        }
    };
}

covered_manifest_case!(
    cargo_lock_keeps_project_covered,
    "Cargo.toml",
    "[package]\nname = 'fixture'\nversion = '0.1.0'\n[dependencies]\nexample = '=1.2.3'\n",
    "Cargo.lock",
    "[[package]]\nname = \"example\"\nversion = \"1.2.3\"\n",
    "crates.io",
    "example"
);
covered_manifest_case!(
    gem_lock_keeps_project_covered,
    "Gemfile",
    "gem 'example', '1.2.3'\n",
    "Gemfile.lock",
    "GEM\n  specs:\n    example (1.2.3)\n",
    "RubyGems",
    "example"
);
covered_manifest_case!(
    composer_lock_keeps_project_covered,
    "composer.json",
    r#"{"require":{"example/package":"1.2.3"}}"#,
    "composer.lock",
    r#"{"packages":[{"name":"example/package","version":"1.2.3"}]}"#,
    "Packagist",
    "example/package"
);

#[test]
fn action_unknown_names_the_scan_error_without_claiming_sarif_coverage() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join(if cfg!(unix) {
        "project\n::error::untrusted"
    } else {
        "project"
    });
    fs::create_dir(&project).unwrap();
    fs::write(project.join("pom.xml"), "<project/>").unwrap();
    let output_file = root.path().join("action-output");
    let sarif = root.path().join("action.sarif");
    let scan = |fail: &str| {
        fs::write(&output_file, "").unwrap();
        Command::new(env!("CARGO_BIN_EXE_vorda"))
            .env("VORDA_ADVISORIES", "online")
            .arg("action-scan")
            .env("VORDA_PATH", format!("'{}'", project.display()))
            .env("VORDA_SARIF", &sarif)
            .env("GITHUB_OUTPUT", &output_file)
            .env("VORDA_FAIL", fail)
            .env("TMPDIR", root.path())
            .output()
            .unwrap()
    };

    // Report-only mode warns and keeps the step green.
    let output = scan("false");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("::warning title=vorda::Scan incomplete"));

    // With the gate on, a scan that could not check everything fails the step.
    let output = scan("true");
    assert_eq!(output.status.code(), Some(2));
    assert!(fs::read_to_string(&output_file)
        .unwrap()
        .contains("status=unknown"));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stdout.contains("::error title=vorda::Scan incomplete, so this is not a pass"),
        "{stdout}"
    );
    assert!(!stdout.contains("SARIF coverage findings"), "{stdout}");
    assert!(
        stderr.contains("pom.xml") && stderr.contains("not supported"),
        "{stderr}"
    );
    assert!(
        !stderr.lines().any(|line| line.starts_with("::error::")),
        "{stderr}"
    );
    let sarif: Value = serde_json::from_slice(&fs::read(sarif).unwrap()).unwrap();
    assert_eq!(sarif["runs"][0]["results"], json!([]));
}

covered_manifest_case!(
    installed_php_manifests_use_ancestor_lock,
    "vendor/example/package/composer.json",
    r#"{"name":"example/package","require":{"php":">=7"}}"#,
    "composer.lock",
    r#"{"packages":[{"name":"example/package","version":"1.2.3"}]}"#,
    "Packagist",
    "example/package"
);
covered_manifest_case!(
    installed_gem_manifests_use_ancestor_lock,
    "vendor/bundle/ruby/3.2.0/gems/example/Gemfile",
    "gemspec\n",
    "Gemfile.lock",
    "GEM\n  specs:\n    example (1.2.3)\n",
    "RubyGems",
    "example"
);
covered_manifest_case!(
    covered_gems_rb_keeps_existing_ruby_lock_coverage,
    "vendor/example/gems.rb",
    "gem 'example'\n",
    "Gemfile.lock",
    "GEM\n  specs:\n    example (1.2.3)\n",
    "RubyGems",
    "example"
);
covered_manifest_case!(
    uv_member_uses_ancestor_python_lock,
    "packages/member/pyproject.toml",
    "[project]\nname = 'member'\ndependencies = ['example==1.2.3']\n",
    "uv.lock",
    "version = 1\n[manifest]\nmembers = [\"member\"]\n[[package]]\nname = \"member\"\nversion = \"0.1.0\"\nsource = { editable = \"packages/member\" }\n[[package]]\nname = \"example\"\nversion = \"1.2.3\"\n",
    "PyPI",
    "example"
);
#[test]
fn nested_go_module_needs_its_own_sum() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("member")).unwrap();
    fs::write(root.path().join("member/go.mod"), "module example\n").unwrap();
    fs::write(root.path().join("go.sum"), "example v1.2.3 h1:example\n").unwrap();
    let (exit, result) = scan_version(root.path(), "Go", "example", "v1.2.3");
    assert_eq!(exit, 2, "{result}");
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["coverage_evidence"]["status"], "partial");
    assert!(result["errors"].to_string().contains("member/go.mod"));
}

#[test]
fn adjacent_go_sum_keeps_its_module_covered() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("go.mod"), "module example\n").unwrap();
    fs::write(root.path().join("go.sum"), "example v1.2.3 h1:example\n").unwrap();
    let (exit, result) = scan_version(root.path(), "Go", "example", "v1.2.3");
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["status"], "no-known-findings");
    assert_eq!(result["coverage_evidence"]["status"], "complete");
    assert_eq!(result["errors"], json!([]));
}
covered_manifest_case!(
    adjacent_pipfile_lock_keeps_its_manifest_covered,
    "Pipfile",
    "[packages]\nexample='==1.2.3'\n",
    "Pipfile.lock",
    r#"{"_meta":{"pipfile-spec":6},"default":{"example":{"version":"==1.2.3"}}}"#,
    "PyPI",
    "example"
);
covered_manifest_case!(nuget_projects_use_ancestor_lock, "src/App/App.csproj", "<Project><ItemGroup><PackageReference Include=\"example\" Version=\"1.2.3\"/></ItemGroup></Project>", "packages.lock.json", r#"{"version":1,"dependencies":{"net8.0":{"app":{"type":"Project"},"example":{"type":"Direct","resolved":"1.2.3"}}}}"#, "NuGet", "example");

#[test]
fn tool_only_pyproject_is_not_an_unread_dependency_manifest() {
    for text in [
        "[tool.ruff]\nline-length=88\n",
        "[project]\nname='docs'\nversion='1.0'\n",
        "[project]\ndependencies=[]\n",
        "[project.optional-dependencies]\ntest=[]\n",
        "[project]\nname='docs'\nversion='1.0'\n[project.urls]\ndependencies='https://example.invalid/dependencies'\n",
        "[tool.poetry.plugins.dependencies]\nexample='example:run'\n",
        "[tool.pdm.scripts]\ndependencies='python tools/dependencies.py'\n",
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        fs::create_dir(root.path().join("docs")).unwrap();
        fs::write(root.path().join("docs/pyproject.toml"), text).unwrap();
        let (exit, result) = scan(root.path(), "PyPI");
        assert_eq!(exit, 0, "{result}");
        assert_eq!(result["errors"], json!([]));
        assert_eq!(result["coverage_evidence"]["status"], "complete");
    }
}

#[test]
fn python_dependency_declarations_without_a_lock_are_still_unknown() {
    for text in [
        "[project]\ndependencies=['Django==2.2']\n",
        "[project.optional-dependencies]\ntest=['Django==2.2']\n",
        "[tool.poetry.dependencies]\nDjango='2.2'\n",
        "[tool.poetry.group.test.dependencies]\nDjango='2.2'\n",
        "[tool.pdm.dev-dependencies]\ntest=['Django==2.2']\n",
        "[dependency-groups]\ntest=['Django==2.2']\n",
        "[project]\ndynamic=['dependencies']\n",
        "project=[{dependencies=['Django==2.2']}]\n",
        "[invalid toml",
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        fs::create_dir(root.path().join("app")).unwrap();
        fs::write(root.path().join("app/pyproject.toml"), text).unwrap();
        unknown(root.path(), &["pyproject.toml"]);
    }
}

#[test]
fn pip_tools_inputs_are_covered_only_by_a_supported_compiled_same_stem() {
    for name in [
        "requirements",
        "requirements-dev",
        "requirements/requirements-prod",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path.with_extension("in"), "example\n").unwrap();
        fs::write(path.with_extension("txt"), "example==1.2.3\n").unwrap();
        let (exit, result) = scan(root.path(), "PyPI");
        assert_eq!(exit, 0, "{result}");
        assert_eq!(result["errors"], json!([]));
        assert_eq!(result["coverage_evidence"]["status"], "complete");
    }
}

#[test]
fn an_uncompiled_input_is_read_and_its_unpinned_lines_stay_unknown() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    fs::write(root.path().join("requirements-dev.in"), "Django\n").unwrap();
    unknown(root.path(), &["requirements-dev.in", "Django==VERSION"]);
}

mixed_unread_case!(csharp_project_without_lock_is_unknown, "src/App/App.csproj", "<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.1\"/></ItemGroup></Project>");
mixed_unread_case!(fsharp_project_without_lock_is_unknown, "App.fsproj", "<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.1\"/></ItemGroup></Project>");
mixed_unread_case!(visual_basic_project_without_lock_is_unknown, "App.vbproj", "<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.1\"/></ItemGroup></Project>");
mixed_unread_case!(
    packages_config_without_lock_is_unknown,
    "packages.config",
    "<packages><package id=\"Newtonsoft.Json\" version=\"12.0.1\"/></packages>"
);
mixed_unread_case!(central_packages_without_lock_is_unknown, "Directory.Packages.props", "<Project><ItemGroup><PackageVersion Include=\"Newtonsoft.Json\" Version=\"12.0.1\"/></ItemGroup></Project>");

#[test]
fn prose_in_requirements_folders_is_not_dependency_input() {
    for (name, text) in [
        (
            "docs/requirements/user-stories.txt",
            "As a user I want to log in.\n",
        ),
        ("requirements/README.txt", "Pinned files live here.\n"),
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        let (exit, result) = scan(root.path(), "PyPI");
        assert_eq!(exit, 0, "{result}");
        assert_eq!(result["errors"], json!([]));
    }
}

#[test]
fn requirement_direct_references_are_not_mistaken_for_prose() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    fs::create_dir_all(root.path().join("requirements/production")).unwrap();
    fs::write(
        root.path().join("requirements/production/urls.txt"),
        "https://example.invalid/example.whl\n",
    )
    .unwrap();
    unknown(root.path(), &["urls.txt"]);
}

mixed_unread_case!(
    swift_lock_is_recognised_unsupported,
    "Package.resolved",
    "{\"pins\":[],\"version\":2}"
);
mixed_unread_case!(
    pod_lock_is_recognised_unsupported,
    "Podfile.lock",
    "PODS:\n  - example (1.2.3)\n"
);
mixed_unread_case!(
    renv_lock_is_recognised_unsupported,
    "renv.lock",
    "{\"Packages\":{}}"
);
mixed_unread_case!(
    conda_environment_is_recognised_unsupported,
    "environment.yml",
    "dependencies:\n  - pip:\n    - Django==2.2\n"
);
mixed_unread_case!(
    conan_input_is_recognised_unsupported,
    "conanfile.txt",
    "[requires]\nexample/1.2.3\n"
);
mixed_unread_case!(
    sbt_input_is_recognised_unsupported,
    "build.sbt",
    "libraryDependencies += \"example\" % \"example\" % \"1.2.3\"\n"
);
mixed_unread_case!(
    gems_rb_without_lock_is_unknown,
    "gems.rb",
    "gem 'example', '1.2.3'\n"
);
mixed_unread_case!(
    rye_lock_is_recognised_unsupported,
    "requirements-dev.lock",
    "example==1.2.3\n"
);
mixed_unread_case!(
    pixi_lock_is_recognised_unsupported,
    "pixi.lock",
    "version: 6\n"
);
mixed_unread_case!(
    requirements_pip_is_recognised_unsupported,
    "requirements.pip",
    "Django==2.2\n"
);
mixed_unread_case!(
    capital_requirements_is_recognised_unsupported,
    "sub/Requirements.txt",
    "Django==2.2\n"
);
mixed_unread_case!(
    capital_pom_is_recognised_unsupported,
    "POM.xml",
    "<project/>\n"
);
mixed_unread_case!(
    gradle_settings_is_recognised_unsupported,
    "settings.gradle",
    "rootProject.name = 'example'\n"
);
mixed_unread_case!(
    gradle_versions_is_recognised_unsupported,
    "gradle/libs.versions.toml",
    "[libraries]\nexample = 'example:example:1.2.3'\n"
);

#[cfg(unix)]
#[test]
fn nonignored_symlink_directory_is_unknown_but_ignored_directory_is_not() {
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("package-lock.json"), LOCK).unwrap();
    for (name, expected) in [("web", 2), ("node_modules", 0)] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join(name)).unwrap();
        let (exit, result) = scan(root.path(), "PyPI");
        assert_eq!(exit, expected, "{result}");
        assert_eq!(result["packages"].as_array().unwrap().len(), 1);
        if expected == 2 {
            assert_eq!(result["status"], "unknown");
            assert!(result["errors"].to_string().contains("symlink directory"));
        } else {
            assert_eq!(result["errors"], json!([]));
        }
    }
}

#[test]
fn missing_lock_diagnostics_name_the_remedy_and_unsupported_formats_do_not() {
    for (name, text, command) in [
        ("package.json", "{}", "npm install --package-lock-only"),
        (
            "Cargo.toml",
            "[package]\nname='example'\n",
            "cargo generate-lockfile",
        ),
        ("Gemfile", "gem 'example'", "bundle lock"),
        ("composer.json", "{}", "composer update --no-install"),
        ("Pipfile", "[packages]\nexample='*'\n", "pipenv lock"),
        (
            "app/pyproject.toml",
            "[project]\ndependencies=['Django==2.2']\n",
            "uv lock",
        ),
        ("App.csproj", "<Project/>", "dotnet restore --use-lock-file"),
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        let result = unknown(root.path(), &[name]);
        let errors = result["errors"].to_string();
        assert!(errors.contains("No supported lockfile"), "{result}");
        assert!(
            errors.contains(command) && errors.contains("scan where"),
            "{result}"
        );
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pom.xml");
    fs::write(&path, "<project/>").unwrap();
    let result = unknown(&path, &["pom.xml"]);
    let errors = result["errors"][0]["error"].as_str().unwrap();
    assert!(errors.contains("Vorda does not read"), "{result}");
    assert_eq!(
        errors.matches(path.to_str().unwrap()).count(),
        1,
        "{result}"
    );
}
