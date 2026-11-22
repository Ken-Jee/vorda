// What the project walker reads, skips and caps: nothing it leaves unread may come back
// complete, and no lockfile, readable or not, may cost more than the per-input cap.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn write(root: &Path, name: &str, text: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn npm_lock(name: &str, version: &str) -> String {
    json!({"lockfileVersion":3,"packages":{"":{},(format!("node_modules/{name}")):{"version":version}}})
        .to_string()
}

/// `vorda inventory --root ROOT` as JSON, asking for JSON when the command offers a choice.
fn inventory(root: &Path) -> (i32, Value, usize) {
    let bin = env!("CARGO_BIN_EXE_vorda");
    let help = Command::new(bin)
        .args(["inventory", "--help"])
        .output()
        .unwrap();
    let state = tempfile::tempdir().unwrap();
    let mut command = Command::new(bin);
    command.arg("--state").arg(state.path()).arg("inventory");
    if String::from_utf8_lossy(&help.stdout).contains("--json") {
        command.arg("--json");
    }
    let output = command.arg("--root").arg(root).output().unwrap();
    let result = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), result, output.stdout.len())
}

fn names(result: &Value) -> Vec<String> {
    let mut names: Vec<String> = result["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

fn errors(result: &Value) -> Vec<String> {
    serde_json::from_value(result["errors"].clone()).unwrap()
}

fn assert_complete(exit: i32, result: &Value) {
    assert_eq!(exit, 0, "{result}");
    assert_eq!(result["status"], "complete", "{result}");
    assert_eq!(result["errors"], json!([]), "{result}");
}

fn assert_unknown(exit: i32, result: &Value, names: &[&str]) {
    assert_eq!(exit, 2, "{result}");
    assert_eq!(result["status"], "unknown", "{result}");
    assert_ne!(result["input_evidence"]["status"], "complete", "{result}");
    let errors = result["errors"].to_string();
    for name in names {
        assert!(errors.contains(name), "missing {name}: {result}");
    }
}

#[test]
fn lockfiles_in_dot_folders_and_ordinary_skip_names_are_read() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(root, "package-lock.json", &npm_lock("root-dep", "1.0.0"));
    write(
        root,
        ".github/actions/build/package-lock.json",
        &npm_lock("lodash", "4.17.20"),
    );
    write(root, ".devcontainer/requirements.txt", "django==2.2.0\n");
    write(
        root,
        "target/package-lock.json",
        &npm_lock("left-pad", "1.0.0"),
    );
    write(root, "venv/requirements.txt", "flask==1.0\n");
    write(root, ".cache/tools/requirements.txt", "jinja2==2.10\n");
    let (exit, result, _) = inventory(root);
    assert_complete(exit, &result);
    assert_eq!(
        names(&result),
        ["django", "flask", "jinja2", "left-pad", "lodash", "root-dep"]
    );
}

#[test]
fn generated_folders_holding_a_lockfile_are_unknown() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(root, "requirements.txt", "requests==2.0.0\n");
    write(root, "env/pyvenv.cfg", "home = /usr/bin\n");
    write(root, "env/lib/site/requirements.txt", "django==2.2.0\n");
    write(
        root,
        "build/CACHEDIR.TAG",
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    write(root, "build/package/crate/Cargo.lock", "version = 3\n");
    let (exit, result, _) = inventory(root);
    assert_unknown(
        exit,
        &result,
        &["Python virtual environment", "CACHEDIR.TAG", "env", "build"],
    );
    assert_eq!(errors(&result).len(), 2, "{result}");
    assert_eq!(names(&result), ["requests"]);
}

#[test]
fn generated_folders_without_a_lockfile_are_skipped_and_named() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(root, "requirements.txt", "requests==2.0.0\n");
    write(root, ".venv/pyvenv.cfg", "home = /usr/bin\n");
    write(root, ".venv/lib/site/pkg/package.json", "{}");
    write(
        root,
        "target/CACHEDIR.TAG",
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    write(root, "target/debug/out/pom.xml", "<project/>");
    let (exit, result, _) = inventory(root);
    assert_complete(exit, &result);
    let skipped: Vec<_> = result["input_evidence"]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["kind"] == "skipped-folder")
        .map(|o| o["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(skipped.len(), 2, "{result}");
    assert!(skipped.iter().any(|p| p.ends_with(".venv")), "{skipped:?}");
    assert!(skipped.iter().any(|p| p.ends_with("target")), "{skipped:?}");
}

const CAP: usize = 20_000;

fn unreadable_lockfiles(over: usize) -> Vec<(&'static str, String)> {
    let lines = |line: &str| line.repeat(over);
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({}));
    for i in 0..over {
        packages.insert(format!("node_modules/Bad Name {i}"), json!({"version":"1"}));
    }
    vec![
        ("go.sum", lines("example.com/m v1\n")),
        // No `go` directive: the pre-1.17 note is the last entry.
        ("go.mod", "x\n".repeat(over - 1)),
        ("requirements.txt", lines("example>=1\n")),
        (
            "package-lock.json",
            json!({"lockfileVersion":3,"packages":packages}).to_string(),
        ),
    ]
}

#[test]
fn unreadable_entries_count_toward_the_per_input_cap() {
    for (name, text) in unreadable_lockfiles(CAP + 1) {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), &format!("big/{name}"), &text);
        write(root.path(), "small/requirements.txt", "requests==2.0.0\n");
        let (exit, result, _) = inventory(root.path());
        assert_unknown(exit, &result, &[name, "over the per-input cap of 20000"]);
        assert_eq!(errors(&result).len(), 1, "{name}: {}", result["errors"]);
        assert_eq!(names(&result), ["requests"], "{name}");
    }
    for (name, text) in unreadable_lockfiles(CAP) {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), name, &text);
        let (exit, result, _) = inventory(root.path());
        assert_eq!(exit, 2, "{name}");
        assert_eq!(errors(&result).len(), CAP, "{name}");
    }
}

#[test]
fn readable_and_unreadable_entries_share_the_per_input_cap() {
    let root = tempfile::tempdir().unwrap();
    let mut text = String::new();
    for i in 0..CAP / 2 {
        text.push_str(&format!("example.com/m{i} v1.0.0 h1:x=\n"));
    }
    text.push_str(&"example.com/m v1\n".repeat(CAP / 2 + 1));
    write(root.path(), "go.sum", &text);
    let (exit, result, _) = inventory(root.path());
    assert_unknown(exit, &result, &["over the per-input cap of 20000"]);
    assert_eq!(errors(&result).len(), 1, "{}", result["errors"]);
    assert_eq!(result["packages"], json!([]));
}

#[test]
fn a_lockfile_of_many_unreadable_lines_is_one_short_unknown() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "go.sum", &"example.com/m v1\n".repeat(400_000));
    let (exit, result, size) = inventory(root.path());
    assert_unknown(exit, &result, &["over the per-input cap of 20000"]);
    assert_eq!(errors(&result).len(), 1, "{}", result["errors"]);
    assert!(size < 64 * 1024, "{size} bytes of output");
}

#[test]
fn many_lockfiles_of_unreadable_entries_stop_at_the_per_scan_cap() {
    let root = tempfile::tempdir().unwrap();
    for dir in ["a", "b", "c"] {
        write(
            root.path(),
            &format!("{dir}/go.sum"),
            &"example.com/m v1\n".repeat(CAP),
        );
    }
    let (exit, result, _) = inventory(root.path());
    assert_unknown(exit, &result, &["over the per-scan cap of 50000"]);
    assert_eq!(errors(&result).len(), 2 * CAP + 1);
}

#[test]
fn a_nested_manifest_an_ancestor_lock_does_not_list_is_unknown() {
    for (lock, lock_text, manifest, manifest_text) in [
        (
            "package-lock.json",
            npm_lock("root-dep", "1.0.0"),
            "services/api/package.json",
            r#"{"dependencies":{"lodash":"4.17.20"}}"#,
        ),
        (
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n".into(),
            "tools/other/Cargo.toml",
            "[package]\nname = \"other\"\nversion = \"0.1.0\"\n[dependencies]\nsmallvec = \"=0.6.9\"\n",
        ),
        (
            "uv.lock",
            "version = 1\n\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n".into(),
            "services/py/pyproject.toml",
            "[project]\nname = \"py\"\nversion = \"0.1.0\"\ndependencies = [\"django==2.2.0\"]\n",
        ),
        (
            "packages.lock.json",
            r#"{"version":1,"dependencies":{"net8.0":{"example":{"type":"Direct","resolved":"1.2.3"}}}}"#.into(),
            "src/App/App.csproj",
            "<Project/>",
        ),
        (
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"a\"\nversion = \"0.1.0\"\n".into(),
            "old/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.0.1\"\n[dependencies]\nsmallvec = \"=0.6.9\"\n",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), lock, &lock_text);
        write(root.path(), manifest, manifest_text);
        let (exit, result, _) = inventory(root.path());
        assert_unknown(
            exit,
            &result,
            &[manifest, &format!("{lock} does not list this folder")],
        );
    }
}

#[test]
fn nested_members_an_ancestor_lock_lists_stay_complete() {
    for (lock, lock_text, manifest, manifest_text) in [
        (
            "package-lock.json",
            json!({"lockfileVersion":3,"packages":{"":{"workspaces":["services/*"]},"services/api":{"name":"api"},"node_modules/api":{"resolved":"services/api","link":true},"node_modules/lodash":{"version":"4.17.21"}}}).to_string(),
            "services/api/package.json",
            r#"{"name":"api"}"#,
        ),
        (
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"member\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n".into(),
            "crates/member/Cargo.toml",
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
        ),
        (
            "uv.lock",
            "version = 1\n\n[[package]]\nname = \"py\"\nversion = \"0.1.0\"\nsource = { editable = \"services/py\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n".into(),
            "services/py/pyproject.toml",
            "[project]\nname = \"py\"\nversion = \"0.1.0\"\ndependencies = [\"requests\"]\n",
        ),
        (
            "poetry.lock",
            "[[package]]\nname = \"member\"\nversion = \"0.1.0\"\n\n[package.source]\ntype = \"directory\"\nurl = \"packages/member\"\n\n[[package]]\nname = \"example\"\nversion = \"1.2.3\"\n\n[metadata]\nlock-version = \"2.1\"\n".into(),
            "packages/member/setup.cfg",
            "[options]\ninstall_requires = example==1.2.3\n",
        ),
        (
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"member\"\nversion = \"0.2.0\"\ndependencies = [\n \"itoa\",\n]\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n".into(),
            "crates/member/Cargo.toml",
            "[package]\nname = \"member\"\nversion = \"0.2.0\"\n[dependencies]\nitoa = \"1\"\n",
        ),
        (
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"member\"\nversion = \"0.1.0\"".into(),
            "crates/member/Cargo.toml",
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
        ),
        (
            "uv.lock",
            "version = 1\n\n[[package]]\nname = \"x\"\nversion = \"0.1.0\"\nsource = { directory = \"libs/x\" }\n".into(),
            "libs/x/pyproject.toml",
            "[project]\nname = \"x\"\nversion = \"0.1.0\"\ndependencies = [\"requests\"]\n",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), lock, &lock_text);
        write(root.path(), manifest, manifest_text);
        let (exit, result, _) = inventory(root.path());
        assert_complete(exit, &result);
    }
}

#[test]
fn a_nested_package_json_without_dependencies_needs_no_lock() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(root, "package-lock.json", &npm_lock("root-dep", "1.0.0"));
    write(root, ".next/package.json", r#"{"type":"commonjs"}"#);
    write(root, "dist/esm/package.json", r#"{"type":"module"}"#);
    write(
        root,
        ".yarn/sdks/typescript/package.json",
        r#"{"name":"typescript","version":"5.0.0","main":"./lib/typescript.js"}"#,
    );
    let (exit, result, _) = inventory(root);
    assert_complete(exit, &result);
}

#[test]
fn yarn_classic_members_are_covered_by_the_root_workspaces() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(
        root,
        "package.json",
        r#"{"private":true,"workspaces":["packages/*"]}"#,
    );
    write(
        root,
        "yarn.lock",
        "# yarn lockfile v1\n\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n",
    );
    let deps = r#"{"name":"a","dependencies":{"lodash":"^4.17.21"}}"#;
    write(root, "packages/a/package.json", deps);
    write(root, "tools/x/package.json", deps);
    let (exit, result, _) = inventory(root);
    assert_unknown(exit, &result, &["tools/x/package.json"]);
    assert_eq!(errors(&result).len(), 1, "{result}");
}

/// npm, pnpm, bun and yarn Berry write every member into the lock, so the root `workspaces`
/// globs prove nothing there: a folder the globs name but the lock does not list is unknown.
#[test]
fn workspaces_globs_do_not_cover_a_member_other_locks_leave_out() {
    let mut wrong = Vec::new();
    for (lock, lock_text) in [
        (
            "package-lock.json",
            json!({"lockfileVersion":3,"packages":{"":{"workspaces":["packages/*"]},"packages/a":{"name":"a"},"node_modules/a":{"resolved":"packages/a","link":true}}}).to_string(),
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/a:\n    dependencies:\n      lodash:\n        specifier: 4.17.20\n        version: 4.17.20\n".into(),
        ),
        (
            "bun.lock",
            r#"{"lockfileVersion": 1, "workspaces": {"": {"name": "root"}, "packages/a": {"name": "a"}}, "packages": {}}"#.into(),
        ),
        (
            "yarn.lock",
            "__metadata:\n  version: 8\n\n\"a@workspace:packages/a\":\n  version: 0.0.0-use.local\n  resolution: \"a@workspace:packages/a\"\n  languageName: unknown\n  linkType: soft\n".into(),
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        write(root, "package.json", r#"{"private":true,"workspaces":["packages/*"]}"#);
        write(root, lock, &lock_text);
        let deps = r#"{"dependencies":{"lodash":"4.17.20"}}"#;
        write(root, "packages/a/package.json", deps);
        write(root, "packages/b/package.json", deps);
        let (exit, result, _) = inventory(root);
        let errors = result["errors"].to_string();
        if exit != 2 || !errors.contains("packages/b/package.json") || errors.contains("packages/a/") {
            wrong.push(format!("{lock}: {result}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[cfg(unix)]
#[test]
fn a_linked_folder_with_a_generated_marker_stays_unknown() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("project");
    write(&root, "package-lock.json", &npm_lock("root-dep", "1.0.0"));
    write(
        outer.path(),
        "elsewhere/CACHEDIR.TAG",
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    );
    write(
        outer.path(),
        "elsewhere/package-lock.json",
        &npm_lock("lodash", "4.17.20"),
    );
    std::os::unix::fs::symlink(outer.path().join("elsewhere"), root.join("linked")).unwrap();
    let (exit, result, _) = inventory(&root);
    assert_unknown(exit, &result, &["linked", "skipped symlink directory"]);
}

#[test]
fn folders_with_a_marker_no_tool_wrote_are_walked() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(root, "requirements.txt", "requests==2.0.0\n");
    write(root, "out/CACHEDIR.TAG", "not a cache tag\n");
    write(
        root,
        "out/app/package.json",
        r#"{"dependencies":{"lodash":"4.17.20"}}"#,
    );
    write(root, "env/pyvenv.cfg", "made = by hand\n");
    write(root, "env/requirements.txt", "django==2.2.0\n");
    let (exit, result, _) = inventory(root);
    assert_unknown(exit, &result, &["out/app/package.json"]);
    assert_eq!(names(&result), ["django", "requests"]);
}

#[test]
fn vscode_test_and_next_build_folders_are_generated() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(root, "package-lock.json", &npm_lock("lodash", "4.17.21"));
    let deps = r#"{"name":"x","dependencies":{"lodash":"^4.17.21"}}"#;
    write(
        root,
        ".vscode-test/vscode-linux/resources/app/package.json",
        deps,
    );
    write(root, ".next/standalone/package.json", deps);
    let (exit, result, _) = inventory(root);
    assert_complete(exit, &result);
    write(root, ".output/server/package.json", deps);
    let (exit, result, _) = inventory(root);
    assert_unknown(exit, &result, &[".output/server/package.json"]);
}

#[test]
fn yarn_classic_reads_workspaces_only_from_a_private_root_and_named_members() {
    let lock = "# yarn lockfile v1\n\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n";
    for (root_json, member, unknown) in [
        (
            r#"{"private":true,"workspaces":["packages/*"]}"#,
            r#"{"name":"b","dependencies":{"lodash":"^4.17.21"}}"#,
            false,
        ),
        (
            r#"{"workspaces":["packages/*"]}"#,
            r#"{"name":"b","dependencies":{"lodash":"^4.17.21"}}"#,
            true,
        ),
        (
            r#"{"private":true,"workspaces":["packages/*"]}"#,
            r#"{"dependencies":{"lodash":"^4.17.21"}}"#,
            true,
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        write(root, "package.json", root_json);
        write(root, "yarn.lock", lock);
        write(root, "packages/b/package.json", member);
        let (exit, result, _) = inventory(root);
        if unknown {
            assert_unknown(exit, &result, &["packages/b/package.json"]);
        } else {
            assert_complete(exit, &result);
        }
    }
}

#[test]
fn a_pnpm_importer_that_records_nothing_still_lists_its_folder() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    write(
        root,
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: 4.17.21\n        version: 4.17.21\n\n  packages/cfg: {}\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n",
    );
    write(
        root,
        "package.json",
        r#"{"dependencies":{"lodash":"4.17.21"}}"#,
    );
    write(
        root,
        "packages/cfg/package.json",
        r#"{"name":"cfg","peerDependencies":{"eslint":"^9"}}"#,
    );
    let (exit, result, _) = inventory(root);
    assert_complete(exit, &result);
}
