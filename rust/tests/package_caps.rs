use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

/// An npm lockfile of `count` packages named `prefix-N`.
fn lock(dir: &Path, prefix: &str, count: usize) {
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({"name": prefix}));
    for i in 0..count {
        packages.insert(
            format!("node_modules/{prefix}-{i}"),
            json!({"version": "1.0.0"}),
        );
    }
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("package-lock.json"),
        json!({"name": prefix, "lockfileVersion": 3, "requires": true, "packages": packages})
            .to_string(),
    )
    .unwrap();
}

fn inventory(root: &Path) -> (i32, Value) {
    let state = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(state.path())
        .args(["inventory", "--root"])
        .arg(root)
        .output()
        .unwrap();
    let result = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), result)
}

fn errors(result: &Value) -> Vec<String> {
    result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect()
}

fn names_with(result: &Value, prefix: &str) -> usize {
    result["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["name"].as_str().unwrap().starts_with(prefix))
        .count()
}

#[test]
fn a_lockfile_at_the_per_input_cap_is_read_whole() {
    let root = tempfile::tempdir().unwrap();
    lock(root.path(), "atcap", 20_000);
    let (exit, result) = inventory(root.path());
    assert_eq!(errors(&result), Vec::<String>::new());
    assert_eq!(exit, 0);
    assert_eq!(names_with(&result, "atcap-"), 20_000);
}

#[test]
fn a_lockfile_over_the_per_input_cap_is_unknown_and_not_truncated() {
    let root = tempfile::tempdir().unwrap();
    lock(&root.path().join("big"), "overcap", 20_001);
    lock(&root.path().join("small"), "small", 3);
    let (exit, result) = inventory(root.path());
    assert_eq!(exit, 2);
    assert_eq!(result["status"], "unknown");
    let errors = errors(&result);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("big"), "{errors:?}");
    assert!(
        errors[0].contains("over the per-input cap of 20000"),
        "{errors:?}"
    );
    assert_eq!(names_with(&result, "overcap-"), 0);
    assert_eq!(names_with(&result, "small-"), 3);
}

#[test]
fn inputs_past_the_per_scan_cap_are_unknown_and_not_read() {
    let root = tempfile::tempdir().unwrap();
    lock(&root.path().join("a"), "first", 20_000);
    lock(&root.path().join("b"), "second", 20_000);
    lock(&root.path().join("c"), "third", 10_001);
    lock(&root.path().join("d"), "fourth", 2);
    let (exit, result) = inventory(root.path());
    assert_eq!(exit, 2);
    assert_eq!(result["status"], "unknown");
    let errors = errors(&result);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("package-lock.json"), "{errors:?}");
    assert!(
        errors[0].contains("/c/") || errors[0].contains("\\c\\"),
        "{errors:?}"
    );
    assert!(
        errors[0].contains("over the per-scan cap of 50000 packages"),
        "{errors:?}"
    );
    assert_eq!(names_with(&result, "first-"), 20_000);
    assert_eq!(names_with(&result, "second-"), 20_000);
    assert_eq!(names_with(&result, "third-"), 0);
    assert_eq!(names_with(&result, "fourth-"), 2);
}
