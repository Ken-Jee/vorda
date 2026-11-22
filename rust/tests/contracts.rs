use serde_json::{json, Value};
use vorda::domain::{Package, Record};

#[test]
fn package_round_trip_retains_imported_metadata_and_large_integers() {
    let raw = r#"{"name":"example","version":"1","ecosystem":"npm","path":"/selected/package-lock.json","scope":"reachable-unknown","origin":"project","dependency":false,"counter":184467440737095516160000,"confidence":null}"#;
    let expected: Value = serde_json::from_str(raw).unwrap();
    let package: Package = serde_json::from_str(raw).unwrap();
    assert_eq!(serde_json::to_value(package).unwrap(), expected);
}

#[test]
fn health_records_do_not_acquire_package_fields() {
    let health = json!({"key":"health:lock", "asset":"health:lock", "kind":"health", "title":"Scanner lock timed out"});
    let record: Record = serde_json::from_value(health.clone()).unwrap();
    assert_eq!(serde_json::to_value(record).unwrap(), health);
}

#[test]
fn integer_options_preserve_sign_and_unbounded_magnitude() {
    assert_eq!(
        vorda::domain::integer(" +001_024 ").unwrap().to_string(),
        "1024"
    );
    assert_eq!(vorda::domain::integer("-00").unwrap().to_string(), "0");
    assert_eq!(
        vorda::domain::integer("184467440737095516160000")
            .unwrap()
            .to_string(),
        "184467440737095516160000"
    );
    for invalid in ["true", "1.0", "1e3", "1__0", "_1", "1_", ""] {
        assert!(vorda::domain::integer(invalid).is_err());
    }
}

#[test]
fn unknown_command_fails_without_creating_state() {
    let state = std::env::temp_dir().join(format!("vorda-foundation-{}", std::process::id()));
    assert!(!state.exists());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&state)
        .arg("not-a-command")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["status"], "usage_error");
    assert!(!state.exists());
}

#[test]
fn mail_help_needs_no_action_and_creates_no_state() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("not-created");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&state)
        .args(["mail", "--help"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(!state.exists());
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("--reader"));
}

#[test]
#[cfg(unix)]
fn explicitly_selected_state_follows_symlinked_parent_directories() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let linked = root.path().join("linked");
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    let state = linked.join("new-state");
    assert_eq!(
        vorda::cli::state_path(&linked.join("missing/../new-state")).unwrap(),
        real.join("new-state")
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&state)
        .args(["mail", "list", "--reader", "test"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );
    assert!(real.join("new-state/mail.db").is_file());
}
