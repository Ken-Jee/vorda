use serde_json::Value;
use std::process::Command;

#[test]
fn usage_errors_are_distinct_from_scan_unknown() {
    let state = tempfile::tempdir().unwrap();
    for args in [
        vec!["scan", "--typo"],
        vec!["scan", "--root"],
        vec!["scan", "--root", "--json"],
        vec!["scan", "--root", "-h"],
        vec!["verify-self", "--file", "--sig", "--pubkey", "some-key"],
        vec!["--state", "--help"],
        vec!["db", "update", "--from", "--json"],
        vec!["agentbom", "--root", "--offline"],
        vec!["inventory", "folder"],
        vec!["inventory", "--format", "invalid"],
        vec!["mail", "list", "--reader", "test", "--limit", "bad"],
        vec!["not-a-command"],
        vec!["db", "update", "--ecosystem", "bogus"],
        vec!["render-manifests", "--typo"],
        vec!["link", "--typo"],
        vec!["capture"],
        vec!["snapshot-read"],
        vec!["hub-mcp", "--hub", "invalid", "--reader-env", "EXAMPLE"],
        vec!["connect", "invalid"],
        vec!["scan", "--offline-db", "--online"],
        vec!["dashboard", "--port", "bad"],
        vec!["db", "typo"],
        vec!["verify-self", "--typo"],
        vec!["mode", "frob"],
        vec!["can", "agent", "frob"],
        vec!["watch", "status", "--backend", "frob"],
        vec!["dashboard", "--bind", "frob"],
        vec!["scan", "--root", ".", "--webhook", "notaurl"],
        vec!["scan", "--root", ".", "--ntfy", "ftp://example.invalid/x"],
        vec!["mail", "frob", "--reader", "test"],
        vec!["mail", "snooze", "--reader", "test", "--seconds", "x"],
        vec!["action-scan", "extra"],
        vec!["update", "--typo"],
        vec!["update", "--version"],
        vec!["update", "--version", "../x"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(state.path())
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(64), "{args:?}: {output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["status"], "usage_error");
    }
}

#[test]
fn a_dashboard_token_is_never_invented_where_output_is_not_a_terminal() {
    // Piped stdout stands for a log such as the systemd journal: a random token printed there
    // would let a log reader log in, so --token needs VORDA_DASHBOARD_TOKEN instead.
    let state = tempfile::tempdir().unwrap();
    for flag in ["--token", "--allow-writes"] {
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(state.path())
            .args(["dashboard", "--port", "0", flag])
            .env_remove("VORDA_DASHBOARD_TOKEN")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(64), "{flag}: {output:?}");
        assert!(output.stdout.is_empty(), "{flag}: {output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error.to_string().contains("VORDA_DASHBOARD_TOKEN"),
            "{error}"
        );
    }
}

#[test]
fn action_usage_errors_fail_even_without_fail_on_findings() {
    let temp = tempfile::tempdir().unwrap();
    let output_file = temp.path().join("output");
    std::fs::write(&output_file, "").unwrap();
    for (sarif, advisories) in [(None, ""), (Some(temp.path().join("s.sarif")), "bogus")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
        command
            .arg("action-scan")
            .env_remove("VORDA_SARIF")
            .env("GITHUB_OUTPUT", &output_file)
            .env("VORDA_ADVISORY_INPUT", advisories)
            .env("VORDA_FAIL", "false");
        if let Some(path) = sarif {
            command.env("VORDA_SARIF", path);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(64), "{advisories}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("::error"));
    }
}

#[test]
fn usage_errors_name_the_mistake() {
    let state = tempfile::tempdir().unwrap();
    for (args, names) in [
        // `link` prints only an error class for operational errors, but a usage error's text.
        (vec!["link", "frob"], "frob"),
        (vec!["mail", "frob", "--reader", "test"], "frob"),
        (
            vec!["mail", "read", "--reader", "test", "--id", "x"],
            "--id",
        ),
        (vec!["dashboard", "--bind", "frob"], "IP address"),
        (
            vec!["scan", "--oci", "/vorda-no-such.tar"],
            "no such OCI archive",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(state.path())
            .args(&args)
            .output()
            .unwrap();
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["error"].as_str().unwrap().contains(names),
            "{args:?}: {error}"
        );
    }
}

#[test]
fn help_and_harmless_flags_exit_zero() {
    let state = tempfile::tempdir().unwrap();
    for args in [
        vec!["capture", "--help"],
        vec!["help", "capture"],
        vec!["action-scan", "--help"],
        vec!["dashboard", "--help"],
        vec!["mail", "list", "--reader", "test", "--json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(state.path())
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
    }
}

#[test]
fn operational_errors_remain_unknown() {
    let state = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(state.path().join("missing"))
        .args(["scan", "--root", "/vorda-no-such-folder", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["status"], "unknown");
}
