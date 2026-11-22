use serde_json::{json, Value};
use std::fs;
use vorda::{store::identity, surfaces::mcp};

#[test]
fn host_inventory_requires_valid_local_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&state).unwrap();
    let call = |args: Value| {
        mcp::call(
            &state,
            &json!({"method":"tools/call","params":{"name":"inventory","arguments":args}}),
            None,
            None,
        )
    };
    for flag in ["os_packages", "tools", "browsers", "installed_apps"] {
        fs::write(
            state.join("config.json"),
            json!({"roots":[root],flag:"true"}).to_string(),
        )
        .unwrap();
        assert!(call(json!({})).is_err());
        fs::write(
            state.join("config.json"),
            json!({"roots":[root],flag:false}).to_string(),
        )
        .unwrap();
        assert!(call(json!({flag:true})).is_err());
    }
    let response = call(json!({})).unwrap();
    let result: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(result["packages"].as_array().unwrap().is_empty());
    assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
}

#[test]
fn malformed_mailbox_calls_fail_before_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    for (name, args) in [
        ("ack", json!({"reader":"agent"})),
        ("read", json!({"reader":"agent","unexpected":true})),
        ("list", json!({})),
    ] {
        let request = json!({"method":"tools/call","params":{"name":name,"arguments":args}});
        assert!(mcp::call(&state, &request, None, None).is_err());
        assert!(!state.exists());
    }
}

#[test]
fn scoped_agent_discovery_bounds_local_manifest_search() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("server.js"), "").unwrap();
    fs::write(
        temp.path().join("package.json"),
        json!({"name":"outside","version":"1.2.3"}).to_string(),
    )
    .unwrap();
    let config = root.join(".mcp.json");
    fs::write(
        &config,
        json!({"mcpServers":{"local":{"command":"node","args":["./server.js"]}}}).to_string(),
    )
    .unwrap();
    let scan = || {
        vorda::scanner::agentbom::collect_scoped(
            temp.path(),
            std::slice::from_ref(&root),
            "fixture",
        )
        .unwrap()
    };
    assert!(scan().packages.is_empty());
    fs::write(
        root.join("package.json"),
        json!({"name":"inside","version":"1.2.3"}).to_string(),
    )
    .unwrap();
    let bom = scan();
    assert!(bom.packages.iter().any(|p| p.name == "inside"));
    assert!(!bom.packages.iter().any(|p| p.name == "outside"));
    fs::write(temp.path().join("outside.js"), "").unwrap();
    fs::write(
        &config,
        json!({"mcpServers":{"external":{"command":"node","args":["../outside.js"]}}}).to_string(),
    )
    .unwrap();
    let bom = scan();
    assert!(bom.packages.is_empty());
    assert!(!bom.errors.is_empty());
}

#[test]
fn mcp_checks_configured_roots_without_changing_scope_or_allowing_other_roots() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let other = temp.path().join("other");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&other).unwrap();
    fs::write(project.join("requirements.txt"), "requests==2.0.0\n").unwrap();
    let state = temp.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::write(
        state.join("config.json"),
        json!({"roots":[project]}).to_string(),
    )
    .unwrap();
    let request =
        json!({"method":"tools/call","params":{"name":"check","arguments":{"offline":true}}});
    let response = mcp::call(&state, &request, None, None).unwrap();
    let result: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        result["scan_scope"],
        identity(&json!([[project], false, false, false, ""])).unwrap()
    );
    assert_eq!(result["packages"][0]["name"], "requests");
    let denied = json!({"method":"tools/call","params":{"name":"check","arguments":{"offline":true,"roots":[other]}}});
    assert!(mcp::call(&state, &denied, None, None).is_err());
}

#[cfg(unix)]
#[test]
fn mcp_does_not_remove_symlink_evidence_before_scanning() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let alias = temp.path().join("alias");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("requirements.txt"), "requests==2.0.0\n").unwrap();
    std::os::unix::fs::symlink(&project, &alias).unwrap();
    let state = temp.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::write(
        state.join("config.json"),
        json!({"roots":[project]}).to_string(),
    )
    .unwrap();
    let request = json!({"method":"tools/call","params":{"name":"check","arguments":{"offline":true,"roots":[alias]}}});
    match mcp::call(&state, &request, None, None) {
        Err(_) => {}
        Ok(response) => {
            let result: Value =
                serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
            assert!(result["packages"].as_array().unwrap().is_empty());
            assert_ne!(result["status"], "no-known-findings");
        }
    }
}

#[test]
fn mcp_without_config_accepts_its_working_directory() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    fs::create_dir(&project).unwrap();
    let cwd = project.to_string_lossy().into_owned();
    #[cfg(windows)]
    let cwd = format!("{}{}", cwd[..1].to_lowercase(), &cwd[1..]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args([
            "--state",
            temp.path().join("state").to_str().unwrap(),
            "mcp",
        ])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check","arguments":{"offline":true}}})).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(response.get("result").is_some(), "{response}");
}

#[test]
fn mcp_inventory_discovers_only_configured_packages_without_mailbox_changes() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&state).unwrap();
    fs::write(project.join("requirements.txt"), "requests==2.0.0\n").unwrap();
    fs::write(
        state.join("config.json"),
        json!({"roots":[project]}).to_string(),
    )
    .unwrap();
    let tools = mcp::call(&state, &json!({"method":"tools/list"}), None, None).unwrap();
    assert!(tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "inventory"));
    let request = json!({"method":"tools/call","params":{"name":"inventory","arguments":{}}});
    let response = mcp::call(&state, &request, None, None).unwrap();
    let result: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["packages"].as_array().unwrap().len(), 1);
    assert_eq!(result["packages"][0]["name"], "requests");
    assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
    let denied = json!({"method":"tools/call","params":{"name":"inventory","arguments":{"roots":[temp.path()]}}});
    assert!(mcp::call(&state, &denied, None, None).is_err());
}

#[test]
fn mcp_agent_inventory_is_scoped_and_does_not_execute_discovered_servers() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&state).unwrap();
    let marker = project.join("must-not-exist");
    fs::write(
        project.join(".mcp.json"),
        json!({"mcpServers":{"example":{"command":"touch","args":[marker]}}}).to_string(),
    )
    .unwrap();
    fs::write(
        state.join("config.json"),
        json!({"roots":[project]}).to_string(),
    )
    .unwrap();
    let request = json!({"method":"tools/call","params":{"name":"agent_inventory","arguments":{}}});
    let response = mcp::call(&state, &request, None, None).unwrap();
    let result: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(
        result["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["name"] == "example"),
        "{result}"
    );
    assert_eq!(result["status"], "inventory-only");
    assert_eq!(result["coverage"]["advisories_checked"], false);
    assert!(!marker.exists());
    assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
    let denied = json!({"method":"tools/call","params":{"name":"agent_inventory","arguments":{"roots":[temp.path()]}}});
    assert!(mcp::call(&state, &denied, None, None).is_err());
}

#[test]
fn mcp_agent_check_matches_cli_and_keeps_offline_coverage_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&state).unwrap();
    fs::write(
        project.join(".mcp.json"),
        json!({"mcpServers":{"example":{"command":"npx","args":["-y","example@1.2.3"]}}})
            .to_string(),
    )
    .unwrap();
    fs::write(
        state.join("config.json"),
        json!({"roots":[project]}).to_string(),
    )
    .unwrap();
    let request =
        json!({"method":"tools/call","params":{"name":"agent_check","arguments":{"offline":true}}});
    let response = mcp::call(&state, &request, None, None).unwrap();
    let result: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["packages"], 1);
    assert!(result["coverage"]["skipped_kinds"]
        .as_array()
        .unwrap()
        .contains(&json!("model")));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(temp.path().join("cli-state"))
        .args(["agentbom", "--offline", "--no-models", "--root"])
        .arg(&project)
        .arg("--home")
        .arg(temp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let cli: Value = serde_json::from_slice(&output.stdout).unwrap();
    for field in ["status", "packages", "coverage"] {
        assert_eq!(result[field], cli[field], "{field}");
    }
    let store = vorda::store::Store::open(&state).unwrap();
    let count: i64 = store
        .db
        .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
        .unwrap();
    mcp::call(&state, &request, None, None).unwrap();
    assert_eq!(
        store
            .db
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        count
    );
}

#[test]
fn locally_selected_installed_inventory_includes_separate_msix_outcome() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("project")).unwrap();
    fs::write(
        temp.path().join("config.json"),
        json!({"installed_apps":true,"roots":[temp.path().join("project")]}).to_string(),
    )
    .unwrap();
    let response = mcp::call(
        temp.path(),
        &json!({"method":"tools/call","params":{"name":"inventory","arguments":{}}}),
        None,
        None,
    )
    .unwrap();
    let result: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    let outcomes = result["source_outcomes"].as_array().unwrap();
    let msix = outcomes
        .iter()
        .find(|o| o["source"] == "windows-msix")
        .unwrap();
    assert_eq!(msix["path"], "windows-msix:HKCU:activatable-packages");
    assert_eq!(msix["advisory_coverage"], "not-assessed");
    #[cfg(not(windows))]
    assert_eq!(msix["outcome"], "unsupported");
}
