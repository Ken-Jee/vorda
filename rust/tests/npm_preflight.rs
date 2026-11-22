#![cfg(unix)]
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    policy::Policy,
    repair::{commands, locked},
};

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn repo(root: &Path, manifest: &Value, lock: &Value) {
    fs::create_dir(root).unwrap();
    fs::write(root.join("package.json"), manifest.to_string()).unwrap();
    fs::write(root.join("package-lock.json"), lock.to_string()).unwrap();
    git(root, &["init", "-b", "main"]);
    git(root, &["config", "user.name", "Fixture"]);
    git(root, &["config", "user.email", "fixture@example.invalid"]);
    git(root, &["add", "."]);
    git(root, &["commit", "-m", "Initial"]);
}
fn input() -> (Value, Value) {
    (
        json!({"name":"fixture","version":"1.0.0","dependencies":{"minimist":"1.2.5"}}),
        json!({"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{"minimist":"1.2.5"}},"node_modules/minimist":{"version":"1.2.5","resolved":"https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz","integrity":"sha512-fixture"}}}),
    )
}

#[test]
fn unsupported_resolution_is_refused_before_any_runtime_execution() {
    let t = tempfile::tempdir().unwrap();
    let marker = t.path().join("runtime-entered");
    let npm = t.path().join("npm-probe");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}/nonregistry.tgz");
    // Even npm --version must wait until the input is safe to interpret.
    fs::write(&npm, format!("#!/bin/bash\n: > '{}'\nexec 3<>/dev/tcp/127.0.0.1/{}\nprintf 'GET /nonregistry.tgz HTTP/1.0\\r\\n\\r\\n' >&3\nexec 3>&-\nexit 93\n", marker.display(), address.port())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&npm, fs::Permissions::from_mode(0o700)).unwrap();
    let node = t.path().join("node-probe");
    fs::copy("/bin/bash", &node).unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = json!({"node":node,"npm":npm});
    let policy = Policy::new(json!({"allow":["patch"]})).unwrap();
    let mut cases = Vec::new();
    for spec in [
        url.as_str(),
        "https://example.invalid/a.tgz",
        "git+https://example.invalid/a",
        "file:../a",
        "npm:other@1.0.0",
        "latest",
        "workspace:*",
    ] {
        let (mut m, mut l) = input();
        m["dependencies"]["extra"] = json!(spec);
        cases.push((m.clone(), l.clone())); // Missing from lock, original exploit.
        l["packages"][""]["dependencies"] = m["dependencies"].clone();
        l["packages"]["node_modules/extra"] =
            json!({"version":spec,"resolved":"https://registry.npmjs.org/extra/-/extra-1.0.0.tgz"});
        cases.push((m, l));
    }
    for key in [
        "workspaces",
        "overrides",
        "resolutions",
        "bundledDependencies",
        "bundleDependencies",
    ] {
        let (mut m, l) = input();
        m[key] = json!({});
        cases.push((m, l));
    }
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let (mut m, l) = input();
        m[section]["extra"] = json!("1.0.0");
        cases.push((m, l));
    }
    let (m, mut l) = input();
    l["packages"]["node_modules/minimist"]["dependencies"] = json!({"extra":url});
    cases.push((m, l));
    let (m, mut l) = input();
    l["packages"]["node_modules/minimist"]["resolved"] = json!(url);
    cases.push((m, l));
    let (m, mut l) = input();
    l["packages"]["node_modules/minimist"]["version"] = json!("1.2.4");
    cases.push((m, l));
    for (i, (manifest, lock)) in cases.into_iter().enumerate() {
        let root = t.path().join(format!("repo-{i}"));
        repo(&root, &manifest, &lock);
        let result = locked::resolve(&root, "minimist", "1.2.8", &policy, Some(&runtime), |_| {
            panic!("refused input must not scan")
        })
        .unwrap();
        assert_eq!(result["status"], "failed", "case {i}: {result}");
        assert!(!result["errors"].as_array().unwrap().is_empty());
        assert!(
            !marker.exists(),
            "npm ran before refusing case {i}: {result}"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    // Discriminating control: supported input reaches the runtime probe.
    let (m, l) = input();
    let root = t.path().join("supported");
    repo(&root, &m, &l);
    let result = locked::resolve(&root, "minimist", "1.2.8", &policy, Some(&runtime), |_| {
        panic!("probe fails before scan")
    })
    .unwrap();
    assert_eq!(result["status"], "failed");
    assert!(
        marker.exists(),
        "supported input never reached runtime: {result}"
    );
    let (mut request, _) = listener
        .accept()
        .expect("runtime probe must contact loopback in supported control");
    use std::io::Read;
    let mut request_bytes = String::new();
    request.read_to_string(&mut request_bytes).unwrap();
    assert!(request_bytes.starts_with("GET /nonregistry.tgz HTTP/1.0"));
    // A writable runtime still fails closed even for otherwise supported input.
    fs::remove_file(&marker).unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o777)).unwrap();
    let result = locked::resolve(&root, "minimist", "1.2.8", &policy, Some(&runtime), |_| {
        panic!("unsafe runtime must not scan")
    })
    .unwrap();
    assert_eq!(result["status"], "failed");
    assert!(!marker.exists(), "unsafe runtime executed: {result}");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn repository_change_dirty_candidate_and_rollback_failure_remain_explicit() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    let (m, _) = input();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("package.json"), m.to_string()).unwrap();
    git(&root, &["init", "-b", "main"]);
    git(&root, &["config", "user.name", "Fixture"]);
    git(&root, &["config", "user.email", "fixture@example.invalid"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "Initial"]);
    let check = json!(["sh", "-c", "true"]);
    let plan = commands::repo_plan(&root, "minimist", "1.2.5", "1.2.8", &check, None).unwrap();
    fs::write(root.join("untracked"), "dirty").unwrap();
    assert!(commands::apply_repo(&plan, "refuse-dirty").is_err());
    fs::remove_file(root.join("untracked")).unwrap();
    fs::write(root.join("changed"), "changed").unwrap();
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "Changed head"]);
    assert!(commands::apply_repo(&plan, "refuse-head").is_err());
    let check = json!(["sh", "-c", "rm package.json; mkdir package.json; exit 7"]);
    let plan = commands::repo_plan(&root, "minimist", "1.2.5", "1.2.8", &check, None).unwrap();
    let error = commands::apply_repo(&plan, "failed-rollback").unwrap_err();
    assert_eq!(error.class, "rollback-failed");
    assert!(error.to_string().contains("rollback:"));
    assert!(root.join("package.json").is_dir());
    assert_eq!(
        commands::run(
            &["git".into(), "branch".into(), "--show-current".into()],
            Some(&root)
        )
        .unwrap()
        .trim(),
        "failed-rollback"
    );
}

#[test]
fn successful_check_cannot_change_the_reviewed_lock_candidate() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    let (manifest, lock) = input();
    repo(&root, &manifest, &lock);
    let before_manifest = fs::read_to_string(root.join("package.json")).unwrap();
    let before_lock = fs::read_to_string(root.join("package-lock.json")).unwrap();
    let after_manifest =
        json!({"name":"fixture","version":"1.0.0","dependencies":{"minimist":"1.2.8"}});
    let after_lock = json!({"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{"minimist":"1.2.8"}},"node_modules/minimist":{"version":"1.2.8","resolved":"https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz","integrity":"sha512-fixture"}}});
    let candidate = json!({"before":{"package.json":before_manifest,"package-lock.json":before_lock},"after":{"package.json":after_manifest.to_string(),"package-lock.json":after_lock.to_string()},"package_delta":[]});
    let check = json!([
        "sh",
        "-c",
        "sed -i 's/\"lockfileVersion\":3/\"lockfileVersion\":4/' package-lock.json"
    ]);
    let plan = commands::repo_plan(
        &root,
        "minimist",
        "1.2.5",
        "1.2.8",
        &check,
        Some(&candidate),
    )
    .unwrap();
    let error = commands::apply_repo(&plan, "unreviewed-check").unwrap_err();
    assert_eq!(error.class, "rolled-back");
    assert!(error
        .to_string()
        .contains("changed the reviewed locked candidate"));
    assert_eq!(
        fs::read_to_string(root.join("package.json")).unwrap(),
        before_manifest
    );
    assert_eq!(
        fs::read_to_string(root.join("package-lock.json")).unwrap(),
        before_lock
    );
    assert!(commands::run(
        &["git".into(), "status".into(), "--porcelain".into()],
        Some(&root)
    )
    .unwrap()
    .trim()
    .is_empty());
    assert_eq!(
        commands::run(
            &["git".into(), "branch".into(), "--show-current".into()],
            Some(&root)
        )
        .unwrap()
        .trim(),
        "main"
    );
}
