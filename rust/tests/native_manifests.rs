use std::fs;
use vorda::release::manifests::render;

#[test]
fn native_manifests_require_all_artifacts_and_preserve_existing_output() {
    let root = tempfile::tempdir().unwrap();
    let dist = root.path().join("dist");
    fs::create_dir(&dist).unwrap();
    let output = root.path().join("manifests");
    fs::write(dist.join("SHA256SUMS"), "").unwrap();
    assert!(render(&dist, "https://github.com/example/vorda", "0.1.0", &output).is_err());
    assert!(!output.exists());
    let targets = [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc.exe",
    ];
    let hashes: String = targets
        .iter()
        .enumerate()
        .map(|(i, t)| format!("{:064x}  vorda-0.1.0-{t}\n", i + 1))
        .collect();
    fs::write(dist.join("SHA256SUMS"), hashes).unwrap();
    render(&dist, "https://github.com/example/vorda", "0.1.0", &output).unwrap();
    let brew = fs::read_to_string(output.join("homebrew/vorda.rb")).unwrap();
    assert!(!brew.contains("python"));
    assert!(!brew.contains("@SHA"));
    assert!(brew.contains("vorda-0.1.0-aarch64-apple-darwin"));
    let winget = fs::read_to_string(output.join("winget/Ken-Jee.vorda.installer.yaml")).unwrap();
    assert!(winget.contains("x86_64-pc-windows-msvc.exe"));
    assert!(!winget.contains("Python"));
    let mcp: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output.join("mcp/server.json")).unwrap()).unwrap();
    assert_eq!(mcp["packages"][0]["registryType"], "cargo");
    assert!(mcp["packages"][0].get("runtimeHint").is_none());
    assert!(render(&dist, "https://github.com/example/vorda", "0.1.0", &output).is_err());
    assert_eq!(
        fs::read_to_string(output.join("homebrew/vorda.rb")).unwrap(),
        brew
    );
}
