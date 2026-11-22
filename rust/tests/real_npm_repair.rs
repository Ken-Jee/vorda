use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    cli,
    domain::ScanOptions,
    repair::{commands, Repairs},
    store::Store,
};
fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
#[test]
#[ignore = "explicit real npm runtime and free public registry/advisory access required"]
fn real_npm_reviewed_lock_candidate_applies_and_preserves_sibling() {
    let node = std::env::var("VORDA_TEST_NODE").unwrap();
    let npm = std::env::var("VORDA_TEST_NPM").unwrap();
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("package.json"),json!({"name":"repair-control","version":"1.0.0","scripts":{"postinstall":"exit 77"},"dependencies":{"minimist":"1.2.5"}}).to_string()).unwrap();
    let config1 = t.path().join("user-npmrc");
    let config2 = t.path().join("global-npmrc");
    fs::write(&config1, "").unwrap();
    fs::write(&config2, "").unwrap();
    commands::run(
        &[
            node.clone(),
            npm.clone(),
            format!("--userconfig={}", config1.display()),
            format!("--globalconfig={}", config2.display()),
            "install".into(),
            "--package-lock-only".into(),
            "--ignore-scripts".into(),
            "--no-audit".into(),
            "--no-fund".into(),
            "--registry=https://registry.npmjs.org".into(),
        ],
        Some(&root),
    )
    .unwrap();
    git(&root, &["init", "-b", "main"]);
    git(&root, &["config", "user.name", "Fixture"]);
    git(&root, &["config", "user.email", "fixture@example.invalid"]);
    git(&root, &["add", "."]);
    git(&root, &["commit", "-m", "Initial"]);
    let state = t.path().join("state");
    let mut store = Store::open(&state).unwrap();
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![root.join("package-lock.json")];
    let before = cli::check(&options, &mut store).unwrap();
    assert!(
        before["errors"].as_array().unwrap().is_empty(),
        "{before:?}"
    );
    let initial = store.active().unwrap();
    let target = initial
        .iter()
        .find(|f| f["package"]["name"] == "minimist")
        .expect("vulnerable minimist baseline");
    let item = target["key"].as_str().unwrap().to_owned();
    let sibling=json!({"key":"synthetic-sibling","asset":"sibling","kev":null,"epss":null,"title":"Retain unrelated evidence","package":{"name":"sibling","version":"1.0.0","ecosystem":"npm","path":root.join("package-lock.json"),"scope":"runtime"}}).as_object().unwrap().clone();
    let mut seeded = initial;
    seeded.push(sibling.clone());
    store.reconcile(&seeded, &Default::default(), &[]).unwrap();
    let policy = t.path().join("policy.json");
    let fleet = t.path().join("fleet.json");
    let config = t.path().join("fix.json");
    fs::write(&policy, json!({"allow":["patch"]}).to_string()).unwrap();
    fs::write(
        &fleet,
        json!({"mode":"fix","allow":["lockfiles"]}).to_string(),
    )
    .unwrap();
    fs::write(&config,json!({"policy":policy,"fleet":fleet,"runtime":{"node":node,"npm":npm},"repositories":{root.to_str().unwrap():[node,"-e","const p=require('./package-lock.json');if(p.packages['node_modules/minimist'].version!=='1.2.8')process.exit(1)"]}}).to_string()).unwrap();
    let mut repairs = Repairs::open(&state, &config).unwrap();
    repairs
        .dispatch("claim", &json!({"item":item,"agent":"test"}))
        .unwrap();
    let plan=repairs.generated_plan(&json!({"kind":"repo","root":root,"package":"minimist","old":"1.2.5","new":"1.2.8","locked":true})).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(root.join("package-lock.json")).unwrap())
            .unwrap()["packages"]["node_modules/minimist"]["version"],
        "1.2.5"
    );
    repairs
        .dispatch("plan", &json!({"item":item,"agent":"test","plan":plan}))
        .unwrap();
    repairs.draft(&item, "test").unwrap();
    let row = repairs.row(&item).unwrap();
    let digest = vorda::repair::digest(&row["plan"]).unwrap();
    assert!(repairs
        .approve(&item, true, "local-owner", "cli", "wrong-digest")
        .is_err());
    assert!(repairs.apply(&item, "test", false).is_err());
    repairs
        .approve(&item, true, "local-owner", "cli", &digest)
        .unwrap();
    assert_eq!(
        repairs.apply(&item, "test", false).unwrap()["status"],
        "verified"
    );
    assert!(store.active().unwrap().iter().any(|f| f == &sibling));
    assert!(!store.active().unwrap().iter().any(|f| f["key"] == item));
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(root.join("package-lock.json")).unwrap())
            .unwrap()["packages"]["node_modules/minimist"]["version"],
        "1.2.8"
    );
}
