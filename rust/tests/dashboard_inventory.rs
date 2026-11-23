use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::surfaces::dashboard::{data, inventory::inventory_screen, views};

fn lock(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
}

/// One offline project scan of a folder holding two lockfiles.
fn scanned(root: &Path, state: &Path) -> Value {
    lock(root);
    lock(&root.join("web"));
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(state)
        .args(["scan", "--json", "--offline", "--root"])
        .arg(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    data::snapshot(state, vorda::store::now(), None).unwrap()
}

#[test]
fn project_lockfiles_counts_lockfiles_not_saved_scans() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("shop");
    let snapshot = scanned(&root, &temp.path().join("state"));
    let home = views::overview_screen(&snapshot);
    assert!(
        home.contains("<span>Project lockfiles</span><span>2 found</span>"),
        "{home}"
    );

    let page = inventory_screen(&snapshot, "projects");
    assert!(
        page.contains("Projects<span class=\"n\">1</span>"),
        "{page}"
    );
    assert!(page.contains("aria-current=\"page\">Projects"), "{page}");
    assert!(
        page.contains(&format!("npm · {} · 2 lockfiles", root.display())),
        "{page}"
    );
    assert!(page.contains("Coverage is part of the result"), "{page}");
    assert!(page.contains("data-copy=\"vorda inventory --format cyclonedx\""));
}

#[test]
fn machines_tab_says_coverage_is_partial_after_an_offline_scan() {
    let temp = tempfile::tempdir().unwrap();
    let snapshot = scanned(&temp.path().join("shop"), &temp.path().join("state"));
    // An unknown tab falls back to Machines.
    let page = inventory_screen(&snapshot, "nonsense");
    assert!(page.contains("aria-current=\"page\">Machines"), "{page}");
    assert!(page.contains("Coverage partial"), "{page}");
    assert!(!page.contains("Coverage complete"), "{page}");
    assert!(
        page.contains("System packages, browsers, tools · 2 packages"),
        "{page}"
    );
}

fn tool(host: &str, path: &str, name: &str, checked: bool) -> Value {
    json!({"host":host,"category":"Developer Tools","subtype":"tool","checked":checked,"finding_count":0,
        "record":{"name":name,"version":"1.2.3","ecosystem":"npm","path":path,"origin":"tool"}})
}

fn machine(items: Vec<Value>) -> Value {
    json!({"now":1000.0,"has_scans":true,
        "hosts":[{"host":"box","scan":"ok","problems":[],"last":{"finished":999.0}}],
        "projects":[],"issues":[],"assets":{"items":items}})
}

#[test]
fn agent_tools_tab_counts_agent_clis_and_lists_other_tools() {
    let snapshot = machine(vec![
        tool("box", "tool:claude", "@anthropic-ai/claude-code", true),
        tool("box", "tool:node", "node", false),
    ]);
    let page = inventory_screen(&snapshot, "agents");
    assert!(
        page.contains("Agent tools<span class=\"n\">1</span>"),
        "{page}"
    );
    assert!(!page.contains("No agent tools found"), "{page}");
    assert!(page.contains("@anthropic-ai/claude-code 1.2.3"), "{page}");
    assert!(page.contains("Agent CLI · npm advisories"), "{page}");
    assert!(page.contains(">Checked<"), "{page}");
    assert!(page.contains(">Not checked<"), "{page}");
    let home = views::overview_screen(&snapshot);
    assert!(
        home.contains("<span>Agent tools</span><span>1 found</span>"),
        "{home}"
    );

    let none = inventory_screen(
        &machine(vec![tool("box", "tool:node", "node", true)]),
        "agents",
    );
    assert!(none.contains("No agent tools found"), "{none}");
    assert!(none.contains("node 1.2.3"), "{none}");
    let home = views::overview_screen(&machine(vec![tool("box", "tool:node", "node", true)]));
    assert!(
        home.contains("<span>Agent tools</span><span>None found</span>"),
        "{home}"
    );
}

#[test]
fn empty_tabs_and_first_run_have_their_own_states() {
    let page = inventory_screen(&machine(vec![]), "browsers");
    assert!(page.contains("No browsers found"), "{page}");
    let page = inventory_screen(&machine(vec![]), "projects");
    assert!(page.contains("No projects found"), "{page}");
    let page = inventory_screen(&machine(vec![]), "machines");
    assert!(page.contains("Coverage complete"), "{page}");

    let first = inventory_screen(&json!({"now":1000.0}), "projects");
    assert!(first.contains("No inventory yet"), "{first}");
    assert!(first.contains("data-copy=\"vorda scan\""), "{first}");
    assert!(!first.contains("<span class=\"n\">"), "{first}");
}

#[test]
fn one_unchecked_source_is_singular_on_the_overview() {
    let snapshot = json!({"now":1000.0,"has_scans":true,
        "hosts":[{"host":"box","scan":"failed","problems":["npm advisories"],"problem_count":1,"last":{"finished":999.0}}],
        "projects":[],"issues":[],"assets":{"items":[]}});
    let home = views::overview_screen(&snapshot);
    assert!(home.contains("1 source could not be checked"), "{home}");
    assert!(!home.contains("1 sources"), "{home}");
}
