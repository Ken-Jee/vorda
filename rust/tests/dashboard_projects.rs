use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    store::Store,
    surfaces::dashboard::{data, views},
};

fn scan(state: &Path, root: &Path) -> Value {
    scan_many(state, &[root])
}

fn scan_many(state: &Path, roots: &[&Path]) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command
        .arg("--state")
        .arg(state)
        .args(["scan", "--offline", "--json"]);
    for &root in roots {
        fs::create_dir_all(root).unwrap();
        command.arg("--root").arg(root);
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn finding(state: &Path, root: &Path, scope: &Value, name: &str) {
    finding_at(state, &root.join("package-lock.json"), scope, name);
}

fn finding_at(state: &Path, lockfile: &Path, scope: &Value, name: &str) {
    Store::open(state)
        .unwrap()
        .reconcile(
            &[json!({
                "key":name,"host":vorda::store::hostname().unwrap(),"scan_scope":scope,
                "advisory":name,"package":{"name":name,"version":"1","ecosystem":"npm",
                "path":lockfile,"scope":"reachable-unknown"},
                "priority":{"level":"high"}
            })
            .as_object()
            .unwrap()
            .clone()],
            &Default::default(),
            &[],
        )
        .unwrap();
}

fn pages(state: &Path) -> (Value, String, String) {
    let s = data::snapshot(state, vorda::store::now(), None).unwrap();
    let home = views::now_screen(&s);
    let findings = views::render(&s, "findings", "", "all", "", "", false).unwrap();
    (s, home, findings)
}

// Record the successful online scan shape without contacting advisory services.
fn record_online_scan(state: &Path, roots: &[&Path], checked: &[&Path], status: &str) -> Value {
    let mut saved = scan_many(state, roots);
    saved["packages"] = json!(checked
        .iter()
        .map(|root| json!({
            "name":"example","version":"1.0.0","ecosystem":"npm",
            "path":root.join("package-lock.json")
        }))
        .collect::<Vec<_>>());
    saved["coverage_evidence"] = json!({
        "status":if checked.is_empty() {"partial"} else {"complete"},
        "observations":checked.iter().map(|root| json!({
            "kind":"supported-input","path":root.join("package-lock.json")
        })).collect::<Vec<_>>()
    });
    mark_online(state, saved, status)
}

fn mark_online(state: &Path, mut saved: Value, status: &str) -> Value {
    saved["status"] = json!(status);
    saved["errors"] = json!([]);
    let scope = saved["scan_scope"].as_str().unwrap();
    Store::open(state)
        .unwrap()
        .persist_assessment(scope, &saved)
        .unwrap();
    let db = rusqlite::Connection::open(state.join("mail.db")).unwrap();
    db.execute(
        "UPDATE scans SET status=?,errors='[]' WHERE scan_scope=?",
        [status, scope],
    )
    .unwrap();
    db.execute("UPDATE findings SET active=0 WHERE json_extract(payload,'$.kind')='health' AND json_extract(payload,'$.scan_scope')=?", [scope]).unwrap();
    saved
}

// A real scan lists the package each of its findings names; `finding_at` uses version 1.
fn also_lists(state: &Path, mut saved: Value, lockfile: &Path, name: &str) -> Value {
    let status = saved["status"].as_str().unwrap().to_string();
    saved["packages"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":name,"version":"1","ecosystem":"npm","path":lockfile}));
    mark_online(state, saved, &status)
}

fn get(state: &Path, target: &str) -> String {
    use vorda::surfaces::dashboard::{App, Request};
    let bind = std::net::Ipv4Addr::LOCALHOST.to_string();
    let app = App::new(state, &bind, 7780, String::new(), false, None).unwrap();
    let response = app.handle(&Request {
        method: "GET".into(),
        target: target.into(),
        headers: std::collections::BTreeMap::from([("host".into(), format!("{bind}:7780"))]),
        body: vec![],
    });
    assert_eq!(response.status, 200);
    String::from_utf8(response.body).unwrap()
}

fn finding_link(home: &str, key: &str, value: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(key, value)
        .finish();
    home.split("href=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|href| href.starts_with("/findings?") && href.contains(query.as_str()))
        .expect("project finding link")
        .replace("&amp;", "&")
}

#[test]
fn online_empty_project_is_unknown_with_both_saved_scan_statuses() {
    for status in ["no-known-findings", "unknown"] {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("empty-project");
        record_online_scan(t.path(), &[&root], &[], status);
        let (_, home, findings) = pages(t.path());
        assert!(
            home.contains("Can't confirm") && home.contains("Nothing checked"),
            "{home}"
        );
        assert!(home.contains("1 project unknown"), "{home}");
        assert!(
            !home.contains("All clear") && !home.contains("Fine") && !home.contains("No scans yet"),
            "{home}"
        );
        let card = home
            .split("<a class=\"row\"")
            .find(|row| row.contains("Nothing checked"))
            .unwrap();
        assert!(
            card.contains("Can't confirm") && !card.contains("Clear"),
            "{card}"
        );
        assert!(findings.contains("Can&#x27;t confirm"), "{findings}");
        let page = get(
            t.path(),
            &finding_link(&home, "project", root.to_str().unwrap()),
        );
        assert!(
            page.contains("Can&#x27;t confirm") && !page.contains("Nothing found"),
            "{page}"
        );
    }
}

#[test]
fn empty_root_already_saved_as_unknown_with_a_named_error_is_counted_once() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("empty-project");
    let reason = "No package versions found; nothing was checked; package coverage is unknown";
    let mut saved = record_online_scan(t.path(), &[&root], &[], "unknown");
    saved["errors"] = json!([reason]);
    let scope = saved["scan_scope"].as_str().unwrap();
    Store::open(t.path())
        .unwrap()
        .persist_assessment(scope, &saved)
        .unwrap();
    let db = rusqlite::Connection::open(t.path().join("mail.db")).unwrap();
    db.execute(
        "UPDATE scans SET errors=? WHERE scan_scope=?",
        [json!([reason]).to_string(), scope.to_string()],
    )
    .unwrap();
    let (_, home, _) = pages(t.path());
    assert!(
        home.contains("1 project unknown") && !home.contains("2 projects unknown"),
        "{home}"
    );
    assert!(
        !home.contains("All clear") && !home.contains("Fine"),
        "{home}"
    );
    let card = home
        .split("<a class=\"row\"")
        .find(|row| row.contains("empty-project"))
        .unwrap();
    assert_eq!(card.matches("Can't confirm").count(), 1, "{card}");
    assert!(!card.contains("Clear"), "{card}");
}

#[test]
fn legacy_online_empty_scope_is_unknown_without_claiming_a_root() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("empty-project");
    let mut saved = record_online_scan(t.path(), &[&root], &[], "no-known-findings");
    saved.as_object_mut().unwrap().remove("scan_roots");
    let scope = saved["scan_scope"].as_str().unwrap();
    Store::open(t.path())
        .unwrap()
        .persist_assessment(scope, &saved)
        .unwrap();
    let (_, home, _) = pages(t.path());
    let target = finding_link(&home, "scope", scope);
    let row = home
        .split("<a class=\"row\"")
        .find(|row| row.contains(&target))
        .unwrap();
    assert!(
        row.contains("Saved historical scope") && row.contains("Nothing checked"),
        "{row}"
    );
    assert!(
        !row.contains("Clear") && !home.contains("All clear"),
        "{home}"
    );
    assert!(home.contains("1 project unknown"), "{home}");
    assert!(get(t.path(), &target).contains("Can&#x27;t confirm"));
}

#[test]
fn online_empty_root_stays_unknown_beside_a_covered_root_in_separate_or_combined_scans() {
    for combined in [false, true] {
        let t = tempfile::tempdir().unwrap();
        let covered = t.path().join("covered-project");
        let empty = t.path().join("empty-project");
        if combined {
            record_online_scan(
                t.path(),
                &[&covered, &empty],
                &[&covered],
                "no-known-findings",
            );
        } else {
            record_online_scan(t.path(), &[&covered], &[&covered], "no-known-findings");
            record_online_scan(t.path(), &[&empty], &[], "no-known-findings");
        }
        let (_, home, _) = pages(t.path());
        assert!(
            home.contains("1 project unknown") && home.contains("Nothing checked"),
            "{home}"
        );
        assert!(
            !home.contains("All clear") && !home.contains("Fine"),
            "{home}"
        );
        let card = home
            .split("<a class=\"row\"")
            .find(|row| row.contains("Nothing checked"))
            .unwrap();
        assert!(
            card.contains("Can't confirm") && !card.contains("Clear"),
            "{card}"
        );
        let empty_page = get(
            t.path(),
            &finding_link(&home, "project", empty.to_str().unwrap()),
        );
        assert!(empty_page.contains("Can&#x27;t confirm"), "{empty_page}");
        let covered_page = get(
            t.path(),
            &finding_link(&home, "project", covered.to_str().unwrap()),
        );
        assert!(covered_page.contains("Nothing found"), "{covered_page}");
    }
}

#[test]
fn legacy_card_is_historical_after_findings_move_to_a_known_root() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("legacy-project");
    let mut old = record_online_scan(t.path(), &[&root], &[&root], "no-known-findings");
    old.as_object_mut().unwrap().remove("scan_roots");
    let scope = old["scan_scope"].as_str().unwrap().to_owned();
    Store::open(t.path())
        .unwrap()
        .persist_assessment(&scope, &old)
        .unwrap();
    finding(t.path(), &root, &json!(scope), "MOVED-ADV");
    let sibling = t.path().join("sibling");
    let current = record_online_scan(
        t.path(),
        &[&root, &sibling],
        &[&root, &sibling],
        "no-known-findings",
    );
    finding(t.path(), &root, &current["scan_scope"], "MOVED-ADV");
    let (_, home, _) = pages(t.path());
    let target = finding_link(&home, "scope", &scope);
    let row = home
        .split("<a class=\"row\"")
        .find(|row| row.contains(&target))
        .unwrap();
    assert!(row.contains("Saved historical scope"), "{home}");
    assert!(!row.contains("Clear"), "{home}");
    let current_page = get(
        t.path(),
        &finding_link(&home, "project", root.to_str().unwrap()),
    );
    assert!(current_page.contains("MOVED-ADV"), "{current_page}");
    assert!(!current_page.contains("Scan failed"), "{current_page}");
}

#[test]
fn vulnerable_imported_package_list_shows_its_findings_over_http() {
    let t = tempfile::tempdir().unwrap();
    let cwd = t.path().join("workdir");
    let lockfile = Path::new("/app/package-lock.json");
    let saved = record_online_scan(t.path(), &[&cwd], &[Path::new("/app")], "vulnerable");
    let saved = also_lists(t.path(), saved, lockfile, "IMPORT-ADV");
    finding_at(t.path(), lockfile, &saved["scan_scope"], "IMPORT-ADV");
    let (_, home, _) = pages(t.path());
    let card = home
        .split("<a class=\"row\"")
        .find(|row| row.contains("Imported package list"))
        .expect(&home);
    assert!(card.contains("1 open") && card.contains("Urgent"), "{card}");
    assert!(
        !card.contains("Nothing checked") && !home.contains("Scan failed"),
        "{home}"
    );
    let page = get(
        t.path(),
        &finding_link(&home, "scope", saved["scan_scope"].as_str().unwrap()),
    );
    assert!(
        page.contains("IMPORT-ADV") && !page.contains("Scan failed"),
        "{page}"
    );
    assert!(!home.contains("All clear"), "{home}");
}

#[test]
fn clean_complete_imported_package_list_can_be_all_clear() {
    let t = tempfile::tempdir().unwrap();
    let cwd = t.path().join("workdir");
    let saved = record_online_scan(t.path(), &[&cwd], &[Path::new("/app")], "no-known-findings");
    let (_, home, _) = pages(t.path());
    assert!(home.contains("All clear"), "{home}");
    assert!(
        !home.contains("Can't confirm")
            && !home.contains("Scan failed")
            && !home.contains("Nothing checked"),
        "{home}"
    );
    assert!(home.contains("0 projects unknown"), "{home}");
    let page = get(
        t.path(),
        &finding_link(&home, "scope", saved["scan_scope"].as_str().unwrap()),
    );
    assert!(page.contains("Nothing found"), "{page}");
}

#[test]
fn packages_outside_the_roots_keep_their_own_card_beside_a_walked_root() {
    let t = tempfile::tempdir().unwrap();
    let (a, outside) = (t.path().join("walked"), Path::new("/app"));
    let lockfile = outside.join("package-lock.json");
    let saved = record_online_scan(t.path(), &[&a], &[&a, outside], "vulnerable");
    let saved = also_lists(t.path(), saved, &lockfile, "OUT-ADV");
    finding(t.path(), &a, &saved["scan_scope"], "ROOT-ADV");
    finding_at(t.path(), &lockfile, &saved["scan_scope"], "OUT-ADV");
    let (_, home, _) = pages(t.path());
    let root_page = get(
        t.path(),
        &finding_link(&home, "project", a.to_str().unwrap()),
    );
    assert!(
        root_page.contains("ROOT-ADV") && !root_page.contains("OUT-ADV"),
        "{root_page}"
    );
    let scope_page = get(
        t.path(),
        &finding_link(&home, "scope", saved["scan_scope"].as_str().unwrap()),
    );
    assert!(scope_page.contains("OUT-ADV"), "{scope_page}");
}

#[test]
fn unconfirmed_pages_say_what_is_true_and_what_to_do_not_scan_failed() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("empty-project");
    record_online_scan(t.path(), &[&root], &[], "no-known-findings");
    let (_, home, _) = pages(t.path());
    let page = get(
        t.path(),
        &finding_link(&home, "project", root.to_str().unwrap()),
    );
    for text in [&home, &page] {
        assert!(!text.contains("Scan failed"), "{text}");
        assert!(
            text.contains("no supported lockfile found") && text.contains("vorda check"),
            "{text}"
        );
    }
}

fn lock(dir: &Path, prefix: &str, count: usize) {
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({"name": prefix}));
    for i in 0..count {
        packages.insert(
            format!("node_modules/{prefix}-{i}"),
            json!({"version":"1.0.0"}),
        );
    }
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("package-lock.json"),
        json!({"name":prefix,"lockfileVersion":3,"requires":true,"packages":packages}).to_string(),
    )
    .unwrap();
}

// An offline scan saved as the online scan would be: only its own inventory errors remain.
fn keep_inventory_errors(state: &Path, roots: &[&Path]) {
    let mut saved = scan_many(state, roots);
    let errors: Vec<Value> = saved["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["source"] == "inventory")
        .cloned()
        .collect();
    assert!(!errors.is_empty(), "{saved}");
    saved["errors"] = json!(errors);
    let scope = saved["scan_scope"].as_str().unwrap().to_string();
    Store::open(state)
        .unwrap()
        .persist_assessment(&scope, &saved)
        .unwrap();
    let db = rusqlite::Connection::open(state.join("mail.db")).unwrap();
    db.execute(
        "UPDATE scans SET errors=? WHERE scan_scope=?",
        [json!(errors).to_string(), scope.clone()],
    )
    .unwrap();
    db.execute("UPDATE findings SET active=0 WHERE json_extract(payload,'$.kind')='health' AND json_extract(payload,'$.scan_scope')=? AND key<>?", [scope.clone(), format!("health:{scope}:inventory")]).unwrap();
}

#[test]
fn unconfirmed_cards_name_the_scans_own_reason() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let (cap, empty, sym) = (
        t.path().join("cap_over"),
        t.path().join("empty_dir"),
        t.path().join("symdir"),
    );
    lock(&cap, "overcap", 20_001);
    lock(&sym, "sym", 1);
    fs::create_dir_all(t.path().join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(t.path().join("elsewhere"), sym.join("linked")).unwrap();
    keep_inventory_errors(&state, &[&cap, &empty]);
    keep_inventory_errors(&state, &[&sym]);
    let (_, home, _) = pages(&state);
    let card = |root: &Path| {
        home.split("<a class=\"row\"")
            .find(|row| row.contains(&format!("{} · scanned", root.display())))
            .expect(&home)
            .to_string()
    };
    let cap_card = card(&cap);
    assert!(
        cap_card.contains("Can't confirm")
            && cap_card.contains("over the per-input cap")
            && !cap_card.contains("no supported lockfile found"),
        "{cap_card}"
    );
    // A sibling with no lockfile keeps its own reason, not the other folder's.
    let empty_card = card(&empty);
    assert!(
        empty_card.contains("no supported lockfile found") && !empty_card.contains("per-input cap"),
        "{empty_card}"
    );
    let sym_card = card(&sym);
    assert!(
        sym_card.contains("Can't confirm") && sym_card.contains("skipped symlink directory"),
        "{sym_card}"
    );
    let page = get(
        &state,
        &finding_link(&home, "project", sym.to_str().unwrap()),
    );
    assert!(
        page.contains("skipped symlink directory")
            && !page.contains("run vorda check again")
            && !page.contains("retries on the next scan"),
        "{page}"
    );
    // One scan of two folders saves one scan-health finding; each page keeps its own reason.
    let page = |root: &Path| {
        get(
            &state,
            &finding_link(&home, "project", root.to_str().unwrap()),
        )
    };
    let cap_page = page(&cap);
    assert!(cap_page.contains("over the per-input cap"), "{cap_page}");
    let empty_page = page(&empty);
    assert!(
        empty_page.contains("Part of the scan could not run")
            && !empty_page.contains("per-input cap"),
        "{empty_page}"
    );
}

#[test]
fn nested_roots_name_one_shared_error_once() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let (outer, inner) = (t.path().join("outer"), t.path().join("outer/inner"));
    lock(&outer, "outer", 1);
    lock(&inner, "inner", 1);
    fs::create_dir_all(t.path().join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(t.path().join("elsewhere"), inner.join("linked")).unwrap();
    keep_inventory_errors(&state, &[&outer, &inner]);
    let (_, home, _) = pages(&state);
    for root in [&outer, &inner] {
        let card = home
            .split("<a class=\"row\"")
            .find(|row| row.contains(&format!("{} · scanned", root.display())))
            .expect(&home);
        assert!(
            card.contains("skipped symlink directory") && !card.contains("and 1 more"),
            "{card}"
        );
    }
}

#[test]
fn a_finding_in_a_sibling_sharing_the_name_prefix_stays_on_its_own_card() {
    let t = tempfile::tempdir().unwrap();
    let (app, apple) = (t.path().join("app"), t.path().join("apple"));
    let lockfile = apple.join("package-lock.json");
    let saved = record_online_scan(t.path(), &[&app, &apple], &[&app, &apple], "vulnerable");
    let saved = also_lists(t.path(), saved, &lockfile, "APPLE-ADV");
    finding_at(t.path(), &lockfile, &saved["scan_scope"], "APPLE-ADV");
    let (_, home, _) = pages(t.path());
    let page = |root: &Path| {
        get(
            t.path(),
            &finding_link(&home, "project", root.to_str().unwrap()),
        )
    };
    let apple_page = page(&apple);
    assert!(apple_page.contains("APPLE-ADV"), "{apple_page}");
    let app_page = page(&app);
    assert!(!app_page.contains("APPLE-ADV"), "{app_page}");
}

#[test]
fn a_sibling_folder_sharing_the_name_prefix_keeps_its_scan_error() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let proj = t.path().join("proj");
    let siblings = [
        t.path().join("proj:evil"),
        t.path().join("proj: evil"),
        t.path().join("proj2"),
    ];
    lock(&proj, "proj", 1);
    fs::create_dir_all(t.path().join("elsewhere")).unwrap();
    for dir in &siblings {
        lock(dir, "sibling", 1);
        std::os::unix::fs::symlink(t.path().join("elsewhere"), dir.join("linked")).unwrap();
    }
    keep_inventory_errors(&state, &[&proj, &siblings[0], &siblings[1], &siblings[2]]);
    let (_, home, _) = pages(&state);
    let card = |root: &Path| {
        home.split("<a class=\"row\"")
            .find(|row| row.contains(&format!("{} · scanned", root.display())))
            .expect(&home)
            .to_string()
    };
    let proj_card = card(&proj);
    assert!(
        !proj_card.contains("skipped symlink directory"),
        "{proj_card}"
    );
    for dir in &siblings {
        let sibling_card = card(dir);
        assert!(
            sibling_card.contains("Can't confirm")
                && sibling_card.contains("skipped symlink directory"),
            "{sibling_card}"
        );
    }
}

#[test]
fn legacy_only_cards_keep_their_state_and_are_told_apart() {
    let t = tempfile::tempdir().unwrap();
    let mut urgent = record_online_scan(
        t.path(),
        &[&t.path().join("one")],
        &[&t.path().join("one")],
        "vulnerable",
    );
    urgent.as_object_mut().unwrap().remove("scan_roots");
    urgent.as_object_mut().unwrap().remove("coverage_evidence");
    let scope = urgent["scan_scope"].as_str().unwrap().to_owned();
    Store::open(t.path())
        .unwrap()
        .persist_assessment(&scope, &urgent)
        .unwrap();
    finding(t.path(), &t.path().join("one"), &json!(scope), "LEGACY-ADV");
    let mut quiet =
        record_online_scan(t.path(), &[&t.path().join("two")], &[], "no-known-findings");
    quiet.as_object_mut().unwrap().remove("scan_roots");
    quiet.as_object_mut().unwrap().remove("coverage_evidence");
    let quiet_scope = quiet["scan_scope"].as_str().unwrap().to_owned();
    Store::open(t.path())
        .unwrap()
        .persist_assessment(&quiet_scope, &quiet)
        .unwrap();
    let (_, home, _) = pages(t.path());
    let rows: Vec<_> = home.split("<a class=\"row\"").skip(1).collect();
    let loud = rows
        .iter()
        .find(|r| r.contains("LEGACY-ADV") || r.contains(&scope[..8]))
        .expect(&home);
    assert!(loud.contains("Urgent"), "{loud}");
    let names: Vec<_> = rows.iter().filter(|r| r.contains("Saved scan")).collect();
    assert!(names.len() == 2 && names[0] != names[1], "{home}");
    assert!(
        rows.iter()
            .all(|r| r.contains("Location not recorded") || !r.contains("Saved scan")),
        "{home}"
    );
}

#[test]
fn changed_root_selection_keeps_prior_project_findings() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let alpha = t.path().join("alpha");
    let beta = t.path().join("beta");
    let first = scan(&state, &alpha);
    finding(&state, &alpha, &first["scan_scope"], "RETAINED-ADV");
    let latest = scan_many(&state, &[alpha.as_path(), beta.as_path()]);
    assert_ne!(first["scan_scope"], latest["scan_scope"]);
    let (snapshot, home, _) = pages(&state);
    let projects = snapshot["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 2);
    let project = projects
        .iter()
        .find(|p| p["root"] == alpha.to_str().unwrap())
        .unwrap();
    assert_eq!(project["scope"], latest["scan_scope"]);
    assert_eq!(
        project["last"]["finished"],
        snapshot["hosts"][0]["last"]["finished"]
    );
    assert_eq!(project["open"], 1, "{home}");
    assert!(home.contains("1 urgent, 1 open"), "{home}");
    let target = finding_link(&home, "project", alpha.to_str().unwrap());
    let page = get(&state, &target);
    assert!(page.contains("RETAINED-ADV"), "{page}");
    assert!(
        page.contains("Open findings</div><div class=\"hero\">1</div>"),
        "{page}"
    );
}

#[test]
fn legacy_partial_checkpoint_keeps_findings_outside_its_last_input_folder() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let root = t.path().join("project");
    let mut old = scan(&state, &root);
    let scope = old["scan_scope"].clone();
    let mut other = scan(&state, &t.path().join("second-project"));
    let other_scope = other["scan_scope"].clone();
    for saved in [&mut old, &mut other] {
        let saved_scope = saved["scan_scope"].as_str().unwrap().to_owned();
        saved.as_object_mut().unwrap().remove("scan_roots");
        saved["coverage_evidence"] = json!({"status":"partial","observations":[{
            "kind":"supported-input","path":root.join("backend/package-lock.json")
        }]});
        Store::open(&state)
            .unwrap()
            .persist_assessment(&saved_scope, saved)
            .unwrap();
    }
    finding(&state, &root.join("backend"), &scope, "BACKEND-ADV");
    finding(&state, &root.join("frontend"), &scope, "FRONTEND-ADV");
    finding(&state, &root.join("backend"), &other_scope, "OTHER-ADV");
    let (snapshot, home, _) = pages(&state);
    let projects = snapshot["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 2, "{home}");
    let original = projects.iter().find(|p| p["scope"] == scope).unwrap();
    assert_eq!(original["open"], 2, "{home}");
    assert_eq!(original["urgent"], 2, "{home}");
    let sibling = projects.iter().find(|p| p["scope"] == other_scope).unwrap();
    assert_eq!(sibling["open"], 1);
    assert!(home.contains("Original scan root not recorded"));
    let page = get(
        &state,
        &finding_link(&home, "scope", scope.as_str().unwrap()),
    );
    assert!(
        page.contains("BACKEND-ADV") && page.contains("FRONTEND-ADV"),
        "{page}"
    );
    assert!(!page.contains("OTHER-ADV"), "{page}");
    assert!(
        page.contains("Open findings</div><div class=\"hero\">2</div>"),
        "{page}"
    );
}

#[test]
fn projects_in_one_scan_have_separate_finding_views() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let alpha = t.path().join("alpha");
    let beta = t.path().join("beta");
    let scan = scan_many(&state, &[alpha.as_path(), beta.as_path()]);
    finding(&state, &alpha, &scan["scan_scope"], "ALPHA-ADV");
    finding(&state, &beta, &scan["scan_scope"], "BETA-ADV");
    let (snapshot, _, _) = pages(&state);
    assert_eq!(snapshot["projects"].as_array().unwrap().len(), 2);
    assert_eq!(snapshot["projects"][0]["open"], 1);
    assert_eq!(snapshot["projects"][1]["open"], 1);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("scope", scan["scan_scope"].as_str().unwrap())
        .append_pair("project", alpha.to_str().unwrap())
        .finish();
    let page = get(&state, &format!("/findings?{query}"));
    assert!(page.contains("ALPHA-ADV"), "{page}");
    assert!(!page.contains("BETA-ADV"), "{page}");
    assert!(
        page.contains("Open findings</div><div class=\"hero\">1</div>"),
        "{page}"
    );
}

#[test]
fn clear_project_does_not_hide_open_sibling_and_project_links_filter_findings() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let root = t.path().join("open-project");
    let first = scan(&state, &root);
    finding(&state, &root, &first["scan_scope"], "SIBLING-ADV");
    let clear_root = t.path().join("clear-project");
    let clear = record_online_scan(&state, &[&clear_root], &[&clear_root], "no-known-findings");
    let (_, home, findings) = pages(&state);
    assert!(!home.contains("All clear"), "{home}");
    assert!(
        home.contains("1 open") && home.contains("clear-project"),
        "{home}"
    );
    let target = finding_link(&home, "project", root.to_str().unwrap());
    let project_page = get(&state, &target);
    assert!(project_page.contains("SIBLING-ADV"), "{project_page}");
    assert!(findings.contains("SIBLING-ADV"));
    let selected =
        std::collections::BTreeSet::from([clear["scan_scope"].as_str().unwrap().to_owned()]);
    let s = data::snapshot(&state, vorda::store::now(), Some(&selected)).unwrap();
    assert!(views::now_screen(&s).contains("All clear"));
    let filtered = views::render(&s, "findings", "", "all", "", "", false).unwrap();
    assert!(!filtered.contains("SIBLING-ADV"));
}

#[test]
fn scanning_two_projects_then_empty_keeps_all_projects_and_sums_findings() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let a = t.path().join("alpha");
    let b = t.path().join("beta");
    let first = scan(&state, &a);
    finding(&state, &a, &first["scan_scope"], "ALPHA-ADV");
    let second = scan(&state, &b);
    finding(&state, &b, &second["scan_scope"], "BETA-ADV");
    for empty in [false, true] {
        if empty {
            scan(&state, &t.path().join("empty"));
        }
        let (_, home, findings) = pages(&state);
        assert!(home.contains("alpha") && home.contains("beta"), "{home}");
        assert!(home.contains("2 open"), "{home}");
        assert!(!home.contains("No scans yet") && !home.contains("All clear"));
        assert!(
            findings.contains("ALPHA-ADV") && findings.contains("BETA-ADV"),
            "{findings}"
        );
        assert!(findings.contains("Open findings</div><div class=\"hero\">2</div>"));
    }
    scan(&state, &a);
    let (snapshot, _, _) = pages(&state);
    let projects = snapshot["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 3);
    let alpha = projects
        .iter()
        .find(|p| p["root"] == a.to_str().unwrap())
        .unwrap();
    assert_eq!(
        alpha["last"]["finished"],
        snapshot["hosts"][0]["last"]["finished"]
    );
    assert_eq!(alpha["open"], 1);
}

#[test]
fn no_scans_is_the_only_no_scans_state() {
    let t = tempfile::tempdir().unwrap();
    Store::open(t.path()).unwrap();
    assert!(pages(t.path()).1.contains("No scans yet"));
    scan(t.path(), &t.path().join("empty"));
    assert!(!pages(t.path()).1.contains("No scans yet"));
    let selection = std::collections::BTreeSet::from(["no-such-scope".to_owned()]);
    let selected = data::snapshot(t.path(), vorda::store::now(), Some(&selection)).unwrap();
    for screen in ["now", "hosts", "findings"] {
        let page = views::render(&selected, screen, "", "all", "", "", false).unwrap();
        assert!(!page.contains("No scans yet"), "{screen}: {page}");
        assert!(page.contains("No scans in this view"), "{screen}: {page}");
    }
}

#[test]
fn unknown_project_is_named_even_after_a_clear_project() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    scan(&state, &t.path().join("unknown-project"));
    let clear_root = t.path().join("clear-project");
    record_online_scan(&state, &[&clear_root], &[&clear_root], "no-known-findings");
    let (_, home, _) = pages(&state);
    assert!(
        home.contains("Can't confirm") && home.contains("unknown-project"),
        "{home}"
    );
    assert!(home.contains("clear-project"));
    assert!(!home.contains("All clear"));
    let target = finding_link(&home, "project", clear_root.to_str().unwrap());
    let page = get(&state, &target);
    assert!(page.contains("Nothing found"), "{page}");
}

#[test]
fn urgent_and_unknown_both_stay_in_the_headline() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("urgent-project");
    let s = scan(t.path(), &root);
    finding(t.path(), &root, &s["scan_scope"], "URGENT-ADV");
    let (_, home, _) = pages(t.path());
    assert!(home.contains("Can't confirm"));
    assert!(
        home.contains("<span class=\"label\">need you</span>"),
        "{home}"
    );
}

#[test]
fn agent_text_observations_count_as_open_on_both_pages() {
    let t = tempfile::tempdir().unwrap();
    Store::open(t.path())
        .unwrap()
        .reconcile(
            &[json!({"key":"text","kind":"skill",
        "evidence_basis":"static-text-pattern","item":"example","rule":"AB-P5",
        "title":"Agent text observation","path":"/tools/SKILL.md"})
            .as_object()
            .unwrap()
            .clone()],
            &Default::default(),
            &[],
        )
        .unwrap();
    let (_, home, findings) = pages(t.path());
    assert!(home.contains("0 urgent, 1 open"), "{home}");
    assert!(
        findings.contains("Open findings</div><div class=\"hero\">1</div>"),
        "{findings}"
    );
}

#[test]
fn hostile_and_missing_old_projects_remain_visible_and_escaped() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let root = t.path().join("<img src=x onerror=alert(1)>");
    scan(&state, &root);
    fs::remove_dir(&root).unwrap();
    let s = data::snapshot(&state, vorda::store::now() + 3. * 86400., None).unwrap();
    let home = views::now_screen(&s);
    assert!(home.contains("&lt;img"), "{home}");
    assert!(!home.contains("<img"));
    assert!(home.contains("Folder missing"), "{home}");
    assert!(home.contains("3 d") || home.contains("3d"), "{home}");
}

fn open_count(page: &str) -> usize {
    page.split("Open findings</div><div class=\"hero\">")
        .nth(1)
        .and_then(|rest| rest.split('<').next())
        .map_or(0, |n| n.parse().unwrap())
}

fn import_card<'a>(home: &'a str, scope: &Value) -> &'a str {
    let name = format!("Imported package list {}", &scope.as_str().unwrap()[..8]);
    home.split("<a class=\"row\"")
        .find(|row| row.contains(&name))
        .expect(home)
}

const LIST_LOCKFILE: &str = "/app/package-lock.json";

fn write_list(dir: &Path, file: &str, packages: &[(&str, &str)]) {
    let packages: Vec<_> = packages
        .iter()
        .map(|(name, version)| {
            json!({"name":name,"version":version,"ecosystem":"npm",
            "path":LIST_LOCKFILE,"scope":"runtime"})
        })
        .collect();
    fs::write(
        dir.join(file),
        json!({"status":"complete","observed":vorda::store::now(),
            "coverage":[{"status":"complete"}],"packages":packages})
        .to_string(),
    )
    .unwrap();
}

// A real offline `--inventory-file` scan, then saved as the online scan would be.
fn import_scan(state: &Path, dir: &Path, typed: &str, status: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .current_dir(dir)
        .arg("--state")
        .arg(state)
        .args(["scan", "--offline", "--json", "--inventory-file", typed])
        .output()
        .unwrap();
    let saved = serde_json::from_slice(&output.stdout).expect("scan output");
    mark_online(state, saved, status)["scan_scope"].clone()
}

fn import_finding(state: &Path, scope: &Value, (name, version): (&str, &str), advisory: &str) {
    Store::open(state)
        .unwrap()
        .reconcile(
            &[json!({
                "key":advisory,"host":vorda::store::hostname().unwrap(),
                "scan_scope":scope,"advisory":advisory,
                "asset":vorda::store::identity(&json!([LIST_LOCKFILE,"npm",name,version])).unwrap(),
                "package":{"name":name,"version":version,"ecosystem":"npm","path":LIST_LOCKFILE,
                    "scope":"reachable-unknown"},
                "priority":{"level":"high"}
            })
            .as_object()
            .unwrap()
            .clone()],
            &Default::default(),
            &[],
        )
        .unwrap();
}

#[test]
fn two_lists_naming_one_file_keep_their_own_findings() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    write_list(t.path(), "a.json", &[("is-number", "7.0.0")]);
    write_list(t.path(), "b.json", &[("lodash", "4.17.20")]);
    let clean = import_scan(&state, t.path(), "a.json", "no-known-findings");
    let vulnerable = import_scan(&state, t.path(), "b.json", "vulnerable");
    import_finding(&state, &vulnerable, ("lodash", "4.17.20"), "LODASH-ADV");
    let (_, home, _) = pages(&state);
    let card = import_card(&home, &clean);
    assert!(card.contains("Clear") && card.contains("0 open"), "{card}");
    let page = get(
        &state,
        &finding_link(&home, "scope", clean.as_str().unwrap()),
    );
    assert!(page.contains("Nothing found"), "{page}");
    let card = import_card(&home, &vulnerable);
    assert!(card.contains("Urgent") && card.contains("1 open"), "{card}");
    let page = get(
        &state,
        &finding_link(&home, "scope", vulnerable.as_str().unwrap()),
    );
    assert_eq!(open_count(&page), 1, "{page}");
}

#[test]
fn a_group_mixing_two_lists_packages_counts_only_each_cards_own() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    write_list(t.path(), "a.json", &[("is-number", "7.0.0")]);
    write_list(
        t.path(),
        "b.json",
        &[("lodash", "4.17.20"), ("is-number", "7.0.0")],
    );
    let one = import_scan(&state, t.path(), "a.json", "no-known-findings");
    let both = import_scan(&state, t.path(), "b.json", "vulnerable");
    import_finding(&state, &both, ("lodash", "4.17.20"), "LODASH-ADV");
    import_finding(&state, &both, ("is-number", "7.0.0"), "NUMBER-ADV");
    let (_, home, _) = pages(&state);
    for (scope, open) in [(&one, 1), (&both, 2)] {
        let card = import_card(&home, scope);
        assert!(card.contains(&format!(" {open} open")), "{card}");
        let page = get(
            &state,
            &finding_link(&home, "scope", scope.as_str().unwrap()),
        );
        assert_eq!(open_count(&page), open, "{page}");
    }
}

#[test]
fn container_image_packages_are_named_by_their_source() {
    let t = tempfile::tempdir().unwrap();
    let cwd = t.path().join("workdir");
    let mut saved = record_online_scan(t.path(), &[&cwd], &[], "no-known-findings");
    saved["packages"] = json!([{"name":"busybox","version":"1.36.1","ecosystem":"Alpine:v3.19",
        "path":"/images/app.tar","origin":"image"}]);
    let saved = mark_online(t.path(), saved, "no-known-findings");
    let (_, home, _) = pages(t.path());
    let short = &saved["scan_scope"].as_str().unwrap()[..8];
    assert!(home.contains(&format!("Container image {short}")), "{home}");
    assert!(!home.contains("Imported package list"), "{home}");
}

#[test]
fn one_package_list_imported_under_two_scopes_keeps_both_cards_true() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    write_list(t.path(), "sbom.json", &[("example", "1.0.0")]);
    let scopes: Vec<Value> = ["sbom.json", "./sbom.json"]
        .iter()
        .map(|typed| import_scan(&state, t.path(), typed, "vulnerable"))
        .collect();
    assert_ne!(scopes[0], scopes[1]);
    // The finding belongs to the newer scan only, as after a real re-check.
    import_finding(&state, &scopes[1], ("example", "1.0.0"), "TWICE-ADV");
    let (_, home, _) = pages(&state);
    for scope in &scopes {
        let card = import_card(&home, scope);
        assert!(card.contains("Urgent") && card.contains("1 open"), "{card}");
        let page = get(
            &state,
            &finding_link(&home, "scope", scope.as_str().unwrap()),
        );
        assert!(page.contains("known flaws"), "{page}");
        assert_eq!(open_count(&page), 1, "{page}");
    }
}

#[test]
fn imported_card_and_its_link_count_only_packages_outside_the_roots() {
    let t = tempfile::tempdir().unwrap();
    let (cwd, outside) = (t.path().join("workdir"), Path::new("/app"));
    let lockfile = outside.join("package-lock.json");
    let saved = record_online_scan(t.path(), &[&cwd], &[&cwd, outside], "vulnerable");
    let saved = also_lists(t.path(), saved, &lockfile, "OUT-ADV");
    finding(t.path(), &cwd, &saved["scan_scope"], "ROOT-ADV");
    finding_at(t.path(), &lockfile, &saved["scan_scope"], "OUT-ADV");
    let (_, home, _) = pages(t.path());
    let card = import_card(&home, &saved["scan_scope"]);
    assert!(card.contains("1 open"), "{card}");
    let page = get(
        t.path(),
        &finding_link(&home, "scope", saved["scan_scope"].as_str().unwrap()),
    );
    assert!(
        page.contains("OUT-ADV") && !page.contains("ROOT-ADV"),
        "{page}"
    );
    assert_eq!(open_count(&page), 1, "{page}");
}

#[test]
fn package_path_climbing_out_with_dot_dot_is_not_in_the_working_folder() {
    let t = tempfile::tempdir().unwrap();
    let cwd = t.path().join("workdir");
    let elsewhere = cwd.join("..").join("elsewhere");
    let saved = record_online_scan(t.path(), &[&cwd], &[&elsewhere], "no-known-findings");
    let (_, home, _) = pages(t.path());
    import_card(&home, &saved["scan_scope"]);
    assert!(!home.contains(cwd.to_str().unwrap()), "{home}");
}

// Each card judges every finding; that must stay cheap on a host with thousands of them.
#[test]
fn thousands_of_findings_across_lists_still_render_quickly() {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let host = vorda::store::hostname().unwrap();
    for list in 0..4 {
        let names: Vec<String> = (0..1000).map(|i| format!("pkg{list}-{i}")).collect();
        let packages: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "1.0.0")).collect();
        let file = format!("list{list}.json");
        write_list(t.path(), &file, &packages);
        let scope = import_scan(&state, t.path(), &file, "vulnerable");
        let findings: Vec<_> = names
            .iter()
            .map(|name| {
                json!({
                    "key":format!("ADV-{name}"),"host":host,"scan_scope":scope,"advisory":format!("ADV-{name}"),
                    "asset":vorda::store::identity(&json!([LIST_LOCKFILE,"npm",name,"1.0.0"])).unwrap(),
                    "package":{"name":name,"version":"1.0.0","ecosystem":"npm","path":LIST_LOCKFILE,
                        "scope":"reachable-unknown"},
                    "priority":{"level":"high"}
                })
                .as_object()
                .unwrap()
                .clone()
            })
            .collect();
        Store::open(&state)
            .unwrap()
            .reconcile(&findings, &Default::default(), &[])
            .unwrap();
    }
    let started = std::time::Instant::now();
    let snapshot = data::snapshot(&state, vorda::store::now(), None).unwrap();
    let took = started.elapsed();
    let projects = snapshot["projects"].as_array().unwrap();
    assert_eq!(projects.len(), 4);
    assert!(projects.iter().all(|p| p["open"] == 1000), "{projects:?}");
    eprintln!("snapshot of 4000 findings took {took:?}");
    // A debug build took about 38 s here before; about 3 s after, and about
    // twice that under a loaded test run, so the limit leaves room for slow CI.
    assert!(took.as_secs_f64() < 20., "snapshot took {took:?}");
}
