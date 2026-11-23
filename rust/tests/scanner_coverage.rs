// What the scanner reads from each lockfile, and how it scores what it finds.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use vorda::{
    scanner::feeds::{KEV, OSV},
    store::{identity, now},
};

const DEAD: &str = "http://127.0.0.1:9";

fn inventory(files: &[(&str, &str)]) -> (i32, Value) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    for (name, text) in files {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(temp.path().join("state"))
        .args(["inventory", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn packages(data: &Value) -> Vec<String> {
    let mut list: Vec<String> = data["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| format!("{}:{}@{}", p["ecosystem"], p["name"], p["version"]).replace('"', ""))
        .collect();
    list.sort();
    list
}

fn complete(files: &[(&str, &str)], expected: &[&str]) {
    let (code, data) = inventory(files);
    assert_eq!(code, 0, "{data}");
    assert_eq!(data["status"], "complete", "{data}");
    assert_eq!(packages(&data), expected, "{data}");
}

fn write_cache(state: &Path, key: Value, url: &str, data: Value) {
    let cache = state.join("cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        cache.join(format!("{}.json", identity(&key).unwrap())),
        json!({"source_url":url,"checked":now(),"fetched_at":"fixture","data":data}).to_string(),
    )
    .unwrap();
}

/// Scan one lockfile with every feed answer served from a synthetic cache behind a dead
/// proxy: `package` is the query OSV receives, `selected` the detail filter, `records` the
/// advisories returned for it.
fn scan(
    lock: (&str, &str),
    package: (&str, &str, &str),
    selected: (&str, &str),
    records: &[Value],
) -> (i32, Value) {
    let temp = tempfile::tempdir().unwrap();
    let (root, state) = (temp.path().join("project"), temp.path().join("state"));
    fs::create_dir(&root).unwrap();
    fs::write(root.join(lock.0), lock.1).unwrap();
    let (ecosystem, name, version) = package;
    write_cache(
        &state,
        json!([KEV, null]),
        KEV,
        json!({"vulnerabilities":[]}),
    );
    let batch = format!("{OSV}/querybatch");
    write_cache(
        &state,
        json!([batch, {"queries":[{"package":{"name":name,"ecosystem":ecosystem},"version":version}]}]),
        &batch,
        json!({"results":[{"vulns":records.iter().map(|r| json!({"id":r["id"]})).collect::<Vec<_>>()}]}),
    );
    for record in records {
        let url = format!("{OSV}/vulns/{}", record["id"].as_str().unwrap());
        write_cache(
            &state,
            json!([url, null, [[selected.0, selected.1]]]),
            &url,
            record.clone(),
        );
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command.env("VORDA_ADVISORIES", "online");
    command
        .arg("--state")
        .arg(&state)
        .args(["scan", "--json", "--root"])
        .arg(&root);
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(var, DEAD);
    }
    let output = command
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn finding<'a>(data: &'a Value, advisory: &str) -> &'a Value {
    data["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["advisory"] == advisory)
        .unwrap_or_else(|| panic!("no {advisory}: {data}"))
}

#[test]
fn a_yarn_alias_is_checked_as_the_package_it_installs() {
    let v1 = "# yarn lockfile v1\n\n\"lodash-old@npm:lodash@4.17.20\":\n  version \"4.17.20\"\n\nscoped-alias@npm:@scope/real@1.0.0:\n  version \"1.0.0\"\n\nminimist@^1.2.8:\n  version \"1.2.8\"\n";
    let berry = "__metadata:\n  version: 8\n\n\"lodash-old@npm:lodash@4.17.20\":\n  version: 4.17.20\n  resolution: \"lodash@npm:4.17.20\"\n\n\"minimist@npm:^1.2.8\":\n  version: 1.2.8\n";
    complete(
        &[("yarn.lock", v1)],
        &[
            "npm:@scope/real@1.0.0",
            "npm:lodash@4.17.20",
            "npm:minimist@1.2.8",
        ],
    );
    complete(
        &[("yarn.lock", berry)],
        &["npm:lodash@4.17.20", "npm:minimist@1.2.8"],
    );
}

#[test]
fn a_triple_equals_python_pin_is_an_exact_version() {
    complete(
        &[("requirements.txt", "django===2.2\nsix==1.16.0\n")],
        &["PyPI:django@2.2", "PyPI:six@1.16.0"],
    );
    complete(
        &[(
            "Pipfile.lock",
            &json!({"_meta":{"pipfile-spec":6},"default":{"django":{"version":"===2.2"}}})
                .to_string(),
        )],
        &["PyPI:django@2.2"],
    );
}

#[test]
fn a_pypi_name_matches_its_advisory_under_any_spelling() {
    // pip freeze writes `Django`; OSV records it as `django`.
    let record = json!({"id":"GHSA-fixture-pypi-name","summary":"Synthetic finding","affected":[{"package":{"name":"django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.2.1"}]}]}]});
    let (code, data) = scan(
        ("requirements.txt", "Django==2.2\n"),
        ("PyPI", "Django", "2.2"),
        ("PyPI", "django"),
        &[record],
    );
    assert_eq!(code, 3, "{data}");
    assert_eq!(data["errors"], json!([]), "{data}");
    let f = finding(&data, "GHSA-fixture-pypi-name");
    assert_eq!(f["fixed"], json!(["2.2.1"]), "{f}");
    assert_eq!(f["package"]["name"], "Django", "{f}");
}

#[test]
fn cvss4_vectors_and_advisory_labels_set_the_priority() {
    let v4 = json!({"id":"GHSA-fixture-cvss4","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],"affected":[{"package":{"name":"lodash","ecosystem":"npm"}}]});
    let label = json!({"id":"GHSA-fixture-label","database_specific":{"severity":"MODERATE"},"affected":[{"package":{"name":"lodash","ecosystem":"npm"}}]});
    let lock =
        json!({"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}})
            .to_string();
    let (code, data) = scan(
        ("package-lock.json", &lock),
        ("npm", "lodash", "4.17.20"),
        ("npm", "lodash"),
        &[v4, label],
    );
    assert_eq!(code, 3, "{data}");
    let p = &finding(&data, "GHSA-fixture-cvss4")["priority"];
    assert_eq!(p["level"], "critical", "{p}");
    assert_eq!(p["cvss"], json!(9.3), "{p}");
    assert_eq!(p["scoring_reason"], "supported-cvss4", "{p}");
    let p = &finding(&data, "GHSA-fixture-label")["priority"];
    assert_eq!(p["level"], "medium", "{p}");
    assert_eq!(p["scoring_reason"], "advisory-severity-label", "{p}");
}

const GO_SUM: &str = "golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 h1:fixture=\ngolang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:fixture=\ngolang.org/x/crypto v0.17.0 h1:fixture=\ngolang.org/x/text v0.3.8 h1:fixture=\ngithub.com/new/name v1.2.0 h1:fixture=\n";

#[test]
fn go_mod_selects_module_versions_and_no_standard_library() {
    let module = "module example.com/demo\n\ngo 1.21\n\ntoolchain go1.21.5\n\nrequire (\n\tgolang.org/x/crypto v0.17.0\n\tgithub.com/old/name v1.0.0 // indirect\n)\n\nrequire golang.org/x/text v0.3.8\n\nreplace github.com/old/name => github.com/new/name v1.2.0\n";
    let expected = [
        "Go:github.com/new/name@v1.2.0",
        "Go:golang.org/x/crypto@v0.17.0",
        "Go:golang.org/x/text@v0.3.8",
    ];
    // go.sum also holds the crypto version go.mod no longer selects.
    complete(&[("go.mod", module), ("go.sum", GO_SUM)], &expected);
    // A module without go.sum is read from go.mod. Neither `go` nor `toolchain` names the Go
    // that builds it, so no `stdlib` package is listed (osv-scanner lists none either).
    complete(
        &[(
            "go.mod",
            "module m\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.8\n",
        )],
        &["Go:golang.org/x/text@v0.3.8"],
    );
}

#[test]
fn go_mod_that_cannot_list_the_whole_build_is_unknown() {
    let (code, data) = inventory(&[(
        "go.mod",
        "module m\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.8\n\nreplace golang.org/x/text => ../text\n",
    )]);
    assert_eq!(code, 2, "{data}");
    assert!(packages(&data).is_empty(), "{data}");
    assert!(
        data["errors"].to_string().contains("replace => ../text"),
        "{data}"
    );
    // Before Go 1.17 go.mod may omit indirect modules.
    let old = "module m\n\ngo 1.16\n\nrequire golang.org/x/text v0.3.8\n";
    let (code, data) = inventory(&[("go.mod", old)]);
    assert_eq!(code, 2, "{data}");
    assert!(data["errors"].to_string().contains("before 1.17"), "{data}");
    // With go.sum beside it, go.sum lists the build.
    let (code, data) = inventory(&[("go.mod", old), ("go.sum", GO_SUM)]);
    assert_eq!(code, 0, "{data}");
    assert_eq!(packages(&data).len(), 4, "{data}");
}

#[test]
fn toml_and_yaml_lockfiles_are_read_by_their_grammar_not_their_layout() {
    complete(
        &[(
            "Cargo.lock",
            "version = 4\n\n[[package]]\nname = 'good'\nversion = '1.2.3'\n",
        )],
        &["crates.io:good@1.2.3"],
    );
    complete(
        &[(
            "poetry.lock",
            "package = [{ name = \"demo\", version = \"1.2.3\" }]\n\n[metadata]\nlock-version = \"2.1\"\n",
        )],
        &["PyPI:demo@1.2.3"],
    );
    complete(
        &[(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages: {good@1.0.0: {resolution: {integrity: x}}}\n",
        )],
        &["npm:good@1.0.0"],
    );
    complete(
        &[(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n    good@1.0.0:\n        resolution: {integrity: x}\n    other@2.0.0:\n        resolution: {integrity: y}\n",
        )],
        &["npm:good@1.0.0", "npm:other@2.0.0"],
    );
}

fn unknown(files: &[(&str, &str)], detail: &str) -> Value {
    let (code, data) = inventory(files);
    assert_eq!(code, 2, "{data}");
    assert_eq!(data["status"], "unknown", "{data}");
    assert!(
        data["errors"].to_string().contains(detail),
        "{detail}: {data}"
    );
    data
}

#[test]
fn a_yarn_alias_without_a_version_is_checked_as_the_real_package() {
    // package.json `"lodash-old": "npm:lodash"`: yarn v1 writes no version in the header.
    complete(
        &[(
            "yarn.lock",
            "\"lodash-old@npm:lodash\":\n  version \"4.17.20\"\n",
        )],
        &["npm:lodash@4.17.20"],
    );
    complete(
        // Through a registry proxy whose URL path has a prefix.
        &[("yarn.lock", "\"trav@npm:@babel/traverse\":\n  version \"7.23.0\"\n  resolved \"https://host/artifactory/api/npm/npm-remote/@babel/traverse/-/traverse-7.23.0.tgz#x\"\n")],
        &["npm:@babel/traverse@7.23.0"],
    );
}

const GO_HEAD: &str = "module m\n\ngo 1.21\n\ntoolchain go1.21.5\n\n";

#[test]
fn go_mod_blocks_and_lines_are_read_or_refused_never_dropped() {
    let module = format!("{GO_HEAD}require(\n\tgolang.org/x/crypto v0.17.0\n)\n");
    complete(&[("go.mod", &module)], &["Go:golang.org/x/crypto@v0.17.0"]);
    for body in [
        "require golang.org/x/crypto\n",
        "require golang.org/x/crypto v0.17.0 extra\n",
        "frobnicate golang.org/x/crypto v0.17.0\n",
        "replace golang.org/x/crypto =>\n",
        "require (\n\tgolang.org/x/crypto v0.17.0\n",
    ] {
        unknown(&[("go.mod", &format!("{GO_HEAD}{body}"))], "go.mod");
    }
}

#[test]
fn a_version_specific_go_replace_wins_over_a_path_only_one() {
    let module = format!("{GO_HEAD}require golang.org/x/net v0.10.0\n\nreplace golang.org/x/net => golang.org/x/net v0.17.0\nreplace golang.org/x/net v0.10.0 => golang.org/x/net v0.1.0\n");
    complete(&[("go.mod", &module)], &["Go:golang.org/x/net@v0.1.0"]);
}

/// Inventory with the scan root set to `root`; state under `temp`.
fn scan_at(temp: &Path, root: &Path) -> (Option<i32>, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(temp.join("state"))
        .args(["inventory", "--root"])
        .arg(root)
        .output()
        .unwrap();
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    (output.status.code(), data)
}

const IN_WORKSPACE: &str = "inside a Go workspace";

/// A go.mod at `dir` that requires x/net.
fn go_module(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("go.mod"),
        format!("{GO_HEAD}require golang.org/x/net v0.17.0\n"),
    )
    .unwrap();
}

/// The scan's errors that name `module`'s go.mod.
fn module_errors(data: &Value, module: &Path) -> Vec<String> {
    let module = module.join("go.mod").display().to_string();
    serde_json::from_value::<Vec<String>>(data["errors"].clone())
        .unwrap()
        .into_iter()
        .filter(|e| e.contains(&module))
        .collect()
}

#[test]
fn a_go_module_inside_a_go_workspace_is_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    // go.work in the module's own folder, its parent, and its grandparent. Its text does not
    // matter: one that lists no module at all still makes the module unknown.
    let (same, parent, grand) = (root.join("same"), root.join("p/a"), root.join("g/a/b"));
    for module in [&same, &parent, &grand] {
        go_module(module);
    }
    fs::write(same.join("go.work"), "go 1.21\n\nuse ./other\n").unwrap();
    fs::write(root.join("p/go.work"), "go 1.21\n").unwrap();
    fs::write(root.join("g/go.work"), "").unwrap();
    let free = root.join("free");
    go_module(&free);
    let (code, data) = scan_at(temp.path(), &root);
    assert_eq!(code, Some(2), "{data}");
    for module in [&same, &parent, &grand] {
        let errors = module_errors(&data, module);
        assert!(
            errors.iter().any(|e| e.contains(IN_WORKSPACE)),
            "{}: {errors:?}",
            module.display()
        );
    }
    assert_eq!(module_errors(&data, &free), Vec::<String>::new());
    // A module with no go.work above it is still complete on its own.
    let (code, data) = scan_at(temp.path(), &free);
    assert_eq!(code, Some(0), "{data}");
    assert!(data["packages"].to_string().contains("v0.17.0"), "{data}");
    // A go.work above the scan root counts too, as cmd/go looks upward.
    let (code, data) = scan_at(temp.path(), &parent);
    assert_eq!(code, Some(2), "{data}");
    assert!(data["errors"].to_string().contains(IN_WORKSPACE), "{data}");
}

#[cfg(unix)]
#[test]
fn a_go_work_is_never_opened_so_any_entry_by_that_name_is_unknown() {
    let temp = tempfile::tempdir().unwrap();
    // A folder, a link to nowhere, and a link to itself: none can be read, all count.
    let folder = temp.path().join("folder");
    go_module(&folder.join("app"));
    fs::create_dir_all(folder.join("go.work")).unwrap();
    let dangling = temp.path().join("dangling");
    go_module(&dangling.join("app"));
    std::os::unix::fs::symlink(dangling.join("missing"), dangling.join("go.work")).unwrap();
    let looped = temp.path().join("looped");
    go_module(&looped.join("app"));
    std::os::unix::fs::symlink(looped.join("go.work"), looped.join("go.work")).unwrap();
    for dir in [folder, dangling, looped] {
        let start = std::time::Instant::now();
        let (code, data) = scan_at(temp.path(), &dir);
        assert!(start.elapsed().as_secs() < 10);
        assert_eq!(code, Some(2), "{data}");
        let errors = module_errors(&data, &dir.join("app"));
        assert!(
            errors.iter().any(|e| e.contains(IN_WORKSPACE)),
            "{}: {errors:?}",
            dir.display()
        );
    }
}

#[test]
fn replace_lines_do_not_count_as_go_mod_entries() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("app");
    fs::create_dir_all(&root).unwrap();
    let mut module = format!("{GO_HEAD}require (\n");
    for i in 0..15_000 {
        module.push_str(&format!("\texample.com/m{i} v1.0.0\n"));
    }
    module.push_str(")\n");
    for i in 0..5_002 {
        module.push_str(&format!(
            "replace example.com/r{i} => example.com/s{i} v1.0.0\n"
        ));
    }
    fs::write(root.join("go.mod"), module).unwrap();
    let (code, data) = scan_at(temp.path(), &root);
    assert_eq!(code, Some(0), "{}", data["errors"]);
    assert_eq!(data["packages"].as_array().unwrap().len(), 15_000);
}

#[test]
fn a_pre_117_module_read_through_go_sum_keeps_its_go_mod_problems() {
    unknown(
        &[
            ("go.mod", "module m\n\ngo 1.16\n\nrequire golang.org/x/text v0.3.8\n\nreplace example.com/lib => ../lib\nrequire example.com/lib v1.0.0\n"),
            ("go.sum", GO_SUM),
        ],
        "replace => ../lib",
    );
}

#[test]
fn oversized_or_deeply_nested_toml_and_yaml_are_unknown_before_parsing() {
    // A flat list of tiny values costs the parsers ~200 bytes each; refuse before parsing.
    let list = format!("[{}1]", "1,".repeat(3_100_000));
    let started = std::time::Instant::now();
    unknown(
        &[(
            "Cargo.lock",
            &format!(
                "version = 4\nx = {list}\n\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n"
            ),
        )],
        "too large",
    );
    let list = format!("[{}1]", "1,".repeat(5_000_000));
    unknown(
        &[(
            "pnpm-lock.yaml",
            &format!("lockfileVersion: '9.0'\nx: {list}\npackages:\n  good@1.0.0: {{}}\n"),
        )],
        "too large",
    );
    // pyproject.toml is weighed like a TOML lockfile.
    unknown(
        &[(
            "pyproject.toml",
            &format!("[tool.x]\ny = [{}{{}}]\n", "{},".repeat(500_000)),
        )],
        "pyproject.toml dependencies: too large",
    );
    assert!(started.elapsed().as_secs() < 30, "{:?}", started.elapsed());
    let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
    unknown(
        &[(
            "pnpm-lock.yaml",
            &format!("lockfileVersion: '9.0'\npackages:\n  good@1.0.0:\n    resolution: {deep}\n"),
        )],
        "nested",
    );
}

const PNPM: &str = "lockfileVersion: '9.0'\npackages:\n  good@1.0.0: {}\n";

#[test]
fn a_small_yaml_alias_is_read_and_quoted_stars_are_scalars() {
    complete(
        &[(
            "pnpm-lock.yaml",
            &format!("{PNPM}  other@2.0.0:\n    peerDependencies:\n      good: '*'\n      peer: workspace:*\na: &a [1]\nb: [*a, {{\"k\":*a}}]\n"),
        )],
        &["npm:good@1.0.0", "npm:other@2.0.0"],
    );
}

#[test]
fn a_yaml_alias_bomb_is_unknown_wherever_the_alias_sits() {
    // A 40 KB file whose aliases replay a 2,000-item list into gigabytes.
    let anchor = format!("a: &a [{}1]\n", "1,".repeat(1999));
    for alias in ["{\"k\":*a}", "*a"] {
        let replays = vec![alias; 4000].join(", ");
        let started = std::time::Instant::now();
        unknown(
            &[("pnpm-lock.yaml", &format!("{PNPM}{anchor}x: [{replays}]\n"))],
            "too large",
        );
        assert!(started.elapsed().as_secs() < 30, "{:?}", started.elapsed());
    }
}

#[test]
fn yaml_flow_pairs_and_tags_are_charged_as_they_are_built() {
    // Implicit flow pairs (`[a: , …]`) and tags make nodes from a few bytes each.
    for unit in ["a: , ", "!t a: !t , "] {
        let x = unit.repeat(700_000);
        unknown(
            &[("pnpm-lock.yaml", &format!("{PNPM}x: [{x}]\n"))],
            "parsing would hold over 768000000 bytes",
        );
    }
}

#[test]
fn yaml_directives_are_unknown_before_parsing() {
    // pnpm never writes directives, and the YAML parser checks each `%TAG` against all others.
    let tags: String = (0..20_000)
        .map(|i| format!("%TAG !h{i}! tag:x{i}.example,2000:\n"))
        .collect();
    let started = std::time::Instant::now();
    unknown(
        &[("pnpm-lock.yaml", &format!("{tags}---\n{PNPM}"))],
        "20000 directive lines",
    );
    assert!(started.elapsed().as_secs() < 5, "{:?}", started.elapsed());
    complete(
        &[(
            "pnpm-lock.yaml",
            &format!("%YAML 1.1\n%TAG !e! tag:e.example,2000:\n---\n{PNPM}"),
        )],
        &["npm:good@1.0.0"],
    );
}

#[test]
fn one_huge_toml_array_or_inline_table_is_unknown_before_parsing() {
    let lock = |x: &str| {
        format!("version = 4\nx = {x}\n\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n")
    };
    let keys = (0..20_000)
        .map(|i| format!("k{i} = 1"))
        .collect::<Vec<_>>()
        .join(", ");
    for x in [
        format!("{{{keys}}}"),
        format!("{{a = {{b = {{{keys}}}}}}}"),
        format!("[{}1]", "1, ".repeat(20_000)),
    ] {
        unknown(&[("Cargo.lock", &lock(&x))], "holds over 10000 items");
    }
    // Commas inside a string are not items.
    complete(
        &[(
            "Cargo.lock",
            &lock(&format!("[\"{}\", 'a,b']", ",".repeat(20_000))),
        )],
        &["crates.io:good@1.2.3"],
    );
}

#[test]
fn toml_dotted_keys_are_weighed_before_parsing() {
    let dotted: String = (0..13_000)
        .map(|i| format!("x{i}{} = 1\n", ".a".repeat(40)))
        .collect();
    unknown(
        &[(
            "Cargo.lock",
            &format!("version = 4\n{dotted}\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n"),
        )],
        "too large",
    );
}

#[test]
fn a_toml_or_yaml_lockfile_over_the_byte_limit_is_unknown() {
    const LIMIT: usize = 48_000_000;
    let lock = |len: usize| {
        let head = "lockfileVersion: '9.0'\npackages:\n  good@1.0.0: {}\n# ";
        format!("{head}{}\n", "x".repeat(len - head.len() - 1))
    };
    complete(&[("pnpm-lock.yaml", &lock(LIMIT))], &["npm:good@1.0.0"]);
    unknown(&[("pnpm-lock.yaml", &lock(LIMIT + 1))], "too large");
}

#[test]
fn cvss4_scores_use_base_metrics_only() {
    let base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    let p = vorda::scanner::priority::priority(
        &json!({"severity":[{"type":"CVSS_V4","score":format!("{base}/E:U")}]}),
    );
    assert_eq!(p["cvss"], json!(9.3), "{p}");
    assert_eq!(p["level"], "critical", "{p}");
    let junk = vorda::scanner::priority::priority(
        &json!({"severity":[{"type":"CVSS_V4","score":format!("{base}/XX:Y")}]}),
    );
    assert_ne!(junk["cvss"], json!(9.3), "{junk}");
}

#[test]
fn a_go_mod_may_start_with_a_byte_order_mark() {
    complete(
        &[(
            "go.mod",
            "\u{feff}module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n",
        )],
        &["Go:golang.org/x/text@v0.3.0"],
    );
}

#[test]
fn brackets_inside_toml_strings_are_not_nesting() {
    let text = format!(
        "version = 4\n\n[[package]]\nname = \"good\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\" # {}\n",
        "[".repeat(70),
        "{".repeat(70)
    );
    complete(&[("Cargo.lock", &text)], &["crates.io:good@1.2.3"]);
}

fn npm_workspaces(globs: &[String], members: &[String]) -> String {
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({ "workspaces": globs }));
    for member in members {
        packages.insert(member.clone(), json!({ "name": member.replace('/', "-") }));
    }
    packages.insert("node_modules/good".into(), json!({ "version": "1.2.3" }));
    json!({ "lockfileVersion": 3, "packages": packages }).to_string()
}

#[test]
fn npm_workspace_patterns_past_the_bound_are_unknown_not_matched_key_by_key() {
    let wild = |n: usize| (0..n).map(|i| format!("g{i}/*")).collect::<Vec<_>>();
    let members = ["w/a".to_string()];
    let mut ok = wild(127);
    ok.push("w/*".into());
    // Repeats and exact folder names are not wildcard patterns to compare against.
    ok.extend(std::iter::repeat_n("w/*".to_string(), 5_000));
    ok.extend((0..5_000).map(|i| format!("lib/p{i}")));
    complete(
        &[("package-lock.json", &npm_workspaces(&ok, &members))],
        &["npm:good@1.2.3"],
    );
    let mut over = wild(128);
    over.push("w/*".into());
    unknown(
        &[("package-lock.json", &npm_workspaces(&over, &members))],
        "more than 128 wildcard patterns",
    );
    let deep = [format!("{}*", "a/".repeat(16)), "w/*".into()];
    unknown(
        &[("package-lock.json", &npm_workspaces(&deep, &members))],
        "longer than 16 folders",
    );
}

#[test]
fn npm_workspace_members_count_toward_the_per_input_cap() {
    let globs = ["w/*".to_string()];
    let members = |n: usize| (0..n).map(|i| format!("w/m{i}")).collect::<Vec<_>>();
    complete(
        &[(
            "package-lock.json",
            &npm_workspaces(&globs, &members(19_998)),
        )],
        &["npm:good@1.2.3"],
    );
    unknown(
        &[(
            "package-lock.json",
            &npm_workspaces(&globs, &members(20_000)),
        )],
        "per-input cap",
    );
}

#[test]
fn npm_workspace_folder_names_count_toward_the_per_input_cap() {
    let names = |n: usize| (0..n).map(|i| format!("p{i}")).collect::<Vec<_>>();
    let mut excludes = names(10_000);
    excludes.extend((0..10_001).map(|i| format!("!x{i}")));
    complete(
        &[("package-lock.json", &npm_workspaces(&names(20_000), &[]))],
        &["npm:good@1.2.3"],
    );
    for globs in [names(20_001), excludes] {
        unknown(
            &[("package-lock.json", &npm_workspaces(&globs, &[]))],
            "folder names than the per-input cap",
        );
    }
}

const CLEAN_LOCK: &str =
    r#"{"lockfileVersion":3,"packages":{"node_modules/good":{"version":"1.2.3"}}}"#;

#[test]
fn other_dependency_files_are_named_in_any_letter_case() {
    for name in [
        "Pom.xml",
        "Gopkg.lock",
        "paket.lock",
        "Package.swift",
        "conan.lock",
        "vcpkg.json",
        "ivy.xml",
        "Chart.lock",
        "tool.gemspec",
    ] {
        unknown(&[("package-lock.json", CLEAN_LOCK), (name, "x")], name);
    }
    // A gem's spec is read through the Gemfile.lock bundler writes for it.
    complete(
        &[
            ("package-lock.json", CLEAN_LOCK),
            ("tool.gemspec", "x"),
            ("Gemfile", "source 'https://rubygems.org'\ngemspec\n"),
            (
                "Gemfile.lock",
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n",
            ),
        ],
        &["RubyGems:rake@13.0.6", "npm:good@1.2.3"],
    );
}

#[test]
fn each_gem_version_is_listed_once_whatever_its_platform_builds() {
    complete(
        &[(
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.10-arm64-darwin)\n      racc (~> 1.4)\n    nokogiri (1.13.10-x86_64-linux-musl)\n      racc (~> 1.4)\n    nokogiri (1.13.10)\n      racc (~> 1.4)\n    racc (1.6.2-java)\n\nPLATFORMS\n  arm64-darwin\n  java\n  ruby\n  x86_64-linux-musl\n\nDEPENDENCIES\n  nokogiri\n",
        )],
        &["RubyGems:nokogiri@1.13.10", "RubyGems:racc@1.6.2"],
    );
}

#[test]
fn a_lockfile_that_declares_no_dependencies_is_a_complete_scan() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"empty","version":"1.0.0"}}}"#,
    )
    .unwrap();
    fs::write(
        root.join("package.json"),
        r#"{"name":"empty","version":"1.0.0","scripts":{"test":"true"}}"#,
    )
    .unwrap();
    let state = temp.path().join("state");
    write_cache(
        &state,
        json!([KEV, null]),
        KEV,
        json!({"vulnerabilities":[]}),
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command.env("VORDA_ADVISORIES", "online");
    command
        .arg("--state")
        .arg(&state)
        .args(["scan", "--root"])
        .arg(&root);
    for var in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        command.env(var, DEAD);
    }
    let output = command
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stderr.contains("declare no dependencies"), "{stderr}");
    // An empty folder has nothing to read: no packages, no errors, and no completed lockfile.
    let (code, data) = inventory(&[] as &[(&str, &str)]);
    assert_eq!(code, 0, "{data}");
    assert_eq!(data["errors"], json!([]), "{data}");
    assert_eq!(data["completed_paths"], json!([]), "{data}");
}

#[test]
fn an_empty_lockfile_is_complete_only_beside_a_manifest_that_declares_nothing() {
    let crate_only = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n";
    let bare_npm = r#"{"name":"x","version":"1.0.0"}"#;
    let root_only = r#"{"lockfileVersion":3,"packages":{"":{"name":"x"}}}"#;
    let yarn1 = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n";
    let pnpm = "lockfileVersion: '9.0'\nimporters:\n  .: {}\n";
    for files in [
        vec![("Cargo.toml", crate_only), ("Cargo.lock", "version = 4\n")],
        vec![("package.json", bare_npm), ("package-lock.json", root_only)],
        vec![("package.json", bare_npm), ("yarn.lock", yarn1)],
        vec![("package.json", bare_npm), ("pnpm-lock.yaml", pnpm)],
        vec![("requirements.txt", "# nothing yet\n\n")],
    ] {
        let (code, data) = inventory(&files);
        assert_eq!(code, 0, "{data}");
        assert_eq!(data["status"], "complete", "{data}");
        assert_eq!(data["packages"], json!([]), "{data}");
    }
    let cargo = format!("{crate_only}[dependencies]\nserde = \"1\"\n");
    let npm = r#"{"name":"x","dependencies":{"lodash":"^4.17.0"}}"#;
    let berry = "__metadata:\n  version: 8\n  cacheKey: 10\n";
    for (files, detail) in [
        (
            vec![("Cargo.toml", cargo.as_str()), ("Cargo.lock", "")],
            "Cargo.lock is empty",
        ),
        (
            vec![
                ("Cargo.toml", cargo.as_str()),
                ("Cargo.lock", "version = 4\n"),
            ],
            "Cargo.toml declares dependencies but Cargo.lock lists none",
        ),
        (
            vec![
                (
                    "Cargo.toml",
                    "[package]\nname = \"x\"\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
                ),
                ("Cargo.lock", "version = 4\n"),
            ],
            "Cargo.toml declares dependencies but Cargo.lock lists none",
        ),
        (
            vec![("package.json", npm), ("yarn.lock", "")],
            "yarn.lock is empty",
        ),
        (
            vec![("package.json", npm), ("yarn.lock", yarn1)],
            "package.json declares dependencies but yarn.lock lists none",
        ),
        (
            vec![("package.json", npm), ("yarn.lock", berry)],
            "package.json declares dependencies but yarn.lock lists none",
        ),
        (
            vec![("package.json", npm), ("package-lock.json", root_only)],
            "package.json declares dependencies but package-lock.json lists none",
        ),
        (
            vec![
                (
                    "package.json",
                    r#"{"name":"x","workspaces":["packages/*"]}"#,
                ),
                ("package-lock.json", root_only),
            ],
            "package.json declares dependencies but package-lock.json lists none",
        ),
        (
            vec![("package.json", npm), ("pnpm-lock.yaml", pnpm)],
            "package.json declares dependencies but pnpm-lock.yaml lists none",
        ),
        (
            vec![("package-lock.json", root_only)],
            "package-lock.json lists no packages and there is no readable package.json beside it",
        ),
        (
            vec![
                ("package.json", "{not json"),
                ("package-lock.json", root_only),
            ],
            "package-lock.json lists no packages and there is no readable package.json beside it",
        ),
        (
            vec![("main.go", "package main\n"), ("go.sum", "")],
            "go.sum is empty",
        ),
        (vec![("requirements.txt", "")], "requirements.txt is empty"),
    ] {
        unknown(&files, detail);
    }
}

#[test]
fn each_manifest_kind_decides_whether_an_empty_lockfile_beside_it_is_complete() {
    let pep621 = "[project]\nname = \"x\"\nversion = \"0.1.0\"\n";
    let poetry = "[tool.poetry]\nname = \"x\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.9\"\n";
    let pipfile = "[[source]]\nurl = \"https://pypi.org/simple\"\nname = \"pypi\"\n\n[requires]\npython_version = \"3.12\"\n\n[packages]\n\n[dev-packages]\n";
    let composer = r#"{"name":"x/y","require":{"php":">=8.1","ext-json":"*"}}"#;
    let gemfile = "source \"https://rubygems.org\"\nruby \"3.3.0\"\n";
    let uv_lock = "version = 1\npackage = []\n";
    let poetry_lock = "package = []\n[metadata]\nlock-version = \"2.1\"\n";
    let pipfile_lock = r#"{"_meta":{"hash":{"sha256":"x"},"pipfile-spec":6,"requires":{},"sources":[]},"default":{},"develop":{}}"#;
    let composer_lock = r#"{"packages":[],"packages-dev":[]}"#;
    let gemfile_lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n\nBUNDLED WITH\n   2.4.10\n";
    let go116 = "module x\n\ngo 1.16\n";
    for files in [
        vec![("pyproject.toml", pep621), ("uv.lock", uv_lock)],
        vec![("pyproject.toml", poetry), ("poetry.lock", poetry_lock)],
        vec![("Pipfile", pipfile), ("Pipfile.lock", pipfile_lock)],
        vec![
            ("composer.json", composer),
            ("composer.lock", composer_lock),
        ],
        vec![("Gemfile", gemfile), ("Gemfile.lock", gemfile_lock)],
        vec![("go.mod", "module x\n"), ("go.sum", "")],
    ] {
        complete(&files, &[]);
    }
    complete(&[("go.mod", go116), ("go.sum", "")], &[]);
    let go116_req = format!("{go116}\nrequire example.com/a v1.0.0\n");
    complete(
        &[
            ("go.mod", go116_req.as_str()),
            (
                "go.sum",
                "example.com/a v1.0.0 h1:AAAA=\nexample.com/a v1.0.0/go.mod h1:BBBB=\n",
            ),
        ],
        &["Go:example.com/a@v1.0.0"],
    );
    let pep621_deps = format!("{pep621}dependencies = [\"requests\"]\n");
    let poetry_deps = format!("{poetry}requests = \"*\"\n");
    let declares = |manifest: &str, lock: &str| {
        format!("{manifest} declares dependencies but {lock} lists none")
    };
    let go_none = "go.mod requires modules but go.sum lists none";
    for (files, detail) in [
        (
            vec![
                ("pyproject.toml", pep621_deps.as_str()),
                ("uv.lock", uv_lock),
            ],
            declares("pyproject.toml", "uv.lock"),
        ),
        (
            vec![
                ("pyproject.toml", poetry_deps.as_str()),
                ("poetry.lock", poetry_lock),
            ],
            declares("pyproject.toml", "poetry.lock"),
        ),
        (
            vec![
                ("Pipfile", "[packages]\nrequests = \"*\"\n"),
                ("Pipfile.lock", pipfile_lock),
            ],
            declares("Pipfile", "Pipfile.lock"),
        ),
        (
            vec![
                ("composer.json", r#"{"require":{"monolog/monolog":"^3"}}"#),
                ("composer.lock", composer_lock),
            ],
            declares("composer.json", "composer.lock"),
        ),
        (
            vec![
                (
                    "Gemfile",
                    "source \"https://rubygems.org\"\ngem \"rails\"\n",
                ),
                ("Gemfile.lock", gemfile_lock),
            ],
            declares("Gemfile", "Gemfile.lock"),
        ),
        (
            vec![
                ("go.mod", "module x\n\nrequire example.com/a v1.0.0\n"),
                ("go.sum", ""),
            ],
            go_none.into(),
        ),
        (
            vec![("go.mod", go116_req.as_str()), ("go.sum", "")],
            go_none.into(),
        ),
        (
            vec![("go.mod", go116_req.as_str()), ("go.sum", "\n\n")],
            go_none.into(),
        ),
    ] {
        unknown(&files, &detail);
    }
}

#[test]
fn a_requirements_file_with_only_options_is_unknown() {
    for text in [
        "-c constraints.txt\n",
        "--index-url https://example.invalid/simple\n",
        "--find-links ./wheels\n",
        "--hash=sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
    ] {
        unknown(&[("requirements.txt", text)], "no readable package entries");
    }
}

#[test]
fn a_requirements_file_may_start_with_a_byte_order_mark() {
    complete(
        &[("requirements.txt", "\u{feff}django==2.2.0\n")],
        &["PyPI:django@2.2.0"],
    );
}

#[cfg(unix)]
#[test]
fn a_linked_folder_is_unknown_unless_its_target_is_read_inside_the_root() {
    let temp = tempfile::tempdir().unwrap();
    let (root, outside) = (temp.path().join("project"), temp.path().join("outside"));
    for dir in [
        root.join("real"),
        root.join("node_modules/pkg"),
        outside.clone(),
    ] {
        fs::create_dir_all(dir).unwrap();
    }
    fs::write(root.join("package-lock.json"), CLEAN_LOCK).unwrap();
    let run = || {
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(temp.path().join("state"))
            .args(["inventory", "--root"])
            .arg(&root)
            .output()
            .unwrap();
        let data: Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.code().unwrap(), data)
    };
    std::os::unix::fs::symlink(root.join("real"), root.join("docs")).unwrap();
    let (code, data) = run();
    assert_eq!((code, &data["status"]), (0, &json!("complete")), "{data}");
    assert!(
        data["warnings"].to_string().contains("is read there"),
        "{data}"
    );
    let stderr = || {
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(temp.path().join("state"))
            .args(["inventory", "--root"])
            .arg(&root)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    // Several harmless skips are one terminal line; --json still lists each.
    std::os::unix::fs::symlink(root.join("real"), root.join("more")).unwrap();
    let text = stderr();
    assert_eq!(text.matches("Warning:").count(), 1, "{text}");
    assert!(
        !text.contains("docs") && text.contains("Skipped 2 symlinked folders"),
        "{text}"
    );
    fs::remove_file(root.join("more")).unwrap();
    fs::remove_file(root.join("docs")).unwrap();
    // Warnings printed to the terminal show invisible characters as `?`.
    let hidden = root.join("l\u{202E}k");
    std::os::unix::fs::symlink(root.join("real"), &hidden).unwrap();
    let stderr = stderr();
    assert!(
        stderr.contains("Warning: ") && stderr.contains("l?k"),
        "{stderr}"
    );
    assert!(!stderr.contains('\u{202E}'), "{stderr}");
    fs::remove_file(hidden).unwrap();
    for (link, target) in [
        ("ext", outside.clone()),
        ("dep", root.join("node_modules/pkg")),
    ] {
        std::os::unix::fs::symlink(target, root.join(link)).unwrap();
        let (code, data) = run();
        assert_eq!(code, 2, "{data}");
        assert!(
            data["errors"]
                .to_string()
                .contains(&format!("{link}: skipped symlink directory")),
            "{data}"
        );
        fs::remove_file(root.join(link)).unwrap();
    }
}

#[test]
fn a_go_standard_library_fix_moves_the_toolchain() {
    let temp = tempfile::tempdir().unwrap();
    let store = vorda::store::Store::open(temp.path()).unwrap();
    let finding = |name: &str, version: &str, fixed: &str| {
        json!({"asset":name,"package":{"ecosystem":"Go","name":name,"version":version,"path":"/p/go.mod"},
            "fixed":[fixed],"affected_ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":fixed}]}]})
    };
    for f in [
        finding("stdlib", "1.21.0", "1.21.6"),
        finding("golang.org/x/text", "v0.3.0", "0.3.8"),
    ] {
        store
            .db
            .execute(
                "INSERT INTO findings VALUES(?1,?2,1)",
                (f["asset"].as_str().unwrap(), f.to_string()),
            )
            .unwrap();
    }
    let commands = vorda::surfaces::advice::fix_commands(&store)
        .unwrap()
        .to_string();
    assert!(commands.contains("go get toolchain@go1.21.6"), "{commands}");
    assert!(!commands.contains("stdlib@"), "{commands}");
    assert!(
        commands.contains("go get golang.org/x/text@v0.3.8"),
        "{commands}"
    );
}

const PYLOCK: &str = "lock-version = \"1.0\"\ncreated-by = \"uv\"\n\n[[packages]]\nname = \"django\"\nversion = \"2.2.0\"\nmarker = \"python_version >= '3.8'\"\nsdist = { url = \"https://files.pythonhosted.org/django-2.2.0.tar.gz\", hashes = { sha256 = \"00\" } }\n\n[[packages]]\nname = \"app\"\ndirectory = { path = \".\", editable = true }\n";

#[test]
fn a_pylock_lists_its_registry_packages_and_skips_the_project_folder() {
    complete(&[("pylock.toml", PYLOCK)], &["PyPI:django@2.2.0"]);
    complete(&[("pylock.dev.toml", PYLOCK)], &["PyPI:django@2.2.0"]);
    // An empty pylock has no manifest beside it to show the project declares nothing.
    unknown(
        &[("pylock.toml", "lock-version = \"1.0\"\npackages = []\n")],
        "lists no packages",
    );
}

#[test]
fn a_pylock_entry_from_vcs_an_archive_or_outside_the_project_is_not_checked() {
    for (source, shown) in [
        ("vcs = { type = \"git\", url = \"https://example.invalid/x.git\", commit-id = \"ab\" }", "vcs"),
        ("archive = { url = \"https://example.invalid/x.tar.gz\", hashes = { sha256 = \"00\" } }", "archive"),
        ("directory = { path = \"../x\" }", "file:../x"),
    ] {
        let text = format!("{PYLOCK}\n[[packages]]\nname = \"x\"\nversion = \"1.0\"\n{source}\n");
        let data = unknown(&[("pylock.toml", &text)], "Uncheckable package entry");
        assert_eq!(packages(&data), ["PyPI:django@2.2.0"], "{data}");
        assert!(data["errors"].to_string().contains(shown), "{data}");
    }
}

#[test]
fn a_pylock_with_an_unknown_lock_version_is_not_read() {
    unknown(
        &[("pylock.toml", "lock-version = \"2.0\"\npackages = []\n")],
        "unsupported lock-version",
    );
    unknown(
        &[("pylock.toml", "packages = []\n")],
        "missing lock-version",
    );
    // Another letter case is named as unread, not silently ignored.
    unknown(&[("Pylock.toml", PYLOCK)], "Pylock.toml");
}

#[test]
fn files_in_a_requirements_folder_are_read_like_requirements_txt() {
    complete(
        &[
            ("requirements/base.txt", "django==2.2.0\n"),
            (
                "requirements/dev/test.txt",
                "--index-url https://example.invalid/simple\npytest==7.0.0  # tests\n",
            ),
            ("requirements/README.txt", "Pinned files live here.\n"),
        ],
        &["PyPI:django@2.2.0", "PyPI:pytest@7.0.0"],
    );
    unknown(
        &[("requirements/base.txt", "django==2.2.0\nhttpx>=0.27\n")],
        "uv pip compile base.txt",
    );
}

#[test]
fn a_requirements_in_without_a_compiled_file_is_read_for_its_pins() {
    complete(
        &[("requirements.in", "django==2.2.0\n")],
        &["PyPI:django@2.2.0"],
    );
    let data = unknown(
        &[("requirements.in", "django==2.2.0\nhttpx\n")],
        "uv pip compile requirements.in",
    );
    assert_eq!(packages(&data), ["PyPI:django@2.2.0"], "{data}");
    // A compiled file beside the input is read instead: its .txt, or a pylock that lists
    // every package the input names.
    complete(
        &[
            ("requirements.in", "Django>=2.2  # web\n"),
            ("pylock.toml", PYLOCK),
        ],
        &["PyPI:django@2.2.0"],
    );
    for input in ["httpx\n", "django\nhttpx\n", "-r base.in\ndjango\n"] {
        unknown(
            &[("requirements.in", input), ("pylock.toml", PYLOCK)],
            "requirements.in",
        );
    }
    complete(
        &[
            ("requirements/base.in", "httpx\n"),
            ("requirements/base.txt", "httpx==0.27.0\n"),
        ],
        &["PyPI:httpx@0.27.0"],
    );
}
