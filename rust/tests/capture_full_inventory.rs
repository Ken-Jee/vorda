//! Native capture records every package the scanner reads from each selected lockfile.
//! Observable through the CLI (`capture`, `capture-export`, `capture-attempt`, `inventory`) and the
//! saved-view reader. All inputs are synthetic.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::PathBuf, process::Command};
use vorda::{snapshot::read, store::capture::full_grant};

/// Documented per-capture package cap (docs/native-capture.md).
const CAP: usize = 1500;

struct Lane {
    tmp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
}
impl Lane {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        fs::create_dir(&root).unwrap();
        let state = tmp.path().join("state");
        Self { tmp, root, state }
    }
    fn put(&self, rel: &str, bytes: &str) {
        let path = self.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn request(&self, token: &str, inputs: &[&str]) -> Value {
        json!({"token":token,"binding":{"tenant":"t","site":"s","device":"dev-a","generation":"gen-1","scope":"scope-a","source":"npm-a"},"root":self.root,"inputs":inputs,"observed_at":"1793898285.4219873","completed_at":"1793898285.5764945"})
    }
    fn run(&self, request: &Value) -> std::process::Output {
        let path = self.tmp.path().join("request.json");
        fs::write(&path, request.to_string()).unwrap();
        Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(&self.state)
            .arg("capture")
            .arg(path)
            .output()
            .unwrap()
    }
    fn cap(&self, request: &Value) -> Value {
        let out = self.run(request);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    fn export(&self, outcome: &Value) -> Vec<u8> {
        let path = self.tmp.path().join("export.json");
        let result = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(&self.state)
            .arg("capture-export")
            .arg(outcome["snapshot_id"].as_str().unwrap())
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::read(path).unwrap()
    }
    /// The v1 scanner's view of the same tree: (ecosystem, name, version).
    fn scan(&self) -> BTreeSet<(String, String, String)> {
        let out = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(self.tmp.path().join("scan-state"))
            .args(["inventory", "--root"])
            .arg(&self.root)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        v["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(triple)
            .collect()
    }
}
fn triple(p: &Value) -> (String, String, String) {
    let s = |k: &str| p[k].as_str().unwrap().to_string();
    (s("ecosystem"), s("name"), s("version"))
}
fn snapshot(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
fn records(v: &Value) -> &Vec<Value> {
    v["records"].as_array().unwrap()
}
fn captured(v: &Value) -> BTreeSet<(String, String, String)> {
    records(v).iter().map(|r| triple(&r["package"])).collect()
}
fn list(bytes: &[u8]) -> Value {
    let v = snapshot(bytes);
    serde_json::to_value(
        read(
            bytes,
            full_grant(&v).to_string().as_bytes(),
            br#"{"op":"list"}"#,
            "1793898330",
        )
        .unwrap(),
    )
    .unwrap()
}
fn sha(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

/// A realistic synthetic npm v3 lockfile: scoped names, `dev`/`optional` flags, `resolved` and
/// `integrity` fields, a named root entry, nested copies of other packages at a different version,
/// and one nested copy of the same name and version (scanner reports it twice). Returns the text and
/// the number of distinct (name, version) pairs.
fn synthetic_npm_lock(n: usize) -> (String, usize) {
    let mut packages = serde_json::Map::new();
    packages.insert(
        "".into(),
        json!({"name":"synthetic-app","version":"1.0.0","dependencies":{"synthetic-pkg-0001":"^1.0.0"}}),
    );
    let name_of = |i: usize| {
        if i.is_multiple_of(7) {
            format!("@synthetic-scope/pkg-{i:04}")
        } else {
            format!("synthetic-pkg-{i:04}")
        }
    };
    let entry = |name: &str, version: &str, i: usize| {
        let integrity = format!(
            "sha512-{}{}",
            sha(&format!("{name}{version}")),
            &sha(&format!("{version}{name}"))[..24]
        );
        let mut e = json!({
            "version": version,
            "resolved": format!("https://registry.example.invalid/{name}/-/{}-{version}.tgz", name.rsplit('/').next().unwrap()),
            "integrity": integrity,
            "license": "MIT",
            "dependencies": {"synthetic-pkg-0001": "^1.0.0", "synthetic-pkg-0002": "~1.2.0"},
            "engines": {"node": ">=18"},
        });
        if i.is_multiple_of(5) {
            e["dev"] = json!(true);
        }
        if i.is_multiple_of(11) {
            e["optional"] = json!(true);
        }
        e
    };
    let mut distinct = BTreeSet::new();
    for i in 1..=n {
        let name = name_of(i);
        let version = format!("1.{}.{}", i % 50, i % 9);
        packages.insert(format!("node_modules/{name}"), entry(&name, &version, i));
        distinct.insert((name, version));
    }
    // Nested copies reuse existing names, so they must not add distinct pairs beyond the budget:
    // a same-name/same-version copy (deduplicated) and, only when there is room, none other.
    if n >= 100 {
        let name = name_of(100);
        let version = format!("1.{}.{}", 100 % 50, 100 % 9);
        packages.insert(
            format!("node_modules/synthetic-pkg-0001/node_modules/{name}"),
            entry(&name, &version, 100),
        );
    }
    let lock = json!({"name":"synthetic-app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":packages});
    (serde_json::to_string_pretty(&lock).unwrap(), distinct.len())
}

#[test]
fn full_npm_lockfile_records_every_package_the_scan_reports() {
    let l = Lane::new();
    let (text, distinct) = synthetic_npm_lock(CAP);
    assert_eq!(distinct, CAP);
    l.put("app/package-lock.json", &text);
    let out = l.cap(&l.request("t1", &["app/package-lock.json"]));
    assert_eq!(out["status"], "committed", "{out}");
    assert_eq!(out["coverage"]["inventory"]["state"], "complete");
    let bytes = l.export(&out);
    let v = snapshot(&bytes);
    assert_eq!(records(&v).len(), CAP);
    assert_eq!(captured(&v), l.scan(), "capture and v1 scan disagree");
    let unique = |k: &str| -> BTreeSet<String> {
        records(&v)
            .iter()
            .map(|r| r[k].as_str().unwrap().to_string())
            .collect()
    };
    let (ids, components, locations) = (
        unique("record_id"),
        unique("component_id"),
        unique("location_ref"),
    );
    assert_eq!(
        (ids.len(), components.len(), locations.len()),
        (CAP, CAP, CAP)
    );
    let listed = list(&bytes);
    let counts = &listed["counts"];
    assert_eq!(
        (counts["records"].as_u64(), counts["packages"].as_u64()),
        (Some(CAP as u64), Some(CAP as u64))
    );
    // Sizes the hub slices size their limits from.
    let artifact = v["retained_payload_utf8"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    eprintln!(
        "SIZES lockfile={} artifact={} export={}",
        text.len(),
        artifact.as_str().unwrap().len(),
        bytes.len()
    );
    assert!(bytes.len() <= 4 * 1024 * 1024);
}

#[test]
fn every_supported_lockfile_kind_matches_the_scan() {
    let l = Lane::new();
    let kinds: [(&str, &str); 14] = [
        ("npm1/package-lock.json", r#"{"lockfileVersion":1,"dependencies":{"synthetic-a":{"version":"1.0.0","dependencies":{"synthetic-b":{"version":"2.0.0"}}},"synthetic-c":{"version":"3.1.4","dev":true}}}"#),
        ("npm3/package-lock.json", r#"{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/synthetic-d":{"version":"1.0.0"},"node_modules/@synthetic/e":{"version":"0.2.0"}}}"#),
        ("yarn/yarn.lock", "synthetic-f@^1.0.0:\n  version \"1.2.3\"\n\n\"@synthetic/g@^2.0.0\":\n  version \"2.4.6\"\n"),
        ("pnpm/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  synthetic-h@1.0.0:\n    resolution: {integrity: synthetic}\n  '@synthetic/i@2.0.0':\n    resolution: {integrity: synthetic}\n"),
        ("bun/bun.lock", r#"{"lockfileVersion":1,"packages": {"synthetic-j": ["synthetic-j@1.1.1", "", {}, "synthetic"], "synthetic-k": ["synthetic-k@2.2.2", "", {}, "synthetic"]}}"#),
        ("poetry/poetry.lock", "[metadata]\nlock-version = \"2.0\"\n[[package]]\nname = \"synthetic-l\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"synthetic-m\"\nversion = \"2.0.0\"\n"),
        ("uv/uv.lock", "version = 1\n[[package]]\nname = \"synthetic-n\"\nversion = \"3.0.0\"\n\n[[package]]\nname = \"synthetic-o\"\nversion = \"4.0.0\"\n"),
        ("pipenv/Pipfile.lock", r#"{"_meta":{"pipfile-spec":6},"default":{"synthetic-p":{"version":"==1.0.0"}},"develop":{"synthetic-q":{"version":"==2.0.0"}}}"#),
        ("cargo/Cargo.lock", "version = 3\n[[package]]\nname = \"synthetic-r\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"synthetic-s\"\nversion = \"0.2.0\"\n"),
        ("go/go.sum", "example.invalid/synthetic/t v1.0.0 h1:aaa=\nexample.invalid/synthetic/t v1.0.0/go.mod h1:bbb=\nexample.invalid/synthetic/u v2.0.0 h1:ccc=\n"),
        ("ruby/Gemfile.lock", "GEM\n  remote: https://rubygems.example.invalid/\n  specs:\n    synthetic-v (1.0.0)\n    synthetic-w (2.0.0)\n\nPLATFORMS\n  ruby\n"),
        ("php/composer.lock", r#"{"packages":[{"name":"synthetic/x","version":"1.0.0"},{"name":"synthetic/y","version":"2.0.0"}]}"#),
        ("pip/requirements.txt", "synthetic-z==1.0.0\nsynthetic-zz==2.0.0  # pinned\n"),
        ("nuget/packages.lock.json", r#"{"version":1,"dependencies":{"net8.0":{"Synthetic.One":{"type":"Direct","requested":"[1.0.0, )","resolved":"1.0.0"},"Synthetic.Two":{"type":"Transitive","resolved":"2.0.0"}}}}"#),
    ];
    for (path, bytes) in kinds {
        l.put(path, bytes);
    }
    let inputs: Vec<&str> = kinds.iter().map(|k| k.0).collect();
    let out = l.cap(&l.request("kinds", &inputs));
    assert_eq!(out["status"], "committed", "{out}");
    let v = snapshot(&l.export(&out));
    let scanned = l.scan();
    assert_eq!(captured(&v), scanned);
    let ecosystems: BTreeSet<_> = scanned.iter().map(|t| t.0.as_str()).collect();
    for e in ["npm", "PyPI", "crates.io", "Go", "RubyGems", "NuGet"] {
        assert!(ecosystems.contains(e), "{e} missing from {ecosystems:?}");
    }
    // A committed capture means every selected input was read and parsed; the scan found at least
    // two packages in each of the 14 files, and the capture holds exactly those.
    assert!(scanned.len() >= 20, "{scanned:?}");
}

#[test]
fn recapture_replaces_only_the_selected_input_and_keeps_old_snapshots() {
    let l = Lane::new();
    let two = |a: &str, b: &str| {
        format!(
            r#"{{"lockfileVersion":3,"packages":{{"node_modules/{a}":{{"version":"1.0.0"}},"node_modules/{b}":{{"version":"1.0.0"}}}}}}"#
        )
    };
    l.put("a/package-lock.json", &two("synthetic-a1", "synthetic-a2"));
    l.put("b/package-lock.json", &two("synthetic-b1", "synthetic-b2"));
    let first = l.cap(&l.request("r1", &["a/package-lock.json", "b/package-lock.json"]));
    let first_bytes = l.export(&first);
    assert_eq!(records(&snapshot(&first_bytes)).len(), 4);

    // Only `a` is selected again, and it lost a package and gained one.
    l.put("a/package-lock.json", &two("synthetic-a1", "synthetic-a3"));
    let second = l.cap(&l.request("r2", &["a/package-lock.json"]));
    assert_eq!(second["revision"], 2);
    let v = snapshot(&l.export(&second));
    let names: BTreeSet<_> = captured(&v).into_iter().map(|t| t.1).collect();
    assert_eq!(
        names,
        BTreeSet::from(
            [
                "synthetic-a1",
                "synthetic-a3",
                "synthetic-b1",
                "synthetic-b2"
            ]
            .map(String::from)
        )
    );
    assert_eq!(
        l.export(&first),
        first_bytes,
        "an earlier snapshot is immutable"
    );
}

#[test]
fn a_package_over_the_cap_refuses_the_whole_capture_without_truncating() {
    let l = Lane::new();
    let (small, _) = synthetic_npm_lock(10);
    l.put("ok/package-lock.json", &small);
    let ok = l.cap(&l.request("base", &["ok/package-lock.json"]));
    let ok_bytes = l.export(&ok);

    let (big, distinct) = synthetic_npm_lock(CAP + 1);
    assert_eq!(distinct, CAP + 1);
    l.put("big/package-lock.json", &big);
    let r = l.request("over", &["big/package-lock.json"]);
    let out = l.cap(&r);
    assert_eq!(out["status"], "unsuccessful", "{out}");
    assert_eq!(out["coverage"], "unsupported");
    assert_eq!(out["inputs"][0]["error"], "capture_package_limit");
    assert!(out["inputs"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("1500"));
    assert_eq!(out["current_retained"], ok["snapshot_id"]);
    assert_eq!(l.cap(&r), out, "the refusal replays by token");
    assert_eq!(l.export(&ok), ok_bytes);
}

/// `n` distinct synthetic packages named from `from`.
fn flat_lock(from: usize, n: usize) -> String {
    let mut p = serde_json::Map::new();
    for i in from..from + n {
        p.insert(
            format!("node_modules/synthetic-s{i:04}"),
            json!({"version":"1.0.0"}),
        );
    }
    json!({"lockfileVersion":3,"packages":p}).to_string()
}

/// The retained artifact text may be large (the 1,500-package test reads one back); any other string
/// in a saved view is still bounded at 4096 bytes.
#[test]
fn only_the_retained_payload_may_exceed_the_reader_string_limit() {
    let l = Lane::new();
    l.put("a/package-lock.json", &flat_lock(0, 3));
    let out = l.cap(&l.request("small", &["a/package-lock.json"]));
    let mut v = snapshot(&l.export(&out));
    let grant = full_grant(&v);
    let query = br#"{"op":"list"}"#;
    let ask = |v: &Value| {
        read(
            v.to_string().as_bytes(),
            grant.to_string().as_bytes(),
            query,
            "1793898330",
        )
    };
    assert!(ask(&v).is_ok());
    v["records"][0]["package"]["name"] = json!("n".repeat(4097));
    assert!(ask(&v).is_err());
}

/// Within the package cap but too large for the 4 MiB saved view: refused by name, nothing stored.
#[test]
fn a_capture_too_large_for_the_saved_view_is_refused_by_name() {
    let l = Lane::new();
    let mut p = serde_json::Map::new();
    for i in 0..800 {
        p.insert(
            format!("node_modules/synthetic-w{i:04}"),
            json!({"version":"1.0.0","description":"x".repeat(4000)}),
        );
    }
    l.put(
        "big/package-lock.json",
        &json!({"lockfileVersion":3,"packages":p}).to_string(),
    );
    let out = l.run(&l.request("view-limit", &["big/package-lock.json"]));
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("capture_view_size_limit"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Nothing was stored: the next capture is the first revision and the refused token is unknown.
    l.put("ok/package-lock.json", &flat_lock(0, 2));
    let ok = l.cap(&l.request("after", &["ok/package-lock.json"]));
    assert_eq!(ok["revision"], 1);
    let attempt = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&l.state)
        .args(["capture-attempt", "view-limit"])
        .output()
        .unwrap();
    assert!(!attempt.status.success());
}

#[test]
fn the_cap_covers_everything_an_authority_currently_holds() {
    let l = Lane::new();
    l.put("a/package-lock.json", &flat_lock(0, 1000));
    let a = l.cap(&l.request("a", &["a/package-lock.json"]));
    assert_eq!(a["status"], "committed", "{a}");

    // 1,000 held + 501 new is over the cap even though each input is small.
    l.put("b/package-lock.json", &flat_lock(5000, 501));
    let over = l.cap(&l.request("b-over", &["b/package-lock.json"]));
    assert_eq!(over["status"], "unsuccessful", "{over}");
    assert_eq!(over["inputs"][0]["error"], "capture_package_limit");
    assert_eq!(over["current_retained"], a["snapshot_id"]);

    // 1,000 + 500 is exactly the cap.
    l.put("b/package-lock.json", &flat_lock(5000, 500));
    let b = l.cap(&l.request("b-ok", &["b/package-lock.json"]));
    assert_eq!(b["status"], "committed", "{b}");
    assert_eq!(records(&snapshot(&l.export(&b))).len(), CAP);

    // Re-selecting `a` replaces its 1,000 rows, so the count drops and the cap is not double counted.
    l.put("a/package-lock.json", &flat_lock(0, 1000));
    let again = l.cap(&l.request("a-again", &["a/package-lock.json"]));
    assert_eq!(again["status"], "committed", "{again}");
    assert_eq!(records(&snapshot(&l.export(&again))).len(), CAP);
}

#[test]
fn repeated_names_and_versions_follow_the_scan_and_keep_stable_components() {
    let l = Lane::new();
    // synthetic-x appears at two versions plus one nested copy of the same version; synthetic-y once.
    let lock = |y: &str| {
        format!(
            r#"{{"lockfileVersion":3,"packages":{{"node_modules/synthetic-x":{{"version":"1.0.0"}},"node_modules/synthetic-y":{{"version":"{y}"}},"node_modules/synthetic-y/node_modules/synthetic-x":{{"version":"2.0.0"}},"node_modules/other/node_modules/synthetic-x":{{"version":"1.0.0"}}}}}}"#
        )
    };
    l.put("app/package-lock.json", &lock("1.0.0"));
    let one = l.cap(&l.request("rep1", &["app/package-lock.json"]));
    let v1 = snapshot(&l.export(&one));
    assert_eq!(captured(&v1), l.scan());
    let x: Vec<_> = records(&v1)
        .iter()
        .filter(|r| r["package"]["name"] == "synthetic-x")
        .collect();
    assert_eq!(x.len(), 2, "one record per distinct version");
    assert_ne!(x[0]["component_id"], x[1]["component_id"]);
    let y1 = records(&v1)
        .iter()
        .find(|r| r["package"]["name"] == "synthetic-y")
        .unwrap()["component_id"]
        .clone();

    // A version change of a single-version package keeps its component.
    l.put("app/package-lock.json", &lock("1.1.0"));
    let two = l.cap(&l.request("rep2", &["app/package-lock.json"]));
    let v2 = snapshot(&l.export(&two));
    let y2 = records(&v2)
        .iter()
        .find(|r| r["package"]["name"] == "synthetic-y")
        .unwrap();
    assert_eq!(y2["component_id"], y1);
    assert_eq!(y2["package"]["version"], "1.1.0");
}

/// `n` distinct exact pins named from `from`, one per line.
fn dense_pins(from: usize, n: usize) -> String {
    (from..from + n)
        .map(|i| format!("p{i:06}==1.0\n"))
        .collect()
}

/// Selected lockfiles that are each within their own bound but together past the 4 MiB envelope are
/// refused by name with nothing stored, however many packages they hold.
#[test]
fn inputs_past_the_envelope_bound_in_total_are_refused_by_name() {
    let l = Lane::new();
    l.put("ok/package-lock.json", &flat_lock(0, 2));
    let ok = l.cap(&l.request("before", &["ok/package-lock.json"]));
    assert_eq!(ok["revision"], 1);
    let mut inputs = vec![];
    for i in 0..5 {
        // About 1 MiB each: five of them are over 4 MiB, and each is under the 4 MiB file bound.
        let path = format!("d{i}/requirements.txt");
        l.put(&path, &dense_pins(i * 80_000, 80_000));
        inputs.push(path);
    }
    let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let out = l.run(&l.request("envelope", &inputs));
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("capture_size_limit"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let attempt = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&l.state)
        .args(["capture-attempt", "envelope"])
        .output()
        .unwrap();
    assert!(!attempt.status.success(), "a refused envelope is not saved");
    let after = l.cap(&l.request("after", &["ok/package-lock.json"]));
    assert_eq!(after["revision"], 2);
}

/// A lockfile far over the package cap gets the saved, replayable `capture_package_limit` outcome,
/// not a storage-budget error from reserving room for every package it listed.
#[test]
fn a_lockfile_far_over_the_cap_is_a_package_limit_refusal_not_a_storage_error() {
    let l = Lane::new();
    // A small budget: room for the cap's worth of records, not for 20,000 times the per-package reserve.
    fs::create_dir_all(&l.state).unwrap();
    fs::write(
        l.state.join("storage-policy.json"),
        json!({"max_bytes": 40 * 1024 * 1024}).to_string(),
    )
    .unwrap();
    l.put("huge/requirements.txt", &dense_pins(0, 20_000));
    let r = l.request("huge", &["huge/requirements.txt"]);
    let out = l.cap(&r);
    assert_eq!(out["status"], "unsuccessful", "{out}");
    assert_eq!(out["inputs"][0]["error"], "capture_package_limit");
    assert_eq!(l.cap(&r), out, "the refusal replays by token");
}

#[test]
fn lockfiles_the_scanner_cannot_read_unambiguously_are_refused() {
    let l = Lane::new();
    l.put(
        "good/package-lock.json",
        r#"{"lockfileVersion":3,"packages":{"node_modules/synthetic-a":{"version":"1.0.0"}}}"#,
    );
    let base = l.cap(&l.request("base", &["good/package-lock.json"]));
    let base_bytes = l.export(&base);
    for (name, file, bytes, error) in [
        (
            "noversion",
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/synthetic-a":{"resolved":"x"}}}"#,
            "unsupported_input",
        ),
        (
            "dup",
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"node_modules/synthetic-a":{"version":"1","version":"2"}}}"#,
            "duplicate_input_key",
        ),
        (
            "empty",
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{}}"#,
            "unsupported_empty_input",
        ),
        (
            "badpin",
            "requirements.txt",
            "synthetic-a>=1.0\n",
            "unsupported_input",
        ),
        ("noparse", "poetry.lock", "\u{0}", "unsupported_input"),
    ] {
        l.put(&format!("{name}/{file}"), bytes);
        let out = l.cap(&l.request(name, &["good/package-lock.json", &format!("{name}/{file}")]));
        assert_eq!(out["status"], "unsuccessful", "{name}: {out}");
        // The code is the first word; the duplicate-key code is followed by the position.
        let code = out["inputs"][1]["error"].as_str().unwrap();
        assert_eq!(code.split(' ').next(), Some(error), "{name}: {out}");
        assert_eq!(l.export(&base), base_bytes);
    }
    // Names the scanner does not treat as lockfiles, and the binary bun lockfile, never reach the reader.
    for bad in [
        "good/package.json",
        "good/bun.lockb",
        "good/notes.txt",
        "good/requirements-dev.json",
    ] {
        l.put(bad, "{}");
        let out = l.run(&l.request("badname", &[bad]));
        assert!(!out.status.success(), "{bad} accepted");
    }
}
