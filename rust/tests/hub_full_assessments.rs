//! The hub admits what the device capture now produces: every package of every selected lockfile,
//! up to 1,500 packages in one assessment. Driven over real sockets (`POST /v2/batches` with the
//! device credential, `POST /v2/read/...` for the readers) against schema 2 and schema 3 hubs, with
//! requests made by the real device capture path. Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use vorda::{
    link::{
        grants::CaptureGrants,
        native::{validate_ack, Admission, TrustedCapture},
        server::Server,
        storage::Hub,
    },
    store::{capture, now, Store},
};

/// The packages a full assessment can hold (also the device's cap).
const CAP: usize = 1500;
const V2_TABLES: [&str; 9] = [
    "v2_authorities",
    "v2_assessments",
    "v2_observations",
    "v2_current",
    "v2_coverage",
    "v2_deliveries",
    "v2_views",
    "v2_changes",
    "v2_change_state",
];

fn delivery(w: &World) -> Delivery<'_> {
    Delivery {
        device: &w.a1,
        org: ORG,
        site: "site-a",
        scope: "scope-1",
        source: "npm-a",
        observed: Some(now() - 60.0),
        inputs: &["one"],
    }
}
fn trusted(request: &(Value, String, String, Vec<u8>)) -> TrustedCapture {
    TrustedCapture {
        binding: request.0.clone(),
        evidence_id: request.1.clone(),
        artifact_utf8: request.2.clone(),
    }
}
fn serving<R>(w: &World, captures: Vec<TrustedCapture>, run: impl FnOnce(SocketAddr) -> R) -> R {
    let server = Server::bind(Hub::open(&w.db).unwrap(), "127.0.0.1", 0, None, None).unwrap();
    let addr = server.local_addr().unwrap();
    // An unoptimised build parses a full assessment slower than the one-second budget a hub
    // serves with; the budget itself is measured with `perf_hub` on a release build.
    // The operator granted the device and source of each capture, as `capture-allow` does.
    for c in &captures {
        CaptureGrants::allow(
            &w.db,
            c.binding["device"].as_str().unwrap(),
            c.binding["source"].as_str().unwrap(),
        )
        .unwrap();
    }
    let granting = !captures.is_empty();
    let mut admission = Admission::open(&w.db, captures).unwrap();
    if granting {
        admission = admission.with_grants(CaptureGrants::open(&w.db).unwrap());
    }
    let admission = admission.with_budget(Duration::from_secs(30));
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let started = Instant::now();
                if let Err(error) = server.serve_once_with_admission(&admission) {
                    eprintln!("listener failed after {:?}: {error:?}", started.elapsed());
                }
            }
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(addr)));
        stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(addr);
        handle.join().unwrap();
        match result {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e),
        }
    })
}
fn exchange(addr: SocketAddr, path: &str, credential: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {credential}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend(body);
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(&wire).unwrap();
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = vec![];
    let started = Instant::now();
    let read = s.read_to_end(&mut out);
    assert!(
        !out.is_empty(),
        "{path}: empty HTTP response after {:?}; read={read:?}",
        started.elapsed()
    );
    out
}

/// A batch post: the status and the answer body.
fn post(addr: SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let response = exchange(addr, "/v2/batches", &ingest_secret("a1"), request);
    (status(&response), body(&response).to_vec())
}
/// A refusal: the status and the fixed code.
fn refusal(addr: SocketAddr, request: &[u8]) -> (u16, String) {
    let (code, answer) = post(addr, request);
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    (code, answer["error"].as_str().unwrap().to_string())
}
fn read_raw(addr: SocketAddr, route: &str, request: &Value) -> (u16, Vec<u8>) {
    let response = exchange(
        addr,
        &format!("/v2/read/{route}"),
        READER_A,
        request.to_string().as_bytes(),
    );
    (status(&response), response)
}
fn read(addr: SocketAddr, route: &str, request: &Value) -> Value {
    let (code, response) = read_raw(addr, route, request);
    let answer: Value = serde_json::from_slice(body(&response)).unwrap();
    assert_eq!(code, 200, "{route}: {answer}");
    answer
}
/// Every row of a paged list, following the cursor.
fn walk(addr: SocketAddr, route: &str, rows: &str, mut request: Value) -> (Value, Vec<Value>) {
    let mut all = vec![];
    let mut first = Value::Null;
    loop {
        let page = read(addr, route, &request);
        all.extend(page[rows].as_array().unwrap().iter().cloned());
        if first.is_null() {
            first = page.clone();
        }
        match page["next_cursor"].as_str() {
            Some(cursor) => request["cursor"] = json!(cursor),
            None => return (first, all),
        }
    }
}
fn packages(rows: &[Value]) -> BTreeSet<(String, String)> {
    rows.iter()
        .map(|r| {
            let p = &r["package"];
            (
                p["name"]["quoted"].as_str().unwrap().to_string(),
                p["version"]["quoted"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}
fn expected(list: &[(String, String)]) -> BTreeSet<(String, String)> {
    list.iter().cloned().collect()
}
fn counts(w: &World) -> Vec<(String, i64)> {
    let db = rusqlite::Connection::open(&w.db).unwrap();
    V2_TABLES
        .iter()
        .filter_map(|t| {
            db.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .ok()
                .map(|n| (t.to_string(), n))
        })
        .collect()
}
/// The request with its artifact edited and its integrity fields recomputed, so only the hub's
/// own checks of the artifact can refuse it; the hub is told to trust exactly this artifact.
fn forged(
    honest: &(Value, String, String, Vec<u8>),
    edit: impl FnOnce(&mut Value),
) -> (TrustedCapture, Vec<u8>) {
    let mut artifact: Value = serde_json::from_str(&honest.2).unwrap();
    edit(&mut artifact);
    let raw = String::from_utf8(canonical(&artifact)).unwrap();
    let mut request: Value = serde_json::from_slice(&honest.3).unwrap();
    request["artifact_utf8"] = json!(raw);
    request["artifact_sha256"] = json!(hash(raw.as_bytes()));
    request["artifact_byte_length"] = json!(raw.len());
    (
        TrustedCapture {
            binding: honest.0.clone(),
            evidence_id: honest.1.clone(),
            artifact_utf8: raw,
        },
        canonical(&request),
    )
}
fn set_lock(artifact: &mut Value, text: &str) {
    artifact["inputs"][0]["bytes_utf8"] = json!(text);
    artifact["inputs"][0]["sha256"] = json!(hash(text.as_bytes()));
}

#[test]
fn a_1500_package_capture_is_admitted_and_every_package_reads_back() {
    let w = world_logged();
    let pk = synthetic_packages(CAP);
    let request = w.v2_request(&delivery(&w), 1, synthetic_lock(&pk, 0).as_bytes());
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let (first_inventory, inventory, changes, evidence) =
        serving(&w, vec![trusted(&request)], |addr| {
            let (code, ack) = post(addr, &request.3);
            assert_eq!(code, 200, "{}", String::from_utf8_lossy(&ack));
            validate_ack(&request.3, &ack).unwrap();
            let ack: Value = serde_json::from_slice(&ack).unwrap();
            assert_eq!(ack["result"], "published");

            let (first, rows) = walk(
                addr,
                "inventory",
                "inventory",
                json!({"devices":[w.a1],"limit":100}),
            );
            let (_, changes) = walk(
                addr,
                "changes",
                "changes",
                json!({"since":"start","limit":100}),
            );
            let reference = rows[0]["evidence"].as_str().unwrap().to_string();
            let (code, response) = read_raw(addr, "evidence", &json!({"reference":reference}));
            assert_eq!(code, 200);
            (first, rows, changes, response)
        });
    assert_eq!(first_inventory["total"], CAP);
    assert_eq!(inventory.len(), CAP);
    assert_eq!(packages(&inventory), expected(&pk));

    assert_eq!(changes.len(), CAP);
    assert!(changes.iter().all(|c| c["kind"] == "added"));
    assert_eq!(packages(&changes), expected(&pk));
    assert_eq!(assert_log_equals_replay(&w.db), CAP);

    // The evidence answer names the assessment, says it holds 1,500 records and was cut, and
    // stays well inside the 256 KiB answer bound.
    assert!(
        body(&evidence).len() < 256 * 1024,
        "{} bytes",
        body(&evidence).len()
    );
    let evidence: Value = serde_json::from_slice(body(&evidence)).unwrap();
    assert_eq!(evidence["evidence"]["records_total"], CAP);
    assert_eq!(evidence["evidence"]["records_truncated"], true);
    assert_eq!(
        evidence["evidence"]["records"].as_array().unwrap().len(),
        100
    );
}

#[test]
fn a_newer_assessment_replaces_the_packages_of_its_input_and_the_changes_say_how() {
    let w = world_logged();
    let before = synthetic_packages(CAP);
    // Five packages leave, three change version, four arrive.
    let mut after: Vec<(String, String)> = before[5..].to_vec();
    for p in after.iter_mut().take(3) {
        p.1 = "9.9.9".into();
    }
    after.extend((1..=4).map(|i| (format!("synthetic-new-{i:04}"), "2.0.0".to_string())));
    let d = delivery(&w);
    let one = w.v2_request(&d, 1, synthetic_lock(&before, 0).as_bytes());
    let two = w.v2_request(&d, 2, synthetic_lock(&after, 0).as_bytes());
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let (inventory, changes) = serving(&w, vec![trusted(&one), trusted(&two)], |addr| {
        assert_eq!(post(addr, &one.3).0, 200);
        assert_eq!(post(addr, &two.3).0, 200);
        let (_, inventory) = walk(addr, "inventory", "inventory", json!({"limit":100}));
        let (_, changes) = walk(
            addr,
            "changes",
            "changes",
            json!({"since":"start","limit":100}),
        );
        (inventory, changes)
    });
    assert_eq!(inventory.len(), after.len());
    assert_eq!(packages(&inventory), expected(&after));
    let of = |kind: &str| -> Vec<&Value> {
        changes
            .iter()
            .filter(|c| c["assessment_revision"] == 2 && c["kind"] == kind)
            .collect()
    };
    assert_eq!(of("resolved").len(), 5);
    assert_eq!(of("changed").len(), 3);
    assert_eq!(of("added").len(), 4);
    assert!(of("changed")
        .iter()
        .all(|c| c["reason"] == "version_changed" && c["package"]["version"]["quoted"] == "9.9.9"));
    assert_eq!(changes.len(), CAP + 12);
    assert_eq!(assert_log_equals_replay(&w.db), CAP + 12);
}

#[test]
fn a_late_assessment_is_kept_in_history_and_leaves_the_current_packages_alone() {
    let w = world_logged();
    let older = synthetic_packages(CAP);
    let newer: Vec<_> = older[10..].to_vec();
    let d = delivery(&w);
    // Revision 1 is captured first but delivered second.
    let rev1 = w.v2_request(&d, 2, synthetic_lock(&older, 0).as_bytes());
    let rev2 = w.v2_request(&d, 1, synthetic_lock(&newer, 0).as_bytes());
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let inventory = serving(&w, vec![trusted(&rev1), trusted(&rev2)], |addr| {
        let (code, ack) = post(addr, &rev2.3);
        assert_eq!(code, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&ack).unwrap()["result"],
            "published"
        );
        let (code, ack) = post(addr, &rev1.3);
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&ack));
        assert_eq!(
            serde_json::from_slice::<Value>(&ack).unwrap()["result"],
            "historical_only"
        );
        walk(addr, "inventory", "inventory", json!({"limit":100})).1
    });
    assert_eq!(packages(&inventory), expected(&newer));
    assert!(assert_log_equals_replay(&w.db) >= newer.len());
}

#[test]
fn every_lockfile_kind_the_scanner_reads_is_admitted_with_its_ecosystem() {
    let w = world();
    let files: [(&str, &str); 14] = [
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
    let listed: Vec<(&str, &[u8])> = files.iter().map(|f| (f.0, f.1.as_bytes())).collect();
    let request = w.v2_request_files(&delivery(&w), 1, &listed);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let rows = serving(&w, vec![trusted(&request)], |addr| {
        let (code, ack) = post(addr, &request.3);
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&ack));
        walk(addr, "inventory", "inventory", json!({"limit":100})).1
    });
    // The scanner's own reading of the same tree is the oracle.
    let root = w
        .tmp
        .path()
        .join(format!("root-{}-scope-1-npm-a", &w.a1[..8]));
    let out = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(w.tmp.path().join("scan-state"))
        .args(["inventory", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let scan: Value = serde_json::from_slice(&out.stdout).unwrap();
    let triple = |eco: &str, name: &str, version: &str| {
        (eco.to_string(), name.to_string(), version.to_string())
    };
    let scanned: BTreeSet<_> = scan["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            triple(
                p["ecosystem"].as_str().unwrap(),
                p["name"].as_str().unwrap(),
                p["version"].as_str().unwrap(),
            )
        })
        .collect();
    let read_back: BTreeSet<_> = rows
        .iter()
        .map(|r| {
            let p = &r["package"];
            triple(
                p["ecosystem"]["quoted"].as_str().unwrap(),
                p["name"]["quoted"].as_str().unwrap(),
                p["version"]["quoted"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(scanned.len() >= 20, "{scanned:?}");
    assert_eq!(read_back, scanned);
    let ecosystems: BTreeSet<_> = scanned.iter().map(|t| t.0.as_str()).collect();
    for e in [
        "npm",
        "PyPI",
        "crates.io",
        "Go",
        "RubyGems",
        "Packagist",
        "NuGet",
    ] {
        assert!(ecosystems.contains(e), "{e} missing from {ecosystems:?}");
    }
}

#[test]
fn a_tampered_assessment_is_refused_with_a_fixed_code_and_nothing_is_written() {
    let w = world_logged();
    let pk = synthetic_packages(CAP);
    let honest = w.v2_request(&delivery(&w), 1, synthetic_lock(&pk, 0).as_bytes());
    let text = synthetic_lock(&pk, 0);
    let another = |a: &Value, name: &str| {
        let mut r = a["records"][0].clone();
        r["record_id"] = json!(hash(format!("{name}-record").as_bytes()));
        r["location_ref"] = json!(hash(format!("{name}-location").as_bytes()));
        r["component_id"] = json!(format!("component-{name}"));
        r
    };
    type Edit<'a> = Box<dyn Fn(&mut Value) + 'a>;
    let cases: Vec<(&str, Edit, u16, &str)> = vec![
        (
            "a record the input does not hold",
            Box::new(|a| {
                let mut r = another(a, "extra");
                r["package"]["name"] = json!("synthetic-extra");
                *a["records"].as_array_mut().unwrap().last_mut().unwrap() = r;
            }),
            422,
            "captured_member_mismatch",
        ),
        (
            "a record missing",
            Box::new(|a| {
                a["records"].as_array_mut().unwrap().pop();
            }),
            422,
            "captured_member_mismatch",
        ),
        (
            "a package listed twice",
            Box::new(|a| {
                let r = another(a, "twice");
                *a["records"].as_array_mut().unwrap().last_mut().unwrap() = r;
            }),
            422,
            "captured_member_mismatch",
        ),
        (
            "a record id listed twice",
            Box::new(|a| {
                let r = a["records"][0].clone();
                *a["records"].as_array_mut().unwrap().last_mut().unwrap() = r;
            }),
            422,
            "duplicate_record",
        ),
        (
            "an input hash that does not match its text",
            Box::new(|a| a["inputs"][0]["sha256"] = json!("0".repeat(64))),
            422,
            "input_digest",
        ),
        (
            "a repeated key in the lockfile",
            Box::new(|a| {
                let mut t = text.trim_end().to_string();
                t.pop();
                t.push_str(",\"lockfileVersion\":3}");
                set_lock(a, &t);
            }),
            422,
            "duplicate_input_key",
        ),
        (
            "a record of another ecosystem",
            Box::new(|a| a["records"][0]["package"]["ecosystem"] = json!("PyPI")),
            422,
            "captured_member_mismatch",
        ),
        (
            "a record of another version",
            Box::new(|a| a["records"][0]["package"]["version"] = json!("9.9.9")),
            422,
            "captured_member_mismatch",
        ),
        (
            "a record of an input that is not in the assessment",
            Box::new(|a| a["records"][0]["input_path"] = json!("elsewhere/package-lock.json")),
            422,
            "captured_member_mismatch",
        ),
        (
            "more records than an assessment may hold",
            Box::new(|a| {
                let mut more = pk.clone();
                more.push(("synthetic-pkg-9999".into(), "1.0.0".into()));
                set_lock(a, &synthetic_lock(&more, 0));
                let mut r = another(a, "over");
                r["package"]["name"] = json!("synthetic-pkg-9999");
                r["package"]["version"] = json!("1.0.0");
                a["records"].as_array_mut().unwrap().push(r);
            }),
            413,
            "array_limit",
        ),
        (
            "more inputs than an assessment may hold",
            Box::new(|a| {
                for i in 0..256 {
                    a["inputs"].as_array_mut().unwrap().push(json!({"path":format!("gone-{i}/package-lock.json"),"sha256":null,"bytes_utf8":null,"error":"input_read_failed"}));
                }
            }),
            413,
            "array_limit",
        ),
        (
            "a view larger than the saved-view limit",
            Box::new(|a| set_lock(a, &synthetic_lock(&pk, 1200))),
            413,
            "view_limit",
        ),
    ];
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let empty = counts(&w);
    assert!(empty.iter().all(|(_, n)| *n == 0), "{empty:?}");
    for (what, edit, code, tag) in cases {
        let (capture, wire) = forged(&honest, edit);
        let got = serving(&w, vec![capture], |addr| refusal(addr, &wire));
        assert_eq!(got.0, code, "{what}: {got:?}");
        if !tag.is_empty() {
            assert_eq!(got.1, tag, "{what}");
        }
        assert_eq!(counts(&w), empty, "{what} wrote something");
    }
    // None of that blocked the honest request.
    let (code, ack) = serving(&w, vec![trusted(&honest)], |addr| post(addr, &honest.3));
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&ack));
    assert_eq!(assert_log_equals_replay(&w.db), CAP);
}

#[test]
fn an_unapproved_capture_is_refused_before_its_lockfile_text_is_read() {
    let w = world_logged();
    let pk = synthetic_packages(CAP);
    let honest = w.v2_request(&delivery(&w), 1, synthetic_lock(&pk, 0).as_bytes());
    // A request of about 3.6 MiB whose lockfile text the hub's parser refuses (a repeated key), so
    // a hub that read the text first would answer 422 instead of 403.
    let pad = 3_600_000usize.saturating_sub(honest.3.len());
    let (approved, wire) = forged(&honest, |a| {
        let text = synthetic_lock(&pk, 0);
        let mut t = text.trim_end().to_string();
        t.pop();
        t.push_str(",\"lockfileVersion\":3}");
        t.push_str(&" ".repeat(pad));
        set_lock(a, &t);
    });
    assert!(
        wire.len() > 3 << 20 && wire.len() <= 4 << 20,
        "{}",
        wire.len()
    );
    let empty = counts(&w);
    // The text really is refused when the hub is told to trust the artifact...
    let got = serving(&w, vec![approved], |addr| refusal(addr, &wire));
    assert_eq!(got, (422, "duplicate_input_key".to_string()));
    // ...and a device the operator granted nothing gets the cheap refusal instead.
    let got = serving(&w, vec![], |addr| refusal(addr, &wire));
    assert_eq!(got, (403, "capture_unapproved".to_string()));
    assert_eq!(counts(&w), empty);
}

#[test]
fn an_input_path_of_256_bytes_is_taken_by_both_sides_and_a_longer_one_by_neither() {
    let w = world();
    let d = delivery(&w);
    // `<dir>/package-lock.json` is `dir.len() + 18` bytes.
    let dir = |n: usize| {
        let long = format!(
            "{}/{}/{}",
            "a".repeat(100),
            "b".repeat(100),
            "c".repeat(n - 202)
        );
        assert_eq!(long.len(), n);
        long
    };
    // The device refuses a path over the bound by name, before anything is read.
    let tag = format!("{}-{}-{}", &d.device[..8], d.scope, d.source);
    let root = w.tmp.path().join(format!("root-{tag}"));
    std::fs::create_dir_all(root.join(dir(239))).unwrap();
    std::fs::write(
        root.join(dir(239)).join("package-lock.json"),
        synthetic_lock(&synthetic_packages(3), 0),
    )
    .unwrap();
    let mut store = Store::open(&w.tmp.path().join("long-producer")).unwrap();
    let binding = json!({"tenant":ORG,"site":"site-a","device":w.a1,"generation":"g","scope":"scope-1","source":"npm-a"});
    let long_request = json!({"token":"long","binding":binding,"root":root.canonicalize().unwrap(),
        "inputs":[format!("{}/package-lock.json", dir(239))],"observed_at":"1793898285.4219873","completed_at":"1793898285.5764945"});
    let error = capture::capture(&mut store, long_request.to_string().as_bytes())
        .expect_err("a 257-byte path");
    assert!(
        error.to_string().contains("invalid_capture_path"),
        "{error}"
    );

    // At the bound, the whole path from capture to reader works.
    let exact_dir = dir(238);
    let exact = w.v2_request(
        &Delivery {
            inputs: &[exact_dir.as_str()],
            ..delivery(&w)
        },
        1,
        synthetic_lock(&synthetic_packages(3), 0).as_bytes(),
    );
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let rows = serving(&w, vec![trusted(&exact)], |addr| {
        let (code, ack) = post(addr, &exact.3);
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&ack));
        walk(addr, "inventory", "inventory", json!({})).1
    });
    assert_eq!(rows.len(), 3);
}
