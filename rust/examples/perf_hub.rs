//! Builds and measures a hub of 10 devices and tens of thousands of stored observations.
//! Synthetic data only; see `docs/performance.md` for what the numbers do and do not show.
//!
//! * `perf_hub admit DB WORKDIR [TARGET_ROWS [MAX_DB_MIB [change-log] [lockfile]]]` enrolls 10
//!   devices and delivers, through the real trusted-local admission path, authority by authority
//!   (up to 64 assessments of 2 observations each, up to 64 authorities per device). With
//!   `lockfile` each assessment is instead one lockfile of 1,000 packages, a device holds 3
//!   authorities of 2 assessments, and a newer assessment moves a twentieth of the packages. It
//!   stops at TARGET_ROWS stored observation rows when given, otherwise when the hub refuses
//!   with 503 because its database ceiling (MAX_DB_MIB, default 1024) is full. Prints ingest
//!   timings, the number of 503 answers, where it stopped, the hub's footprint and the bytes each
//!   table holds.
//! * `perf_hub full DB WORKDIR RECORDS REVISIONS [change-log]` admits REVISIONS lockfiles of
//!   RECORDS packages through the real admission path into two new devices of DB (a new hub when
//!   there is none), once oldest first and once newest first (late arrivals), and prints the
//!   admission time of each against the one-second budget. The default budget applies.
//! * `perf_hub clone FROM_DB TO_DB TARGET_ROWS` copies an admitted hub and adds rows by direct
//!   SQL (whole authorities copied under a new scope, then single rows) until the table holds
//!   TARGET_ROWS. This does not go through admission and measures nothing about ingest.
//! * `perf_hub query DB [ROUNDS]` serves the hub on a loopback socket, grants a reader of every
//!   site and times each reader route over real HTTP, with response sizes and process memory. It
//!   is not read-only: every run adds one reader grant (the `DB.readers` file) and stops with a
//!   panic on any answer that is not HTTP 200. Its `changes` walk reports per-page milliseconds.
//! * `perf_hub admit-during-walk DB WORKDIR [ADMISSIONS [PACE_MS [idle]]]` admits new assessments
//!   (default 256, one every 50 ms) into a new device outside the reader's view while a reader
//!   walks `changes` over HTTP back to back; `idle` runs the same admissions with no reader. It
//!   reports admission latency, how many admissions were refused with 503, and what the walk
//!   saw. Adds one reader grant and one device to DB.
//! * `perf_hub compare-changes DB` walks `changes` on a schema 2 hub and on a copy that has
//!   gained the change log (`DB.with-log`), at one fixed clock, and fails unless every page is
//!   the same text, cursors included. Like `query` it adds one reader grant to DB.
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use vorda::{
    fleet::{
        auth::{DeviceGrant, GrantRequest, ReaderStore, Site, SourceGrant},
        history::{fleet_changes, ChangeFilter, Since},
        query::PageRequest,
    },
    link::{
        native::{self, Admission, TrustedCapture},
        server::Server,
        storage::Hub,
    },
    store::{capture, now, Store},
};

const ORG: &str = "org-perf";
const DEVICES: usize = 10;
const SITES: usize = 5;
const AUTHORITIES: usize = native::MAX_AUTHORITIES_PER_DEVICE;
const ASSESSMENTS: usize = native::MAX_ASSESSMENTS_PER_AUTHORITY;
/// Observation rows one admitted assessment stores.
const ROWS_PER_ASSESSMENT: usize = 2;

/// What one hub is filled with. `small` is the original shape: assessments of two one-package
/// lockfiles. `lockfile` is a realistic one: each assessment is one lockfile of about a thousand
/// packages, a device holds a few scopes of two assessments each, and a newer assessment moves a
/// twentieth of the packages to another version.
#[derive(Clone, Copy)]
struct Profile {
    rows_per_assessment: usize,
    authorities: usize,
    assessments: usize,
    lockfile: bool,
}
const SMALL: Profile = Profile {
    rows_per_assessment: ROWS_PER_ASSESSMENT,
    authorities: AUTHORITIES,
    assessments: ASSESSMENTS,
    lockfile: false,
};
const LOCKFILE: Profile = Profile {
    rows_per_assessment: 1000,
    authorities: 3,
    assessments: 2,
    lockfile: true,
};

fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn canonical(v: &Value) -> Vec<u8> {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => json!(m
                .iter()
                .map(|(k, v)| (k, sorted(v)))
                .collect::<BTreeMap<_, _>>()),
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sorted(v)).unwrap()
}
fn lock(name: &str, version: &str) -> String {
    json!({"lockfileVersion":3,"packages":{format!("node_modules/{name}"): {"version": version}}})
        .to_string()
}
fn status_kib(field: &str) -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|l| {
            l.trim_start_matches(':')
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}
fn disk(db: &Path) -> Value {
    let size = |suffix: &str| {
        fs::metadata(format!("{}{suffix}", db.display()))
            .map(|m| m.len())
            .unwrap_or(0)
    };
    let conn = Connection::open(db).unwrap();
    let rows = |t: &str| -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
            .unwrap()
    };
    json!({"db_bytes": size(""), "wal_bytes": size("-wal"),
        "v2_observations": rows("v2_observations"), "v2_current": rows("v2_current"),
        "v2_assessments": rows("v2_assessments"), "v2_authorities": rows("v2_authorities"),
        "table_bytes": table_bytes(&conn)})
}
/// Per table: row count and the bytes its columns hold (`SUM(length(col))` over each column read
/// as a blob). This is payload only, not pages, indexes or free space; `db_bytes` is the file.
fn table_bytes(conn: &Connection) -> Value {
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut out = serde_json::Map::new();
    for table in tables {
        let columns: Vec<String> = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let sums = columns
            .iter()
            .map(|c| format!("COALESCE(SUM(length(CAST({c} AS BLOB))),0)"))
            .collect::<Vec<_>>()
            .join("+");
        let (rows, bytes): (i64, i64) = conn
            .query_row(&format!("SELECT count(*), {sums} FROM {table}"), [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        out.insert(table, json!({"rows": rows, "bytes": bytes}));
    }
    Value::Object(out)
}
fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// Checks a schema 3 hub's stored change log against the in-memory replay of every authority and
/// prints how many rows that covered and how long it took.
fn verify_log(db: &Path) {
    let started = Instant::now();
    native::verify_change_log(db).unwrap();
    let conn = Connection::open(db).unwrap();
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM v2_changes", [], |r| r.get(0))
        .unwrap();
    let authorities: i64 = conn
        .query_row("SELECT count(*) FROM v2_change_state", [], |r| r.get(0))
        .unwrap();
    println!(
        "{}",
        json!({"change_log_rows":rows,"authorities":authorities,"stored_equals_replay":true,
        "verify_seconds":started.elapsed().as_secs_f64()})
    );
}

/// A realistic npm v3 lockfile of `records` packages. Revision `rev` moves every twentieth package
/// to a newer version. `tag` keeps package names apart between authorities.
fn full_lock(tag: &str, records: usize, rev: usize) -> String {
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        json!({"name":"synthetic-app","version":"1.0.0"}),
    );
    for i in 1..=records {
        let name = format!("synthetic-{tag}-{i:04}");
        let version = format!("1.{}.{}", if i % 20 == 0 { rev - 1 } else { 0 }, i % 9);
        let digest = hash(format!("{name}{version}").as_bytes());
        packages.insert(
            format!("node_modules/{name}"),
            json!({"version":version,
                "resolved":format!("https://registry.example.invalid/{name}/-/{name}-{version}.tgz"),
                "integrity":format!("sha512-{digest}{}", &hash(digest.as_bytes())[..24]),
                "license":"MIT","dependencies":{"synthetic-app-dep":"^1.0.0"},"engines":{"node":">=18"}}),
        );
    }
    serde_json::to_string_pretty(
        &json!({"name":"synthetic-app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":packages}),
    )
    .unwrap()
}
/// One capture through the real capture and export path, and what the hub is told to trust.
struct Capturing<'a> {
    binding: &'a Value,
    /// Keeps the authority's files, tokens and package names apart.
    tag: &'a str,
    rev: usize,
    inputs: &'a [&'a str],
    t0: f64,
}
fn captured(store: &mut Store, work: &Path, c: &Capturing) -> TrustedCapture {
    let observed = format!("{:.4}", c.t0 - 600.0 + (c.rev as f64));
    let request = json!({"token":format!("token-{}-{}", c.tag, c.rev),"binding":c.binding,
        "root":work.join(format!("root-{}", c.tag)),"inputs":c.inputs,
        "observed_at":observed,"completed_at":observed});
    let outcome = capture::capture(store, &serde_json::to_vec(&request).unwrap()).unwrap();
    let export = work.join("export.json");
    capture::export(store, outcome["snapshot_id"].as_str().unwrap(), &export).unwrap();
    let view: Value = serde_json::from_slice(&fs::read(&export).unwrap()).unwrap();
    let evidence = view["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["assessment_id"] == outcome["assessment_id"])
        .and_then(|r| r["dimensions"]["evidence"].as_str())
        .unwrap()
        .to_string();
    let raw = view["retained_payload_utf8"][&evidence]
        .as_str()
        .unwrap()
        .to_string();
    // The producer keeps every capture's saved view, attempt and artifact, and a full lockfile's
    // are megabytes: sixty-four of them pass its 256 MiB state ceiling. The harness has already
    // taken what the hub is sent, so earlier ones are dropped from the producer (not from any hub).
    store
        .db
        .execute(
            "DELETE FROM capture_views WHERE revision < ?",
            [outcome["revision"].as_i64().unwrap()],
        )
        .unwrap();
    store
        .db
        .execute(
            "DELETE FROM capture_attempts WHERE token != ?",
            [outcome["token"].as_str().unwrap()],
        )
        .unwrap();
    store
        .db
        .execute(
            "DELETE FROM capture_artifacts WHERE evidence != ?",
            [&evidence],
        )
        .unwrap();
    TrustedCapture {
        binding: c.binding.clone(),
        evidence_id: evidence,
        artifact_utf8: raw,
    }
}
/// The wire request that delivers `capture` as the authority's `sequence`th delivery.
fn wire(capture: &TrustedCapture, sequence: usize) -> Vec<u8> {
    canonical(
        &json!({"schema":2,"binding":capture.binding,"sequence":sequence,"evidence_id":capture.evidence_id,
        "artifact_sha256":hash(capture.artifact_utf8.as_bytes()),
        "artifact_byte_length":capture.artifact_utf8.len(),"artifact_utf8":capture.artifact_utf8}),
    )
}
/// The captures of revisions `1..=revs` of one authority in capture order. `records` gives each a
/// lockfile of that many packages; `None` gives the small shape of two one-package lockfiles.
fn produce(
    store: &mut Store,
    work: &Path,
    binding: &Value,
    tag: &str,
    revs: usize,
    (records, t0): (Option<usize>, f64),
) -> Vec<TrustedCapture> {
    let root = work.join(format!("root-{tag}"));
    (1..=revs)
        .map(|rev| {
            let inputs: &[&str] = match records {
                Some(n) => {
                    fs::create_dir_all(root.join("app")).unwrap();
                    fs::write(root.join("app/package-lock.json"), full_lock(tag, n, rev)).unwrap();
                    &["app/package-lock.json"]
                }
                None => {
                    for p in 0..2 {
                        let dir = root.join(format!("p{p}"));
                        fs::create_dir_all(&dir).unwrap();
                        fs::write(
                            dir.join("package-lock.json"),
                            lock(&format!("pkg-{tag}-{p}"), &format!("1.{rev}.0")),
                        )
                        .unwrap();
                    }
                    &["p0/package-lock.json", "p1/package-lock.json"]
                }
            };
            captured(
                store,
                work,
                &Capturing {
                    binding,
                    tag,
                    rev,
                    inputs,
                    t0,
                },
            )
        })
        .collect()
}
/// The captures and wire requests for revisions `1..=revs` of one authority, in order, made through
/// the real capture and export path.
fn produce_wires(
    store: &mut Store,
    work: &Path,
    binding: &Value,
    tag: &str,
    revs: usize,
    shape: (Option<usize>, f64),
) -> (Vec<TrustedCapture>, Vec<Vec<u8>>) {
    let captures = produce(store, work, binding, tag, revs, shape);
    let wires = captures.iter().zip(1..).map(|(c, n)| wire(c, n)).collect();
    (captures, wires)
}

fn admit(
    db: &Path,
    work: &Path,
    target_rows: Option<usize>,
    max_db_mib: u64,
    change_log: bool,
    profile: Profile,
) {
    fs::create_dir_all(work).unwrap();
    let work = work.canonicalize().unwrap();
    let t0 = now();
    let max_bytes = max_db_mib * 1024 * 1024;
    let hub = Hub::with_limit(db, max_bytes).unwrap();
    let mut ids = vec![];
    for d in 0..DEVICES {
        let tag = format!("perf-{d}");
        let invite = format!("synthetic-invite-{tag}-perf-fixture-only-0000000");
        let ingest = format!("synthetic-ingest-{tag}-perf-fixture-only-0000000");
        hub.invite(&invite, ORG, &format!("site-{}", d % SITES), 3600.0)
            .unwrap();
        ids.push(hub.enroll(&invite, &ingest).unwrap());
    }
    native::migrate_with_limit(db, max_bytes).unwrap();
    if change_log {
        native::migrate_change_log_with_limit(db, max_bytes).unwrap();
    }
    let (mut produce, mut admitted) = (Duration::ZERO, Duration::ZERO);
    let mut refused_503 = 0; // stops the run at the first 503, so this ends 0 or 1
    let mut each = vec![];
    let mut stores: Vec<Store> = (0..DEVICES)
        .map(|d| Store::open(&work.join(format!("producer-{d}"))).unwrap())
        .collect();
    let mut stopped = Value::Null;
    // Authority-major, so every device holds data when the hub reaches its ceiling.
    'fill: for a in 0..profile.authorities {
        for (d, identity) in ids.iter().enumerate() {
            let remaining = target_rows.map_or(profile.assessments, |target| {
                (target.saturating_sub(each.len() * profile.rows_per_assessment))
                    .div_ceil(profile.rows_per_assessment)
                    .min(profile.assessments)
            });
            if remaining == 0 {
                break 'fill;
            }
            let site = format!("site-{}", d % SITES);
            let store = &mut stores[d];
            // One open admission holds the captures of at most three authorities.
            let started = Instant::now();
            let scope = format!("scope-{a:02}");
            let source = format!("src-{}", a % 4);
            let binding = json!({"tenant":ORG,"site":site,"device":identity["device"],
                "generation":identity["generation"],"scope":scope,"source":source});
            let (captures, wires) = produce_wires(
                store,
                &work,
                &binding,
                &format!("{d}-{a}"),
                remaining,
                (profile.lockfile.then_some(profile.rows_per_assessment), t0),
            );
            produce += started.elapsed();
            let admission = Admission::open_with_limit(db, captures, max_bytes).unwrap();
            for (n, wire) in wires.iter().enumerate() {
                let started = Instant::now();
                match admission.admit_at(wire, &format!("{:.9}", t0)) {
                    Ok(_) => {
                        let took = started.elapsed();
                        admitted += took;
                        each.push(took.as_secs_f64() * 1000.0);
                    }
                    // The hub refuses with 503 once its page ceiling is full.
                    Err(e) if e.http_status == Some(503) => {
                        refused_503 += 1;
                        stopped = json!({"device":d,"authority_index":a,"assessment":n + 1,"error":e.message});
                        break 'fill;
                    }
                    Err(e) => panic!("admission failed: {}", e.message),
                }
            }
        }
    }
    each.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stored = each.len() * profile.rows_per_assessment;
    println!(
        "{}",
        json!({"profile":if profile.lockfile {"lockfile"} else {"small"},"records_per_assessment":profile.rows_per_assessment,"devices":DEVICES,"requests_admitted":each.len(),"stopped_at":stopped,
        "max_db_bytes":max_bytes,"target_rows":target_rows,"observation_rows_stored":stored,
        "target_reached":target_rows.map(|target| stored >= target),"stopped_by_503":refused_503,
        "producer_capture_and_export_seconds":produce.as_secs_f64(),
        "hub_admission_seconds":admitted.as_secs_f64(),
        "admit_ms":{"p50":percentile(&each,0.5),"p95":percentile(&each,0.95),"max":each[each.len()-1]},
        "process_peak_rss_kib":status_kib("VmHWM"),"disk":disk(db)})
    );
}

fn clone_rows(from: &Path, to: &Path, target: i64) {
    fs::copy(from, to).unwrap();
    let mut db = Connection::open(to).unwrap();
    let total = |db: &Connection| -> i64 {
        db.query_row("SELECT count(*) FROM v2_observations", [], |r| r.get(0))
            .unwrap()
    };
    let tx = db.transaction().unwrap();
    let authorities: Vec<String> = tx
        .prepare("SELECT authority FROM v2_authorities ORDER BY authority")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let per_authority = (ASSESSMENTS * 2) as i64;
    let mut n = 0;
    while total(&tx) + per_authority <= target {
        let old = &authorities[n % authorities.len()];
        let mut tuple: Vec<Value> = serde_json::from_str(old).unwrap();
        tuple[4] = json!(format!("{}-copy{n}", tuple[4].as_str().unwrap()));
        let new = serde_json::to_string(&tuple).unwrap();
        for table in [
            "v2_authorities",
            "v2_assessments",
            "v2_observations",
            "v2_current",
            "v2_coverage",
            "v2_deliveries",
            "v2_views",
        ] {
            let columns: Vec<String> = tx
                .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let rest = columns[1..].join(",");
            tx.execute(
                &format!(
                    "INSERT INTO {table} SELECT ?{} FROM {table} WHERE authority=?",
                    if rest.is_empty() {
                        String::new()
                    } else {
                        format!(",{rest}")
                    }
                ),
                params![new, old],
            )
            .unwrap();
        }
        n += 1;
    }
    // The remainder is single extra history rows under an existing assessment.
    let missing = target - total(&tx);
    for i in 0..missing {
        tx.execute(
            "INSERT INTO v2_observations SELECT authority,record||?,assessment,payload FROM v2_observations WHERE rowid=(SELECT min(rowid) FROM v2_observations)",
            params![format!("-extra{i}")],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    println!(
        "{}",
        json!({"copied_authorities":n,"extra_rows":missing,"disk":disk(to)})
    );
}

/// Stops the listener thread of a `thread::scope` when dropped, also while a panic unwinds, so
/// the scope can join that thread instead of waiting for it forever in `accept`.
struct StopListener<'a> {
    stop: &'a AtomicBool,
    addr: SocketAddr,
}

impl Drop for StopListener<'_> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr);
    }
}

/// One POST over a fresh loopback connection: the status and the answer body.
fn exchange(addr: SocketAddr, path: &str, credential: &str, body: &str) -> (u16, Vec<u8>) {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {credential}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = vec![];
    let _ = s.read_to_end(&mut out);
    let code = String::from_utf8_lossy(&out[..out.len().min(12)])
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let at = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |p| p + 4);
    (code, out[at..].to_vec())
}

fn query(db: &Path, rounds: usize) {
    let hub = Hub::open(db).unwrap();
    let secret = format!(
        "synthetic-reader-perf-{}-fixture-only-000000",
        std::process::id()
    );
    let sites: Vec<Site> = (0..SITES)
        .map(|s| Site {
            org: ORG.into(),
            site: format!("site-{s}"),
        })
        .collect();
    ReaderStore::grant(
        &hub,
        &secret,
        &GrantRequest {
            label: "perf reader",
            sites: &sites,
            devices: DeviceGrant::All,
            sources: SourceGrant::All,
            ttl: 3600.0,
        },
    )
    .unwrap();
    let server = Server::bind(hub, "127.0.0.1", 0, None, None).unwrap();
    let addr = server.local_addr().unwrap();
    let admission = Admission::open(db, vec![]).unwrap();
    let stop = AtomicBool::new(false);
    let rss_before = status_kib("VmRSS");
    let mut report = serde_json::Map::new();
    thread::scope(|scope| {
        let _stop_listener = StopListener { stop: &stop, addr };
        scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let _ = server.serve_once_with_admission(&admission);
            }
        });
        let cases: [(&str, &str); 9] = [
            ("devices", "{}"),
            ("devices", r#"{"limit":100}"#),
            ("findings", "{}"),
            ("status", "{}"),
            ("sources", "{}"),
            ("inventory", "{}"),
            ("inventory", r#"{"name":"pkg-0-0-0"}"#),
            ("changes", r#"{"since":"start"}"#),
            ("changes", r#"{"since":"start","limit":100}"#),
        ];
        for (route, body) in cases {
            let path = format!("/v2/read/{route}");
            let mut ms = vec![];
            let mut shape = (0, 0);
            for round in 0..=rounds {
                let started = Instant::now();
                let r = exchange(addr, &path, &secret, body);
                if round > 0 {
                    ms.push(started.elapsed().as_secs_f64() * 1000.0);
                }
                assert_eq!(r.0, 200, "{route} {body} answered {}", r.0);
                shape = (r.0, r.1.len());
            }
            ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            report.insert(
                format!("{route} {body}"),
                json!({"http_status":shape.0,"response_bytes":shape.1,
                "ms":{"p50":percentile(&ms,0.5),"p95":percentile(&ms,0.95),"max":ms[ms.len()-1]}}),
            );
        }
        // Walk every page of the two largest listings.
        for (route, first) in [
            ("inventory", json!({"limit":100})),
            ("changes", json!({"since":"start","limit":100})),
        ] {
            let started = Instant::now();
            let (mut pages, mut rows, mut cursor) = (0, 0, Value::Null);
            let mut page_ms = vec![];
            loop {
                let mut request = first.clone();
                if !cursor.is_null() {
                    request["cursor"] = cursor.clone();
                }
                let page_started = Instant::now();
                let (code, body) = exchange(
                    addr,
                    &format!("/v2/read/{route}"),
                    &secret,
                    &request.to_string(),
                );
                page_ms.push(page_started.elapsed().as_secs_f64() * 1000.0);
                // A page that is not a 200 with a JSON body would silently shorten the walk.
                assert_eq!(code, 200, "{route} page {pages} answered {code}");
                let page: Value = serde_json::from_slice(&body)
                    .unwrap_or_else(|e| panic!("{route} page {pages} is not JSON: {e}"));
                pages += 1;
                rows += page["inventory"]
                    .as_array()
                    .or_else(|| page["changes"].as_array())
                    .map_or(0, Vec::len);
                cursor = page["next_cursor"].clone();
                assert!(pages <= 5000, "{route} walk did not end");
                if cursor.is_null() {
                    break;
                }
            }
            let seconds = started.elapsed().as_secs_f64();
            page_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            report.insert(
                format!("walk {route}"),
                json!({"pages":pages,"rows":rows,"seconds":seconds,
                "page_ms":{"p50":percentile(&page_ms,0.5),"p95":percentile(&page_ms,0.95),"max":page_ms[page_ms.len()-1]}}),
            );
        }
    });
    println!(
        "{}",
        json!({"rounds":rounds,"routes":report,"rss_kib_before":rss_before,
        "rss_kib_after":status_kib("VmRSS"),"peak_rss_kib":status_kib("VmHWM"),"disk":disk(db)})
    );
}

/// `{p50, p95, max}` of milliseconds, null when there are none.
fn spread(ms: &mut [f64]) -> Value {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    match ms.last() {
        None => Value::Null,
        Some(max) => json!({"p50":percentile(ms,0.5),"p95":percentile(ms,0.95),"max":max}),
    }
}

/// Admits `admissions` new assessments, one every `pace_ms`, while a reader walks `changes` over
/// real HTTP back to back (`walk`) or while nothing reads (`idle`, the baseline). The writer is a
/// new device of another organisation, so its admissions stay outside the reader's view and the
/// walk's cursors stay valid; the database lock is shared all the same. A refused (503)
/// admission is counted and tried again, up to 20 times. Prints the admission latencies, the 503
/// count and what the walk saw. Adds one reader grant and one device to DB.
fn admit_during_walk(db: &Path, work: &Path, admissions: usize, pace_ms: u64, walk: bool) {
    fs::create_dir_all(work).unwrap();
    let work = work.canonicalize().unwrap();
    let t0 = now();
    let tag = std::process::id();
    let hub = Hub::open(db).unwrap();
    let invite = format!("synthetic-invite-live-{tag}-perf-fixture-only-0000000");
    let ingest = format!("synthetic-ingest-live-{tag}-perf-fixture-only-0000000");
    hub.invite(&invite, "org-live", "site-live", 3600.0)
        .unwrap();
    let identity = hub.enroll(&invite, &ingest).unwrap();
    let secret = format!("synthetic-reader-perf-{tag}-fixture-only-000000");
    let sites: Vec<Site> = (0..SITES)
        .map(|s| Site {
            org: ORG.into(),
            site: format!("site-{s}"),
        })
        .collect();
    ReaderStore::grant(
        &hub,
        &secret,
        &GrantRequest {
            label: "perf reader",
            sites: &sites,
            devices: DeviceGrant::All,
            sources: SourceGrant::All,
            ttl: 3600.0,
        },
    )
    .unwrap();
    // Everything is produced before the clock starts; only admission runs against the walk.
    let mut store = Store::open(&work.join("producer-live")).unwrap();
    let mut batches = vec![];
    for k in 0..admissions.div_ceil(ASSESSMENTS) {
        let binding = json!({"tenant":"org-live","site":"site-live","device":identity["device"],
            "generation":identity["generation"],"scope":format!("live-{k}"),"source":"src-0"});
        let revs = (admissions - k * ASSESSMENTS).min(ASSESSMENTS);
        batches.push(produce_wires(
            &mut store,
            &work,
            &binding,
            &format!("live-{k}"),
            revs,
            (None, t0),
        ));
    }
    let server = Server::bind(hub, "127.0.0.1", 0, None, None).unwrap();
    let addr = server.local_addr().unwrap();
    let serving = Admission::open(db, vec![]).unwrap();
    let stop = AtomicBool::new(false);
    let (mut admit_ms, mut ok, mut refused, mut other) = (vec![], 0, 0, vec![]);
    let mut seen = json!(null);
    thread::scope(|scope| {
        let _stop_listener = StopListener { stop: &stop, addr };
        scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let _ = server.serve_once_with_admission(&serving);
            }
        });
        let walker = walk.then(|| {
            scope.spawn(|| {
                let started = Instant::now();
                let (mut walks, mut pages, mut failed, mut page_ms) = (0, 0, vec![], vec![]);
                'walks: while !stop.load(Ordering::Acquire) {
                    let mut cursor = Value::Null;
                    loop {
                        if stop.load(Ordering::Acquire) {
                            break 'walks;
                        }
                        let mut request = json!({"since":"start","limit":100});
                        if !cursor.is_null() {
                            request["cursor"] = cursor.clone();
                        }
                        let page_started = Instant::now();
                        let (code, body) =
                            exchange(addr, "/v2/read/changes", &secret, &request.to_string());
                        page_ms.push(page_started.elapsed().as_secs_f64() * 1000.0);
                        if code != 200 {
                            failed.push(code);
                            break;
                        }
                        pages += 1;
                        let page: Value = serde_json::from_slice(&body).unwrap();
                        cursor = page["next_cursor"].clone();
                        if cursor.is_null() {
                            walks += 1;
                            break;
                        }
                    }
                }
                json!({"walks_completed":walks,"pages":pages,"seconds":started.elapsed().as_secs_f64(),
                    "non_200_answers":failed,"page_ms":spread(&mut page_ms)})
            })
        });
        // Let the walk get going before the first admission.
        if walk {
            thread::sleep(Duration::from_secs(2));
        }
        for (captures, wires) in batches {
            let admission = Admission::open(db, captures).unwrap();
            for wire in &wires {
                for attempt in 1..=20 {
                    let started = Instant::now();
                    match admission.admit_at(wire, &format!("{:.9}", now())) {
                        Ok(_) => {
                            ok += 1;
                            admit_ms.push(started.elapsed().as_secs_f64() * 1000.0);
                            break;
                        }
                        Err(e) if e.http_status == Some(503) => {
                            refused += 1;
                            if attempt == 20 {
                                other.push("gave up after 20 refusals".to_string());
                            }
                        }
                        Err(e) => {
                            other.push(e.message);
                            break;
                        }
                    }
                }
                thread::sleep(Duration::from_millis(pace_ms));
            }
        }
        stop.store(true, Ordering::Release);
        if let Some(walker) = walker {
            seen = walker.join().unwrap();
        }
    });
    println!(
        "{}",
        json!({"mode":if walk {"walk"} else {"idle"},"pace_ms":pace_ms,"admissions_requested":admissions,
        "admitted":ok,"refused_503":refused,"other_errors":other,"admit_ms":spread(&mut admit_ms),
        "walk":seen,"schema":vorda::link::native::schema_version(db).ok()})
    );
}

/// Admits `revs` revisions of a lockfile of `records` packages into each of two new devices of the
/// hub at `db` (a new hub when there is none), timing every admission against the one-second
/// budget. One device is delivered oldest first: every revision is published, and the first is
/// timed apart. The other is delivered newest first: all but the first are late, so each is
/// admitted by recomputing its authority from every revision the hub holds by then.
fn full(db: &Path, work: &Path, records: usize, revs: usize, change_log: bool) {
    fs::create_dir_all(work).unwrap();
    let work = work.canonicalize().unwrap();
    let t0 = now();
    let max_bytes = 4096 * 1024 * 1024;
    let hub = Hub::with_limit(db, max_bytes).unwrap();
    let tag = std::process::id();
    let mut identities = vec![];
    for n in 0..2 {
        let invite = format!("synthetic-invite-full-{tag}-{n}-perf-fixture-only-0000000");
        let ingest = format!("synthetic-ingest-full-{tag}-{n}-perf-fixture-only-0000000");
        hub.invite(&invite, ORG, "site-full", 3600.0).unwrap();
        identities.push(hub.enroll(&invite, &ingest).unwrap());
    }
    if native::schema_version(db).unwrap() == 1 {
        native::migrate_with_limit(db, max_bytes).unwrap();
    }
    if change_log && native::schema_version(db).unwrap() == 2 {
        native::migrate_change_log_with_limit(db, max_bytes).unwrap();
    }
    let mut report = serde_json::Map::new();
    for (n, (identity, newest_first)) in identities.iter().zip([false, true]).enumerate() {
        let binding = json!({"tenant":ORG,"site":"site-full","device":identity["device"],
            "generation":identity["generation"],"scope":format!("scope-full-{n}"),"source":"src-0"});
        let mut store = Store::open(&work.join(format!("producer-full-{n}"))).unwrap();
        let mut captures = produce(
            &mut store,
            &work,
            &binding,
            &format!("full-{tag}-{n}"),
            revs,
            (Some(records), t0),
        );
        if newest_first {
            captures.reverse();
        }
        let wires: Vec<_> = captures.iter().zip(1..).map(|(c, s)| wire(c, s)).collect();
        let admission = Admission::open_with_limit(db, captures, max_bytes).unwrap();
        let (mut first, mut rest, mut results) = (None, vec![], BTreeMap::<String, usize>::new());
        for wire in &wires {
            let started = Instant::now();
            let ack = admission
                .admit_at(wire, &format!("{:.9}", now()))
                .unwrap_or_else(|e| panic!("admission refused: {} {:?}", e.message, e.http_status));
            let took = started.elapsed().as_secs_f64() * 1000.0;
            *results
                .entry(
                    serde_json::from_slice::<Value>(&ack).unwrap()["result"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                )
                .or_default() += 1;
            if first.is_none() {
                first = Some(took);
            } else {
                rest.push(took);
            }
        }
        report.insert(
            if newest_first {
                "newest_first"
            } else {
                "in_order"
            }
            .into(),
            json!({"results":results,"first_ms":first,"later_ms":spread(&mut rest)}),
        );
    }
    println!(
        "{}",
        json!({"records_per_assessment":records,"revisions":revs,"change_log":change_log,
        "schema":native::schema_version(db).ok(),"runs":report,"process_peak_rss_kib":status_kib("VmHWM"),
        "disk":disk(db)})
    );
}

/// Walks `changes` on a schema 2 hub and on a copy of it that has gained the change log, at one
/// fixed clock, and checks that every page is the same text, cursors included. Panics on the
/// first page that differs; otherwise prints, per walk, the pages, rows and a digest of the text.
fn compare_changes(db: &Path) {
    let hub = Hub::open(db).unwrap();
    let secret = "synthetic-reader-compare-fixture-only-000000";
    let sites: Vec<Site> = (0..SITES)
        .map(|s| Site {
            org: ORG.into(),
            site: format!("site-{s}"),
        })
        .collect();
    ReaderStore::grant(
        &hub,
        secret,
        &GrantRequest {
            label: "compare reader",
            sites: &sites,
            devices: DeviceGrant::All,
            sources: SourceGrant::All,
            ttl: 3600.0,
        },
    )
    .unwrap();
    let beside = |suffix: &str| {
        let mut name = db.as_os_str().to_owned();
        name.push(suffix);
        std::path::PathBuf::from(name)
    };
    let with_log = beside(".with-log");
    fs::copy(db, &with_log).unwrap();
    fs::copy(beside(".readers"), beside(".with-log.readers")).unwrap();
    native::migrate_change_log(&with_log).unwrap();
    let log_hub = Hub::open(&with_log).unwrap();
    let (plain, logged) = (
        ReaderStore::open(db).unwrap().authorize(secret).unwrap(),
        ReaderStore::open(&with_log)
            .unwrap()
            .authorize(secret)
            .unwrap(),
    );
    let conn = Connection::open(db).unwrap();
    let device: String = conn
        .query_row("SELECT id FROM devices ORDER BY id LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let median: f64 = conn
        .query_row(
            "SELECT CAST(received AS REAL) FROM v2_assessments ORDER BY 1 LIMIT 1 OFFSET (SELECT count(*)/2 FROM v2_assessments)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let at = now();
    let cases: [(&str, ChangeFilter, Since); 5] = [
        ("start", ChangeFilter::default(), Since::Start),
        (
            "since the median receipt",
            ChangeFilter::default(),
            Since::Time(median),
        ),
        (
            "site-0",
            ChangeFilter {
                sites: vec!["site-0".into()],
                ..Default::default()
            },
            Since::Start,
        ),
        (
            "one device",
            ChangeFilter {
                devices: vec![device],
                ..Default::default()
            },
            Since::Start,
        ),
        (
            "source src-0",
            ChangeFilter {
                sources: vec!["src-0".into()],
                ..Default::default()
            },
            Since::Time(median),
        ),
    ];
    let mut report = serde_json::Map::new();
    for (name, filter, since) in &cases {
        let (mut pages, mut rows, mut cursor) = (0, 0, None::<String>);
        let mut digest = Sha256::new();
        loop {
            let request = PageRequest {
                limit: Some(100),
                cursor: cursor.as_deref(),
            };
            let a = fleet_changes(&hub, &plain, filter, since, &request, at).unwrap();
            let b = fleet_changes(&log_hub, &logged, filter, since, &request, at).unwrap();
            assert_eq!(
                a.to_string(),
                b.to_string(),
                "{name}: page {pages} differs with the change log"
            );
            digest.update(a.to_string().as_bytes());
            pages += 1;
            rows += a["changes"].as_array().map_or(0, Vec::len);
            cursor = a["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        report.insert(
            name.to_string(),
            json!({"pages":pages,"rows":rows,"sha256":format!("{:x}",digest.finalize())}),
        );
    }
    println!(
        "{}",
        json!({"identical_with_and_without_log":true,"walks":report})
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("admit") => admit(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args.get(4).map(|rows| rows.parse().unwrap()),
            args.get(5).map_or(1024, |mib| mib.parse().unwrap()),
            args.get(6..).unwrap_or_default().iter().any(|flag| flag == "change-log"),
            if args.get(6..).unwrap_or_default().iter().any(|flag| flag == "lockfile") {
                LOCKFILE
            } else {
                SMALL
            },
        ),
        Some("full") => full(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
            args.get(6..).unwrap_or_default().iter().any(|flag| flag == "change-log"),
        ),
        Some("verify-log") => verify_log(Path::new(&args[2])),
        Some("clone") => clone_rows(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].parse().unwrap(),
        ),
        Some("query") => query(
            Path::new(&args[2]),
            args.get(3).map_or(20, |r| r.parse().unwrap()),
        ),
        Some("compare-changes") => compare_changes(Path::new(&args[2])),
        Some("admit-during-walk") => admit_during_walk(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args.get(4).map_or(256, |n| n.parse().unwrap()),
            args.get(5).map_or(50, |ms| ms.parse().unwrap()),
            args.get(6).is_none_or(|mode| mode != "idle"),
        ),
        _ => eprintln!(
            "usage: perf_hub admit DB WORKDIR [TARGET_ROWS [MAX_DB_MIB [change-log] [lockfile]]] | full DB WORKDIR RECORDS REVISIONS [change-log] | verify-log DB | clone FROM TO ROWS | query DB [ROUNDS] | compare-changes DB | admit-during-walk DB WORKDIR [ADMISSIONS [PACE_MS [idle]]]"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A panic in the scope body (a failed assertion on a non-200 answer) must not leave the
    /// process waiting for a listener thread that is blocked in `accept`.
    #[test]
    fn a_panic_in_the_scope_still_stops_the_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            thread::scope(|scope| {
                let _stop_listener = StopListener { stop: &stop, addr };
                scope.spawn(|| {
                    while !stop.load(Ordering::Acquire) {
                        let _ = listener.accept();
                    }
                });
                panic!("answered 503");
            });
        }));
        assert!(outcome.is_err());
        assert!(stop.load(Ordering::Acquire));
    }
}
