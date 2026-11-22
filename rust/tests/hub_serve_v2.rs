mod common;
use common::{body, canonical, hash, status};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use vorda::{
    link::{
        client::Outbox,
        grants::CaptureGrants,
        native::{self, Admission, TrustedCapture},
        server::Server,
        storage::Hub,
    },
    store::{capture, Store},
};

const INVITE: &str = "synthetic-invite-only-0000000000000000000";
const DEVICE: &str = "synthetic-device-only-0000000000000000000";

struct World {
    _tmp: tempfile::TempDir,
    db: PathBuf,
    binding: Value,
    raw: String,
    evidence: String,
    v2_request: Vec<u8>,
    outbox: Outbox,
    batch7: Value,
    ack7: Vec<u8>,
}
fn v1_world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("hub.db");
    let hub = Hub::open(&db).unwrap();
    hub.invite(INVITE, "test-org", "test-site", 60.0).unwrap();
    let enrolled = hub.enroll(INVITE, DEVICE).unwrap();
    let binding = json!({"tenant":"test-org","site":"test-site","device":enrolled["device"],"generation":enrolled["generation"],"scope":"test-scope","source":"test-npm"});

    let root = tmp.path().join("root");
    fs::create_dir_all(root.join("one")).unwrap();
    fs::write(
        root.join("one/package-lock.json"),
        include_bytes!("fixtures/capture/L1.json"),
    )
    .unwrap();
    let mut store = Store::open(&tmp.path().join("producer")).unwrap();
    let outcome = capture::capture(&mut store, &serde_json::to_vec(&json!({"token":"capture-1","binding":binding,"root":root.canonicalize().unwrap(),"inputs":["one/package-lock.json"],"observed_at":"1793898285.4219873","completed_at":"1793898285.5764945"})).unwrap()).unwrap();
    let export = tmp.path().join("export.json");
    capture::export(
        &mut store,
        outcome["snapshot_id"].as_str().unwrap(),
        &export,
    )
    .unwrap();
    let view: Value = serde_json::from_slice(&fs::read(export).unwrap()).unwrap();
    let evidence = view["evidence"][0]["evidence_id"]
        .as_str()
        .unwrap()
        .to_string();
    let raw = view["retained_payload_utf8"][&evidence]
        .as_str()
        .unwrap()
        .to_string();
    let v2_request = canonical(
        &json!({"schema":2,"binding":binding,"sequence":1,"evidence_id":evidence,"artifact_sha256":hash(raw.as_bytes()),"artifact_byte_length":raw.len(),"artifact_utf8":raw}),
    );

    let outbox = Outbox::open(&tmp.path().join("outbox.db")).unwrap();
    outbox
        .bind(
            binding["device"].as_str().unwrap(),
            binding["generation"].as_str().unwrap(),
        )
        .unwrap();
    outbox
        .database
        .connect()
        .unwrap()
        .execute("UPDATE identity SET sequence=6", [])
        .unwrap();
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/capture/V1.json")).unwrap();
    batch["device"] = binding["device"].clone();
    batch["generation"] = binding["generation"].clone();
    let batch7 = outbox.enqueue(&batch).unwrap();
    assert_eq!(batch7["sequence"], 7);
    let ack7 = hub.ingest(DEVICE, &batch7).unwrap();
    batch["scan"] = json!("00000000-0000-4000-8000-000000000008");
    assert_eq!(outbox.enqueue(&batch).unwrap()["sequence"], 8);

    assert_eq!(user_version(&db), 1);
    World {
        _tmp: tmp,
        db,
        binding,
        raw,
        evidence,
        v2_request,
        outbox,
        batch7,
        ack7,
    }
}
fn world() -> World {
    let w = v1_world();
    native::migrate(&w.db).unwrap();
    assert_eq!(user_version(&w.db), 2);
    w
}
impl World {
    fn admission(&self) -> Admission {
        Admission::open(
            &self.db,
            vec![TrustedCapture {
                binding: self.binding.clone(),
                evidence_id: self.evidence.clone(),
                artifact_utf8: self.raw.clone(),
            }],
        )
        .unwrap()
    }
    fn drain(&self, addr: SocketAddr) -> bool {
        self.outbox
            .drain(&format!("http://{addr}"), DEVICE, None)
            .unwrap()
    }
    fn pending(&self) -> Vec<i64> {
        let db = Connection::open(&self.outbox.database.path).unwrap();
        let mut query = db
            .prepare("SELECT sequence FROM pending ORDER BY sequence")
            .unwrap();
        let sequences = query
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        sequences
    }
}
fn user_version(db: &Path) -> i64 {
    Connection::open(db)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}
fn rows(db: &Path, tables: &[&str]) -> Value {
    let db = Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut out = serde_json::Map::new();
    for table in tables {
        let mut query = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
            .unwrap();
        let columns = query.column_count();
        let all: Vec<Value> = query
            .query_map([], |r| {
                Ok(json!((0..columns)
                    .map(|i| match r.get_ref(i).unwrap() {
                        rusqlite::types::ValueRef::Null => Value::Null,
                        rusqlite::types::ValueRef::Integer(v) => json!(v),
                        rusqlite::types::ValueRef::Real(v) => json!(v),
                        rusqlite::types::ValueRef::Text(v) => json!(String::from_utf8_lossy(v)),
                        rusqlite::types::ValueRef::Blob(v) => json!(hash(v)),
                    })
                    .collect::<Vec<_>>()))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        out.insert(table.to_string(), json!(all));
    }
    Value::Object(out)
}
const V1: &[&str] = &[
    "devices",
    "credentials",
    "batches",
    "scans",
    "findings",
    "coverage",
];
const V2: &[&str] = &[
    "v2_authorities",
    "v2_assessments",
    "v2_observations",
    "v2_current",
    "v2_coverage",
    "v2_deliveries",
    "v2_views",
];
const V2_DURABLE: &[&str] = &[
    "v2_authorities",
    "v2_assessments",
    "v2_observations",
    "v2_deliveries",
    "v2_views",
];

fn serving<R>(w: &World, run: impl FnOnce(SocketAddr) -> R) -> R {
    serving_with(w, w.admission(), run)
}
/// An in-process listener whose operator granted the world's device its source, as `capture-allow` does.
fn serving_with<R>(w: &World, admission: Admission, run: impl FnOnce(SocketAddr) -> R) -> R {
    CaptureGrants::allow(
        &w.db,
        w.binding["device"].as_str().unwrap(),
        w.binding["source"].as_str().unwrap(),
    )
    .unwrap();
    let admission = admission.with_grants(CaptureGrants::open(&w.db).unwrap());
    let server = Server::bind(Hub::open(&w.db).unwrap(), "127.0.0.1", 0, None, None).unwrap();
    let addr = server.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let _ = server.serve_once_with_admission(&admission);
            }
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(addr)));
        stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(addr); // wake the blocked accept
        handle.join().unwrap();
        match result {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e),
        }
    })
}
fn exchange(addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    s.write_all(bytes).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = vec![];
    s.read_to_end(&mut out).unwrap();
    out
}
fn post(route: &str, credential: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {credential}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend(body);
    wire
}
fn v2(w: &World, addr: SocketAddr) -> Vec<u8> {
    let response = exchange(addr, &post("/v2/batches", DEVICE, &w.v2_request));
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    native::validate_ack(&w.v2_request, body(&response)).unwrap();
    body(&response).to_vec()
}
fn v1_replay(w: &World, addr: SocketAddr) -> Vec<u8> {
    let response = exchange(
        addr,
        &post(
            "/v1/batches",
            DEVICE,
            &vorda::link::encode(&w.batch7).unwrap(),
        ),
    );
    assert_eq!(status(&response), 200);
    body(&response).to_vec()
}

#[test]
fn legacy_v1_queue_delivers_after_upgrade() {
    let w = world();
    let before = rows(&w.db, V1);
    serving(&w, |addr| {
        assert!(w.drain(addr), "sequence 7 replay");
        assert_eq!(w.pending(), vec![8]);
        assert!(w.drain(addr), "sequence 8");
    });
    assert_eq!(w.pending(), Vec::<i64>::new());
    let after = rows(&w.db, V1);
    let ack = |state: &Value, sequence: u64| {
        state["batches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r[1] == sequence)
            .cloned()
    };
    assert_eq!(
        ack(&before, 7),
        ack(&after, 7),
        "sequence 7 ACK row survives the upgrade untouched"
    );
    assert_eq!(ack(&before, 8), None);
    assert!(ack(&after, 8).is_some());
    assert_eq!(after["devices"][0][5], 8);
    let stored7: Vec<u8> = Connection::open(&w.db)
        .unwrap()
        .query_row("SELECT ack FROM batches WHERE sequence=7", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored7, w.ack7);
    for (table, rows) in rows(&w.db, V2).as_object().unwrap() {
        assert_eq!(rows, &json!([]), "{table}");
    }
}

#[test]
fn v2_batch_is_accepted_durably_and_replays_identically() {
    let w = world();
    let (ack, replay) = serving(&w, |addr| {
        let unknown = exchange(
            addr,
            &post(
                "/v2/batches",
                "synthetic-unknown-only-000000000000000000",
                &w.v2_request,
            ),
        );
        assert_eq!(status(&unknown), 401);
        assert_eq!(rows(&w.db, V2)["v2_deliveries"], json!([]));
        (v2(&w, addr), v2(&w, addr))
    });
    assert_eq!(ack, replay);
    let parsed: Value = serde_json::from_slice(&ack).unwrap();
    assert_eq!(
        (parsed["sequence"].clone(), parsed["result"].clone()),
        (json!(1), json!("published"))
    );
    let state = rows(&w.db, V2);
    for table in V2_DURABLE {
        assert!(
            !state[*table].as_array().unwrap().is_empty(),
            "{table} is durable"
        );
    }
    assert_eq!(state["v2_deliveries"].as_array().unwrap().len(), 1);
}

#[test]
fn v1_then_v2_then_v1_each_leave_the_other_untouched() {
    let w = world();
    serving(&w, |addr| {
        assert!(w.drain(addr));
        let v1_state = rows(&w.db, V1);
        let first = v2(&w, addr);
        assert_eq!(rows(&w.db, V1), v1_state, "v2 changed v1 state");
        let v2_state = rows(&w.db, V2);
        assert!(w.drain(addr));
        assert_eq!(w.pending(), Vec::<i64>::new());
        assert_eq!(rows(&w.db, V2), v2_state, "v1 changed v2 state");
        assert_eq!(v2(&w, addr), first);
        assert_eq!(v1_replay(&w, addr), w.ack7);
    });
}

#[test]
fn restart_on_the_same_database_replays_both_versions() {
    let w = world();
    let first = serving(&w, |addr| {
        assert!(w.drain(addr));
        v2(&w, addr)
    });
    let state = (rows(&w.db, V1), rows(&w.db, V2));
    assert_eq!(state.0["devices"][0][5], 7);
    serving(&w, |addr| {
        assert_eq!(v2(&w, addr), first);
        assert_eq!(v1_replay(&w, addr), w.ack7);
        assert!(
            w.drain(addr),
            "sequence 8 is still queued and still deliverable"
        );
    });
    assert_eq!(rows(&w.db, V2), state.1);
    assert_eq!(w.pending(), Vec::<i64>::new());
    assert_eq!(rows(&w.db, V1)["devices"][0][5], 8);
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spawn_serve(db: &Path, port: u16) -> Child {
    spawn_serve_with(db, port, &[])
}
fn spawn_serve_with(db: &Path, port: u16, extra: &[&str]) -> Child {
    Child(
        std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
            .args([
                "link",
                "--db",
                db.to_str().unwrap(),
                "serve",
                "--port",
                &port.to_string(),
            ])
            .args(extra)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn launch(db: &Path) -> (Child, SocketAddr) {
    launch_with(db, &[])
}
fn launch_with(db: &Path, extra: &[&str]) -> (Child, SocketAddr) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = spawn_serve_with(db, port, extra);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..100 {
        if TcpStream::connect(addr).is_ok() {
            // The probe consumed one sequential accept; let the server return to accept.
            thread::sleep(Duration::from_millis(100));
            return (child, addr);
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("link serve did not start");
}

#[test]
fn newer_schema_refuses_to_serve_and_is_not_modified() {
    let w = world();
    Connection::open(&w.db)
        .unwrap()
        .pragma_update(None, "user_version", 3)
        .unwrap();
    let bytes = fs::read(&w.db).unwrap();
    assert!(Hub::open(&w.db).is_err());
    assert!(Admission::open(&w.db, vec![]).is_err());
    let mut child = spawn_serve(&w.db, 0);
    let mut waited = 0;
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            waited < 100,
            "link serve kept running on a newer schema instead of refusing"
        );
        waited += 1;
        thread::sleep(Duration::from_millis(100));
    };
    assert!(!status.success(), "link serve must refuse a newer schema");
    assert_eq!(fs::read(&w.db).unwrap(), bytes);
}

#[test]
fn v1_request_errors_match_the_legacy_server_byte_for_byte() {
    let w = world();
    let legacy_db = w._tmp.path().join("legacy.db");
    Hub::open(&legacy_db).unwrap();
    let legacy = Server::bind(Hub::open(&legacy_db).unwrap(), "127.0.0.1", 0, None, None).unwrap();
    let legacy_addr = legacy.local_addr().unwrap();
    let cases: Vec<Vec<u8>> = vec![
        b"GET /v1/batches HTTP/1.1\r\n\r\n".to_vec(),
        b"POST /v1/batches\r\n\r\n".to_vec(),
        b"POST /v1/batches HTTP/1.1 extra\r\n\r\n".to_vec(),
        b"POST /v1/other HTTP/1.1\r\n\r\n".to_vec(),
        b"POST /v1/batchesX HTTP/1.1\r\n\r\n".to_vec(),
        b"POST /V1/batches HTTP/1.1\r\n\r\n".to_vec(),
        b"POSTX /v1/batches HTTP/1.1\r\n\r\n".to_vec(),
        b"\r\n".to_vec(),
        b"POST /v1/batches HTTP/1.1".to_vec(),
        b"POST /v1/\xff HTTP/1.1\r\n\r\n".to_vec(),
        b"POST\t/v1/batches\tHTTP/1.1\r\n\r\n".to_vec(),
        "POST\u{2003}/v1/enroll  HTTP/1.1\r\n\r\n".as_bytes().to_vec(),
        b"POST /v1/batches HTTP/1.1\nContent-Length: 2\n\n{}".to_vec(),
        b"POST /v1/batches HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"POST /v1/batches HTTP/1.1\r\nAuthorization: Bearer x\r\n\r\n".to_vec(),
        b"POST /v1/batches HTTP/1.1\r\nAuthorization: Bearer x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        post("/v1/enroll", "x", b"{\"credential\":\"short\"}"),
        post("/v1/batches", DEVICE, b"{}"),
        post("/v1/batches", DEVICE, b"not json"),
    ];
    for case in cases {
        let (old, new) = thread::scope(|scope| {
            let h = scope.spawn(|| legacy.serve_once());
            let old = exchange(legacy_addr, &case);
            h.join().unwrap().ok();
            let new = serving(&w, |addr| exchange(addr, &case));
            (old, new)
        });
        assert!(!old.is_empty());
        assert_eq!(old, new, "{:?}", String::from_utf8_lossy(&case));
    }
}

#[test]
fn link_serve_selects_the_route_set_from_the_hub_schema() {
    let w = world();
    let (_child, addr) = launch(&w.db);
    assert!(
        w.drain(addr),
        "v1 delivers through link serve on a schema-2 hub"
    );
    let refused = exchange(addr, &post("/v2/batches", DEVICE, &w.v2_request));
    assert_eq!(
        status(&refused),
        403,
        "{}",
        String::from_utf8_lossy(&refused)
    );
    assert_eq!(rows(&w.db, V2)["v2_deliveries"], json!([]));

    let legacy = tempfile::tempdir().unwrap();
    let db = legacy.path().join("hub.db");
    let hub = Hub::open(&db).unwrap();
    hub.invite(INVITE, "o", "s", 60.0).unwrap();
    hub.enroll(INVITE, DEVICE).unwrap();
    let (_child, addr) = launch(&db);
    let missing = exchange(addr, &post("/v2/batches", DEVICE, b"{}"));
    assert_eq!(status(&missing), 404);
}

fn link(db: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args(["link", "--db", db.to_str().unwrap()])
        .args(args)
        .output()
        .unwrap()
}
fn failed_copy(db: &Path) -> PathBuf {
    PathBuf::from(format!("{}.failed-v2", db.display()))
}
fn refused(db: &Path, args: &[&str], reason: &str) {
    let before = fs::read(db).unwrap();
    let out = link(db, args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains(reason),
        "{args:?}: {stderr}"
    );
    assert_eq!(
        fs::read(db).unwrap(),
        before,
        "a refused {args:?} must not touch the database"
    );
    assert!(!failed_copy(db).exists());
}

#[test]
fn operator_commands_upgrade_and_roll_back_through_the_cli() {
    let w = v1_world();
    {
        let (_server, addr) = launch(&w.db);
        assert_eq!(
            status(&exchange(addr, &post("/v2/batches", DEVICE, b"{}"))),
            404
        );
    }
    let before = rows(&w.db, V1);
    assert!(link(&w.db, &["migrate"]).status.success());
    assert_eq!(user_version(&w.db), 2);
    assert!(
        link(&w.db, &["migrate"]).status.success(),
        "migrate is idempotent"
    );
    {
        let (_server, addr) = launch(&w.db);
        assert!(
            w.drain(addr) && w.drain(addr),
            "sequences 7 (replay) and 8 (new) over v1"
        );
    }
    serving(&w, |addr| v2(&w, addr));
    let live = fs::read(&w.db).unwrap();
    assert_eq!(rows(&w.db, V1)["devices"][0][5], 8);

    refused(&w.db, &["restore"], "--discard-post-upgrade");
    assert_eq!(user_version(&w.db), 2);

    assert!(link(&w.db, &["restore", "--discard-post-upgrade"])
        .status
        .success());
    assert_eq!(user_version(&w.db), 1);
    assert_eq!(rows(&w.db, V1), before, "the pre-upgrade state is back");
    assert_eq!(
        fs::read(failed_copy(&w.db)).unwrap(),
        live,
        "the live database is kept beside it"
    );
    let (_server, addr) = launch(&w.db);
    assert_eq!(v1_replay(&w, addr), w.ack7);
    assert_eq!(
        status(&exchange(addr, &post("/v2/batches", DEVICE, b"{}"))),
        404
    );
}

#[test]
fn restore_refuses_after_a_v2_delivery_alone() {
    let w = world();
    serving(&w, |addr| v2(&w, addr));
    refused(&w.db, &["restore"], "--discard-post-upgrade");
}

#[test]
fn restore_refuses_after_a_v1_write_alone() {
    let w = world();
    {
        let (_server, addr) = launch(&w.db);
        assert!(w.drain(addr) && w.drain(addr));
    }
    refused(&w.db, &["restore"], "--discard-post-upgrade");
}

#[test]
fn restore_needs_no_flag_when_nothing_was_written_after_the_upgrade() {
    let w = world();
    let backup = fs::read(format!("{}.v1-backup", w.db.display())).unwrap();
    assert!(link(&w.db, &["restore"]).status.success());
    assert_eq!(fs::read(&w.db).unwrap(), backup);
    assert!(failed_copy(&w.db).exists());
}

#[test]
fn operator_commands_refuse_while_the_hub_is_in_use() {
    let w = v1_world();
    {
        let (_server, _) = launch(&w.db);
        refused(&w.db, &["migrate"], "stop link serve first");
        assert_eq!(user_version(&w.db), 1);
    }
    assert!(
        link(&w.db, &["migrate"]).status.success(),
        "the lock dies with the server"
    );
    {
        let (_server, _) = launch(&w.db);
        refused(
            &w.db,
            &["restore", "--discard-post-upgrade"],
            "stop link serve first",
        );
    }
    // An admission in flight holds the database-file lock.
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&w.db)
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&file).unwrap();
    refused(&w.db, &["restore", "--discard-post-upgrade"], "locked");
    drop(file);
    assert!(link(&w.db, &["restore", "--discard-post-upgrade"])
        .status
        .success());
}

#[test]
fn migrate_on_an_upgraded_hub_only_verifies_after_traffic() {
    let w = v1_world();
    assert!(link(&w.db, &["migrate"]).status.success());
    {
        let (_server, addr) = launch(&w.db);
        assert!(w.drain(addr) && w.drain(addr));
    }
    serving(&w, |addr| v2(&w, addr));
    let live = fs::read(&w.db).unwrap();
    assert!(
        link(&w.db, &["migrate"]).status.success(),
        "migrate after v1 and v2 traffic"
    );
    assert_eq!(fs::read(&w.db).unwrap(), live);
}

#[test]
fn migrate_with_change_log_upgrades_to_schema_3_and_restore_drops_it_through_the_cli() {
    let w = v1_world();
    // The flag belongs to migrate alone; a refused argument touches nothing.
    let before = fs::read(&w.db).unwrap();
    for action in ["serve", "restore", "revoke"] {
        assert!(!link(&w.db, &[action, "--change-log"]).status.success());
    }
    assert_eq!(fs::read(&w.db).unwrap(), before);
    assert!(link(&w.db, &["migrate", "--change-log"]).status.success());
    assert_eq!(user_version(&w.db), 3);
    {
        let (_server, addr) = launch(&w.db);
        assert!(
            w.drain(addr) && w.drain(addr),
            "v1 traffic on a schema 3 hub"
        );
        assert_ne!(
            status(&exchange(addr, &post("/v2/batches", DEVICE, b"{}"))),
            404,
            "a schema 3 hub serves v2"
        );
    }
    serving(&w, |addr| v2(&w, addr));
    let logged = |db: &Path| -> i64 {
        Connection::open(db)
            .unwrap()
            .query_row("SELECT count(*) FROM v2_changes", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(logged(&w.db), 1, "the admission wrote its change row");
    let live = fs::read(&w.db).unwrap();
    assert!(link(&w.db, &["migrate"]).status.success());
    assert!(link(&w.db, &["migrate", "--change-log"]).status.success());
    assert_eq!(
        fs::read(&w.db).unwrap(),
        live,
        "migrate on schema 3 only verifies"
    );

    // The flag has nothing to discard on schema 3: say so rather than ignore it.
    refused(
        &w.db,
        &["restore", "--discard-post-upgrade"],
        "does not apply to a schema 3 hub",
    );
    assert_eq!(user_version(&w.db), 3);
    // The log goes first, without a flag: it is derived, so no admission is lost.
    assert!(link(&w.db, &["restore"]).status.success());
    assert_eq!(user_version(&w.db), 2);
    assert_eq!(
        rows(&w.db, V2)["v2_deliveries"].as_array().unwrap().len(),
        1
    );
    refused(&w.db, &["restore"], "--discard-post-upgrade");
    assert!(link(&w.db, &["restore", "--discard-post-upgrade"])
        .status
        .success());
    assert_eq!(user_version(&w.db), 1);
}

#[test]
fn restore_refuses_after_a_revocation_alone() {
    let w = world();
    let device = w.binding["device"].as_str().unwrap();
    assert!(link(&w.db, &["revoke", "--device", device])
        .status
        .success());
    refused(&w.db, &["restore"], "--discard-post-upgrade");
}

#[test]
fn hub_commands_share_the_serve_lock_and_exclude_restore() {
    let w = world();
    let device = w.binding["device"].as_str().unwrap();
    let lock_path = format!("{}.serve-lock", w.db.display());
    let held = |exclusive: bool| {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        if exclusive {
            fs2::FileExt::try_lock_exclusive(&file).unwrap();
        } else {
            fs2::FileExt::try_lock_shared(&file).unwrap();
        }
        file
    };
    {
        let (_server, _) = launch(&w.db);
        assert!(
            link(&w.db, &["snapshot", "--device", device])
                .status
                .success(),
            "coexists with link serve"
        );
    }
    drop(held(false));
    {
        let _writer = held(false); // a revoke in flight
        refused(
            &w.db,
            &["restore", "--discard-post-upgrade"],
            "stop link serve first",
        );
    }
    {
        let _restore = held(true);
        refused(
            &w.db,
            &["revoke", "--device", device],
            "migrated or restored",
        );
    }
    assert!(link(&w.db, &["revoke", "--device", device])
        .status
        .success());
}

#[test]
fn hub_commands_still_create_a_missing_database_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("new-dir/nested/hub.db");
    let secret = "synthetic-invite-only-0000000000000000000";
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args([
            "link",
            "--db",
            db.to_str().unwrap(),
            "invite",
            "--org",
            "o",
            "--site",
            "s",
            "--invite-env",
            "SYNTH_INVITE",
        ])
        .env("SYNTH_INVITE", secret)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(user_version(&db), 1);
}

#[test]
fn discard_flag_is_accepted_only_by_restore() {
    let tmp = tempfile::tempdir().unwrap();
    let result = tmp.path().join("result.json");
    fs::write(
        &result,
        json!({"scan_scope":"s","findings":[],"status":"no-known-findings","coverage_evidence":{"status":"complete"},"inventory_observed_at":vorda::store::now()}).to_string(),
    )
    .unwrap();
    let result = result.to_str().unwrap();
    for action in ["export", "queue"] {
        let outbox = tmp.path().join(format!("{action}.db"));
        Outbox::open(&outbox)
            .unwrap()
            .bind("test-device", "g-1")
            .unwrap();
        let queued = || -> i64 {
            Connection::open(&outbox)
                .unwrap()
                .query_row("SELECT count(*) FROM pending", [], |r| r.get(0))
                .unwrap()
        };
        let args = [action, "--result", result, "--consent"];
        let refused = link(&outbox, &[&args[..], &["--discard-post-upgrade"]].concat());
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            refused.status.code() == Some(64) && stderr.contains("usage_error"),
            "{action}: {stderr}"
        );
        assert_eq!(queued(), 0, "{action}: a refused flag must do nothing");
        let accepted = link(&outbox, &args);
        assert!(
            accepted.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        assert_eq!(queued(), i64::from(action == "queue"));
    }
}

// m5s2: evidence-integrity pins at admission. Every refusal leaves the hub exactly as it was.

fn all_rows(db: &Path) -> Value {
    let tables: Vec<&str> = V1.iter().chain(V2).copied().collect();
    rows(db, &tables)
}
/// Envelope for an artifact text: integrity fields and canonical form are correct unless the test changes them.
fn envelope(w: &World, raw: &str, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut q: Value = serde_json::from_slice(&w.v2_request).unwrap();
    q["artifact_utf8"] = json!(raw);
    q["artifact_sha256"] = json!(hash(raw.as_bytes()));
    q["artifact_byte_length"] = json!(raw.len());
    edit(&mut q);
    canonical(&q)
}
fn artifact(w: &World, edit: impl FnOnce(&mut Value)) -> String {
    let mut a: Value = serde_json::from_str(&w.raw).unwrap();
    edit(&mut a);
    String::from_utf8(canonical(&a)).unwrap()
}
/// Post `wire` to the in-process listener that trusts the world's own capture (plus `extra`), and require the hub
/// to be byte-for-byte what it was.
fn refusal_by(w: &World, wire: &[u8], admission: Admission) -> (u16, String) {
    let before = all_rows(&w.db);
    let response = serving_with(w, admission, |addr| {
        exchange(addr, &post("/v2/batches", DEVICE, wire))
    });
    assert_eq!(all_rows(&w.db), before, "a refused post changed the hub");
    let reply: Value = serde_json::from_slice(body(&response)).unwrap();
    (
        status(&response),
        reply["error"].as_str().unwrap().to_string(),
    )
}
fn refusal(w: &World, wire: &[u8]) -> (u16, String) {
    refusal_by(w, wire, w.admission())
}

// m6s1: the byte ceiling is configurable. Hubs here are filled with inert rows up to a ceiling
// instead of through hundreds of admissions; the ceiling check does not care what the rows are.

const MIB: u64 = 1024 * 1024;
// The big statement takes a unique id (?1) and a size (?2). The small v1 rows fill the last page of the
// tables a v1 delivery writes, so that the next row of the delivery needs a page of its own.
const PAD_V1: &str = "INSERT INTO findings VALUES('pad',?1,'s',zeroblob(?2))";
const PAD_V1_ROWS: [&str; 5] = [
    "INSERT INTO batches VALUES('pad',?1+0*?2,'d',x'7b7d')",
    "INSERT INTO scans VALUES('pad',?1+0*?2)",
    "INSERT INTO findings VALUES('pad',?1+0*?2,'s',x'7b7d')",
    "INSERT INTO coverage VALUES('pad',?1+0*?2,'s')",
    "INSERT INTO audit VALUES(?1+0*?2,'pad','a')",
];
const PAD_V2: &str = "INSERT INTO v2_assessments VALUES('pad',?1,?1,?1,'d',zeroblob(?2),x'5b5d','1','published',x'7b7d')";
/// Grows the database until SQLite itself refuses another page at `ceiling` bytes.
fn fill_to_ceiling(db: &Path, ceiling: u64, big: &str, rows: &[&str]) {
    let c = Connection::open(db).unwrap();
    let page: u64 = c
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    c.pragma_update(None, "max_page_count", ceiling / page)
        .unwrap();
    let mut id = 0_i64;
    for size in [MIB, MIB / 16, MIB / 256, MIB / 4096] {
        while c.execute(big, rusqlite::params![id, size as i64]).is_ok() {
            id += 1;
        }
    }
    // No page is left to allocate, so each of these stops when its table's last page is full.
    for row in rows {
        while c.execute(row, rusqlite::params![id, 0]).is_ok() {
            id += 1;
        }
    }
    let len = fs::metadata(db).unwrap().len();
    assert!(len <= ceiling && ceiling - len < page, "{len} vs {ceiling}");
}
/// The pending v1 batch of an outbox as the wire carries it.
fn pending_wire(w: &World, sequence: i64) -> Vec<u8> {
    let raw: Vec<u8> = Connection::open(&w.outbox.database.path)
        .unwrap()
        .query_row(
            "SELECT payload FROM pending WHERE sequence=?",
            [sequence],
            |r| r.get(0),
        )
        .unwrap();
    post(
        "/v1/batches",
        DEVICE,
        &vorda::link::encode(&serde_json::from_slice::<Value>(&raw).unwrap()).unwrap(),
    )
}

#[test]
fn a_native_hub_at_its_configured_ceiling_answers_503_and_keeps_its_data() {
    let w = world();
    fill_to_ceiling(&w.db, 16 * MIB, PAD_V2, &PAD_V1_ROWS);
    let capture = || {
        vec![TrustedCapture {
            binding: w.binding.clone(),
            evidence_id: w.evidence.clone(),
            artifact_utf8: w.raw.clone(),
        }]
    };
    let before = all_rows(&w.db);
    let full = Admission::open_with_limit(&w.db, capture(), 16 * MIB).unwrap();
    let error = full
        .admit_at(&w.v2_request, "1793898286.000000000")
        .unwrap_err();
    assert_eq!(
        (error.http_status, error.message.as_str()),
        (Some(503), "storage_failure")
    );
    assert_eq!(all_rows(&w.db), before, "the refused admission wrote");
    let full = Admission::open_with_limit(&w.db, capture(), 16 * MIB).unwrap();
    assert_eq!(
        refusal_by(&w, &w.v2_request, full),
        (503, "storage unavailable; retry later".into())
    );
    // Only the ceiling refused it: the same request is admitted when the ceiling is the default.
    serving(&w, |addr| {
        v2(&w, addr);
    });
    assert_eq!(
        rows(&w.db, V2)["v2_deliveries"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn link_serve_max_db_mib_bounds_the_hub_it_serves() {
    let w = world();
    fill_to_ceiling(&w.db, 16 * MIB, PAD_V2, &PAD_V1_ROWS);
    let before = all_rows(&w.db);
    {
        let (_child, addr) = launch_with(&w.db, &["--max-db-mib", "16"]);
        let full = exchange(addr, &pending_wire(&w, 8));
        assert_eq!(status(&full), 503, "{}", String::from_utf8_lossy(&full));
        let reply: Value = serde_json::from_slice(body(&full)).unwrap();
        assert_eq!(
            reply["error"].as_str(),
            Some("storage unavailable; retry later"),
            "{reply}"
        );
    }
    assert_eq!(all_rows(&w.db), before, "a refused delivery wrote");
    let (_child, addr) = launch_with(&w.db, &["--max-db-mib", "64"]);
    let room = exchange(addr, &pending_wire(&w, 8));
    assert_eq!(status(&room), 200, "{}", String::from_utf8_lossy(&room));
}

#[test]
fn max_db_mib_must_be_a_whole_number_of_mebibytes() {
    let w = world();
    for bad in ["0", "-1", "1.5", "sixteen", "", "1099511627776"] {
        refused(&w.db, &["serve", "--max-db-mib", bad], "--max-db-mib");
    }
    refused(&w.db, &["migrate", "--max-db-mib", "0"], "--max-db-mib");
}

#[test]
fn every_hub_writing_command_accepts_max_db_mib() {
    let w = world();
    for action in [
        "invite",
        "revoke",
        "rotate",
        "snapshot",
        "enroll-local",
        "import",
        "reader-grant",
        "reader-revoke",
    ] {
        let out = link(&w.db, &[action, "--max-db-mib", "64"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && !stderr.contains("unrecognized"),
            "{action}: {stderr}"
        );
    }
}

#[test]
fn revoke_uses_the_ceiling_it_is_given() {
    let w = world();
    let device = w.binding["device"].as_str().unwrap();
    fill_to_ceiling(&w.db, 16 * MIB, PAD_V1, &PAD_V1_ROWS);
    let before = all_rows(&w.db);
    let full = link(&w.db, &["revoke", "--device", device, "--max-db-mib", "16"]);
    assert!(
        !full.status.success(),
        "a revoke that needs a page at a full ceiling must fail"
    );
    assert_eq!(all_rows(&w.db), before, "the refused revoke wrote");
    let room = link(&w.db, &["revoke", "--device", device, "--max-db-mib", "64"]);
    assert!(
        room.status.success(),
        "{}",
        String::from_utf8_lossy(&room.stderr)
    );
}

#[test]
fn migrate_refuses_a_hub_that_already_exceeds_the_ceiling_before_writing() {
    let w = v1_world();
    fill_to_ceiling(&w.db, 2 * MIB, PAD_V1, &[]);
    refused(
        &w.db,
        &["migrate", "--max-db-mib", "1"],
        "migration_storage_failure",
    );
    assert_eq!(user_version(&w.db), 1);
    assert!(!PathBuf::from(format!("{}.v1-backup", w.db.display())).exists());
    let out = link(&w.db, &["migrate", "--max-db-mib", "16"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(user_version(&w.db), 2);
}

#[test]
fn shipped_link_serve_on_a_schema_2_hub_refuses_a_v2_post_and_writes_nothing() {
    let w = world();
    let (_child, addr) = launch(&w.db);
    let before = all_rows(&w.db);
    let response = exchange(addr, &post("/v2/batches", DEVICE, &w.v2_request));
    let reply: Value = serde_json::from_slice(body(&response)).unwrap();
    assert_eq!(
        (status(&response), reply["error"].as_str()),
        (403, Some("capture_unapproved")),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(all_rows(&w.db), before, "the refused post wrote to the hub");
    assert_eq!(rows(&w.db, V2)["v2_deliveries"], json!([]));
    // The same listener still delivers the v1 queue: nothing about the refusal disturbed it.
    assert!(w.drain(addr));
}

#[test]
fn coverage_claims_beyond_what_a_scan_proves_are_refused() {
    let w = world();
    // a one-off table of (label, mutator); an alias would not clarify it
    #[allow(clippy::type_complexity)]
    let cases: [(&str, fn(&mut Value)); 4] = [
        ("advisory results", |a| {
            a["coverage"]["advisories"] = json!({"state":"complete","reason":null})
        }),
        ("global_clean", |a| {
            a["coverage"]["global_clean"] = json!(true)
        }),
        ("fix_verified", |a| {
            a["coverage"]["fix_verified"] = json!(true)
        }),
        ("inventory not partial", |a| {
            a["coverage"]["inventory"] = json!({"state":"partial","reason":"input_read_failed"})
        }),
    ];
    for (name, edit) in cases {
        let raw = artifact(&w, edit);
        let wire = envelope(&w, &raw, |_| {});
        // Trust this very artifact: only the coverage claim stands between it and the hub.
        let admission = Admission::open(
            &w.db,
            vec![TrustedCapture {
                binding: w.binding.clone(),
                evidence_id: w.evidence.clone(),
                artifact_utf8: raw,
            }],
        )
        .unwrap();
        assert_eq!(
            refusal_by(&w, &wire, admission),
            (422, "unsupported_coverage".into()),
            "{name}"
        );
    }
}

#[test]
fn forged_identity_and_binding_are_refused_with_fixed_codes() {
    let w = world();
    for key in ["device", "generation", "tenant", "site"] {
        let mut forged = w.binding.clone();
        forged[key] = json!("synthetic-forged-0000000000000000000");
        let raw = artifact(&w, |a| a["binding"] = forged.clone());
        let wire = envelope(&w, &raw, |q| q["binding"] = forged.clone());
        let admission = Admission::open(
            &w.db,
            vec![TrustedCapture {
                binding: forged.clone(),
                evidence_id: w.evidence.clone(),
                artifact_utf8: raw,
            }],
        )
        .unwrap();
        assert_eq!(
            refusal_by(&w, &wire, admission),
            (403, "identity_mismatch".into()),
            "{key} differs from the credential's enrolment"
        );
    }
    // Same credential identity on the envelope, but the artifact claims another scope.
    let mut other = w.binding.clone();
    other["scope"] = json!("synthetic-other-scope");
    let raw = artifact(&w, |a| a["binding"] = other.clone());
    let wire = envelope(&w, &raw, |_| {});
    let admission = Admission::open(
        &w.db,
        vec![TrustedCapture {
            binding: w.binding.clone(),
            evidence_id: w.evidence.clone(),
            artifact_utf8: raw,
        }],
    )
    .unwrap();
    assert_eq!(
        refusal_by(&w, &wire, admission),
        (403, "binding_mismatch".into())
    );
}

#[test]
fn an_artifact_that_does_not_match_its_declared_hash_or_length_is_refused() {
    let w = world();
    let wrong_hash = envelope(&w, &w.raw, |q| {
        q["artifact_sha256"] = json!(hash(b"another artifact"))
    });
    assert_eq!(refusal(&w, &wrong_hash), (422, "artifact_integrity".into()));
    let wrong_length = envelope(&w, &w.raw, |q| {
        q["artifact_byte_length"] = json!(w.raw.len() + 1)
    });
    assert_eq!(
        refusal(&w, &wrong_length),
        (422, "artifact_integrity".into())
    );
}

#[test]
fn an_escaped_duplicate_key_is_refused_at_the_envelope_and_the_artifact() {
    let w = world();
    // `\u0073chema` is `schema` once unescaped, so a decoder that keeps the last value would read schema 2 twice.
    for (name, duplicate) in [
        ("escaped", r#""\u0073chema":2,"#),
        ("plain", r#""schema":2,"#),
    ] {
        let mut wire = w.v2_request.clone();
        wire.splice(1..1, duplicate.bytes());
        assert_eq!(
            refusal(&w, &wire),
            (400, "invalid_json".into()),
            "envelope, {name}"
        );
    }
    for (name, duplicate) in [
        ("escaped", r#""\u0072evision":9,"#),
        ("plain", r#""revision":9,"#),
    ] {
        let raw = format!("{{{duplicate}{}", &w.raw[1..]);
        let wire = envelope(&w, &raw, |_| {});
        let admission = Admission::open(
            &w.db,
            vec![TrustedCapture {
                binding: w.binding.clone(),
                evidence_id: w.evidence.clone(),
                artifact_utf8: raw,
            }],
        )
        .unwrap();
        assert_eq!(
            refusal_by(&w, &wire, admission),
            (400, "invalid_json".into()),
            "artifact, {name}"
        );
    }
}

// m6s8: the hub trusts an enrolled device's credential for the sources its operator names. Every
// case below runs the shipped `link serve` and the shipped operator commands.

const GRANT_READER: &str = "synthetic-capture-grant-reader-0000000000";
const OTHER_INVITE: &str = "synthetic-other-invite-only-000000000000";
const OTHER_DEVICE: &str = "synthetic-other-device-only-000000000000";

fn link_env(db: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args(["link", "--db", db.to_str().unwrap()])
        .args(args)
        .env("GRANT_READER", GRANT_READER)
        .output()
        .unwrap()
}
fn operator_ok(db: &Path, args: &[&str]) -> Value {
    let out = link_env(db, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
fn device_of(w: &World) -> String {
    w.binding["device"].as_str().unwrap().to_string()
}
fn allow(w: &World, verb: &str) {
    operator_ok(
        &w.db,
        &[verb, "--device", &device_of(w), "--source", "test-npm"],
    );
}
fn answer(response: &[u8]) -> (u16, String) {
    let reply: Value = serde_json::from_slice(body(response)).unwrap_or(Value::Null);
    (
        status(response),
        reply["error"].as_str().unwrap_or("").to_string(),
    )
}
fn read_inventory(addr: SocketAddr) -> Value {
    let response = exchange(addr, &post("/v2/read/inventory", GRANT_READER, b"{}"));
    assert_eq!(
        status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    serde_json::from_slice(body(&response)).unwrap()
}
/// What a read says about the data, without the second it was issued in: `as_of` and each
/// row's age move with the request clock. Every age must still be measured from that `as_of`.
fn data_of(mut read: Value) -> Value {
    let as_of = read["as_of"].as_f64().unwrap();
    for row in read["inventory"].as_array_mut().unwrap() {
        let observed = row["observed_at"]["value"].as_f64().unwrap();
        assert_eq!(row["age_seconds"].as_f64().unwrap(), as_of - observed);
        row.as_object_mut().unwrap().remove("age_seconds");
    }
    read.as_object_mut().unwrap().remove("as_of");
    read
}

#[test]
fn a_granted_source_is_admitted_and_read_and_a_denied_one_is_refused_with_data_kept() {
    let w = world();
    operator_ok(
        &w.db,
        &[
            "reader-grant",
            "--reader-env",
            "GRANT_READER",
            "--label",
            "synthetic-reader",
            "--org",
            "test-org",
            "--site",
            "test-site",
            "--ttl",
            "3600",
        ],
    );
    let (_child, addr) = launch(&w.db);
    let wire = post("/v2/batches", DEVICE, &w.v2_request);

    // No grant: refused, nothing written.
    let before = all_rows(&w.db);
    assert_eq!(
        answer(&exchange(addr, &wire)),
        (403, "capture_unapproved".into())
    );
    assert_eq!(all_rows(&w.db), before);

    // Granted while the hub is serving: the next post is admitted and the reader sees it.
    allow(&w, "capture-allow");
    let accepted = exchange(addr, &wire);
    assert_eq!(
        status(&accepted),
        200,
        "{}",
        String::from_utf8_lossy(&accepted)
    );
    native::validate_ack(&w.v2_request, body(&accepted)).unwrap();
    let seen = read_inventory(addr);
    assert!(
        !seen["inventory"].as_array().unwrap().is_empty(),
        "the reader sees no inventory: {seen}"
    );
    let kept = all_rows(&w.db);
    assert_ne!(kept, before);

    // Denied: the next post is refused, and what was admitted stays.
    allow(&w, "capture-deny");
    assert_eq!(
        answer(&exchange(addr, &wire)),
        (403, "capture_unapproved".into())
    );
    assert_eq!(all_rows(&w.db), kept);
    // A later read can fall in a later second; the data it reads must be the same.
    assert_eq!(data_of(read_inventory(addr)), data_of(seen));

    // Granted again, then the device is revoked: the credential is refused and the data stays.
    allow(&w, "capture-allow");
    operator_ok(&w.db, &["revoke", "--device", &device_of(&w)]);
    let rows_after_revoke = all_rows(&w.db);
    assert_eq!(
        answer(&exchange(addr, &wire)),
        (401, "invalid_credential".into())
    );
    assert_eq!(all_rows(&w.db), rows_after_revoke);
    assert!(!rows(&w.db, &["v2_assessments"])["v2_assessments"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn a_grant_for_another_devices_binding_does_not_let_this_credential_post_it() {
    let w = world();
    let hub = Hub::open(&w.db).unwrap();
    hub.invite(OTHER_INVITE, "test-org", "test-site", 60.0)
        .unwrap();
    let other = hub.enroll(OTHER_INVITE, OTHER_DEVICE).unwrap();
    let other_id = other["device"].as_str().unwrap();
    operator_ok(
        &w.db,
        &[
            "capture-allow",
            "--device",
            other_id,
            "--source",
            "test-npm",
        ],
    );
    let (_child, addr) = launch(&w.db);
    let before = all_rows(&w.db);

    // The first device holds no grant of its own: the other device's grant is not its trust.
    assert_eq!(
        answer(&exchange(addr, &post("/v2/batches", DEVICE, &w.v2_request))),
        (403, "capture_unapproved".into())
    );
    // It cannot present the other device's binding either, though that device is granted.
    let mut q: Value = serde_json::from_slice(&w.v2_request).unwrap();
    q["binding"]["device"] = json!(other_id);
    q["binding"]["generation"] = other["generation"].clone();
    assert_eq!(
        answer(&exchange(
            addr,
            &post("/v2/batches", DEVICE, &canonical(&q))
        )),
        (403, "identity_mismatch".into())
    );
    assert_eq!(all_rows(&w.db), before);
}

#[test]
fn a_new_generation_ends_the_trust_a_grant_gave_the_old_one() {
    let w = world();
    allow(&w, "capture-allow");
    let (_child, addr) = launch(&w.db);
    // The hub moves the device to a new generation while it serves.
    Connection::open(&w.db)
        .unwrap()
        .execute("UPDATE devices SET generation='generation-two'", [])
        .unwrap();
    let before = all_rows(&w.db);
    assert_eq!(
        answer(&exchange(addr, &post("/v2/batches", DEVICE, &w.v2_request))),
        (403, "identity_mismatch".into())
    );
    assert_eq!(all_rows(&w.db), before);
}

#[test]
fn a_grant_file_made_for_another_hub_is_refused_by_the_operator_commands_and_while_serving() {
    let w = world();
    let foreign = world();
    allow(&w, "capture-allow");
    allow(&foreign, "capture-allow");
    let side = |w: &World| PathBuf::from(format!("{}.capture-grants", w.db.display()));

    // Swapped in while the hub serves: the next post is refused and nothing is written.
    let (_child, addr) = launch(&w.db);
    fs::copy(side(&foreign), side(&w)).unwrap();
    let before = all_rows(&w.db);
    assert_eq!(
        answer(&exchange(addr, &post("/v2/batches", DEVICE, &w.v2_request))),
        (503, "storage unavailable; retry later".into())
    );
    assert_eq!(all_rows(&w.db), before);

    // The operator commands and a fresh serve refuse it as well, naming the file.
    let device = device_of(&w);
    for verb in ["capture-allow", "capture-deny"] {
        let out = link_env(&w.db, &[verb, "--device", &device, "--source", "s"]);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("different hub"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = link_env(&w.db, &["serve", "--port", "0"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("different hub"));
}

#[test]
fn the_grant_file_is_private_and_a_file_of_another_format_is_refused_everywhere() {
    let w = world();
    let side = PathBuf::from(format!("{}.capture-grants", w.db.display()));
    assert!(!side.exists());
    // A device the hub never enrolled cannot be granted, and nothing is created for it.
    let out = link_env(
        &w.db,
        &[
            "capture-allow",
            "--device",
            "no-such-device",
            "--source",
            "test-npm",
        ],
    );
    assert!(!out.status.success());
    assert!(!side.exists());

    allow(&w, "capture-allow");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&side).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // Denying what was never granted is not an error and leaves the file usable.
    operator_ok(
        &w.db,
        &[
            "capture-deny",
            "--device",
            &device_of(&w),
            "--source",
            "other-source",
        ],
    );

    Connection::open(&side)
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    let device = device_of(&w);
    for args in [
        vec![
            "capture-allow",
            "--device",
            device.as_str(),
            "--source",
            "s",
        ],
        vec!["capture-deny", "--device", device.as_str(), "--source", "s"],
    ] {
        let out = link_env(&w.db, &args);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("capture grants"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = link_env(&w.db, &["serve", "--port", "0"]);
    assert!(
        !out.status.success(),
        "serve started on a grant file of another format"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("capture grants"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
