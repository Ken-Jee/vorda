mod common;
use common::{body, canonical, hash, status};
use rusqlite::Connection;
use rustls::pki_types::{pem::PemObject, CertificateDer};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use vorda::{
    link::{
        grants::CaptureGrants,
        native::{self, Admission, TrustedCapture},
        server::Server,
        storage::Hub,
    },
    store::{capture, Store},
};
const INVITE: &str = "synthetic-invite-only-0000000000000000000";
const DEVICE: &str = "synthetic-device-only-0000000000000000000";
const CLIENT_GUARD: Duration = Duration::from_secs(20);
const UNKNOWN: &str = "synthetic-unknown-only-000000000000000000";
struct Fixture {
    _tmp: tempfile::TempDir,
    hub: Hub,
    binding: Value,
    raw: String,
    evidence: String,
    request: Vec<u8>,
    v1: Option<LegacyV1>,
}
#[derive(Clone)]
struct LegacyV1 {
    request: Vec<u8>,
    ack: Vec<u8>,
    snapshot: Vec<u8>,
    rows: Value,
}
impl Fixture {
    fn new() -> Self {
        Self::with_legacy(false)
    }
    fn with_legacy(legacy: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let hub = Hub::open(&tmp.path().join("hub.db")).unwrap();
        hub.invite(INVITE, "test-org", "test-site", 60.0).unwrap();
        let enrolled = hub.enroll(INVITE, DEVICE).unwrap();
        let binding = json!({"tenant":"test-org","site":"test-site","device":enrolled["device"],"generation":enrolled["generation"],"scope":"test-scope","source":"test-npm"});
        let row: (String, String, String, String) = hub
            .database
            .connect()
            .unwrap()
            .query_row("SELECT org,site,id,generation FROM devices", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!(
            json!([row.0, row.1, row.2, row.3]),
            json!([
                binding["tenant"],
                binding["site"],
                binding["device"],
                binding["generation"]
            ])
        );
        let root = tmp.path().join("root");
        fs::create_dir_all(root.join("one")).unwrap();
        fs::write(
            root.join("one/package-lock.json"),
            include_bytes!("fixtures/capture/L1.json"),
        )
        .unwrap();
        let mut store = Store::open(&tmp.path().join("producer")).unwrap();
        let outcome = capture::capture(&mut store, &serde_json::to_vec(&json!({"token":"capture-1","binding":binding,"root":root.canonicalize().unwrap(),"inputs":["one/package-lock.json"],"observed_at":"1793898285.4219873","completed_at":"1793898285.5764945"})).unwrap()).unwrap();
        assert_eq!(outcome["revision"], 1);
        let export = tmp.path().join("export.json");
        capture::export(
            &mut store,
            outcome["snapshot_id"].as_str().unwrap(),
            &export,
        )
        .unwrap();
        let view: Value = serde_json::from_slice(&fs::read(export).unwrap()).unwrap();
        assert_eq!(view["records"].as_array().unwrap().len(), 1);
        assert_eq!(view["evidence"].as_array().unwrap().len(), 1);
        let evidence = view["evidence"][0]["evidence_id"]
            .as_str()
            .unwrap()
            .to_string();
        let raw = view["retained_payload_utf8"][&evidence]
            .as_str()
            .unwrap()
            .to_string();
        let artifact: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(artifact["binding"], binding);
        assert_eq!(artifact["revision"], 1);
        assert_eq!(view["evidence"][0]["source_sha256"], hash(raw.as_bytes()));
        assert_eq!(view["evidence"][0]["source_byte_length"], raw.len());
        assert_eq!(artifact["assessment_id"], outcome["assessment_id"]);
        let pending: i64 = store
            .db
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pending, 0);
        let request = canonical(
            &json!({"schema":2,"binding":binding,"sequence":1,"evidence_id":evidence,"artifact_sha256":hash(raw.as_bytes()),"artifact_byte_length":raw.len(),"artifact_utf8":raw}),
        );
        let mut f = Self {
            _tmp: tmp,
            hub,
            binding,
            raw,
            evidence,
            request,
            v1: None,
        };
        if legacy {
            let mut batch: Value =
                serde_json::from_str(include_str!("fixtures/link-v1.json")).unwrap();
            batch["device"] = f.binding["device"].clone();
            batch["generation"] = f.binding["generation"].clone();
            batch["sequence"] = json!(7);
            let ack = f.hub.ingest(DEVICE, &batch).unwrap();
            let request = vorda::link::encode(&batch).unwrap();
            let snapshot = canonical(
                &f.hub
                    .snapshot(f.binding["device"].as_str().unwrap())
                    .unwrap(),
            );
            let rows = framing_database(&f);
            f.v1 = Some(LegacyV1 {
                request,
                ack,
                snapshot,
                rows,
            });
            let db = f.hub.database.connect().unwrap();
            assert_eq!(
                db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                1
            );
            drop(db);
            let before = fs::read(&f.hub.database.path).unwrap();
            assert!(Admission::open(&f.hub.database.path, vec![trusted(&f)]).is_err());
            assert_eq!(fs::read(&f.hub.database.path).unwrap(), before);
        }
        native::migrate(&f.hub.database.path).unwrap();
        f
    }
    fn admission(&self) -> Admission {
        granted(
            Admission::open(&self.hub.database.path, vec![trusted(self)]).unwrap(),
            &self.hub.database.path,
            std::slice::from_ref(&self.binding),
        )
    }
    fn counts(&self) -> Vec<i64> {
        let db = Connection::open(&self.hub.database.path).unwrap();
        [
            "v2_deliveries",
            "v2_views",
            "v2_assessments",
            "v2_observations",
        ]
        .iter()
        .map(|table| {
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        })
        .collect()
    }
    fn server(&self) -> Server {
        Server::bind(
            Hub::open(&self.hub.database.path).unwrap(),
            "127.0.0.1",
            0,
            None,
            None,
        )
        .unwrap()
    }
}
fn wire(body: &[u8], credential: &str) -> Vec<u8> {
    let mut wire = format!("POST /v2/batches HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {credential}\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
    wire.extend(body);
    wire
}
fn exchange(addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
    // An early refusal can close the upload before write_all finishes. Read that answer;
    // accepting an empty/partial response or a success after a failed upload is forbidden.
    let write_error = s.write_all(bytes).err();
    if let Some(error) = &write_error {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ),
            "request write: {error}"
        );
    }
    let mut out = vec![];
    let read_error = s.read_to_end(&mut out).err();
    if let Some(error) = &read_error {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "response read: {error}"
        );
    }
    if write_error.is_some() || read_error.is_some() {
        let end = out
            .windows(4)
            .position(|s| s == b"\r\n\r\n")
            .expect("reset before complete response headers");
        let text = std::str::from_utf8(&out[..end]).unwrap();
        let size: usize = text
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            out.len() - end - 4,
            size,
            "reset before complete response body"
        );
        if let Some(error) = write_error {
            assert!(status(&out) >= 400, "success after failed upload: {error}");
            eprintln!(
                "read a complete HTTP {} refusal after upload closed: {error}",
                status(&out)
            );
        }
    }
    out
}
// Socket tests have wall-clock bounds and some set process-wide environment variables, so one runs at a time.
static EXCLUSIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    EXCLUSIVE.lock().unwrap_or_else(|e| e.into_inner())
}
fn serving(f: &Fixture, run: impl FnOnce(SocketAddr)) {
    let server = f.server();
    let addr = server.local_addr().unwrap();
    let admission = f.admission();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(addr)));
        stop.store(true, Ordering::Release);
        h.join().unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    });
}
#[test]
fn v2_route_after_long_whitespace_keeps_the_v2_line_ceiling() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
        let counts = f.counts();
        let raw = wire(&f.request, DEVICE);
        let mut long = b"POST".to_vec();
        long.extend(std::iter::repeat_n(b' ', 1100));
        long.extend(&raw[5..]);
        assert_eq!(status(&settled(addr, &long)), 413);
        assert_eq!(f.counts(), counts);
    });
}
#[test]
fn v1_long_first_line_matches_ordinary_listener() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let make = |invite: &str| {
        let body = serde_json::to_vec(&json!({"credential": format!("{invite}-device")})).unwrap();
        let mut raw = format!("POST /v1/enroll {}HTTP/1.1\r\nAuthorization: Bearer {invite}\r\nContent-Length: {}\r\n\r\n", " ".repeat(2048), body.len()).into_bytes();
        raw.extend(&body);
        raw
    };
    let ordinary = f.server();
    let addr = ordinary.local_addr().unwrap();
    f.hub
        .invite(
            "long-line-ordinary-invite-00000000000000",
            "org",
            "site",
            60.0,
        )
        .unwrap();
    thread::scope(|scope| {
        let h = scope.spawn(|| ordinary.serve_once().unwrap());
        assert_eq!(
            status(&exchange(
                addr,
                &make("long-line-ordinary-invite-00000000000000")
            )),
            200
        );
        h.join().unwrap();
    });
    f.hub
        .invite(
            "long-line-invite-00000000000000000000000",
            "org",
            "site",
            60.0,
        )
        .unwrap();
    serving(&f, |addr| {
        assert_eq!(
            status(&exchange(
                addr,
                &make("long-line-invite-00000000000000000000000")
            )),
            200
        );
        let mut q = wire(&f.request, DEVICE);
        q.splice(16..16, std::iter::repeat_n(b' ', 1024));
        assert_eq!(status(&settled(addr, &q)), 413);
        assert_eq!(f.counts(), vec![0, 0, 0, 0]);
    });
}
#[test]
fn sqlite_wait_is_capped_by_remaining_active_budget() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let writer = Connection::open(&f.hub.database.path).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let connect_started = Instant::now();
        let mut active = TcpStream::connect(addr).unwrap();
        active.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
        let bytes = wire(&f.request, DEVICE);
        active.write_all(&bytes[..bytes.len() - 1]).unwrap();
        thread::sleep(Duration::from_millis(20));
        assert_eq!(status(&exchange(addr, b"")), 503);
        thread::sleep(Duration::from_millis(4900));
        let _ = active.write_all(&bytes[bytes.len() - 1..]);
        let mut response = vec![];
        let transport = active.read_to_end(&mut response);
        let elapsed = connect_started.elapsed();
        let expected_body = br#"{"error":"storage unavailable; retry later"}"#;
        let mut permitted = format!("HTTP/1.1 503 Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nRetry-After: 5\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n", expected_body.len()).into_bytes();
        permitted.extend_from_slice(expected_body);
        let valid = permitted.starts_with(&response);
        writer.execute_batch("ROLLBACK").unwrap();
        let counts_after_refusal = f.counts();
        let recovery = settled(addr, &bytes);
        let counts_after_recovery = f.counts();
        assert_eq!(counts_after_refusal, vec![0, 0, 0, 0]);
        assert_eq!(status(&recovery), 200);
        native::validate_ack(&f.request, body(&recovery)).unwrap();
        assert_eq!(counts_after_recovery, vec![1, 1, 1, 1]);
        assert!(
            transport.is_ok()
                || transport
                    .as_ref()
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
        );
        assert!(
            valid,
            "deadline close contains bytes outside permitted 503 grammar: {response:?}"
        );
        assert!(elapsed <= ACTIVE_CLOSE_BOUND);
    });
}
#[test]
fn sqlite_writer_busy_refuses_without_publication_then_recovers() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let writer = Connection::open(&f.hub.database.path).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let start = Instant::now();
        assert_eq!(status(&exchange(addr, &wire(&f.request, DEVICE))), 503);
        assert!(start.elapsed() < STORAGE_REFUSAL_BOUND);
        writer.execute_batch("ROLLBACK").unwrap();
        assert_eq!(f.counts(), vec![0, 0, 0, 0]);
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
        assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    });
}
#[test]
fn enrolled_publish_auth_precedence_replay_and_revoke() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let baseline = settled(addr, &wire(&f.request, DEVICE));
        assert_eq!(
            status(&baseline),
            200,
            "{}",
            String::from_utf8_lossy(&baseline)
        );
        native::validate_ack(&f.request, body(&baseline)).unwrap();
        let counts = f.counts();
        assert_eq!(counts, vec![1, 1, 1, 1]);
        for credential in [UNKNOWN, INVITE] {
            assert_eq!(status(&settled(addr, &wire(&f.request, credential))), 401);
            assert_eq!(f.counts(), counts);
        }
        for key in ["tenant", "site", "device", "generation"] {
            let mut q: Value = serde_json::from_slice(&f.request).unwrap();
            q["binding"][key] = json!("different");
            assert_eq!(status(&settled(addr, &wire(&canonical(&q), DEVICE))), 403);
            assert_eq!(f.counts(), counts);
        }
        let malformed = b"{\"schema\":2,\"schema\":2}";
        for credential in [UNKNOWN, DEVICE] {
            assert_eq!(status(&settled(addr, &wire(malformed, credential))), 400);
        }
        let mut q: Value = serde_json::from_slice(&f.request).unwrap();
        q["artifact_sha256"] = json!("0".repeat(64));
        assert_eq!(status(&settled(addr, &wire(&canonical(&q), UNKNOWN))), 401);
        assert_eq!(status(&settled(addr, &wire(&canonical(&q), DEVICE))), 422);
        assert_eq!(settled(addr, &wire(&f.request, DEVICE)), baseline);
        assert_eq!(f.counts(), counts);
        f.hub.revoke(f.binding["device"].as_str().unwrap()).unwrap();
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 401);
        assert_eq!(f.counts(), counts);
    });
}
#[test]
fn config_removal_rejects_saved_ack_and_ordinary_server_has_no_v2() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
    });
    let server = f.server();
    let addr = server.local_addr().unwrap();
    let admission = Admission::open(&f.hub.database.path, vec![]).unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 403);
        stop.store(true, Ordering::Release);
        h.join().unwrap();
    });
    let server = f.server();
    let addr = server.local_addr().unwrap();
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_once().unwrap());
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 404);
        h.join().unwrap();
    });
    assert_eq!(f.counts(), vec![1, 1, 1, 1]);
}
#[test]
fn stalled_active_rejects_second_peer_and_recovers() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let mut active = TcpStream::connect(addr).unwrap();
        active.write_all(b"POST /v2/batches HTTP/1.1\r\n").unwrap();
        thread::sleep(Duration::from_millis(30));
        let start = Instant::now();
        let response = exchange(addr, b"");
        assert_eq!(status(&response), 503);
        assert!(response.windows(16).any(|x| x == b"Retry-After: 5\r\n"));
        assert!(start.elapsed() <= BUSY_PEER_CLOSE_BOUND);
        assert_eq!(f.counts(), vec![0, 0, 0, 0]);
        drop(active);
        thread::sleep(Duration::from_millis(30));
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
    });
}

fn tls_files(f: &Fixture) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = f._tmp.path().join("cert.pem");
    let key = f._tmp.path().join("key.pem");
    common::tls::certificate(&cert, &key);
    (cert, key)
}
fn tls_request(
    addr: SocketAddr,
    cert: &std::path::Path,
    hostname: &str,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(fs::File::open(cert)?) {
        roots.add(cert.map_err(std::io::Error::other)?).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connection = rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        rustls::pki_types::ServerName::try_from(hostname.to_string()).unwrap(),
    )
    .unwrap();
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(CLIENT_GUARD))?;
    tcp.set_write_timeout(Some(CLIENT_GUARD))?;
    let mut tls = rustls::StreamOwned::new(connection, tcp);
    tls.write_all(request)?;
    tls.flush()?;
    let mut bytes = vec![];
    match tls.read_to_end(&mut bytes) {
        Ok(_) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !bytes.is_empty() => Ok(bytes),
        Err(e) => Err(e),
    }
}
const BUSY_PEER_CLOSE_BOUND: Duration = Duration::from_millis(1500);
const HANDSHAKE_CLOSE_BOUND: Duration = Duration::from_millis(1150);
const ACTIVE_CLOSE_BOUND: Duration = Duration::from_millis(6500);
const STORAGE_REFUSAL_BOUND: Duration = Duration::from_millis(2500);
#[test]
fn tls_positive_hostname_refusal_and_stalled_handshakes() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let (cert, key) = tls_files(&f);
    let server = Server::bind(
        Hub::open(&f.hub.database.path).unwrap(),
        "127.0.0.1",
        0,
        Some(&cert),
        Some(&key),
    )
    .expect("SETUP: TLS server");
    let addr = server.local_addr().unwrap();
    let admission = f.admission();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(
                status(&tls_settled(addr, &cert, &wire(&f.request, DEVICE))),
                200
            );
            thread::sleep(Duration::from_millis(20));
            assert!(tls_request(addr, &cert, "wrong.invalid", &wire(&f.request, DEVICE)).is_err());
            thread::sleep(Duration::from_millis(20));
            let other = Fixture::new();
            let (wrong_ca, _) = tls_files(&other);
            assert!(tls_request(addr, &wrong_ca, "localhost", &wire(&f.request, DEVICE)).is_err());
            thread::sleep(Duration::from_millis(20));
            assert_eq!(
                status(&tls_settled(addr, &cert, &wire(&f.request, DEVICE))),
                200
            );
            quiet(addr);
            let mut active = TcpStream::connect(addr).unwrap();
            active.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
            thread::sleep(Duration::from_millis(30));
            let mut rejected = TcpStream::connect(addr).unwrap();
            rejected.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
            let start = Instant::now();
            assert_eq!(rejected.read(&mut [0]).unwrap(), 0);
            assert!(start.elapsed() <= BUSY_PEER_CLOSE_BOUND);
            assert_eq!(active.read(&mut [0]).unwrap(), 0);
            assert!(start.elapsed() <= HANDSHAKE_CLOSE_BOUND);
            thread::sleep(Duration::from_millis(20));
            assert_eq!(
                status(&tls_settled(addr, &cert, &wire(&f.request, DEVICE))),
                200
            );
        }));
        stop.store(true, Ordering::Release);
        h.join().unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    });
    assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    assert!(Server::bind(
        Hub::open(&f.hub.database.path).unwrap(),
        "0.0.0.0",
        0,
        None,
        None
    )
    .is_err());
}

fn tls_serving(
    f: &Fixture,
    cert: &std::path::Path,
    key: &std::path::Path,
    run: impl FnOnce(SocketAddr),
) {
    let server = Server::bind(
        Hub::open(&f.hub.database.path).unwrap(),
        "127.0.0.1",
        0,
        Some(cert),
        Some(key),
    )
    .expect("SETUP: TLS server");
    let addr = server.local_addr().unwrap();
    let admission = f.admission();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(addr)));
        stop.store(true, Ordering::Release);
        h.join().unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    });
}
const STALLED_CLOSE_MIN_MS: f64 = 900.0;
const STALLED_CLOSE_MAX_MS: f64 = 1150.0;
const STALLED_CLOSE_TYPICAL_MS: f64 = 1000.0;
#[test]
fn tls_stalled_handshake_closes_within_budget() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let (cert, key) = tls_files(&f);
    tls_serving(&f, &cert, &key, |addr| {
        let mut ms = vec![];
        for _ in 0..10 {
            quiet(addr);
            let origin = Instant::now();
            let mut stalled = TcpStream::connect(addr).unwrap();
            stalled.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
            await_close(&mut stalled);
            ms.push(origin.elapsed().as_secs_f64() * 1000.0);
        }
        let fastest = ms.iter().cloned().fold(f64::MAX, f64::min);
        assert!(
            fastest <= STALLED_CLOSE_TYPICAL_MS,
            "no stalled handshake closed within {STALLED_CLOSE_TYPICAL_MS} ms: {ms:?}"
        );
        for m in &ms {
            assert!(
                (STALLED_CLOSE_MIN_MS..=STALLED_CLOSE_MAX_MS).contains(m),
                "stalled handshake closed at {m} ms"
            );
        }
    });
    assert_eq!(f.counts(), vec![0, 0, 0, 0]);
}

const ROTATION_GRACE_SECS: f64 = 1.5;
#[test]
fn allocation_framing_and_rotation_refusals_preserve_the_published_view() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let baseline = settled(addr, &wire(&f.request, DEVICE));
        assert_eq!(status(&baseline), 200);
        let counts = f.counts();
        let view = f.admission().saved_view(&f.binding).unwrap();
        for credential in [UNKNOWN, DEVICE] {
            let oversize=format!("POST /v2/batches HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {credential}\r\nContent-Length: 4259841\r\n\r\n");
            assert_eq!(status(&settled(addr, oversize.as_bytes())), 413);
            let mut q: Value = serde_json::from_slice(&f.request).unwrap();
            q["binding"]["scope"] = json!("x".repeat(4097));
            assert_eq!(
                status(&settled(addr, &wire(&canonical(&q), credential))),
                413
            );
            let mut q: Value = serde_json::from_slice(&f.request).unwrap();
            for n in 0..33 {
                q[format!("extra{n}")] = json!(0);
            }
            assert_eq!(
                status(&settled(addr, &wire(&canonical(&q), credential))),
                413
            );
            let q = format!("{}0{}", "[".repeat(17), "]".repeat(17));
            assert_eq!(status(&settled(addr, &wire(q.as_bytes(), credential))), 413);
            let mut q: Value = serde_json::from_slice(&f.request).unwrap();
            q["schema"] = json!(3);
            assert_eq!(
                status(&settled(addr, &wire(&canonical(&q), credential))),
                422
            );
        }
        for (extra, expected) in [
            ("Transfer-Encoding: chunked\r\n", 415),
            ("Content-Encoding: identity\r\n", 415),
            ("Expect: 100-continue\r\n", 417),
            ("Host: duplicate\r\n", 400),
        ] {
            let raw = wire(&f.request, DEVICE);
            let cut = raw.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 2;
            let mut altered = raw[..cut].to_vec();
            altered.extend(extra.as_bytes());
            altered.extend(&raw[cut..]);
            assert_eq!(status(&settled(addr, &altered)), expected);
        }
        let new = "synthetic-rotated-device-0000000000000000000";
        f.hub
            .rotate(
                f.binding["device"].as_str().unwrap(),
                new,
                ROTATION_GRACE_SECS,
            )
            .unwrap();
        assert_eq!(settled(addr, &wire(&f.request, DEVICE)), baseline);
        thread::sleep(Duration::from_secs_f64(ROTATION_GRACE_SECS) + Duration::from_millis(20));
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 401);
        assert_eq!(settled(addr, &wire(&f.request, new)), baseline);
        assert_eq!(f.counts(), counts);
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), view);
    });
}

#[test]
fn fragmented_eof_and_pipeline_requests_have_one_dispatch() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let bytes = wire(&f.request, DEVICE);
        let baseline = not_busy(|| {
            let mut s = TcpStream::connect(addr).expect("SETUP: fragmented connection");
            s.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
            for piece in bytes.chunks(31) {
                if s.write_all(piece).is_err() {
                    break;
                }
            }
            let mut baseline = vec![];
            let _ = s.read_to_end(&mut baseline);
            baseline
        });
        assert_eq!(status(&baseline), 200);
        native::validate_ack(&f.request, body(&baseline)).unwrap();
        let view = f.admission().saved_view(&f.binding).unwrap();
        let counts = f.counts();
        for cut in [20, bytes.len() - 1] {
            let response = not_busy(|| {
                let mut s = TcpStream::connect(addr).expect("SETUP: EOF connection");
                s.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
                let _ = s.write_all(&bytes[..cut]);
                let _ = s.shutdown(std::net::Shutdown::Write);
                let mut response = vec![];
                let _ = s.read_to_end(&mut response);
                response
            });
            assert_eq!(status(&response), 400);
            assert_eq!(f.counts(), counts);
        }
        // Send the second request only after the first response: close must prevent dispatch.
        let (mut s, response) = (0..BUSY_RETRIES)
            .find_map(|_| {
                let mut s = TcpStream::connect(addr).unwrap();
                s.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
                let _ = s.write_all(&bytes);
                let mut response = vec![];
                let _ = s.read_to_end(&mut response);
                if !response.is_empty() && status(&response) != 503 {
                    return Some((s, response));
                }
                thread::sleep(Duration::from_millis(5));
                None
            })
            .expect("still busy");
        assert_eq!(response, baseline);
        let _ = s.write_all(&bytes);
        assert_eq!(s.read(&mut [0]).unwrap(), 0);
        assert_eq!(f.counts(), counts);
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), view);
    });
}

#[test]
fn intentional_unread_ack_recovers_exact_first_receipt() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let mut s = TcpStream::connect(addr).expect("SETUP: lost response connection");
        s.write_all(&wire(&f.request, DEVICE)).unwrap();
        let start = Instant::now();
        while f.counts() != vec![1, 1, 1, 1] {
            assert!(
                start.elapsed() < CLIENT_GUARD,
                "SETUP: publication must commit before dropping response"
            );
            thread::yield_now();
        }
        // The sender discards the response after observing the committed publication.
        drop(s);
        let db = Connection::open(&f.hub.database.path).unwrap();
        let original: Vec<u8> = db
            .query_row("SELECT ack FROM v2_deliveries", [], |r| r.get(0))
            .unwrap();
        let before = durable_state(&f);
        let retry = settled(addr, &wire(&f.request, DEVICE));
        assert_eq!(status(&retry), 200);
        assert_eq!(body(&retry), original);
        assert_eq!(durable_state(&f), before);
        native::validate_ack(&f.request, &original).unwrap();
        assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    });
}

#[test]
fn mixed_v1_v2_busy_peers_never_dispatch_and_recover() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
        let counts = f.counts();
        let view = f.admission().saved_view(&f.binding).unwrap();
        for first in [
            b"POST /v1/enroll HTTP/1.1\r\n".as_slice(),
            b"POST /v2/batches HTTP/1.1\r\n",
        ] {
            for second in [
                b"POST /v1/enroll HTTP/1.1\r\n".as_slice(),
                b"POST /v2/batches HTTP/1.1\r\n",
            ] {
                let active = (0..BUSY_RETRIES)
                    .find_map(|_| {
                        let mut candidate = TcpStream::connect(addr).unwrap();
                        let _ = candidate.write_all(first);
                        candidate
                            .set_read_timeout(Some(Duration::from_millis(200)))
                            .unwrap();
                        match candidate.read(&mut [0]) {
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                Some(candidate)
                            }
                            _ => {
                                thread::sleep(Duration::from_millis(5));
                                None
                            }
                        }
                    })
                    .expect("SETUP: no free active slot");
                let start = Instant::now();
                let mut rejected = TcpStream::connect(addr).expect("SETUP: busy peer");
                rejected.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
                rejected.write_all(second).unwrap();
                let mut response = vec![];
                match rejected.read_to_end(&mut response) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                    Err(e) => panic!("busy read: {e}"),
                }
                // A reset after the full 503 is fine; the declared body length must still arrive.
                let text = std::str::from_utf8(&response).unwrap();
                let declared: usize = text
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(body(&response).len(), declared);
                assert_eq!(status(&response), 503);
                assert!(start.elapsed() <= BUSY_PEER_CLOSE_BOUND);
                assert!(response.windows(16).any(|x| x == b"Retry-After: 5\r\n"));
                assert_eq!(f.counts(), counts);
                drop(active);
                thread::sleep(Duration::from_millis(20));
                assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
            }
        }
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), view);
    });
}

#[test]
fn nested_structural_and_semantic_errors_are_paired_by_credential() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
        let counts = f.counts();
        let view = f.admission().saved_view(&f.binding).unwrap();
        let a: Value = serde_json::from_str(&f.raw).unwrap();
        let mut variants = vec![];
        let mut typed = a.clone();
        typed["legacy_import"] = json!("false");
        variants.push((canonical(&typed), 400, 400));
        let mut typed = a.clone();
        typed["inputs"][0]["bytes_utf8"] = json!(1);
        variants.push((canonical(&typed), 400, 400));
        variants.push((format!(" {{}}{}", f.raw).into_bytes(), 400, 400));
        variants.push((
            format!("{{\"revision\":1,{}", &f.raw[1..]).into_bytes(),
            400,
            400,
        ));
        let mut semantic = a.clone();
        semantic["inputs"][0]["sha256"] = json!("0".repeat(64));
        // A device the operator granted has its text read, so a bad input hash is a 422 for it
        // (the ungranted case is pinned in `hub_full_assessments` and `hub_serve_v2`).
        variants.push((canonical(&semantic), 401, 422));
        for (raw, invalid, valid) in variants {
            let raw = String::from_utf8(raw).unwrap();
            let mut q: Value = serde_json::from_slice(&f.request).unwrap();
            q["artifact_sha256"] = json!(hash(raw.as_bytes()));
            q["artifact_byte_length"] = json!(raw.len());
            q["artifact_utf8"] = json!(raw);
            let bytes = canonical(&q);
            for (credential, expected) in [(UNKNOWN, invalid), (DEVICE, valid)] {
                assert_eq!(status(&settled(addr, &wire(&bytes, credential))), expected);
                assert_eq!(f.counts(), counts);
                assert_eq!(f.admission().saved_view(&f.binding).unwrap(), view);
            }
        }
    });
}

fn produced(f: &Fixture, binding: Value) -> (TrustedCapture, Vec<u8>) {
    let dir = f._tmp.path().join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(dir.join("root/one")).unwrap();
    fs::write(
        dir.join("root/one/package-lock.json"),
        include_bytes!("fixtures/capture/L1.json"),
    )
    .unwrap();
    let mut store = Store::open(&dir.join("store")).expect("SETUP: separate producer");
    let outcome = capture::capture(&mut store, &canonical(&json!({"token":"paired-capture","binding":binding,"root":dir.join("root").canonicalize().unwrap(),"inputs":["one/package-lock.json"],"observed_at":"1793898285.4219873","completed_at":"1793898285.5764945"}))).expect("SETUP: supported capture");
    assert_eq!(outcome["status"], "committed", "SETUP: capture must commit");
    let export = dir.join("export.json");
    capture::export(
        &mut store,
        outcome["snapshot_id"].as_str().unwrap(),
        &export,
    )
    .unwrap();
    let view: Value = serde_json::from_slice(&fs::read(&export).unwrap()).unwrap();
    assert_eq!(view["records"].as_array().unwrap().len(), 1);
    let e = view["evidence"][0]["evidence_id"]
        .as_str()
        .unwrap()
        .to_string();
    let raw = view["retained_payload_utf8"][&e]
        .as_str()
        .unwrap()
        .to_string();
    let digest = hash(raw.as_bytes());
    assert_eq!(view["evidence"][0]["source_sha256"], digest);
    assert_eq!(view["evidence"][0]["source_byte_length"], raw.len());
    let q = canonical(
        &json!({"schema":2,"binding":binding,"sequence":1,"evidence_id":e,"artifact_sha256":digest,"artifact_byte_length":raw.len(),"artifact_utf8":raw}),
    );
    (
        TrustedCapture {
            binding,
            evidence_id: e,
            artifact_utf8: raw,
        },
        q,
    )
}

#[test]
fn supported_captures_isolate_tuple_checks_from_configuration_checks() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200)
    });
    let counts = f.counts();
    for key in ["tenant", "site", "device", "generation"] {
        let mut binding = f.binding.clone();
        binding[key] = json!(format!("different-{key}"));
        let (capture, q) = produced(&f, binding);
        let bindings = [f.binding.clone(), capture.binding.clone()];
        let admission = granted(
            Admission::open(&f.hub.database.path, vec![trusted(&f), capture])
                .expect("SETUP: both captures configured so config cannot mask tuple check"),
            &f.hub.database.path,
            &bindings,
        );
        let server = f.server();
        let addr = server.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        thread::scope(|scope| {
            let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_eq!(
                    status(&settled(addr, &wire(&f.request, DEVICE))),
                    200,
                    "SETUP: same-route authorized replay"
                );
                assert_eq!(status(&settled(addr, &wire(&q, UNKNOWN))), 401);
                assert_eq!(
                    status(&settled(addr, &wire(&q, DEVICE))),
                    403,
                    "tuple {key}"
                );
                assert_eq!(f.counts(), counts);
            }));
            stop.store(true, Ordering::Release);
            h.join().unwrap();
            if let Err(e) = result {
                std::panic::resume_unwind(e);
            }
        });
    }
}

#[test]
fn a_source_the_operator_did_not_grant_is_forbidden() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let mut binding = f.binding.clone();
    binding["source"] = json!("unapproved-source");
    let queries = vec![produced(&f, binding).1];
    serving(&f, |addr| {
        assert_eq!(
            status(&settled(addr, &wire(&f.request, DEVICE))),
            200,
            "SETUP: approved capture"
        );
        let counts = f.counts();
        let view = f.admission().saved_view(&f.binding).unwrap();
        for q in queries {
            assert_eq!(status(&settled(addr, &wire(&q, UNKNOWN))), 401);
            assert_eq!(status(&settled(addr, &wire(&q, DEVICE))), 403);
            assert_eq!(f.counts(), counts);
            assert_eq!(f.admission().saved_view(&f.binding).unwrap(), view);
        }
    });
}

#[test]
fn late_v2_route_exceeding_the_v1_fallback_ceiling_still_refuses_as_v2() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        assert_eq!(
            status(&settled(addr, &wire(&f.request, DEVICE))),
            200,
            "SETUP: same-route approved publication"
        );
        let counts = f.counts();
        let mut first = b"POST".to_vec();
        first.extend(std::iter::repeat_n(b' ', 1100));
        first.extend(b"/v2/batches HTTP/1.1");
        first.resize(65535, b' ');
        first.extend(b"\r\n");
        assert_eq!(first.len(), 65537);
        assert_eq!(status(&settled(addr, &first)), 413);
        assert_eq!(f.counts(), counts);
    });
}

#[test]
fn streaming_v1_semantics_match_ordinary_rejections() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let mut cases: Vec<(Vec<u8>, u16)> = vec![
        (b"POST /v1/enroll arbitrary\n\n".to_vec(), 400),
        (b"GET /unknown arbitrary\n".to_vec(), 501),
        (b"POST /unknown arbitrary\n".to_vec(), 404),
        (b"POST /v1/enroll\n".to_vec(), 501),
        (b"POST /v1/enroll x extra\n".to_vec(), 501),
        (b"POST /v1/enroll x\xff\n".to_vec(), 400),
        (b"POST /v1/enroll x\xe2\n".to_vec(), 400),
        (
            "\u{2003}POST\u{2003}/v1/enroll\u{2003}anything\n\n"
                .as_bytes()
                .to_vec(),
            400,
        ),
    ];
    let mut ceiling = b"POST /unknown x".to_vec();
    ceiling.resize(65535, b' ');
    ceiling.push(b'\n');
    cases.push((ceiling.clone(), 404));
    ceiling.insert(0, b' ');
    cases.push((ceiling, 400));
    for (raw, expected) in cases {
        let ordinary = f.server();
        let addr = ordinary.local_addr().unwrap();
        thread::scope(|scope| {
            let h = scope.spawn(|| ordinary.serve_once().unwrap());
            assert_eq!(status(&settled(addr, &raw)), expected);
            h.join().unwrap();
        });
        serving(&f, |addr| {
            assert_eq!(status(&settled(addr, &raw)), expected)
        });
    }
    assert_eq!(f.counts(), vec![0, 0, 0, 0]);
}

#[test]
fn streaming_v2_boundaries_and_undecidable_cutoff() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        assert_eq!(status(&settled(addr, &wire(&f.request, DEVICE))), 200);
        let counts = f.counts();
        for n in [1023, 1024, 1025] {
            let mut raw = b"POST /v2/batches HTTP/1.1".to_vec();
            raw.resize(n, b' ');
            raw.extend(b"\r\n\r\n");
            assert_eq!(
                status(&settled(addr, &raw)),
                if n > 1024 { 413 } else { 400 }
            );
        }
        for split in 0..=4 {
            let mut raw = b"POST".to_vec();
            raw.resize(1024 - split, b' ');
            raw.extend(b"/v2/batches HTTP/1.1\r\n");
            assert_eq!(status(&settled(addr, &raw)), 413);
        }
        for offset in [65530, 65532, 65533, 65536] {
            let mut raw = b"POST".to_vec();
            raw.resize(offset, b' ');
            raw.extend(b"/v2/batches HTTP/1.1\r\n");
            assert_eq!(
                status(&settled(addr, &raw)),
                if offset <= 65532 { 413 } else { 400 }
            );
        }
        let mut raw = b"POST".to_vec();
        raw.resize(40000, b' ');
        raw.extend(b"/v1/enroll anything\n\n");
        assert_eq!(status(&settled(addr, &raw)), 400);
        let out = not_busy(|| {
            let mut s = TcpStream::connect(addr).unwrap();
            for byte in "POST\u{2003}/v2/batches HTTP/1.1\r\n\r\n".as_bytes() {
                if s.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            let mut out = vec![];
            let _ = s.read_to_end(&mut out);
            out
        });
        assert_eq!(status(&out), 400);
        assert_eq!(f.counts(), counts);
    });
}

#[test]
fn streaming_header_line_count_and_aggregate_boundaries() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let raw = wire(&f.request, DEVICE);
        assert_eq!(status(&settled(addr, &raw)), 200);
        let counts = f.counts();
        let pos = raw.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 2;
        for n in [2048, 2049] {
            let mut q = raw.clone();
            let mut header = b"X: ".to_vec();
            header.resize(n, b'a');
            header.extend(b"\r\n");
            q.splice(pos..pos, header);
            assert_eq!(
                status(&settled(addr, &q)),
                if n == 2048 { 200 } else { 413 }
            );
        }
        for count in [32, 33] {
            let mut q = raw.clone();
            let extra = (0..count - 4)
                .map(|n| format!("X-{n}: a\r\n"))
                .collect::<String>();
            q.splice(pos..pos, extra.bytes());
            assert_eq!(
                status(&settled(addr, &q)),
                if count == 32 { 200 } else { 413 }
            );
        }
        for total in [8192, 8193] {
            let mut q = raw.clone();
            let mut extra = Vec::new();
            let needed = total - (pos + 2);
            for n in 0..4 {
                let len = needed / 4 + usize::from(n < needed % 4);
                let mut h = format!("X-{n}: ").into_bytes();
                h.resize(len - 2, b'a');
                h.extend(b"\r\n");
                extra.extend(h);
            }
            q.splice(pos..pos, extra);
            assert_eq!(
                status(&settled(addr, &q)),
                if total == 8192 { 200 } else { 413 }
            );
        }
        assert_eq!(f.counts(), counts);
    });
}

#[test]
fn streaming_unicode_long_v1_enrollment_and_split_v2_tokens() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let make = |invite: &str| {
        let body = serde_json::to_vec(&json!({"credential": format!("{invite}-device")})).unwrap();
        let mut raw = format!("\u{2003}POST\u{2003}{}\u{2003}/v1/enroll\u{2003}arbitrary-version\nAuthorization: Bearer {invite}\nContent-Length: {}\n\n", " ".repeat(4000), body.len()).into_bytes();
        raw.extend(body);
        raw
    };
    let ordinary = f.server();
    let addr = ordinary.local_addr().unwrap();
    let invite = "unicode-ordinary-invite-00000000000000";
    f.hub.invite(invite, "org", "site", 60.0).unwrap();
    thread::scope(|scope| {
        let h = scope.spawn(|| ordinary.serve_once().unwrap());
        assert_eq!(status(&settled(addr, &make(invite))), 200);
        h.join().unwrap();
    });
    let invite = "unicode-invite-00000000000000000000000";
    f.hub.invite(invite, "org", "site", 60.0).unwrap();
    serving(&f, |addr| {
        assert_eq!(status(&settled(addr, &make(invite))), 200);
        let raw = wire(&f.request, DEVICE);
        for split in 1..24 {
            let response = not_busy(|| {
                let mut peer = TcpStream::connect(addr).unwrap();
                peer.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
                let _ = peer.write_all(&raw[..split]);
                thread::sleep(Duration::from_millis(1));
                let _ = peer.write_all(&raw[split..]);
                let mut response = Vec::new();
                let _ = peer.read_to_end(&mut response);
                response
            });
            assert_eq!(status(&response), 200);
        }
        assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    });
}

fn durable_state(f: &Fixture) -> Value {
    let db = Connection::open(&f.hub.database.path).unwrap();
    let rows = |sql: &str| -> Vec<Value> {
        db.prepare(sql)
            .unwrap()
            .query_map([], |r| {
                Ok(json!([r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?]))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    json!({"counts":f.counts(),"deliveries":rows("SELECT authority||':'||source||':'||sequence,ack FROM v2_deliveries ORDER BY authority,source,sequence"),"views":rows("SELECT authority||':'||publication,payload FROM v2_views ORDER BY authority,publication")})
}
fn exchange_expecting(
    f: &Fixture,
    addr: SocketAddr,
    name: &str,
    q: &[u8],
    credential: &str,
    expected: u16,
) -> Vec<u8> {
    let before = durable_state(f);
    let response = settled(addr, &wire(q, credential));
    assert_eq!(status(&response), expected, "{name}");
    if expected == 200 {
        native::validate_ack(q, body(&response)).unwrap();
    } else {
        assert_eq!(
            durable_state(f),
            before,
            "{name}: refusal mutated durable ACK/view state"
        );
    }
    response
}
fn configured_serving(f: &Fixture, captures: Vec<TrustedCapture>, run: impl FnOnce(SocketAddr)) {
    let bindings: Vec<Value> = captures.iter().map(|c| c.binding.clone()).collect();
    let admission = Admission::open(&f.hub.database.path, captures).unwrap();
    serving_admission(f, granted(admission, &f.hub.database.path, &bindings), run)
}
/// What the operator's `capture-allow` does for the devices and sources of `bindings`. Without
/// bindings nothing is granted. A device the hub never enrolled cannot be granted and is skipped.
fn granted(admission: Admission, db: &std::path::Path, bindings: &[Value]) -> Admission {
    if bindings.is_empty() {
        return admission;
    }
    for b in bindings {
        let device = b["device"].as_str().unwrap_or("");
        let unknown = Connection::open(db)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM devices WHERE id=?", [device], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
            == 0;
        if unknown {
            continue;
        }
        CaptureGrants::allow(db, device, b["source"].as_str().unwrap_or(""))
            .expect("granting an enrolled device its source");
    }
    admission.with_grants(CaptureGrants::open(db).expect("opening the capture grants"))
}
fn serving_admission(f: &Fixture, admission: Admission, run: impl FnOnce(SocketAddr)) {
    let server = f.server();
    let addr = server.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(addr)));
        stop.store(true, Ordering::Release);
        h.join().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    });
}
fn trusted(f: &Fixture) -> TrustedCapture {
    TrustedCapture {
        binding: f.binding.clone(),
        evidence_id: f.evidence.clone(),
        artifact_utf8: f.raw.clone(),
    }
}
#[test]
fn valid_publish_is_acked_and_replays() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let ack = exchange_expecting(&f, addr, "valid-publish/original", &f.request, DEVICE, 200);
        assert_eq!(f.counts(), vec![1, 1, 1, 1]);
        let saved = f.admission().saved_view(&f.binding).unwrap();
        let view: Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(view["records"].as_array().unwrap().len(), 1);
        let before = durable_state(&f);
        let replay = exchange_expecting(&f, addr, "valid-publish/replay", &f.request, DEVICE, 200);
        assert_eq!(replay, ack);
        assert_eq!(durable_state(&f), before);
    });
}
#[test]
fn other_capture_tuples_are_forbidden_without_changing_state() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        exchange_expecting(
            &f,
            addr,
            "tuple-isolation/original",
            &f.request,
            DEVICE,
            200,
        );
    });
    let baseline = durable_state(&f);
    let saved = f.admission().saved_view(&f.binding).unwrap();
    for key in ["tenant", "site", "device", "generation"] {
        let mut b = f.binding.clone();
        b[key] = json!(format!("different-{key}"));
        let (capture, q) = produced(&f, b.clone());
        configured_serving(&f, vec![trusted(&f), capture], |addr| {
            exchange_expecting(
                &f,
                addr,
                &format!("tuple-isolation/{key}-unknown"),
                &q,
                UNKNOWN,
                401,
            );
            exchange_expecting(
                &f,
                addr,
                &format!("tuple-isolation/{key}-enrolled"),
                &q,
                DEVICE,
                403,
            );
            assert_eq!(durable_state(&f), baseline);
            assert_eq!(f.admission().saved_view(&f.binding).unwrap(), saved);
        });
    }
    let q = include_bytes!("fixtures/capture/request.json");
    let g: Value = serde_json::from_slice(q).unwrap();
    let capture = TrustedCapture {
        binding: g["binding"].clone(),
        evidence_id: g["evidence_id"].as_str().unwrap().into(),
        artifact_utf8: g["artifact_utf8"].as_str().unwrap().into(),
    };
    configured_serving(&f, vec![trusted(&f), capture], |addr| {
        exchange_expecting(&f, addr, "tuple-isolation/fixture-unknown", q, UNKNOWN, 401);
        exchange_expecting(&f, addr, "tuple-isolation/fixture-enrolled", q, DEVICE, 403);
        assert_eq!(durable_state(&f), baseline);
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), saved);
    });
}
#[test]
fn a_second_scope_publishes_while_an_ungranted_source_is_forbidden() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        exchange_expecting(&f, addr, "scope-source/original", &f.request, DEVICE, 200);
    });
    let saved = f.admission().saved_view(&f.binding).unwrap();
    {
        let mut b = f.binding.clone();
        b["source"] = json!("unapproved-source");
        let (_, q) = produced(&f, b);
        serving(&f, |addr| {
            exchange_expecting(&f, addr, "scope-source/source", &q, DEVICE, 403);
        });
    }
    let mut b = f.binding.clone();
    b["scope"] = json!("second-scope");
    let (capture, q) = produced(&f, b.clone());
    configured_serving(&f, vec![trusted(&f), capture], |addr| {
        exchange_expecting(
            &f,
            addr,
            "scope-source/approved-second-scope",
            &q,
            DEVICE,
            200,
        );
        assert_eq!(f.counts(), vec![2, 2, 2, 2]);
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), saved);
    });
}
#[test]
fn revoked_device_is_refused_for_replay_and_new_sequence() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let original =
            exchange_expecting(&f, addr, "revoke-replay/original", &f.request, DEVICE, 200);
        let before = durable_state(&f);
        assert_eq!(
            exchange_expecting(&f, addr, "revoke-replay/replay", &f.request, DEVICE, 200),
            original
        );
        f.hub.revoke(f.binding["device"].as_str().unwrap()).unwrap();
        exchange_expecting(
            &f,
            addr,
            "revoke-replay/revoked-exact",
            &f.request,
            DEVICE,
            401,
        );
        let mut q: Value = serde_json::from_slice(&f.request).unwrap();
        q["sequence"] = json!(2);
        exchange_expecting(
            &f,
            addr,
            "revoke-replay/revoked-new-sequence",
            &canonical(&q),
            DEVICE,
            401,
        );
        assert_eq!(durable_state(&f), before);
    });
}
#[test]
fn removed_configuration_refuses_replay_and_new_sequence_and_keeps_saved_state() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        exchange_expecting(&f, addr, "config-removal/original", &f.request, DEVICE, 200);
    });
    let before = durable_state(&f);
    let saved = f.admission().saved_view(&f.binding).unwrap();
    configured_serving(&f, vec![], |addr| {
        exchange_expecting(
            &f,
            addr,
            "config-removal/removed-exact",
            &f.request,
            DEVICE,
            403,
        );
        let mut q: Value = serde_json::from_slice(&f.request).unwrap();
        q["sequence"] = json!(2);
        exchange_expecting(
            &f,
            addr,
            "config-removal/removed-new-sequence",
            &canonical(&q),
            DEVICE,
            403,
        );
        assert_eq!(durable_state(&f), before);
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), saved);
        assert!(Admission::open(&f.hub.database.path, vec![])
            .unwrap()
            .saved_view(&f.binding)
            .is_err());
    });
}
fn framing_database(f: &Fixture) -> Value {
    let db = Connection::open_with_flags(
        &f.hub.database.path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut state = serde_json::Map::new();
    for table in tables {
        let mut query = db
            .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
            .unwrap();
        let columns = query.column_count();
        let mut rows: Vec<Value> = query
            .query_map([], |r| {
                let mut row = Vec::new();
                for i in 0..columns {
                    row.push(match r.get_ref(i)? {
                        rusqlite::types::ValueRef::Null => Value::Null,
                        rusqlite::types::ValueRef::Integer(v) => json!({"integer":v}),
                        rusqlite::types::ValueRef::Real(v) => json!({"real":v}),
                        rusqlite::types::ValueRef::Text(v) => json!({"text":v}),
                        rusqlite::types::ValueRef::Blob(v) => json!({"blob":v}),
                    });
                }
                Ok(json!(row))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        rows.sort_by_key(canonical);
        state.insert(table, json!(rows));
    }
    Value::Object(state)
}

fn framing_probe(f: &Fixture, initial: &[u8], trickle: &[u8], message: &str) {
    let database_before = framing_database(f);
    let before = durable_state(f);
    let server = f.server();
    let addr = server.local_addr().unwrap();
    let admission = f.admission();
    let stop = AtomicBool::new(false);
    let mut peer = TcpStream::connect(addr).unwrap();
    peer.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
    peer.write_all(initial).unwrap();
    let mut sender = peer.try_clone().unwrap();
    sender
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let lower = Instant::now();
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut witness = Vec::new();
            if !trickle.is_empty() {
                thread::sleep(Duration::from_millis(20));
                witness = exchange(addr, b"");
            }
            let upper_us = lower.elapsed().as_micros();
            let done = AtomicBool::new(false);
            let (response, terminal, close_us, sends) = thread::scope(|s| {
                let writer = s.spawn(|| {
                    let mut sends = Vec::new();
                    for byte in trickle {
                        thread::sleep(Duration::from_millis(150));
                        if done.load(Ordering::Acquire) { break; }
                        let result = sender.write_all(&[*byte]);
                        sends.push(json!({"us":lower.elapsed().as_micros(),"byte":byte,"ok":result.is_ok(),"error":result.as_ref().err().map(ToString::to_string)}));
                        if result.is_err() { break; }
                    }
                    sends
                });
                let mut response = Vec::new();
                let terminal = peer.read_to_end(&mut response).err().map(|e| e.kind());
                let close_us = lower.elapsed().as_micros();
                done.store(true, Ordering::Release);
                (response, terminal, close_us, writer.join().unwrap())
            });
            drop(peer);
            let database_after = framing_database(f);
            let after = durable_state(f);
            thread::sleep(Duration::from_millis(20));
            let recovery = settled(addr, &wire(&f.request, DEVICE));
            let recovered = durable_state(f);
            let replay = settled(addr, &wire(&f.request, DEVICE));
            assert_eq!(
                database_after, database_before,
                "refusal changed logical database contents"
            );
            assert_eq!(after, before, "refusal wrote durable ACK/view state");
            assert_eq!(
                after["counts"],
                json!([0, 0, 0, 0]),
                "extra dispatch published"
            );
            assert_eq!(status(&recovery), 200, "valid same-route setup/recovery");
            native::validate_ack(&f.request, body(&recovery)).unwrap();
            assert_eq!(recovered["counts"], json!([1, 1, 1, 1]));
            assert_eq!(replay, recovery);
            assert_eq!(durable_state(f), recovered);
            assert!(terminal.is_none() || terminal == Some(std::io::ErrorKind::ConnectionReset));
            let payload = canonical(&json!({"error":message}));
            let mut permitted = format!("HTTP/1.1 400 Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",payload.len()).into_bytes();
            permitted.extend_from_slice(&payload);
            if trickle.is_empty() {
                assert_eq!(response, permitted);
            } else {
                assert_eq!(status(&witness), 503, "active acceptance witness");
                assert!(
                    permitted.starts_with(&response),
                    "deadline response outside bounded error prefix"
                );
                assert!(
                    close_us <= ACTIVE_CLOSE_BOUND.as_micros(),
                    "conservative accept-relative upper bound exceeded: {close_us}"
                );
                assert!(
                    close_us.saturating_sub(upper_us) >= 4_000_000,
                    "premature refusal"
                );
                assert!(
                    sends.iter().filter(|v| v["ok"] == true).count() >= 20,
                    "insufficient progress adversary"
                );
                assert!(sends
                    .iter()
                    .any(|v| v["ok"] == true && v["us"].as_u64().unwrap() > 4_000_000));
            }
        }));
        stop.store(true, Ordering::Release);
        h.join().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    });
}

#[test]
fn trailing_bytes_and_pipelined_requests_are_refused_without_dispatch() {
    let _exclusive = exclusive();
    for pipeline in [false, true] {
        let f = Fixture::new();
        let mut bytes = wire(&f.request, DEVICE);
        if pipeline {
            let mut next: Value = serde_json::from_slice(&f.request).unwrap();
            next["sequence"] = json!(2);
            let second = wire(&canonical(&next), DEVICE);
            bytes.extend_from_slice(&second);
        } else {
            bytes.push(b'!');
        }
        assert!(
            bytes.len() < 8192,
            "SETUP: coalesced input must fit default read buffer"
        );
        framing_probe(&f, &bytes, &[], "body_length");
    }
}

#[test]
fn trickled_request_hits_the_absolute_deadline() {
    let _exclusive = exclusive();
    for phase in ["line", "header", "body"] {
        let f = Fixture::new();
        let request = wire(&f.request, DEVICE);
        let (initial, trickle, message) = match phase {
            "line" => (
                b"POST /v2/batches HTTP/1.1".to_vec(),
                vec![b' '; 40],
                "invalid HTTP headers",
            ),
            "header" => (
                b"POST /v2/batches HTTP/1.1\r\nX-Slow: ".to_vec(),
                vec![b'a'; 40],
                "headers_incomplete",
            ),
            _ => (
                request[..request.len() - 40].to_vec(),
                request[request.len() - 40..].to_vec(),
                "truncated_request",
            ),
        };
        framing_probe(&f, &initial, &trickle, message);
    }
}

fn order_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
fn order_lock(f: &Fixture, kind: &str) -> f64 {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(&f.hub.database.path).unwrap();
    let identity = fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|entry| {
            if fs::read_link(entry.path()).ok().as_deref() != Some(f.hub.database.path.as_path()) {
                return None;
            }
            let info = fs::read_to_string(format!(
                "/proc/self/fdinfo/{}",
                entry.file_name().to_string_lossy()
            ))
            .ok()?;
            info.lines()
                .filter(|line| line.starts_with("lock:"))
                .find_map(|line| {
                    let v: Vec<_> = line.split_whitespace().collect();
                    let identity = *v.get(6)?;
                    if identity.rsplit(':').next()? == m.ino().to_string() {
                        Some(identity.to_string())
                    } else {
                        None
                    }
                })
        })
        .expect("SETUP: fdinfo lock must bind kernel identity to exact database path");
    let limit = Instant::now() + CLIENT_GUARD;
    loop {
        let locks = fs::read_to_string("/proc/locks").unwrap();
        let found = locks.lines().any(|line| {
            let v: Vec<_> = line.split_whitespace().collect();
            v.len() == 8
                && v[4] == std::process::id().to_string()
                && v[5] == identity
                && if kind == "pending" {
                    v[1] == "POSIX" && v[3] == "WRITE" && v[6] == "1073741824"
                } else {
                    v[1] == "FLOCK" && v[3] == "WRITE"
                }
        });
        if found {
            return order_now();
        }
        assert!(
            Instant::now() < limit,
            "SETUP: missing {kind} kernel lock witness"
        );
        thread::yield_now();
    }
}
fn order_refusal(f: &Fixture, addr: SocketAddr, name: &str, credential: &str) {
    let before = framing_database(f);
    exchange_expecting(f, addr, name, &f.request, credential, 401);
    assert_eq!(before, framing_database(f));
}
fn order_response(f: &Fixture, response: &[u8]) -> Vec<u8> {
    assert_eq!(status(response), 200);
    native::validate_ack(&f.request, body(response)).unwrap();
    assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    f.admission().saved_view(&f.binding).unwrap();
    body(response).to_vec()
}
#[test]
fn revoke_commit_is_ordered_against_admission_in_both_directions() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    configured_serving(&f, vec![trusted(&f)], |addr| {
        let reader = Connection::open(&f.hub.database.path).unwrap();
        reader
            .execute_batch("BEGIN; SELECT * FROM devices;")
            .unwrap();
        thread::scope(|s| {
            let h = s.spawn(|| exchange(addr, &wire(&f.request, DEVICE)));
            order_lock(&f, "pending");
            let writer = Connection::open(&f.hub.database.path).unwrap();
            writer.busy_timeout(Duration::ZERO).unwrap();
            let blocked = writer.execute_batch("BEGIN IMMEDIATE").unwrap_err();
            assert_eq!(
                blocked.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
            reader.execute_batch("ROLLBACK").unwrap();
            order_response(&f, &h.join().unwrap());
            writer.execute_batch("BEGIN IMMEDIATE").unwrap();
            writer
                .execute(
                    "UPDATE devices SET revoked=1 WHERE id=?",
                    [f.binding["device"].as_str().unwrap()],
                )
                .unwrap();
            writer.execute_batch("COMMIT").unwrap();
        });
        order_refusal(
            &f,
            addr,
            "revoke-order/admission-first/revoked-replay",
            DEVICE,
        );
        assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    });
    let f = Fixture::new();
    configured_serving(&f, vec![trusted(&f)], |addr| {
        exchange_expecting(
            &f,
            addr,
            "revoke-order/revoke-first/valid-baseline",
            &f.request,
            DEVICE,
            200,
        );
        let writer = Connection::open(&f.hub.database.path).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        writer
            .execute(
                "UPDATE devices SET revoked=1 WHERE id=?",
                [f.binding["device"].as_str().unwrap()],
            )
            .unwrap();
        let baseline = durable_state(&f);
        let admitted = AtomicBool::new(false);
        thread::scope(|s| {
            let h = s.spawn(|| until_admitted(addr, &wire(&f.request, DEVICE), &admitted));
            order_lock(&f, "held");
            admitted.store(true, Ordering::Release);
            writer.execute_batch("COMMIT").unwrap();
            let response = h.join().unwrap();
            assert_eq!(durable_state(&f), baseline);
            assert_eq!(status(&response), 401);
        });
        assert_eq!(durable_state(&f), baseline);
        order_refusal(&f, addr, "revoke-order/revoke-first/replay", DEVICE);
        assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    });
}
#[test]
fn rotated_credential_expiry_is_ordered_against_admission() {
    let _exclusive = exclusive();
    const NEW: &str = "synthetic-order-rotated-000000000000000000";
    let f = Fixture::new();
    configured_serving(&f, vec![trusted(&f)], |addr| {
        f.hub
            .rotate(f.binding["device"].as_str().unwrap(), NEW, 2.0)
            .unwrap();
        let expiry: f64 = Connection::open(&f.hub.database.path)
            .unwrap()
            .query_row("SELECT MIN(expires) FROM credentials", [], |r| r.get(0))
            .unwrap();
        while order_now() < expiry - 0.10 {
            thread::yield_now();
        }
        let reader = Connection::open(&f.hub.database.path).unwrap();
        reader
            .execute_batch("BEGIN; SELECT * FROM devices;")
            .unwrap();
        let first_ack = thread::scope(|s| {
            let h = s.spawn(|| exchange(addr, &wire(&f.request, DEVICE)));
            let pending = order_lock(&f, "pending");
            assert!(
                pending < expiry,
                "SETUP: authorization upper bracket missed overlap"
            );
            while order_now() <= expiry {
                thread::yield_now();
            }
            reader.execute_batch("ROLLBACK").unwrap();
            order_response(&f, &h.join().unwrap())
        });
        order_refusal(&f, addr, "rotation-expiry/expired-replay", DEVICE);
        let saved = durable_state(&f);
        let response = exchange_expecting(
            &f,
            addr,
            "rotation-expiry/new-credential-replay",
            &f.request,
            NEW,
            200,
        );
        assert_eq!(body(&response), first_ack);
        assert_eq!(durable_state(&f), saved);
    });
    let f = Fixture::new();
    configured_serving(&f, vec![trusted(&f)], |addr| {
        f.hub
            .rotate(f.binding["device"].as_str().unwrap(), NEW, 2.0)
            .unwrap();
        let writer = Connection::open(&f.hub.database.path).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let expiry: f64 = writer
            .query_row("SELECT MIN(expires) FROM credentials", [], |r| r.get(0))
            .unwrap();
        while order_now() < expiry - 0.10 {
            thread::yield_now();
        }
        let before = durable_state(&f);
        thread::scope(|s| {
            let sent = order_now();
            assert!(sent < expiry, "SETUP: request must arrive during overlap");
            let h = s.spawn(|| exchange(addr, &wire(&f.request, DEVICE)));
            order_lock(&f, "held");
            while order_now() <= expiry {
                thread::yield_now();
            }
            writer.execute_batch("COMMIT").unwrap();
            let response = h.join().unwrap();
            assert_eq!(status(&response), 401);
        });
        assert_eq!(durable_state(&f), before);
        let ack = exchange_expecting(
            &f,
            addr,
            "rotation-expiry/new-credential-recovery",
            &f.request,
            NEW,
            200,
        );
        order_response(&f, &ack);
    });
}
fn v1_queue(out: &vorda::link::client::Outbox) -> Value {
    let db = Connection::open(&out.database.path).unwrap();
    let rows: Vec<Value> = db
        .prepare("SELECT sequence,payload,attempts,due FROM pending ORDER BY sequence")
        .unwrap()
        .query_map([], |r| {
            Ok(json!([
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, f64>(3)?
            ]))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    json!({"identity":out.identity().unwrap(),"pending":rows})
}

#[derive(Clone, Copy)]
enum V1Reply {
    BadAck,
    RetryAfter,
    Ack,
}
fn v1_relay(
    addr: SocketAddr,
    out: &vorda::link::client::Outbox,
    reply: V1Reply,
    at: f64,
) -> (bool, Vec<u8>, Vec<u8>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = listener.local_addr().unwrap();
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(at.to_bits()));
    let reply_clock = clock.clone();
    thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
            let mut request = Vec::new();
            let mut one = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut one).unwrap();
                request.push(one[0]);
                assert!(request.len() <= 8192);
            }
            let n: usize = std::str::from_utf8(&request)
                .unwrap()
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            let start = request.len();
            request.resize(start + n, 0);
            s.read_exact(&mut request[start..]).unwrap();
            let response = settled(addr, &request);
            assert_eq!(status(&response), 200);
            let batch: Value = serde_json::from_slice(&request[start..]).unwrap();
            let mut ack: Value = serde_json::from_slice(body(&response)).unwrap();
            vorda::link::client::validate_ack(&batch, &ack).unwrap();
            let sent_body = request[start..].to_vec();
            let server_response = response.clone();
            let sent = if matches!(reply, V1Reply::RetryAfter) {
                b"HTTP/1.1 503 Busy\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            } else if matches!(reply, V1Reply::BadAck) {
                ack["digest"] = json!("0".repeat(64));
                let b = vorda::link::encode(&ack).unwrap();
                let mut raw = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                )
                .into_bytes();
                raw.extend(b);
                raw
            } else {
                response
            };
            reply_clock.store((at + 0.5).to_bits(), Ordering::SeqCst);
            s.write_all(&sent).unwrap();
            (sent_body, server_response)
        });
        let ok = out
            .deliver_with_clock(&format!("http://{relay}"), DEVICE, None, || {
                f64::from_bits(clock.load(Ordering::SeqCst))
            })
            .unwrap()
            .is_some();
        let (sent_body, server_response) = peer.join().unwrap();
        (ok, sent_body, server_response)
    })
}

fn v1_outbox_through_listener(after_v2: bool, retry_after: bool) {
    use vorda::link::{self, client::Outbox};
    let f = Fixture::new();
    let out = Outbox::open(&f._tmp.path().join("legacy.db")).unwrap();
    out.bind(
        f.binding["device"].as_str().unwrap(),
        f.binding["generation"].as_str().unwrap(),
    )
    .unwrap();
    // Materialize an existing legacy identity at sequence six, then enqueue through the public API.
    out.database
        .connect()
        .unwrap()
        .execute("UPDATE identity SET sequence=6", [])
        .unwrap();
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/capture/V1.json")).unwrap();
    batch["device"] = f.binding["device"].clone();
    batch["generation"] = f.binding["generation"].clone();
    let queued = out.enqueue(&batch).unwrap();
    assert_eq!(queued["sequence"], 7);
    let original = link::encode(&queued).unwrap();
    let mut at = vorda::store::now();
    serving(&f, |addr| {
        let original_ack = if after_v2 {
            Some(exchange_expecting(
                &f,
                addr,
                "v1-isolation-v2-publish",
                &f.request,
                DEVICE,
                200,
            ))
        } else {
            None
        };
        let before = framing_database(&f);
        for (name, bad) in [("bad7", true), ("good7", false), ("good8", false)] {
            if name == "good7" {
                let due = v1_queue(&out)["pending"][0][3].as_f64().unwrap();
                let before = v1_queue(&out);
                assert!(out
                    .deliver_with_clock(&format!("http://{addr}"), DEVICE, None, || due - 0.001)
                    .unwrap()
                    .is_none());
                assert_eq!(
                    v1_queue(&out),
                    before,
                    "not eligible before the saved due time"
                );
                at = due;
            }
            if name == "good8" {
                batch["scan"] = json!("00000000-0000-4000-8000-000000000008");
                assert_eq!(out.enqueue(&batch).unwrap()["sequence"], 8);
            }
            let reply = if !bad {
                V1Reply::Ack
            } else if retry_after {
                V1Reply::RetryAfter
            } else {
                V1Reply::BadAck
            };
            let (ok, wire_body, server_response) = v1_relay(addr, &out, reply, at);
            assert_eq!(ok, !bad);
            if name != "good8" {
                assert_eq!(wire_body, original);
            }
            let queue = v1_queue(&out);
            if bad {
                assert_eq!(queue["pending"][0][0], 7);
                assert_eq!(queue["pending"][0][1], json!(original));
                assert_eq!(queue["pending"][0][2], 1);
                let delay = queue["pending"][0][3].as_f64().unwrap() - (at + 0.5);
                if retry_after {
                    assert_eq!(delay, 5.0, "wait exactly the hub's Retry-After, not longer");
                } else {
                    assert!((1.0..=2.0).contains(&delay), "initial jitter: {delay}");
                    assert!(
                        delay < 3.0,
                        "retry must not be scheduled unboundedly far away"
                    );
                }
                assert_eq!(
                    link::digest(&queued).unwrap(),
                    serde_json::from_slice::<Value>(body(&server_response)).unwrap()["digest"]
                );
            } else {
                assert_eq!(queue["pending"], json!([]));
            }
            let now = framing_database(&f);
            for (table, rows) in before.as_object().unwrap() {
                if table.starts_with("v2_") {
                    assert_eq!(&now[table], rows, "v1 mutated {table}");
                }
            }
        }
        assert_eq!(out.identity().unwrap().unwrap()["sequence"], 8);
        let after = framing_database(&f);
        assert_ne!(before, after, "must observe real v1 publication");
        if let Some(ack) = original_ack {
            let replay =
                exchange_expecting(&f, addr, "v1-isolation-v2-replay", &f.request, DEVICE, 200);
            assert_eq!(body(&ack), body(&replay));
            assert_eq!(framing_database(&f), after);
        }
    });
}
#[test]
fn v1_sender_retries_a_bad_ack_and_drains_through_the_listener() {
    let _exclusive = exclusive();
    v1_outbox_through_listener(false, false);
}
#[test]
fn v1_publication_leaves_v2_rows_and_replay_unchanged() {
    let _exclusive = exclusive();
    v1_outbox_through_listener(true, false);
}
#[test]
fn v1_retry_after_controls_the_saved_deadline_and_eligibility() {
    let _exclusive = exclusive();
    v1_outbox_through_listener(false, true);
}
fn precedence_artifact(f: &Fixture, a: &Value) -> Vec<u8> {
    precedence_raw(f, String::from_utf8(canonical(a)).unwrap())
}
fn precedence_raw(f: &Fixture, raw: String) -> Vec<u8> {
    let mut q: Value = serde_json::from_slice(&f.request).unwrap();
    q["artifact_sha256"] = json!(hash(raw.as_bytes()));
    q["artifact_byte_length"] = json!(raw.len());
    q["artifact_utf8"] = json!(raw);
    canonical(&q)
}
#[test]
fn refusal_precedence_by_credential_class() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let a: Value = serde_json::from_str(&f.raw).unwrap();
    let input = a["inputs"][0]["bytes_utf8"].as_str().unwrap();
    let mut cases: Vec<(&str, Vec<u8>, u16, u16)> = vec![];
    let mut q = f.request.clone();
    let pos = q.iter().position(|b| *b == b'a').unwrap();
    q[pos] = 0xff;
    cases.push(("wire-utf8", q, 400, 400));
    cases.push((
        "artifact-surrogate",
        precedence_raw(&f, f.raw.replacen("{", "{\"bad\":\"\\ud800\",", 1)),
        400,
        400,
    ));
    let mut changed = a.clone();
    let text = input.replacen("{", "{\"bad\":\"\\ud800\",", 1);
    changed["inputs"][0]["sha256"] = json!(hash(text.as_bytes()));
    changed["inputs"][0]["bytes_utf8"] = json!(text);
    cases.push((
        "input-surrogate",
        precedence_artifact(&f, &changed),
        401,
        422,
    ));
    let mut changed = a.clone();
    let text = input.replacen("{", "{\"lockfileVer\\u0073ion\":3,", 1);
    changed["inputs"][0]["sha256"] = json!(hash(text.as_bytes()));
    changed["inputs"][0]["bytes_utf8"] = json!(text);
    cases.push((
        "input-escaped-duplicate",
        precedence_artifact(&f, &changed),
        401,
        422,
    ));
    let mut changed = a.clone();
    changed["records"][0]["package"]
        .as_object_mut()
        .unwrap()
        .remove("namespace");
    cases.push((
        "artifact-missing-field",
        precedence_artifact(&f, &changed),
        400,
        400,
    ));
    let mut q = f.request.clone();
    q.push(b' ');
    cases.push(("noncanonical-envelope", q, 400, 400));
    let mut q: Value = serde_json::from_slice(&f.request).unwrap();
    q["schema"] = json!(3);
    cases.push(("unsupported-schema", canonical(&q), 422, 422));
    let mut changed = a.clone();
    changed["inputs"][0]["bytes_utf8"] = json!("x".repeat(4 * 1024 * 1024 + 1));
    cases.push((
        "nested-input-size",
        precedence_artifact(&f, &changed),
        413,
        413,
    ));
    let mut q: Value = serde_json::from_slice(&f.request).unwrap();
    q["artifact_byte_length"] = json!(f.raw.len() + 1);
    cases.push(("semantic-artifact-length", canonical(&q), 401, 422));
    let mut q: Value = serde_json::from_slice(&f.request).unwrap();
    q["artifact_sha256"] = json!("0".repeat(64));
    cases.push(("semantic-artifact-hash", canonical(&q), 401, 422));
    let mut changed = a.clone();
    changed["inputs"][0]["sha256"] = json!("0".repeat(64));
    cases.push((
        "semantic-input-hash",
        precedence_artifact(&f, &changed),
        401,
        422,
    ));
    let mut q: Value = serde_json::from_slice(&f.request).unwrap();
    q["binding"]["site"] = json!("different-site");
    cases.push(("identity-binding", canonical(&q), 401, 403));
    let mut q: Value = serde_json::from_slice(&f.request).unwrap();
    q["binding"]["scope"] = json!("unapproved-scope");
    cases.push(("trusted-binding", canonical(&q), 401, 403));
    serving(&f, |addr| {
        let original = exchange_expecting(&f, addr, "precedence/positive", &f.request, DEVICE, 200);
        assert_eq!(f.counts(), vec![1, 1, 1, 1]);
        for (name, bytes, invalid, valid) in cases {
            for (class, credential, expected) in
                [("invalid", UNKNOWN, invalid), ("valid", DEVICE, valid)]
            {
                let name = format!("precedence/{name}/{class}");
                let before = framing_database(&f);
                exchange_expecting(&f, addr, &name, &bytes, credential, expected);
                assert_eq!(before, framing_database(&f), "{name}: any hub row changed");
            }
        }
        let replay = exchange_expecting(&f, addr, "precedence/replay", &f.request, DEVICE, 200);
        assert_eq!(replay, original);
        let mut q: Value = serde_json::from_slice(&f.request).unwrap();
        q["sequence"] = json!(2);
        exchange_expecting(&f, addr, "precedence/recovery", &canonical(&q), DEVICE, 200);
        assert_eq!(f.counts(), vec![2, 1, 1, 1]);
    });
}

fn tls_client_connection(cert: &std::path::Path, hostname: &str) -> rustls::ClientConnection {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_reader_iter(fs::File::open(cert).unwrap()) {
        roots.add(c.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        rustls::pki_types::ServerName::try_from(hostname.to_string()).unwrap(),
    )
    .unwrap()
}
fn tls_client_stream(
    addr: SocketAddr,
    cert: &std::path::Path,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
    tcp.set_write_timeout(Some(CLIENT_GUARD)).unwrap();
    let mut s = rustls::StreamOwned::new(tls_client_connection(cert, "localhost"), tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).unwrap();
    }
    assert!(matches!(
        s.conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2 | rustls::ProtocolVersion::TLSv1_3)
    ));
    s
}
fn accepted_sockets(addr: SocketAddr) -> usize {
    let table = fs::read_to_string("/proc/net/tcp").unwrap();
    let fds: Vec<String> = fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|p| fs::read_link(p.path()).ok())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    // The live TCP table can repeat a row during connection churn. Count socket
    // identities, so duplicate rows do not invent a third accepted socket.
    let sockets: std::collections::BTreeSet<_> = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let v: Vec<_> = line.split_whitespace().collect();
            if v[1].ends_with(&format!(":{:04X}", addr.port()))
                && v[3] != "0A"
                && fds.contains(&format!("socket:[{}]", v[9]))
            {
                Some(v[9].to_string())
            } else {
                None
            }
        })
        .collect();
    sockets.len()
}
fn await_close(tcp: &mut TcpStream) {
    let mut b = [0; 8192];
    loop {
        match tcp.read(&mut b) {
            Ok(0) => return,
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return,
            Err(e) => panic!("unexpected close observation failure: {e:?}"),
        }
    }
}
#[test]
fn tls_refusals_and_stalls_leave_the_hub_unchanged() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let (cert, key) = tls_files(&f);
    let other = Fixture::new();
    let (wrong_ca, _) = tls_files(&other);
    let server = Server::bind(
        Hub::open(&f.hub.database.path).unwrap(),
        "127.0.0.1",
        0,
        Some(&cert),
        Some(&key),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let admission = f.admission();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let h = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let baseline =
                tls_request(addr, &cert, "localhost", &wire(&f.request, DEVICE)).unwrap();
            order_response(&f, &baseline);
            let db = framing_database(&f);
            let state = durable_state(&f);
            for (name, ca, host) in [
                ("hostname", &cert, "wrong.invalid"),
                ("ca", &wrong_ca, "localhost"),
            ] {
                thread::sleep(Duration::from_millis(30));
                let e = tls_request(addr, ca, host, &wire(&f.request, DEVICE)).unwrap_err();
                let concrete = e
                    .get_ref()
                    .and_then(|v| v.downcast_ref::<rustls::Error>())
                    .expect("concrete rustls error required");
                match concrete {
                    rustls::Error::InvalidCertificate(
                        rustls::CertificateError::UnknownIssuer
                        | rustls::CertificateError::BadSignature,
                    ) if name == "ca" => (),
                    rustls::Error::InvalidCertificate(
                        rustls::CertificateError::NotValidForNameContext { .. },
                    ) if name == "hostname" => (),
                    v => panic!("wrong validation category: {v:?}"),
                }
                assert_eq!(framing_database(&f), db);
                assert_eq!(durable_state(&f), state);
                thread::sleep(Duration::from_millis(30));
                let r = tls_settled(addr, &cert, &wire(&f.request, DEVICE));
                assert_eq!(r, baseline);
            }
            for established in [false, true] {
                quiet(addr);
                let mut tls = None;
                let mut raw = None;
                if established {
                    let mut s = tls_client_stream(addr, &cert);
                    s.write_all(b"POST /v2/batches HTTP/1.1\r\nX-Progress: ")
                        .unwrap();
                    s.flush().unwrap();
                    tls = Some(s);
                } else {
                    let mut s = TcpStream::connect(addr).unwrap();
                    s.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
                    let mut c = tls_client_connection(&cert, "localhost");
                    while c.wants_write() {
                        c.write_tls(&mut s).unwrap();
                    }
                    let mut bytes = [0; 8192];
                    let n = s.read(&mut bytes).unwrap();
                    assert!(n > 0 && c.is_handshaking());
                    raw = Some(s);
                }
                assert_eq!(accepted_sockets(addr), 1);
                let mut busy = TcpStream::connect(addr).unwrap();
                busy.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
                let mut c = tls_client_connection(&cert, "localhost");
                while c.wants_write() {
                    c.write_tls(&mut busy).unwrap();
                }
                let mut bytes = [0; 8192];
                let n = busy.read(&mut bytes).unwrap();
                assert!(n > 0);
                assert_eq!(accepted_sockets(addr), 2);
                await_close(&mut busy);
                assert_eq!(framing_database(&f), db);
                assert_eq!(durable_state(&f), state);
                let rejection = tls_request(addr, &cert, "localhost", b"").unwrap();
                assert_eq!(status(&rejection), 503);
                assert!(rejection.windows(16).any(|v| v == b"Retry-After: 5\r\n"));
                assert!(rejection.windows(19).any(|v| v == b"Connection: close\r\n"));
                assert!(body(&rejection).len() <= 4096);
                let _: Value = serde_json::from_slice(body(&rejection)).unwrap();
                assert_eq!(framing_database(&f), db);
                assert_eq!(durable_state(&f), state);
                if let Some(s) = tls.as_mut() {
                    for _ in 0..3 {
                        thread::sleep(Duration::from_millis(1000));
                        s.write_all(b"x").unwrap();
                        s.flush().unwrap();
                    }
                }
                let active = if let Some(s) = tls.as_mut() {
                    &mut s.sock
                } else {
                    raw.as_mut().unwrap()
                };
                await_close(active);
                assert_eq!(framing_database(&f), db);
                assert_eq!(durable_state(&f), state);
                thread::sleep(Duration::from_millis(30));
                let recovered = tls_settled(addr, &cert, &wire(&f.request, DEVICE));
                assert_eq!(recovered, baseline);
            }
        }));
        stop.store(true, Ordering::Release);
        h.join().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    });
}

#[test]
fn migrated_hub_replays_v2_and_v1_across_restart() {
    let _exclusive = exclusive();
    let f = Fixture::with_legacy(true);
    let LegacyV1 {
        request: legacy,
        ack,
        snapshot: snapshot_bytes,
        rows: old,
    } = f.v1.clone().unwrap();
    let migrated = framing_database(&f);
    for (table, rows) in old.as_object().unwrap() {
        assert_eq!(&migrated[table], rows, "migration changed {table}");
    }
    assert_eq!(f.counts(), vec![0, 0, 0, 0]);
    let mut original = Vec::new();
    serving(&f, |addr| {
        original = exchange_expecting(
            &f,
            addr,
            "migration-restart/publish",
            &f.request,
            DEVICE,
            200,
        );
    });
    assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    let saved = f.admission().saved_view(&f.binding).unwrap();
    let before = framing_database(&f);
    serving(&f, |addr| {
        let replay = exchange_expecting(
            &f,
            addr,
            "migration-restart/replay",
            &f.request,
            DEVICE,
            200,
        );
        assert_eq!(body(&replay), body(&original));
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), saved);
        assert_eq!(framing_database(&f), before);
        let mut request = format!("POST /v1/batches HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {DEVICE}\r\nContent-Length: {}\r\n\r\n", legacy.len()).into_bytes();
        request.extend(&legacy);
        let response = exchange(addr, &request);
        assert_eq!(status(&response), 200);
        assert_eq!(body(&response), ack);
        let snapshot = f
            .hub
            .snapshot(f.binding["device"].as_str().unwrap())
            .unwrap();
        assert_eq!(canonical(&snapshot), snapshot_bytes);
        assert_eq!(framing_database(&f), before);
    });
    let after = framing_database(&f);
    for (table, rows) in old.as_object().unwrap() {
        assert_eq!(&after[table], rows, "restart changed {table}");
    }
    let db = f.hub.database.connect().unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(db);
}

#[cfg(feature = "native-admission-test")]
struct EnvGuard(&'static str);
#[cfg(feature = "native-admission-test")]
impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        std::env::set_var(key, value);
        Self(key)
    }
}
#[cfg(feature = "native-admission-test")]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var(self.0);
    }
}

#[cfg(feature = "native-admission-test")]
fn budget_refusal_then_recovery(
    f: &Fixture,
    addr: SocketAddr,
    name: &str,
    refuse: impl FnOnce() -> Vec<u8>,
) {
    let before = framing_database(f);
    let refused = refuse();
    assert_eq!(status(&refused), 503, "{name}");
    let head =
        std::str::from_utf8(&refused[..refused.windows(4).position(|w| w == b"\r\n\r\n").unwrap()])
            .unwrap();
    assert!(head.contains("Retry-After: 5"), "{name}: {head}");
    assert!(head.contains("Connection: close"), "{name}: {head}");
    assert_eq!(f.counts(), vec![0, 0, 0, 0], "{name}: refusal published");
    assert_eq!(
        framing_database(f),
        before,
        "{name}: refusal changed durable rows"
    );

    let ok = exchange_expecting(f, addr, &format!("{name}/retry"), &f.request, DEVICE, 200);
    assert_eq!(f.counts(), vec![1, 1, 1, 1]);
    let committed = framing_database(f);
    let saved = f.admission().saved_view(&f.binding).unwrap();
    let replay = exchange_expecting(f, addr, &format!("{name}/replay"), &f.request, DEVICE, 200);
    assert_eq!(replay, ok, "{name}: replay differs from first ACK");
    assert_eq!(framing_database(f), committed);
    assert_eq!(f.admission().saved_view(&f.binding).unwrap(), saved);
}

#[cfg(feature = "native-admission-test")]
#[test]
fn full_database_refuses_with_503_then_recovers() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        budget_refusal_then_recovery(&f, addr, "budget-db-full", || {
            let _cap = EnvGuard::set("VORDA_NATIVE_PAGE_LIMIT", "current");
            exchange(addr, &wire(&f.request, DEVICE))
        });
    });
}

#[cfg(feature = "native-admission-test")]
#[test]
fn budget_expired_before_acquisition_refuses_with_503_then_recovers() {
    let _exclusive = exclusive();
    use std::os::unix::fs::OpenOptionsExt;
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("hold");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    serving(&f, |addr| {
        budget_refusal_then_recovery(&f, addr, "budget-expiry", || {
            let _hold = EnvGuard::set("VORDA_NATIVE_HOLD_FIFO", &fifo);
            let request = wire(&f.request, DEVICE);
            let client = thread::spawn(move || exchange(addr, &request));
            // Non-blocking writer open succeeds only once the admission hook is reading the FIFO.
            let start = Instant::now();
            let mut writer = loop {
                match fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&fifo)
                {
                    Ok(w) => break w,
                    Err(_) if start.elapsed() < CLIENT_GUARD => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("admission-held hook never opened the FIFO: {e}"),
                }
            };
            let held = Instant::now();
            thread::sleep(Duration::from_millis(1200));
            assert!(held.elapsed() >= Duration::from_millis(1100));
            writer.write_all(&[1]).unwrap();
            client.join().unwrap()
        });
    });
}

#[cfg(feature = "native-admission-test")]
#[test]
fn budget_expired_before_acquisition_still_delivers_the_refusal() {
    let _exclusive = exclusive();
    use std::os::unix::fs::OpenOptionsExt;
    let f = Fixture::new();
    let fifo = f._tmp.path().join("reply-hold");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let _hold = EnvGuard::set("VORDA_NATIVE_HOLD_FIFO", &fifo);
    let server = f.server();
    let addr = server.local_addr().unwrap();
    let admission = f.admission();
    thread::scope(|scope| {
        let served = scope.spawn(|| server.serve_once_with_admission(&admission));
        let client = scope.spawn(|| exchange(addr, &wire(&f.request, DEVICE)));
        let start = Instant::now();
        let mut writer = loop {
            match fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
            {
                Ok(writer) => break writer,
                Err(_) if start.elapsed() < CLIENT_GUARD => thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("admission did not reach the hold point: {e}"),
            }
        };
        // The FIFO witnesses admission readiness. Cross the five-second socket deadline
        // deliberately, then let the product's own expired-budget path produce its refusal.
        thread::sleep(Duration::from_millis(5100));
        writer.write_all(&[1]).unwrap();
        drop(writer);
        let served = served.join().unwrap();
        let response = client.join().unwrap();
        assert!(
            !response.is_empty(),
            "completed refusal was lost: {served:?}"
        );
        assert!(served.is_ok(), "{served:?}");
        assert_eq!(status(&response), 503);
        assert!(response.windows(16).any(|w| w == b"Retry-After: 5\r\n"));
        assert_eq!(
            serde_json::from_slice::<Value>(body(&response)).unwrap(),
            json!({"error":"storage unavailable; retry later"})
        );
    });
    assert_eq!(f.counts(), vec![0, 0, 0, 0]);
}

// Allocation-capacity: each ceiling is exercised through the socket at the limit and one past it.
fn batch(
    f: &Fixture,
    artifact: &Value,
    evidence: &str,
    sequence: u64,
) -> (TrustedCapture, Vec<u8>) {
    let raw = String::from_utf8(canonical(artifact)).unwrap();
    let mut q: Value = serde_json::from_slice(&f.request).unwrap();
    q["sequence"] = json!(sequence);
    q["evidence_id"] = json!(evidence);
    q["artifact_utf8"] = json!(raw);
    q["artifact_sha256"] = json!(hash(raw.as_bytes()));
    q["artifact_byte_length"] = json!(raw.len());
    let capture = TrustedCapture {
        binding: f.binding.clone(),
        evidence_id: evidence.into(),
        artifact_utf8: raw,
    };
    (capture, canonical(&q))
}
const BUSY_RETRIES: usize = 2000;
// A connection made before the previous worker has exited is refused 503, undispatched; the busy and
// storage refusals share one body, so callers must expect a non-503 and a 503 is never accepted.
fn not_busy(mut attempt: impl FnMut() -> Vec<u8>) -> Vec<u8> {
    for _ in 0..BUSY_RETRIES {
        let response = attempt();
        if !response.is_empty() && status(&response) != 503 {
            return response;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("still busy");
}
// Retries a pre-dispatch 503 only until the admission lock is witnessed; a later 503 is returned.
fn until_admitted(addr: SocketAddr, request: &[u8], admitted: &AtomicBool) -> Vec<u8> {
    for _ in 0..BUSY_RETRIES {
        let response = exchange(addr, request);
        if admitted.load(Ordering::Acquire) || (!response.is_empty() && status(&response) != 503) {
            return response;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("still busy");
}
fn tls_settled(addr: SocketAddr, cert: &std::path::Path, request: &[u8]) -> Vec<u8> {
    not_busy(|| tls_request(addr, cert, "localhost", request).expect("SETUP: TLS request"))
}
// Waits until the server has released the previous connection so a timing sample cannot hit the busy slot.
fn quiet(addr: SocketAddr) {
    let start = Instant::now();
    while accepted_sockets(addr) != 0 {
        assert!(
            start.elapsed() < CLIENT_GUARD,
            "SETUP: server never released the previous connection"
        );
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(100));
}
fn settled(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    not_busy(|| exchange(addr, request))
}
fn padded_input(artifact: &mut Value, index: usize, pad: usize) {
    let bytes: String = artifact["inputs"][index]["bytes_utf8"]
        .as_str()
        .unwrap()
        .trim_end()
        .to_string();
    let bytes = format!("{bytes}{}", " ".repeat(pad));
    artifact["inputs"][index]["sha256"] = json!(hash(bytes.as_bytes()));
    artifact["inputs"][index]["bytes_utf8"] = json!(bytes);
}
fn with_second_input(f: &Fixture, suffix: &str) -> Value {
    let mut a: Value = serde_json::from_str(&f.raw).unwrap();
    let mut input = a["inputs"][0].clone();
    let mut record = a["records"][0].clone();
    input["path"] = json!(format!("two{suffix}/package-lock.json"));
    record["input_path"] = input["path"].clone();
    for key in ["record_id", "component_id", "location_ref"] {
        record[key] = json!(format!("{}{suffix}", record[key].as_str().unwrap()));
    }
    a["inputs"].as_array_mut().unwrap().push(input);
    a["records"].as_array_mut().unwrap().push(record);
    a
}

#[test]
fn delivery_ceiling_accepts_128_and_refuses_the_129th() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    serving(&f, |addr| {
        let mut q: Value = serde_json::from_slice(&f.request).unwrap();
        for sequence in 1..=129u64 {
            q["sequence"] = json!(sequence);
            let response = settled(addr, &wire(&canonical(&q), DEVICE));
            if sequence <= 128 {
                assert_eq!(status(&response), 200, "sequence {sequence}");
            } else {
                assert_eq!(status(&response), 413);
            }
        }
        // Only the first delivery published; the other 127 replayed the same assessment.
        assert_eq!(f.counts(), vec![128, 1, 1, 1]);
    });
}

#[test]
fn history_ceiling_accepts_64_assessments_and_refuses_the_65th() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let (captures, requests): (Vec<_>, Vec<_>) = (0..65u64)
        .map(|i| {
            let mut a: Value = serde_json::from_str(&f.raw).unwrap();
            a["assessment_id"] = json!(format!("history-{i}"));
            a["revision"] = json!(i + 1);
            a["records"][0]["record_id"] = json!(format!("history-record-{i}"));
            batch(&f, &a, &format!("history-evidence-{i}"), i + 1)
        })
        .unzip();
    configured_serving(&f, captures, |addr| {
        for (i, request) in requests.iter().enumerate().take(64) {
            assert_eq!(
                status(&settled(addr, &wire(request, DEVICE))),
                200,
                "assessment {i}"
            );
        }
        assert_eq!(f.counts(), vec![64, 64, 64, 64]);
        let view = f.admission().saved_view(&f.binding).unwrap();
        assert_eq!(status(&settled(addr, &wire(&requests[64], DEVICE))), 413);
        assert_eq!(f.counts(), vec![64, 64, 64, 64]);
        assert_eq!(f.admission().saved_view(&f.binding).unwrap(), view);
    });
}

#[test]
fn artifact_size_and_input_count_ceilings_refuse_past_the_limit() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    // The artifact text is bounded at 4 MiB. Whitespace padding in an input's lockfile text sizes
    // it exactly.
    let sized = |total: usize| {
        let mut a = with_second_input(&f, "-2");
        padded_input(&mut a, 0, 64000);
        padded_input(&mut a, 1, 0);
        let base = canonical(&a).len();
        padded_input(&mut a, 1, total - base);
        assert_eq!(canonical(&a).len(), total);
        a
    };
    let (large, request) = batch(&f, &sized(3 * 1024 * 1024), &f.evidence, 1);
    let (_, one_past) = batch(&f, &sized(4 * 1024 * 1024 + 1), &f.evidence, 1);
    // One input past the 256 a capture may select.
    let (_, too_many_inputs) = batch(
        &f,
        &{
            let mut a = with_second_input(&f, "-2");
            for n in 3..=257 {
                let more = with_second_input(&f, &format!("-{n}"));
                a["inputs"]
                    .as_array_mut()
                    .unwrap()
                    .push(more["inputs"][1].clone());
                a["records"]
                    .as_array_mut()
                    .unwrap()
                    .push(more["records"][1].clone());
            }
            a
        },
        &f.evidence,
        1,
    );
    // An unoptimised build takes longer over a 3 MiB artifact than the one-second budget a hub has.
    let bindings = [large.binding.clone()];
    let admission = granted(
        Admission::open(&f.hub.database.path, vec![large]).unwrap(),
        &f.hub.database.path,
        &bindings,
    )
    .with_budget(Duration::from_secs(30));
    serving_admission(&f, admission, |addr| {
        for credential in [UNKNOWN, DEVICE] {
            assert_eq!(status(&settled(addr, &wire(&one_past, credential))), 413);
            assert_eq!(
                status(&settled(addr, &wire(&too_many_inputs, credential))),
                413
            );
        }
        assert_eq!(f.counts(), vec![0, 0, 0, 0]);
        let r = settled(addr, &wire(&request, DEVICE));
        assert_eq!(status(&r), 200, "{}", String::from_utf8_lossy(body(&r)));
        assert_eq!(f.counts(), vec![1, 1, 1, 2]);
    });
}

#[test]
fn stalled_tls_flood_never_holds_more_than_two_accepted_sockets() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let (cert, key) = tls_files(&f);
    tls_serving(&f, &cert, &key, |addr| {
        // One active slot plus one busy rejection handshake; the rest wait in the kernel backlog.
        let peers: Vec<_> = (0..5).map(|_| TcpStream::connect(addr).unwrap()).collect();
        let mut peak = 0;
        let sampling = Instant::now();
        while sampling.elapsed() < CLIENT_GUARD
            && (sampling.elapsed() < Duration::from_millis(600) || peak < 2)
        {
            peak = peak.max(accepted_sockets(addr));
        }
        assert_eq!(peak, 2);
        drop(peers);
        thread::sleep(Duration::from_millis(1100));
        assert_eq!(
            status(&tls_settled(addr, &cert, &wire(&f.request, DEVICE))),
            200
        );
    });
}

// Holds the final handshake flight until `at_ms` after connect, then reports whether the server answers.
fn tls_final_flight_answered(addr: SocketAddr, cert: &std::path::Path, at_ms: u64) -> bool {
    let origin = Instant::now();
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(CLIENT_GUARD)).unwrap();
    let mut client = tls_client_connection(cert, "localhost");
    client.write_tls(&mut tcp).unwrap();
    while client.is_handshaking() {
        assert!(
            client.read_tls(&mut tcp).unwrap() > 0,
            "SETUP: server flight"
        );
        client.process_new_packets().unwrap();
    }
    thread::sleep(Duration::from_millis(at_ms).saturating_sub(origin.elapsed()));
    client.writer().write_all(b"\r\n\r\n").unwrap();
    while client.wants_write() {
        let _ = client.write_tls(&mut tcp);
    }
    let mut answer = [0; 16];
    while let Ok(n) = client.read_tls(&mut tcp) {
        if n == 0 || client.process_new_packets().is_err() {
            break;
        }
        if client.reader().read(&mut answer).is_ok_and(|n| n > 0) {
            return answer.starts_with(b"HTTP/1.1 ");
        }
    }
    false
}

#[test]
fn tls_late_final_flight_is_not_promoted() {
    let _exclusive = exclusive();
    let f = Fixture::new();
    let (cert, key) = tls_files(&f);
    tls_serving(&f, &cert, &key, |addr| {
        // A final flight well inside the 950 ms cutoff completes the handshake.
        assert!(tls_final_flight_answered(addr, &cert, 600));
        quiet(addr);
        // A final flight arriving after the cutoff must not complete the handshake.
        assert!(!tls_final_flight_answered(addr, &cert, 990));
    });
    assert_eq!(f.counts(), vec![0, 0, 0, 0]);
}
