#[path = "common/tls.rs"]
mod tls;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::TcpStream,
};
use vorda::{
    domain::Record,
    link::{
        self,
        client::{request, sign_receipt, Outbox},
        server::Server,
        storage::Hub,
    },
    store::{identity, python_json, Store},
};

const INVITE: &str = "synthetic-invite-for-tests-only-0000";
const CREDENTIAL: &str = "synthetic-device-for-tests-only-0000";
const OTHER: &str = "synthetic-other-for-tests-only-00000";
fn finding() -> Record {
    json!({"key":"finding-a","asset":"asset-a","title":"example finding","package":{"name":"example","version":"1","ecosystem":"npm","path":"/selected/lock","scope":"reachable-unknown"},"kev":false,"epss":0.1}).as_object().unwrap().clone()
}
fn batch(identity: &Value, sequence: i64, state: &str, findings: bool) -> Value {
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/link-v1.json")).unwrap();
    batch["device"] = identity["device"].clone();
    batch["generation"] = identity["generation"].clone();
    batch["sequence"] = json!(sequence);
    batch["scan"] = json!(uuid::Uuid::new_v4().to_string());
    batch["observed"] = json!(vorda::store::now());
    batch["coverage"] = json!({"project-a":state});
    if !findings {
        batch["findings"] = json!([]);
    }
    batch
}
fn enrolled(root: &std::path::Path) -> (Hub, Value) {
    let hub = Hub::open(&root.join("hub.db")).unwrap();
    hub.invite(INVITE, "org-a", "site-a", 600.0).unwrap();
    let identity = hub.enroll(INVITE, CREDENTIAL).unwrap();
    (hub, identity)
}

#[test]
fn python_identity_preserves_unicode_numeric_and_spacing_semantics() {
    let value: Value = serde_json::from_str(r#"{"astral":"😀","accent":"é","float":1e-7,"large":100000000000000000000000000000000000000000000000000,"negative":-0.0}"#).unwrap();
    assert_eq!(identity(&value).unwrap(), "a39b43bf91548f3ec94b0831");
    assert_eq!(
        python_json(&value, false).unwrap(),
        r#"{"accent": "\u00e9", "astral": "\ud83d\ude00", "float": 1e-07, "large": 100000000000000000000000000000000000000000000000000, "negative": -0.0}"#
    );
    assert_ne!(
        link::digest(&value).unwrap()[..24],
        identity(&value).unwrap()
    );
    for (raw, expected) in [
        ("0.00001", "1e-05"),
        ("1.0e16", "1e+16"),
        ("1000000000000000.0", "1000000000000000.0"),
        ("0.0001", "0.0001"),
        ("1.0", "1.0"),
    ] {
        assert_eq!(
            python_json(&serde_json::from_str(raw).unwrap(), true).unwrap(),
            expected
        );
    }
}

#[test]
fn mailbox_retention_receipts_and_reopen_are_durable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::open(tmp.path()).unwrap();
    let f = finding();
    assert_eq!(
        store
            .reconcile(
                std::slice::from_ref(&f),
                &BTreeSet::new(),
                &["owned-channel".into()]
            )
            .unwrap()
            .len(),
        1
    );
    let listed = store
        .mail("reader", "list", &0.into(), &3600.into())
        .unwrap();
    let id = listed[0]["id"].as_number().unwrap().clone();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(
        store.mail("reader", "read", &id, &3600.into()).unwrap()[0]["state"],
        "open"
    );
    assert_eq!(
        store
            .mail("reader", "list", &0.into(), &3600.into())
            .unwrap(),
        json!([])
    );
    assert_eq!(
        store
            .mail("other", "list", &0.into(), &3600.into())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.mail("reader", "snooze", &id, &(-1).into()).unwrap(),
        json!({"message":id,"snooze":true})
    );
    assert_eq!(
        store
            .mail("reader", "list", &0.into(), &3600.into())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.mail("reader", "ack", &id, &3600.into()).unwrap(),
        json!({"message":id,"ack":true})
    );
    store.reconcile(&[], &BTreeSet::new(), &[]).unwrap();
    assert_eq!(store.active().unwrap().len(), 1);
    let mut refreshed = f;
    refreshed.insert("fetched_at".into(), json!(123));
    refreshed.insert("kev".into(), Value::Null);
    refreshed.insert("epss".into(), Value::Null);
    assert!(store
        .reconcile(&[refreshed], &BTreeSet::new(), &[])
        .unwrap()
        .is_empty());
    assert_eq!(store.active().unwrap()[0]["epss"], 0.1);
    store
        .reconcile(&[], &BTreeSet::from(["asset-a".into()]), &[])
        .unwrap();
    drop(store);
    let mut reopened = Store::open(tmp.path()).unwrap();
    assert!(reopened.active().unwrap().is_empty());
    assert_eq!(
        reopened
            .mail("other", "read", &0.into(), &0.into())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let mirrored = std::fs::read_to_string(tmp.path().join("inbox.jsonl")).unwrap();
    assert_eq!(mirrored.lines().count(), 2);
    assert!(mirrored
        .lines()
        .all(|s| serde_json::from_str::<Value>(s).unwrap()["state"] == "closed"));
    let queued: i64 = reopened
        .db
        .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(queued, 1);
}

#[test]
fn acknowledgements_replay_rotation_and_partial_scopes_match_durable_state() {
    let tmp = tempfile::tempdir().unwrap();
    let (hub, id) = enrolled(tmp.path());
    let b = batch(&id, 1, "complete", true);
    let ack = hub.ingest(CREDENTIAL, &b).unwrap();
    assert_eq!(hub.ingest(CREDENTIAL, &b).unwrap(), ack);
    let restarted = Hub::open(&tmp.path().join("hub.db")).unwrap();
    assert_eq!(restarted.ingest(CREDENTIAL, &b).unwrap(), ack);
    let mut conflict = b.clone();
    conflict["findings"] = json!([]);
    assert_eq!(
        hub.ingest(CREDENTIAL, &conflict).unwrap_err().http_status,
        Some(409)
    );
    let device = id["device"].as_str().unwrap();
    for seq in 2..5 {
        hub.ingest(CREDENTIAL, &batch(&id, seq, "partial", false))
            .unwrap();
        assert_eq!(
            hub.snapshot(device).unwrap()["findings"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    let mut unrelated = batch(&id, 5, "complete", false);
    unrelated["coverage"] = json!({"project-b":"complete"});
    hub.ingest(CREDENTIAL, &unrelated).unwrap();
    assert_eq!(
        hub.snapshot(device).unwrap()["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    hub.rotate(device, OTHER, 0.0).unwrap();
    assert_eq!(
        hub.ingest(CREDENTIAL, &batch(&id, 6, "complete", false))
            .unwrap_err()
            .http_status,
        Some(401)
    );
    hub.ingest(OTHER, &batch(&id, 6, "complete", false))
        .unwrap();
    assert_eq!(hub.snapshot(device).unwrap()["findings"], json!([]));
    assert_eq!(
        hub.enroll(INVITE, OTHER).unwrap_err().http_status,
        Some(401)
    );
    hub.revoke(device).unwrap();
    assert_eq!(
        hub.ingest(OTHER, &batch(&id, 7, "complete", false))
            .unwrap_err()
            .http_status,
        Some(401)
    );
}

#[test]
fn untrusted_numbers_and_scope_conflicts_never_advance_device_state() {
    let tmp = tempfile::tempdir().unwrap();
    let (hub, id) = enrolled(tmp.path());
    for (field, cases) in [
        (
            "sequence",
            vec![
                "true",
                "1.0",
                "9223372036854775808",
                "-1",
                "1844674407370955161600000000000000000000000000",
            ],
        ),
        (
            "observed",
            vec![
                "true",
                "1e9999",
                "1000000000000000000000000000000000000000000000000000000000",
            ],
        ),
    ] {
        for raw in cases {
            let mut b = batch(&id, 1, "complete", true);
            b[field] = serde_json::from_str(raw).unwrap();
            assert_eq!(
                hub.ingest(CREDENTIAL, &b)
                    .unwrap_err()
                    .http_status
                    .unwrap_or(400),
                400
            );
        }
    }
    hub.ingest(CREDENTIAL, &batch(&id, 1, "complete", true))
        .unwrap();
    let mut collision = batch(&id, 2, "partial", true);
    collision["coverage"] = json!({"project-b":"partial"});
    collision["findings"][0]["scope"] = json!("project-b");
    assert_eq!(
        hub.ingest(CREDENTIAL, &collision).unwrap_err().http_status,
        Some(409)
    );
    assert_eq!(
        hub.snapshot(id["device"].as_str().unwrap()).unwrap()["device"]["sequence"],
        1
    );
    let snapshot = hub.snapshot(id["device"].as_str().unwrap()).unwrap();
    assert!(snapshot["coverage"].get("project-b").is_none());
    assert_eq!(snapshot["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn offline_receipts_are_authenticated_and_queue_limits_do_not_consume_sequence() {
    let tmp = tempfile::tempdir().unwrap();
    let (hub, id) = enrolled(tmp.path());
    let out = Outbox::with_limits(&tmp.path().join("out.db"), 64 * 1024 * 1024, 1).unwrap();
    out.bind(
        id["device"].as_str().unwrap(),
        id["generation"].as_str().unwrap(),
    )
    .unwrap();
    let queued = out.enqueue(&batch(&id, 88, "complete", true)).unwrap();
    assert_eq!(queued["sequence"], 1);
    assert!(out.enqueue(&batch(&id, 99, "complete", false)).is_err());
    assert_eq!(out.identity().unwrap().unwrap()["sequence"], 1);
    let ack: Value =
        serde_json::from_slice(&hub.ingest(CREDENTIAL, &out.bundle().unwrap()).unwrap()).unwrap();
    let wrong = json!({"ack":ack,"signature":sign_receipt(&ack,OTHER).unwrap()});
    assert!(out.confirm(&wrong, CREDENTIAL).is_err());
    assert_eq!(out.health().unwrap()["queued"], 1);
    let receipt = json!({"ack":ack,"signature":sign_receipt(&ack,CREDENTIAL).unwrap()});
    out.confirm(&receipt, CREDENTIAL).unwrap();
    assert_eq!(out.health().unwrap()["queued"], 0);
    let out = Outbox::open(&tmp.path().join("out.db")).unwrap();
    assert_eq!(
        out.enqueue(&batch(&id, 88, "partial", false)).unwrap()["sequence"],
        2
    );
    let before = vorda::store::now();
    assert!(!out
        .drain("http://outside.invalid", CREDENTIAL, None)
        .unwrap());
    let health = out.health().unwrap();
    assert_eq!(health["queued"], 1);
    assert_eq!(health["attempts"], 1);
    assert!(health["next_attempt"].as_f64().unwrap() >= before + 1.0);
    out.database
        .connect()
        .unwrap()
        .execute("UPDATE pending SET due=?", [vorda::store::now() + 3600.0])
        .unwrap();
    assert!(!out
        .drain("http://outside.invalid", CREDENTIAL, None)
        .unwrap());
    assert_eq!(out.health().unwrap()["attempts"], 1);
}

#[test]
fn loopback_transport_and_duplicate_headers_preserve_security_controls() {
    let tmp = tempfile::tempdir().unwrap();
    let (hub, id) = enrolled(tmp.path());
    assert!(Server::bind(
        Hub::open(&tmp.path().join("hub.db")).unwrap(),
        "0.0.0.0",
        0,
        None,
        None
    )
    .is_err());
    let server = Server::bind(hub, "127.0.0.1", 0, None, None).unwrap();
    let address = server.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        for _ in 0..3 {
            server.serve_once().unwrap();
        }
    });
    let b = batch(&id, 1, "complete", true);
    let ack = request(
        &format!("http://{address}"),
        "/v1/batches",
        CREDENTIAL,
        &b,
        None,
    )
    .unwrap();
    assert_eq!(ack["digest"], link::digest(&b).unwrap());
    for (headers, status) in [
        ("Content-Length: 2\r\nContent-Length: 2\r\n", 400),
        ("Content-Length: 2\r\nContent-Encoding: gzip\r\n", 415),
    ] {
        let mut stream = TcpStream::connect(address).unwrap();
        write!(stream,"POST /v1/batches HTTP/1.1\r\nHost: localhost\r\n{headers}Authorization: Bearer {CREDENTIAL}\r\n\r\n{{}}").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{response}"
        );
    }
    thread.join().unwrap();
    for url in [
        "http://example.invalid",
        "https://user:pass@example.invalid",
        "https://example.invalid/path",
        "https://example.invalid?query=1",
    ] {
        assert!(request(url, "/v1/batches", CREDENTIAL, &b, None).is_err());
    }
}

#[test]
#[cfg(unix)]
fn tls_requires_trusted_certificate_and_matching_hostname() {
    let tmp = tempfile::tempdir().unwrap();
    let certificate = tmp.path().join("certificate.pem");
    let key = tmp.path().join("private.pem");
    tls::certificate(&certificate, &key);
    let hub = Hub::open(&tmp.path().join("hub.db")).unwrap();
    hub.invite(INVITE, "org", "site", 600.0).unwrap();
    let server = Server::bind(hub, "127.0.0.1", 0, Some(&certificate), Some(&key)).unwrap();
    let port = server.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        for _ in 0..4 {
            let _ = server.serve_once();
        }
    });
    let url = format!("https://localhost:{port}");
    let enrollment = json!({"credential":CREDENTIAL});
    assert!(request(&url, "/v1/enroll", INVITE, &enrollment, None).is_err());
    assert!(request(
        &format!("https://127.0.0.1:{port}"),
        "/v1/enroll",
        INVITE,
        &enrollment,
        Some(&certificate)
    )
    .is_err());
    let identity = request(&url, "/v1/enroll", INVITE, &enrollment, Some(&certificate)).unwrap();
    let batch = batch(&identity, 1, "complete", true);
    let ack = request(&url, "/v1/batches", CREDENTIAL, &batch, Some(&certificate)).unwrap();
    assert_eq!(ack["digest"], link::digest(&batch).unwrap());
    thread.join().unwrap();
}

#[test]
fn slow_peer_does_not_hold_outbox_write_lock_and_retry_survives_reopen() {
    use std::{
        net::TcpListener,
        sync::mpsc,
        time::{Duration, Instant},
    };
    let t = tempfile::tempdir().unwrap();
    let (_, identity) = enrolled(t.path());
    let path = t.path().join("outbox.db");
    let outbox = Outbox::open(&path).unwrap();
    outbox
        .bind(
            identity["device"].as_str().unwrap(),
            identity["generation"].as_str().unwrap(),
        )
        .unwrap();
    outbox
        .enqueue(&batch(&identity, 1, "complete", true))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = [0; 8192];
        // one read only waits for the request to arrive; read_exact would block
        #[allow(clippy::unused_io_amount)]
        stream.read(&mut bytes).unwrap();
        tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(1000));
        let _ = stream
            .write_all(b"HTTP/1.1 503 Error\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    });
    let other = Outbox::open(&path).unwrap();
    let drain =
        std::thread::spawn(move || other.drain(&format!("http://{addr}"), CREDENTIAL, None));
    rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let start = Instant::now();
    outbox
        .enqueue(&batch(&identity, 2, "complete", true))
        .unwrap();
    assert!(start.elapsed() < Duration::from_millis(700));
    assert!(!drain.join().unwrap().unwrap());
    peer.join().unwrap();
    drop(outbox);
    let reopened = Outbox::open(&path).unwrap();
    assert_eq!(reopened.identity().unwrap().unwrap()["sequence"], 2);
    let count: i64 = reopened
        .database
        .connect()
        .unwrap()
        .query_row("SELECT count(*) FROM pending", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn trickling_request_hits_absolute_hub_deadline() {
    use std::time::{Duration, Instant};
    let t = tempfile::tempdir().unwrap();
    let (hub, _) = enrolled(t.path());
    let server = Server::bind(hub, "127.0.0.1", 0, None, None).unwrap();
    let addr = server.local_addr().unwrap();
    let started = Instant::now();
    let worker = std::thread::spawn(move || server.serve_once());
    let mut stream = TcpStream::connect(addr).unwrap();
    for _ in 0..7 {
        if stream.write_all(b"G").is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(900));
    }
    assert!(worker.join().unwrap().is_err());
    assert!(started.elapsed() < Duration::from_secs(8));
}

#[test]
fn sqlite_snapshot_restore_keeps_active_findings_and_delivery_ack() {
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(&t.path().join("state")).unwrap();
    store
        .reconcile(&[finding()], &BTreeSet::new(), &[])
        .unwrap();
    store.mail("reader", "ack", &1.into(), &0.into()).unwrap();
    let restore = t.path().join("restored");
    std::fs::create_dir(&restore).unwrap();
    store
        .db
        .execute("VACUUM INTO ?", [restore.join("mail.db").to_str().unwrap()])
        .unwrap();
    let mut restored = Store::open(&restore).unwrap();
    assert_eq!(restored.active().unwrap(), store.active().unwrap());
    assert_eq!(
        restored
            .mail("reader", "list", &0.into(), &0.into())
            .unwrap(),
        json!([])
    );
    assert_eq!(
        restored
            .attention("reader", "current", None, 0, 10)
            .unwrap()["items"][0]["state"],
        "open"
    );
}
