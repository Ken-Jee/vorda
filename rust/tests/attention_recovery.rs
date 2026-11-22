use serde_json::{json, Value};
use std::collections::BTreeSet;
use vorda::{store::Store, surfaces::mcp};
fn finding(key: &str, scope: &str) -> vorda::domain::Record {
    json!({"key":key,"asset":key,"title":key,"scan_scope":scope})
        .as_object()
        .unwrap()
        .clone()
}
#[test]
fn saved_attention_recovers_seen_delivery_without_mutation_and_ack_keeps_current() {
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    store
        .reconcile(
            &[finding("a", "A"), finding("b", "B")],
            &BTreeSet::new(),
            &[],
        )
        .unwrap();
    store.mail("agent", "read", &0.into(), &0.into()).unwrap();
    drop(store);
    let mut store = Store::open(t.path()).unwrap();
    assert_eq!(
        store.mail("agent", "list", &0.into(), &0.into()).unwrap(),
        json!([])
    );
    let response=mcp::call(t.path(),&json!({"method":"tools/call","params":{"name":"attention","arguments":{"reader":"agent","mode":"pending","scope":"A","limit":1}}}),None,None).unwrap();
    let data: Value =
        serde_json::from_str(response["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(data["items"].as_array().unwrap().len(), 1);
    assert_eq!(data["items"][0]["key"], "a");
    let id = data["items"][0]["id"].as_i64().unwrap();
    assert_eq!(
        store
            .attention("agent", "pending", Some("A"), 0, 1)
            .unwrap(),
        data
    );
    store.mail("agent", "ack", &id.into(), &0.into()).unwrap();
    assert_eq!(
        store
            .attention("agent", "pending", Some("A"), 0, 1)
            .unwrap()["items"],
        json!([])
    );
    assert_eq!(
        store
            .attention("agent", "current", Some("A"), 0, 1)
            .unwrap()["items"][0]["state"],
        "open"
    );
    let mut writer = Store::open(t.path()).unwrap();
    writer
        .reconcile(&[finding("c", "A")], &BTreeSet::new(), &[])
        .unwrap();
    let page = store
        .attention("agent", "current", Some("A"), 0, 1)
        .unwrap();
    assert!(page["next_cursor"].is_i64());
    assert_eq!(
        store
            .attention(
                "agent",
                "current",
                Some("A"),
                page["next_cursor"].as_i64().unwrap(),
                1
            )
            .unwrap()["items"][0]["key"],
        "c"
    );
}
#[test]
fn concurrent_legacy_open_and_new_schema_refusal() {
    let t = tempfile::tempdir().unwrap();
    let db = rusqlite::Connection::open(t.path().join("mail.db")).unwrap();
    db.execute_batch("CREATE TABLE receipts(reader TEXT,message INTEGER,ack INTEGER DEFAULT 0,snooze REAL DEFAULT 0,PRIMARY KEY(reader,message)); PRAGMA user_version=1;").unwrap();
    drop(db);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let workers = (0..4)
        .map(|_| {
            let path = t.path().to_owned();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                Store::open(&path).unwrap();
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
    let store = Store::open(t.path()).unwrap();
    store.db.pragma_update(None, "user_version", 99).unwrap();
    drop(store);
    assert!(Store::open(t.path()).is_err());
}

fn health_open(store: &Store, channel: &str) -> bool {
    let key = format!("health:delivery:{channel}");
    store
        .active()
        .unwrap()
        .iter()
        .any(|f| f["key"] == key.as_str())
}

/// (attempts, last_error present, delivered) of every queued row of a channel.
fn outbox(store: &Store, channel: &str) -> Vec<(i64, bool, i64)> {
    store
        .db
        .prepare("SELECT attempts,last_error IS NOT NULL,delivered FROM outbox WHERE channel=? ORDER BY message")
        .unwrap()
        .query_map([channel], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// A local webhook endpoint bound once for the whole test, so no port is freed and
/// re-bound. It answers 503 until `set_up(true)`, then 200, and keeps the request
/// bodies it accepted. Its accept loop gives up after a deadline, so a regression fails the test
/// instead of hanging it.
struct Hook {
    port: u16,
    up: std::sync::Arc<std::sync::atomic::AtomicBool>,
    bodies: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Hook {
    fn start() -> Self {
        use std::io::{Read, Write};
        use std::sync::{atomic::Ordering, Arc, Mutex};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (up, stop, bodies) = (up.clone(), stop.clone(), bodies.clone());
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
                while !stop.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    let Ok((mut stream, _)) = listener.accept() else {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        continue;
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let text = String::from_utf8_lossy(&request).into_owned();
                        if let Some((header, body)) = text.split_once("\r\n\r\n") {
                            let length = header
                                .lines()
                                .filter_map(|l| l.split_once(':'))
                                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if body.len() >= length {
                                if up.load(Ordering::SeqCst) {
                                    bodies.lock().unwrap().push(body.to_string());
                                }
                                break;
                            }
                        }
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => request.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let status = if up.load(Ordering::SeqCst) {
                        "200 OK"
                    } else {
                        "503 Service Unavailable"
                    };
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                }
            })
        };
        Hook {
            port,
            up,
            bodies,
            stop,
            thread: Some(thread),
        }
    }
    fn url(&self, name: &str) -> String {
        format!("http://127.0.0.1:{}/{name}", self.port)
    }
    fn set_up(&self, up: bool) {
        self.up.store(up, std::sync::atomic::Ordering::SeqCst);
    }
    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn webhook_channel(url: &str) -> String {
    vorda::delivery::channel_keys(&vorda::delivery::Options {
        webhook: Some(url.into()),
        ..Default::default()
    })
    .unwrap()
    .remove(0)
}

#[test]
fn a_message_stops_retrying_after_24_failed_attempts_and_the_warning_clears() {
    use vorda::delivery::{drain, expire, Options};
    let t = tempfile::tempdir().unwrap();
    let mut store = Store::open(t.path()).unwrap();
    let hook = Hook::start();
    let options = Options {
        webhook: Some(hook.url("hook")),
        ..Default::default()
    };
    let channel = webhook_channel(&hook.url("hook"));
    store
        .reconcile(
            &[finding("f", "s")],
            &BTreeSet::new(),
            std::slice::from_ref(&channel),
        )
        .unwrap();
    assert_eq!(
        drain(&mut store, &options)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    expire(&mut store, std::slice::from_ref(&channel)).unwrap();
    assert!(health_open(&store, &channel), "still retrying");
    let ready = |store: &Store| {
        store
            .db
            .execute(
                "UPDATE outbox SET next_attempt=0 WHERE channel=?",
                [&channel],
            )
            .unwrap();
    };
    store
        .db
        .execute("UPDATE outbox SET attempts=23 WHERE channel=?", [&channel])
        .unwrap();
    ready(&store);
    drain(&mut store, &options).unwrap();
    expire(&mut store, std::slice::from_ref(&channel)).unwrap();
    assert!(!health_open(&store, &channel), "nothing left to retry");
    assert_eq!(outbox(&store, &channel), [(24, true, -1)]);
    ready(&store);
    assert!(drain(&mut store, &options)
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        outbox(&store, &channel),
        [(24, true, -1)],
        "no 25th attempt"
    );
}

#[test]
fn a_quiet_week_clears_only_that_channels_warning_and_the_queued_message_sends_when_it_returns() {
    use vorda::{
        cli,
        delivery::{drain, Options},
        domain::ScanOptions,
    };
    let t = tempfile::tempdir().unwrap();
    let project = t.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let mut store = Store::open(&t.path().join("state")).unwrap();
    let hook = Hook::start();
    let (url, other_url) = (hook.url("a"), hook.url("b"));
    let (channel, other) = (webhook_channel(&url), webhook_channel(&other_url));
    store
        .reconcile(
            &[finding("f", "s")],
            &BTreeSet::new(),
            &[channel.clone(), other.clone()],
        )
        .unwrap();
    for endpoint in [&url, &other_url] {
        let failing = Options {
            webhook: Some(endpoint.clone()),
            ..Default::default()
        };
        assert_eq!(
            drain(&mut store, &failing)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    assert!(health_open(&store, &channel) && health_open(&store, &other));
    let queued = outbox(&store, &channel);
    let other_queued = outbox(&store, &other);
    assert!(queued.iter().all(|row| *row == (1, true, 0)));
    // `other` stays recently attempted while `channel` ages: both are unused by every
    // check below, so only the age of the last attempt can tell them apart.
    let age = |store: &Store, days: i64| {
        store
            .db
            .execute(
                "UPDATE outbox SET next_attempt=next_attempt-?1*86400 WHERE channel=?2",
                rusqlite::params![days, channel],
            )
            .unwrap();
        store
            .db
            .execute(
                "UPDATE messages SET created=created-?1*86400",
                rusqlite::params![days],
            )
            .unwrap();
    };
    let mut options = ScanOptions::default();
    options.inventory.roots = vec![project];
    options.offline = true;
    // Under a week quiet: nothing is cleared and every row is untouched.
    age(&store, 6);
    cli::check(&options, &mut store).unwrap();
    assert!(
        health_open(&store, &channel),
        "6 quiet days keep the warning"
    );
    assert!(health_open(&store, &other));
    assert_eq!(outbox(&store, &channel), queued);
    assert_eq!(outbox(&store, &other), other_queued);
    // Over a week quiet: only that channel's warning clears; its rows are kept.
    age(&store, 2);
    cli::check(&options, &mut store).unwrap();
    assert!(!health_open(&store, &channel), "8 quiet days clear it");
    assert!(
        health_open(&store, &other),
        "a recently used channel keeps its warning"
    );
    assert_eq!(
        outbox(&store, &channel),
        queued,
        "no queued message dropped or abandoned"
    );
    assert_eq!(outbox(&store, &other), other_queued);
    cli::check(&options, &mut store).unwrap();
    assert!(
        !health_open(&store, &channel),
        "not raised again without a new failure"
    );
    // The channel returns while its endpoint is still down: a new failure raises the warning.
    options.webhook = Some(url);
    let result = cli::check(&options, &mut store).unwrap();
    assert_eq!(result["delivery_errors"].as_array().unwrap().len(), 1);
    assert!(health_open(&store, &channel));
    assert!(matches!(outbox(&store, &channel)[0], (n, true, 0) if n >= 2));
    // The endpoint comes back: the kept message is delivered.
    hook.set_up(true);
    store
        .db
        .execute(
            "UPDATE outbox SET next_attempt=0 WHERE channel=?",
            [&channel],
        )
        .unwrap();
    let result = cli::check(&options, &mut store).unwrap();
    assert!(result["delivery_errors"].as_array().unwrap().is_empty());
    assert!(hook.bodies().iter().any(|b| b.contains("\"title\":\"f\"")));
    assert!(outbox(&store, &channel).iter().all(|row| row.2 == 1));
    assert!(!health_open(&store, &channel));
    assert_eq!(
        outbox(&store, &other),
        other_queued,
        "the other channel's rows are untouched"
    );
}
