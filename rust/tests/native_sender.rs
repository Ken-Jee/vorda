//! The native sender, end to end through the shipped commands: a device enrols over loopback TLS,
//! captures a lockfile, `link queue-native` queues the capture and `link send` posts it. The
//! hub side is the real listener (`Server` + `Admission` with the operator's grants); the reader
//! side is real HTTP. Synthetic fixtures only.
mod common;
use common::{synthetic_lock, synthetic_packages};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use vorda::{
    link::{
        client::Outbox, grants::CaptureGrants, native::Admission, server::Server, storage::Hub,
    },
    store::now,
};

const ORG: &str = "test-org";
const SITE: &str = "test-site";
const SOURCE: &str = "npm-a";
const INVITE: &str = "synthetic-sender-invite-0000000000000";
const DEVICE: &str = "synthetic-sender-device-0000000000000";
const READER: &str = "synthetic-sender-reader-0000000000000";

struct Lab {
    tmp: tempfile::TempDir,
    hub: PathBuf,
    outbox: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    identity: std::cell::RefCell<(String, String)>,
    captures: std::cell::Cell<usize>,
}
impl Lab {
    /// A schema 2 hub with one invite, and a TLS certificate for loopback.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let (cert, key) = (tmp.path().join("cert.pem"), tmp.path().join("key.pem"));
        common::tls::certificate(&cert, &key);
        let lab = Self {
            hub: tmp.path().join("hub.db"),
            outbox: tmp.path().join("outbox.db"),
            cert,
            key,
            tmp,
            identity: Default::default(),
            captures: Default::default(),
        };
        lab.link(
            &lab.hub,
            &[
                "invite",
                "--invite-env",
                "SYN_INVITE",
                "--org",
                ORG,
                "--site",
                SITE,
            ],
        );
        lab.link(&lab.hub, &["migrate"]);
        lab
    }
    fn device(&self) -> String {
        self.identity.borrow().0.clone()
    }
    fn generation(&self) -> String {
        self.identity.borrow().1.clone()
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vorda"))
            .args(args)
            .env("SYN_INVITE", INVITE)
            .env("SYN_DEVICE", DEVICE)
            .env("SYN_READER", READER)
            .output()
            .unwrap()
    }
    fn link_out(&self, db: &Path, args: &[&str]) -> Output {
        let mut all = vec!["link", "--db", db.to_str().unwrap()];
        all.extend(args);
        self.run(&all)
    }
    fn link(&self, db: &Path, args: &[&str]) -> Value {
        let out = self.link_out(db, args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    /// Enrols the device over TLS against a serving hub and grants its source, as the operator would.
    fn enrol(&self, hub_url: &str) {
        let identity = self.link(
            &self.outbox,
            &[
                "enroll",
                "--hub",
                hub_url,
                "--ca-file",
                self.cert.to_str().unwrap(),
                "--invite-env",
                "SYN_INVITE",
                "--credential-env",
                "SYN_DEVICE",
            ],
        );
        *self.identity.borrow_mut() = (
            identity["device"].as_str().unwrap().into(),
            identity["generation"].as_str().unwrap().into(),
        );
        self.link(
            &self.hub,
            &[
                "capture-allow",
                "--device",
                &self.device(),
                "--source",
                SOURCE,
            ],
        );
        self.link(
            &self.hub,
            &[
                "reader-grant",
                "--reader-env",
                "SYN_READER",
                "--label",
                "synthetic-reader",
                "--org",
                ORG,
                "--site",
                SITE,
                "--ttl",
                "3600",
            ],
        );
    }
    /// Captures `lock` as the lockfile of `scope` and returns the saved view file.
    fn capture(&self, scope: &str, lock: &str) -> PathBuf {
        self.capture_with(scope, lock, json!({}))
    }
    /// A capture whose request also carries the keys of `extra` (for example a provider outcome).
    fn capture_with(&self, scope: &str, lock: &str, extra: Value) -> PathBuf {
        self.captures.set(self.captures.get() + 1);
        let n = self.captures.get();
        let root = self.tmp.path().join(format!("app-{scope}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package-lock.json"), lock).unwrap();
        let request = self.tmp.path().join(format!("request-{n}.json"));
        let observed = now() - 60.0;
        let mut body = json!({"token":format!("token-{n}"),"binding":{"tenant":ORG,"site":SITE,"device":self.device(),"generation":self.generation(),"scope":scope,"source":SOURCE},
                "root":root,"inputs":["package-lock.json"],"observed_at":format!("{observed:.4}"),"completed_at":format!("{:.4}", observed + 1.0)});
        for (key, value) in extra.as_object().unwrap() {
            body[key] = value.clone();
        }
        fs::write(&request, body.to_string()).unwrap();
        let state = self.tmp.path().join(format!("state-{scope}"));
        let out = self.run(&[
            "--state",
            state.to_str().unwrap(),
            "capture",
            request.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let outcome: Value = serde_json::from_slice(&out.stdout).unwrap();
        let view = self.tmp.path().join(format!("view-{n}.json"));
        let out = self.run(&[
            "--state",
            state.to_str().unwrap(),
            "capture-export",
            outcome["snapshot_id"].as_str().unwrap(),
            view.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        view
    }
    /// The device retires `scope`'s source and returns the saved view file of the retirement.
    fn retire(&self, scope: &str) -> PathBuf {
        self.captures.set(self.captures.get() + 1);
        let n = self.captures.get();
        let state = self.tmp.path().join(format!("state-{scope}"));
        let out = self.run(&[
            "--state",
            state.to_str().unwrap(),
            "capture-retire",
            "--scope",
            scope,
            "--source",
            SOURCE,
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let outcome: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(outcome["status"], "committed", "{outcome}");
        let view = self.tmp.path().join(format!("view-{n}.json"));
        let out = self.run(&[
            "--state",
            state.to_str().unwrap(),
            "capture-export",
            outcome["snapshot_id"].as_str().unwrap(),
            view.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        view
    }
    /// Rewrites the artifact a saved view carries, as a tampering device would, and returns the file.
    fn tampered(&self, view: &Path, edit: impl FnOnce(&mut Value)) -> PathBuf {
        let mut saved: Value = serde_json::from_slice(&fs::read(view).unwrap()).unwrap();
        let payloads = saved["retained_payload_utf8"].as_object_mut().unwrap();
        let key = payloads.keys().next().unwrap().clone();
        let mut artifact: Value = serde_json::from_str(payloads[&key].as_str().unwrap()).unwrap();
        edit(&mut artifact);
        payloads.insert(key, json!(artifact.to_string()));
        let path = self
            .tmp
            .path()
            .join(format!("tampered-{}.json", saved.to_string().len()));
        fs::write(&path, saved.to_string()).unwrap();
        path
    }
    /// The request an entry of the outbox holds, posted by hand: the hub's status and error text.
    fn post_queued(&self, url: &str, sequence: i64) -> (u16, String) {
        let payload: Vec<u8> = Connection::open(&self.outbox)
            .unwrap()
            .query_row(
                "SELECT payload FROM native_pending WHERE sequence=?",
                [sequence],
                |r| r.get(0),
            )
            .unwrap();
        self.post_raw(url, payload)
    }
    fn post_raw(&self, url: &str, body: Vec<u8>) -> (u16, String) {
        let mut client = reqwest::blocking::Client::builder().use_native_tls();
        for cert in reqwest::Certificate::from_pem_bundle(&fs::read(&self.cert).unwrap()).unwrap() {
            client = client.add_root_certificate(cert);
        }
        let sent = client
            .build()
            .unwrap()
            .post(format!("{url}/v2/batches"))
            .header("Authorization", format!("Bearer {DEVICE}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send();
        // A hub that refuses a body before reading it may close the connection mid-write: status 0.
        let response = match sent {
            Ok(response) => response,
            Err(error) => return (0, format!("{error:?}")),
        };
        let status = response.status().as_u16();
        let text = response.text().unwrap();
        let error = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or(text);
        (status, error)
    }
    fn queue(&self, view: &Path) -> Value {
        self.link(
            &self.outbox,
            &[
                "queue-native",
                "--capture",
                view.to_str().unwrap(),
                "--consent",
            ],
        )
    }
    fn send_from(&self, outbox: &Path, hub_url: &str) -> Value {
        let out = self.run(&[
            "link",
            "--db",
            outbox.to_str().unwrap(),
            "send",
            "--hub",
            hub_url,
            "--ca-file",
            self.cert.to_str().unwrap(),
            "--credential-env",
            "SYN_DEVICE",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
    fn send(&self, hub_url: &str) -> Value {
        self.send_from(&self.outbox, hub_url)
    }
    fn health(&self) -> Value {
        self.link(&self.outbox, &["health"])
    }
    /// Moves the clock past every backoff of the outbox, so the next `send` tries the entry again.
    fn skip_backoff(&self) {
        Connection::open(&self.outbox)
            .unwrap()
            .execute("UPDATE native_pending SET due=0", [])
            .unwrap();
    }
    /// Puts one entry's next attempt far in the future, as a long backoff would.
    fn defer(&self, sequence: i64, scope_hint: &str) {
        Connection::open(&self.outbox)
            .unwrap()
            .execute(
                "UPDATE native_pending SET due=? WHERE sequence=? AND authority LIKE ?",
                rusqlite::params![now() + 3600.0, sequence, format!("%{scope_hint}%")],
            )
            .unwrap();
    }
    fn reader(&self, url: &str, route: &str, body: Value) -> (u16, Value) {
        let mut client = reqwest::blocking::Client::builder()
            .use_native_tls()
            .timeout(Duration::from_secs(60));
        for cert in reqwest::Certificate::from_pem_bundle(&fs::read(&self.cert).unwrap()).unwrap() {
            client = client.add_root_certificate(cert);
        }
        let response = client
            .build()
            .unwrap()
            .post(format!("{url}/v2/read/{route}"))
            .header("Authorization", format!("Bearer {READER}"))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .unwrap();
        (
            response.status().as_u16(),
            serde_json::from_slice(&response.bytes().unwrap()).unwrap_or(Value::Null),
        )
    }
    /// Every package the reader's `inventory` returns for the device, following the cursor.
    fn inventory(&self, url: &str) -> (Vec<Value>, Value) {
        let mut request = json!({"devices":[self.device()],"limit":100});
        let (mut rows, mut first) = (vec![], Value::Null);
        loop {
            let (code, page) = self.reader(url, "inventory", request.clone());
            assert_eq!(code, 200, "{page}");
            rows.extend(page["inventory"].as_array().unwrap().iter().cloned());
            if first.is_null() {
                first = page.clone();
            }
            match page["next_cursor"].as_str() {
                Some(cursor) => request["cursor"] = json!(cursor),
                None => return (rows, first),
            }
        }
    }
}
fn packages(rows: &[Value]) -> BTreeSet<(String, String)> {
    rows.iter()
        .map(|r| {
            (
                r["package"]["name"]["quoted"].as_str().unwrap().to_string(),
                r["package"]["version"]["quoted"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect()
}
/// Runs `run` against a TLS listener of the lab's hub that gives each admission `budget`.
fn serving<R>(lab: &Lab, budget: Duration, run: impl FnOnce(&str) -> R) -> R {
    let server = Server::bind(
        Hub::open(&lab.hub).unwrap(),
        "127.0.0.1",
        0,
        Some(&lab.cert),
        Some(&lab.key),
    )
    .unwrap();
    let url = format!("https://localhost:{}", server.local_addr().unwrap().port());
    let admission = Admission::open(&lab.hub, vec![])
        .unwrap()
        .with_grants(CaptureGrants::open(&lab.hub).unwrap())
        .with_budget(budget);
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let handle = scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let started = Instant::now();
                if let Err(error) = server.serve_once_with_admission(&admission) {
                    eprintln!(
                        "native listener call failed after {:?}: {error:?}",
                        started.elapsed()
                    );
                }
            }
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&url)));
        stop.store(true, Ordering::Release);
        let _ = std::net::TcpStream::connect(server.local_addr().unwrap());
        handle.join().unwrap();
        match result {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e),
        }
    })
}
const HEALTHY: Duration = Duration::from_secs(30);

/// A lab whose device is enrolled and granted, with the listener's address no longer needed.
fn enrolled() -> Lab {
    let lab = Lab::new();
    serving(&lab, HEALTHY, |url| lab.enrol(url));
    lab
}

#[test]
fn a_1500_package_capture_is_queued_sent_and_read_back_with_its_evidence() {
    let lab = Lab::new();
    let pk = synthetic_packages(1500);
    serving(&lab, HEALTHY, |url| {
        lab.enrol(url);
        let view = lab.capture("scope-a", &synthetic_lock(&pk, 0));
        let queued = lab.queue(&view);
        assert_eq!(queued["sequence"], 1);
        assert_eq!(lab.health()["queued"], 1);

        let sent = lab.send(url);
        assert_eq!(sent["delivered"], true, "{sent}");
        assert_eq!(sent["ack"]["result"], "published");
        assert_eq!(sent["ack"]["sequence"], 1);
        assert_eq!(sent["queued"], 0);

        let (rows, first) = lab.inventory(url);
        assert_eq!(first["total"], 1500);
        assert_eq!(packages(&rows), pk.iter().cloned().collect());
        let reference = rows[0]["evidence"].as_str().unwrap();
        let (code, evidence) = lab.reader(url, "evidence", json!({"reference":reference}));
        assert_eq!(code, 200);
        assert_eq!(evidence["evidence"]["records_total"], 1500);
    });
}

#[test]
fn resending_the_same_entry_returns_the_identical_ack() {
    let lab = enrolled();
    let view = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(20), 0));
    lab.queue(&view);
    // The device went down after the hub accepted the entry and before it forgot it: the same
    // entry is in a second copy of the outbox.
    let copy = lab.tmp.path().join("outbox-copy.db");
    fs::copy(&lab.outbox, &copy).unwrap();
    let (first, again) = serving(&lab, HEALTHY, |url| {
        (lab.send(url), lab.send_from(&copy, url))
    });
    assert_eq!(first["delivered"], true);
    assert_eq!(again["delivered"], true);
    assert_eq!(
        serde_json::to_string(&first["ack"]).unwrap(),
        serde_json::to_string(&again["ack"]).unwrap()
    );
}

#[test]
fn a_revoked_device_is_refused_with_401_and_its_entry_stays_queued() {
    let lab = enrolled();
    let view = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(20), 0));
    lab.queue(&view);
    lab.link(&lab.hub, &["revoke", "--device", &lab.device()]);
    let sent = serving(&lab, HEALTHY, |url| lab.send(url));
    assert_eq!(sent["delivered"], false);
    assert_eq!(sent["queued"], 1);
    assert_eq!(sent["needs_attention"], true);
    assert_eq!(sent["attention"][0]["last_status"], 401);
    assert_eq!(lab.health()["queued"], 1);
    // The refusal is not retried at once: the second send makes no request, so the attempt
    // count stays, and the entry is still there.
    let again = serving(&lab, HEALTHY, |url| lab.send(url));
    assert_eq!(again["delivered"], false);
    assert_eq!(again["queued"], 1);
    assert_eq!(again["attempts"], sent["attempts"]);
}

/// A v1 batch queued through the outbox, as the scan commands do.
fn queue_v1(lab: &Lab, scan: &str) -> Value {
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/capture/V1.json")).unwrap();
    batch["device"] = json!(lab.device());
    batch["generation"] = json!(lab.generation());
    batch["scan"] = json!(scan);
    Outbox::open(&lab.outbox).unwrap().enqueue(&batch).unwrap()
}
/// Sets when entry `sequence` of `table` was queued, as a clock that stepped back would.
fn requeued_at(lab: &Lab, table: &str, sequence: i64, at: f64) {
    Connection::open(&lab.outbox)
        .unwrap()
        .execute(
            &format!("UPDATE {table} SET queued=? WHERE sequence=?"),
            rusqlite::params![at, sequence],
        )
        .unwrap();
}

#[test]
fn v1_batches_go_out_in_sequence_order_whatever_the_clock_said() {
    let lab = enrolled();
    assert_eq!(
        queue_v1(&lab, "00000000-0000-4000-8000-000000000001")["sequence"],
        1
    );
    assert_eq!(
        queue_v1(&lab, "00000000-0000-4000-8000-000000000002")["sequence"],
        2
    );
    // The clock stepped back between the two: batch 2 looks older than batch 1.
    requeued_at(&lab, "pending", 1, now() + 1000.0);
    requeued_at(&lab, "pending", 2, now());
    serving(&lab, HEALTHY, |url| {
        let first = lab.send(url);
        assert_eq!(first["delivered"], true, "{first}");
        assert_eq!(first["ack"]["sequence"], 1);
        let second = lab.send(url);
        assert_eq!(second["delivered"], true, "{second}");
        assert_eq!(second["ack"]["sequence"], 2);
    });
}

#[test]
fn native_requests_of_one_authority_go_out_in_sequence_order_whatever_the_clock_said() {
    let lab = enrolled();
    let one = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(10), 0));
    let two = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(11), 0));
    assert_eq!(lab.queue(&one)["sequence"], 1);
    assert_eq!(lab.queue(&two)["sequence"], 2);
    requeued_at(&lab, "native_pending", 1, now() + 1000.0);
    requeued_at(&lab, "native_pending", 2, now());
    serving(&lab, HEALTHY, |url| {
        let first = lab.send(url);
        assert_eq!(first["delivered"], true, "{first}");
        assert_eq!(first["ack"]["sequence"], 1);
        let second = lab.send(url);
        assert_eq!(second["delivered"], true, "{second}");
        assert_eq!(second["ack"]["sequence"], 2);
    });
}

#[test]
fn a_repeated_503_for_one_entry_is_bounded_and_flagged_and_does_not_hold_back_other_authorities() {
    let lab = enrolled();
    let first = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(30), 0));
    let second = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(40), 0));
    let other = lab.capture("scope-b", &synthetic_lock(&synthetic_packages(50), 0));
    // Sequences count per authority, not per outbox.
    assert_eq!(lab.queue(&first)["sequence"], 1);
    assert_eq!(lab.queue(&second)["sequence"], 2);
    assert_eq!(lab.queue(&other)["sequence"], 1);

    // A hub that cannot finish an admission in time answers every post with 503 and Retry-After.
    serving(&lab, Duration::ZERO, |url| {
        for attempt in 1..=5 {
            let sent = lab.send(url);
            assert_eq!(sent["delivered"], false);
            assert_eq!(sent["queued"], 3, "the entry is never dropped");
            assert_eq!(sent["attempts"], attempt);
            assert_eq!(
                sent["needs_attention"],
                attempt == 5,
                "attempt {attempt}: {sent}"
            );
            lab.skip_backoff();
        }
        let health = lab.health();
        assert_eq!(health["attention"][0]["last_status"], 503);
        assert_eq!(health["attention"][0]["attempts"], 5);
    });

    // The hub recovers while the stuck entry waits out a long backoff. The other authority gets
    // through; the stuck authority's second entry waits behind its first, because the hub would
    // refuse sequence 1 once sequence 2 had arrived.
    lab.defer(1, "scope-a");
    serving(&lab, HEALTHY, |url| {
        let sent = lab.send(url);
        assert_eq!(sent["delivered"], true, "{sent}");
        assert_eq!(sent["ack"]["binding"]["scope"], "scope-b");
        assert_eq!(sent["queued"], 2);
        let nothing = lab.send(url);
        assert_eq!(nothing["delivered"], false);
        assert_eq!(nothing["queued"], 2);

        lab.skip_backoff();
        let one = lab.send(url);
        assert_eq!(
            (&one["ack"]["binding"]["scope"], &one["ack"]["sequence"]),
            (&json!("scope-a"), &json!(1))
        );
        let last = lab.send(url);
        assert_eq!(last["ack"]["sequence"], 2);
        assert_eq!(last["queued"], 0);
        assert_eq!(last["needs_attention"], false);

        let (rows, _) = lab.inventory(url);
        let expected: BTreeSet<_> = synthetic_packages(40)
            .into_iter()
            .chain(synthetic_packages(50))
            .collect();
        assert_eq!(packages(&rows), expected);
    });
}

#[test]
fn a_503_with_retry_after_is_not_retried_before_the_hub_said() {
    let lab = enrolled();
    let view = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(10), 0));
    lab.queue(&view);
    serving(&lab, Duration::ZERO, |url| {
        let started = now();
        let sent = lab.send(url);
        let finished = now();
        assert_eq!(sent["attempts"], 1);
        assert!(
            sent["next_attempt"].as_f64().unwrap() >= started.min(finished) + 4.0,
            "{sent}"
        );
        // Before then a send makes no request: the attempt count does not move.
        assert_eq!(lab.send(url)["attempts"], 1);
    });
}

/// A listener that answers every post with 200 and `body`, and counts the posts.
fn answering(body: &'static str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let posts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = posts.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut seen = vec![];
            let mut chunk = [0u8; 65536];
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                seen.extend(&chunk[..n]);
                let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if n == 0 {
                        break;
                    }
                    continue;
                };
                let head = String::from_utf8_lossy(&seen[..end]).to_lowercase();
                let length: usize = head
                    .split("content-length: ")
                    .nth(1)
                    .and_then(|s| s.split("\r\n").next())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if seen.len() >= end + 4 + length || n == 0 {
                    break;
                }
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
        }
    });
    (url, posts)
}

#[test]
fn an_ack_that_does_not_answer_the_request_leaves_the_entry_queued() {
    let lab = enrolled();
    let view = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(10), 0));
    lab.queue(&view);
    let (url, posts) = answering(r#"{"schema":2,"result":"published"}"#);
    let sent = lab.send_from(&lab.outbox, &url);
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert_eq!(sent["delivered"], false);
    assert_eq!(sent["queued"], 1);
    assert_eq!(sent["attempts"], 1);
    // The hub answered 200: this is a bad answer, not a refusal that retrying cannot change.
    assert_eq!(sent["needs_attention"], false, "{sent}");
}

/// A saved capture view that holds one artifact for `device`, `filler` bytes of it padding.
fn handmade_view(device: &str, generation: &str, filler: usize) -> Value {
    let artifact = json!({"binding":{"tenant":ORG,"site":SITE,"device":device,"generation":generation,"scope":"scope-h","source":SOURCE},"filler":"x".repeat(filler)});
    json!({"assessment_bindings":[{"assessment_id":"a1","revision":1}],"records":[{"assessment_id":"a1","dimensions":{"evidence":"e1"}}],"retained_payload_utf8":{"e1":artifact.to_string()}})
}

#[test]
fn a_capture_the_hub_cannot_take_is_refused_before_anything_is_queued() {
    let lab = Lab::new();
    let identity = lab.tmp.path().join("identity.json");
    fs::write(
        &identity,
        json!({"device":"synthetic-device-1","generation":"synthetic-gen-1"}).to_string(),
    )
    .unwrap();
    lab.link(
        &lab.outbox,
        &["bind", "--identity", identity.to_str().unwrap()],
    );
    // The view fits the file bound; the request made from it does not fit the hub's.
    let limit = vorda::store::capture::VIEW_LIMIT + 64 * 1024;
    let probe = handmade_view("synthetic-device-1", "synthetic-gen-1", 0)
        .to_string()
        .len();
    let view = lab.tmp.path().join("big.json");
    fs::write(
        &view,
        handmade_view("synthetic-device-1", "synthetic-gen-1", limit - probe - 20).to_string(),
    )
    .unwrap();
    let out = lab.link_out(
        &lab.outbox,
        &[
            "queue-native",
            "--capture",
            view.to_str().unwrap(),
            "--consent",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing was queued"));
    assert_eq!(lab.health()["queued"], 0);
    // Nothing was spent: a capture that fits gets sequence 1.
    fs::write(
        &view,
        handmade_view("synthetic-device-1", "synthetic-gen-1", 10).to_string(),
    )
    .unwrap();
    assert_eq!(lab.queue(&view)["sequence"], 1);
}

#[test]
fn a_capture_for_another_device_is_refused_and_queue_native_needs_consent() {
    let lab = Lab::new();
    let identity = lab.tmp.path().join("identity.json");
    fs::write(
        &identity,
        json!({"device":"synthetic-device-1","generation":"synthetic-gen-1"}).to_string(),
    )
    .unwrap();
    lab.link(
        &lab.outbox,
        &["bind", "--identity", identity.to_str().unwrap()],
    );
    let view = lab.tmp.path().join("other.json");
    fs::write(
        &view,
        handmade_view("synthetic-device-2", "synthetic-gen-1", 1).to_string(),
    )
    .unwrap();
    let out = lab.link_out(
        &lab.outbox,
        &[
            "queue-native",
            "--capture",
            view.to_str().unwrap(),
            "--consent",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("identity mismatch"));
    let out = lab.link_out(
        &lab.outbox,
        &["queue-native", "--capture", view.to_str().unwrap()],
    );
    assert!(!out.status.success());
    assert_eq!(lab.health()["queued"], 0);
}

#[test]
fn an_outbox_made_before_native_sending_keeps_its_entries_and_they_still_send() {
    let lab = enrolled();
    queue_v1(&lab, "00000000-0000-4000-8000-000000000001");
    // The outbox as the previous release left it: no native tables, no order columns.
    Connection::open(&lab.outbox)
        .unwrap()
        .execute_batch("DROP TABLE native_pending; DROP TABLE native_sequence; ALTER TABLE pending DROP COLUMN queued; ALTER TABLE pending DROP COLUMN status;")
        .unwrap();
    assert_eq!(lab.health()["queued"], 1);
    let view = lab.capture("scope-a", &synthetic_lock(&synthetic_packages(10), 0));
    assert_eq!(lab.queue(&view)["sequence"], 1);
    let health = lab.health();
    assert_eq!(health["queued"], 2);
    assert_eq!(health["needs_attention"], false);
    // The old entry is still the batch the v1 commands see, and it goes out first.
    assert_eq!(lab.link(&lab.outbox, &["bundle"])["sequence"], 1);
    serving(&lab, HEALTHY, |url| {
        let old = lab.send(url);
        assert_eq!(old["delivered"], true, "{old}");
        assert!(old["ack"].get("binding").is_none());
        let native = lab.send(url);
        assert_eq!(native["delivered"], true, "{native}");
        assert_eq!(native["ack"]["result"], "published");
        assert_eq!(native["queued"], 0);
    });
}

/// Every row of a reader list, following the cursor.
fn walk(lab: &Lab, url: &str, route: &str, mut request: Value) -> Vec<Value> {
    let mut rows = vec![];
    loop {
        let (code, page) = lab.reader(url, route, request.clone());
        assert_eq!(code, 200, "{page}");
        rows.extend(page[route].as_array().unwrap().iter().cloned());
        match page["next_cursor"].as_str() {
            Some(cursor) => request["cursor"] = json!(cursor),
            None => return rows,
        }
    }
}
fn kinds(rows: &[Value], kind: &str) -> usize {
    rows.iter().filter(|r| r["kind"] == kind).count()
}
fn send_ok(lab: &Lab, url: &str) -> Value {
    let sent = lab.send(url);
    assert_eq!(sent["delivered"], true, "{sent}");
    sent
}

#[test]
fn a_retired_source_reads_as_retired_not_stale_leaves_without_resolving_and_reopens_later() {
    retirement_flow(false);
}
/// The same flow on a hub that keeps the change log: the stored rows must equal the replay.
#[test]
fn a_retired_source_on_a_hub_with_a_change_log_replays_to_the_same_rows() {
    retirement_flow(true);
}
fn retirement_flow(logged: bool) {
    let lab = enrolled();
    if logged {
        lab.link(&lab.hub, &["migrate", "--change-log"]);
    }
    let pk = synthetic_packages(5);
    serving(&lab, HEALTHY, |url| {
        lab.queue(&lab.capture("scope-a", &synthetic_lock(&pk, 0)));
        send_ok(&lab, url);

        let retired = lab.retire("scope-a");
        assert_eq!(lab.queue(&retired)["sequence"], 2);
        assert_eq!(send_ok(&lab, url)["ack"]["result"], "published");

        let ask = json!({"devices":[lab.device()]});
        let sources = walk(&lab, url, "sources", ask.clone());
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0]["coverage"]["inventory"]["state"], "retired");
        assert_eq!(sources[0]["freshness"], "retired");
        assert_eq!(sources[0]["records"], 0);
        let (code, only) = lab.reader(url, "sources", json!({"freshness":"retired"}));
        assert_eq!((code, only["total"].clone()), (200, json!(1)), "{only}");
        let (_, status) = lab.reader(url, "status", ask.clone());
        assert_eq!(status["sources"]["retired"], 1, "{status}");
        assert_eq!(status["sources"]["by_inventory_state"]["retired"], 1);
        assert!(status["sources"]["by_observation_freshness"]
            .get("stale")
            .is_none());
        assert_eq!(lab.inventory(url).1["total"], 0);

        let mut since = ask.clone();
        since["since"] = json!("start");
        let changes = walk(&lab, url, "changes", since.clone());
        assert_eq!(kinds(&changes, "added"), 5);
        assert_eq!(kinds(&changes, "retired"), 5);
        assert_eq!(kinds(&changes, "resolved"), 0);
        assert!(changes
            .iter()
            .filter(|r| r["kind"] == "retired")
            .all(|r| r["reason"] == "source_retired_by_device" && r["assessment_revision"] == 2));

        // A later normal assessment reopens the source.
        lab.queue(&lab.capture("scope-a", &synthetic_lock(&pk, 0)));
        send_ok(&lab, url);
        let sources = walk(&lab, url, "sources", ask.clone());
        assert_eq!(sources[0]["coverage"]["inventory"]["state"], "complete");
        assert_eq!(sources[0]["freshness"], "fresh");
        let (_, status) = lab.reader(url, "status", ask);
        assert_eq!(status["sources"]["retired"], 0);
        assert_eq!(lab.inventory(url).1["total"], 5);
        let changes = walk(&lab, url, "changes", since);
        assert_eq!(kinds(&changes, "added"), 10);
        assert_eq!(kinds(&changes, "retired"), 5);
        assert_eq!(kinds(&changes, "resolved"), 0);
    });
    if logged {
        let c = Connection::open(&lab.hub).unwrap();
        let authority: String = c
            .query_row("SELECT authority FROM v2_authorities", [], |r| r.get(0))
            .unwrap();
        let log = vorda::link::change_log::stored(&c, &authority).unwrap();
        assert_eq!(
            log,
            vorda::link::change_log::replayed(&c, &authority).unwrap()
        );
        assert_eq!(log.iter().filter(|r| r.kind == "retired").count(), 5);
    }
}

#[test]
fn a_log_saved_before_retirement_existed_still_reads_and_continues_with_a_retirement() {
    let lab = enrolled();
    lab.link(&lab.hub, &["migrate", "--change-log"]);
    let pk = synthetic_packages(4);
    serving(&lab, HEALTHY, |url| {
        lab.queue(&lab.capture("scope-a", &synthetic_lock(&pk, 0)));
        send_ok(&lab, url);
    });
    let ask = json!({"devices":[lab.device()],"since":"start"});
    let before = serving(&lab, HEALTHY, |url| walk(&lab, url, "changes", ask.clone()));
    // The state as the release before retirement saved it.
    let versions =
        |from: &str, to: &str| {
            Connection::open(&lab.hub)
            .unwrap()
            .execute(
                "UPDATE v2_change_state SET state=CAST(replace(CAST(state AS TEXT),?,?) AS BLOB)",
                [format!("\"replay_version\":{from}"), format!("\"replay_version\":{to}")],
            )
            .unwrap()
        };
    assert_eq!(versions("4", "3"), 1);
    let old = serving(&lab, HEALTHY, |url| walk(&lab, url, "changes", ask.clone()));
    assert_eq!(old, before);
    lab.link(&lab.hub, &["migrate"]);

    serving(&lab, HEALTHY, |url| {
        lab.queue(&lab.retire("scope-a"));
        send_ok(&lab, url);
        let after = walk(&lab, url, "changes", ask.clone());
        assert_eq!(kinds(&after, "retired"), 4);
    });
    let c = Connection::open(&lab.hub).unwrap();
    let authority: String = c
        .query_row("SELECT authority FROM v2_authorities", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        vorda::link::change_log::stored(&c, &authority).unwrap(),
        vorda::link::change_log::replayed(&c, &authority).unwrap()
    );
    let saved: String = c
        .query_row("SELECT CAST(state AS TEXT) FROM v2_change_state", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(saved.contains("\"replay_version\":4"), "{saved}");
    lab.link(&lab.hub, &["migrate"]);
}

#[test]
fn retiring_a_source_the_device_never_captured_is_refused() {
    let lab = enrolled();
    let state = lab.tmp.path().join("state-empty");
    let out = lab.run(&[
        "--state",
        state.to_str().unwrap(),
        "capture-retire",
        "--scope",
        "scope-a",
        "--source",
        SOURCE,
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown_capture_source"));
}

fn unavailable_provider() -> Value {
    json!({"provider":{"name":"osv","request":"synthetic-request","status":"unavailable","checked_at":"1793898300.25","response_utf8":null}})
}

#[test]
fn an_unavailable_advisory_provider_reads_as_unavailable_with_its_check_time() {
    let lab = enrolled();
    let pk = synthetic_packages(5);
    serving(&lab, HEALTHY, |url| {
        let view = lab.capture_with("scope-a", &synthetic_lock(&pk, 0), unavailable_provider());
        lab.queue(&view);
        send_ok(&lab, url);
        let sources = walk(&lab, url, "sources", json!({"devices":[lab.device()]}));
        assert_eq!(sources[0]["coverage"]["inventory"]["state"], "complete");
        assert_eq!(sources[0]["coverage"]["advisories"]["state"], "unavailable");
        assert_eq!(sources[0]["advisory_checked_at"]["value"], 1793898300.25);
        assert_eq!(sources[0]["records"], 5);
        let (rows, _) = lab.inventory(url);
        assert_eq!(rows.len(), 5);
        assert!(rows
            .iter()
            .all(|r| r["advisory_coverage"]["state"] == "unavailable"
                && r["inventory_coverage"]["state"] == "complete"));
    });
}

#[test]
fn tampered_retirements_and_provider_outcomes_are_refused_with_fixed_codes() {
    let lab = enrolled();
    let pk = synthetic_packages(3);
    serving(&lab, HEALTHY, |url| {
        lab.queue(&lab.capture("scope-a", &synthetic_lock(&pk, 0)));
        send_ok(&lab, url);
        let retired = lab.retire("scope-a");
        let provided = lab.capture_with("scope-a", &synthetic_lock(&pk, 0), unavailable_provider());
        type Edit = fn(&mut Value);
        let cases: Vec<(&Path, Edit, &str)> = vec![
            (
                &retired,
                |a| a["inputs"] = json!([{"path":"package-lock.json","sha256":null,"bytes_utf8":null,"error":"input_read_failed"}]),
                "invalid_retirement",
            ),
            (
                &retired,
                |a| a["records"] = json!([{"record_id":"r","component_id":"c","location_ref":"l","package":{"ecosystem":"npm","namespace":null,"name":"x","version":"1.0.0","qualifiers":{}},"legacy_aliases":[],"input_path":"package-lock.json"}]),
                "invalid_retirement",
            ),
            (
                &retired,
                |a| a["provider"] = json!({"name":"osv"}),
                "invalid_retirement",
            ),
            (
                &retired,
                |a| a["coverage"]["fix_verified"] = json!(true),
                "unsupported_coverage",
            ),
            (
                &retired,
                |a| a["coverage"]["global_clean"] = json!(true),
                "unsupported_coverage",
            ),
            (
                &retired,
                |a| a["coverage"]["inventory"]["reason"] = json!("anything"),
                "unsupported_coverage",
            ),
            (
                &provided,
                |a| a["coverage"]["fix_verified"] = json!(true),
                "unsupported_coverage",
            ),
            (
                &provided,
                |a| a["coverage"]["global_clean"] = json!(true),
                "unsupported_coverage",
            ),
            (
                &provided,
                |a| a["coverage"]["advisories"] = json!({"state":"complete","reason":null}),
                "unsupported_coverage",
            ),
            (
                &provided,
                |a| a["provider"]["checked_at"] = json!("1793898300.5"),
                "invalid_provider",
            ),
            (
                &provided,
                |a| a["provider"]["status"] = json!("available"),
                "invalid_provider",
            ),
        ];
        for (n, (view, edit, code)) in cases.into_iter().enumerate() {
            let queued = lab.queue(&lab.tampered(view, edit));
            let sequence = queued["sequence"].as_i64().unwrap();
            assert_eq!(
                lab.post_queued(url, sequence),
                (422, code.to_string()),
                "case {n}"
            );
        }
        let long = lab.queue(&lab.tampered(&provided, |a| {
            a["provider"]["request"] = json!("x".repeat(4097));
        }));
        assert_eq!(
            lab.post_queued(url, long["sequence"].as_i64().unwrap()),
            (413, "string_limit".to_string())
        );
        // Oversize bodies are still refused before anything is read.
        assert!([413, 0].contains(&lab.post_raw(url, vec![b' '; 6 << 20]).0));
        // Nothing tampered reached the hub: the source still reads as it did.
        let sources = walk(&lab, url, "sources", json!({"devices":[lab.device()]}));
        assert_eq!(sources[0]["coverage"]["inventory"]["state"], "complete");
        assert_eq!(sources[0]["records"], 3);
    });
}

#[test]
fn a_retirement_for_a_source_the_hub_has_never_seen_is_refused_and_writes_nothing() {
    let lab = enrolled();
    let pk = synthetic_packages(3);
    serving(&lab, HEALTHY, |url| {
        // The device captured and retired locally, but the hub never saw the capture.
        lab.capture("scope-a", &synthetic_lock(&pk, 0));
        let retired = lab.retire("scope-a");
        let queued = lab.queue(&retired);
        assert_eq!(
            lab.post_queued(url, queued["sequence"].as_i64().unwrap()),
            (422, "invalid_retirement".to_string())
        );
        let sources = walk(&lab, url, "sources", json!({"devices":[lab.device()]}));
        assert!(sources.is_empty(), "{sources:?}");
    });
}

#[test]
fn a_retirement_from_a_device_that_lost_its_grant_is_refused_and_writes_nothing() {
    let lab = enrolled();
    let pk = synthetic_packages(3);
    serving(&lab, HEALTHY, |url| {
        lab.queue(&lab.capture("scope-a", &synthetic_lock(&pk, 0)));
        send_ok(&lab, url);
        lab.link(
            &lab.hub,
            &[
                "capture-deny",
                "--device",
                &lab.device(),
                "--source",
                SOURCE,
            ],
        );
        let queued = lab.queue(&lab.retire("scope-a"));
        assert_eq!(
            lab.post_queued(url, queued["sequence"].as_i64().unwrap()),
            (403, "capture_unapproved".to_string())
        );
        let sources = walk(&lab, url, "sources", json!({"devices":[lab.device()]}));
        assert_eq!(sources[0]["coverage"]["inventory"]["state"], "complete");
        assert_eq!(sources[0]["records"], 3);
    });
}

/// A v1 batch with one finding per `(key, package)`, in scope `scope-a`, queued through the outbox.
fn queue_findings(lab: &Lab, findings: &[(&str, &str, &str)]) {
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/capture/V1.json")).unwrap();
    batch["device"] = json!(lab.device());
    batch["generation"] = json!(lab.generation());
    batch["scan"] = json!("00000000-0000-4000-8000-0000000000f1");
    batch["observed"] = json!(now() - 30.0);
    batch["coverage"] = json!({"scope-a": "complete"});
    batch["findings"] = json!(findings
        .iter()
        .map(|(key, name, version)| json!({"advisory":"SYNTHETIC-2026-0001","ecosystem":"npm","key":key,
            "location":"a".repeat(64),"name":name,"scope":"scope-a","source":"synthetic.invalid","version":version}))
        .collect::<Vec<_>>());
    Outbox::open(&lab.outbox).unwrap().enqueue(&batch).unwrap();
}

/// `vorda hub-mcp` over stdio against the lab's TLS hub: one request line, one reply line.
struct Mcp {
    child: std::process::Child,
    lines: std::io::BufReader<std::process::ChildStdout>,
    id: u64,
}
impl Mcp {
    fn start(lab: &Lab, url: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .args([
                "hub-mcp",
                "--hub",
                url,
                "--reader-env",
                "SYN_READER",
                "--ca-file",
            ])
            .arg(&lab.cert)
            .env("SYN_READER", READER)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let lines = std::io::BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            lines,
            id: 0,
        }
    }
    fn rpc(&mut self, method: &str, params: Value) -> Value {
        use std::io::BufRead;
        self.id += 1;
        let line = json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params});
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        let mut reply = String::new();
        self.lines.read_line(&mut reply).unwrap();
        serde_json::from_str(&reply).unwrap_or_else(|_| panic!("not a reply line: {reply:?}"))
    }
    /// `(is_error, text or parsed hub answer)` of one tool call.
    fn tool(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let result =
            self.rpc("tools/call", json!({"name":name,"arguments":arguments}))["result"].clone();
        let items = result["content"].as_array().unwrap();
        if result["isError"] == true {
            return (true, items[0]["text"].clone());
        }
        (
            false,
            serde_json::from_str(items[1]["text"].as_str().unwrap()).unwrap(),
        )
    }
    fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let (is_error, answer) = self.tool(name, arguments);
        assert!(!is_error, "{name}: {answer}");
        answer
    }
}
impl Drop for Mcp {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}
/// The hub database and everything beside it, byte for byte.
fn hub_bytes(lab: &Lab) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files: Vec<_> = fs::read_dir(lab.hub.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("hub.db")
        })
        .map(|p| (p.clone(), fs::read(p).unwrap()))
        .collect();
    files.sort();
    files
}

#[test]
fn findings_then_finding_then_evidence_works_over_mcp_on_a_hub_the_sender_filled() {
    let lab = enrolled();
    // Another site's device holds a finding the reader's grant does not cover.
    let other = common::enroll(
        &Hub::open(&lab.hub).unwrap(),
        ORG,
        "synthetic-other-site",
        "o1",
        &["synthetic-other-key"],
    );
    let pk = synthetic_packages(5);
    queue_findings(
        &lab,
        &[
            ("synthetic-key-hit", &pk[2].0, &pk[2].1),
            ("synthetic-key-miss", &pk[3].0, "9.9.9"),
        ],
    );
    lab.queue(&lab.capture("scope-a", &synthetic_lock(&pk, 0)));
    serving(&lab, HEALTHY, |url| {
        while lab.health()["queued"] != 0 {
            send_ok(&lab, url);
        }
        let mut mcp = Mcp::start(&lab, url);
        let listed = mcp.rpc("tools/list", json!({}));
        let names: Vec<_> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 9);
        assert!(names.contains(&"finding"));

        // findings -> finding -> evidence.
        let listing = mcp.ok("findings", json!({}));
        let row = listing["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"]["quoted"] == pk[2].0.as_str())
            .expect("the sent finding is listed");
        assert_eq!(row["device"], lab.device().as_str());
        let key = row["key"].as_str().unwrap();
        let before = hub_bytes(&lab);
        let finding = mcp.ok("finding", json!({"key": key}));
        assert_eq!(hub_bytes(&lab), before, "a read changed the hub");
        assert_eq!(finding["occurrences_total"], 1);
        let occurrence = &finding["occurrences"][0];
        assert_eq!(occurrence["device"], lab.device().as_str());
        assert_eq!(occurrence["site"], SITE);
        assert_eq!(occurrence["v1"]["freshness"], "fresh");
        assert!(occurrence["v1"]["received_at"].as_f64().unwrap() > 0.0);
        assert_eq!(occurrence["coverage"]["scope"], "scope-a");
        assert_eq!(occurrence["coverage"]["state"], "complete");
        let matches = occurrence["inventory"]["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1, "{finding}");
        assert_eq!(matches[0]["package"]["name"]["quoted"], pk[2].0.as_str());
        assert_eq!(matches[0]["package"]["version"]["quoted"], pk[2].1.as_str());
        assert_eq!(matches[0]["source"], SOURCE);
        assert_eq!(matches[0]["inventory_coverage"]["state"], "complete");
        let reference = matches[0]["evidence"].as_str().unwrap();
        let evidence = mcp.ok("evidence", json!({"reference": reference}));
        assert_eq!(evidence["evidence"]["records_total"], 5);
        assert!(evidence["evidence"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["package"]["name"]["quoted"] == pk[2].0.as_str()));

        // The same package name at another version is not a match.
        let miss = mcp.ok("finding", json!({"key": "synthetic-key-miss"}));
        assert_eq!(miss["occurrences"][0]["inventory"]["matches_total"], 0);

        // A key from another site answers exactly as a key that does not exist, over MCP and HTTP.
        let (is_error, missing) = mcp.tool("finding", json!({"key": "synthetic-no-such-key"}));
        assert!(is_error && missing.as_str().unwrap().starts_with("Not found"));
        assert_eq!(
            mcp.tool("finding", json!({"key": "synthetic-other-key"})),
            (true, missing.clone())
        );
        let http_missing = lab.reader(url, "finding", json!({"key": "synthetic-no-such-key"}));
        assert_eq!(http_missing.0, 404);
        assert_eq!(
            lab.reader(url, "finding", json!({"key": "synthetic-other-key"})),
            http_missing
        );
        assert!(!format!("{missing}{http_missing:?}").contains(&other));
    });
}
