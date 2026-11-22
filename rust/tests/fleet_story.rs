//! One vertical story: a site with a vulnerable device, a partially scanned one and a benign one
//! that goes silent, read over HTTP by a site-scoped reader who sees the gap, the age and nothing
//! of another site. The owner's re-collected capture is then admitted in-process through the
//! shipped v2 admission (`World::deliver`), not `link send` (v1 queue/send does not write the v2
//! tables), and the next read over HTTP shows it. The owner-side v2 send is not tested here.
//! Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use vorda::link::{native::Admission, server::Server, storage::Hub};

/// Serve the real hub path (reader routes, ingest routes) on a fresh socket until `run` returns.
fn serving<R>(w: &World, run: impl FnOnce(SocketAddr) -> R) -> R {
    let server = Server::bind(Hub::open(&w.db).unwrap(), "127.0.0.1", 0, None, None).unwrap();
    let addr = server.local_addr().unwrap();
    let admission = Admission::open(&w.db, vec![]).unwrap();
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
    s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    s.write_all(bytes).unwrap();
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = vec![];
    let _ = s.read_to_end(&mut out);
    out
}
fn wire(path: &str, credential: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {credential}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend(body);
    wire
}
/// A read request: the status and the JSON body.
fn read(addr: SocketAddr, route: &str, credential: &str, request: &Value) -> (u16, Value) {
    let response = exchange(
        addr,
        &wire(
            &format!("/v2/read/{route}"),
            credential,
            request.to_string().as_bytes(),
        ),
    );
    let parsed = serde_json::from_slice(body(&response)).unwrap_or(Value::Null);
    (status(&response), parsed)
}
fn ok(addr: SocketAddr, route: &str, credential: &str, request: Value) -> Value {
    let (code, answer) = read(addr, route, credential, &request);
    assert_eq!(code, 200, "{route} {request}: {answer}");
    answer
}
fn row_of<'a>(answer: &'a Value, list: &str, device: &str) -> &'a Value {
    answer[list]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["device"] == device)
        .unwrap_or_else(|| panic!("no {list} row for {device}: {answer}"))
}
fn delivery<'a>(device: &'a str, site: &'a str, t: f64, inputs: &'a [&'a str]) -> Delivery<'a> {
    Delivery {
        device,
        org: ORG,
        site,
        scope: "scope-1",
        source: "npm-a",
        observed: Some(t),
        inputs,
    }
}

#[test]
fn a_scoped_reader_sees_the_gap_and_the_silence_and_the_owners_redelivery_shows_on_the_next_read() {
    let w = world();
    // a1 holds version 1 findings (the vulnerable one), a2 is scanned with one input missing, and
    // a3 has no findings at all but stopped reporting five days ago.
    let a3 = enroll_without_evidence(&w, "site-a", "a3");
    let t = vorda::store::now();
    let day = 86400.0;
    for (d, site, observed, inputs) in [
        (&w.a1, "site-a", t - 300.0, &["one"][..]),
        (&w.a2, "site-a", t - 300.0, &["one", "absent"][..]),
        (&a3, "site-a", t - 5.0 * day, &["one"][..]),
        (&w.b1, "site-b", t - 60.0, &["one"][..]),
        (&w.x1, "site-a", t - 60.0, &["one"][..]),
    ] {
        let org = if d == &w.x1 { "org-other" } else { ORG };
        let d = Delivery {
            org,
            ..delivery(d, site, observed, inputs)
        };
        w.deliver(&d, 1).unwrap();
    }
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    grant(&w, READER_B, &["site-b"], &[], 3600.0);
    // Read from the database only to forge a reference to another site's evidence.
    let db = rusqlite::Connection::open(&w.db).unwrap();
    let b1_reference: String = db
        .query_row(
            "SELECT evidence FROM v2_assessments WHERE json_extract(authority,'$[2]')=?",
            [&w.b1],
            |r| r.get(0),
        )
        .unwrap();
    drop(db);

    let (silent_before, one_before) = serving(&w, |addr| {
        // The vulnerable device's findings are listed; nothing of site B or the other
        // organization is.
        let findings = ok(addr, "findings", READER_A, json!({}));
        let mut keys: Vec<_> = findings["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["key"].as_str().unwrap().to_string())
            .collect();
        keys.sort();
        assert_eq!(keys, ["finding-a1-x", "finding-a1-y", "finding-a2-x"]);

        // The inventory finds the component on every device of the site and says how old each
        // observation is, so a stale one cannot pass for fresh.
        let inventory = ok(addr, "inventory", READER_A, json!({"name": "samepackage"}));
        assert_eq!(inventory["total"], 3, "a1, a2 and a3; not b1, not x1");
        let one = row_of(&inventory, "inventory", &w.a1);
        assert_eq!(one["freshness"], "fresh");
        assert!(one["age_seconds"].as_f64().unwrap() < 3600.0);
        assert_eq!(one["package"]["version"]["quoted"], "1.0.0");
        let quiet = row_of(&inventory, "inventory", &a3);
        assert_eq!(quiet["freshness"], "stale");
        assert!(quiet["age_seconds"].as_f64().unwrap() > 4.0 * day);

        // The coverage gap is named: the partial source is partial and its failed input counted,
        // the others complete.
        let sources = ok(addr, "sources", READER_A, json!({}));
        assert_eq!(sources["total"], 3);
        let partial = row_of(&sources, "sources", &w.a2);
        assert_eq!(partial["coverage"]["inventory"]["state"], "partial");
        assert_eq!(
            partial["coverage"]["inputs"],
            json!({"complete": 1, "failed": 1})
        );
        for complete in [&w.a1, &a3] {
            let row = row_of(&sources, "sources", complete);
            assert_eq!(row["coverage"]["inventory"]["state"], "complete");
        }
        assert_eq!(
            row_of(&sources, "sources", &a3)["freshness"],
            "stale",
            "the silent device is stale, not absent"
        );

        // The totals count this site only.
        let overview = ok(addr, "status", READER_A, json!({}));
        assert_eq!(overview["devices"]["enrolled"], 3);
        assert_eq!(overview["sources"]["total"], 3);
        assert_eq!(
            overview["sources"]["by_observation_freshness"],
            json!({"fresh": 2, "stale": 1})
        );
        assert_eq!(
            overview["sources"]["by_inventory_state"],
            json!({"complete": 2, "partial": 1})
        );
        assert_eq!(overview["sources"]["with_failed_inputs"], 1);

        // Nothing of another site, anywhere in what this reader was told.
        let evidence = ok(
            addr,
            "evidence",
            READER_A,
            json!({"reference": one["evidence"]}),
        );
        assert_eq!(evidence["evidence"]["device"], w.a1.as_str());
        let missing = read(
            addr,
            "evidence",
            READER_A,
            &json!({"reference": "nothing/here"}),
        );
        assert_eq!(missing.0, 404);
        assert_eq!(
            read(
                addr,
                "evidence",
                READER_A,
                &json!({"reference": format!("{}/{b1_reference}", w.b1)})
            ),
            missing,
            "another site's evidence looks like nothing"
        );
        let changes = ok(addr, "changes", READER_A, json!({"since": "start"}));
        let devices = ok(addr, "devices", READER_A, json!({}));
        for (route, answer) in [
            ("findings", &findings),
            ("inventory", &inventory),
            ("sources", &sources),
            ("status", &overview),
            ("evidence", &evidence),
            ("changes", &changes),
            ("devices", &devices),
        ] {
            for hidden in [
                w.b1.as_str(),
                w.x1.as_str(),
                "site-b",
                "org-other",
                "finding-b1",
                "finding-x1",
            ] {
                assert!(
                    !answer.to_string().contains(hidden),
                    "{hidden} leaked in {route}"
                );
            }
        }
        // The other site's reader gets that site and none of this one.
        let theirs = ok(addr, "sources", READER_B, json!({}));
        assert_eq!(theirs["total"], 1);
        assert!(!theirs.to_string().contains(&a3));

        // There is no way to repair anything through the reader's door.
        for path in [
            "/v2/read/repair",
            "/v2/read/fix",
            "/v2/read/apply",
            "/v2/read/remediate",
            "/v2/repair",
            "/v2/batches/repair",
        ] {
            let answer = exchange(addr, &wire(path, READER_A, b"{}"));
            assert_eq!(status(&answer), 404, "{path}");
            assert_eq!(body(&answer), br#"{"error":"route"}"#, "{path}");
        }
        let before = ok(
            addr,
            "changes",
            READER_A,
            json!({"since": "start", "devices": [a3]}),
        );
        assert_eq!(before["total"], 1, "one assessment so far: it was added");
        (row_of(&sources, "sources", &a3).clone(), one.clone())
    });

    // The owner collects on the silent device again and delivers the new capture: its component
    // changed from 1.0.0 to 2.0.0.
    let l2 = include_bytes!("fixtures/capture/L2.json");
    let now = vorda::store::now();
    w.deliver_lock(&delivery(&a3, "site-a", now - 30.0, &["one"]), 2, l2)
        .unwrap();

    serving(&w, |addr| {
        let sources = ok(addr, "sources", READER_A, json!({}));
        let back = row_of(&sources, "sources", &a3);
        assert_eq!(back["freshness"], "fresh", "the next read shows it alive");
        assert!(back["age_seconds"].as_f64().unwrap() < 3600.0);
        assert_ne!(back["observed_at"], silent_before["observed_at"]);
        let received_before = silent_before["last_received"].as_f64().unwrap();
        assert!(back["last_received"].as_f64().unwrap() > received_before);
        assert_eq!(back["assessment_revision"], 2);

        let inventory = ok(addr, "inventory", READER_A, json!({"name": "samepackage"}));
        assert_eq!(inventory["total"], 3);
        let row = row_of(&inventory, "inventory", &a3);
        assert_eq!(row["package"]["version"]["quoted"], "2.0.0");
        assert_eq!(row["freshness"], "fresh");
        // The devices the owner did not touch read exactly as before.
        // Untouched, only older: every field but the age is equal, and the age did not reset.
        let strip = |row: &Value| {
            let mut row = row.clone();
            row.as_object_mut().unwrap().remove("age_seconds");
            row
        };
        let now_row = row_of(&inventory, "inventory", &w.a1);
        assert_eq!(strip(now_row), strip(&one_before));
        assert!(
            now_row["age_seconds"].as_f64().unwrap() >= one_before["age_seconds"].as_f64().unwrap()
        );
        assert_eq!(
            row_of(&sources, "sources", &w.a2)["coverage"]["inventory"]["state"],
            "partial",
            "the gap on the other device is still named"
        );

        let overview = ok(addr, "status", READER_A, json!({}));
        assert_eq!(
            overview["sources"]["by_observation_freshness"],
            json!({"fresh": 3})
        );

        // The change is on record, with what it replaced.
        let changes = ok(
            addr,
            "changes",
            READER_A,
            json!({"since": "start", "devices": [a3]}),
        );
        let kinds: Vec<_> = changes["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kinds, ["added", "changed"]);
        assert_eq!(changes["changes"][1]["previous_version"]["quoted"], "1.0.0");
        assert!(!changes.to_string().contains(&w.b1));
    });
}
