//! The reader routes of `link serve` (`POST /v2/read/...`), driven over real sockets against a
//! schema-2 hub. Synthetic fixtures only.
mod common;
use common::*;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use vorda::fleet::auth::{DeviceGrant, GrantRequest, ReaderStore, Site, SourceGrant};
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
                let started = Instant::now();
                if let Err(error) = server.serve_once_with_admission(&admission) {
                    eprintln!(
                        "reader listener call failed after {:?}: {error:?}",
                        started.elapsed()
                    );
                }
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
fn reader_a(w: &World) -> String {
    grant(w, READER_A, &["site-a"], &[], 3600.0)
}
const NEVER_GRANTED: &str = "synthetic-never-granted-000000000000";
const READER_WIDE: &str = "synthetic-reader-wide-tests-only-00000";

#[test]
fn a_reader_lists_and_opens_its_devices_over_http() {
    let w = world();
    reader_a(&w);
    serving(&w, |addr| {
        let view = ok(addr, "devices", READER_A, json!({}));
        let mut expected = vec![w.a1.clone(), w.a2.clone()];
        expected.sort();
        assert_eq!(device_ids(&view), expected);
        assert_eq!(view["contract_version"], "m3-fleet-1");
        assert_eq!(view["total"], 2);
        assert!(!view.to_string().contains(READER_A));
        for hidden in [w.b1.as_str(), w.x1.as_str(), "site-b", "org-other"] {
            assert!(!view.to_string().contains(hidden), "{hidden} leaked");
        }
        let one = ok(addr, "device", READER_A, json!({"device": w.a1}));
        assert_eq!(one["device"], w.a1.as_str());
        assert_eq!(read(addr, "device", READER_A, &json!({})).0, 400);

        // Filters narrow inside a grant that has more to give.
        grant(&w, READER_WIDE, &["site-a", "site-b"], &[], 3600.0);
        let wide = |request: Value| device_ids(&ok(addr, "devices", READER_WIDE, request));
        assert_eq!(wide(json!({})).len(), 3);
        assert_eq!(
            wide(json!({"sites": ["site-b"]})),
            std::slice::from_ref(&w.b1)
        );
        assert_eq!(
            wide(json!({"devices": [w.a2]})),
            std::slice::from_ref(&w.a2)
        );

        // A device outside the grant looks exactly like one that does not exist.
        let missing = read(
            addr,
            "device",
            READER_A,
            &json!({"device": uuid::Uuid::new_v4().to_string()}),
        );
        let other_site = read(addr, "device", READER_A, &json!({"device": w.b1}));
        let other_org = read(addr, "device", READER_A, &json!({"device": w.x1}));
        assert_eq!(missing.0, 404);
        assert_eq!(other_site, missing);
        assert_eq!(other_org, missing);
    });
}

#[test]
fn unknown_expired_and_revoked_readers_get_one_answer_and_nothing_else_is_said() {
    let w = world();
    let revoked = reader_a(&w);
    ReaderStore::open(&w.db).unwrap().revoke(&revoked).unwrap();
    serving(&w, |addr| {
        let answers: Vec<_> = [READER_A, NEVER_GRANTED, "short"]
            .iter()
            .map(|secret| exchange(addr, &wire("/v2/read/devices", secret, b"{}")))
            .collect();
        for answer in &answers {
            assert_eq!(status(answer), 401);
            assert_eq!(body(answer), body(&answers[0]), "one body for every reason");
        }
        let text = String::from_utf8_lossy(&answers[0]).to_string();
        assert!(!text.contains(READER_A));
        // Authentication comes before the body is looked at: no oracle through validation errors.
        let garbage = exchange(addr, &wire("/v2/read/devices", NEVER_GRANTED, b"not json"));
        assert_eq!(body(&garbage), body(&answers[0]));
        let unlisted = exchange(
            addr,
            &wire("/v2/read/devices", NEVER_GRANTED, br#"{"now":1}"#),
        );
        assert_eq!(body(&unlisted), body(&answers[0]));
        // No credential, or one that is not a bearer token, is the same answer too.
        for header in [
            "",
            "Authorization: Basic YTpi\r\n",
            "Authorization: Bearer\r\n",
            "Authorization: bearer lowercase-scheme-0000000000000000\r\n",
        ] {
            let request = format!(
                "POST /v2/read/devices HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{header}Content-Length: 2\r\n\r\n{{}}"
            );
            let answer = exchange(addr, request.as_bytes());
            assert_eq!(status(&answer), 401, "{header:?}");
            assert_eq!(body(&answer), body(&answers[0]), "{header:?}");
        }
    });
}

#[test]
fn a_reader_whose_store_cannot_be_read_gets_the_same_401() {
    let w = world();
    reader_a(&w);
    serving(&w, |addr| {
        let unknown = exchange(addr, &wire("/v2/read/devices", NEVER_GRANTED, b"{}"));
        assert_eq!(status(&unknown), 401);
        std::fs::write(format!("{}.readers", w.db.display()), b"not a database").unwrap();
        let broken = exchange(addr, &wire("/v2/read/devices", READER_A, b"{}"));
        assert_eq!(status(&broken), 401, "{}", String::from_utf8_lossy(&broken));
        assert_eq!(body(&broken), body(&unknown));
    });
}

#[test]
fn only_post_to_a_listed_route_is_answered() {
    let w = world();
    reader_a(&w);
    serving(&w, |addr| {
        let get = format!("GET /v2/read/devices HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {READER_A}\r\n\r\n");
        assert_eq!(status(&exchange(addr, get.as_bytes())), 405);
        for path in [
            "/v2/read/nothing",
            "/v2/read/",
            "/v2/read/devices/",
            "/v2/read/DEVICES",
            "/v2/readers/devices",
            "/v2/read",
        ] {
            let answer = exchange(addr, &wire(path, READER_A, b"{}"));
            assert_eq!(status(&answer), 404, "{path}");
        }
        for route in ["devices", "findings", "status", "sources", "inventory"] {
            let path = format!("/v2/read/{route}");
            assert_eq!(status(&exchange(addr, &wire(&path, READER_A, b"{}"))), 200);
        }
        let start = br#"{"since":"start"}"#;
        assert_eq!(
            status(&exchange(addr, &wire("/v2/read/changes", READER_A, start))),
            200
        );
        let reference = br#"{"reference":"nothing/here"}"#;
        // A listed route that finds nothing says "not found"; an unlisted one says "route".
        let missing = exchange(addr, &wire("/v2/read/evidence", READER_A, reference));
        assert_eq!(status(&missing), 404);
        assert_eq!(body(&missing), br#"{"error":"not found"}"#);
        let unlisted = exchange(addr, &wire("/v2/read/nothing", READER_A, reference));
        assert_eq!(body(&unlisted), br#"{"error":"route"}"#);
        assert_eq!(
            status(&exchange(
                addr,
                &wire(
                    "/v2/read/device",
                    READER_A,
                    format!(r#"{{"device":"{}"}}"#, w.a1).as_bytes()
                )
            )),
            200
        );
    });
}

#[test]
fn the_batch_trial_entry_point_does_not_accept_read_routes() {
    let w = world();
    reader_a(&w);
    let admission = Admission::open(&w.db, vec![]).unwrap();
    let refused = admission
        .http_trial(&wire("/v2/read/devices", READER_A, b"{}"))
        .unwrap_err();
    assert_eq!(refused.http_status, Some(404));
}

#[test]
fn ingest_and_reader_credentials_are_refused_on_each_others_routes() {
    let w = world();
    reader_a(&w);
    let ingest = ingest_secret("a1"); // the credential a1 enrolled with
    let before = std::fs::read(&w.db).unwrap();
    // Well-formed requests for each ingest route, so the credential is what is refused.
    let v1: Value = serde_json::from_str(include_str!("fixtures/link-v1.json")).unwrap();
    let delivery = Delivery {
        device: &w.a1,
        org: ORG,
        site: "site-a",
        scope: "scope-1",
        source: "npm-a",
        observed: Some(vorda::store::now() - 60.0),
        inputs: &["one"],
    };
    let v2 = w.v2_request(&delivery, 1, L1).3;
    serving(&w, |addr| {
        // An enrolled device's credential does not read.
        assert_eq!(
            status(&exchange(addr, &wire("/v2/read/devices", &ingest, b"{}"))),
            401
        );
        // A reader's credential does not enroll, submit v1 evidence, or submit v2 evidence.
        let enroll = json!({"credential": "synthetic-new-device-credential-000000"}).to_string();
        let requests = [
            ("/v1/batches", v1.to_string().into_bytes()),
            ("/v1/enroll", enroll.into_bytes()),
            ("/v2/batches", v2.clone()),
        ];
        for (path, request) in requests {
            let answer = exchange(addr, &wire(path, READER_A, &request));
            assert_eq!(
                status(&answer),
                401,
                "{path}: {}",
                String::from_utf8_lossy(&answer)
            );
            assert!(!String::from_utf8_lossy(&answer).contains(READER_A));
        }
    });
    assert_eq!(
        std::fs::read(&w.db).unwrap(),
        before,
        "a refused request changed the hub"
    );
}

#[test]
fn findings_pages_follow_their_cursors_over_http_and_stay_inside_the_grant() {
    let w = world();
    reader_a(&w);
    grant(&w, READER_B, &["site-a"], &[], 3600.0);
    grant(&w, READER_WIDE, &["site-a", "site-b"], &[], 3600.0);
    serving(&w, |addr| {
        let first = ok(addr, "findings", READER_A, json!({"limit": 1}));
        assert_eq!(
            (first["total"].as_i64(), first["page_end"].as_str()),
            (Some(3), Some("limit"))
        );
        let cursor = first["next_cursor"].as_str().unwrap().to_string();
        let second = ok(
            addr,
            "findings",
            READER_A,
            json!({"limit": 5, "cursor": cursor}),
        );
        assert_eq!(
            (second["page_end"].as_str(), second["next_cursor"].is_null()),
            (Some("last"), true)
        );
        let mut keys: Vec<String> = [&first, &second]
            .iter()
            .flat_map(|p| p["findings"].as_array().unwrap().clone())
            .map(|f| f["key"].as_str().unwrap().to_string())
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            ["finding-a1-x", "finding-a1-y", "finding-a2-x"],
            "every finding once"
        );
        for hidden in ["finding-b1", "finding-x1", "site-b", "org-other"] {
            assert!(
                !format!("{first}{second}").contains(hidden),
                "{hidden} leaked"
            );
        }

        // A made-up, altered, borrowed or re-aimed cursor is refused like any other: one answer.
        let invented = read(
            addr,
            "findings",
            READER_A,
            &json!({"limit": 1, "cursor": "AAAA"}),
        );
        assert_eq!(invented.0, 400);
        let mut altered = cursor.clone().into_bytes();
        let last = altered.len() - 1;
        altered[last] = if altered[last] == b'0' { b'1' } else { b'0' };
        let altered = String::from_utf8(altered).unwrap();
        for (request, reader, why) in [
            (json!({"limit": 1, "cursor": altered}), READER_A, "altered"),
            (
                json!({"limit": 1, "cursor": cursor}),
                READER_B,
                "another reader",
            ),
            (
                json!({"limit": 1, "cursor": cursor, "name": "x"}),
                READER_A,
                "another query",
            ),
        ] {
            assert_eq!(read(addr, "findings", reader, &request), invented, "{why}");
        }
        assert_eq!(
            read(
                addr,
                "devices",
                READER_A,
                &json!({"limit": 1, "cursor": cursor})
            ),
            invented,
            "another list"
        );

        // Filters narrow only.
        let other_site = ok(
            addr,
            "findings",
            READER_A,
            json!({"sites": ["site-b"], "devices": [w.b1]}),
        );
        assert_eq!(other_site["total"], 0);
        // ...and do narrow, inside a grant that has more to give.
        let wide = |request: Value| ok(addr, "findings", READER_WIDE, request)["total"].clone();
        assert_eq!(wide(json!({})), 6);
        assert_eq!(wide(json!({"sites": ["site-b"]})), 3);
        assert_eq!(wide(json!({"devices": [w.a1]})), 2);
        assert_eq!(wide(json!({"name": "package-of-finding-a2-x"})), 1);
        assert_eq!(wide(json!({"advisory": "no-such-advisory"})), 0);
        assert_eq!(
            read(
                addr,
                "findings",
                READER_A,
                &json!({"cursor": cursor, "advisory": "x"})
            ),
            invented,
            "another query by advisory"
        );
        for bad in [
            json!({"limit": "1"}),
            json!({"limit": 0}),
            json!({"limit": 1.5}),
            json!({"devices": "a"}),
            json!({"nope": 1}),
            json!([1]),
        ] {
            assert_eq!(read(addr, "findings", READER_A, &bad).0, 400, "{bad}");
        }
    });
}

#[test]
fn no_request_field_or_header_reaches_a_clock() {
    let w = world();
    standard_deliveries(&w);
    reader_a(&w);
    serving(&w, |addr| {
        // Fields that would set a time are not part of any route.
        let routes = [
            ("devices", json!({})),
            ("device", json!({"device": w.a1})),
            ("findings", json!({})),
            ("status", json!({})),
            ("sources", json!({})),
            ("inventory", json!({})),
            ("changes", json!({"since": "start"})),
            ("evidence", json!({"reference": "x/y"})),
        ];
        for (route, base) in &routes {
            for field in ["now", "as_of", "time", "timestamp", "clock", "today"] {
                let mut request = base.clone();
                request[field] = json!(1);
                let (code, answer) = read(addr, route, READER_A, &request);
                assert_eq!(code, 400, "{route} accepted {field}: {answer}");
                assert_eq!(answer, json!({"error": "unknown field"}));
            }
        }

        // Headers that look like clocks are not read either: the answer carries the server's time.
        let before = vorda::store::now();
        let request = format!(
            "POST /v2/read/devices HTTP/1.1\r\nHost: localhost\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nX-Now: 4102444800\r\nX-As-Of: 1\r\nX-Request-Time: 1\r\nContent-Type: application/json\r\nAuthorization: Bearer {READER_A}\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        let answer = exchange(addr, request.as_bytes());
        assert_eq!(status(&answer), 200);
        let view: Value = serde_json::from_slice(body(&answer)).unwrap();
        let after = vorda::store::now();
        let as_of = view["as_of"].as_f64().unwrap();
        assert!(
            as_of >= before.min(after).floor() && as_of <= before.max(after),
            "as_of {as_of} is not the server's clock"
        );
        // Freshness is the server's clock too: a day-old header time would have made these stale.
        let sources = ok(addr, "sources", READER_A, json!({}));
        assert!(
            sources["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["freshness"] == "fresh"),
            "freshness used another clock"
        );
        // The cursor the walk starts is stamped with that clock, so it is good for the next hour
        // and not for a day: a clock from the request would move that.
        let page = ok(addr, "devices", READER_A, json!({"limit": 1}));
        assert!(page["next_cursor"].is_string());
    });
}

#[test]
fn a_reader_revoked_or_expired_mid_walk_is_refused_on_the_next_page() {
    let w = world();
    let revoked = reader_a(&w);
    let expiring = ReaderStore::grant(
        &w.hub,
        READER_B,
        &GrantRequest {
            label: "short",
            sites: &[Site {
                org: ORG.into(),
                site: "site-a".into(),
            }],
            devices: DeviceGrant::All,
            sources: SourceGrant::All,
            ttl: 3600.0,
        },
    )
    .unwrap();
    serving(&w, |addr| {
        let unknown = read(addr, "devices", NEVER_GRANTED, &json!({"limit": 1}));
        assert_eq!(unknown.0, 401);
        let cursor = ok(addr, "devices", READER_A, json!({"limit": 1}))["next_cursor"].clone();
        let early = ok(addr, "devices", READER_B, json!({"limit": 1}))["next_cursor"].clone();
        ReaderStore::open(&w.db).unwrap().revoke(&revoked).unwrap();
        for request in [json!({"limit": 1, "cursor": cursor}), json!({"limit": 1})] {
            assert_eq!(read(addr, "devices", READER_A, &request), unknown);
        }
        // Expire the fixture after its first page; a sleep cannot guarantee expiry if the
        // wall clock steps backwards while the test is running.
        rusqlite::Connection::open(format!("{}.readers", w.db.display()))
            .unwrap()
            .execute("UPDATE readers SET expires=0 WHERE id=?", [&expiring])
            .unwrap();
        assert_eq!(
            read(
                addr,
                "devices",
                READER_B,
                &json!({"limit": 1, "cursor": early})
            ),
            unknown
        );
    });
}

fn raw_request(path: &str, headers: &str, body: &[u8], declared: usize) -> Vec<u8> {
    let mut wire = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Authorization: Bearer {READER_A}\r\nContent-Length: {declared}\r\n\r\n"
    )
    .into_bytes();
    wire.extend(body);
    wire
}
const JSON: &str = "Content-Type: application/json\r\n";

#[test]
fn oversized_and_malformed_requests_get_fixed_refusals_and_change_nothing() {
    let w = world();
    reader_a(&w);
    let before = std::fs::read(&w.db).unwrap();
    serving(&w, |addr| {
        let refused = |wire: Vec<u8>, code: u16, why: &str| {
            let answer = exchange(addr, &wire);
            assert_eq!(
                status(&answer),
                code,
                "{why}: {}",
                String::from_utf8_lossy(&answer)
            );
            let text = String::from_utf8_lossy(body(&answer)).to_string();
            assert!(
                text.len() < 200 && text.starts_with("{\"error\":"),
                "{why}: not a fixed body: {text}"
            );
            assert!(!text.contains(READER_A), "{why}: echoed the credential");
            text
        };
        // The request line.
        refused(
            wire(
                &format!("/v2/read/devices?{}", "a".repeat(2000)),
                READER_A,
                b"{}",
            ),
            413,
            "long request line",
        );
        // Headers: too many, one too long.
        let many: String = (0..40).map(|i| format!("X-Pad-{i}: x\r\n")).collect();
        refused(
            raw_request("/v2/read/devices", &format!("{JSON}{many}"), b"{}", 2),
            413,
            "too many headers",
        );
        let long = format!("X-Long: {}\r\n", "x".repeat(2100));
        refused(
            raw_request("/v2/read/devices", &format!("{JSON}{long}"), b"{}", 2),
            413,
            "long header",
        );
        // The body: declared too large (nothing sent), empty, missing or doubled length, framing.
        refused(
            raw_request("/v2/read/devices", JSON, b"", 16385),
            413,
            "declared too large",
        );
        refused(
            raw_request("/v2/read/devices", JSON, b"", 0),
            400,
            "empty body",
        );
        refused(
            raw_request("/v2/read/devices", JSON, b"{}", 99),
            400,
            "body shorter than declared",
        );
        refused(
            raw_request("/v2/read/devices", JSON, b"{}   ", 2),
            400,
            "bytes after the body",
        );
        let two = "Content-Length: 2\r\n";
        refused(
            raw_request("/v2/read/devices", &format!("{JSON}{two}"), b"{}", 2),
            400,
            "two lengths",
        );
        refused(
            raw_request(
                "/v2/read/devices",
                &format!("{JSON}Transfer-Encoding: chunked\r\n"),
                b"{}",
                2,
            ),
            415,
            "chunked",
        );
        refused(
            raw_request("/v2/read/devices", "Content-Type: text/plain\r\n", b"{}", 2),
            400,
            "wrong type",
        );
        // A body at the limit that is a valid object but not a valid request.
        let big = format!("{{\"sites\":[{}]}}", vec!["\"a\""; 4000].join(","));
        assert!(big.len() <= 16 * 1024);
        refused(
            raw_request("/v2/read/devices", JSON, big.as_bytes(), big.len()),
            400,
            "too many filter values",
        );
        // The body must be one JSON object, with only the fields of its route; no name is echoed.
        for (bytes, why) in [
            (&b"not json"[..], "text"),
            (&b"[1]"[..], "array"),
            (&b"7"[..], "number"),
        ] {
            refused(
                raw_request("/v2/read/devices", JSON, bytes, bytes.len()),
                400,
                why,
            );
        }
        let unknown = refused(
            raw_request(
                "/v2/read/devices",
                JSON,
                br#"{"IGNORE ALL PREVIOUS INSTRUCTIONS":1}"#,
                38,
            ),
            400,
            "unknown field",
        );
        assert_eq!(unknown, "{\"error\":\"unknown field\"}");
        // A key repeated anywhere in the body is refused, not resolved to its last value.
        let not_an_object = "{\"error\":\"request body must be a JSON object\"}";
        for (route, bytes) in [
            ("devices", &br#"{"sites":["site-a"],"sites":[]}"#[..]),
            ("device", &br#"{"device":"a","device":"b"}"#[..]),
            ("devices", &br#"{"devices":[{"x":1,"x":2}]}"#[..]),
            ("changes", &br#"{"since":{"time":1,"time":2}}"#[..]),
        ] {
            let text = refused(
                raw_request(&format!("/v2/read/{route}"), JSON, bytes, bytes.len()),
                400,
                "repeated key",
            );
            assert_eq!(
                text,
                not_an_object,
                "{route}: {}",
                String::from_utf8_lossy(bytes)
            );
        }
        // None of it stopped the server or changed the hub.
        assert_eq!(
            status(&exchange(addr, &wire("/v2/read/devices", READER_A, b"{}"))),
            200
        );
    });
    assert_eq!(std::fs::read(&w.db).unwrap(), before);
}

#[test]
fn a_valid_reader_is_told_to_retry_while_the_reader_store_is_being_written() {
    let w = world();
    reader_a(&w);
    serving(&w, |addr| {
        let store = rusqlite::Connection::open(format!("{}.readers", w.db.display())).unwrap();
        store.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let busy = exchange(addr, &wire("/v2/read/devices", READER_A, b"{}"));
        assert_eq!(status(&busy), 503, "{}", String::from_utf8_lossy(&busy));
        assert_eq!(
            String::from_utf8_lossy(body(&busy)),
            "{\"error\":\"storage unavailable; retry later\"}"
        );
        assert_eq!(header_of(&busy, "Retry-After").as_deref(), Some("5"));
        // The answer does not depend on the credential: a stranger learns nothing either way.
        let stranger = exchange(addr, &wire("/v2/read/devices", NEVER_GRANTED, b"{}"));
        assert_eq!(status(&stranger), 503);
        assert_eq!(body(&stranger), body(&busy));
        store.execute_batch("COMMIT").unwrap();
        assert_eq!(
            status(&exchange(addr, &wire("/v2/read/devices", READER_A, b"{}"))),
            200
        );
    });
}

#[test]
fn a_devices_walk_follows_its_cursor_over_http_to_the_last_page() {
    let w = world();
    standard_deliveries(&w);
    reader_a(&w);
    serving(&w, |addr| {
        let whole = ok(addr, "devices", READER_A, json!({}));
        let all = device_ids(&whole);
        assert!(all.len() >= 2);
        let first = ok(addr, "devices", READER_A, json!({"limit": 1}));
        let mut seen = device_ids(&first);
        let mut cursor = first["next_cursor"].clone();
        for _ in 0..1000 {
            if cursor.is_null() {
                break;
            }
            let next = cursor
                .as_str()
                .unwrap_or_else(|| panic!("next_cursor is neither a string nor null: {cursor}"));
            let page = ok(
                addr,
                "devices",
                READER_A,
                json!({"limit": 1, "cursor": next}),
            );
            seen.extend(device_ids(&page));
            cursor = page["next_cursor"].clone();
            assert!(
                seen.len() <= all.len(),
                "the walk does not advance: {seen:?}"
            );
        }
        assert!(
            cursor.is_null(),
            "the devices walk did not end within 1000 pages ({} rows); last cursor {cursor}",
            seen.len()
        );
        assert_eq!(seen, all);
    });
}

/// The value of a response header, when it is there exactly once.
fn header_of(response: &[u8], name: &str) -> Option<String> {
    let head = &response[..response
        .windows(4)
        .position(|p| p == b"\r\n\r\n")
        .unwrap_or(response.len())];
    let found: Vec<_> = String::from_utf8_lossy(head)
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(": "))
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.to_string())
        .collect();
    (found.len() == 1).then(|| found[0].clone())
}

#[test]
fn every_read_response_forbids_caching_and_sniffing() {
    let w = world();
    reader_a(&w);
    serving(&w, |addr| {
        let long = format!("/v2/read/devices?{}", "a".repeat(2000));
        let get = format!(
            "GET /v2/read/devices HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {READER_A}\r\n\r\n"
        );
        let requests: Vec<(&str, u16, Vec<u8>)> = vec![
            ("answer", 200, wire("/v2/read/devices", READER_A, b"{}")),
            (
                "detail",
                404,
                wire("/v2/read/device", READER_A, br#"{"device":"x"}"#),
            ),
            (
                "unknown reader",
                401,
                wire("/v2/read/devices", NEVER_GRANTED, b"{}"),
            ),
            ("bad body", 400, wire("/v2/read/devices", READER_A, b"nope")),
            (
                "unknown field",
                400,
                wire("/v2/read/devices", READER_A, br#"{"now":1}"#),
            ),
            (
                "no such route",
                404,
                wire("/v2/read/nothing", READER_A, b"{}"),
            ),
            ("wrong method", 405, get.into_bytes()),
            ("long request line", 413, wire(&long, READER_A, b"{}")),
            (
                "declared too large",
                413,
                raw_request("/v2/read/devices", JSON, b"", 16385),
            ),
        ];
        for (why, code, request) in &requests {
            let answer = exchange(addr, request);
            assert_eq!(status(&answer), *code, "{why}");
            assert_eq!(
                header_of(&answer, "Cache-Control").as_deref(),
                Some("no-store"),
                "{why}"
            );
            assert_eq!(
                header_of(&answer, "X-Content-Type-Options").as_deref(),
                Some("nosniff"),
                "{why}"
            );
            assert_eq!(
                header_of(&answer, "Content-Type").as_deref(),
                Some("application/json"),
                "{why}"
            );
        }
        // A request that never names /v2/ keeps the legacy answer, which carries neither header.
        let legacy = exchange(addr, b"POST /v1/other HTTP/1.1\r\n\r\n");
        assert_eq!(status(&legacy), 404);
        for name in ["Cache-Control", "X-Content-Type-Options"] {
            assert_eq!(header_of(&legacy, name), None, "{name}");
        }
    });
}

#[test]
fn an_answer_over_the_response_limit_is_a_fixed_500_not_a_large_response() {
    let w = world();
    reader_a(&w);
    let hub = Hub::open(&w.db).unwrap();
    let handle = |limit| vorda::fleet::http::handle_capped(&hub, "devices", READER_A, b"{}", limit);
    let answer = handle(vorda::fleet::http::MAX_RESPONSE).unwrap();
    assert!(answer.len() > 100 && answer.len() < vorda::fleet::http::MAX_RESPONSE);
    let at_limit = handle(answer.len()).unwrap();
    assert_eq!(at_limit.len(), answer.len(), "at the limit");
    let mut first: Value = serde_json::from_slice(&answer).unwrap();
    let mut second: Value = serde_json::from_slice(&at_limit).unwrap();
    // Separate requests carry their own clock, including when it steps backwards.
    first.as_object_mut().unwrap().remove("as_of");
    second.as_object_mut().unwrap().remove("as_of");
    assert_eq!(second, first, "the same answer fits at the limit");
    let over = handle(answer.len() - 1).unwrap_err();
    assert_eq!(
        (over.http_status, over.message.as_str()),
        (Some(500), "response_limit")
    );
    // The limit is checked after the reader is known: a stranger learns nothing about sizes.
    let stranger =
        vorda::fleet::http::handle_capped(&hub, "devices", NEVER_GRANTED, b"{}", 1).unwrap_err();
    assert_eq!(stranger.http_status, Some(401));
}

#[test]
fn a_failure_inside_the_hub_is_a_503_and_says_nothing_about_it() {
    let w = world();
    reader_a(&w);
    // A stored finding the hub cannot read back.
    rusqlite::Connection::open(&w.db)
        .unwrap()
        .execute("UPDATE findings SET payload=x'7b'", [])
        .unwrap();
    serving(&w, |addr| {
        let answer = exchange(addr, &wire("/v2/read/findings", READER_A, b"{}"));
        assert_eq!(status(&answer), 503, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            String::from_utf8_lossy(body(&answer)),
            "{\"error\":\"storage unavailable; retry later\"}"
        );
        assert_eq!(header_of(&answer, "Retry-After").as_deref(), Some("5"));
        assert_eq!(
            header_of(&answer, "Cache-Control").as_deref(),
            Some("no-store")
        );
    });
}

#[test]
fn a_slow_client_cannot_extend_the_deadline_or_block_the_next_reader() {
    let w = world();
    reader_a(&w);
    serving(&w, |addr| {
        // Headers complete, body promised and never sent.
        let started = Instant::now();
        let mut stalled = TcpStream::connect(addr).unwrap();
        stalled
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        stalled
            .write_all(&raw_request("/v2/read/devices", JSON, b"{", 50))
            .unwrap();
        let mut answer = vec![];
        let _ = stalled.read_to_end(&mut answer);
        assert!(
            started.elapsed() < Duration::from_millis(6500),
            "the stalled body held the server for {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() > Duration::from_secs(3),
            "the server gave up early: {:?}",
            started.elapsed()
        );
        // (Past its deadline the server closes without answering.)
        assert!(answer.is_empty() || status(&answer) == 400);

        // Headers trickled a byte at a time: the same total deadline, however long it is stretched.
        let started = Instant::now();
        let mut slow = TcpStream::connect(addr).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let wire = raw_request("/v2/read/devices", JSON, b"{}", 2);
        for byte in &wire {
            if slow.write_all(&[*byte]).is_err() || started.elapsed() > Duration::from_secs(9) {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        assert!(
            started.elapsed() < Duration::from_millis(6500),
            "a trickle held the server for {:?}",
            started.elapsed()
        );

        // And the next reader is served at once.
        let next = Instant::now();
        assert_eq!(status(&exchange(addr, &wire_for(READER_A))), 200);
        assert!(next.elapsed() < Duration::from_secs(2));
    });
}
fn wire_for(secret: &str) -> Vec<u8> {
    wire("/v2/read/devices", secret, b"{}")
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn no_reader_secret_appears_in_any_response_or_in_what_link_serve_prints() {
    let w = world();
    reader_a(&w);
    let wrong = "synthetic-wrong-reader-secret-0000000000";
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Child(
        std::process::Command::new(env!("CARGO_BIN_EXE_vorda"))
            .args([
                "link",
                "--db",
                w.db.to_str().unwrap(),
                "serve",
                "--port",
                &port.to_string(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut up = false;
    for _ in 0..100 {
        if TcpStream::connect(addr).is_ok() {
            up = true;
            thread::sleep(Duration::from_millis(150));
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(up, "link serve did not start");
    let mut responses = vec![];
    for (secret, route, request) in [
        (READER_A, "devices", json!({})),
        (READER_A, "findings", json!({"limit": 1})),
        (READER_A, "device", json!({"device": "nope"})),
        (READER_A, "devices", json!({"now": 1})),
        (wrong, "devices", json!({})),
    ] {
        responses.push(exchange(
            addr,
            &wire(
                &format!("/v2/read/{route}"),
                secret,
                request.to_string().as_bytes(),
            ),
        ));
    }
    // The served process answers reads with the headers too, not only the test harness.
    assert_eq!(status(&responses[0]), 200);
    assert_eq!(
        header_of(&responses[0], "Cache-Control").as_deref(),
        Some("no-store")
    );
    responses.push(exchange(
        addr,
        &wire("/v1/batches", READER_A, b"{\"schema\":1}"),
    ));
    let _ = child.0.kill();
    let mut output = String::new();
    if let Some(mut out) = child.0.stdout.take() {
        let _ = out.read_to_string(&mut output);
    }
    if let Some(mut err) = child.0.stderr.take() {
        let _ = err.read_to_string(&mut output);
    }
    for response in &responses {
        let text = String::from_utf8_lossy(response);
        assert!(
            !text.contains(READER_A) && !text.contains(wrong),
            "a response echoed a secret"
        );
    }
    assert!(
        !output.contains(READER_A) && !output.contains(wrong),
        "link serve printed a secret: {output}"
    );
}

#[test]
fn status_sources_and_inventory_answer_over_http_inside_the_grant_and_its_sources() {
    let w = world();
    standard_deliveries(&w);
    reader_a(&w);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    grant(&w, READER_WIDE, &["site-a", "site-b"], &[], 3600.0);
    serving(&w, |addr| {
        let status_view = ok(addr, "status", READER_A, json!({}));
        assert_eq!(status_view["devices"]["enrolled"], 2);
        assert_eq!(status_view["sources"]["total"], 3);
        assert_eq!(
            status_view["freshness_policy"]["fresh_for_seconds"],
            36 * 3600
        );
        let relaxed = ok(
            addr,
            "status",
            READER_A,
            json!({"fresh_for_seconds": 7 * 86400}),
        );
        assert_eq!(relaxed["freshness_policy"]["fresh_for_seconds"], 7 * 86400);
        let one = ok(addr, "status", READER_A, json!({"devices": [w.a2]}));
        assert_eq!(one["devices"]["enrolled"], 1);
        let wide = ok(addr, "status", READER_WIDE, json!({"sites": ["site-b"]}));
        assert_eq!(wide["devices"]["enrolled"], 1);
        for bad in [59, 91 * 86400] {
            assert_eq!(
                read(addr, "status", READER_A, &json!({"fresh_for_seconds": bad})).0,
                400
            );
        }
        assert_eq!(
            read(addr, "status", READER_A, &json!({"fresh_for_seconds": "9"})).0,
            400
        );

        // Sources, walked one page at a time.
        let mut seen = vec![];
        let mut cursor = Value::Null;
        for _ in 0..1000 {
            let page = ok(
                addr,
                "sources",
                READER_A,
                json!({"limit": 1, "cursor": cursor}),
            );
            seen.extend(
                page["sources"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| (s["device"].clone(), s["scope"].clone(), s["source"].clone())),
            );
            assert!(page["data_notice"].is_string());
            cursor = page["next_cursor"].clone();
            if cursor.is_null() {
                break;
            }
        }
        assert!(
            cursor.is_null(),
            "the sources walk did not end within 1000 pages ({} rows); last cursor {cursor}",
            seen.len()
        );
        assert_eq!(seen.len(), 3);

        let inventory = ok(
            addr,
            "inventory",
            READER_A,
            json!({"name": "samepackage", "ecosystem": "npm"}),
        );
        assert_eq!(inventory["total"], 3);
        assert!(inventory["inventory"][0]["package"]["name"]["quoted"] == "samepackage");
        for (field, miss) in [
            ("name", "other"),
            ("ecosystem", "pypi"),
            ("version", "9.9.9"),
        ] {
            let none = ok(addr, "inventory", READER_A, json!({ field: miss }));
            assert_eq!(none["total"], 0, "{field}");
        }
        let one_device = ok(addr, "inventory", READER_A, json!({"devices": [w.a2]}));
        assert_eq!(one_device["total"], 1);
        let one_source = ok(addr, "sources", READER_A, json!({"sources": ["pip-a"]}));
        assert_eq!(one_source["total"], 1);
        let stale = ok(addr, "sources", READER_A, json!({"freshness": "stale"}));
        assert_eq!(stale["total"], 0);
        let complete = ok(
            addr,
            "sources",
            READER_A,
            json!({"inventory_state": "complete"}),
        );
        assert_eq!(complete["total"], 3);
        let partial = ok(
            addr,
            "sources",
            READER_A,
            json!({"inventory_state": "partial"}),
        );
        assert_eq!(partial["total"], 0);
        // The freshness window the caller names is the one the answer applies and declares.
        for route in ["sources", "inventory"] {
            let weekly = ok(
                addr,
                route,
                READER_A,
                json!({"fresh_for_seconds": 7 * 86400}),
            );
            assert_eq!(weekly["freshness_policy"]["fresh_for_seconds"], 7 * 86400);
            let refused = read(addr, route, READER_A, &json!({"fresh_for_seconds": 59}));
            assert_eq!(refused.0, 400, "{route}");
        }
        let by_source =
            |source: &str| ok(addr, "inventory", READER_A, json!({"sources": [source]}));
        let (pip, npm) = (by_source("pip-a"), by_source("npm-a"));
        assert_eq!((&pip["total"], &npm["total"]), (&json!(1), &json!(2)));
        for (answer, source) in [(&pip, "pip-a"), (&npm, "npm-a")] {
            for row in answer["inventory"].as_array().unwrap() {
                assert_eq!(row["source"], source);
            }
        }
        for answer in [
            &status_view,
            &inventory,
            &ok(addr, "sources", READER_A, json!({})),
        ] {
            for hidden in [w.b1.as_str(), w.x1.as_str(), "site-b", "org-other"] {
                assert!(!answer.to_string().contains(hidden), "{hidden} leaked");
            }
        }
        // A listed source narrows every list, and a filter cannot name another.
        assert_eq!(ok(addr, "sources", READER_B, json!({}))["total"], 1);
        assert_eq!(ok(addr, "inventory", READER_B, json!({}))["total"], 1);
        assert_eq!(
            ok(addr, "sources", READER_B, json!({"sources": ["npm-a"]}))["total"],
            0
        );
        assert_eq!(
            ok(addr, "status", READER_B, json!({}))["sources"]["total"],
            1
        );
        for bad in [
            json!({"freshness": "soon"}),
            json!({"sources": [1]}),
            json!({"now": 1}),
        ] {
            assert_eq!(read(addr, "sources", READER_A, &bad).0, 400, "{bad}");
        }
        // Each list refuses the cursor of another.
        let first = ok(addr, "sources", READER_A, json!({"limit": 1}));
        let moved = read(
            addr,
            "inventory",
            READER_A,
            &json!({"limit": 1, "cursor": first["next_cursor"]}),
        );
        assert_eq!(moved.0, 400);
    });
}

fn four_assessments(w: &World, device: &str, org: &str, site: &str) {
    let t = vorda::store::now() - 3600.0;
    let d = Delivery {
        device,
        org,
        site,
        scope: "scope-1",
        source: "npm-a",
        observed: Some(t),
        inputs: &["one"],
    };
    let l2 = include_bytes!("fixtures/capture/L2.json");
    let l3 = include_bytes!("fixtures/capture/L3.json");
    for (n, lock) in [L1, &l2[..], &l3[..], L1].into_iter().enumerate() {
        w.deliver_lock(&d, n as i64 + 1, lock).unwrap();
    }
    // These walks assert chronological changes and since-windows, so give their fixture
    // explicit receipt order rather than depending on the host clock during delivery.
    rusqlite::Connection::open(&w.db)
        .unwrap()
        .execute(
            "UPDATE v2_assessments SET received=CAST(? + revision AS TEXT) WHERE json_extract(authority,'$[2]')=?",
            rusqlite::params![t, device],
        )
        .unwrap();
}

#[test]
fn an_evidence_reference_survives_a_newer_assessment_and_a_restart_and_opens_for_no_other_reader() {
    let w = world();
    let t = vorda::store::now() - 3600.0;
    fn on<'a>(device: &'a str, site: &'a str, t: f64) -> Delivery<'a> {
        Delivery {
            device,
            org: ORG,
            site,
            scope: "scope-1",
            source: "npm-a",
            observed: Some(t),
            inputs: &["one"],
        }
    }
    let l2 = include_bytes!("fixtures/capture/L2.json");
    let a1 = on(&w.a1, "site-a", t);
    let b1 = on(&w.b1, "site-b", t);
    w.deliver(&a1, 1).unwrap();
    w.deliver(&b1, 1).unwrap();
    // A second source on the same device, so a source-restricted reader sees a1 but not this
    // reference.
    let pip = Delivery {
        scope: "scope-2",
        source: "pip-a",
        ..on(&w.a1, "site-a", t)
    };
    w.deliver(&pip, 1).unwrap();
    reader_a(&w);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    grant(&w, READER_WIDE, &["site-b"], &[], 3600.0);

    let reference = serving(&w, |addr| {
        let inventory = ok(
            addr,
            "inventory",
            READER_A,
            json!({"devices": [w.a1], "sources": ["npm-a"]}),
        );
        let reference = inventory["inventory"][0]["evidence"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(reference.starts_with(&format!("{}/", w.a1)));
        reference
    });
    let before = serving(&w, |addr| {
        ok(addr, "evidence", READER_A, json!({"reference": reference}))
    });
    assert_eq!(before["evidence"]["assessment_revision"], 1);

    // A newer assessment arrives and the hub is served again on a fresh socket.
    w.deliver_lock(&a1, 2, &l2[..]).unwrap();
    serving(&w, |addr| {
        let now = ok(
            addr,
            "inventory",
            READER_A,
            json!({"devices": [w.a1], "sources": ["npm-a"]}),
        );
        assert_ne!(now["inventory"][0]["evidence"], reference.as_str());
        assert_eq!(
            ok(addr, "evidence", READER_A, json!({"reference": reference})),
            before,
            "the older reference still opens the older assessment"
        );
        // The reference of site A opens for no reader that does not cover it, and the answer is
        // the one given to a reference that names nothing.
        let missing = read(
            addr,
            "evidence",
            READER_A,
            &json!({"reference": "nothing/here"}),
        );
        assert_eq!(missing.0, 404);
        for other in [READER_B, READER_WIDE] {
            assert_eq!(
                read(addr, "evidence", other, &json!({"reference": reference})),
                missing,
                "{other}"
            );
        }
    });
}

/// Every object key in an answer, at any depth.
fn keys_of(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                out.push(k.clone());
                keys_of(v, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| keys_of(v, out)),
        _ => {}
    }
}

#[test]
fn no_reader_route_carries_a_deployment_or_running_claim_in_any_field() {
    let w = world();
    four_assessments(&w, &w.a1, ORG, "site-a");
    reader_a(&w);
    // Words that would claim a package is deployed, running, loaded or reachable in production.
    let claims = [
        "deploy",
        "running",
        "runtime",
        "in_use",
        "loaded",
        "active",
        "production",
        "reachab",
        "exploitab",
        "safe",
    ];
    serving(&w, |addr| {
        let first = ok(addr, "inventory", READER_A, json!({"devices": [w.a1]}));
        let reference = first["inventory"][0]["evidence"]
            .as_str()
            .unwrap()
            .to_string();
        let requests = [
            ("devices", json!({})),
            ("device", json!({"device": w.a1})),
            ("findings", json!({})),
            ("status", json!({})),
            ("sources", json!({})),
            ("inventory", json!({})),
            ("changes", json!({"since": "start"})),
            ("evidence", json!({"reference": reference})),
        ];
        for (route, request) in requests {
            let answer = ok(addr, route, READER_A, request);
            let mut keys = vec![];
            keys_of(&answer, &mut keys);
            // The answer is not empty, so an absent claim is not an empty answer.
            assert!(keys.len() > 5, "{route} answered almost nothing: {answer}");
            for key in &keys {
                for claim in claims {
                    assert!(
                        !key.to_lowercase().contains(claim),
                        "{route} carries the field {key}"
                    );
                }
            }
        }
        // The two routes that list findings and history have rows to carry a claim on.
        assert!(!ok(addr, "findings", READER_A, json!({}))["findings"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(
            !ok(addr, "changes", READER_A, json!({"since": "start"}))["changes"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn a_changes_walk_over_http_is_the_same_before_and_after_the_hub_gains_a_log() {
    let w = world();
    four_assessments(&w, &w.a1, ORG, "site-a");
    four_assessments(&w, &w.a2, ORG, "site-a");
    reader_a(&w);
    let walk = |w: &World| -> Vec<Value> {
        serving(w, |addr| {
            let mut pages: Vec<Value> = vec![];
            let mut request = json!({"since": "start", "limit": 4});
            loop {
                let mut page = ok(addr, "changes", READER_A, request.clone());
                // The clock of a walk, and so the bytes of its cursors, is all two walks may not
                // share; the fleet history tests compare cursors at a fixed clock.
                page.as_object_mut().unwrap().remove("as_of");
                let next = page["next_cursor"].clone();
                page["next_cursor"] = json!(!next.is_null());
                pages.push(page);
                if next.is_null() {
                    return pages;
                }
                request["cursor"] = next;
            }
        })
    };
    let before = walk(&w);
    assert!(before.len() > 2, "the walk spans pages");
    vorda::link::native::migrate_change_log(&w.db).unwrap();
    let after = walk(&w);
    let text = |pages: &[Value]| pages.iter().map(Value::to_string).collect::<Vec<_>>();
    assert_eq!(text(&before), text(&after));
}

#[test]
fn changes_and_evidence_answer_over_http_and_hide_what_the_grant_does_not_cover() {
    let w = world();
    four_assessments(&w, &w.a1, ORG, "site-a");
    four_assessments(&w, &w.b1, ORG, "site-b");
    // A second source at site A, so a source-restricted grant has something to be restricted to.
    let other = Delivery {
        device: &w.a2,
        org: ORG,
        site: "site-a",
        scope: "scope-2",
        source: "pip-a",
        observed: Some(vorda::store::now() - 60.0),
        inputs: &["one"],
    };
    w.deliver(&other, 1).unwrap();
    reader_a(&w);
    grant_sources(&w, READER_B, &["site-a"], &["pip-a"]);
    let db = rusqlite::Connection::open(&w.db).unwrap();
    let second: f64 = db
        .query_row(
            "SELECT CAST(received AS REAL) FROM v2_assessments WHERE revision=2 AND json_extract(authority,'$[2]')=?",
            [&w.a1],
            |r| r.get(0),
        )
        .unwrap();
    let b1_reference: String = db
        .query_row(
            "SELECT evidence FROM v2_assessments WHERE revision=1 AND json_extract(authority,'$[2]')=?",
            [&w.b1],
            |r| r.get(0),
        )
        .unwrap();
    serving(&w, |addr| {
        let all = ok(
            addr,
            "changes",
            READER_A,
            json!({"since": "start", "devices": [w.a1]}),
        );
        let kinds: Vec<_> = all["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            kinds,
            ["added", "changed", "resolved", "added", "resolved", "reopened"]
        );
        assert_eq!(all["changes"][1]["previous_version"]["quoted"], "1.0.0");
        assert_eq!(all["window"]["available"], 1);
        assert!(!all.to_string().contains(&w.b1));
        let cut = ok(
            addr,
            "changes",
            READER_A,
            json!({"since": {"time": second}, "devices": [w.a1]}),
        );
        assert_eq!(cut["total"], 4);
        let paged = ok(
            addr,
            "changes",
            READER_A,
            json!({"since": "start", "limit": 4, "devices": [w.a1]}),
        );
        assert_eq!(paged["page_end"], "limit");
        let cursor = paged["next_cursor"].clone();
        assert_eq!(
            ok(
                addr,
                "changes",
                READER_A,
                json!({"since": "start", "limit": 4, "devices": [w.a1], "cursor": cursor})
            )["page_end"],
            "last"
        );
        let narrowed = ok(
            addr,
            "changes",
            READER_A,
            json!({"since": "start", "sources": ["pip-a"]}),
        );
        assert_eq!(narrowed["total"], 1);
        // A window that has not begun, or no window at all, is a bad request.
        for bad in [
            json!({"since": {"time": 4_000_000_000.0}}),
            json!({"since": "yesterday"}),
            json!({"since": {"time": 1, "extra": 2}}),
            json!({}),
            json!({"since": {"time": "x"}}),
        ] {
            assert_eq!(read(addr, "changes", READER_A, &bad).0, 400, "{bad}");
        }
        assert_eq!(
            ok(
                addr,
                "changes",
                READER_B,
                json!({"since": "start", "devices": [w.a1]})
            )["total"],
            0,
            "a pip-a reader sees no npm-a history"
        );
        assert_eq!(
            ok(addr, "changes", READER_B, json!({"since": "start"}))["total"],
            1,
            "only the pip-a authority"
        );

        // Evidence by the reference the changes carry; anything else looks like nothing.
        let reference = all["changes"][0]["evidence"].as_str().unwrap().to_string();
        let detail = ok(addr, "evidence", READER_A, json!({"reference": reference}));
        assert_eq!(detail["evidence"]["device"], w.a1.as_str());
        assert_eq!(
            detail["evidence"]["records"][0]["package"]["name"]["quoted"],
            "samepackage"
        );
        let missing = read(
            addr,
            "evidence",
            READER_A,
            &json!({"reference": "nothing/here"}),
        );
        assert_eq!(missing.0, 404);
        for hidden in [format!("{}/{b1_reference}", w.b1), reference.clone()] {
            let who = if hidden == reference {
                READER_B
            } else {
                READER_A
            };
            assert_eq!(
                read(addr, "evidence", who, &json!({"reference": hidden})),
                missing,
                "{hidden}"
            );
        }
        for bad in [json!({"reference": 1}), json!({})] {
            assert_eq!(read(addr, "evidence", READER_A, &bad).0, 400, "{bad}");
        }
    });
}

/// Makes the stored finding `key` of `device` the package `(ecosystem, name, version)`.
fn shape_finding(w: &World, device: &str, key: &str, package: (&str, &str, &str)) {
    let changed = rusqlite::Connection::open(&w.db)
        .unwrap()
        .execute(
            "UPDATE findings SET payload=CAST(json_set(CAST(payload AS TEXT),'$.ecosystem',?,'$.name',?,'$.version',?) AS BLOB) WHERE device=? AND key=?",
            rusqlite::params![package.0, package.1, package.2, device, key],
        )
        .unwrap();
    assert_eq!(changed, 1, "SETUP: {device} holds {key}");
}
const READER_SOURCES: &str = "synthetic-reader-src-tests-only-00000";
const READER_ONE_DEVICE: &str = "synthetic-reader-one-tests-only-00000";

#[test]
fn a_finding_lists_its_granted_occurrences_with_v1_freshness_batch_coverage_and_matching_native_rows(
) {
    let w = world();
    standard_deliveries(&w);
    reader_a(&w);
    grant(&w, READER_WIDE, &["site-a", "site-b"], &[], 3600.0);
    // One key on a site-a and a site-b device; neither has native inventory.
    let s1 = enroll(&w.hub, ORG, "site-a", "s1", &["synthetic-shared"]);
    let s2 = enroll(&w.hub, ORG, "site-b", "s2", &["synthetic-shared"]);
    // The native inventory of a1 holds samepackage 1.0.0 (npm) under two sources, and a2 holds it too.
    shape_finding(&w, &w.a1, "finding-a1-x", ("npm", "samepackage", "1.0.0"));
    shape_finding(&w, &w.a1, "finding-a1-y", ("npm", "samepackage", "2.0.0"));
    shape_finding(&w, &w.a2, "finding-a2-x", ("PyPI", "samepackage", "1.0.0"));
    serving(&w, |addr| {
        let answer = ok(addr, "finding", READER_A, json!({"key": "finding-a1-x"}));
        assert_eq!(answer["key"], "finding-a1-x");
        assert_eq!(answer["occurrences_total"], 1);
        assert_eq!(answer["occurrences_truncated"], false);
        let occurrence = &answer["occurrences"][0];
        assert_eq!(occurrence["device"], w.a1.as_str());
        assert_eq!(occurrence["site"], "site-a");
        assert_eq!(occurrence["org"], ORG);
        assert_eq!(occurrence["name"]["quoted"], "samepackage");
        assert_eq!(occurrence["v1"]["freshness"], "fresh");
        assert!(occurrence["v1"]["received_at"].as_f64().unwrap() > 0.0);
        assert_eq!(occurrence["v1"]["basis"], "received_at");
        // The batch's own coverage for the finding's scope.
        assert_eq!(occurrence["coverage"]["scope"], "project-a");
        assert_eq!(occurrence["coverage"]["state"], "complete");
        // Both sources of a1 hold the package; a2's copy of it is another device's.
        let inventory = &occurrence["inventory"];
        assert_eq!(inventory["matches_total"], 2);
        let rows = inventory["matches"].as_array().unwrap();
        let mut sources: Vec<_> = rows
            .iter()
            .map(|r| r["source"].as_str().unwrap().to_string())
            .collect();
        sources.sort();
        assert_eq!(sources, ["npm-a", "pip-a"]);
        for row in rows {
            assert_eq!(row["device"], w.a1.as_str());
            assert_eq!(row["package"]["version"]["quoted"], "1.0.0");
            // Each row's evidence reference opens through `evidence`.
            let reference = row["evidence"].as_str().unwrap();
            let evidence = ok(addr, "evidence", READER_A, json!({"reference": reference}));
            assert_eq!(evidence["evidence"]["device"], w.a1.as_str());
        }

        // The join is on ecosystem, name and version: another version or ecosystem matches nothing.
        for (key, why) in [
            ("finding-a1-y", "another version"),
            ("finding-a2-x", "another ecosystem"),
        ] {
            let answer = ok(addr, "finding", READER_A, json!({"key": key}));
            assert_eq!(
                answer["occurrences"][0]["inventory"]["matches_total"], 0,
                "{why}"
            );
            assert_eq!(answer["occurrences"][0]["inventory"]["matches"], json!([]));
        }
        // A finding with no native inventory is still an occurrence, with no rows.
        let shared = ok(
            addr,
            "finding",
            READER_A,
            json!({"key": "synthetic-shared"}),
        );
        assert_eq!(shared["occurrences_total"], 1);
        assert_eq!(shared["occurrences"][0]["device"], s1.as_str());

        // The wider grant sees the same key on both sites, in device order.
        let wide = ok(
            addr,
            "finding",
            READER_WIDE,
            json!({"key": "synthetic-shared"}),
        );
        assert_eq!(wide["occurrences_total"], 2);
        let mut devices: Vec<_> = wide["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["device"].as_str().unwrap().to_string())
            .collect();
        let sorted = {
            let mut d = devices.clone();
            d.sort();
            d
        };
        assert_eq!(devices, sorted);
        devices.sort();
        let mut both = vec![s1.clone(), s2.clone()];
        both.sort();
        assert_eq!(devices, both);
        // The narrow reader's answer names nothing of the other site.
        assert!(!format!("{shared}").contains("site-b") && !format!("{shared}").contains(&s2));
    });
}

#[test]
fn a_finding_key_outside_the_grant_answers_exactly_like_a_missing_one_over_http() {
    let w = world();
    standard_deliveries(&w);
    reader_a(&w);
    grant_sources(&w, READER_SOURCES, &["site-a"], &["npm-a"]);
    grant(&w, READER_ONE_DEVICE, &["site-a"], &[w.a2.as_str()], 3600.0);
    serving(&w, |addr| {
        let missing = read(
            addr,
            "finding",
            READER_A,
            &json!({"key": "synthetic-no-such-key"}),
        );
        assert_eq!(missing.0, 404);
        assert_eq!(missing.1, json!({"error": "not found"}), "one fixed answer");
        let outside = [
            (READER_A, "finding-b1-x", "another site"),
            (READER_A, "finding-x1-x", "another organization"),
            (
                READER_ONE_DEVICE,
                "finding-a1-x",
                "another device of the site",
            ),
            (
                READER_SOURCES,
                "finding-a1-x",
                "a source-restricted grant sees no v1 evidence",
            ),
        ];
        for (reader, key, why) in outside {
            assert_eq!(
                read(addr, "finding", reader, &json!({"key": key})),
                missing,
                "{why}"
            );
        }
        // Inside the grant the same routes answer.
        assert_eq!(
            ok(addr, "finding", READER_A, json!({"key": "finding-a1-x"}))["occurrences_total"],
            1
        );
        assert_eq!(
            ok(
                addr,
                "finding",
                READER_ONE_DEVICE,
                json!({"key": "finding-a2-x"})
            )["occurrences_total"],
            1
        );
    });
}

#[test]
fn a_bad_or_oversize_finding_key_gets_a_fixed_400_that_does_not_echo_it() {
    let w = world();
    reader_a(&w);
    let long = "synthetic-long-".repeat(30);
    serving(&w, |addr| {
        let bad = [
            json!({}),
            json!({"key": null}),
            json!({"key": 1}),
            json!({"key": ["finding-a1-x"]}),
            json!({"key": ""}),
            json!({"key": long}),
            json!({"key": "finding-a1-x", "device": w.a1}),
        ];
        for body in bad {
            let (code, answer) = read(addr, "finding", READER_A, &body);
            assert_eq!(code, 400, "{body}");
            assert!(!answer.to_string().contains("synthetic-long"), "{body}");
        }
        // The longest accepted key is an ordinary miss, not a refusal.
        let edge = "k".repeat(256);
        assert_eq!(
            read(addr, "finding", READER_A, &json!({"key": edge})).0,
            404
        );
        // The body size limit of every read route applies.
        let huge = json!({"key": "k".repeat(20_000)});
        assert_eq!(read(addr, "finding", READER_A, &huge).0, 413);
    });
}
