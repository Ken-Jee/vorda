use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use vorda::delivery::{deliver, Options};

/// Serves one request and returns the body the client sent.
fn one_request() -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/topic", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        let body = loop {
            let n = conn.read(&mut chunk).unwrap();
            raw.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&raw).to_string();
            if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                let want: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                if rest.len() >= want {
                    break rest[..want].to_string();
                }
            }
            assert!(n > 0, "client closed before the body arrived");
        };
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        body
    });
    (url, handle)
}

fn ntfy_body(titles: &[&str]) -> String {
    let (url, server) = one_request();
    let messages: Vec<_> = titles.iter().map(|t| json!({"title": t})).collect();
    deliver(
        &messages,
        &Options {
            ntfy: Some(url),
            ..Default::default()
        },
    )
    .unwrap();
    server.join().unwrap()
}

#[test]
fn each_alert_is_one_line_in_the_ntfy_body() {
    let body = ntfy_body(&[
        "synthetic-alpha",
        "synthetic-beta\nsplit\r\nacross\rlines",
        "synthetic\u{2028}line\u{2029}para\u{85}next\ttab\u{7}bell",
        "synthetic-omega",
    ]);
    assert_eq!(body.lines().count(), 4, "{body:?}");
    assert!(
        !body.chars().any(|c| c.is_control() && c != '\n'),
        "{body:?}"
    );
    assert!(!body.contains(['\u{2028}', '\u{2029}', '\r']), "{body:?}");
    let lines: Vec<_> = body.lines().collect();
    assert_eq!(lines[0], "synthetic-alpha");
    assert_eq!(lines[3], "synthetic-omega");
    // Each control character becomes one space, so `\r\n` becomes two.
    assert_eq!(lines[1], "synthetic-beta split  across lines");
}

#[test]
fn plain_titles_are_sent_unchanged() {
    assert_eq!(
        ntfy_body(&["synthetic-one", "synthetic two"]),
        "synthetic-one\nsynthetic two"
    );
}
