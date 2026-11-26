use serde_json::Value;
use std::process::{Command, Stdio};

#[test]
fn scheduled_missing_database_saves_and_delivers_unknown_health() {
    use std::io::{Read, Write};
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let webhook = format!("http://{}/hook", server.local_addr().unwrap());
    let receiver = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            match server.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                    }
                    let headers = String::from_utf8(request).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    return serde_json::from_slice::<Value>(&body).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "scheduled health was not delivered"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let state = temp.path().join("state");
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&state)
        .args(["check", "--scheduled", "--json", "--root"])
        .arg(temp.path())
        .args(["--webhook", &webhook])
        .env_remove("VORDA_ADVISORIES")
        .env("VORDA_ADVISORY_DB_DIR", temp.path().join("db"))
        .env("CI", "true")
        .env("NO_PROXY", "127.0.0.1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["advisory_source"], "offline-db");
    assert!(!result["errors"].as_array().unwrap().is_empty());
    let delivered = receiver.join().unwrap();
    assert!(delivered.to_string().contains("health"), "{delivered}");
    let store = vorda::store::Store::open(&state).unwrap();
    assert!(store
        .active()
        .unwrap()
        .iter()
        .any(|f| f["kind"] == "health"));
    let saved: i64 = store
        .db
        .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))
        .unwrap();
    assert!(saved > 0);
}

#[test]
fn missing_database_never_uses_network_or_waits_for_piped_input() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
    for args in [vec!["scan"], vec!["check"], vec!["scan", "--offline-db"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .args(["--state"])
            .arg(temp.path().join("state"))
            .args(args)
            .arg("--root")
            .arg(temp.path())
            .arg("--json")
            .env_remove("VORDA_ADVISORIES")
            .env("VORDA_ADVISORY_DB_DIR", temp.path().join("db"))
            .env("CI", "true")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["status"], "unknown");
        assert!(error["error"].as_str().unwrap().contains("vorda db update"));
    }
}

#[cfg(unix)]
#[test]
fn terminal_setup_explains_coverage_and_allows_cancel_or_online_once() {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    for (choice, piped) in [("\n", false), ("2\n", false), ("\n", true)] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("requirements.txt"), "example==1.2.3\n").unwrap();
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        master.write_all(choice.as_bytes()).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(temp.path().join("state"))
            .args(["scan", "--root"])
            .arg(temp.path())
            .env_remove("CI")
            .env_remove("GITHUB_ACTIONS")
            .env_remove("VORDA_ADVISORIES")
            .env("VORDA_ADVISORY_DB_DIR", temp.path().join("db"))
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .stdin(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap())
            .stdout(if piped {
                Stdio::piped()
            } else {
                slave.try_clone().unwrap().into()
            })
            .spawn()
            .unwrap();
        drop(slave);
        let mut bytes = Vec::new();
        let _ = master.read_to_end(&mut bytes);
        assert_eq!(child.wait().unwrap().code(), Some(2));
        let text = String::from_utf8_lossy(&bytes);
        if piped {
            assert!(text.contains("cannot prompt"), "{text}");
            assert!(!text.contains("Select [1]"), "{text}");
            continue;
        }
        for fact in [
            "80 seconds",
            "npm",
            "PyPI",
            "crates.io",
            "Go",
            "unknown",
            "--online",
            "--offline-db",
            "package names never leave",
        ] {
            assert!(text.contains(fact), "{fact}: {text}");
        }
        if choice == "\n" {
            // Cancel is the person's choice, said on its own line, not an error object.
            assert!(text.contains("\nCancelled; no scan was run"), "{text}");
            assert!(!text.contains("\"error\""), "{text}");
        } else {
            assert!(!text.contains("no scan was run"), "{text}");
        }
        assert!(!temp.path().join("db").exists());
    }
}

#[test]
fn action_without_database_reports_unknown_even_when_fail_on_findings_is_false() {
    // The advisories input wins over VORDA_ADVISORIES, so offline-db never goes online.
    for (input, env) in [("", None), ("offline-db", Some("online"))] {
        let temp = tempfile::tempdir().unwrap();
        let (sarif, outputs) = (temp.path().join("scan.sarif"), temp.path().join("output"));
        std::fs::write(&outputs, "").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
        command
            .arg("action-scan")
            .env_remove("VORDA_ADVISORIES")
            .env("VORDA_ADVISORY_INPUT", input)
            .env("VORDA_ADVISORY_DB_DIR", temp.path().join("db"))
            .env("VORDA_SARIF", &sarif)
            .env("GITHUB_OUTPUT", &outputs)
            .env("VORDA_PATH", temp.path())
            .env("VORDA_FAIL", "false")
            .stdin(Stdio::null());
        if let Some(value) = env {
            command.env("VORDA_ADVISORIES", value);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["status"], "unknown");
        assert_eq!(
            std::fs::read_to_string(&outputs).unwrap(),
            "status=unknown\nfindings=0\ncoverage=partial\nnot-assessed=0\n"
        );
        let report: Value = serde_json::from_slice(&std::fs::read(&sarif).unwrap()).unwrap();
        assert_eq!(report["runs"][0]["results"], serde_json::json!([]));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("::error title=vorda::") && stdout.contains("advisories: online"),
            "{stdout}"
        );
    }
}
