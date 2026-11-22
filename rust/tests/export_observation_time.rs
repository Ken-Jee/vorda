//! m6s5: the version 1 export takes its observation time from the scan result itself
//! (`inventory_observed_at`), never from the result file's modification time.
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vorda::link::client::Outbox;

const DAY: f64 = 86400.0;
const NO_TIME: &str = "this result has no observation time; scan again";

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

struct Lane {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    outbox: PathBuf,
}
impl Lane {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let outbox = dir.join("outbox.db");
        Outbox::open(&outbox)
            .unwrap()
            .bind("test-device", "g-1")
            .unwrap();
        Lane {
            _tmp: tmp,
            dir,
            outbox,
        }
    }
    /// A complete scan result whose `inventory_observed_at` is `observed` (JSON null when `None`, absent when `Absent`).
    fn result(&self, name: &str, observed: Observed) -> PathBuf {
        let mut result = json!({
            "scan_scope": "s",
            "findings": [],
            "status": "no-known-findings",
            "coverage_evidence": {"status": "complete"},
        });
        match observed {
            Observed::At(t) => result["inventory_observed_at"] = json!(t),
            Observed::Null => result["inventory_observed_at"] = Value::Null,
            Observed::Absent => {}
        }
        let path = self.dir.join(name);
        fs::write(&path, result.to_string()).unwrap();
        path
    }
    fn link(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vorda"))
            .args(["link", "--db", self.outbox.to_str().unwrap()])
            .args(args)
            .output()
            .unwrap()
    }
    fn run(&self, action: &str, result: &Path) -> Output {
        self.link(&[action, "--result", result.to_str().unwrap(), "--consent"])
    }
    fn queued(&self) -> i64 {
        Connection::open(&self.outbox)
            .unwrap()
            .query_row("SELECT count(*) FROM pending", [], |r| r.get(0))
            .unwrap()
    }
    fn sequence(&self) -> i64 {
        Outbox::open(&self.outbox)
            .unwrap()
            .identity()
            .unwrap()
            .unwrap()["sequence"]
            .as_i64()
            .unwrap()
    }
    fn oldest_age(&self) -> f64 {
        let health = self.link(&["health"]);
        assert!(health.status.success());
        serde_json::from_slice::<Value>(&health.stdout).unwrap()["oldest_age"]
            .as_f64()
            .unwrap()
    }
}
#[derive(Clone, Copy)]
enum Observed {
    At(f64),
    Null,
    Absent,
}

fn set_mtime(path: &Path, at: SystemTime) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(at)
        .unwrap();
}
fn stdout_json(out: &Output) -> Value {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn a_touched_or_copied_result_keeps_the_scans_own_time() {
    let lane = Lane::new();
    let scanned = now() - 3.0 * DAY;
    let original = lane.result("last-scan.json", Observed::At(scanned));
    // The file is touched (mtime = now) and also copied to a fresh file: both look brand new on disk.
    set_mtime(&original, SystemTime::now());
    let copy = lane.dir.join("copy.json");
    fs::copy(&original, &copy).unwrap();
    assert!(
        copy.metadata().unwrap().modified().unwrap() + Duration::from_secs(60) > SystemTime::now()
    );

    for file in [&original, &copy] {
        let exported = stdout_json(&lane.run("export", file));
        assert_eq!(exported["observed"].as_f64().unwrap(), scanned);
    }

    // Queued and read back from the outbox, the batch is three days old: stale, not fresh.
    assert!(lane.run("queue", &copy).status.success());
    assert_eq!(lane.queued(), 1);
    let age = lane.oldest_age();
    assert!(
        (3.0 * DAY..3.0 * DAY + 600.0).contains(&age),
        "oldest_age {age}"
    );
}

#[test]
fn an_old_file_holding_a_new_scan_is_not_stale() {
    let lane = Lane::new();
    let scanned = now() - 5.0;
    let result = lane.result("last-scan.json", Observed::At(scanned));
    set_mtime(&result, UNIX_EPOCH + Duration::from_secs(86400));
    let exported = stdout_json(&lane.run("export", &result));
    assert_eq!(exported["observed"].as_f64().unwrap(), scanned);
}

#[test]
fn a_result_without_an_observation_time_is_refused_and_queues_nothing() {
    let lane = Lane::new();
    for (name, observed) in [
        ("absent.json", Observed::Absent),
        ("null.json", Observed::Null),
        ("zero.json", Observed::At(0.0)),
        ("negative.json", Observed::At(-5.0)),
    ] {
        let result = lane.result(name, observed);
        set_mtime(&result, SystemTime::now());
        for action in ["export", "queue"] {
            let out = lane.run(action, &result);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !out.status.success() && stderr.contains(NO_TIME),
                "{name} {action}: {stderr}"
            );
            let error: Value = serde_json::from_str(stderr.trim()).unwrap_or_else(|_| {
                panic!("{name} {action}: stderr is not one JSON error: {stderr}")
            });
            assert_eq!(error["error"], NO_TIME, "{name} {action}");
            assert!(out.stdout.is_empty(), "{name} {action} printed a batch");
        }
        assert_eq!(lane.queued(), 0, "{name}");
        assert_eq!(
            lane.sequence(),
            0,
            "{name}: a refusal must not consume a sequence"
        );
    }
}

#[test]
fn a_non_numeric_observation_time_is_refused() {
    let lane = Lane::new();
    let result = lane.result("text.json", Observed::Absent);
    let mut doc: Value = serde_json::from_slice(&fs::read(&result).unwrap()).unwrap();
    doc["inventory_observed_at"] = json!("1793700000");
    fs::write(&result, doc.to_string()).unwrap();
    let out = lane.run("queue", &result);
    assert!(
        !out.status.success() && String::from_utf8_lossy(&out.stderr).contains(NO_TIME),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(lane.queued(), 0);
}

#[test]
fn a_far_future_observation_time_is_refused_at_export() {
    let lane = Lane::new();
    let result = lane.result("future.json", Observed::At(now() + 3600.0));
    for action in ["export", "queue"] {
        let out = lane.run(action, &result);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("in the future"),
            "{action}: {stderr}"
        );
        assert!(out.stdout.is_empty());
    }
    assert_eq!(lane.queued(), 0);
    assert_eq!(lane.sequence(), 0);
    // Within the five minute allowance the time is kept as given.
    let near = now() + 60.0;
    let result = lane.result("near.json", Observed::At(near));
    assert_eq!(
        stdout_json(&lane.run("export", &result))["observed"]
            .as_f64()
            .unwrap(),
        near
    );
}

#[test]
fn a_real_scan_result_carries_its_own_time_into_the_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("requirements.txt"), "example==1.2.3\n").unwrap();
    let state = tmp.path().join("state");
    let before = now();
    // An offline scan cannot reach advisory feeds, so its exit status is not the point; it still saves a result.
    Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&state)
        .args(["scan", "--json", "--offline", "--root"])
        .arg(&project)
        .output()
        .unwrap();
    let saved = state.join("last-scan.json");
    let scan: Value = serde_json::from_slice(&fs::read(&saved).unwrap()).unwrap();
    let observed = scan["inventory_observed_at"]
        .as_f64()
        .expect("a normal scan records when its inventory was observed");
    assert!(observed >= before - 1.0 && observed <= now() + 1.0);

    // Making the saved file look three days old does not make the scan old, and vice versa.
    set_mtime(&saved, SystemTime::now() - Duration::from_secs(3 * 86400));
    let lane = Lane::new();
    assert_eq!(
        stdout_json(&lane.run("export", &saved))["observed"]
            .as_f64()
            .unwrap(),
        observed
    );
    assert!(lane.run("queue", &saved).status.success());
    assert!(lane.oldest_age() < 600.0);
}
