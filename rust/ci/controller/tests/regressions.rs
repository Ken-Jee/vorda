use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    dir: PathBuf,
    proc_root: Option<String>,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vorda-controller-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let fixture = Self {
            dir,
            proc_root: None,
        };
        fs::create_dir_all(fixture.dir.join("source/rust/src/bin")).unwrap();
        fs::create_dir(fixture.dir.join("target")).unwrap();
        fs::create_dir(fixture.dir.join("source/rust/tests")).unwrap();
        fixture.write("source/.gitignore", "*.marker\n/rust/target\n");
        fixture.write(
            "source/rust/Cargo.toml",
            "[package]\nname = \"controller-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\n",
        );
        fixture.write(
            "source/rust/Cargo.lock",
            "version = 4\n\n[[package]]\nname = \"controller-fixture\"\nversion = \"0.1.0\"\n",
        );
        fixture.write("source/rust/src/bin/vorda.rs", "fn main() {}\n");
        fixture.write(
            "source/rust/src/lib.rs",
            "//! ```\n//! assert_eq!(1, 1);\n//! ```\n",
        );
        fixture.write(
            "source/rust/src/bin/ci_helper.rs",
            r#"
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args[1], "smoke");
    assert!(std::process::Command::new(&args[2]).status().unwrap().success());
    std::fs::write("smoke.marker", "executed").unwrap();
}
"#,
        );
        fixture.write(
            "source/rust/tests/execution.rs",
            r#"
#[test]
fn observable_test_execution() {
    std::fs::write("../test.marker", "executed").unwrap();
    assert!(std::env::var_os("VORDA_FIXTURE_FAIL").is_none());
}
"#,
        );
        assert!(Command::new("git")
            .args(["init", "-q"])
            .current_dir(fixture.dir.join("source"))
            .status()
            .unwrap()
            .success());
        fixture
    }

    fn write(&self, name: &str, contents: &str) {
        fs::write(self.dir.join(name), contents).unwrap();
    }

    fn invoke(&self, args: &[&str], fail: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vorda-ci-controller"));
        command
            .args(args)
            .env("VORDA_SOURCE_ROOT", self.dir.join("source"))
            .env("CARGO_TARGET_DIR", self.dir.join("target"))
            .env_remove("VORDA_FIXTURE_FAIL");
        if fail {
            command.env("VORDA_FIXTURE_FAIL", "1");
        }
        if let Some(root) = &self.proc_root {
            command.env("VORDA_CONTROLLER_PROC", root);
        }
        command.output().unwrap()
    }

    fn check(&self, seed: bool, fail: bool) -> Output {
        let result = self.dir.join("result.json");
        let mut args = vec!["ci", "--result-file", result.to_str().unwrap()];
        if seed {
            args.push("--compile-only");
        }
        self.invoke(&args, fail)
    }

    fn passed(&self, output: Output) -> Value {
        if !output.status.success() {
            for entry in fs::read_dir(self.dir.join("target/acceptance-v2")).unwrap() {
                let log = entry.unwrap().path().join("check.log");
                if let Ok(text) = fs::read_to_string(log) {
                    eprintln!("{text}");
                }
            }
        }
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&fs::read(self.dir.join("result.json")).unwrap()).unwrap()
    }

    fn no_success_receipts(&self) {
        assert!(!self.dir.join("result.json").exists());
        for entry in fs::read_dir(self.dir.join("target/acceptance-v2")).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert!(!path.join("last-check.json").exists());
                assert!(!path.join("last-seed.json").exists());
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[test]
fn seed_does_not_execute_and_warm_acceptance_always_does() {
    let f = Fixture::new();
    let seed = f.passed(f.check(true, false));
    assert_eq!(seed["status"], "compiled");
    assert_eq!(seed["tests_executed"], false);
    assert!(!f.dir.join("source/test.marker").exists());
    assert!(!f.dir.join("source/smoke.marker").exists());
    let ns = f
        .dir
        .join("target/acceptance-v2")
        .join(seed["namespace"].as_str().unwrap());
    assert!(!ns.join("last-check.json").exists());
    assert!(ns.join("last-seed.json").exists());
    for _ in 0..2 {
        let accepted = f.passed(f.check(false, false));
        assert_eq!(accepted["status"], "passed");
        assert_eq!(accepted["test_results_reused"], false);
        assert!(ns.join("last-check.json").exists());
        for marker in ["source/test.marker", "source/smoke.marker"] {
            assert_eq!(fs::read_to_string(f.dir.join(marker)).unwrap(), "executed");
            fs::remove_file(f.dir.join(marker)).unwrap();
        }
    }
}

#[test]
fn failed_seed_clears_previous_acceptance_and_requested_success() {
    let f = Fixture::new();
    let seed = f.passed(f.check(true, false));
    f.passed(f.check(false, false));
    let ns = f
        .dir
        .join("target/acceptance-v2")
        .join(seed["namespace"].as_str().unwrap());
    assert!(ns.join("last-seed.json").exists());
    assert!(ns.join("last-check.json").exists());
    f.write("source/rust/tests/execution.rs", "this cannot compile\n");
    assert!(!f.check(true, false).status.success());
    f.no_success_receipts();
}

#[test]
fn failing_executed_test_cannot_replay_success() {
    let f = Fixture::new();
    let accepted = f.passed(f.check(false, false));
    let ns = f
        .dir
        .join("target/acceptance-v2")
        .join(accepted["namespace"].as_str().unwrap());
    assert!(ns.join("last-check.json").exists());
    fs::remove_file(f.dir.join("source/smoke.marker")).unwrap();
    assert!(!f.check(false, true).status.success());
    f.no_success_receipts();
    assert!(!f.dir.join("source/smoke.marker").exists());
}

#[test]
fn failing_doctest_fails_acceptance() {
    let f = Fixture::new();
    f.write(
        "source/rust/src/lib.rs",
        "//! ```\n//! assert_eq!(1, 2);\n//! ```\n",
    );
    assert!(!f.check(false, false).status.success());
    f.no_success_receipts();
}

/// Test source that leaves a long sleeper behind and records its pid, then ends with `ending`.
fn straggler_source(ending: &str) -> String {
    format!(
        r#"
fn leave_straggler(file: &str) {{
    let child = std::process::Command::new("sleep")
        .arg("600")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::fs::write(file, child.id().to_string()).unwrap();
}}
{ending}
"#
    )
}

fn alive(pid: i32) -> bool {
    // A zombie still answers kill(pid, 0); only a running process counts as a straggler.
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => !stat
            .rsplit(')')
            .next()
            .unwrap()
            .trim_start()
            .starts_with('Z'),
        Err(_) => false,
    }
}

/// Reads the pid a fixture left behind and gives the controller a bounded time to have reaped it.
fn straggler_gone(f: &Fixture, file: &str) {
    let pid: i32 = fs::read_to_string(f.dir.join(file))
        .expect("the fixture never left a straggler, so this test would prove nothing")
        .parse()
        .unwrap();
    for _ in 0..50 {
        if !alive(pid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    panic!("process {pid} left by the failed command survived the controller");
}

// nextest puts every test in its own process group, so `stop` must signal every group of the
// session, not only the group of the process it spawned.
#[test]
fn a_process_left_by_a_failing_test_does_not_outlive_the_controller() {
    let f = Fixture::new();
    f.write(
        "source/rust/tests/execution.rs",
        &straggler_source(
            r#"
#[test]
fn leaves_a_process_and_fails() {
    leave_straggler("../test-straggler.marker");
    panic!("deliberate failure");
}
"#,
        ),
    );
    let output = f.check(false, false);
    assert!(!output.status.success());
    f.no_success_receipts();
    straggler_gone(&f, "source/test-straggler.marker");
}

#[test]
fn a_process_left_by_a_failing_smoke_command_does_not_outlive_the_controller() {
    let f = Fixture::new();
    f.write(
        "source/rust/src/bin/vorda.rs",
        &straggler_source(
            r#"
fn main() {
    leave_straggler("smoke-straggler.marker");
    std::process::exit(3);
}
"#,
        ),
    );
    let output = f.check(false, false);
    assert!(!output.status.success());
    f.no_success_receipts();
    straggler_gone(&f, "source/smoke-straggler.marker");
}

#[test]
fn without_proc_a_process_ignoring_term_is_still_killed_after_the_grace_period() {
    let mut f = Fixture::new();
    // /proc cannot be listed, so only the spawned command's own group can be stopped.
    f.proc_root = Some("/nonexistent-proc".into());
    f.write(
        "source/rust/src/bin/vorda.rs",
        r#"
fn main() {
    let child = std::process::Command::new("sh")
        .args(["-c", "trap '' TERM; sleep 600"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::fs::write("term-ignoring.marker", child.id().to_string()).unwrap();
    std::process::exit(3);
}
"#,
    );
    let output = f.check(false, false);
    assert!(!output.status.success());
    f.no_success_receipts();
    straggler_gone(&f, "source/term-ignoring.marker");
}

/// A test that deletes `victim` (relative to the active namespace) and keeps running long
/// enough for the controller's periodic accounting to notice, then passes.
fn deleting_source(victim: &str) -> String {
    format!(
        r#"
#[test]
fn deletes_a_cache_file_then_passes() {{
    let target = std::path::PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap());
    std::fs::remove_file(target.parent().unwrap().join("{victim}")).unwrap();
    std::fs::write("../deleted.marker", "deleted").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(5));
}}
"#
    )
}

#[test]
fn a_cache_file_deleted_mid_run_does_not_yield_success() {
    for victim in ["owner.json", "check.log"] {
        let f = Fixture::new();
        f.write("source/rust/tests/execution.rs", &deleting_source(victim));
        let output = f.check(false, false);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // The marker proves the deletion happened, so the failure below is the controller's.
        assert!(f.dir.join("source/deleted.marker").exists());
        assert!(
            !output.status.success(),
            "deleting {victim} still succeeded: {stdout}"
        );
        assert!(
            stdout.contains(r#""status":"failed""#) && stdout.contains("No such file"),
            "unexpected failure for {victim}: {stdout}"
        );
        f.no_success_receipts();
    }
}

#[test]
fn invalid_arguments_invalidate_every_supplied_result_destination() {
    let f = Fixture::new();
    let first = f.dir.join("first.json");
    let second = f.dir.join("second.json");
    let a = first.to_str().unwrap();
    let b = second.to_str().unwrap();
    for args in [
        vec!["invalid", "--result-file", a],
        vec!["ci", "--unknown", "--result-file", a],
        vec!["ci", "--result-file", a, "--result-file", b],
        vec!["ci", "--result-file", a, "--result-file"],
    ] {
        f.write("first.json", r#"{"status":"passed"}"#);
        f.write("second.json", r#"{"status":"passed"}"#);
        assert!(!f.invoke(&args, false).status.success());
        assert!(!first.exists());
        if args.contains(&b) {
            assert!(!second.exists());
        }
    }
}
