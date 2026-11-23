#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{fs, path::Path, process::Command};

#[test]
fn watch_records_advisory_choice_and_warns_before_offline_schedules_age_out() {
    if [
        "/usr/local/bin/launchctl",
        "/usr/bin/launchctl",
        "/bin/launchctl",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("state");
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let run = |flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(&state)
            .args(["watch", "install", "--backend", "launchd", "--root"])
            .arg(temp.path())
            .args(flags)
            .env("HOME", &home)
            .env_remove("VORDA_ADVISORIES")
            .env("VORDA_ADVISORY_DB_DIR", temp.path().join("db"))
            .output()
            .unwrap()
    };
    for (flags, mode) in [
        (vec![], "offline-db"),
        (vec!["--online"], "online"),
        (vec!["--offline-db"], "offline-db"),
    ] {
        let output = run(&flags);
        assert_eq!(
            output.status.code(),
            Some(2),
            "launchctl is absent: {output:?}"
        );
        let job: Value =
            plist::from_file(home.join("Library/LaunchAgents/dev.vorda.hourly.plist")).unwrap();
        let argv = job["ProgramArguments"].as_array().unwrap();
        assert!(argv.contains(&Value::from(format!("--{mode}"))), "{job}");
        assert!(argv.contains(&Value::from("--scheduled")), "{job}");
    }
    assert_eq!(run(&["--online", "--offline-db"]).status.code(), Some(64));
    let status = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(&state)
        .args(["watch", "status", "--online", "--offline-db"])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(64), "{status:?}");
    let help = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args(["watch", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout)
        .unwrap()
        .contains("vorda db update"));
}

#[test]
fn watch_scans_the_machine_unless_a_root_is_named() {
    if Path::new("/usr/bin/launchctl").exists() || Path::new("/bin/launchctl").exists() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir(&home).unwrap();
    let roots = |flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_vorda"))
            .arg("--state")
            .arg(temp.path().join("state"))
            .args(["watch", "install", "--backend", "launchd", "--online"])
            .args(flags)
            .env("HOME", &home)
            .output()
            .unwrap();
        let job: Value =
            plist::from_file(home.join("Library/LaunchAgents/dev.vorda.hourly.plist")).unwrap();
        let argv: Vec<_> = job["ProgramArguments"].as_array().unwrap().clone();
        argv.windows(2)
            .filter(|w| w[0] == "--root")
            .map(|w| w[1].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let project = temp.path().to_str().unwrap();
    assert!(roots(&[]).is_empty());
    assert_eq!(roots(&["--root", project]).len(), 1);
    assert!(roots(&["--machine"]).is_empty());
    let both = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(temp.path().join("state"))
        .args([
            "watch",
            "install",
            "--backend",
            "launchd",
            "--machine",
            "--root",
            project,
        ])
        .env("HOME", &home)
        .output()
        .unwrap();
    assert_eq!(both.status.code(), Some(64), "{both:?}");
}
