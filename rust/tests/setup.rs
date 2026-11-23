use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const DEAD: &str = "http://127.0.0.1:9";

/// A home with one project, every network route dead, and no advisory choice anywhere.
fn vorda(home: &Path, args: &[&str]) -> Command {
    std::fs::create_dir_all(home.join("code/app")).unwrap();
    std::fs::write(home.join("code/app/requirements.txt"), "example==1.2.3\n").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_vorda"));
    command
        .arg("--state")
        .arg(home.join("state"))
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("VORDA_ADVISORY_DB_DIR", home.join("db"))
        .env_remove("VORDA_ADVISORIES")
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
    ] {
        command.env(var, DEAD);
    }
    command
}

fn saved(home: &Path) -> Value {
    let config = std::fs::read(home.join("state/config.json")).unwrap();
    serde_json::from_slice::<Value>(&config).unwrap()["advisories"].clone()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn setup_saves_the_choice_then_scans_the_machine() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let output = vorda(home, &["setup"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{}", text(&output));
    assert!(text(&output).contains("--offline-db"), "{}", text(&output));
    assert!(!home.join("state/config.json").exists());

    // Offline: the choice is kept even when the download fails, and no scan runs.
    let output = vorda(home, &["setup", "--offline-db", "--no-watch"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(
        text(&output).contains("vorda db update"),
        "{}",
        text(&output)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("vorda dashboard"));
    assert_eq!(saved(home), "offline-db");

    // Online replaces it, keeps other settings, and the scan is of the whole machine.
    let config = home.join("state/config.json");
    std::fs::write(&config, r#"{"advisories":"offline-db","tools":true}"#).unwrap();
    let output = vorda(home, &["setup", "--online", "--no-watch"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert_eq!(saved(home), "online");
    let config: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    assert_eq!(config["tools"], true);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vorda dashboard"), "{stdout}");

    for args in [
        &["setup", "--online", "--offline-db"][..],
        &["setup", "--watch", "--no-watch"],
        &["setup", "--json"],
    ] {
        let output = vorda(home, args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(64),
            "{args:?}: {}",
            text(&output)
        );
    }
}

#[test]
fn bare_vorda_prints_help_unless_a_person_has_not_chosen_yet() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let output = vorda(home, &[]).stdin(Stdio::null()).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("Usage: vorda"));
    assert!(!home.join("state/config.json").exists());
    #[cfg(unix)]
    {
        // First run in a terminal: choose online, decline the watch, and the scan runs.
        let (code, shown) = terminal(vorda(home, &[]), "2\n\n");
        assert_eq!(code, Some(2), "{shown}");
        assert_eq!(saved(home), "online");
        assert!(shown.contains("vorda dashboard"), "{shown}");
        assert!(!home.join("state/watch.json").exists());
        // Once chosen, bare vorda in a terminal is help again.
        let (code, shown) = terminal(vorda(home, &[]), "");
        assert_eq!(code, Some(0), "{shown}");
        assert!(shown.contains("Usage: vorda"), "{shown}");
    }
}

/// Run `command` on a fresh pseudo-terminal fed `input`; returns the exit code and what it showed.
#[cfg(unix)]
fn terminal(mut command: Command, input: &str) -> (Option<i32>, String) {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
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
    master.write_all(input.as_bytes()).unwrap();
    let mut child = command
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .stdin(slave.try_clone().unwrap())
        .stderr(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .spawn()
        .unwrap();
    // The command keeps its copies of the terminal open; only dropping both lets the read end.
    drop(command);
    drop(slave);
    let mut bytes = Vec::new();
    let _ = master.read_to_end(&mut bytes);
    let code = child.wait().unwrap().code();
    (code, String::from_utf8_lossy(&bytes).into_owned())
}
