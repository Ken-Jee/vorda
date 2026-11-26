use crate::repair::commands::*;
use crate::{store::atomic, Error, Result};
use serde_json::{json, Value};
use std::{fs, path::Path};
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}
fn join(args: &[String]) -> String {
    args.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" ")
}

fn systemctl(args: &[&str], checked: bool) -> Result<String> {
    let mut command = strings(&["/usr/bin/env"]);
    #[cfg(target_os = "linux")]
    {
        let expected = format!("/run/user/{}", unsafe { libc::geteuid() });
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok();
        let bus_address = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
        command.extend(
            user_bus_environment(
                Path::new(&expected),
                runtime_dir.as_deref(),
                bus_address.as_deref(),
            )
            .into_iter()
            .flatten(),
        );
    }
    command.extend(strings(&["/usr/bin/systemctl", "--user"]));
    command.extend(strings(args));
    execute(&command, None, None, checked)
}

#[cfg(target_os = "linux")]
fn user_bus_environment(
    expected: &Path,
    runtime_dir: Option<&str>,
    bus_address: Option<&str>,
) -> Option<[String; 2]> {
    use std::{ffi::OsStr, path::Component};

    let runtime_dir = runtime_dir?;
    let bus_address = bus_address?;
    if expected.as_os_str() != OsStr::new(runtime_dir) {
        return None;
    }
    let path = bus_address.strip_prefix("unix:path=")?;
    if path.contains(['%', ',', ';', '\0']) {
        return None;
    }
    let path = Path::new(path);
    let relative = path.strip_prefix(expected).ok()?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return None;
    }
    let target = path.canonicalize().ok()?;
    if target == expected || !target.starts_with(expected) {
        return None;
    }
    Some([
        format!("XDG_RUNTIME_DIR={runtime_dir}"),
        format!("DBUS_SESSION_BUS_ADDRESS={bus_address}"),
    ])
}

pub fn watch(state: &Path, args: &super::super::surfaces::Args) -> Result<Value> {
    let marker = state.join("watch.json");
    let previous = if marker.exists() {
        read_json(&marker)?
    } else {
        json!({})
    };
    let backend = args
        .option("backend")
        .or_else(|| previous["backend"].as_str())
        .unwrap_or(if cfg!(windows) {
            "windows"
        } else if cfg!(target_os = "macos") {
            "launchd"
        } else if Path::new("/usr/bin/systemctl").exists() {
            "systemd"
        } else {
            "cron"
        });
    if !["systemd", "cron", "launchd", "windows"].contains(&backend) {
        return Err(Error::usage("unrecognized scheduler backend"));
    }
    if args.flag("online") && args.flag("offline-db") {
        return Err(Error::usage("--offline-db and --online cannot be combined"));
    }
    let action = args.position(0).unwrap_or("status");
    if action == "status" {
        return match backend {
            "systemd" => {
                let mut units = json!({});
                for name in ["vorda-hourly", "vorda-daily"] {
                    units[name] =
                        json!(systemctl(&["is-enabled", &format!("{name}.timer")], false)?.trim());
                }
                Ok(
                    json!({"installed":units.as_object().unwrap().values().all(|v|v=="enabled"),"backend":backend,"units":units}),
                )
            }
            "cron" => Ok(
                json!({"installed":execute(&strings(&["crontab","-l"]),None,None,false)?.lines().any(|l|l.ends_with("# vorda")),"backend":backend}),
            ),
            "windows" => {
                let mut tasks = json!({});
                for name in ["hourly", "daily"] {
                    tasks[name] = json!(run(
                        &strings(&["schtasks.exe", "/Query", "/TN", &format!("vorda-{name}")]),
                        None
                    )
                    .is_ok());
                }
                Ok(
                    json!({"installed":tasks.as_object().unwrap().values().all(|v|v==true),"backend":backend,"tasks":tasks}),
                )
            }
            _ => {
                let text = run(&strings(&["launchctl", "list"]), None)?;
                Ok(
                    json!({"installed":(["hourly","daily"].iter().all(|s|text.contains(&format!("dev.vorda.{s}")))),"backend":backend}),
                )
            }
        };
    }
    if !["install", "uninstall"].contains(&action) {
        return Err(Error::new("unrecognized watch action"));
    }
    let install = action == "install";
    let offline_db = if args.flag("online") {
        false
    } else if args.flag("offline-db") {
        true
    } else {
        crate::scanner::osvdb::configured_scan(state)?
    };
    let refresh_db = install
        && offline_db
        && matches!(backend, "systemd" | "cron")
        && !args.flag("no-db-refresh");
    let mut roots: Vec<String> = args.options("root").into_iter().map(String::from).collect();
    if args.flag("machine") && !roots.is_empty() {
        return Err(Error::usage("--machine and --root cannot be combined"));
    }
    if roots.is_empty() && !args.flag("machine") {
        roots = previous["roots"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect();
    }
    roots = configured_roots(roots)?;
    let cwd = std::env::current_dir()?;
    let search = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
    if cwd.to_string_lossy().contains(['\r', '\n'])
        || search.contains(['\r', '\n'])
        || state.to_string_lossy().contains(['\r', '\n'])
        || roots.iter().any(|s| s.contains(['\r', '\n']))
    {
        return Err(Error::new("scheduler paths must not contain line breaks"));
    }
    let config_path = state.join("config.json");
    let mut config = if config_path.exists() {
        read_json(&config_path)?
    } else {
        json!({})
    };
    if !config.is_object() {
        return Err(Error::new("local configuration must be an object"));
    }
    for (flag, key) in [
        ("os-packages", "os_packages"),
        ("tools", "tools"),
        ("browsers", "browsers"),
    ] {
        if config.get(key).is_some_and(|v| !v.is_boolean()) {
            return Err(Error::new(format!(
                "local configuration {key} must be a boolean"
            )));
        }
        config[key] = json!(args.flag(flag) || config[key].as_bool().unwrap_or(false));
    }
    // A machine watch leaves the roots MCP may check as they were.
    if install && !roots.is_empty() {
        config["roots"] = json!(roots);
    }
    if install {
        config["path"] = json!(search);
        atomic(&config_path, &config.to_string())?;
    }
    fs::create_dir_all(state.join("empty"))?;
    let mut argv = vec![
        std::env::current_exe()?.to_string_lossy().into_owned(),
        "--state".into(),
        state.to_string_lossy().into_owned(),
    ];
    let update = refresh_db.then(|| {
        let mut update = argv.clone();
        update.extend(strings(&["db", "update"]));
        update
    });
    argv.extend([
        "check".into(),
        "--scheduled".into(),
        if offline_db {
            "--offline-db"
        } else {
            "--online"
        }
        .into(),
    ]);
    for flag in ["os-packages", "tools", "browsers"] {
        if config[flag.replace('-', "_")].as_bool().unwrap_or(false) {
            argv.push(format!("--{flag}"));
        }
    }
    for root in &roots {
        argv.extend(strings(&["--root", root]));
    }
    let mut paths = Vec::new();
    match backend {
        "systemd" => {
            let dir = home().join(".config/systemd/user");
            fs::create_dir_all(&dir)?;
            for (name, cadence) in [
                ("vorda-hourly", "hourly"),
                ("vorda-daily", "*-*-* 03:15:00"),
            ] {
                let service = dir.join(format!("{name}.service"));
                let timer = dir.join(format!("{name}.timer"));
                paths.extend([service.clone(), timer.clone()]);
                if service.exists()
                    && !fs::read_to_string(&service)?.contains(state.to_string_lossy().as_ref())
                {
                    return Err(Error::new("existing timer belongs to another mailbox"));
                }
                if install {
                    let update = update.as_deref().filter(|_| name == "vorda-daily");
                    atomic(&service, &systemd_service(&argv, &cwd, &search, update))?;
                    let delay = if update.is_some() {
                        "RandomizedDelaySec=30m\n"
                    } else {
                        ""
                    };
                    atomic(&timer,&format!("[Unit]\nDescription=Vulnerability mailbox\n[Timer]\nOnCalendar={cadence}\n{delay}Persistent=true\n[Install]\nWantedBy=timers.target\n"))?;
                } else {
                    systemctl(&["disable", "--now", &format!("{name}.timer")], false)?;
                    systemctl(&["stop", &format!("{name}.service")], false)?;
                    for p in [&service, &timer] {
                        if p.exists() {
                            fs::remove_file(p)?;
                        }
                    }
                }
            }
            systemctl(&["daemon-reload"], true)?;
            if install {
                systemctl(
                    &["enable", "--now", "vorda-hourly.timer", "vorda-daily.timer"],
                    true,
                )?;
            }
        }
        "cron" => {
            let mut listing = std::process::Command::new("crontab");
            listing
                .arg("-l")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let output = bounded_status(listing, 5)?;
            if ![Some(0), Some(1)].contains(&output.status.code()) {
                return Err(Error::new(String::from_utf8_lossy(&output.stderr)));
            }
            let old = String::from_utf8_lossy(&output.stdout);
            let mut lines: Vec<String> = old
                .lines()
                .filter(|s| !s.ends_with("# vorda"))
                .map(String::from)
                .collect();
            if install {
                lines.extend(cron_entries(&argv, &search, update.as_deref()));
            }
            execute(
                &strings(&["crontab", "-"]),
                None,
                Some(&format!("{}\n", lines.join("\n"))),
                true,
            )?;
        }
        "launchd" => {
            let dir = home().join("Library/LaunchAgents");
            fs::create_dir_all(&dir)?;
            for (name, seconds) in [("hourly", 3600), ("daily", 86400)] {
                let path = dir.join(format!("dev.vorda.{name}.plist"));
                paths.push(path.clone());
                if install {
                    let doc = json!({"Label":format!("dev.vorda.{name}"),"ProgramArguments":argv,"StartInterval":seconds,"WorkingDirectory":std::env::current_dir()?,"EnvironmentVariables":{"PATH":search}});
                    let mut buffer = Vec::new();
                    plist::to_writer_xml(&mut buffer, &doc)
                        .map_err(|e| Error::new(e.to_string()))?;
                    atomic(
                        &path,
                        std::str::from_utf8(&buffer).map_err(|e| Error::new(e.to_string()))?,
                    )?;
                    run(
                        &strings(&["launchctl", "load", &path.to_string_lossy()]),
                        None,
                    )?;
                } else {
                    run(
                        &strings(&["launchctl", "unload", &path.to_string_lossy()]),
                        None,
                    )?;
                    if path.exists() {
                        fs::remove_file(path)?;
                    }
                }
            }
        }
        _ => {
            for (name, cadence) in [("hourly", "HOURLY"), ("daily", "DAILY")] {
                if install {
                    let windows = windows_join(&argv);
                    run(
                        &strings(&[
                            "schtasks.exe",
                            "/Create",
                            "/F",
                            "/TN",
                            &format!("vorda-{name}"),
                            "/SC",
                            cadence,
                            "/TR",
                            &windows,
                        ]),
                        None,
                    )?;
                } else {
                    run(
                        &strings(&[
                            "schtasks.exe",
                            "/Delete",
                            "/F",
                            "/TN",
                            &format!("vorda-{name}"),
                        ]),
                        None,
                    )?;
                }
            }
        }
    }
    let warnings = if !install || !offline_db {
        vec![]
    } else if refresh_db {
        vec!["The daily schedule refreshes the local advisory database before scanning. It downloads public advisory data without sending package names. If the refresh fails, the scan still runs."]
    } else {
        vec!["Run `vorda db update` daily to refresh the local advisory database. A missing or stale database records unknown health with no network fallback."]
    };
    let result = json!({"installed":install,"backend":backend,"files":paths,"roots":roots,"machine":roots.is_empty(),
        "advisories":if offline_db { "offline-db" } else { "online" },
        "db_refresh":refresh_db,"warnings":warnings});
    atomic(&marker, &result.to_string())?;
    Ok(result)
}

fn windows_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            let mut out = String::from("\"");
            let mut slashes = 0;
            for c in arg.chars() {
                if c == '\\' {
                    slashes += 1;
                    continue;
                }
                if c == '"' {
                    out.push_str(&"\\".repeat(slashes * 2 + 1));
                    out.push(c);
                } else {
                    out.push_str(&"\\".repeat(slashes));
                    out.push(c);
                }
                slashes = 0;
            }
            out.push_str(&"\\".repeat(slashes * 2));
            out.push('"');
            out
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn cron_entries(argv: &[String], search: &str, update: Option<&[String]>) -> [String; 2] {
    let environment = quote(&format!("PATH={search}"));
    let command = format!("env {environment} {}", join(argv));
    let (minute, daily) = match update {
        Some(update) => (
            15 + uuid::Uuid::new_v4().as_bytes()[0] % 30,
            format!("env {environment} {} || :; {command}", join(update)),
        ),
        None => (15, command.clone()),
    };
    [
        format!("0 * * * * {} # vorda", command.replace('%', "\\%")),
        format!("{minute} 3 * * * {} # vorda", daily.replace('%', "\\%")),
    ]
}

fn systemd_command(argv: &[String]) -> String {
    argv.iter()
        .map(|s| json!(s).to_string().replace('%', "%%").replace('$', "$$"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn systemd_service(argv: &[String], cwd: &Path, search: &str, update: Option<&[String]>) -> String {
    let args = systemd_command(argv);
    let pre = update
        .map(|argv| format!("ExecStartPre=-{}\n", systemd_command(argv)))
        .unwrap_or_default();
    format!("[Unit]\nDescription=Vulnerability mailbox\n[Service]\nType=oneshot\nEnvironment={}\nWorkingDirectory={}\n{pre}ExecStart={args}\nSuccessExitStatus=3\n",
        json!(format!("PATH={search}")).to_string().replace('%', "%%"),
        cwd.to_string_lossy().replace('%', "%%"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn systemctl_forwards_only_a_bus_inside_the_current_users_runtime_directory() {
        use std::{fs, os::unix::fs::symlink};

        let temp = tempfile::tempdir().unwrap();
        let expected = temp.path().canonicalize().unwrap().join("1001");
        fs::create_dir(&expected).unwrap();
        let other = expected.with_file_name("10010");
        fs::create_dir(&other).unwrap();
        let bus = expected.join("bus");
        let other_bus = other.join("bus");
        let _local = std::os::unix::net::UnixListener::bind(&bus).unwrap();
        let _other = std::os::unix::net::UnixListener::bind(&other_bus).unwrap();
        let linked_bus = expected.join("linked-bus");
        symlink(&other_bus, &linked_bus).unwrap();

        let runtime = expected.to_str().unwrap();
        let address = format!("unix:path={}", bus.display());
        let environment = |dir, bus| super::user_bus_environment(&expected, dir, bus);
        assert_eq!(
            environment(Some(runtime), Some(&address)),
            Some([
                format!("XDG_RUNTIME_DIR={runtime}"),
                format!("DBUS_SESSION_BUS_ADDRESS={address}"),
            ]),
        );
        assert!(environment(other.to_str(), Some(&address)).is_none());
        assert!(environment(None, Some(&address)).is_none());
        assert!(environment(Some(runtime), None).is_none());
        for refused in [
            format!("unix:path={}", other_bus.display()),
            format!("unix:path={runtime}/../10010/bus"),
            format!("unix:path={}", linked_bus.display()),
            format!("{address},guid=fixture"),
            format!("{address};unix:path={}", other_bus.display()),
            format!("unix:path={runtime}/%62us"),
            "unix:abstract=fixture".into(),
        ] {
            assert!(
                super::user_bus_environment(&expected, Some(runtime), Some(&refused)).is_none(),
                "{refused}"
            );
        }
    }

    #[test]
    fn generated_service_is_accepted_by_systemd() {
        let verifier = std::path::Path::new("/usr/bin/systemd-analyze");
        if !verifier.exists() {
            eprintln!("systemd-analyze unavailable; platform verification required separately");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("project with spaces and %");
        std::fs::create_dir(&cwd).unwrap();
        let unit = temp.path().join("vorda-test.service");
        let service = super::systemd_service(
            &["/bin/true".into()],
            &cwd,
            "/usr/bin:/bin",
            Some(&["/bin/false".into()]),
        );
        assert!(service.contains("ExecStartPre=-\"/bin/false\"\nExecStart=\"/bin/true\"\n"));
        std::fs::write(&unit, service).unwrap();
        let output = std::process::Command::new(verifier)
            .arg("verify")
            .arg(&unit)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn cron_runs_the_daily_check_even_if_refresh_fails() {
        let scan = super::strings(&["/bin/echo", "scan"]);
        let update = super::strings(&["/bin/sh", "-c", "echo update; exit 1"]);
        let run = |entry: &str| {
            let command = entry.splitn(6, ' ').nth(5).unwrap();
            let output = std::process::Command::new("/bin/sh")
                .args(["-ec", command])
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap()
        };
        let [hourly, daily] = super::cron_entries(&scan, "/usr/bin:/bin", Some(&update));
        let minute: u8 = daily.split_whitespace().next().unwrap().parse().unwrap();
        assert!((15..45).contains(&minute));
        assert_eq!(run(&hourly), "scan\n");
        assert_eq!(run(&daily), "update\nscan\n");
        let [_, daily] = super::cron_entries(&scan, "/usr/bin:/bin", None);
        assert_eq!(run(&daily), "scan\n");
    }
}

/// The project roots a watch scans; none means the scheduled check scans the machine.
fn configured_roots(roots: Vec<String>) -> Result<Vec<String>> {
    roots
        .iter()
        .map(|root| crate::cli::resolved(Path::new(root)).map(|p| p.to_string_lossy().into_owned()))
        .collect()
}

#[cfg(test)]
mod root_tests {
    use super::*;
    #[test]
    fn scheduler_config_normalizes_roots_for_mcp_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        let spelling = project.join("..").join("project").join("");
        let roots = configured_roots(vec![spelling.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(
            roots,
            vec![crate::cli::resolved(&project)
                .unwrap()
                .to_string_lossy()
                .into_owned()]
        );
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::write(
            state.join("config.json"),
            json!({"roots":roots}).to_string(),
        )
        .unwrap();
        let request =
            json!({"method":"tools/call","params":{"name":"check","arguments":{"offline":true}}});
        assert!(crate::surfaces::mcp::call(&state, &request, None, None).is_ok());
    }
}
