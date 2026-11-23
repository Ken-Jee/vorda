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
                    units[name] = json!(execute(
                        &strings(&[
                            "systemctl",
                            "--user",
                            "is-enabled",
                            &format!("{name}.timer")
                        ]),
                        None,
                        None,
                        false
                    )?
                    .trim());
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
        "check".into(),
        "--scheduled".into(),
        if offline_db {
            "--offline-db"
        } else {
            "--online"
        }
        .into(),
    ];
    for flag in ["os-packages", "tools", "browsers"] {
        if config[flag.replace('-', "_")].as_bool().unwrap_or(false) {
            argv.push(format!("--{flag}"));
        }
    }
    for root in &roots {
        argv.extend(strings(&["--root", root]));
    }
    let command = join(&argv);
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
                    atomic(&service, &systemd_service(&argv, &cwd, &search))?;
                    atomic(&timer,&format!("[Unit]\nDescription=Vulnerability mailbox\n[Timer]\nOnCalendar={cadence}\nPersistent=true\n[Install]\nWantedBy=timers.target\n"))?;
                } else {
                    execute(
                        &strings(&[
                            "systemctl",
                            "--user",
                            "disable",
                            "--now",
                            &format!("{name}.timer"),
                        ]),
                        None,
                        None,
                        false,
                    )?;
                    execute(
                        &strings(&["systemctl", "--user", "stop", &format!("{name}.service")]),
                        None,
                        None,
                        false,
                    )?;
                    for p in [&service, &timer] {
                        if p.exists() {
                            fs::remove_file(p)?;
                        }
                    }
                }
            }
            run(&strings(&["systemctl", "--user", "daemon-reload"]), None)?;
            if install {
                run(
                    &strings(&[
                        "systemctl",
                        "--user",
                        "enable",
                        "--now",
                        "vorda-hourly.timer",
                        "vorda-daily.timer",
                    ]),
                    None,
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
                let invocation = format!("env {} {command}", quote(&format!("PATH={search}")))
                    .replace('%', "\\%");
                lines.extend([
                    format!("0 * * * * {invocation} # vorda"),
                    format!("15 3 * * * {invocation} # vorda"),
                ]);
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
    let result = json!({"installed":install,"backend":backend,"files":paths,"roots":roots,"machine":roots.is_empty(),
        "advisories":if offline_db { "offline-db" } else { "online" },
        "warnings":if install && offline_db { vec!["Scheduled offline-db scans never refresh the local advisory database automatically; run `vorda db update` daily before scheduled scans. Databases that are missing or older than 72 hours (adjustable via VORDA_ADVISORY_DB_MAX_AGE_HOURS) record unknown health messages and never fall back to the network. Reinstall with `--online` to explicitly send package names and versions to OSV.dev instead."] } else { vec![] }});
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

fn systemd_service(argv: &[String], cwd: &Path, search: &str) -> String {
    let args = argv
        .iter()
        .map(|s| json!(s).to_string().replace('%', "%%").replace('$', "$$"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("[Unit]\nDescription=Vulnerability mailbox\n[Service]\nType=oneshot\nEnvironment={}\nWorkingDirectory={}\nExecStart={args}\nSuccessExitStatus=3\n",
        json!(format!("PATH={search}")).to_string().replace('%', "%%"),
        cwd.to_string_lossy().replace('%', "%%"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
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
        std::fs::write(
            &unit,
            super::systemd_service(&["/bin/true".into()], &cwd, "/usr/bin:/bin"),
        )
        .unwrap();
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
