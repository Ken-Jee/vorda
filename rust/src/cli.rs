use crate::domain::{InventoryOptions, Package, Record, ScanOptions};
use crate::scanner::{self, input};
use crate::store::{asset, atomic, identity, now, Store};
use crate::{Error, Result};
use rusqlite::params;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

/// Why Ubuntu OS-package results are labelled experimental, in plain words.
const UBUNTU_EXPERIMENTAL: &str = "OSV-decided findings miss Canonical's not-affected or won't-fix status, causing false alarms; kernel-header packages (linux-libc-dev) add many findings; a scan can end unknown when a Canonical record has no entry for this release.";

const HELP: &str = "Usage: vorda [--state DIR] COMMAND [options]
       vorda help [COMMAND] | vorda COMMAND --help | vorda --version

To start, run vorda setup to choose offline or online advisories and scan this machine. You can also run vorda scan for this machine or vorda scan PATH for one project (run vorda help scan to see its options).

Check:
  scan          Check this machine (OS packages, tools, browsers, apps, home projects) or named paths or images for vulnerabilities
  check         Same as scan
  inventory     List the packages a scan would check, without looking up advisories
  db            Download or show the offline advisory database that scan uses by default (same as --offline-db)
  agentbom      List AI agent tooling (MCP servers, skills, models) and check it (preview)
Read results:
  mail          List, read, acknowledge or snooze saved findings
  dashboard     Serve the local web dashboard of saved scans
  mcp           Run the MCP server that lets coding agents scan and read the mailbox
Set up:
  setup         Choose offline or online advisories, optionally schedule scans, and scan this machine
  connect       Add Vorda to an agent client's config
  snippet       Print agent setup snippets
  hook          Print the agent session hook output
  watch         Install, remove or show scheduled scans
Act on findings:
  fix           Print fix commands (and swap Chromium with --chromium --apply)
  repair        Plan, review and apply reviewed dependency repairs
  repair-mcp    Run the MCP server for the repair queue
  mode          Show or set watch, advise or fix mode
  can           Ask whether an agent may take an action
Fleet:
  link          Link machines to a hub
  hub-mcp       Run the MCP server that reads a hub
  snapshot-read Read a saved snapshot (trusted local input)
Other:
  update        Update this executable from a signed release
  verify-self   Verify this executable's signature
  licenses      Print third-party licenses
  version       Print the version

Scan exits: 0 = no known findings, 3 = vulnerable, 2 = unknown/incomplete or operational error, 64 = usage error (EX_USAGE).";

fn array(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

/// Prints warnings to stderr. Two or more of one repetitive kind (symlinked folders read
/// elsewhere, test or example files not covered) collapse to one line; each is in --json.
fn print_warnings(warnings: &Value) {
    let warnings = array(warnings);
    let (linked, other): (Vec<&str>, Vec<&str>) = warnings
        .iter()
        .map(|w| w.as_str().unwrap_or("unknown inventory warning"))
        .partition(|w| w.ends_with(scanner::inventory::READ_THERE));
    let (test_data, other): (Vec<&str>, Vec<&str>) = other
        .into_iter()
        .partition(|w| w.ends_with(scanner::inventory::NOT_COVERED_TEST_DATA));
    for warning in other {
        eprintln!("Warning: {}", shown(warning));
    }
    for (group, many) in [
        (linked, COPY_LINKED_SKIPPED),
        (test_data, COPY_TEST_DATA_SKIPPED),
    ] {
        match group[..] {
            [] => {}
            [one] => eprintln!("Warning: {}", shown(one)),
            _ => eprintln!("Warning: {}", many.replace("{n}", &group.len().to_string())),
        }
    }
}
fn strings(value: &Value) -> BTreeSet<String> {
    array(value)
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}
pub(crate) fn resolved(path: &Path) -> Result<PathBuf> {
    let path = input::absolute(path)?;
    #[cfg(windows)]
    let explicit_verbatim = path.to_string_lossy().starts_with(r"\\?\");
    let path = path.canonicalize().unwrap_or(path);
    #[cfg(windows)]
    if !explicit_verbatim {
        // Python realpath omits an added Win32 verbatim prefix when equivalent.
        let text = path.to_string_lossy();
        let ordinary = if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
            Some(PathBuf::from(format!(r"\\{unc}")))
        } else {
            text.strip_prefix(r"\\?\").map(PathBuf::from)
        };
        if let Some(ordinary) = ordinary {
            if ordinary.canonicalize().ok().as_ref() == Some(&path) {
                return Ok(ordinary);
            }
        }
    }
    Ok(path)
}

pub fn state_path(path: &Path) -> Result<PathBuf> {
    let path = if path.starts_with("~") {
        crate::repair::commands::home().join(
            path.strip_prefix("~")
                .map_err(|e| Error::new(e.to_string()))?,
        )
    } else {
        path.to_path_buf()
    };
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut ancestor = path.as_path();
    let mut missing = Vec::new();
    let mut result = loop {
        match ancestor.canonicalize() {
            Ok(canonical) => break canonical,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor
                    .components()
                    .next_back()
                    .ok_or_else(|| Error::new("cannot resolve state path"))?;
                missing.push(name.as_os_str().to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| Error::new("cannot resolve state path"))?;
            }
            Err(e) => return Err(e.into()),
        }
    };
    for component in missing.into_iter().rev() {
        if component == ".." {
            result.pop();
        } else if component != "." {
            result.push(component);
        }
        if let Ok(canonical) = result.canonicalize() {
            result = canonical;
        }
    }
    Ok(result)
}

fn snapshot_input(path: &str, limit: usize) -> Vec<u8> {
    let read = || -> std::io::Result<Vec<u8>> {
        if !std::fs::metadata(path)?.is_file() {
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            return Ok(Vec::new());
        }
        let mut bytes = Vec::new();
        file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    read().unwrap_or_default()
}

fn snapshot_read(args: &[String]) -> Result<i32> {
    if args == ["--help"] || args == ["-h"] {
        outln(format_args!("Usage: vorda snapshot-read SNAPSHOT.json GRANT.json QUERY.json AS_OF\nTrusted-local snapshot, grant and as-of inputs; no authentication, collection or state writes."))?;
        return Ok(0);
    }
    let response = if let [snapshot, grant, query, as_of] = args {
        crate::snapshot::read(
            &snapshot_input(snapshot, 4 * 1024 * 1024),
            &snapshot_input(grant, 64 * 1024),
            &snapshot_input(query, 16 * 1024),
            as_of,
        )
    } else {
        return Err(Error::usage(
            "snapshot-read takes exactly SNAPSHOT.json GRANT.json QUERY.json AS_OF (see vorda snapshot-read --help)",
        ));
    };
    let (value, code) = match response {
        Ok(value) => (serde_json::to_value(value)?, 0),
        Err(error) => (json!({"error":error,"data":null}), 2),
    };
    outln(format_args!("{}", serde_json::to_string(&value)?))?;
    Ok(code)
}

const SETUP: &str = "No local offline advisory database found. An offline scan without the database reports unknown. Vorda scans offline by default and never falls back to the network automatically.\n\nThe offline advisory database covers npm, PyPI, crates.io, and Go from any inventory source. Other ecosystems and network-only feeds are listed in not_assessed. Pass --online to check them.\n\nChoose an option:\n  1) Download the offline advisory database now (25 to 80 seconds, about 190 MB; package names never leave this machine)\n  2) Scan online this once (sends package names and versions to OSV.dev)\n  Enter) Cancel without scanning\n\nRun vorda setup to save an offline or online choice for future scans, or pass --online or --offline-db for a single scan.";
const SETUP_UNATTENDED: &str = "No local offline advisory database found, and Vorda cannot prompt in noninteractive, CI, or Action runs (result: unknown, exit 2). It never falls back to the network. Run `vorda db update` first, or `vorda scan --online` once. Offline scans cover npm, PyPI, crates.io, and Go, and package names never leave this machine; other ecosystems and network-only feeds are listed in not_assessed. Pass --online to check them.";
const SETUP_PROMPT: &str =
    "Select [1] download offline advisory database, [2] scan online once, or Enter to cancel: ";
const SETUP_INVALID: &str = "No valid choice; no scan was run. Run vorda db update to download the offline advisory database.";

const SETUP_CANCELLED: &str =
    "Cancelled; no scan was run. Run vorda db update to download the offline advisory database.";

/// Whether a machine scan on an Ubuntu host reads OS packages. Ubuntu results are experimental
/// (`UBUNTU_EXPERIMENTAL`), so they are labelled; set false to leave them to `--os-packages`.
const MACHINE_UBUNTU_OS_PACKAGES: bool = true;

/// A scan with no PATH, `--root`, `--inventory-file` or `--oci` checks this machine: OS
/// packages, tools, browsers, installed apps (Windows only), and the projects under the home folder.
fn machine_scan(inventory: &mut InventoryOptions) -> Result<()> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Error::new(COPY_NO_HOME))?;
    // The walk refuses a linked root, and some systems link /home elsewhere. Windows keeps the
    // plain spelling: canonical paths there carry a verbatim prefix scopes never use.
    #[cfg(not(windows))]
    let home =
        std::fs::canonicalize(&home).map_err(|e| Error::new(format!("{}: {e}", home.display())))?;
    inventory.roots = vec![home];
    inventory.machine = true;
    inventory.tools = true;
    inventory.browsers = true;
    // The installed-app sources read the Windows registry; elsewhere they could only report
    // that it is missing, which is not something the scan failed to check.
    inventory.installed_apps = cfg!(windows);
    let ubuntu = scanner::distro::ecosystem(
        &std::fs::read_to_string("/etc/os-release").unwrap_or_default(),
        "",
    )
    .starts_with("Ubuntu:");
    inventory.os_packages |= MACHINE_UBUNTU_OS_PACKAGES || !ubuntu;
    Ok(())
}

/// Settle the advisory mode before a scan. `false` when the person cancelled first-use setup.
pub(crate) fn prepare_scan(
    options: &mut ScanOptions,
    state: &Path,
    interactive: bool,
) -> Result<bool> {
    if options.offline {
        if options.offline_db == Some(true) {
            return Err(Error::usage(
                "--offline and the offline advisory database cannot be combined",
            ));
        }
        options.offline_db = Some(false);
        return Ok(true);
    }
    let offline = match options.offline_db {
        Some(choice) => choice,
        None => scanner::osvdb::configured_scan(state)?,
    };
    options.offline_db = Some(offline);
    if !offline || scanner::osvdb::installed() || options.inventory.scheduled {
        return Ok(true);
    }
    if !interactive || !terminal() {
        return Err(Error::new(SETUP_UNATTENDED));
    }
    eprintln!("{SETUP}");
    match ask(SETUP_PROMPT)?.as_str() {
        "1" => {
            advisory_db(&["update".into()])?;
        }
        "2" => options.offline_db = Some(false),
        "" => return Ok(false),
        _ => return Err(Error::new(SETUP_INVALID)),
    }
    Ok(true)
}

/// A person can answer a prompt: every standard stream is a terminal and this is not CI.
fn terminal() -> bool {
    std::env::var_os("CI").is_none()
        && std::env::var_os("GITHUB_ACTIONS").is_none()
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal()
        && std::io::stdout().is_terminal()
}

/// Print `prompt` to stderr and return the trimmed answer line.
fn ask(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    // End of input leaves the cursor after the prompt; anything printed next starts a new line.
    if !answer.ends_with('\n') {
        eprintln!();
    }
    Ok(answer.trim().to_owned())
}

const SETUP_USAGE: &str = "Usage: vorda setup [--offline-db | --online] [--watch | --no-watch]\n\nChoose offline or online advisories, save the choice to config.json, download the local database when offline, optionally install scheduled machine scans, and run the first scan of this machine.\n\n  --offline-db  Use the local advisory database (default in a terminal; downloads OSV exports for npm, PyPI, crates.io and Go plus the CISA KEV list to ~/.cache/vorda/advisory-db, 25 to 80 seconds and about 190 MB; package names never leave this machine; other ecosystems and network-only feeds are listed as not assessed)\n  --online      Send package names and versions to OSV.dev on each scan and also check the feeds the offline database lacks\n  --watch       Install scheduled hourly and daily machine scans (vorda watch install --machine) without prompting\n  --no-watch    Skip scheduled machine scans without prompting\n\nIn a terminal without a mode flag, setup prompts for 1 (offline, default on Enter) or 2 (online); any other answer exits 64 without saving. Outside a terminal or in CI, pass --offline-db or --online or setup exits 64 without saving.\n\nThe choice is saved as \"advisories\": \"offline-db\" or \"advisories\": \"online\" in config.json in the state folder (keeping any other keys) and applies to later vorda scan, vorda check, vorda watch install and MCP check runs. Single-scan --online or --offline-db flags still win for that scan, and VORDA_ADVISORIES wins over config.json (setup prints a note if it is set to the other mode). Run vorda setup again anytime to change the saved choice.\n\nIn offline mode, setup runs vorda db update. If the download fails or any line is not updated, setup stops with exit 2 without scanning; the choice stays saved so you can run vorda db update and then vorda scan.\n\nWithout --watch or --no-watch, setup asks in a terminal whether to install scheduled hourly and daily machine scans via systemd, cron, launchd or Windows Task Scheduler (default no; only y or yes installs), and skips them outside a terminal. On systemd and cron, the daily offline schedule refreshes the local advisory database by default. On other backends or after an install with --no-db-refresh, run vorda db update daily.\n\nLast, setup runs vorda scan on this machine (OS packages, tools, browsers, installed apps (Windows only), and project lockfiles under home), prints a reminder to run vorda dashboard, and exits with the scan's exit code (0 no known findings, 3 vulnerable, 2 unknown). Running bare vorda with no arguments in a terminal (outside CI) before any mode is set in config.json or VORDA_ADVISORIES starts setup automatically; vorda --help, -h and help always print help.";
const SETUP_MODE: &str = "Choose how Vorda checks for advisories. Offline is the default so your package names never leave this machine.\n\n  1) Offline advisory database (default): downloads OSV exports for npm, PyPI, crates.io and Go plus the CISA KEV list to ~/.cache/vorda/advisory-db (25 to 80 seconds, about 190 MB). Package names never leave this machine; other ecosystems and network-only feeds are listed as not assessed.\n  2) Online advisories: each scan sends package names and versions to OSV.dev and also checks the feeds the offline database lacks.\n\nYour choice is saved for later scans. Run vorda setup again anytime to change it.";
const SETUP_MODE_PROMPT: &str = "Choose advisory mode [1/2, Enter for 1]: ";
const SETUP_MODE_INVALID: &str =
    "Invalid choice: enter 1 (or press Enter) for offline, or 2 for online; nothing was saved.";
const SETUP_NEEDS_MODE: &str =
    "vorda setup needs --offline-db or --online outside a terminal or in CI; nothing was saved.";
const SETUP_SAVED_OFFLINE: &str = "Saved offline advisory mode (offline-db) to config.json; pass --online to override a single scan.";
const SETUP_SAVED_ONLINE: &str = "Saved online advisory mode (online) to config.json; pass --offline-db to override a single scan.";
const SETUP_ENV_OVERRIDES: &str = "Note: VORDA_ADVISORIES is set to the other mode and wins over the saved choice in config.json.";
const SETUP_DB_FAILED: &str = "Offline advisory database update did not complete; offline mode stays saved and no scan was run. Run vorda db update and then vorda scan.";
const SETUP_WATCH_PROMPT: &str =
    "Install scheduled hourly and daily scans of this machine? [y/N]: ";
const SETUP_WATCH_OFFLINE_NOTE: &str = "Note: systemd and cron refresh the offline database before the daily scan. For other schedulers, run vorda db update daily.";
const SETUP_WATCH_DONE: &str = "Scheduled hourly and daily machine scans are installed.";
const SETUP_SCAN_START: &str = "Starting the first scan of this machine (OS packages, tools, browsers, installed apps (Windows only), and project lockfiles under home)...";
const SETUP_DASHBOARD: &str = "Run vorda dashboard to see the results in the local web dashboard.";

/// Whether config.json or VORDA_ADVISORIES already settles the advisory mode.
fn advisories_chosen(state: &Path) -> bool {
    std::env::var_os("VORDA_ADVISORIES").is_some_and(|v| !v.is_empty())
        || std::fs::read(state.join("config.json"))
            .map(|bytes| {
                serde_json::from_slice::<Value>(&bytes).map_or(true, |c| !c["advisories"].is_null())
            })
            .unwrap_or(false)
}

/// `vorda setup`: choose and save the advisory mode, fetch the offline database, offer scheduled
/// machine scans, then run the first machine scan. Its exit code is the scan's.
fn setup(state: &Path, rest: &[String]) -> Result<i32> {
    let (mut offline, mut watch) = (None, None);
    for arg in rest {
        match arg.as_str() {
            "--help" | "-h" => {
                outln(format_args!("{SETUP_USAGE}"))?;
                return Ok(0);
            }
            "--offline-db" | "--online" if offline.is_none() => {
                offline = Some(arg == "--offline-db")
            }
            "--watch" | "--no-watch" if watch.is_none() => watch = Some(arg == "--watch"),
            "--offline-db" | "--online" | "--watch" | "--no-watch" => {
                return Err(Error::usage(format!(
                    "{arg} cannot be combined with an earlier choice"
                )))
            }
            _ => return Err(Error::usage(format!("unrecognized setup argument: {arg}"))),
        }
    }
    let terminal = terminal();
    let offline = match offline {
        Some(choice) => choice,
        None if terminal => {
            eprintln!("{SETUP_MODE}");
            match ask(SETUP_MODE_PROMPT)?.as_str() {
                "" | "1" => true,
                "2" => false,
                _ => return Err(Error::usage(SETUP_MODE_INVALID)),
            }
        }
        None => return Err(Error::usage(SETUP_NEEDS_MODE)),
    };
    let path = state.join("config.json");
    let mut config = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(Error::new(format!("{}: {e}", path.display()))),
    };
    if !config.is_object() {
        return Err(Error::new("local configuration must be an object"));
    }
    let mode = if offline { "offline-db" } else { "online" };
    config["advisories"] = json!(mode);
    atomic(&path, &config.to_string())?;
    eprintln!(
        "{}",
        if offline {
            SETUP_SAVED_OFFLINE
        } else {
            SETUP_SAVED_ONLINE
        }
    );
    if std::env::var("VORDA_ADVISORIES").is_ok_and(|v| !v.is_empty() && v != mode) {
        eprintln!("{SETUP_ENV_OVERRIDES}");
    }
    if offline {
        let updated = advisory_db(&["update".into()]);
        if let Err(e) = &updated {
            eprintln!("{e}");
        }
        if !matches!(updated, Ok(0)) {
            return Err(Error::new(SETUP_DB_FAILED));
        }
    }
    let watch = match watch {
        Some(choice) => choice,
        None if terminal => {
            if offline {
                eprintln!("{SETUP_WATCH_OFFLINE_NOTE}");
            }
            matches!(
                ask(SETUP_WATCH_PROMPT)?.to_lowercase().as_str(),
                "y" | "yes"
            )
        }
        None => false,
    };
    if watch {
        Store::open(state)?;
        let args = crate::surfaces::Args::parse(
            &["install".into(), "--machine".into(), format!("--{mode}")],
            &["machine", "offline-db", "online"],
            &[],
        )?;
        let installed = crate::delivery::schedule::watch(state, &args)?;
        eprintln!("{SETUP_WATCH_DONE}");
        for warning in array(&installed["warnings"]) {
            eprintln!("{}", string_of(&warning));
        }
    }
    eprintln!("{SETUP_SCAN_START}");
    let state = state
        .to_str()
        .ok_or_else(|| Error::new("the state folder path must be valid UTF-8"))?;
    let code = run(&["--state".into(), state.into(), "scan".into()])?;
    outln(format_args!("{SETUP_DASHBOARD}"))?;
    Ok(code)
}

/// The state folder when neither `--state` nor `VORDA_HOME` names one: `~/.local/share/vorda`, or
/// `%LOCALAPPDATA%\vorda\state` on Windows (`local_app_data` is only set there). A Windows home
/// that already has `.local\share\vorda` from an earlier version keeps using it.
fn default_state(
    home: Option<std::ffi::OsString>,
    local_app_data: Option<std::ffi::OsString>,
) -> PathBuf {
    let legacy = home
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local")
        .join("share")
        .join("vorda");
    match local_app_data.filter(|l| !l.is_empty()) {
        Some(local) if !legacy.is_dir() => PathBuf::from(local).join("vorda").join("state"),
        _ => legacy,
    }
}

pub fn run(args: &[String]) -> Result<i32> {
    let mut iter = args.iter().peekable();
    let mut state = std::env::var_os("VORDA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            default_state(
                std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }),
                std::env::var_os("LOCALAPPDATA").filter(|_| cfg!(windows)),
            )
        });
    if iter.peek().is_some_and(|s| s.as_str() == "--state") {
        iter.next();
        state = PathBuf::from(
            iter.next()
                .filter(|value| !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V"))
                .ok_or_else(|| Error::usage("--state requires a value"))?,
        );
    }
    let Some(command) = iter.next() else {
        // The first bare `vorda` in a terminal, before any advisory choice, runs setup.
        if terminal() {
            let state = state_path(&state)?;
            if !advisories_chosen(&state) {
                return setup(&state, &[]);
            }
        }
        outln(format_args!("{HELP}"))?;
        return Ok(0);
    };
    let rest: Vec<String> = iter.cloned().collect();
    if command == "--help" || command == "-h" || (command == "help" && rest.is_empty()) {
        outln(format_args!("{HELP}"))?;
        return Ok(0);
    }
    if command == "help" {
        return match rest.as_slice() {
            [topic] => run(&[topic.clone(), "--help".into()]),
            _ => Err(Error::usage("help takes at most one command name")),
        };
    }
    if command == "version" && (rest == ["--help"] || rest == ["-h"]) {
        outln(format_args!("Usage: vorda version"))?;
        return Ok(0);
    }
    if command == "--version" || command == "-V" || (command == "version" && rest.is_empty()) {
        outln(format_args!("vorda {}", env!("CARGO_PKG_VERSION")))?;
        return Ok(0);
    }
    if command == "snapshot-read" {
        return snapshot_read(&rest);
    }
    if command == "licenses" {
        if rest == ["--help"] || rest == ["-h"] {
            outln(format_args!("Usage: vorda licenses"))?;
        } else if rest.is_empty() {
            emit(crate::release::licenses())?;
        } else {
            return Err(Error::usage("licenses takes no arguments"));
        }
        return Ok(0);
    }
    if command == "verify-self" {
        return crate::release::verify_self(&rest);
    }
    if command == "action-scan" {
        return crate::release::action::run(&rest);
    }
    if command == "render-manifests" {
        return crate::release::manifests::run(&rest);
    }
    if command == "link" {
        return crate::link::run(&rest);
    }
    if command == "db" {
        return advisory_db(&rest);
    }
    if command == "hub-mcp" {
        return crate::surfaces::hub_mcp::run(&rest);
    }
    let state = state_path(&state)?;
    if command == "setup" {
        return setup(&state, &rest);
    }
    if command == "update" {
        return crate::update::run(&rest, &state);
    }
    if command.starts_with("capture") {
        return crate::store::capture::command(&state, command, &rest);
    }
    match command.as_str() {
        "scan" | "check" | "inventory" => {
            let mut options = ScanOptions::default();
            let mut format = if command == "inventory" {
                "json"
            } else {
                "summary"
            }
            .to_string();
            let mut iter = rest.iter();
            while let Some(arg) = iter.next() {
                let mut value = || {
                    iter.next()
                        .filter(|value| {
                            !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V")
                        })
                        .ok_or_else(|| Error::usage(format!("{arg} requires a value")))
                };
                match arg.as_str() {
                    "--root" => options.inventory.roots.push(PathBuf::from(value()?)),
                    "--exclude" if command != "inventory" => options
                        .inventory
                        .exclude
                        .push(input::absolute(Path::new(value()?))?),
                    "--os-packages" => options.inventory.os_packages = true,
                    "--tools" => options.inventory.tools = true,
                    "--browsers" => options.inventory.browsers = true,
                    "--installed-apps" => options.inventory.installed_apps = true,
                    "--installed-root" => options
                        .inventory
                        .installed_roots
                        .push(PathBuf::from(value()?)),
                    "--oci" => options.inventory.oci = Some(input::absolute(Path::new(value()?))?),
                    "--format" if command == "inventory" => {
                        format = value()?.clone();
                        if !["json", "cyclonedx", "spdx"].contains(&format.as_str()) {
                            return Err(Error::usage("invalid inventory format"));
                        }
                    }
                    "--scheduled" if command != "inventory" => options.inventory.scheduled = true,
                    "--offline" if command != "inventory" => options.offline = true,
                    "--offline-db" | "--online" if command != "inventory" => {
                        let choice = Some(arg == "--offline-db");
                        if options.offline_db.is_some_and(|c| Some(c) != choice) {
                            return Err(Error::usage(
                                "--offline-db and --online cannot be combined",
                            ));
                        }
                        options.offline_db = choice;
                    }
                    "--inventory-file" if command != "inventory" => {
                        options.inventory_file = Some(PathBuf::from(value()?))
                    }
                    "--webhook" | "--ntfy" if command != "inventory" => {
                        let url = value()?.clone();
                        if crate::delivery::endpoint_url(&url).is_none() {
                            return Err(Error::usage(format!(
                                "{arg} needs an http:// or https:// URL with a host"
                            )));
                        }
                        if arg == "--webhook" {
                            options.webhook = Some(url);
                        } else {
                            options.ntfy = Some(url);
                        }
                    }
                    "--desktop" if command != "inventory" => options.desktop = true,
                    "--json" if command != "inventory" => format = "json".to_string(),
                    "--help" | "-h" => {
                        outln(format_args!("Usage: vorda {command} {}[--root DIR] [--os-packages] [--tools] [--browsers] [--installed-apps] [--installed-root PATH] [--oci ARCHIVE]{}",
                        if command == "inventory" {""} else {"[PATH ...] "},
                        if command == "inventory" {" [--format json|cyclonedx|spdx]"} else {" [--exclude PATH] [--offline | --offline-db | --online] [--scheduled] [--inventory-file FILE] [--webhook URL] [--ntfy URL] [--desktop] [--json]\n\nWith no PATH, --root, --inventory-file, or --oci, scans this machine: OS packages, tools, browsers, installed apps (Windows only), and project lockfiles under your home folder (skipping caches, toolchains, downloads, app data, and trash). Pass one or more PATH arguments to scan only those folders or lockfiles; a bare PATH works like --root DIR.\nPrints a short summary; --json prints the full machine-readable result.\n--offline makes no network request and reads no advisories: it lists the packages found, and the result is always unknown (exit 2). For a complete check without network, use --offline-db.\nManual scan and check commands default to the local offline advisory database (--offline-db). Use --online to query OSV.dev for one scan, --offline-db to use the local database, or --offline for an inventory-only scan that always reports unknown (distinct from --offline-db). Mode precedence is CLI flags, then VORDA_ADVISORIES, then config.json (advisories), then the --offline-db default. If no local advisory indexes exist yet, an interactive terminal prompts to download the database or scan online once; noninteractive runs exit 2 (unknown) with no automatic network fallback."}))?;
                        if command != "inventory" {
                            outln(format_args!("\n{COPY_EXCLUDE_HELP}"))?;
                            outln(format_args!("\n--os-packages on Ubuntu (host or --oci image) is experimental: {UBUNTU_EXPERIMENTAL}"))?;
                        }
                        return Ok(0);
                    }
                    _ if !arg.starts_with('-') && command != "inventory" => {
                        options.inventory.roots.push(PathBuf::from(arg))
                    }
                    _ if !arg.starts_with('-') => {
                        return Err(Error::usage(format!(
                            "unrecognized {command} argument: {arg} (to scan it, pass --root {arg})"
                        )))
                    }
                    _ => {
                        return Err(Error::usage(format!(
                            "unrecognized {command} argument: {arg}"
                        )))
                    }
                }
            }
            if command != "inventory"
                && options.inventory.roots.is_empty()
                && options.inventory_file.is_none()
                && options.inventory.oci.is_none()
            {
                machine_scan(&mut options.inventory)?;
            }
            // A mistyped folder would otherwise be saved as a project that stays on the
            // dashboard as "Folder missing"; scheduled scans keep reporting a vanished root.
            if command != "inventory" && !options.inventory.scheduled {
                if let Some(root) = options.inventory.roots.iter().find(|root| !root.exists()) {
                    return Err(Error::new(format!(
                        "{}: no such folder or file; nothing was scanned or saved",
                        root.display()
                    )));
                }
            }
            if let Some(oci) = options.inventory.oci.as_ref().filter(|oci| !oci.exists()) {
                return Err(Error::new(format!(
                    "{}: no such OCI archive; nothing was scanned or saved",
                    oci.display()
                )));
            }
            if command != "inventory" && !prepare_scan(&mut options, &state, format != "json")? {
                // A terminal may not echo the Enter, so start a new line either way.
                eprintln!("\n{SETUP_CANCELLED}");
                return Ok(2);
            }
            let mut store = Store::open(&state)?;
            if command == "inventory" {
                options.inventory.cache_dir = Some(store.root.join("cache/browser-versions"));
                let result = Value::Object(scanner::inventory(&options.inventory)?);
                print_warnings(&result["warnings"]);
                let packages: Vec<Package> = serde_json::from_value(result["packages"].clone())?;
                let output = match format.as_str() {
                    "cyclonedx" => scanner::outputs::cyclonedx(&packages),
                    "spdx" => scanner::outputs::spdx(&packages),
                    _ => result.clone(),
                };
                emit(&format!("{}\n", serde_json::to_string_pretty(&output)?))?;
                return Ok(
                    if !array(&result["errors"]).is_empty()
                        || options.inventory.oci.is_some() && result["status"] != "complete"
                    {
                        2
                    } else {
                        0
                    },
                );
            }
            let result = Value::Object(check(&options, &mut store)?);
            if format == "json" {
                for note in strings(&result["experimental"]) {
                    eprintln!("Experimental: {note}");
                }
                emit(&format!("{}\n", serde_json::to_string_pretty(&result)?))?;
            } else {
                emit(&summary(command, &result))?;
            }
            if result["status"] == "no-known-findings" && array(&result["packages"]).is_empty() {
                if array(&result["completed_paths"]).is_empty() {
                    eprintln!("{COPY_NOTHING_TO_SCAN}");
                } else {
                    eprintln!(
                        "No package versions found: the lockfiles read declare no dependencies."
                    );
                }
            }
            Ok(if result["status"] == "unknown" {
                2
            } else if !array(&result["findings"]).is_empty() {
                3
            } else {
                0
            })
        }
        "agentbom" => agentbom(&rest, &state),
        "mail" => {
            if rest.iter().any(|s| s == "--help" || s == "-h") {
                outln(format_args!("Usage: vorda mail {{list,read,ack,snooze}} --reader NAME [--id INTEGER] [--seconds INTEGER] [--limit N]\n\nlist shows the oldest 20 unread messages unless --limit raises it."))?;
                return Ok(0);
            }
            let action = match rest.first() {
                Some(s) if ["list", "read", "ack", "snooze"].contains(&s.as_str()) => s,
                Some(s) if !s.starts_with('-') => {
                    return Err(Error::usage(format!(
                        "unrecognized mail action {s:?}; use list, read, ack or snooze"
                    )))
                }
                _ => return Err(Error::usage("mail action is required")),
            };
            let mut reader = None;
            let mut id = serde_json::Number::from(0);
            let mut seconds = serde_json::Number::from(3600);
            let mut limit = crate::store::MAIL_PAGE;
            let mut iter = rest[1..].iter();
            while let Some(arg) = iter.next() {
                // Mail output is always JSON, so --json is accepted and changes nothing.
                if arg == "--json" {
                    continue;
                }
                let value = iter
                    .next()
                    .filter(|value| {
                        !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V")
                    })
                    .ok_or_else(|| Error::usage(format!("{arg} requires a value")))?;
                match arg.as_str() {
                    "--reader" => reader = Some(value.as_str()),
                    "--limit" if action.as_str() == "list" => {
                        limit = Some(value)
                            .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
                            .and_then(|v| v.parse().ok())
                            .filter(|n| *n > 0)
                            .ok_or_else(|| Error::usage("--limit must be a positive integer"))?
                    }
                    "--id" | "--seconds" => {
                        let n = crate::domain::integer(value)
                            .map_err(|_| Error::usage(format!("{arg} must be an integer")))?;
                        if arg == "--id" {
                            id = n;
                        } else {
                            seconds = n;
                        }
                    }
                    _ => return Err(Error::usage(format!("unrecognized mail argument: {arg}"))),
                }
            }
            let reader = reader.ok_or_else(|| Error::usage("--reader is required"))?;
            if ["ack", "snooze"].contains(&action.as_str()) && id.as_f64().is_some_and(|n| n <= 0.0)
            {
                return Err(Error::usage("--id is required"));
            }
            let mut store = Store::open(&state)?;
            let mut mail = store.mail(reader, action, &id, &seconds)?;
            if action.as_str() == "list" {
                let (page, more) = crate::store::page(mail, 0, limit);
                if more > 0 {
                    eprintln!(
                        "Showing {}; {more} more. Pass --limit {} to list them all.",
                        plural(page.len(), "unread message", "unread messages"),
                        page.len() + more
                    );
                }
                mail = Value::Array(page);
            }
            emit(&format!("{}\n", serde_json::to_string_pretty(&mail)?))?;
            Ok(0)
        }
        "dashboard" | "mcp" | "repair" | "repair-mcp" | "connect" | "mode" | "can" | "hook"
        | "snippet" | "watch" | "fix" => {
            let mut argv = vec![command.clone()];
            argv.extend(rest);
            crate::surfaces::run(&argv, &state)
        }
        _ => Err(Error::usage(format!("unrecognized command: {command}"))),
    }
}

/// `vorda db update|status`: refresh or show the offline advisory database.
fn advisory_db(rest: &[String]) -> Result<i32> {
    const USAGE: &str = "Usage: vorda db update [--ecosystem NAME]... [--from DIR] [--json]\n       vorda db status [--json]\n\nupdate downloads OSV per-ecosystem exports (all.zip) and the CISA KEV list to build the local offline advisory database (VORDA_ADVISORY_DB_DIR, default ~/.cache/vorda/advisory-db). OSV exports carry no completeness marker, so update replaces an index only when readable and large enough: it keeps the current index if an export has fewer than 90% of the most entries a clean index has held, or under about half of a complete export for its ecosystem (VORDA_ADVISORY_DB_MIN_ENTRIES overrides this for a small private mirror). --from reads DIR/<Ecosystem>/all.zip and DIR/kev.json instead of downloading; their age is the files' modification time. Ecosystems: npm, PyPI, crates.io, Go (default: all). update exits 2 unless every line is `updated`; it also exits 2 if the copy just loaded is already older than the VORDA_ADVISORY_DB_MAX_AGE_HOURS limit (default 72; that line reads `updated-stale`). status shows what `scan --offline-db` (default scan) would use and exits 2 unless every line is ready; an index older than that limit is not used.";
    let action = rest.first().map(String::as_str);
    if !matches!(action, Some("update" | "status")) {
        if rest.is_empty() || rest[0] == "--help" || rest[0] == "-h" {
            outln(format_args!("{USAGE}"))?;
            return Ok(0);
        }
        let action = format!("{:?}", rest[0]);
        return Err(Error::usage(format!(
            "unrecognized db action {action}; use update or status (see vorda db --help)"
        )));
    }
    let (mut ecosystems, mut from, mut as_json) = (Vec::new(), None, false);
    let mut iter = rest[1..].iter();
    while let Some(arg) = iter.next() {
        let mut value = || {
            iter.next()
                .filter(|value| !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V"))
                .ok_or_else(|| Error::usage(format!("{arg} requires a value")))
        };
        match arg.as_str() {
            "--ecosystem" if action == Some("update") => ecosystems.push(value()?.clone()),
            "--from" if action == Some("update") => from = Some(PathBuf::from(value()?)),
            "--json" => as_json = true,
            "--help" | "-h" => {
                outln(format_args!("{USAGE}"))?;
                return Ok(0);
            }
            _ => return Err(Error::usage(format!("unrecognized db argument: {arg}"))),
        }
    }
    let (lines, ok_word) = if action == Some("update") {
        (
            scanner::osvdb::update(&ecosystems, from.as_deref())?,
            "updated",
        )
    } else {
        (scanner::osvdb::status(), "ready")
    };
    let ok = lines
        .iter()
        .all(|l| l["outcome"] == ok_word || l["state"] == ok_word);
    if as_json {
        emit(&format!("{}\n", serde_json::to_string_pretty(&lines)?))?;
    } else {
        let mut out = String::new();
        for l in &lines {
            let word = l["outcome"].as_str().or(l["state"].as_str()).unwrap_or("");
            out.push_str(&match l["error"].as_str() {
                Some(e) => format!("{}: {word}: {e}\n", string_of(&l["ecosystem"])),
                None => format!(
                    "{}: {word}, fetched {} from {}{}\n",
                    string_of(&l["ecosystem"]),
                    string_of(&l["fetched_at"]),
                    string_of(&l["source_url"]),
                    l["records"]
                        .as_u64()
                        .map(|n| format!(", {n} advisories"))
                        .unwrap_or_default()
                ),
            });
        }
        emit(&out)?;
    }
    Ok(if ok { 0 } else { 2 })
}

fn string_of(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

/// Print to stdout; a reader that closed the pipe early (`vorda scan | head`) is not an error.
pub(crate) fn emit(text: &str) -> Result<()> {
    use std::io::Write;
    match std::io::stdout().lock().write_all(text.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

/// `println!` that, like `emit`, treats a closed pipe as the end of output.
pub(crate) fn outln(text: std::fmt::Arguments) -> Result<()> {
    emit(&format!("{text}\n"))
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Finding priority levels, most urgent first (`priority.level` in the JSON).
const LEVELS: [&str; 4] = ["critical", "high", "medium", "low"];
const UNRATED: &str = "unrated";
const DEV_ONLY: &str = "dev-only";
const COPY_VULNERABLE_INCOMPLETE: &str = "The listed findings are real (exit 3), but some files or entries failed or were not checked (listed below); more findings may exist in what was not checked.\n";
const COPY_NOTHING_TO_SCAN: &str = "Nothing to scan: no recognized dependency files found, so the result is no-known-findings (exit 0). Add a supported lockfile or pinned requirements.txt, or run `vorda scan --os-packages` to check installed OS packages.";
const COPY_CLEAN_WITH_GAPS: &str = "Not a clean result (exit 2): checked packages had no known findings, but the skipped files or entries listed below could hold a vulnerable package; fix what is listed, or leave a folder or file out on purpose with --exclude PATH.\n";
const COPY_NOT_CHECKED: &str = "Not checked";
const COPY_MACHINE: &str = "Machine scan: OS packages, tools, browsers, installed apps (Windows only), and projects under {home} (skipped folders: {n}). To scan one project, run vorda scan PATH.\n";
const COPY_NO_HOME: &str = "Cannot find a home folder (HOME, or USERPROFILE on Windows, is unset or empty), so nothing was scanned. Run vorda scan PATH to scan one project.";
const COPY_NOT_ASSESSED: &str = "Not assessed by design; does not make the scan unknown";
const COPY_EXCLUDED: &str = "Excluded:";
const COPY_EXCLUDE_HELP: &str = "--exclude PATH  Leave a folder or file under a root out of the scan on purpose (repeatable). Excluded paths appear in the summary and JSON \"excluded\" field and are not checked, so the result says nothing about them. Scans with --exclude are saved separately from full scans and never close findings a full scan saved.";

const COPY_EXCLUDE_MISSED: &str = "--exclude {path} was not reached (it does not exist or is not under a scanned root), so nothing was left out; the path is not listed as excluded and the scan is saved as a full scan.";
const COPY_LINKED_SKIPPED: &str = "Skipped {n} symlinked folders because each points to a folder already inside the scan and read there, so nothing was missed (see \"warnings\" in --json output for the full list).";
const COPY_TEST_DATA_SKIPPED: &str = "{n} files in test or example folders were not checked and did not make the scan unknown (see \"warnings\" in --json output for the full list; scan the folder with --root to check it strictly).";

/// The default scan output: a few lines a person can act on. `--json` has the rest.
fn summary(command: &str, result: &Value) -> String {
    let findings = array(&result["findings"]);
    // A failed delivery alone makes the result unknown, so the summary names it too.
    let mut errors = array(&result["errors"]);
    errors.extend(array(&result["delivery_errors"]).into_iter().map(|e| {
        json!({"source": format!("delivery to {}", e["channel"].as_str().unwrap_or("?")), "error": e["error"]})
    }));
    let found = array(&result["packages"]).len();
    let unchecked: Vec<(&String, u64)> = result["ecosystems"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(e, c)| Some((e, c["not_assessed"].as_u64().filter(|n| *n > 0)?)))
        .collect();
    let unassessed: u64 = unchecked.iter().map(|(_, n)| n).sum();
    let checked = match unassessed {
        0 => format!("{} checked", plural(found, "package", "packages")),
        n => format!(
            "{} of {} checked, {n} not assessed",
            (found as u64).saturating_sub(n),
            plural(found, "package", "packages")
        ),
    };
    let cwd = std::env::current_dir().unwrap_or_default();
    // One line per package version, however many lockfiles list it. The key is the whole
    // package manager, name and version; the cut-short label is for display only.
    let mut groups: Vec<(String, String, Vec<String>, Vec<&Value>)> = Vec::new();
    for finding in &findings {
        let p = &finding["package"];
        // JSON-quoted parts, so no two different triples join to the same key.
        let key = json!([p["ecosystem"], p["name"], p["version"]]).to_string();
        let package = format!(
            "{} {}",
            clipped(p["name"].as_str().unwrap_or("?")),
            clipped(p["version"].as_str().unwrap_or("?"))
        );
        let path = Path::new(p["path"].as_str().unwrap_or("?"));
        let path = shown(
            &path
                .strip_prefix(&cwd)
                .unwrap_or(path)
                .display()
                .to_string(),
        );
        match groups.iter_mut().find(|(k, ..)| *k == key) {
            Some((_, _, paths, group)) => {
                if !paths.contains(&path) {
                    paths.push(path);
                }
                group.push(finding);
            }
            None => groups.push((key, package, vec![path], vec![finding])),
        }
    }
    let level = |f: &Value| {
        LEVELS
            .iter()
            .position(|l| f["priority"]["level"] == *l)
            .unwrap_or(LEVELS.len())
    };
    let dev_only = |group: &[&Value]| {
        group
            .iter()
            .all(|f| f["package"]["scope"] == "likely-dev-only")
    };
    // Most urgent first: priority, then known exploited, then runtime before dev-only. The
    // name and key break ties, so every run prints the same lines.
    groups.sort_by_cached_key(|(key, package, _, group)| {
        (
            group.iter().map(|f| level(f)).min(),
            std::cmp::Reverse(group.iter().filter(|f| f["kev"] == true).count()),
            dev_only(group),
            package.clone(),
            key.clone(),
        )
    });
    for (_, _, paths, group) in &mut groups {
        paths.sort();
        group.sort_by(|a, b| a["advisory"].as_str().cmp(&b["advisory"].as_str()));
    }
    let (gaps, errors): (Vec<Value>, Vec<Value>) =
        errors.into_iter().partition(|e| e["not_covered"] == true);
    let status = result["status"].as_str().unwrap_or("unknown");
    // An experimental result leads with why its count can mislead, before the count.
    let mut out: String = strings(&result["experimental"])
        .iter()
        .map(|note| format!("Experimental: {note}\n"))
        .collect();
    out.push_str(&format!("Vorda {command}: {status}, {checked}\n"));
    if result["machine"] == true {
        let skipped = array(&result["coverage_evidence"]["observations"])
            .iter()
            .filter(|e| e["kind"] == "skipped-folder")
            .count();
        out.push_str(
            &COPY_MACHINE
                .replace(
                    "{home}",
                    &shown(
                        &strings(&result["scan_roots"])
                            .into_iter()
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                )
                .replace("{n}", &skipped.to_string()),
        );
    }
    if result["advisory_source"] == "offline-db" {
        out.push_str("Advisories: local offline database (no network); not ranked by EPSS exploit-likelihood score (online scans fetch it).\n");
    }
    if !unchecked.is_empty() {
        let list: Vec<_> = unchecked
            .iter()
            .map(|(e, n)| format!("{e} ({n})"))
            .collect();
        out.push_str(&format!(
            "Not assessed: {}.{}\n",
            list.join(", "),
            if result["advisory_source"] == "offline-db" {
                " --online checks ecosystems the offline database does not cover."
            } else {
                ""
            }
        ));
    }
    let checked_any = !array(&result["packages"]).is_empty();
    match status {
        "unknown" if errors.is_empty() && !gaps.is_empty() && checked_any => {
            out.push_str(COPY_CLEAN_WITH_GAPS)
        }
        "unknown" => out.push_str(
            "The scan is incomplete, so this is not a clean result. Read the errors below.\n",
        ),
        "vulnerable" if !gaps.is_empty() || !errors.is_empty() => {
            out.push_str(COPY_VULNERABLE_INCOMPLETE)
        }
        // stderr says why nothing was checked.
        "no-known-findings" if !checked_any => {}
        "no-known-findings" => out.push_str("No known vulnerabilities in the packages checked.\n"),
        _ => {}
    }
    if !groups.is_empty() {
        let mut counts: Vec<String> = LEVELS
            .iter()
            .chain([&UNRATED])
            .enumerate()
            .filter_map(|(rank, word)| {
                let n = findings.iter().filter(|f| level(f) == rank).count();
                (n > 0).then(|| format!("{n} {word}"))
            })
            .collect();
        let dev = findings
            .iter()
            .filter(|f| f["package"]["scope"] == "likely-dev-only")
            .count();
        if dev > 0 {
            counts.push(format!("{dev} {DEV_ONLY}"));
        }
        out.push_str(&format!(
            "{} in {} ({}):\n",
            plural(findings.len(), "finding", "findings"),
            plural(groups.len(), "package", "packages"),
            counts.join(", ")
        ));
    }
    for (_, package, paths, group) in groups.iter().take(8) {
        let tag = LEVELS
            .get(group.iter().map(|f| level(f)).min().unwrap_or(LEVELS.len()))
            .unwrap_or(&UNRATED);
        let mut advisories: Vec<&str> = Vec::new();
        let mut kev = 0;
        for f in group {
            let id = f["advisory"].as_str().unwrap_or("");
            if id.is_empty() || !advisories.contains(&id) {
                advisories.push(id);
                kev += usize::from(f["kev"] == true);
            }
        }
        let per_advisory: Vec<Vec<&str>> = group
            .iter()
            .map(|f| {
                f["fixed"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect()
            })
            .collect();
        let installed = &group[0]["package"];
        // Lowest first on the installed release line where the version scheme is known;
        // otherwise in advisory order, each in the feed's own order.
        let mut fixed = scanner::versions::upgrades(
            installed["ecosystem"].as_str().unwrap_or(""),
            installed["version"].as_str().unwrap_or(""),
            &per_advisory,
        )
        .filter(|up| !up.is_empty())
        .unwrap_or_default();
        if fixed.is_empty() {
            for v in per_advisory.iter().flatten() {
                if !fixed.contains(v) {
                    fixed.push(v);
                }
            }
        }
        let fixed: Vec<String> = fixed.into_iter().map(clipped).collect();
        let place = match paths.len() {
            1 => paths[0].clone(),
            n => format!("{} and {}", paths[0], plural(n - 1, "other", "others")),
        };
        out.push_str(&format!(
            "  [{tag}] {package} ({place}): {}{}{}{}\n",
            plural(advisories.len(), "advisory", "advisories"),
            if kev > 0 {
                format!(", {kev} known exploited")
            } else {
                String::new()
            },
            match fixed.len() {
                // The advisory's own title says what kind it is, such as unmaintained.
                0 => match group.iter().find_map(|f| f["summary"].as_str()) {
                    Some(text) if advisories.len() == 1 => {
                        format!("; no fixed version listed ({})", clipped(text))
                    }
                    _ => "; no fixed version listed".to_string(),
                },
                1..=3 => format!("; fixed in {}", shown(&fixed.join(", "))),
                _ => "; several fixed versions, see --json".to_string(),
            },
            if dev_only(group) {
                format!("; {DEV_ONLY}")
            } else {
                String::new()
            }
        ));
    }
    if groups.len() > 8 {
        out.push_str(&format!("  ... and {} more packages\n", groups.len() - 8));
    }
    let not_assessed: Vec<Value> = array(&result["not_assessed"])
        .iter()
        .map(|n| {
            let count = array(&n["packages"]).len();
            json!({"source":n["source"],"error":if count == 0 {
                n["reason"].as_str().unwrap_or("").to_string()
            } else {
                format!("{} ({})", n["reason"].as_str().unwrap_or(""), plural(count, "package", "packages"))
            }})
        })
        .collect();
    for (heading, list) in [
        (plural(errors.len(), "error", "errors"), &errors),
        (format!("{COPY_NOT_CHECKED} ({})", gaps.len()), &gaps),
        (
            format!("{COPY_NOT_ASSESSED} ({})", not_assessed.len()),
            &not_assessed,
        ),
    ] {
        if list.is_empty() {
            continue;
        }
        out.push_str(&format!("{heading}:\n"));
        for error in list.iter().take(3) {
            let text = match (error.as_str(), error["error"].as_str()) {
                (Some(text), _) => text.to_string(),
                (None, Some(text)) => match error["source"].as_str() {
                    Some(source) => format!("{source}: {text}"),
                    None => text.to_string(),
                },
                _ => error.to_string(),
            };
            out.push_str(&format!("  {}\n", shown(&text)));
        }
        if list.len() > 3 {
            out.push_str(&format!("  ... and {} more\n", list.len() - 3));
        }
    }
    let excluded = strings(&result["excluded"]);
    if !excluded.is_empty() {
        let excluded: Vec<String> = excluded.iter().map(|p| shown(p)).collect();
        out.push_str(&format!("{COPY_EXCLUDED} {}\n", excluded.join(", ")));
    }
    if !findings.is_empty() {
        out.push_str("Findings saved locally: vorda dashboard (browser) or vorda mail list --reader NAME (JSON for scripts/AI agents; any label like claude, tracks what each read).\n");
    }
    out.push_str(&format!("Full result: vorda {command} --json\n"));
    out
}

/// Names, paths and errors come from untrusted files and feeds: no control codes, line breaks,
/// invisible characters or text-direction overrides.
fn shown(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}' => '?',
            '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' => '?',
            '\u{E0000}'..='\u{E007F}' => '?',
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

/// A package name or version from a lockfile or feed, cut short so one line stays readable.
fn clipped(text: &str) -> String {
    let text = shown(text);
    match text.char_indices().nth(120) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

fn bom_rows(store: &Store) -> Result<Vec<Value>> {
    let exists: bool = store.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='asset_observations')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(vec![]);
    }
    let raw: Vec<String> = store
        .db
        .prepare("SELECT payload FROM asset_observations")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    raw.iter().map(|s| Ok(serde_json::from_str(s)?)).collect()
}

fn agentbom(args: &[String], state: &Path) -> Result<i32> {
    let mut roots = Vec::new();
    let mut home = None;
    let mut host = None;
    let (mut models, mut include_home, mut offline, mut no_save) = (true, false, false, false);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" | "--home" | "--host" => {
                let value = iter
                    .next()
                    .filter(|value| {
                        !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V")
                    })
                    .ok_or_else(|| Error::usage(format!("{arg} requires a value")))?;
                match arg.as_str() {
                    "--root" => roots.push(PathBuf::from(value)),
                    "--home" => home = Some(PathBuf::from(value)),
                    _ => host = Some(value.clone()),
                }
            }
            "--no-models" => models = false,
            "--include-home" => include_home = true,
            "--offline" => offline = true,
            "--no-save" => no_save = true,
            "--help" | "-h" => {
                outln(format_args!("Usage: vorda agentbom [--root DIR] [--home DIR] [--host HOST] [--include-home] [--offline] [--no-save] [--no-models]"))?;
                return Ok(0);
            }
            _ => {
                return Err(Error::usage(format!(
                    "unrecognized agentbom argument: {arg}"
                )))
            }
        }
    }
    let home = input::absolute(&home.unwrap_or_else(crate::repair::commands::home))?;
    if home.ancestors().any(input::linked) {
        return Err(Error::new("selected home is linked"));
    }
    let host = match host {
        Some(host) => host,
        None => crate::store::hostname()?,
    };
    let bom = scanner::agentbom::collect(&home, &roots, &host, models, include_home)?;
    let output = assess_agentbom(state, bom, offline, no_save)?;
    emit(&format!("{}\n", serde_json::to_string_pretty(&output)?))?;
    Ok(if output["status"] == "unknown" {
        2
    } else if output["findings"].as_array().is_some_and(|f| f.is_empty()) {
        0
    } else {
        1
    })
}

pub fn assess_agentbom(
    state: &Path,
    bom: scanner::agentbom::Bom,
    offline: bool,
    no_save: bool,
) -> Result<Value> {
    let start = Instant::now();
    let host = bom.host.clone();
    let mut store = Store::open(state)?;
    let offline_db = scanner::osvdb::configured(&store.root)?;
    if offline_db && offline {
        return Err(Error::usage(
            "--offline and the offline advisory database cannot be combined",
        ));
    }
    let cves = Value::Object(if offline_db {
        scanner::agentbom::match_packages(
            &bom,
            &mut scanner::osvdb::LocalDb::new(&scanner::osvdb::root()),
        )?
    } else {
        scanner::agentbom::match_packages(
            &bom,
            &mut scanner::feeds::Fetch::new(&store.root.join("cache"), offline),
        )?
    });
    let mut errors = bom.errors.clone();
    errors.extend(array(&cves["errors"]));
    let severity = |v: &Value| {
        ["critical", "high", "medium", "low", "info"]
            .iter()
            .position(|s| v["severity"] == *s)
            .unwrap_or(9)
    };
    let mut findings = bom.findings.clone();
    findings.sort_by(|a, b| {
        severity(a)
            .cmp(&severity(b))
            .then_with(|| a["title"].as_str().cmp(&b["title"].as_str()))
    });
    findings.extend(array(&cves["findings"]));
    let status = if !errors.is_empty() || bom.incomplete || offline {
        "unknown"
    } else if findings.is_empty() {
        "no-known-findings"
    } else if array(&cves["findings"]).is_empty()
        && bom
            .findings
            .iter()
            .all(|f| f["evidence_basis"] == "static-text-pattern")
    {
        "attention"
    } else {
        "vulnerable"
    };
    let scope = identity(&json!(["agentbom", host, bom.scope]))?;
    if !no_save {
        let _lock = store.locked()?;
        store.db.execute_batch("CREATE TABLE IF NOT EXISTS bom(host TEXT,kind TEXT,name TEXT,version TEXT,source TEXT)")?;
        let legacy: BTreeSet<(String, String, String, String, String)> = store
            .db
            .prepare("SELECT host,kind,name,version,source FROM bom WHERE host=?")?
            .query_map([&host], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        let previous: BTreeSet<_> = crate::assets::bom_records(&bom_rows(&store)?)
            .into_keys()
            .collect();
        let coverage = scanner::agentbom::covered(
            &bom,
            &cves,
            &store
                .active()?
                .into_iter()
                .map(Value::Object)
                .collect::<Vec<_>>(),
        )?;
        let records: Vec<Record> = findings
            .iter()
            .map(|v| {
                v.as_object()
                    .cloned()
                    .ok_or_else(|| Error::new("invalid BOM finding"))
            })
            .collect::<Result<_>>()?;
        // This save holds the scanner lock, so an earlier lock-timeout finding is over.
        let mut closable = coverage.clone();
        closable.insert("health:lock".into());
        store.reconcile(&records, &closable, &[])?;
        let items = bom
            .items
            .iter()
            .map(|v| {
                v.as_object()
                    .cloned()
                    .ok_or_else(|| Error::new("invalid BOM item"))
            })
            .collect::<Result<Vec<_>>>()?;
        let current = crate::assets::observations(&bom.packages, &items, Some(&host))?;
        crate::assets::save(
            &mut store,
            &scope,
            &current,
            &coverage,
            status != "unknown" && bom.skip_kinds.is_empty(),
            None,
        )?;
        let present: BTreeSet<_> = current
            .iter()
            .filter_map(|r| r.get("id").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        let observations: Vec<(String, String)> = store
            .db
            .prepare("SELECT id,payload FROM asset_observations WHERE scope=?")?
            .query_map([&scope], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let tx = store.db.transaction()?;
        for (id, payload) in observations {
            if !present.contains(&id)
                && strings(&serde_json::from_str::<Value>(&payload)?["aliases"])
                    .iter()
                    .any(|a| coverage.contains(a))
            {
                tx.execute(
                    "DELETE FROM asset_observations WHERE scope=? AND id=?",
                    params![scope, id],
                )?;
            }
        }
        tx.commit()?;
        let retained: BTreeSet<_> = crate::assets::bom_records(&bom_rows(&store)?)
            .into_keys()
            .collect();
        let mut rows: BTreeSet<_> = legacy.difference(&previous).cloned().collect();
        rows.extend(retained);
        rows.retain(|r| r.0 == host);
        let tx = store.db.transaction()?;
        tx.execute("DELETE FROM bom WHERE host=?", [&host])?;
        for (host, kind, name, version, source) in rows {
            tx.execute(
                "INSERT INTO bom VALUES(?,?,?,?,?)",
                params![host, kind, name, version, source],
            )?;
        }
        tx.commit()?;
    }
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for item in &bom.items {
        *counts
            .entry(item["kind"].as_str().unwrap_or("").into())
            .or_default() += 1;
    }
    let packages: BTreeSet<_> = bom
        .packages
        .iter()
        .map(|p| (&p.ecosystem, &p.name, &p.version))
        .collect();
    let mut output = json!({"host":host,"status":status,"seconds":(start.elapsed().as_secs_f64()*1000.0).round()/1000.0,"counts":counts,"findings":findings,"items":bom.items,"posture":bom.posture,"packages":packages.len(),"errors":errors,"warnings":array(&cves["warnings"]),"sources":cves["sources"],"coverage":{"cve":"npm and PyPI packages via OSV/KEV/EPSS","inventory_only":["ide-extension","model","skill","hook","OCI image"]}});
    if !no_save {
        output["assets"] =
            crate::assets::summary(&store.db, None, Some(&BTreeSet::from([scope.clone()])))?;
    }
    output["coverage"]["skipped_kinds"] = json!(bom.skip_kinds);
    output["coverage"]["incomplete"] = json!(bom.incomplete);
    Ok(output)
}

pub struct Assessment {
    pub result: Record,
    findings: Vec<Record>,
    covered: BTreeSet<String>,
    resolved: BTreeSet<String>,
    channels: Vec<String>,
    packages: Vec<Package>,
    scope: String,
    complete: bool,
    started: Instant,
    observed: Option<f64>,
}

pub fn assess(options: &ScanOptions, store: &Store) -> Result<Assessment> {
    let start = Instant::now();
    let roots = if options.inventory.roots.is_empty() {
        vec![std::env::current_dir()?]
    } else {
        options.inventory.roots.clone()
    };
    let mut selected: Vec<_> = roots
        .iter()
        .map(|r| Ok(resolved(r)?.to_string_lossy().into_owned()))
        .collect::<Result<_>>()?;
    selected.sort();
    let mut scope_parts = vec![
        json!(selected),
        json!(options.inventory.os_packages),
        json!(options.inventory.tools),
        json!(options.inventory.browsers),
        json!(options
            .inventory_file
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| if options.mcp_scope { "" } else { "None" }.into())),
    ];
    if options.inventory.installed_apps || !options.inventory.installed_roots.is_empty() {
        scope_parts.extend([
            json!("installed"),
            json!(options.inventory.installed_apps),
            json!(options.inventory.installed_roots),
        ]);
    }
    if let Some(oci) = &options.inventory.oci {
        scope_parts.extend([json!("oci"), json!(resolved(oci)?.to_string_lossy())]);
    }
    // A machine scan skips folders a scan of the same home folder reads, so it is its own scope.
    if options.inventory.machine {
        scope_parts.push(json!("machine"));
    }
    crate::store::storage_admit(&store.root, 0)?;
    let mut input_options = options.inventory.clone();
    input_options.roots = roots.clone();
    input_options.cache_dir = Some(store.root.join("cache/browser-versions"));
    let mut inventory = if let Some(file) = &options.inventory_file {
        if options.inventory.oci.is_some() {
            scanner::inventory(&input_options)?
        } else {
            let document: Value =
                serde_json::from_slice(&input::read_regular(file, None, input::MAX_FILE, false)?)?;
            let mut errors = match document.get("errors") {
                Some(Value::Array(a)) if a.iter().all(|e| e.is_string() || e.is_object()) => {
                    a.clone()
                }
                Some(_) => return Err(Error::new("inventory errors must be a list of messages")),
                None => vec![],
            };
            let states: Vec<Value> = match document.get("coverage") {
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|c| c.get("status").cloned().unwrap_or(json!("unknown")))
                    .collect(),
                Some(Value::Object(m)) => m.values().cloned().collect(),
                Some(_) => vec![json!("unknown")],
                None => vec![],
            };
            let observed = document
                .get("observed")
                .and_then(Value::as_f64)
                .filter(|n| n.is_finite() && *n >= 0.0 && *n <= now());
            let fresh = observed
                .is_some_and(|n| n.is_finite() && (0.0..=2.0 * 86400.0).contains(&(now() - n)));
            if !["complete", "vulnerable", "no-known-findings"]
                .iter()
                .any(|s| document["status"] == *s)
                || states.iter().any(|s| s != "complete")
                || !fresh
            {
                errors.push(json!(
                    "Imported inventory completeness or freshness is unknown"
                ));
            }
            let packages = if document.is_object() {
                document.get("packages")
            } else {
                Some(&document)
            }
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Error::new("inventory must be a list of name/version/ecosystem/path/scope records")
            })?;
            if packages.iter().any(|p| {
                !p.is_object()
                    || ["name", "version", "ecosystem", "path", "scope"]
                        .iter()
                        .any(|k| !p[*k].as_str().is_some_and(|s| !s.is_empty()))
            }) {
                return Err(Error::new(
                    "inventory must be a list of name/version/ecosystem/path/scope records",
                ));
            }
            let completed: BTreeSet<_> = if errors.is_empty() {
                packages
                    .iter()
                    .filter_map(|p| p["path"].as_str().map(str::to_owned))
                    .collect()
            } else {
                BTreeSet::new()
            };
            json!({"packages":packages,"observed":observed.unwrap_or(0.0),"errors":errors,"completed_paths":completed,"input_evidence":{"status":if errors.is_empty(){"complete"}else{"partial"},"observations":[{"kind":"imported-inventory","path":file}]}}).as_object().unwrap().clone()
        }
    } else {
        scanner::inventory(&input_options)?
    };
    // A scan that leaves a path out never closes findings a full scan of the root saved. An
    // --exclude the walk never reached left nothing out: it is warned about and not listed.
    let observations = inventory
        .get("input_evidence")
        .and_then(|e| e.get("observations"));
    let reached: BTreeSet<String> = array(observations.unwrap_or(&Value::Null))
        .iter()
        .filter(|o| o["kind"] == "excluded")
        .filter_map(|o| o["path"].as_str().map(str::to_owned))
        .collect();
    let (excluded, missed): (BTreeSet<String>, BTreeSet<String>) = options
        .inventory
        .exclude
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .partition(|p| reached.contains(p));
    if !excluded.is_empty() {
        scope_parts.extend([json!("exclude"), json!(excluded)]);
    }
    let scope = identity(&json!(scope_parts))?;
    let archive_unknown =
        options.inventory.oci.is_some() && inventory.get("status") != Some(&json!("complete"));
    let mut errors = array(inventory.get("errors").unwrap_or(&Value::Null));
    let gaps = strings(inventory.get("coverage_gaps").unwrap_or(&Value::Null));
    if archive_unknown && errors.is_empty() {
        errors.push(json!("OCI archive package coverage is unknown"));
    }
    let packages: Vec<Package> =
        serde_json::from_value(inventory.remove("packages").unwrap_or(json!([])))?;
    let completed = if options.inventory.oci.is_some() {
        if archive_unknown {
            BTreeSet::new()
        } else {
            packages.iter().map(|p| p.path.clone()).collect()
        }
    } else {
        strings(inventory.get("completed_paths").unwrap_or(&Value::Null))
    };
    let mut warnings = array(inventory.get("warnings").unwrap_or(&Value::Null));
    warnings.extend(
        missed
            .iter()
            .map(|path| json!(COPY_EXCLUDE_MISSED.replace("{path}", path))),
    );
    let evidence = if options.inventory.oci.is_some() {
        json!({"status":inventory.get("status").unwrap_or(&json!("unknown")),"observations":if archive_unknown { vec![] } else { vec![json!({"kind":"completed-archive","path":options.inventory.oci})] }})
    } else {
        inventory
            .get("input_evidence")
            .cloned()
            .unwrap_or(json!({"status":"partial","observations":[]}))
    };
    let offline_db = match options.offline_db {
        Some(choice) => choice,
        None => scanner::osvdb::configured(&store.root)?,
    };
    if offline_db && options.offline {
        return Err(Error::usage(
            "--offline and the offline advisory database cannot be combined",
        ));
    }
    let mut result = Value::Object(if offline_db {
        scanner::feeds::scan(
            &packages,
            &mut scanner::osvdb::LocalDb::new(&scanner::osvdb::root()),
        )?
    } else {
        scanner::scan(&packages, &store.root.join("cache"), options.offline)?
    });
    warnings.extend(array(&result["warnings"]));
    result["warnings"] = json!(warnings);
    if let Some(image) = inventory.get("image") {
        result["image"] = image.clone();
    }
    for finding in result["findings"]
        .as_array_mut()
        .ok_or_else(|| Error::new("scanner findings required"))?
    {
        finding["scan_scope"] = json!(scope);
        finding["inventory_observed_at"] =
            inventory.get("observed").cloned().unwrap_or(json!(now()));
        finding["advisories_checked_at"] = json!(now());
    }
    if archive_unknown {
        result["covered"] = json!([]);
    }
    let mut all_errors = array(&result["errors"]);
    all_errors.extend(errors.iter().map(|error| {
        let mut error = json!({"source":"inventory","error":error});
        if error["error"].as_str().is_some_and(|e| gaps.contains(e)) {
            error["not_covered"] = json!(true);
        }
        error
    }));
    // A project you name is unknown, not clean, while some of its lockfile packages were never
    // checked. Machine scans, inventory files, images and lockfiles in test or example folders
    // below the root only list them under not_assessed; errors already make a scan unknown.
    if !options.inventory.roots.is_empty()
        && !options.inventory.machine
        && !options.offline
        && all_errors.is_empty()
    {
        let checked = strings(&result["covered"]);
        let named = options
            .inventory
            .roots
            .iter()
            .map(|r| input::absolute(r))
            .collect::<Result<Vec<_>>>()?;
        let mut unchecked = BTreeSet::new();
        for p in &packages {
            let path = Path::new(&p.path);
            let asset = asset(p)?;
            if p.extra.get("origin") == Some(&json!("project"))
                && named
                    .iter()
                    .any(|r| path.starts_with(r) && !scanner::inventory::test_data(path, r))
                && !checked.contains(&asset)
            {
                unchecked.insert(asset);
            }
        }
        if !unchecked.is_empty() {
            let sources: Vec<_> = array(&result["not_assessed"])
                .iter()
                .filter_map(|n| n["source"].as_str().map(str::to_owned))
                .collect();
            all_errors.push(json!({"source":"not-assessed","not_covered":true,"error":format!(
                "{} in the named project not assessed ({}), so a named project is unknown, not clean{}",
                plural(unchecked.len(), "lockfile package", "lockfile packages"),
                sources.join(", "),
                if offline_db { "; pass --online to check ecosystems the offline database does not cover" } else { "" }
            )}));
        }
    }
    result["errors"] = json!(all_errors);
    let mut health = std::collections::BTreeMap::new();
    for error in &all_errors {
        let source = error["source"].as_str().unwrap_or("inventory");
        let key = format!("health:{scope}:{source}");
        health.insert(key.clone(),json!({"key":key,"asset":key,"scan_scope":scope,"kind":"health","title":format!("Feed or scan unavailable: {source}"),"error":error["error"]}));
    }
    let prior = store.active()?;
    let mut covered = strings(&result["covered"]);
    covered.insert("health:lock".into());
    for f in &prior {
        if f.get("scan_scope") == Some(&json!(scope)) && f.get("kind") == Some(&json!("health")) {
            if let Some(key) = f.get("key").and_then(Value::as_str) {
                if !health.contains_key(key) {
                    covered.insert(key.into());
                }
            }
        }
    }
    let resolved: BTreeSet<String> = prior
        .iter()
        .filter(|f| {
            errors.is_empty()
                && !options.offline
                && f.get("scan_scope") == Some(&json!(scope))
                && array(&result["resolutions"]).iter().any(|r| {
                    f.get("advisory") == r.get("advisory")
                        && ["name", "ecosystem", "path", "scope"]
                            .iter()
                            .all(|field| f["package"][field] == r["package"][field])
                })
        })
        .filter_map(|f| f["key"].as_str().map(str::to_owned))
        .collect();
    let observed = inventory.get("observed").and_then(Value::as_f64);
    result["inventory_observed_at"] = json!(observed);
    result["advisories_checked_at"] = json!(now());
    let mut complete_paths = BTreeSet::new();
    if !options.offline {
        for path in completed {
            if packages
                .iter()
                .filter(|p| p.path == path)
                .all(|p| asset(p).is_ok_and(|a| covered.contains(&a)))
            {
                complete_paths.insert(path);
            }
        }
    }
    let selected_roots = roots
        .iter()
        .map(|r| input::absolute(r))
        .collect::<Result<Vec<_>>>()?;
    let authoritative_sources: Vec<Value> =
        array(inventory.get("source_outcomes").unwrap_or(&Value::Null))
            .iter()
            .filter(|s| {
                ["complete", "missing"].contains(&s["outcome"].as_str().unwrap_or(""))
                    && s["source"] != "selected-syft"
            })
            .cloned()
            .collect();
    result["inventory_sources"] = json!(authoritative_sources);
    let mut removals = Vec::new();
    if !options.offline {
        for f in &prior {
            let path = f
                .get("package")
                .and_then(|p| p.get("path"))
                .and_then(Value::as_str);
            let own_scope = f.get("scan_scope") == Some(&json!(scope));
            let source_removed = own_scope
                && path.is_some_and(|p| {
                    !packages.iter().any(|package| package.path == p)
                        && authoritative_sources
                            .iter()
                            .any(|source| crate::assets::source_contains(source, p))
                });
            let removed = source_removed
                || path.is_some_and(|p| {
                    let p = Path::new(p);
                    errors.is_empty()
                        && options.inventory_file.is_none()
                        && options.inventory.oci.is_none()
                        && p.is_absolute()
                        && !p.exists()
                        && !p.ancestors().any(input::linked)
                        && selected_roots.iter().any(|r| p.starts_with(r))
                });
            if removed {
                removals.push(json!({"kind":"observed-removal","path":path}));
            }
            if removed
                || path.is_some_and(|p| complete_paths.contains(p))
                    && (options.inventory_file.is_none() || own_scope)
                || options.inventory_file.is_some()
                    && errors.is_empty()
                    && evidence["status"] == "complete"
                    && own_scope
                    && path.is_some_and(|p| !packages.iter().any(|package| package.path == p))
            {
                if let Some(asset) = f.get("asset").and_then(Value::as_str) {
                    covered.insert(asset.into());
                }
            }
        }
    }
    let exists: bool = store.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='asset_observations')",
        [],
        |r| r.get(0),
    )?;
    let mut known = BTreeSet::new();
    if exists {
        for raw in store
            .db
            .prepare("SELECT payload FROM asset_observations WHERE scope=?")?
            .query_map(params![scope], |r| r.get::<_, String>(0))?
        {
            known.extend(strings(&serde_json::from_str::<Value>(&raw?)?["aliases"]));
        }
    }
    let retained = prior.iter().any(|f| {
        let asset = f.get("asset").and_then(Value::as_str).unwrap_or("");
        let path = f
            .get("package")
            .and_then(|p| p.get("path"))
            .and_then(Value::as_str)
            .map(Path::new);
        let selected = f.get("scan_scope") == Some(&json!(scope))
            || known.contains(asset)
            || path.is_some_and(|p| {
                p.is_absolute() && selected_roots.iter().any(|r| p.starts_with(r))
            });
        selected && f.get("kind") != Some(&json!("health")) && !covered.contains(asset)
    });
    let complete = all_errors.is_empty()
        && array(&result["not_assessed"]).is_empty()
        && !options.offline
        && !retained
        && (evidence["status"] == "complete" || !removals.is_empty());
    let mut observations = array(&evidence["observations"]);
    observations.extend(removals);
    result["coverage_evidence"] =
        json!({"status":if complete {"complete"} else {"partial"},"observations":observations});
    let mut channels = Vec::new();
    if let Some(url) = &options.webhook {
        channels.push(identity(&json!(["webhook", url]))?);
    }
    if let Some(url) = &options.ntfy {
        channels.push(identity(&json!(["ntfy", url]))?);
    }
    if options.desktop {
        channels.push(identity(&json!(["desktop", true]))?);
    }
    let mut persisted = array(&result["findings"]);
    persisted.extend(health.into_values());
    let records = persisted
        .into_iter()
        .map(|v| {
            v.as_object()
                .cloned()
                .ok_or_else(|| Error::new("invalid finding"))
        })
        .collect::<Result<Vec<_>>>()?;
    result["seconds"] = json!((start.elapsed().as_secs_f64() * 1000.0).round() / 1000.0);
    // Findings win over any error. Without findings, any error leaves the result unknown, including
    // a file or entry not checked (`not_covered`) and a named project's unassessed lockfile
    // packages: each could hide a vulnerable package. What a machine scan or an inventory file
    // only lists under not_assessed leaves coverage partial, not the result unknown.
    result["status"] = json!(if !array(&result["findings"]).is_empty() {
        "vulnerable"
    } else if options.offline || !all_errors.is_empty() {
        "unknown"
    } else {
        "no-known-findings"
    });
    result["scan_scope"] = json!(scope);
    result["scan_roots"] = json!(selected);
    if options.inventory.machine {
        result["machine"] = json!(true);
    }
    if !excluded.is_empty() {
        result["excluded"] = json!(excluded);
    }
    result["completed_paths"] = json!(complete_paths);
    Ok(Assessment {
        result: result.as_object().unwrap().clone(),
        findings: records,
        covered,
        resolved,
        channels,
        packages,
        scope,
        complete,
        started: start,
        observed,
    })
}

pub fn commit_assessment(assessment: Assessment, store: &mut Store) -> Result<Record> {
    commit_assessment_selected(assessment, store, false)
}

fn commit_assessment_selected(
    assessment: Assessment,
    store: &mut Store,
    captured: bool,
) -> Result<Record> {
    let Assessment {
        result,
        findings,
        covered,
        resolved,
        channels,
        packages,
        scope,
        complete,
        started,
        observed,
    } = assessment;
    let mut result = Value::Object(result);
    store.db.execute_batch("SAVEPOINT assessment")?;
    let publish = (|| -> Result<()> {
        let changed = store.reconcile_resolved(&findings, &covered, &resolved, &channels)?;
        result["new_messages"] = json!(changed.len());
        result["seconds"] = json!((started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0);
        crate::assets::save_selected(
            store,
            &scope,
            &crate::assets::observations(&packages, &[], None)?,
            &strings(&result["covered"]),
            complete,
            observed,
            captured,
        )?;
        crate::assets::retire_absent_sources(
            store,
            &scope,
            &packages,
            &array(&result["inventory_sources"]),
        )?;
        result["assets"] =
            crate::assets::summary(&store.db, None, Some(&BTreeSet::from([scope.clone()])))?;
        let finished = now();
        store.db.execute_batch("CREATE TABLE IF NOT EXISTS scans(host TEXT,started REAL,finished REAL,status TEXT,seconds REAL,findings INTEGER,errors TEXT,scan_scope TEXT,not_assessed TEXT)")?;
        let columns = store
            .db
            .prepare("PRAGMA table_info(scans)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for column in ["scan_scope", "not_assessed"] {
            if !columns.iter().any(|c| c == column) {
                store
                    .db
                    .execute_batch(&format!("ALTER TABLE scans ADD COLUMN {column} TEXT"))?;
            }
        }
        store.db.execute("INSERT INTO scans(host,started,finished,status,seconds,findings,errors,scan_scope,not_assessed) VALUES(?,?,?,?,?,?,?,?,?)",params![crate::store::hostname()?,finished-result["seconds"].as_f64().unwrap_or(0.0),finished,result["status"].as_str(),result["seconds"].as_f64(),result["findings"].as_array().map(Vec::len),result["errors"].to_string(),scope,json!(array(&result["not_assessed"])).to_string()])?;
        store.persist_assessment(&scope, &result)?;
        crate::store::storage_admit(&store.root, 0)?;
        Ok(())
    })();
    if let Err(error) = publish {
        // A failure such as a full database can end the transaction itself; the failed
        // rollback that follows must not hide the error that caused it.
        let _ = store
            .db
            .execute_batch("ROLLBACK TO assessment; RELEASE assessment");
        return Err(error);
    }
    store.db.execute_batch("RELEASE assessment")?;
    if store.db.is_autocommit() {
        store.recover_exports()?;
    }
    Ok(result.as_object().unwrap().clone())
}

pub fn check(options: &ScanOptions, store: &mut Store) -> Result<Record> {
    if options.inventory.scheduled && store.root.join("config.json").exists() {
        let config: Value =
            serde_json::from_slice(&std::fs::read(store.root.join("config.json"))?)?;
        if let Some(path) = config["path"].as_str() {
            std::env::set_var("PATH", path);
        }
    }
    let lock = store.locked()?;
    let assessment = assess(options, store)?;
    print_warnings(assessment.result.get("warnings").unwrap_or(&Value::Null));
    let mut result = Value::Object(commit_assessment(assessment, store)?);
    if array(&result["packages"]).iter().any(|p| {
        p["ecosystem"]
            .as_str()
            .is_some_and(|e| e.starts_with("Ubuntu:"))
    }) {
        result["experimental"] = json!([format!("os-packages on Ubuntu: {UBUNTU_EXPERIMENTAL}")]);
    }
    let delivery = crate::delivery::Options {
        webhook: options.webhook.clone(),
        ntfy: options.ntfy.clone(),
        desktop: options.desktop,
    };
    let current = crate::delivery::channel_keys(&delivery)?;
    if let Err(error) = crate::delivery::expire(store, &current) {
        eprintln!("Warning: delivery housekeeping skipped: {error}");
    }
    drop(lock);
    if !current.is_empty() {
        result["delivery_errors"] = crate::delivery::drain(store, &delivery)?;
        if result["status"] != "vulnerable"
            && result["delivery_errors"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        {
            result["status"] = json!("unknown");
        }
        atomic(
            &store.root.join("last-scan.json"),
            &serde_json::to_string_pretty(&result)?,
        )?;
    }
    Ok(result.as_object().unwrap().clone())
}

pub(crate) fn commit_capture_native(
    store: &mut Store,
    packages: Vec<Package>,
    scope: String,
) -> Result<()> {
    let result =
        json!({"status":"unknown","findings":[],"errors":[],"covered":[],"inventory_sources":[]});
    commit_assessment_selected(
        Assessment {
            result: result.as_object().unwrap().clone(),
            findings: vec![],
            covered: BTreeSet::new(),
            resolved: BTreeSet::new(),
            channels: vec![],
            packages,
            scope,
            complete: false,
            started: Instant::now(),
            observed: None,
        },
        store,
        true,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    #[test]
    fn windows_state_defaults_to_local_app_data_unless_the_old_folder_exists() {
        let home = std::env::temp_dir().join(format!("vorda-state-home-{}", uuid::Uuid::new_v4()));
        let local = home.join("AppData").join("Local");
        let legacy = home.join(".local").join("share").join("vorda");
        let pick = |l: Option<&std::path::Path>| {
            super::default_state(Some(home.clone().into()), l.map(Into::into))
        };
        assert_eq!(pick(None), legacy, "Linux and macOS are unchanged");
        assert_eq!(pick(Some(&local)), local.join("vorda").join("state"));
        std::fs::create_dir_all(&legacy).unwrap();
        assert_eq!(
            pick(Some(&local)),
            legacy,
            "an existing state folder stays in use"
        );
        std::fs::remove_dir_all(&home).unwrap();
    }

    fn finding(ecosystem: &str, name: &str, path: &str, advisory: &str, fixed: &str) -> Value {
        json!({"advisory":advisory,"fixed":[fixed],"package":{
            "ecosystem":ecosystem,"name":name,"version":"1.2.3","path":path}})
    }

    #[test]
    fn different_packages_never_share_a_summary_line() {
        let long = "x".repeat(130);
        let (a, b) = (format!("{long}a"), format!("{long}b"));
        let result = json!({"status":"vulnerable","packages":[{},{},{},{}],"findings":[
            finding("npm", "example", "/w/web/package-lock.json", "A-1", "1.2.4"),
            finding("PyPI", "example", "/w/api/requirements.txt", "B-1", "2.0"),
            finding("npm", &a, "/w/a/package-lock.json", "C-1", "3.0"),
            finding("npm", &b, "/w/b/package-lock.json", "D-1", "4.0"),
        ],"errors":[]});
        let text = super::summary("scan", &result);
        assert!(
            text.contains("4 findings in 4 packages (4 unrated):"),
            "{text}"
        );
        let lines: Vec<&str> = text.lines().filter(|l| l.contains("advisory")).collect();
        assert_eq!(lines.len(), 4, "{text}");
        for (path, fixed) in [
            ("web/package-lock.json", "1.2.4"),
            ("api/requirements.txt", "2.0"),
            ("a/package-lock.json", "3.0"),
            ("b/package-lock.json", "4.0"),
        ] {
            assert!(
                lines.iter().any(|l| l.contains(path)
                    && l.ends_with(&format!("1 advisory; fixed in {fixed}"))
                    && !l.contains("other")),
                "{path}: {text}"
            );
        }
    }

    #[test]
    fn summary_lines_do_not_depend_on_finding_order() {
        let mut findings = vec![
            finding("npm", "zod", "/w/b/package-lock.json", "B-2", "4.0"),
            finding("npm", "zod", "/w/a/package-lock.json", "B-1", "3.0"),
            finding("npm", "axios", "/w/a/package-lock.json", "A-1", "1.0"),
        ];
        let summary = |findings: &[Value]| {
            let result =
                json!({"status":"vulnerable","packages":[{},{}],"findings":findings,"errors":[]});
            super::summary("scan", &result)
        };
        let first = summary(&findings);
        findings.reverse();
        assert_eq!(first, summary(&findings));
        let axios = first.find("axios").unwrap();
        assert!(axios < first.find("zod").unwrap(), "{first}");
        assert!(first.contains("a/package-lock.json and 1 other"), "{first}");
        assert!(first.contains("fixed in 3.0, 4.0"), "{first}");
    }

    #[test]
    fn the_most_urgent_package_comes_first_and_dev_only_ones_are_marked() {
        let rated = |name: &str, level: &str, scope: &str| {
            let mut f = finding("npm", name, "/w/package-lock.json", name, "9.0");
            f["priority"] = json!({"level": level});
            f["package"]["scope"] = json!(scope);
            f
        };
        let result = json!({"status":"vulnerable","packages":[{},{},{}],"errors":[],"findings":[
            rated("aaa", "low", "runtime"),
            rated("mmm", "high", "likely-dev-only"),
            rated("zzz", "critical", "runtime"),
        ]});
        let text = super::summary("scan", &result);
        let lines: Vec<&str> = text.lines().filter(|l| l.contains("advisory")).collect();
        assert!(lines[0].contains("[critical] zzz"), "{text}");
        assert!(
            lines[1].contains("[high] mmm") && lines[1].ends_with(super::DEV_ONLY),
            "{text}"
        );
        assert!(
            lines[2].contains("[low] aaa") && !lines[2].contains(super::DEV_ONLY),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "(1 critical, 1 high, 1 low, 1 {}):",
                super::DEV_ONLY
            )),
            "{text}"
        );
    }

    #[test]
    fn fixed_versions_are_upgrades_on_the_installed_line_and_an_unfixed_one_says_why() {
        let mut other_line = finding("npm", "example", "/w/package-lock.json", "A-1", "2.0.0");
        other_line["fixed"] = json!(["2.0.0", "1.2.9", "1.1.0"]);
        let unfixed = |name: &str| {
            let mut f = finding("crates.io", name, "/w/Cargo.lock", "R-1", "");
            f["fixed"] = json!([]);
            f["summary"] = json!(format!("{name} is unmaintained"));
            f
        };
        let result = json!({"status":"vulnerable","packages":[{},{}],"errors":[],"findings":[
            other_line,
            finding("npm", "example", "/w/package-lock.json", "A-2", "1.2.5"),
            unfixed("chrono"),
        ]});
        let text = super::summary("scan", &result);
        assert!(
            text.contains("2 advisories; fixed in 1.2.5, 1.2.9\n"),
            "{text}"
        );
        assert!(
            text.contains("1 advisory; no fixed version listed (chrono is unmaintained)\n"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_delivery_is_listed_with_the_errors() {
        let result = json!({"status":"unknown","packages":[{}],"findings":[],"errors":[],
            "delivery_errors":[{"channel":"webhook","error":"connection refused"}]});
        let text = super::summary("scan", &result);
        assert!(
            text.contains("1 error:\n  delivery to webhook: connection refused"),
            "{text}"
        );
    }
}
