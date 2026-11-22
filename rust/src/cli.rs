use crate::domain::{Package, Record, ScanOptions};
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

Check:
  scan          Check lockfiles and pinned requirements (and, if asked, OS packages, tools, browsers, apps, images) for known vulnerabilities
  check         Same as scan
  inventory     List the packages a scan would check, without looking up advisories
  db            Download or show the offline advisory database that scan uses by default (same as --offline-db)
  agentbom      List AI agent tooling (MCP servers, skills, models) and check it (preview)
Read results:
  mail          List, read, acknowledge or snooze saved findings
  dashboard     Serve the local web dashboard of saved scans
  mcp           Run the MCP server that lets coding agents scan and read the mailbox
Set up:
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
  verify-self   Verify this executable's signature
  licenses      Print third-party licenses
  version       Print the version

Scan exits: 0 = no known findings, 3 = vulnerable, 2 = unknown/incomplete or operational error, 64 = usage error (EX_USAGE).";

fn array(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
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

const SETUP: &str = "No local offline advisory database found. Vorda scans offline by default and never falls back to the network automatically.\n\nThe offline advisory database covers npm, PyPI, crates.io, and Go from any inventory source. Other ecosystems and network-only feeds report unknown.\n\nChoose an option:\n  1) Download the offline advisory database now (about 80 seconds; package names never leave this machine)\n  2) Scan online this once (sends package names and versions to OSV.dev)\n  Enter) Cancel without scanning\n\nSwitch later with --online or --offline-db, or persist online mode with VORDA_ADVISORIES=online or config.json (\"advisories\": \"online\").";
const SETUP_UNATTENDED: &str = "No local offline advisory database found, and Vorda cannot prompt in noninteractive, CI, or Action runs (result: unknown, exit 2). It never falls back to the network. Run `vorda db update` first, or `vorda scan --online` once. Offline scans cover npm, PyPI, crates.io, and Go, and package names never leave this machine; other ecosystems and network-only feeds report unknown.";
const SETUP_PROMPT: &str =
    "Select [1] download offline advisory database, [2] scan online once, or Enter to cancel: ";
const SETUP_INVALID: &str = "No valid choice; no scan was run. Run vorda db update to download the offline advisory database.";

const SETUP_CANCELLED: &str =
    "Cancelled; no scan was run. Run vorda db update to download the offline advisory database.";

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
    if !interactive
        || std::env::var_os("CI").is_some()
        || std::env::var_os("GITHUB_ACTIONS").is_some()
        || !std::io::stdin().is_terminal()
        || !std::io::stderr().is_terminal()
        || !std::io::stdout().is_terminal()
    {
        return Err(Error::new(SETUP_UNATTENDED));
    }
    eprintln!("{SETUP}");
    eprint!("{SETUP_PROMPT}");
    std::io::stderr().flush()?;
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    // End of input leaves the cursor after the prompt; anything printed next starts a new line.
    if !choice.ends_with('\n') {
        eprintln!();
    }
    match choice.trim() {
        "1" => {
            advisory_db(&["update".into()])?;
        }
        "2" => options.offline_db = Some(false),
        "" => return Ok(false),
        _ => return Err(Error::new(SETUP_INVALID)),
    }
    Ok(true)
}

pub fn run(args: &[String]) -> Result<i32> {
    let mut iter = args.iter().peekable();
    let mut state = std::env::var_os("VORDA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".local/share/vorda")
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
        outln(format_args!("{HELP}"))?;
        return Ok(0);
    };
    let rest: Vec<String> = iter.cloned().collect();
    if command == "--help" || command == "-h" || (command == "help" && rest.is_empty()) {
        return run(&[]);
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
                        outln(format_args!("Usage: vorda {command} [--root DIR] [--os-packages] [--tools] [--browsers] [--installed-apps] [--installed-root PATH] [--oci ARCHIVE]{}",
                        if command == "inventory" {" [--format json|cyclonedx|spdx]"} else {" [--offline | --offline-db | --online] [--scheduled] [--inventory-file FILE] [--webhook URL] [--ntfy URL] [--desktop] [--json]\n\n--root DIR is a folder or lockfile to scan (repeat it for more; default: the current folder).\nPrints a short summary; --json prints the full machine-readable result.\n--offline makes no network request and reads no advisories: it lists the packages found, and the result is always unknown (exit 2). For a complete check without network, use --offline-db.\nManual scan and check commands default to the local offline advisory database (--offline-db). Use --online to query OSV.dev for one scan, --offline-db to use the local database, or --offline for an inventory-only scan that always reports unknown (distinct from --offline-db). Mode precedence is CLI flags, then VORDA_ADVISORIES, then config.json (advisories), then the --offline-db default. If no local advisory indexes exist yet, an interactive terminal prompts to download the database or scan online once; noninteractive runs exit 2 (unknown) with no automatic network fallback."}))?;
                        if command != "inventory" {
                            outln(format_args!("\n--os-packages on Ubuntu (host or --oci image) is experimental: {UBUNTU_EXPERIMENTAL}"))?;
                        }
                        return Ok(0);
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
                for warning in array(&result["warnings"]) {
                    eprintln!(
                        "Warning: {}",
                        shown(warning.as_str().unwrap_or("inventory warning"))
                    );
                }
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
            if array(&result["packages"]).is_empty()
                && array(&result["errors"]).is_empty()
                && !array(&result["completed_paths"]).is_empty()
            {
                eprintln!("No package versions found: the lockfiles read declare no dependencies.");
            } else if array(&result["packages"]).is_empty() && array(&result["errors"]).is_empty() {
                eprintln!("No package versions found; nothing was checked. Add a supported lockfile or pinned requirements.txt, or run `vorda scan --os-packages` to check installed OS packages.");
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

/// The default scan output: a few lines a person can act on. `--json` has the rest.
fn summary(command: &str, result: &Value) -> String {
    let findings = array(&result["findings"]);
    // A failed delivery alone makes the result unknown, so the summary names it too.
    let mut errors = array(&result["errors"]);
    errors.extend(array(&result["delivery_errors"]).into_iter().map(|e| {
        json!({"source": format!("delivery to {}", e["channel"].as_str().unwrap_or("?")), "error": e["error"]})
    }));
    let checked = plural(array(&result["packages"]).len(), "package", "packages");
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
    // Feeds and walks return findings in no fixed order; sort so every run prints the same lines.
    groups.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
    for (_, _, paths, group) in &mut groups {
        paths.sort();
        group.sort_by(|a, b| a["advisory"].as_str().cmp(&b["advisory"].as_str()));
    }
    let status = result["status"].as_str().unwrap_or("unknown");
    // An experimental result leads with why its count can mislead, before the count.
    let mut out: String = strings(&result["experimental"])
        .iter()
        .map(|note| format!("Experimental: {note}\n"))
        .collect();
    out.push_str(&format!("Vorda {command}: {status}, {checked} checked\n"));
    if result["advisory_source"] == "offline-db" {
        out.push_str("Advisories: local offline database (no network); EPSS not checked.\n");
    }
    match status {
        "unknown" => out.push_str(
            "The scan is incomplete, so this is not a clean result. Read the errors below.\n",
        ),
        "no-known-findings" => out.push_str("No known vulnerabilities in the packages checked.\n"),
        _ => {}
    }
    if !groups.is_empty() {
        out.push_str(&format!(
            "{} in {}:\n",
            plural(findings.len(), "finding", "findings"),
            plural(groups.len(), "package", "packages")
        ));
    }
    for (_, package, paths, group) in groups.iter().take(8) {
        let mut advisories: Vec<&str> = Vec::new();
        let mut kev = 0;
        for f in group {
            let id = f["advisory"].as_str().unwrap_or("");
            if id.is_empty() || !advisories.contains(&id) {
                advisories.push(id);
                kev += usize::from(f["kev"] == true);
            }
        }
        // In advisory order, each in the feed's own order: versions of different package
        // managers do not sort alike.
        let mut fixed: Vec<&str> = Vec::new();
        for version in group
            .iter()
            .flat_map(|f| f["fixed"].as_array().into_iter().flatten())
        {
            if let Some(v) = version.as_str().filter(|v| !fixed.contains(v)) {
                fixed.push(v);
            }
        }
        let fixed: Vec<String> = fixed.into_iter().map(clipped).collect();
        let place = match paths.len() {
            1 => paths[0].clone(),
            n => format!("{} and {}", paths[0], plural(n - 1, "other", "others")),
        };
        out.push_str(&format!(
            "  {package} ({place}): {}{}{}\n",
            plural(advisories.len(), "advisory", "advisories"),
            if kev > 0 {
                format!(", {kev} known exploited")
            } else {
                String::new()
            },
            match fixed.len() {
                0 => "; no fixed version listed".to_string(),
                1..=3 => format!("; fixed in {}", shown(&fixed.join(", "))),
                _ => "; several fixed versions, see --json".to_string(),
            }
        ));
    }
    if groups.len() > 8 {
        out.push_str(&format!("  ... and {} more packages\n", groups.len() - 8));
    }
    if !errors.is_empty() {
        out.push_str(&format!("{}:\n", plural(errors.len(), "error", "errors")));
        for error in errors.iter().take(3) {
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
        if errors.len() > 3 {
            out.push_str(&format!("  ... and {} more\n", errors.len() - 3));
        }
    }
    if !findings.is_empty() {
        out.push_str("Findings are saved: browse them with vorda dashboard (vorda mail list --reader NAME prints them as JSON for agents)\n");
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
    let scope = identity(&json!(scope_parts))?;
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
    let archive_unknown =
        options.inventory.oci.is_some() && inventory.get("status") != Some(&json!("complete"));
    let mut errors = array(inventory.get("errors").unwrap_or(&Value::Null));
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
    all_errors.extend(
        errors
            .iter()
            .map(|error| json!({"source":"inventory","error":error})),
    );
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
    result["status"] = json!(if !all_errors.is_empty() || options.offline {
        "unknown"
    } else if array(&result["findings"]).is_empty() {
        "no-known-findings"
    } else {
        "vulnerable"
    });
    result["scan_scope"] = json!(scope);
    result["scan_roots"] = json!(selected);
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
        store.db.execute_batch("CREATE TABLE IF NOT EXISTS scans(host TEXT,started REAL,finished REAL,status TEXT,seconds REAL,findings INTEGER,errors TEXT,scan_scope TEXT)")?;
        let has_scope = store
            .db
            .prepare("PRAGMA table_info(scans)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .any(|c| c == "scan_scope");
        if !has_scope {
            store
                .db
                .execute_batch("ALTER TABLE scans ADD COLUMN scan_scope TEXT")?;
        }
        store.db.execute("INSERT INTO scans(host,started,finished,status,seconds,findings,errors,scan_scope) VALUES(?,?,?,?,?,?,?,?)",params![crate::store::hostname()?,finished-result["seconds"].as_f64().unwrap_or(0.0),finished,result["status"].as_str(),result["seconds"].as_f64(),result["findings"].as_array().map(Vec::len),result["errors"].to_string(),scope])?;
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
    for warning in array(assessment.result.get("warnings").unwrap_or(&Value::Null)) {
        eprintln!(
            "Warning: {}",
            shown(warning.as_str().unwrap_or("unknown inventory warning"))
        );
    }
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
        if result["delivery_errors"]
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
        assert!(text.contains("4 findings in 4 packages:"), "{text}");
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
