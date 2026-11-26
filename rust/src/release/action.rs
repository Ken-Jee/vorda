use crate::{domain::ScanOptions, store::Store, Error, Result};
use serde_json::{json, Value};
use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

const NO_DATABASE: &str = "No offline advisory database found, so nothing was checked (status unknown). Set input advisories: online (sends package names and versions to OSV.dev) or restore an offline database to VORDA_ADVISORY_DB_DIR before this step.";
const SETUP_FAILED: &str =
    "Setup failed before the scan started (status unknown); see the error in this step's log.";

const HELP: &str = "Usage: vorda action-scan\n\nStep run by the Vorda GitHub Action; not meant to be run by hand. It takes no arguments and reads\nsettings from environment variables the Action sets (VORDA_SARIF, GITHUB_OUTPUT, VORDA_PATH,\nVORDA_ADVISORY_INPUT, VORDA_FAIL). See docs/github-action.md.";

pub fn run(args: &[String]) -> Result<i32> {
    match args {
        [] => {}
        [flag] if flag == "--help" || flag == "-h" => {
            crate::cli::outln(format_args!("{HELP}"))?;
            return Ok(0);
        }
        _ => return Err(Error::usage("action-scan takes no arguments")),
    }
    let result = run_scan();
    if result.as_ref().is_err_and(|e| e.is_usage()) {
        println!("::error title=vorda::Vorda exited 64 (usage error). Check CLI arguments and action inputs; usage errors fail the run regardless of fail-on-findings.");
    }
    result
}

fn run_scan() -> Result<i32> {
    let sarif_path =
        env::var_os("VORDA_SARIF").ok_or_else(|| Error::usage("VORDA_SARIF is required"))?;
    let output_path =
        env::var_os("GITHUB_OUTPUT").ok_or_else(|| Error::usage("GITHUB_OUTPUT is required"))?;
    let roots = shell_words::split(&env::var("VORDA_PATH").unwrap_or_else(|_| ".".into()))
        .map_err(|e| Error::usage(e.to_string()))?;
    let temporary = tempfile::Builder::new().prefix("vorda-action-").tempdir()?;
    let mut options = ScanOptions::default();
    options.inventory.roots = if roots.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        roots.into_iter().map(PathBuf::from).collect()
    };
    options.offline_db = match env::var("VORDA_ADVISORY_INPUT")
        .unwrap_or_default()
        .as_str()
    {
        "" => None,
        "online" => Some(false),
        "offline-db" => Some(true),
        _ => {
            return Err(Error::usage(
                "advisories input must be online, offline-db, or empty",
            ))
        }
    };
    // A scan that never started still reports unknown, so later steps and the run summary see it.
    if let Err(error) = crate::cli::prepare_scan(&mut options, temporary.path(), false) {
        if !error.is_usage() {
            write_outputs(&sarif_path, &output_path, &json!({"findings": []}))?;
            let missing = options.offline_db == Some(true) && !crate::scanner::osvdb::installed();
            println!(
                "::error title=vorda::{}",
                if missing { NO_DATABASE } else { SETUP_FAILED }
            );
            // The CLI's own hint names commands; an Action user changes the input instead.
            if missing {
                return Err(Error::new(NO_DATABASE));
            }
        }
        return Err(error);
    }
    let mut store = Store::open(temporary.path())?;
    let result = Value::Object(crate::cli::check(&options, &mut store)?);
    let (status, findings, coverage) = write_outputs(&sarif_path, &output_path, &result)?;
    let fail = env::var("VORDA_FAIL").as_deref() == Ok("true");
    // Findings or named gaps can come with errors; the log lists them either way.
    for error in crate::scanner::array(&result["errors"]) {
        eprintln!("vorda scan error: {error}");
    }
    // Name what was not assessed first: a named project with such packages is also unknown.
    let gaps = crate::scanner::array(&result["not_assessed"]);
    if !gaps.is_empty() {
        let sources: Vec<_> = gaps.iter().filter_map(|n| n["source"].as_str()).collect();
        println!(
            "::{} title=vorda::Coverage partial{}: {} not assessed ({}). advisories: online checks ecosystems the offline database does not cover.",
            if fail { "error" } else { "warning" },
            if fail { ", so this is not a pass" } else { "" },
            not_assessed(gaps),
            sources.join(", ")
        );
    }
    if status == "unknown" {
        if fail {
            println!("::error title=vorda::Scan incomplete, so this is not a pass; see the scan errors in this step's log.");
            return Ok(2);
        }
        println!("::warning title=vorda::Scan incomplete; see the scan errors in this step's log.");
    }
    let errors = crate::scanner::array(&result["errors"]);
    if status == "vulnerable" && !errors.is_empty() {
        println!("::warning title=vorda::Findings reported, but some files or entries were not checked (see the scan errors in this step's log), so no SARIF is uploaded.");
    }
    if nothing_to_scan(&result) {
        println!(
            "::{} title=vorda::Nothing to scan: no dependency file Vorda recognizes was found{}, and no SARIF is uploaded.",
            if fail { "error" } else { "warning" },
            if fail { ", so this is not a pass" } else { "" },
        );
    }
    Ok(if findings > 0 && fail {
        1
    } else if coverage == "partial" && fail {
        2
    } else {
        0
    })
}

/// The CLI's "Nothing to scan" case: a clean result with no packages and no file read.
fn nothing_to_scan(result: &Value) -> bool {
    result["status"] == "no-known-findings"
        && crate::scanner::array(&result["packages"]).is_empty()
        && crate::scanner::array(&result["completed_paths"]).is_empty()
}

fn not_assessed(gaps: &[Value]) -> usize {
    gaps.iter()
        .map(|n| n["packages"].as_array().map_or(0, Vec::len))
        .sum()
}

fn write_outputs(
    sarif_path: &OsStr,
    output_path: &OsStr,
    result: &Value,
) -> Result<(&'static str, usize, &'static str)> {
    let sarif = crate::scanner::outputs::sarif(result);
    fs::write(sarif_path, serde_json::to_vec_pretty(&sarif)?)?;
    let findings = result["findings"].as_array().map_or(0, Vec::len);
    let status = match result["status"].as_str() {
        Some("vulnerable") => "vulnerable",
        Some("no-known-findings") => "no-known-findings",
        _ => "unknown",
    };
    let gaps = crate::scanner::array(&result["not_assessed"]);
    // Only a complete scan may upload: its SARIF closes alerts for anything it leaves out (a gap,
    // or a file a vulnerable scan could not check), and an empty one (nothing to scan) would
    // replace a real analysis.
    let errors = crate::scanner::array(&result["errors"]);
    let coverage = if status != "unknown"
        && gaps.is_empty()
        && errors.is_empty()
        && !nothing_to_scan(result)
    {
        "complete"
    } else {
        "partial"
    };
    let mut output = OpenOptions::new().append(true).open(output_path)?;
    writeln!(
        output,
        "status={status}\nfindings={findings}\ncoverage={coverage}\nnot-assessed={}",
        not_assessed(gaps)
    )?;
    println!("vorda: {status}, {findings} findings");
    Ok((status, findings, coverage))
}
