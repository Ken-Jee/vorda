//! The offline advisory database: OSV per-ecosystem exports (`all.zip`) kept in a local
//! SQLite index, refreshed on demand, and answered without any network request.
//!
//! The exports are untrusted input. Every way they can make work grow is bounded below;
//! over a bound, that ecosystem's answers are "unknown" with the reason, never "clean".
use super::feeds::{osv_name, FeedSource, KEV, OSV};
use super::{array, error, string, versions};
use crate::{domain::Package, Error, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Where OSV publishes the per-ecosystem exports.
pub const EXPORTS: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// The advisory source an ordinary scan uses when no flag, `VORDA_ADVISORIES` or
/// `advisories` config key says otherwise. This is the single switch for the default.
pub const DEFAULT_ADVISORIES: &str = "online";
/// An index older than this is not trusted: OSV adds advisories every day, so a missed
/// daily refresh is tolerated, a missed weekend of refreshes is reported. Override with
/// `VORDA_ADVISORY_DB_MAX_AGE_HOURS`.
pub const MAX_AGE_HOURS: f64 = 72.0;
/// Starts the error for a feed the offline database never looks up: by design, not a failure.
pub const NEEDS_NETWORK: &str = "offline-db: not looked up, this source needs the network";
/// Starts the reason for an ecosystem the offline database cannot match: by design, not a failure.
pub const NOT_OFFLINE: &str = "offline matching is not available for";

// Bounds on the untrusted exports.
/// Downloaded export on disk.
pub const MAX_ZIP_BYTES: u64 = 1 << 30;
/// Entries in one export (its central directory is held in memory while reading).
pub const MAX_ENTRIES: u64 = 1_000_000;
/// Size of the export's central directory.
pub const MAX_DIRECTORY_BYTES: u64 = 256 << 20;
/// Sum of all expanded records in one export.
pub const MAX_TOTAL_BYTES: u64 = 6 << 30;
/// One expanded record.
pub const MAX_RECORD_BYTES: u64 = 4 << 20;
/// Expansion ratio of one record larger than 64 KiB.
pub const MAX_RATIO: u64 = 200;
/// JSON nesting depth of one record.
pub const MAX_DEPTH: usize = 32;
/// `affected` entries in one record, ranges in one entry, versions listed in one entry.
pub const MAX_AFFECTED: usize = 5_000;
pub const MAX_RANGES: usize = 100;
pub const MAX_VERSIONS: usize = 50_000;
/// Wall time for building one ecosystem's index.
pub const MAX_BUILD_SECONDS: u64 = 1_800;
/// The built index file.
pub const MAX_INDEX_BYTES: u64 = 3 << 30;
/// How the index stores package names (`osv_name`); 1, with no key, kept crates.io
/// spellings exact. An index built with another form would miss records, so it is not
/// used until it is rebuilt.
const NAMES: u64 = 2;
/// Records and their total size read for one package during a scan.
pub const MAX_PACKAGE_RECORDS: usize = 2_000;
pub const MAX_PACKAGE_BYTES: usize = 8 << 20;
/// Advisory data one scan reads from the index, lookups and details together.
pub const MAX_SCAN_BYTES: usize = 32 << 20;
/// Range events of the advisories that match, per package and per scan: every event is
/// copied into the findings, so this bounds the scan's memory.
pub const MAX_PACKAGE_EVENTS: usize = 20_000;
pub const MAX_SCAN_EVENTS: usize = 50_000;
/// Wall time for one export download.
const DOWNLOAD_SECONDS: u64 = 1_200;
/// The KEV list, downloaded whole.
const MAX_KEV_BYTES: u64 = 32 << 20;

/// The folder that holds the index. It is a re-downloadable cache, so it lives outside the
/// state folder and its storage budget.
pub fn root() -> PathBuf {
    if let Some(dir) = std::env::var_os("VORDA_ADVISORY_DB_DIR").filter(|v| !v.is_empty()) {
        return dir.into();
    }
    let cache = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
    };
    cache
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vorda/advisory-db")
}

/// True when scans should use the offline database: `VORDA_ADVISORIES`, then the state
/// folder's `config.json` key `advisories`, then [`DEFAULT_ADVISORIES`].
pub fn configured(state: &Path) -> Result<bool> {
    configured_default(state, DEFAULT_ADVISORIES)
}

pub fn configured_scan(state: &Path) -> Result<bool> {
    configured_default(state, "offline-db")
}

pub fn installed() -> bool {
    versions::ECOSYSTEMS
        .iter()
        .any(|e| index_path(&root(), e).exists())
}

const CONFIG_ADVISORIES: &str = "\"advisories\" in config.json";

fn configured_default(state: &Path, default: &str) -> Result<bool> {
    let from_env = std::env::var("VORDA_ADVISORIES")
        .ok()
        .filter(|v| !v.is_empty());
    let (value, source) = match from_env {
        Some(v) => (v, "VORDA_ADVISORIES"),
        None => {
            let path = state.join("config.json");
            let config: Value = match fs::read(&path) {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(_) => Value::Null,
            };
            match &config["advisories"] {
                Value::Null => (default.to_owned(), "the default"),
                Value::String(v) => (v.clone(), CONFIG_ADVISORIES),
                other => {
                    return Err(error(format!(
                        "{CONFIG_ADVISORIES} must be online or offline-db, not {other}"
                    )))
                }
            }
        }
    };
    match value.as_str() {
        "online" => Ok(false),
        "offline-db" => Ok(true),
        other => Err(error(format!(
            "{source} must be online or offline-db, not {other:?}"
        ))),
    }
}

fn max_age_hours() -> f64 {
    std::env::var("VORDA_ADVISORY_DB_MAX_AGE_HOURS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(MAX_AGE_HOURS)
}

fn index_path(root: &Path, ecosystem: &str) -> PathBuf {
    root.join(format!("{ecosystem}.sqlite"))
}
fn marker_path(root: &Path, ecosystem: &str) -> PathBuf {
    root.join(format!("{ecosystem}.unreadable.json"))
}

/// Why one ecosystem's refresh did not replace its index.
enum Failure {
    /// Network or disk trouble: the previous index stays in use.
    Transient(String),
    /// The export itself is over a bound or malformed: scans report the ecosystem unknown
    /// until a refresh succeeds. The previous index file is kept but not trusted.
    Unreadable(String),
}

/// Refresh the index for `ecosystems` (empty means every ecosystem Vorda matches offline)
/// and the KEV list, from OSV's exports or from a mirror folder holding
/// `<Ecosystem>/all.zip` and `kev.json`. One line of JSON per item.
pub fn update(ecosystems: &[String], from: Option<&Path>) -> Result<Vec<Value>> {
    let root = root();
    fs::create_dir_all(&root)?;
    sweep(&root);
    let wanted: Vec<String> = if ecosystems.is_empty() {
        versions::ECOSYSTEMS.iter().map(|e| e.to_string()).collect()
    } else {
        ecosystems
            .iter()
            .map(|name| {
                versions::ECOSYSTEMS
                    .iter()
                    .find(|e| e.eq_ignore_ascii_case(name))
                    .map_or_else(|| name.clone(), |e| e.to_string())
            })
            .collect()
    };
    let mut out = Vec::new();
    for ecosystem in wanted {
        if !versions::ECOSYSTEMS.contains(&ecosystem.as_str()) {
            return Err(Error::usage(format!(
                "offline matching is not available for {ecosystem:?}; choose from {}",
                versions::ECOSYSTEMS.join(", ")
            )));
        }
        let start = Instant::now();
        let outcome = refresh(&root, &ecosystem, from);
        let seconds = (start.elapsed().as_secs_f64() * 10.0).round() / 10.0;
        out.push(match outcome {
            Ok(meta) => {
                let mut line = json!({"ecosystem":ecosystem,"outcome":"updated","seconds":seconds,"records":meta["records"],"fetched_at":meta["fetched_at"],"source_url":meta["source_url"],"index_bytes":meta["index_bytes"]});
                let bad = meta["bad_count"].as_u64().unwrap_or(0);
                if bad > 0 {
                    line["outcome"] = json!("updated-with-unreadable-records");
                    line["error"] = json!(format!(
                        "{bad} records in the {ecosystem} export could not be read ({}); scans report {ecosystem} unknown until a clean export is loaded",
                        array(&meta["bad"]).first().and_then(Value::as_str).unwrap_or("unreadable")
                    ));
                } else if let Some(why) = stale(
                    &format!("the {ecosystem} export"),
                    meta["fetched"].as_f64().unwrap_or(0.0),
                    &ecosystem,
                ) {
                    line["outcome"] = json!("updated-stale");
                    line["error"] = json!(why);
                }
                line
            }
            Err(Failure::Transient(why)) => json!({"ecosystem":ecosystem,"outcome":"kept-previous","seconds":seconds,"error":why}),
            Err(Failure::Unreadable(why)) => {
                let marker = json!({"error":why,"at":super::outputs::timestamp()});
                crate::store::atomic(&marker_path(&root, &ecosystem), &marker.to_string())?;
                json!({"ecosystem":ecosystem,"outcome":"unreadable","seconds":seconds,"error":why})
            }
        });
    }
    out.push(match refresh_kev(&root, from) {
        Ok((at, source, checked)) => {
            let mut line =
                json!({"ecosystem":"KEV","outcome":"updated","fetched_at":at,"source_url":source});
            if let Some(why) = stale("the KEV list", checked, "KEV") {
                line["outcome"] = json!("updated-stale");
                line["error"] = json!(why);
            }
            line
        }
        Err(why) => json!({"ecosystem":"KEV","outcome":"kept-previous","error":why}),
    });
    Ok(out)
}

/// An age or limit in hours as words that stay true at small values: "72 hours", "1.5 hours",
/// "20 minutes", "under a minute".
fn duration(hours: f64) -> String {
    if hours >= 10.0 || hours == 0.0 {
        format!("{hours:.0} hours")
    } else if hours * 60.0 >= 59.5 {
        let shown = format!("{hours:.1}");
        match shown.trim_end_matches(".0") {
            "1" => "1 hour".into(),
            whole => format!("{whole} hours"),
        }
    } else if hours * 60.0 >= 1.0 {
        match format!("{:.0}", hours * 60.0).as_str() {
            "1" => "1 minute".into(),
            minutes => format!("{minutes} minutes"),
        }
    } else {
        "under a minute".into()
    }
}

/// Why a just-loaded copy is already too old for scans to use, when it is (a mirror whose
/// sync job stopped).
fn stale(what: &str, fetched: f64, name: &str) -> Option<String> {
    let max_age = max_age_hours();
    let age = (super::now() - fetched) / 3600.0;
    (age > max_age).then(|| {
        format!("{what} is {} old, over the limit of {}; it is loaded, but scans report {name} unknown until a fresher copy loads", duration(age), duration(max_age))
    })
}

/// Remove temporary files left by a refresh that was killed more than a day ago.
fn sweep(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age > Duration::from_secs(86_400));
        if old && (name.starts_with(".partial-") || name.starts_with(".build-")) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn refresh(
    root: &Path,
    ecosystem: &str,
    from: Option<&Path>,
) -> std::result::Result<Value, Failure> {
    let id = uuid::Uuid::new_v4();
    let zip = Temp(root.join(format!(".partial-{ecosystem}-{id}.zip")));
    // A mirror's export is as old as the mirror's file, not the time of this copy.
    let (source_url, fetched) = match from {
        Some(dir) => {
            let path = dir.join(ecosystem).join("all.zip");
            let modified = copy_bounded(&path, &zip.0)?;
            (path.to_string_lossy().into_owned(), modified)
        }
        None => {
            let url = format!("{EXPORTS}/{ecosystem}/all.zip");
            download(&url, &zip.0)?;
            (url, super::now())
        }
    };
    let built = Temp(root.join(format!(".build-{ecosystem}-{id}.sqlite")));
    let meta =
        build(&zip.0, ecosystem, &built.0, &source_url, fetched).map_err(Failure::Unreadable)?;
    let size = fs::metadata(&built.0).map(|m| m.len()).unwrap_or(0);
    if size > MAX_INDEX_BYTES {
        return Err(Failure::Unreadable(format!(
            "built index is {size} bytes, over the {MAX_INDEX_BYTES}-byte bound"
        )));
    }
    // OSV exports carry no completeness marker. A partial export that replaced a full
    // index would hide advisories, so one far below a complete export's size, or much
    // smaller than the most entries a clean index has held, is refused.
    let new = ["records", "withdrawn", "bad_count"]
        .iter()
        .map(|k| meta[k].as_u64().unwrap_or(0))
        .sum::<u64>();
    let floor = min_entries(ecosystem);
    if new < floor {
        return Err(Failure::Transient(format!(
            "export has {new} entries, fewer than the {floor} a complete {ecosystem} export holds; the current index is kept (set VORDA_ADVISORY_DB_MIN_ENTRIES for a smaller private mirror)"
        )));
    }
    let high = entries(&index_path(root, ecosystem));
    if let Some(old) = high {
        if new * 10 < old * 9 {
            return Err(Failure::Transient(format!(
                "export has {new} entries, fewer than 90% of the {old} this index has held; the current index is kept (delete {ecosystem}.sqlite from the advisory database folder to accept a smaller export)"
            )));
        }
    }
    // An export with unreadable records is held to the mark but does not raise it, so a
    // clean export of the real size still replaces it.
    let high = if meta["bad_count"].as_u64().unwrap_or(0) > 0 {
        high.unwrap_or(0)
    } else {
        high.unwrap_or(0).max(new)
    };
    Connection::open(&built.0)
        .and_then(|db| {
            db.execute(
                "INSERT INTO meta(key, value) VALUES('high_water', ?1)",
                [high.to_string()],
            )
        })
        .map_err(|e| Failure::Transient(format!("could not record the index size: {e}")))?;
    fs::rename(&built.0, index_path(root, ecosystem))
        .map_err(|e| Failure::Transient(format!("could not replace the index: {e}")))?;
    let _ = fs::remove_file(marker_path(root, ecosystem));
    let mut meta = meta;
    meta["index_bytes"] = json!(size);
    Ok(meta)
}

/// The fewest entries an export may hold: about half of each complete OSV export in late
/// 2026 (exports only grow, as withdrawn records stay), or `VORDA_ADVISORY_DB_MIN_ENTRIES`.
fn min_entries(ecosystem: &str) -> u64 {
    if let Some(n) = std::env::var("VORDA_ADVISORY_DB_MIN_ENTRIES")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return n;
    }
    match ecosystem {
        "npm" => 115_000,
        "PyPI" => 13_000,
        "crates.io" => 1_500,
        "Go" => 4_800,
        _ => 1,
    }
}

/// The most entries (records, withdrawn and unreadable) a clean export has had across
/// this index's refreshes; None when there is no index, or it had unreadable records and
/// predates the stored mark, so it gives no baseline.
fn entries(path: &Path) -> Option<u64> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let get = |key: &str| -> Option<u64> {
        db.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .ok()?
        .parse()
        .ok()
    };
    if get("bad_count")? > 0 {
        return get("high_water");
    }
    let now = get("records")? + get("withdrawn")?;
    Some(get("high_water").unwrap_or(0).max(now))
}

/// The file's modification time, never later than now.
fn modified(meta: &fs::Metadata) -> Option<f64> {
    let at = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(at.as_secs_f64().min(super::now()))
}

/// Copy a mirror's export and return the mirror file's modification time.
fn copy_bounded(from: &Path, to: &Path) -> std::result::Result<f64, Failure> {
    let file = File::open(from)
        .map_err(|e| Failure::Transient(format!("cannot read {}: {e}", from.display())))?;
    let meta = file
        .metadata()
        .map_err(|e| Failure::Transient(e.to_string()))?;
    if !meta.is_file() {
        return Err(Failure::Transient(format!(
            "{} is not a file",
            from.display()
        )));
    }
    if meta.len() > MAX_ZIP_BYTES {
        return Err(Failure::Unreadable(format!(
            "export is {} bytes, over the {MAX_ZIP_BYTES}-byte bound",
            meta.len()
        )));
    }
    let mut out = File::create(to).map_err(|e| Failure::Transient(e.to_string()))?;
    let copied = std::io::copy(&mut file.take(MAX_ZIP_BYTES + 1), &mut out)
        .map_err(|e| Failure::Transient(e.to_string()))?;
    if copied > MAX_ZIP_BYTES {
        return Err(Failure::Unreadable(
            "export grew past the size bound while copying".into(),
        ));
    }
    out.flush().map_err(|e| Failure::Transient(e.to_string()))?;
    modified(&meta).ok_or_else(|| {
        Failure::Transient(format!(
            "{} has no usable modification time",
            from.display()
        ))
    })
}

fn client(seconds: u64) -> std::result::Result<reqwest::blocking::Client, Failure> {
    reqwest::blocking::Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .timeout(Duration::from_secs(seconds))
        .build()
        .map_err(|e| Failure::Transient(e.to_string()))
}

fn download(url: &str, to: &Path) -> std::result::Result<(), Failure> {
    let response = client(DOWNLOAD_SECONDS)?
        .get(url)
        .header("User-Agent", "vorda/0.1")
        .send()
        .map_err(|e| Failure::Transient(format!("{e}: {url}")))?;
    if !response.status().is_success() {
        return Err(Failure::Transient(format!(
            "HTTP Error {}: {url}",
            response.status().as_u16()
        )));
    }
    let expected = response.content_length();
    if expected.is_some_and(|n| n > MAX_ZIP_BYTES) {
        return Err(Failure::Unreadable(format!(
            "export is {} bytes, over the {MAX_ZIP_BYTES}-byte bound",
            expected.unwrap_or(0)
        )));
    }
    let mut out = File::create(to).map_err(|e| Failure::Transient(e.to_string()))?;
    let copied = std::io::copy(&mut response.take(MAX_ZIP_BYTES + 1), &mut out)
        .map_err(|e| Failure::Transient(format!("download failed: {e}: {url}")))?;
    if copied > MAX_ZIP_BYTES {
        return Err(Failure::Unreadable(format!(
            "export is over the {MAX_ZIP_BYTES}-byte bound"
        )));
    }
    if expected.is_some_and(|n| n != copied) {
        return Err(Failure::Transient(format!(
            "download ended early ({copied} of {} bytes): {url}",
            expected.unwrap_or(0)
        )));
    }
    out.flush().map_err(|e| Failure::Transient(e.to_string()))
}

fn refresh_kev(
    root: &Path,
    from: Option<&Path>,
) -> std::result::Result<(String, String, f64), String> {
    let (bytes, source, checked) = match from {
        Some(dir) => {
            let path = dir.join("kev.json");
            let bytes = super::input::read_regular(&path, None, MAX_KEV_BYTES, false)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            // As old as the mirror's file, not the time of this copy.
            let checked = fs::metadata(&path)
                .ok()
                .and_then(|m| modified(&m))
                .ok_or_else(|| format!("{} has no usable modification time", path.display()))?;
            (bytes, path.to_string_lossy().into_owned(), checked)
        }
        None => {
            let response = client(120)
                .map_err(|_| "cannot build HTTP client".to_owned())?
                .get(KEV)
                .header("User-Agent", "vorda/0.1")
                .header("Accept", "application/json")
                .send()
                .map_err(|e| format!("{e}: {KEV}"))?;
            if !response.status().is_success() {
                return Err(format!("HTTP Error {}: {KEV}", response.status().as_u16()));
            }
            let mut bytes = Vec::new();
            response
                .take(MAX_KEV_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_KEV_BYTES {
                return Err("KEV list is over its size bound".into());
            }
            (bytes, KEV.to_owned(), super::now())
        }
    };
    let data: Value = serde_json::from_slice(&bytes).map_err(|e| format!("KEV list: {e}"))?;
    if !data["vulnerabilities"]
        .as_array()
        .is_some_and(|rows| rows.iter().all(|r| !string(r, "cveID").is_empty()))
    {
        return Err("KEV list has an unexpected schema".into());
    }
    let at = super::outputs::timestamp_at(checked);
    let row = json!({"source_url":source,"fetched_at":at,"checked":checked,"data":data});
    crate::store::atomic(&root.join("kev.json"), &row.to_string()).map_err(|e| e.to_string())?;
    Ok((at, source, checked))
}

/// Read the zip's end-of-central-directory record (and its ZIP64 form) and refuse an
/// archive whose directory would be too large to hold in memory, before parsing it.
fn directory_bounds(file: &mut File, len: u64) -> std::result::Result<(), String> {
    let tail_len = len.min(65_557);
    let mut tail = vec![0; tail_len as usize];
    file.seek(SeekFrom::Start(len - tail_len))
        .and_then(|_| file.read_exact(&mut tail))
        .map_err(|e| e.to_string())?;
    let at = tail
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .filter(|p| p + 22 <= tail.len())
        .ok_or("export is not a zip archive")?;
    let u16_at = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]) as u64;
    let u32_at =
        |b: &[u8], i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as u64;
    let u64_at =
        |b: &[u8], i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap_or([0xff; 8]));
    let (mut entries, mut size) = (u16_at(&tail, at + 10), u32_at(&tail, at + 12));
    if entries == 0xFFFF || size == 0xFFFF_FFFF || u32_at(&tail, at + 16) == 0xFFFF_FFFF {
        let eocd = len - tail_len + at as u64;
        let mut locator = [0u8; 20];
        let mut record = [0u8; 56];
        file.seek(SeekFrom::Start(
            eocd.checked_sub(20).ok_or("truncated zip64 locator")?,
        ))
        .and_then(|_| file.read_exact(&mut locator))
        .map_err(|e| e.to_string())?;
        if &locator[..4] != b"PK\x06\x07" {
            return Err("zip64 locator missing".into());
        }
        let offset = u64_at(&locator, 8);
        if offset.checked_add(56).is_none_or(|end| end > len) {
            return Err("zip64 record outside the archive".into());
        }
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut record))
            .map_err(|e| e.to_string())?;
        if &record[..4] != b"PK\x06\x06" {
            return Err("zip64 record missing".into());
        }
        entries = u64_at(&record, 32);
        size = u64_at(&record, 40);
    }
    if entries > MAX_ENTRIES {
        return Err(format!(
            "export has {entries} entries, over the {MAX_ENTRIES} bound"
        ));
    }
    if size > MAX_DIRECTORY_BYTES || size > len {
        return Err(format!("export directory is {size} bytes, over its bound"));
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(())
}

fn depth(value: &Value) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(value, 1)];
    while let Some((v, d)) = stack.pop() {
        deepest = deepest.max(d);
        if d > MAX_DEPTH {
            break;
        }
        match v {
            Value::Array(a) => stack.extend(a.iter().map(|v| (v, d + 1))),
            Value::Object(o) => stack.extend(o.values().map(|v| (v, d + 1))),
            _ => {}
        }
    }
    deepest
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// What one record contributes: the fields the scanner reads, and the package names it
/// affects in this ecosystem, each with a reason when this record cannot be evaluated.
fn compact(
    record: &Value,
    ecosystem: &str,
) -> std::result::Result<(Value, BTreeMap<String, Option<String>>), String> {
    let id = string(record, "id");
    if !valid_id(id) {
        return Err("record without a valid id".into());
    }
    let affected = record["affected"]
        .as_array()
        .ok_or_else(|| format!("{id}: no affected list"))?;
    if affected.len() > MAX_AFFECTED {
        return Err(format!("{id}: {} affected entries", affected.len()));
    }
    let mut names = BTreeMap::new();
    let mut kept = Vec::new();
    for a in affected {
        if string(&a["package"], "ecosystem") != ecosystem {
            continue;
        }
        let name = string(&a["package"], "name");
        if name.is_empty() || name.len() > 1024 {
            return Err(format!("{id}: package name missing or too long"));
        }
        let name = osv_name(ecosystem, name);
        let ranges = array(&a["ranges"]);
        let listed = array(&a["versions"]);
        let problem = if ranges.len() > MAX_RANGES {
            Some(format!(
                "{id} has {} ranges, over the {MAX_RANGES} bound",
                ranges.len()
            ))
        } else if let Some(r) = ranges
            .iter()
            .find(|r| array(&r["events"]).len() > versions::MAX_EVENTS)
        {
            Some(format!(
                "{id} has a range with {} events, over the {} bound",
                array(&r["events"]).len(),
                versions::MAX_EVENTS
            ))
        } else if listed.len() > MAX_VERSIONS {
            Some(format!(
                "{id} lists {} versions, over the {MAX_VERSIONS} bound",
                listed.len()
            ))
        } else {
            None
        };
        let entry = names.entry(name).or_insert(None);
        if problem.is_some() {
            *entry = problem;
            continue;
        }
        kept.push(json!({"package":a["package"],"ranges":ranges.iter().map(|r| json!({"type":r["type"],"events":r["events"]})).collect::<Vec<_>>(),"versions":a["versions"]}));
    }
    let mut out = json!({"id":id,"affected":kept});
    for key in [
        "aliases",
        "upstream",
        "modified",
        "published",
        "summary",
        "severity",
    ] {
        if let Some(v) = record.get(key).filter(|v| !v.is_null()) {
            out[key] = v.clone();
        }
    }
    if let Some(s) = record["database_specific"]["severity"].as_str() {
        out["database_specific"] = json!({"severity":s});
    }
    Ok((out, names))
}

/// Build one ecosystem's index from an export. Err is the reason the export is unreadable.
fn build(
    zip: &Path,
    ecosystem: &str,
    out: &Path,
    source_url: &str,
    fetched: f64,
) -> std::result::Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(MAX_BUILD_SECONDS);
    let mut file = File::open(zip).map_err(|e| e.to_string())?;
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    directory_bounds(&mut file, len)?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("export is not a readable zip: {e}"))?;
    if archive.len() as u64 > MAX_ENTRIES {
        return Err(format!(
            "export has {} entries, over the {MAX_ENTRIES} bound",
            archive.len()
        ));
    }
    let db = Connection::open(out).map_err(|e| e.to_string())?;
    db.execute_batch(
        &format!(
            "PRAGMA page_size=4096; PRAGMA max_page_count={}; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
         CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE record(id TEXT PRIMARY KEY, json TEXT NOT NULL);
         CREATE TABLE package(name TEXT NOT NULL, id TEXT NOT NULL, problem TEXT, UNIQUE(name, id));
         BEGIN;",
            MAX_INDEX_BYTES / 4096
        ),
    )
    .map_err(|e| e.to_string())?;
    let (mut total, mut records, mut withdrawn) = (0u64, 0u64, 0u64);
    let mut bad: Vec<String> = Vec::new();
    let mut bad_count = 0u64;
    let mut buf = Vec::new();
    for i in 0..archive.len() {
        if Instant::now() > deadline {
            return Err(format!(
                "index build took longer than {MAX_BUILD_SECONDS} seconds"
            ));
        }
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("export entry {i} cannot be read: {e}"))?;
        if entry.is_dir() {
            continue;
        }
        let mut reject = |why: String| {
            bad_count += 1;
            if bad.len() < 5 {
                bad.push(why);
            }
        };
        let (declared, compressed) = (entry.size(), entry.compressed_size().max(1));
        if declared > MAX_RECORD_BYTES {
            reject(format!(
                "entry {i} expands to {declared} bytes, over the {MAX_RECORD_BYTES}-byte bound"
            ));
            continue;
        }
        if declared > 65_536 && declared / compressed > MAX_RATIO {
            reject(format!(
                "entry {i} expands {}-fold, over the {MAX_RATIO}-fold bound",
                declared / compressed
            ));
            continue;
        }
        buf.clear();
        (&mut entry)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("export entry {i} is corrupt: {e}"))?;
        drop(entry);
        let size = buf.len() as u64;
        total += size;
        if total > MAX_TOTAL_BYTES {
            return Err(format!("export expands past {MAX_TOTAL_BYTES} bytes"));
        }
        if size > MAX_RECORD_BYTES {
            reject(format!(
                "entry {i} expands past the {MAX_RECORD_BYTES}-byte bound"
            ));
            continue;
        }
        if size > 65_536 && size / compressed > MAX_RATIO {
            reject(format!(
                "entry {i} expands {}-fold, over the {MAX_RATIO}-fold bound",
                size / compressed
            ));
            continue;
        }
        let record: Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(e) => {
                reject(format!("entry {i} is not JSON: {e}"));
                continue;
            }
        };
        if depth(&record) > MAX_DEPTH {
            reject(format!("entry {i} nests deeper than {MAX_DEPTH} levels"));
            continue;
        }
        if record
            .get("withdrawn")
            .is_some_and(|w| !w.is_null() && w != false)
        {
            withdrawn += 1;
            continue;
        }
        let (compact, names) = match compact(&record, ecosystem) {
            Ok(v) => v,
            Err(why) => {
                reject(why);
                continue;
            }
        };
        let id = string(&compact, "id").to_owned();
        db.execute(
            "INSERT OR REPLACE INTO record(id, json) VALUES(?1, ?2)",
            params![id, compact.to_string()],
        )
        .map_err(|e| e.to_string())?;
        for (name, problem) in names {
            db.execute(
                "INSERT OR REPLACE INTO package(name, id, problem) VALUES(?1, ?2, ?3)",
                params![name, id, problem],
            )
            .map_err(|e| e.to_string())?;
        }
        records += 1;
    }
    if records == 0 && bad_count == 0 {
        return Err("export holds no advisory records".into());
    }
    let fetched_at = super::outputs::timestamp_at(fetched);
    let meta = json!({"ecosystem":ecosystem,"source_url":source_url,"fetched_at":fetched_at,"fetched":fetched,"records":records,"withdrawn":withdrawn,"expanded_bytes":total,"zip_bytes":len,"bad_count":bad_count,"bad":bad,"names":NAMES});
    for (key, value) in meta.as_object().into_iter().flatten() {
        db.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)",
            params![key, value.to_string()],
        )
        .map_err(|e| e.to_string())?;
    }
    db.execute_batch("COMMIT; CREATE INDEX package_name ON package(name);")
        .map_err(|e| e.to_string())?;
    db.close().map_err(|(_, e)| e.to_string())?;
    Ok(meta)
}

struct Index {
    db: Connection,
    meta: Value,
}

fn open(root: &Path, ecosystem: &str, max_age: f64) -> std::result::Result<Index, String> {
    if let Ok(bytes) = fs::read(marker_path(root, ecosystem)) {
        let marker: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        return Err(format!(
            "the latest {ecosystem} export could not be read ({}); run `vorda db update` again",
            marker["error"].as_str().unwrap_or("unreadable")
        ));
    }
    let path = index_path(root, ecosystem);
    if !path.is_file() {
        return Err(format!(
            "no local advisory database for {ecosystem}; run `vorda db update`"
        ));
    }
    let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("local advisory database for {ecosystem} cannot be opened: {e}"))?;
    let meta = (|| -> rusqlite::Result<Value> {
        let mut statement = db.prepare("SELECT key, value FROM meta")?;
        let rows =
            statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut meta = json!({});
        for row in rows {
            let (key, value) = row?;
            meta[key] = serde_json::from_str(&value).unwrap_or(Value::Null);
        }
        Ok(meta)
    })()
    .map_err(|e| format!("local advisory database for {ecosystem} cannot be read: {e}"))?;
    let fetched = meta["fetched"].as_f64().unwrap_or(0.0);
    let age = (super::now() - fetched) / 3600.0;
    if meta["ecosystem"] != ecosystem || fetched <= 0.0 || age < -1.0 {
        return Err(format!(
            "local advisory database for {ecosystem} has no valid fetch time"
        ));
    }
    if age > max_age {
        return Err(format!(
            "local advisory database for {ecosystem} is {} old, over the limit of {}; run `vorda db update`",
            duration(age),
            duration(max_age)
        ));
    }
    if meta["names"] != NAMES {
        return Err(format!(
            "local advisory database for {ecosystem} stores package names in an older form; run `vorda db update`"
        ));
    }
    if meta["bad_count"].as_u64().unwrap_or(1) > 0 {
        return Err(format!(
            "{} records in the {ecosystem} export could not be read ({})",
            meta["bad_count"],
            array(&meta["bad"])
                .first()
                .and_then(Value::as_str)
                .unwrap_or("unreadable")
        ));
    }
    Ok(Index { db, meta })
}

/// One line per ecosystem and the KEV list: what a scan would use now.
pub fn status() -> Vec<Value> {
    let root = root();
    let max_age = max_age_hours();
    let mut out: Vec<Value> = versions::ECOSYSTEMS
        .iter()
        .map(|e| match open(&root, e, max_age) {
            Ok(index) => json!({"ecosystem":e,"state":"ready","fetched_at":index.meta["fetched_at"],"source_url":index.meta["source_url"],"records":index.meta["records"]}),
            Err(why) => json!({"ecosystem":e,"state":"unknown","error":why}),
        })
        .collect();
    out.push(match kev(&root, max_age) {
        Ok(row) => json!({"ecosystem":"KEV","state":"ready","fetched_at":row["fetched_at"],"source_url":row["source_url"]}),
        Err(why) => json!({"ecosystem":"KEV","state":"unknown","error":why}),
    });
    out
}

fn kev(root: &Path, max_age: f64) -> std::result::Result<Value, String> {
    const MISSING: &str =
        "the KEV list is not in the local advisory database; run `vorda db update`";
    let not_found = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let root = fs::canonicalize(root).map_err(|e| {
        if not_found(&e) {
            MISSING.to_owned()
        } else {
            format!("cannot read the local KEV list: {e}")
        }
    })?;
    if fs::symlink_metadata(root.join("kev.json")).is_err_and(|e| not_found(&e)) {
        return Err(MISSING.to_owned());
    }
    let bytes = super::input::read_regular(&root.join("kev.json"), None, MAX_KEV_BYTES * 2, false)
        .map_err(|e| format!("cannot read the local KEV list: {e}"))?;
    let row: Value = serde_json::from_slice(&bytes).map_err(|e| format!("local KEV list: {e}"))?;
    let age = (super::now() - row["checked"].as_f64().unwrap_or(0.0)) / 3600.0;
    if !(-1.0..=max_age).contains(&age) {
        return Err(format!(
            "the local KEV list is {} old, over the limit of {}; run `vorda db update`",
            duration(age),
            duration(max_age)
        ));
    }
    Ok(row)
}

/// A feed source that answers OSV queries and the KEV list from the local index and
/// refuses every other request. It has no network code.
pub struct LocalDb {
    root: PathBuf,
    max_age: f64,
    packages: BTreeSet<(String, String)>,
    indexes: BTreeMap<String, std::result::Result<Index, String>>,
    deadline: Instant,
    exhausted: bool,
    /// Bytes of advisory data read so far, against MAX_SCAN_BYTES.
    loaded: usize,
    /// Range events copied into findings so far, against MAX_SCAN_EVENTS.
    events: usize,
    /// How many places each (ecosystem, name, version) is installed: each gets its own
    /// finding with its own copy of the matched ranges.
    copies: BTreeMap<(String, String, String), usize>,
}

impl LocalDb {
    pub fn new(root: &Path) -> Self {
        let budget = std::env::var("VORDA_FEED_BUDGET_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(super::feeds::FEED_BUDGET_SECONDS);
        Self {
            root: root.into(),
            max_age: max_age_hours(),
            packages: BTreeSet::new(),
            indexes: BTreeMap::new(),
            deadline: Instant::now() + Duration::from_secs(budget),
            exhausted: false,
            loaded: 0,
            events: 0,
            copies: BTreeMap::new(),
        }
    }

    fn index(&mut self, ecosystem: &str) -> std::result::Result<&Index, String> {
        if !self.indexes.contains_key(ecosystem) {
            let opened = if versions::ECOSYSTEMS.contains(&ecosystem) {
                open(&self.root, ecosystem, self.max_age)
            } else {
                Err(format!(
                    "{NOT_OFFLINE} {ecosystem}; use online lookups for these packages"
                ))
            };
            self.indexes.insert(ecosystem.to_owned(), opened);
        }
        self.indexes[ecosystem].as_ref().map_err(Clone::clone)
    }

    /// One `querybatch` result row, with `unknown` set when the answer may be incomplete.
    fn query(&mut self, ecosystem: &str, name: &str, version: &str) -> Value {
        if Instant::now() > self.deadline {
            self.exhausted = true;
            return json!({"unknown":"the offline lookup time budget ran out"});
        }
        let index = match self.index(ecosystem) {
            Ok(index) => index,
            Err(why) => return json!({"unknown":why}),
        };
        if !versions::orderable(ecosystem, version) {
            return json!({"unknown":format!("version {version:?} cannot be ordered for {ecosystem}")});
        }
        let name = osv_name(ecosystem, name);
        let rows = (|| -> rusqlite::Result<Vec<(String, String, Option<String>)>> {
            let mut statement = index.db.prepare_cached(
                "SELECT p.id, r.json, p.problem FROM package p JOIN record r ON r.id = p.id WHERE p.name = ?1 LIMIT ?2",
            )?;
            let rows = statement.query_map(params![name, MAX_PACKAGE_RECORDS as i64 + 1], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?;
            rows.collect()
        })();
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => return json!({"unknown":format!("local advisory database read failed: {e}")}),
        };
        let bytes = rows.iter().map(|r| r.1.len()).sum::<usize>();
        if rows.len() > MAX_PACKAGE_RECORDS || bytes > MAX_PACKAGE_BYTES {
            return json!({"unknown":format!("{name} has more advisory data than the offline lookup bound ({MAX_PACKAGE_RECORDS} records, {MAX_PACKAGE_BYTES} bytes)")});
        }
        if self.loaded + bytes > MAX_SCAN_BYTES {
            return json!({"unknown":format!("this scan reached the offline lookup bound of {MAX_SCAN_BYTES} bytes of advisory data")});
        }
        self.loaded += bytes;
        let (mut vulns, mut unknown, mut unmatched) = (Vec::new(), Vec::new(), Vec::new());
        // Range events of matched advisories: each is copied into the findings.
        let mut events = 0;
        for (id, record, problem) in rows {
            if let Some(problem) = problem {
                unknown.push(problem);
                continue;
            }
            let Ok(record) = serde_json::from_str::<Value>(&record) else {
                unknown.push(format!("{id} cannot be read from the local index"));
                continue;
            };
            let (mut reasons, mut notes) = (Vec::new(), Vec::new());
            let (mut hit, mut own) = (false, 0);
            for a in array(&record["affected"]) {
                if string(&a["package"], "ecosystem") != ecosystem
                    || osv_name(ecosystem, string(&a["package"], "name")) != name
                {
                    continue;
                }
                own += array(&a["ranges"])
                    .iter()
                    .map(|r| array(&r["events"]).len())
                    .sum::<usize>();
                match versions::evaluate(ecosystem, version, &id, a) {
                    versions::Verdict::Affected => hit = true,
                    versions::Verdict::NotAffected => {}
                    versions::Verdict::Unmatched(why) => notes.push(why),
                    versions::Verdict::Unknown(why) => reasons.push(why),
                }
            }
            if hit {
                events += own;
                vulns.push(json!({"id":id,"modified":record["modified"]}));
            } else if reasons.is_empty() {
                unmatched.extend(notes);
            } else {
                unknown.extend(reasons);
            }
        }
        let copies = self
            .copies
            .get(&(ecosystem.to_owned(), name.clone(), version.to_owned()))
            .copied()
            .unwrap_or(1);
        let copied = events.saturating_mul(copies);
        if events > MAX_PACKAGE_EVENTS || self.events + copied > MAX_SCAN_EVENTS {
            return json!({"unknown":format!("{name}: matched advisories carry more range events than the offline lookup bound ({MAX_PACKAGE_EVENTS} per package, {MAX_SCAN_EVENTS} per scan counting every place a package is installed)")});
        }
        self.events += copied;
        let mut row = if vulns.is_empty() {
            json!({})
        } else {
            json!({"vulns":vulns})
        };
        if !unknown.is_empty() {
            let more = unknown.len().saturating_sub(3);
            unknown.truncate(3);
            let mut text = unknown.join("; ");
            if more > 0 {
                text.push_str(&format!("; and {more} more"));
            }
            row["unknown"] = json!(text);
        }
        if !unmatched.is_empty() {
            row["unmatched"] = json!(unmatched);
        }
        row
    }

    fn querybatch(&mut self, body: Option<&Value>) -> Result<Value> {
        let queries = body
            .and_then(|b| b["queries"].as_array())
            .ok_or_else(|| error("offline-db: invalid query"))?;
        let mut results = Vec::with_capacity(queries.len());
        let mut used = BTreeSet::new();
        for q in queries {
            let ecosystem = string(&q["package"], "ecosystem").to_owned();
            used.insert(ecosystem.clone());
            results.push(self.query(
                &ecosystem,
                string(&q["package"], "name"),
                string(q, "version"),
            ));
        }
        let fetched_at = used
            .iter()
            .filter_map(|e| self.indexes.get(e).and_then(|i| i.as_ref().ok()))
            .filter_map(|i| i.meta["fetched_at"].as_str())
            .min()
            .map(str::to_owned);
        Ok(
            json!({"source_url":format!("offline-db:{OSV}/querybatch"),"fetched_at":fetched_at,"data":{"results":results}}),
        )
    }

    /// One advisory as OSV would return it. Each index keeps only its own ecosystem's
    /// `affected` entries, so the entries of every loaded index holding `id` are merged.
    fn detail(&mut self, id: &str) -> Result<Value> {
        let (mut merged, mut fetched_at): (Option<Value>, Option<String>) = (None, None);
        for index in self.indexes.values().filter_map(|i| i.as_ref().ok()) {
            let found: Option<String> = index
                .db
                .query_row("SELECT json FROM record WHERE id = ?1", [id], |r| r.get(0))
                .optional()
                .map_err(error)?;
            let Some(json) = found else { continue };
            if self.loaded + json.len() > MAX_SCAN_BYTES {
                return Err(error(format!(
                    "offline-db: this scan reached the offline lookup bound of {MAX_SCAN_BYTES} bytes of advisory data; {id} was not read"
                )));
            }
            self.loaded += json.len();
            let data: Value = serde_json::from_str(&json)?;
            if let Some(at) = index.meta["fetched_at"].as_str() {
                if fetched_at.as_deref().is_none_or(|f| at < f) {
                    fetched_at = Some(at.to_owned());
                }
            }
            match merged.as_mut() {
                None => merged = Some(data),
                Some(m) => {
                    let more = array(&data["affected"]).to_vec();
                    if let Some(affected) = m["affected"].as_array_mut() {
                        affected.extend(more);
                    }
                }
            }
        }
        let Some(mut data) = merged else {
            return Err(error(format!("offline-db: {id} is not in the local index")));
        };
        if let Some(affected) = data["affected"].as_array_mut() {
            affected.retain(|a| {
                let ecosystem = string(&a["package"], "ecosystem");
                self.packages.contains(&(
                    ecosystem.into(),
                    osv_name(ecosystem, string(&a["package"], "name")),
                ))
            });
            for a in affected.iter_mut().filter_map(Value::as_object_mut) {
                a.remove("versions");
            }
        }
        Ok(
            json!({"source_url":format!("offline-db:{OSV}/vulns/{id}"),"fetched_at":fetched_at,"data":data}),
        )
    }
}

impl FeedSource for LocalDb {
    fn get(&mut self, url: &str, body: Option<&Value>) -> Result<Value> {
        if url == format!("{OSV}/querybatch") {
            return self.querybatch(body);
        }
        if let Some(id) = url.strip_prefix(&format!("{OSV}/vulns/")) {
            return self.detail(id);
        }
        if url == KEV {
            let mut row = kev(&self.root, self.max_age).map_err(error)?;
            row["source_url"] = json!(format!("offline-db:{}", string(&row, "source_url")));
            return Ok(row);
        }
        Err(error(format!("{NEEDS_NETWORK}: {url}")))
    }
    fn budget_exhausted(&self) -> bool {
        self.exhausted
    }
    fn select_packages(&mut self, packages: &[Package]) {
        self.packages = packages
            .iter()
            .map(|p| {
                (
                    p.ecosystem.clone(),
                    osv_name(&p.ecosystem, super::source_name(p)),
                )
            })
            .collect();
        self.copies.clear();
        for p in packages {
            let key = (
                p.ecosystem.clone(),
                osv_name(&p.ecosystem, super::source_name(p)),
                super::source_version(p).to_owned(),
            );
            *self.copies.entry(key).or_default() += 1;
        }
    }
    fn offline(&self) -> bool {
        true
    }
    fn local_db(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn age_words_stay_true_at_small_values() {
        let cases = [
            (0.0, "0 hours"),
            (0.001, "under a minute"),
            (1.0 / 60.0, "1 minute"),
            (0.25, "15 minutes"),
        ];
        let more = [
            (59.9 / 60.0, "1 hour"),
            (1.0, "1 hour"),
            (1.5, "1.5 hours"),
            (2.0, "2 hours"),
            (72.0, "72 hours"),
        ];
        for (hours, words) in cases.into_iter().chain(more) {
            assert_eq!(super::duration(hours), words);
        }
    }
}
