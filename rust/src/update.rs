//! `vorda update`: replace this executable with a signed GitHub release, then refresh the
//! offline advisory database when offline mode is saved.
//!
//! Trust comes only from the release key built into the running binary: the release's
//! `SHA256SUMS` must carry a minisign signature from that key, and the downloaded executable
//! must match its SHA-256 line. Nothing else (a key file, a URL, an environment variable) can
//! change which key is trusted.
use crate::cli::outln;
use crate::{Error, Result};
use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const RELEASES: &str = "https://github.com/Ken-Jee/vorda/releases";
/// Larger than any release executable; a bigger response is not a Vorda release.
const MAX_DOWNLOAD: u64 = 256 << 20;

const USAGE: &str = "Usage: vorda update [--check] [--version VERSION]\n\nDownload and install a signed release from https://github.com/Ken-Jee/vorda/releases. Vorda fetches SHA256SUMS and SHA256SUMS.minisig, checks the signature against the release public key built into this executable (key ID 57E5204A70E3811B; no key file, URL or environment variable can change which key is trusted), selects this platform's build (static musl on Linux), downloads the executable, verifies its SHA-256 against the signed list, and verifies the executable's own .minisig signature with the same built-in key.\n\nThe new executable is written beside the current one and renamed into place, keeping the previous executable as vorda.old (vorda.exe.old on Windows) and saving the release signature as vorda.minisig so vorda verify-self verifies it afterwards. Vorda then runs the new executable with --version and restores the previous executable if that check fails. When offline mode is saved (VORDA_ADVISORIES=offline-db or \"advisories\": \"offline-db\" in config.json), update also runs vorda db update with the new executable (including when already up to date), unless --check is set.\n\n  --check            Report whether a newer signed release is available without changing anything or refreshing the offline advisory database\n  --version VERSION  Install a specific release (for example 0.2.0 or v0.2.0), even if it is older than the running version; without this flag, only a newer release is installed\n\nPackage-manager installs, development builds without a built-in release key, and unsigned releases (such as v0.1.0 and v0.1.1) are refused without changing anything. Exits 0 when updated, already up to date or after --check (or with vorda db update's exit code when refreshing the offline advisory database), 2 on errors or rollback, and 64 on usage errors.";
const UPDATE_NO_KEY: &str = "This executable has no built-in release key (it looks like a development build from source), so it cannot check updates. Reinstall a release with the install script or rebuild from source.";
const UPDATE_NO_RELEASE: &str = "No release checksum file (SHA256SUMS) was found for that release; if you passed --version, that version may not exist. Nothing was changed.";
const UPDATE_UNSIGNED: &str = "This release is not signed (missing .minisig), so vorda update cannot install it (releases v0.1.0 and v0.1.1 are unsigned); nothing was changed. To install an unsigned release, run: curl -fsSL https://github.com/Ken-Jee/vorda/releases/latest/download/install.sh | sh";
const UPDATE_BAD_SIGNATURE: &str = "The release signature does not match the release key built into this executable; nothing was changed";
const UPDATE_NO_TARGET: &str = "This release has no build for {target}, or it does not contain the version requested with --version. Nothing was changed.";
const UPDATE_BAD_CHECKSUM: &str = "The SHA-256 checksum of {name} does not match the signed SHA256SUMS file; nothing was installed.";
const UPDATE_MANAGED: &str = "This executable ({path}) is managed by a package manager. Update Vorda with that package manager instead; nothing was changed.";
const UPDATE_CURRENT: &str = "Vorda {version} is up to date.";
const UPDATE_NEWER: &str =
    "The running version is newer than the latest release ({version}); nothing was changed.";
const UPDATE_AVAILABLE: &str = "Vorda {version} is available. Run vorda update to install it.";
const UPDATE_DONE: &str =
    "Updated to Vorda {version} (signature verified). Previous executable kept at {old}.";
const UPDATE_ROLLED_BACK: &str =
    "The new executable did not run as version {version}, so the previous executable was restored.";
const UPDATE_DB: &str = "Offline mode is saved; running vorda db update.";

/// What `install` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The release is this version (or older, when no version was asked for).
    Current(String),
    /// `--check` found this newer version; nothing changed.
    Available(String),
    /// This version now runs from the executable path; the previous one is at the `.old` path.
    Installed(String),
}

/// One release file by name: `Ok(None)` when the release has no such file.
pub type Fetch<'a> = dyn Fn(&str) -> Result<Option<Vec<u8>>> + 'a;

pub fn run(args: &[String], state: &Path) -> Result<i32> {
    let (mut check, mut version) = (false, None);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                outln(format_args!("{USAGE}"))?;
                return Ok(0);
            }
            "--check" => check = true,
            "--version" => {
                let value = iter
                    .next()
                    .filter(|v| !v.starts_with('-'))
                    .ok_or_else(|| Error::usage("--version requires a value"))?;
                let value = value.strip_prefix('v').unwrap_or(value);
                // It becomes part of the release URL path.
                if value.is_empty()
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
                {
                    return Err(Error::usage(format!("invalid --version value: {value}")));
                }
                version = Some(value.to_owned());
            }
            _ => return Err(Error::usage(format!("unrecognized update argument: {arg}"))),
        }
    }
    // Read before anything changes, so a bad config.json stops the update instead of the refresh.
    let refresh_db = !check && crate::scanner::osvdb::configured(state)?;
    let key = crate::release::built_in_key().ok_or_else(|| Error::new(UPDATE_NO_KEY))?;
    let exe = fs::canonicalize(std::env::current_exe()?)?;
    if managed(&exe) {
        return Err(Error::new(
            UPDATE_MANAGED.replace("{path}", &exe.display().to_string()),
        ));
    }
    let base = match &version {
        Some(v) => format!("{RELEASES}/download/v{v}"),
        None => format!("{RELEASES}/latest/download"),
    };
    let outcome = install(
        &|name| download(&format!("{base}/{name}")),
        key,
        &exe,
        env!("CARGO_PKG_VERSION"),
        version.as_deref(),
        check,
    )?;
    match &outcome {
        Outcome::Current(v) if version.is_none() && newer(env!("CARGO_PKG_VERSION"), v) => {
            outln(format_args!("{}", UPDATE_NEWER.replace("{version}", v)))?
        }
        Outcome::Current(v) => outln(format_args!("{}", UPDATE_CURRENT.replace("{version}", v)))?,
        Outcome::Available(v) => {
            outln(format_args!("{}", UPDATE_AVAILABLE.replace("{version}", v)))?
        }
        Outcome::Installed(v) => outln(format_args!(
            "{}",
            UPDATE_DONE
                .replace("{version}", v)
                .replace("{old}", &old_path(&exe).display().to_string())
        ))?,
    }
    if !refresh_db {
        return Ok(0);
    }
    outln(format_args!("{UPDATE_DB}"))?;
    // The new executable refreshes the database, so its own format and checks apply.
    Ok(Command::new(&exe)
        .args(["db", "update"])
        .status()?
        .code()
        .unwrap_or(2))
}

/// Check the release that `fetch` serves against `key` and, unless `check_only`, install its
/// executable for this platform at `exe`. With `want` unset, only a newer release is installed.
pub fn install(
    fetch: &Fetch,
    key: &str,
    exe: &Path,
    current: &str,
    want: Option<&str>,
    check_only: bool,
) -> Result<Outcome> {
    let sums = fetch("SHA256SUMS")?.ok_or_else(|| Error::new(UPDATE_NO_RELEASE))?;
    let signature = fetch("SHA256SUMS.minisig")?.ok_or_else(|| Error::new(UPDATE_UNSIGNED))?;
    verify(&sums, &signature, key)
        .map_err(|detail| Error::new(format!("{UPDATE_BAD_SIGNATURE} ({detail})")))?;
    let target = target();
    let (expected, name, version) = String::from_utf8_lossy(&sums)
        .lines()
        .find_map(|line| entry(line, target))
        .ok_or_else(|| Error::new(UPDATE_NO_TARGET.replace("{target}", target)))?;
    if want.is_some_and(|w| w != version) {
        return Err(Error::new(UPDATE_NO_TARGET.replace("{target}", target)));
    }
    if want.is_none() && !newer(&version, current) {
        return Ok(Outcome::Current(version));
    }
    if check_only {
        return Ok(Outcome::Available(version));
    }
    let bytes =
        fetch(&name)?.ok_or_else(|| Error::new(UPDATE_NO_TARGET.replace("{target}", target)))?;
    if hex(&Sha256::digest(&bytes)) != expected {
        return Err(Error::new(UPDATE_BAD_CHECKSUM.replace("{name}", &name)));
    }
    // The executable's own signature goes beside it, so `vorda verify-self` checks it later.
    let own = fetch(&format!("{name}.minisig"))?.ok_or_else(|| Error::new(UPDATE_UNSIGNED))?;
    verify(&bytes, &own, key)
        .map_err(|detail| Error::new(format!("{UPDATE_BAD_SIGNATURE} ({detail})")))?;
    swap(exe, &bytes, &version)?;
    let mut sig = exe.as_os_str().to_owned();
    sig.push(".minisig");
    let mut file = tempfile::NamedTempFile::new_in(exe.parent().unwrap_or(Path::new(".")))?;
    std::io::Write::write_all(&mut file, &own)?;
    file.persist(sig).map_err(|e| Error::from(e.error))?;
    Ok(Outcome::Installed(version))
}

fn verify(content: &[u8], signature: &[u8], key: &str) -> std::result::Result<(), String> {
    let key = PublicKey::decode(key).map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(signature).map_err(|e| e.to_string())?;
    let signature = Signature::decode(text).map_err(|e| e.to_string())?;
    key.verify(content, &signature, false)
        .map_err(|e| e.to_string())
}

/// `HEX  vorda-VERSION-TARGET[.exe]` as (hex, file name, version).
fn entry(line: &str, target: &str) -> Option<(String, String, String)> {
    let (digest, name) = line.split_once("  ")?;
    let version = name
        .strip_prefix("vorda-")?
        .strip_suffix(if cfg!(windows) { ".exe" } else { "" })?
        .strip_suffix(target)?
        .strip_suffix('-')?;
    let valid = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
    (valid && !version.is_empty() && !version.contains('/')).then(|| {
        (
            digest.to_ascii_lowercase(),
            name.to_owned(),
            version.to_owned(),
        )
    })
}

/// The release build for this platform. Linux releases are static musl builds, which run on
/// any Linux, so a glibc build updates to them too.
fn target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        _ => "unsupported",
    }
}

/// True when `a` is a later version than `b` (`MAJOR.MINOR.PATCH`, a pre-release sorts first).
fn newer(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> (Vec<u64>, bool) {
        let (core, pre) = match v.split_once(['-', '+']) {
            Some((core, _)) => (core, v.as_bytes()[core.len()] == b'-'),
            None => (v, false),
        };
        (
            core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
            !pre,
        )
    }
    parse(a) > parse(b)
}

/// Package-manager installs are updated by their package manager.
fn managed(exe: &Path) -> bool {
    let path = exe.to_string_lossy();
    [
        "/usr/bin/",
        "/usr/lib/",
        "/nix/store/",
        "/snap/",
        "/Cellar/",
        "/opt/homebrew/",
    ]
    .iter()
    .any(|p| path.contains(p))
}

fn old_path(exe: &Path) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(".old");
    PathBuf::from(name)
}

/// Put `bytes` at `exe`, keeping the running version at `exe.old`. The new file is written
/// beside `exe` and renamed over it, so `exe` is never missing or half written. If the new
/// executable does not report `version`, the previous one is put back.
fn swap(exe: &Path, bytes: &[u8], version: &str) -> Result<()> {
    let dir = exe
        .parent()
        .ok_or_else(|| Error::new("executable has no folder"))?;
    let mut new = tempfile::Builder::new()
        .prefix(".vorda-update-")
        .suffix(std::env::consts::EXE_SUFFIX)
        .tempfile_in(dir)?;
    std::io::Write::write_all(&mut new, bytes)?;
    new.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(new.path(), fs::Permissions::from_mode(0o755))?;
    }
    let old = old_path(exe);
    // Windows cannot replace a running executable, but it can rename it.
    if cfg!(windows) {
        fs::rename(exe, &old)?;
    } else {
        fs::copy(exe, &old)?;
    }
    if let Err(e) = new.persist(exe) {
        if cfg!(windows) {
            fs::rename(&old, exe)?;
        }
        return Err(e.error.into());
    }
    if reports(exe, version) {
        return Ok(());
    }
    if cfg!(windows) {
        fs::rename(
            exe,
            dir.join(format!(".vorda-failed-{}.exe", std::process::id())),
        )?;
        fs::rename(&old, exe)?;
    } else {
        fs::rename(&old, exe)?;
    }
    Err(Error::new(UPDATE_ROLLED_BACK.replace("{version}", version)))
}

/// True when `exe --version` runs and prints `vorda VERSION`.
fn reports(exe: &Path, version: &str) -> bool {
    Command::new(exe).arg("--version").output().is_ok_and(|o| {
        o.status.success()
            && String::from_utf8_lossy(&o.stdout).trim() == format!("vorda {version}")
    })
}

fn download(url: &str) -> Result<Option<Vec<u8>>> {
    let response = reqwest::blocking::Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .https_only(true)
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| Error::new(e.to_string()))?
        .get(url)
        .header("User-Agent", concat!("vorda/", env!("CARGO_PKG_VERSION")))
        .send()
        .map_err(|e| Error::new(format!("{e}: {url}")))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(Error::new(format!("{url}: HTTP {}", response.status())));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_DOWNLOAD + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::new(format!("{e}: {url}")))?;
    if bytes.len() as u64 > MAX_DOWNLOAD {
        return Err(Error::new(format!(
            "{url}: larger than any Vorda release file"
        )));
    }
    Ok(Some(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_numerically_with_prereleases_first() {
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("0.2.0", "0.2.0-rc.1"));
        assert!(!newer("0.2.0-rc.1", "0.2.0"));
        assert!(!newer("0.1.1", "0.1.1"));
        assert!(!newer("0.1.0", "0.1.1"));
    }

    #[test]
    fn only_this_targets_line_is_an_entry() {
        let t = target();
        let digest = "a".repeat(64);
        assert_eq!(
            entry(
                &format!("{digest}  vorda-0.2.0-{t}{}", std::env::consts::EXE_SUFFIX),
                t
            ),
            Some((
                digest.clone(),
                format!("vorda-0.2.0-{t}{}", std::env::consts::EXE_SUFFIX),
                "0.2.0".into()
            ))
        );
        assert_eq!(entry(&format!("{digest}  LICENSE"), t), None);
        assert_eq!(
            entry(&format!("{digest}  vorda-0.2.0-other-target"), t),
            None
        );
        assert_eq!(entry(&format!("short  vorda-0.2.0-{t}"), t), None);
    }
}
