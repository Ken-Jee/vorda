use super::commands::*;
use crate::{Error, Result};
use base64::Engine;
use fs2::FileExt;
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
const UNDO: &str = "chromium-check-undo.json";
const KNOWN: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json";
fn version(v: &str) -> Option<Vec<u64>> {
    if !regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
        .unwrap()
        .is_match(v)
    {
        return None;
    }
    v.split('.').map(|s| s.parse().ok()).collect()
}
fn layout(name: &str) -> bool {
    regex::Regex::new(
        r"^(chrome|chrome-headless-shell)-(linux64|linux|mac-arm64|mac-x64|mac|win64|win32|win)$",
    )
    .unwrap()
    .is_match(name)
}
fn client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| Error::new(e.to_string()))
}
fn records(root: &Path) -> Result<Vec<Value>> {
    if !root.join(UNDO).exists() {
        return Ok(vec![]);
    }
    read_json(&root.join(UNDO))?
        .as_array()
        .cloned()
        .ok_or_else(|| Error::new("undo records must be a list"))
}
pub fn valid_undo(root: &Path, rec: &Value) -> bool {
    let (Some(l), Some(b), Some(old)) = (
        rec["layout_dir"].as_str(),
        rec["backup_dir"].as_str(),
        rec["old_version"].as_str(),
    ) else {
        return false;
    };
    let (l, b) = (Path::new(l), Path::new(b));
    l.parent() == Some(root)
        && b.parent() == Some(root)
        && l.file_name().and_then(|s| s.to_str()).is_some_and(layout)
        && version(old).is_some()
        && b.file_name().is_some_and(|s| {
            s == format!(
                "{}.chromium-check-backup-{old}",
                l.file_name().unwrap().to_string_lossy()
            )
            .as_str()
        })
        && !fs::symlink_metadata(l).is_ok_and(|m| m.file_type().is_symlink())
        && !fs::symlink_metadata(b).is_ok_and(|m| m.file_type().is_symlink())
}
pub fn safe_extract<R: Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    dest: &Path,
) -> Result<()> {
    fs::create_dir_all(dest)?;
    let dest = fs::canonicalize(dest)?;
    let mut total = 0u64;
    for i in 0..archive.len() {
        let mut member = archive.by_index(i).map_err(|e| Error::new(e.to_string()))?;
        let rel = member
            .enclosed_name()
            .ok_or_else(|| Error::new("archive path is unsafe"))?;
        if rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(Error::new("archive path is unsafe"));
        }
        let target = dest.join(&rel);
        let mut parent = target.parent();
        while let Some(p) = parent {
            if p == dest {
                break;
            }
            if fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(Error::new("archive path traverses a symlink"));
            }
            parent = p.parent();
        }
        total = total
            .checked_add(member.size())
            .ok_or_else(|| Error::new("archive size overflowed"))?;
        if total > 2_000_000_000 || i >= 100_000 {
            return Err(Error::new("browser archive exceeds extraction limit"));
        }
        let mode = member.unix_mode().unwrap_or(0o644);
        if mode & 0o170000 == 0o120000 {
            let mut link = String::new();
            member.by_ref().take(4097).read_to_string(&mut link)?;
            if link.len() > 4096 {
                return Err(Error::new("symlink is too long"));
            }
            let link_path = Path::new(&link);
            let mut normalized = rel.parent().unwrap_or(Path::new("")).to_path_buf();
            if link_path.is_absolute() {
                return Err(Error::new("archive symlink is unsafe"));
            }
            for c in link_path.components() {
                match c {
                    std::path::Component::Normal(s) => normalized.push(s),
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        if !normalized.pop() {
                            return Err(Error::new("archive symlink is unsafe"));
                        }
                    }
                    _ => return Err(Error::new("archive symlink is unsafe")),
                }
            }
            fs::create_dir_all(target.parent().unwrap())?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(link_path, &target)?;
            #[cfg(not(unix))]
            return Err(Error::new("archive symlinks are unsupported on this host"));
        } else if member.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(Error::new("archive overwrites a symlink"));
            }
            fs::create_dir_all(target.parent().unwrap())?;
            let mut f = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            std::io::copy(&mut member, &mut f)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(target, fs::Permissions::from_mode(mode & 0o777))?;
            }
        }
    }
    Ok(())
}

fn root_lock(root: &Path) -> Result<fs::File> {
    let path = root.join(".vorda-browser.lock");
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::new("browser lock is a symlink"));
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    file.try_lock_exclusive()
        .map_err(|_| Error::new("another browser repair holds this root"))?;
    Ok(file)
}
pub fn install(build: &Value, new: &str, url: &str) -> Result<Value> {
    let layout_dir = fs::canonicalize(field(build, "layout_dir")?)?;
    let root = layout_dir
        .parent()
        .ok_or_else(|| Error::new("browser directory has no parent"))?;
    let _lock = root_lock(root)?;
    let old = field(build, "version")?;
    if version(old).is_none()
        || version(new).is_none()
        || version(old).unwrap()[0] != version(new).unwrap()[0]
        || !layout(layout_dir.file_name().unwrap().to_str().unwrap_or(""))
    {
        return Err(Error::new("an exact same-major browser layout is required"));
    }
    let backup = layout_dir.with_file_name(format!(
        "{}.chromium-check-backup-{old}",
        layout_dir.file_name().unwrap().to_string_lossy()
    ));
    if backup.exists() {
        return Err(Error::new("backup already exists; undo first"));
    }
    let parsed = url::Url::parse(url).map_err(|e| Error::new(e.to_string()))?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("storage.googleapis.com")
        || !parsed.path().starts_with("/chrome-for-testing-public/")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::new("a Chrome for Testing storage URL is required"));
    }
    let mut recs = records(root)?;
    let marker = root.join(UNDO);
    let before = fs::read_to_string(&marker).ok();
    let temp = tempfile::Builder::new()
        .prefix(".chromium-check-")
        .tempdir_in(root)?;
    let archive_path = temp.path().join("build.zip");
    let mut response = client()?
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| Error::new(e.to_string()))?;
    let size = response
        .content_length()
        .filter(|s| *s <= 1_000_000_000)
        .ok_or_else(|| Error::new("needs a Content-Length within the limit"))?;
    let mut expected = None;
    let mut expected_md5 = None;
    for h in response.headers().get_all("x-goog-hash") {
        for pair in h.to_str().unwrap_or("").split(',') {
            if let Some(("md5", v)) = pair.trim().split_once('=') {
                expected_md5 = Some(v.to_string());
            }
            if let Some(("crc32c", v)) = pair.trim().split_once('=') {
                expected = Some(v.to_string());
            }
        }
    }
    if expected.is_none() && expected_md5.is_none() {
        return Err(Error::new(
            "server sent no x-goog-hash; refusing unverifiable download",
        ));
    }
    let mut md5 = Md5::new();
    let mut file = fs::File::create(&archive_path)?;
    let mut crc = 0xffffffffu32;
    let mut copied = 0u64;
    let mut bytes = [0u8; 65536];
    loop {
        let n = response.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        copied += n as u64;
        if copied > size {
            return Err(Error::new("download size does not match"));
        }
        md5.update(&bytes[..n]);
        for b in &bytes[..n] {
            crc ^= *b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82f63b78
                } else {
                    crc >> 1
                };
            }
        }
        file.write_all(&bytes[..n])?;
    }
    file.sync_all()?;
    let verified = if let Some(expected) = expected_md5 {
        base64::engine::general_purpose::STANDARD.encode(md5.finalize()) == expected
    } else {
        base64::engine::general_purpose::STANDARD.encode((crc ^ 0xffffffff).to_be_bytes())
            == expected.unwrap()
    };
    if copied != size || !verified {
        return Err(Error::new("browser size or checksum does not match"));
    }
    let extract = temp.path().join("x");
    let mut archive = zip::ZipArchive::new(fs::File::open(archive_path)?)
        .map_err(|e| Error::new(e.to_string()))?;
    safe_extract(&mut archive, &extract)?;
    let fresh = extract.join(layout_dir.file_name().unwrap());
    let exe = field(build, "path")?;
    let relative = Path::new(exe)
        .strip_prefix(&layout_dir)
        .map_err(|_| Error::new("browser executable is outside the layout"))?;
    if crate::scanner::browsers::version(&fresh, &fresh.join(relative))? != new {
        return Err(Error::new("downloaded browser version differs"));
    }
    recs.push(json!({"layout_dir":layout_dir,"backup_dir":backup,"old_version":old,"new_version":new,"url":url,"at":crate::store::now()}));
    crate::store::atomic(&marker, &serde_json::to_string_pretty(&recs)?)?;
    let restore_marker = || -> Result<()> {
        if let Some(before) = &before {
            crate::store::atomic(&marker, before)?;
        } else {
            fs::remove_file(&marker)?;
        }
        Ok(())
    };
    if let Err(error) = fs::rename(&layout_dir, &backup) {
        restore_marker()?;
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&fresh, &layout_dir) {
        if let Err(rollback) = fs::rename(&backup, &layout_dir) {
            let mut error = Error::new(format!(
                "{error}; rollback: {rollback}; retained undo record"
            ));
            error.class = "rollback-failed".into();
            return Err(error);
        }
        restore_marker()?;
        return Err(error.into());
    }
    Ok(json!({"status":"installed","version":new,"layout_dir":layout_dir,"backup_dir":backup}))
}
fn undo_root(root: &Path) -> Result<i32> {
    let _lock = root_lock(root)?;
    let mut code = 0;
    let mut kept = Vec::new();
    for record in records(root)?.into_iter().rev() {
        if !valid_undo(root, &record) {
            kept.push(record);
            code = 2;
            continue;
        }
        let (layout, backup) = (
            Path::new(field(&record, "layout_dir")?),
            Path::new(field(&record, "backup_dir")?),
        );
        if !backup.is_dir() {
            if layout.is_dir() {
                // Drop the stale record, but keep the failing exit: nothing was restored.
                eprintln!(
                    "Warning: no backup for {}; removed its stale undo record, nothing restored",
                    layout.display()
                );
                code = 2;
            } else {
                kept.push(record);
                code = 2;
            }
            continue;
        }
        if layout.exists() {
            fs::remove_dir_all(layout)?;
        }
        fs::rename(backup, layout)?;
    }
    if kept.is_empty() {
        if root.join(UNDO).exists() {
            fs::remove_file(root.join(UNDO))?;
        }
    } else {
        kept.reverse();
        crate::store::atomic(&root.join(UNDO), &serde_json::to_string_pretty(&kept)?)?;
    }
    Ok(code)
}
pub fn run_browser(state: &Path, roots: &[PathBuf], apply: bool, undo: bool) -> Result<i32> {
    let (builds, errors) = crate::scanner::browsers::collect(roots, None);
    if undo {
        let roots: BTreeSet<PathBuf> = builds
            .iter()
            .filter_map(|b| {
                b["layout_dir"]
                    .as_str()
                    .and_then(|s| Path::new(s).parent())
                    .map(Path::to_path_buf)
            })
            .collect();
        let mut code = 0;
        for root in roots {
            code = code.max(undo_root(&root)?);
        }
        return Ok(code);
    }
    if !errors.is_empty() {
        return Err(Error::new(errors.join("; ")));
    }
    let options = crate::domain::ScanOptions {
        inventory: crate::domain::InventoryOptions {
            roots: roots.to_vec(),
            browsers: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut store = crate::store::Store::open(state)?;
    let scan = Value::Object(crate::cli::check(&options, &mut store)?);
    let response = client()?
        .get(KNOWN)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| Error::new(e.to_string()))?;
    let mut data = String::new();
    response.take(32_000_001).read_to_string(&mut data)?;
    if data.len() > 32_000_000 {
        return Err(Error::new("browser catalog is too large"));
    }
    let known: Value = serde_json::from_str(&data)?;
    for b in builds {
        let Some(current) = b["version"].as_str().and_then(version) else {
            continue;
        };
        let needs = scan["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["package"]["path"] == b["path"])
            .flat_map(|f| {
                if let Some(v) = f["fixed"].as_str() {
                    vec![v.to_string()]
                } else {
                    f["fixed"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                }
            })
            .filter_map(|v| version(&v))
            .max();
        let Some(needs) = needs else {
            continue;
        };
        let mut candidates = Vec::new();
        for entry in known["versions"].as_array().into_iter().flatten() {
            if let Some(v) = entry["version"].as_str().and_then(version) {
                if v[0] == current[0] && v >= needs {
                    for dl in entry["downloads"][field(&b, "kind")?]
                        .as_array()
                        .into_iter()
                        .flatten()
                    {
                        if dl["platform"] == b["platform"] {
                            candidates.push((
                                v.clone(),
                                entry["version"].clone(),
                                dl["url"].clone(),
                            ));
                        }
                    }
                }
            }
        }
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some((_, new, url)) = candidates.pop() {
            if apply {
                println!(
                    "{}",
                    install(&b, new.as_str().unwrap(), url.as_str().unwrap())?
                );
            } else {
                println!(
                    "{}",
                    json!({"status":"dry-run","layout_dir":b["layout_dir"],"version":new,"url":url})
                );
            }
        } else {
            println!(
                "{}",
                json!({"status":"manual-update-required","layout_dir":b["layout_dir"]})
            );
        }
    }
    let final_scan = if apply {
        Value::Object(crate::cli::check(&options, &mut store)?)
    } else {
        scan
    };
    Ok(if final_scan["status"] == "unknown" {
        2
    } else if final_scan["findings"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        3
    } else {
        0
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn undo_drops_record_left_by_install_interrupted_before_the_layout_moved() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let layout = root.join("chrome-linux64");
        fs::create_dir(&layout).unwrap();
        let backup = root.join("chrome-linux64.chromium-check-backup-120.0.0.0");
        let record = json!({"layout_dir":layout,"backup_dir":backup,"old_version":"120.0.0.0","new_version":"120.0.0.1"});
        crate::store::atomic(&root.join(UNDO), &json!([record]).to_string()).unwrap();
        assert_eq!(undo_root(&root).unwrap(), 2, "nothing was restored");
        assert!(!root.join(UNDO).exists(), "the stale record is dropped");
        assert!(layout.is_dir());
        assert_eq!(undo_root(&root).unwrap(), 0, "the next undo is clean");
        fs::remove_dir(&layout).unwrap();
        crate::store::atomic(&root.join(UNDO), &json!([record]).to_string()).unwrap();
        assert_eq!(undo_root(&root).unwrap(), 2, "nothing on disk to restore");
        assert!(root.join(UNDO).exists());
    }
}
