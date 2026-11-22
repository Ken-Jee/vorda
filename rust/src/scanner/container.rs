use super::{error, input, outputs, record};
use crate::{
    domain::{Package, Record},
    Result,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    path::Path,
};

#[derive(Clone, Copy)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_members: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            max_members: 100_000,
        }
    }
}
#[derive(Serialize)]
pub struct ContainerInventory {
    pub packages: Vec<Package>,
    pub coverage: Vec<Record>,
    pub errors: Vec<String>,
    pub status: String,
    pub source: String,
    /// The image's name (from the archive's index annotations), distro and advisory ecosystem.
    pub image: Value,
}
type Files = BTreeMap<String, Option<Vec<u8>>>;
fn read_tar(data: &[u8], remaining: &mut Limits) -> Result<Files> {
    let reader: Box<dyn Read + '_> = if data.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(data))
    } else if data.starts_with(b"BZh") {
        Box::new(bzip2::read::BzDecoder::new(data))
    } else if data.starts_with(b"\xfd7zXZ") {
        Box::new(xz2::read::XzDecoder::new(data))
    } else {
        Box::new(data)
    };
    let mut payload = Vec::new();
    reader
        .take(remaining.max_bytes as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(error)?;
    if payload.len() > remaining.max_bytes {
        return Err(error("archive exceeds configured limits"));
    }
    remaining.max_bytes -= payload.len();
    let mut files = Files::new();
    let mut archive = tar::Archive::new(Cursor::new(payload));
    for entry in archive.entries().map_err(error)? {
        if remaining.max_members == 0 {
            return Err(error("archive exceeds configured limits"));
        }
        remaining.max_members -= 1;
        let mut entry = entry.map_err(error)?;
        let raw = entry.path_bytes();
        let raw = std::str::from_utf8(&raw).map_err(error)?;
        if raw.starts_with('/') || raw.contains('\\') || raw.split('/').any(|p| p == "..") {
            return Err(error("archive path is unsafe"));
        }
        let name = raw
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect::<Vec<_>>()
            .join("/");
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            files.insert(name, None);
            continue;
        }
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() || entry.header().as_bytes()[156] == b'S' {
            return Err(error("unsupported archive member type"));
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(error)?;
        files.insert(name, Some(bytes));
    }
    Ok(files)
}
fn blob<'a>(files: &'a Files, digest: &str) -> Result<&'a [u8]> {
    let value = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| error("unsupported blob digest"))?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error("unsupported blob digest"));
    }
    let bytes = files
        .get(&format!("blobs/sha256/{value}"))
        .ok_or_else(|| error("missing OCI blob"))?
        .as_deref()
        .ok_or_else(|| error("linked OCI metadata is unsupported"))?;
    if format!("{:x}", Sha256::digest(bytes)) != value {
        return Err(error("blob digest does not match"));
    }
    Ok(bytes)
}
fn collect(path: &Path, limits: Limits) -> Result<Collected> {
    let bytes = input::read_regular(path, None, 512_000_000, false)?;
    let mut remaining = limits;
    let files = read_tar(&bytes, &mut remaining)?;
    let index = files
        .get("index.json")
        .ok_or_else(|| {
            error("expected an OCI archive with index.json; Docker archives are unsupported")
        })?
        .as_deref()
        .ok_or_else(|| error("linked OCI metadata is unsupported"))?;
    let index: Value = serde_json::from_slice(index)?;
    let manifests = index["manifests"]
        .as_array()
        .ok_or_else(|| error("invalid OCI index"))?;
    if manifests.len() != 1 {
        return Err(error("select a single-image OCI archive"));
    }
    let mut manifest: Value =
        serde_json::from_slice(blob(&files, super::string(&manifests[0], "digest"))?)?;
    for _ in 0..8 {
        let Some(manifests) = manifest.get("manifests") else {
            break;
        };
        let available: Vec<_> = super::array(manifests)
            .iter()
            .filter(|m| {
                files.contains_key(&format!(
                    "blobs/{}",
                    super::string(m, "digest").replacen(':', "/", 1)
                )) && m["platform"]["os"] != "unknown"
            })
            .collect();
        if available.len() != 1 {
            return Err(error(
                "expected exactly one locally available image platform",
            ));
        }
        manifest = serde_json::from_slice(blob(&files, super::string(available[0], "digest"))?)?;
    }
    let layers = manifest["layers"]
        .as_array()
        .ok_or_else(|| error("invalid OCI manifest"))?;
    let mut root = Files::new();
    for desc in layers {
        let layer = read_tar(blob(&files, super::string(desc, "digest"))?, &mut remaining)?;
        for name in layer.keys() {
            let (parent, base) = name.rsplit_once('/').unwrap_or(("", name));
            if base == ".wh..wh..opq" {
                let prefix = format!("{parent}/");
                root.retain(|k, _| !parent.is_empty() && !k.starts_with(&prefix));
            } else if let Some(target) = base.strip_prefix(".wh.") {
                let target = if parent.is_empty() {
                    target.into()
                } else {
                    format!("{parent}/{target}")
                };
                let prefix = format!("{target}/");
                root.retain(|k, _| *k != target && !k.starts_with(&prefix));
            }
        }
        root.extend(
            layer
                .into_iter()
                .filter(|(name, _)| !name.rsplit('/').next().unwrap_or("").starts_with(".wh.")),
        );
    }
    // os-release(5): read /etc/os-release, else /usr/lib/os-release. Debian and Ubuntu images
    // ship the first as a link to the second; links are not followed, so the fallback reads it.
    let release = ["etc/os-release", "usr/lib/os-release"]
        .iter()
        .find_map(|name| root.get(*name).and_then(Option::as_deref));
    let readable = release.is_some();
    let release = std::str::from_utf8(release.unwrap_or(&[])).map_err(error)?;
    let fields: BTreeMap<_, _> = release
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k, v.trim_matches(['\'', '"'])))
        .collect();
    let mut artifacts = Vec::new();
    let mut coverage = Vec::new();
    // dpkg blocks whose files may not match their version: reported, never checked.
    let mut unsure = Vec::new();
    for (filename, kind) in [
        ("lib/apk/db/installed", "apk"),
        ("var/lib/dpkg/status", "deb"),
    ] {
        let Some(data) = root.get(filename) else {
            continue;
        };
        let data = data
            .as_deref()
            .ok_or_else(|| error("linked package database is unsupported"))?;
        let text = std::str::from_utf8(data)
            .map_err(error)?
            .replace("\r\n", "\n");
        for block in text.split("\n\n") {
            let f: BTreeMap<_, _> = block
                .lines()
                .filter(|l| !l.starts_with(' '))
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k, v.trim()))
                .collect();
            if kind == "apk" && f.contains_key("P") && f.contains_key("V") {
                artifacts.push(json!({"name":f["P"],"version":f["V"],"type":kind,"metadata":{"originPackage":f.get("o").unwrap_or(&f["P"])}}));
            } else if kind == "deb" && !f.is_empty() {
                let shown = |s: &str| format!("{:?}", s.chars().take(96).collect::<String>());
                // `want flag state`, as dpkg-query reads it: config-files and not-installed
                // leave no files; half-installed and reinstreq leave unknown ones.
                let status: Vec<_> = f
                    .get("Status")
                    .map_or(vec![], |s| s.split_whitespace().collect());
                match status[..] {
                    [_, "ok", "installed" | "unpacked" | "half-configured" | "triggers-awaited"
                    | "triggers-pending"] => {}
                    [_, "ok", "config-files" | "not-installed"] => continue,
                    _ => {
                        unsure.push(format!(
                            "dpkg status: {} is {}, so its files may not match its version and it was not checked; coverage is unknown",
                            shown(f.get("Package").unwrap_or(&"a package")),
                            shown(f.get("Status").unwrap_or(&"without a Status line"))
                        ));
                        continue;
                    }
                }
                let name = f
                    .get("Package")
                    .ok_or_else(|| error("missing package name"))?;
                let version = f
                    .get("Version")
                    .ok_or_else(|| error("missing package version"))?;
                let source: Vec<_> = f.get("Source").unwrap_or(name).split_whitespace().collect();
                let mut metadata = json!({"source":source.first().unwrap_or(name)});
                if let Some(v) = source.get(1) {
                    metadata["sourceVersion"] = json!(v.trim_matches(['(', ')']));
                }
                artifacts
                    .push(json!({"name":name,"version":version,"type":kind,"metadata":metadata}));
            }
        }
        coverage.push(record(
            json!({"format":kind,"status":if unsure.is_empty() {"complete"} else {"partial"}}),
        ));
    }
    let packages = outputs::syft_packages(
        &json!({"distro":{"id":fields.get("ID").unwrap_or(&""),"versionID":fields.get("VERSION_ID").unwrap_or(&"")},"artifacts":artifacts}),
        &path.to_string_lossy(),
    )?;
    if root
        .keys()
        .any(|n| n.starts_with("var/lib/rpm/") || n.starts_with("usr/lib/sysimage/rpm/"))
    {
        coverage.push(record(json!({"format":"rpm","status":"unsupported"})));
    }
    let distro = format!(
        "{} {}",
        fields.get("ID").unwrap_or(&""),
        fields.get("VERSION_ID").unwrap_or(&"")
    );
    let distro = distro.trim();
    let annotations = &manifests[0]["annotations"];
    let name = [
        "io.containerd.image.name",
        "org.opencontainers.image.ref.name",
    ]
    .iter()
    .find_map(|k| annotations[*k].as_str());
    let ecosystem = packages.first().map(|p| &p.ecosystem);
    let image =
        json!({"name":name,"distro":(!distro.is_empty()).then_some(distro),"ecosystem":ecosystem});
    let mut errors = unsure;
    let unmatched = packages
        .iter()
        .filter(|p| {
            ["Unmapped:", "Unknown distro:"]
                .iter()
                .any(|u| p.ecosystem.starts_with(u))
        })
        .count();
    if unmatched > 0 {
        errors.push(if readable {
            format!("Image distro {distro} has no advisory mapping; {unmatched} OS packages are not checked")
        } else {
            format!("Image distro unknown (no readable os-release) so it has no advisory mapping; {unmatched} OS packages are not checked")
        });
    }
    let complete = !coverage.is_empty()
        && coverage.iter().all(|c| c["status"] == "complete")
        && unmatched == 0;
    Ok(Collected {
        packages,
        coverage,
        complete,
        image,
        errors,
    })
}
struct Collected {
    packages: Vec<Package>,
    coverage: Vec<Record>,
    complete: bool,
    image: Value,
    errors: Vec<String>,
}
pub fn inventory(path: &Path, limits: Limits) -> ContainerInventory {
    let mut result = ContainerInventory {
        packages: vec![],
        coverage: vec![],
        errors: vec![],
        status: "unknown".into(),
        source: path.to_string_lossy().into(),
        image: Value::Null,
    };
    match collect(path, limits) {
        Ok(c) => {
            result.packages = c.packages;
            result.coverage = c.coverage;
            result.image = c.image;
            result.errors = c.errors;
            if c.complete {
                result.status = "complete".into();
            }
        }
        Err(e) => result.errors.push(e.to_string()),
    }
    result
}
