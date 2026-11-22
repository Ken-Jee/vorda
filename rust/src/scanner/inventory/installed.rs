use super::super::{error, input, now, package};
use crate::{domain::Package, Result};
use serde_json::{json, Value};
use std::{io::Cursor, path::Path};

const MAX_METADATA: u64 = 4_000_000;

#[derive(Default)]
pub struct SourceInventory {
    pub packages: Vec<Package>,
    pub outcomes: Vec<Value>,
}

#[derive(Default)]
pub struct RegistryEntry {
    pub key: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_location: String,
    pub errors: Vec<String>,
}

pub struct RegistrySnapshot {
    pub hive: String,
    pub view: u32,
    pub outcome: String,
    pub entries: Vec<RegistryEntry>,
    pub errors: Vec<String>,
}

fn observation(source: &str, path: &str, outcome: &str, errors: &[String], count: usize) -> Value {
    json!({"source":source,"path":path,"outcome":outcome,"observed":now(),"package_count":count,"errors":errors,
        "presence":if outcome=="missing" {"observed-absence"}else if outcome=="complete" {"metadata-present"}else{"unknown"},"running":"unknown","advisory_coverage":"not-assessed",
        "limitations":["Metadata presence does not prove execution, reachability or complete application coverage"]})
}

fn identified(
    name: &str,
    version: &str,
    ecosystem: &str,
    path: &str,
    source: &str,
    presence: &str,
) -> Package {
    let version = version.trim();
    let candidate = version.strip_prefix('v').unwrap_or(version);
    let known = candidate.starts_with(|c: char| c.is_ascii_digit())
        && candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+_~!-".contains(c))
        && version.len() <= 256;
    let mut p = package(
        name,
        if known { version } else { "unknown" },
        ecosystem,
        path,
        false,
        "installed",
    );
    p.extra.extend(super::super::record(json!({"collector_source":source,"source_id":path,"observed":now(),
        "presence":presence,"running":"unknown","raw_version":version,
        "version_evidence":if known {"metadata"}else{"unknown"},
        "advisory_mapping":if ["npm","PyPI","Maven","NuGet"].contains(&ecosystem)&&known {"coordinate"}else{"unsupported"}})));
    p
}

pub fn registry_inventory(snapshots: &[RegistrySnapshot]) -> SourceInventory {
    let mut result = SourceInventory::default();
    for snapshot in snapshots {
        let source = format!("windows-uninstall:{}:{}", snapshot.hive, snapshot.view);
        let mut errors = snapshot.errors.clone();
        let start = result.packages.len();
        for item in &snapshot.entries {
            errors.extend(item.errors.iter().map(|e| format!("{}: {e}", item.key)));
            if item.name.trim().is_empty() {
                continue;
            }
            let path = format!("{source}/{}", item.key);
            let mut p = identified(
                &item.name,
                &item.version,
                "Windows registered app",
                &path,
                "windows-uninstall",
                "registered",
            );
            p.extra.extend(super::super::record(json!({"registry_hive":snapshot.hive,"registry_view":snapshot.view,
                "registry_key":item.key,"publisher":item.publisher,"install_location":item.install_location})));
            result.packages.push(p);
        }
        let outcome = if snapshot.outcome == "complete" && !errors.is_empty() {
            "partial"
        } else {
            &snapshot.outcome
        };
        result.outcomes.push(observation(
            "windows-uninstall",
            &source,
            outcome,
            &errors,
            result.packages.len() - start,
        ));
    }
    result
}

#[cfg(not(windows))]
pub fn windows_inventory() -> SourceInventory {
    SourceInventory {
        packages: vec![],
        outcomes: vec![observation(
            "windows-uninstall",
            "windows-uninstall",
            "unsupported",
            &["Windows registry is unavailable on this platform".into()],
            0,
        )],
    }
}

#[cfg(windows)]
pub fn windows_inventory() -> SourceInventory {
    registry_inventory(&windows::snapshots())
}

// This source is activation registration metadata, not all installed MSIX packages.
pub fn msix_inventory(snapshot: &RegistrySnapshot) -> SourceInventory {
    let source = "windows-msix:HKCU:activatable-packages";
    let mut result = SourceInventory::default();
    let mut errors = snapshot.errors.clone();
    for entry in &snapshot.entries {
        errors.extend(entry.errors.clone());
        let parts: Vec<_> = entry.key.split('_').collect();
        let valid_identity = parts.len() == 5 && !parts[0].is_empty() && !parts[4].is_empty();
        let (name, version) = if valid_identity {
            (parts[0], parts[1])
        } else {
            errors.push(format!("{}: malformed package identity", entry.key));
            (entry.key.as_str(), "")
        };
        let mut package = identified(
            name,
            version,
            "MSIX",
            &format!("{source}/{}", entry.key),
            "windows-msix",
            "registered",
        );
        // MSIX versions have four unsigned 16-bit components. Keep invalid raw evidence.
        if !valid_identity
            || version.split('.').count() != 4
            || version.split('.').any(|v| {
                v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) || v.parse::<u16>().is_err()
            })
        {
            package.version = "unknown".into();
            package
                .extra
                .insert("version_evidence".into(), json!("unknown"));
        }
        package
            .extra
            .insert("package_full_name".into(), json!(entry.key));
        result.packages.push(package);
    }
    let outcome = if snapshot.outcome == "complete" && !errors.is_empty() {
        "partial"
    } else {
        &snapshot.outcome
    };
    let mut observed = observation(
        "windows-msix",
        source,
        outcome,
        &errors,
        result.packages.len(),
    );
    observed["limitations"].as_array_mut().unwrap().push(json!("Current-user activation registrations only; packages without activation registrations may be absent"));
    result.outcomes.push(observed);
    result
}

pub fn current_user_msix_inventory() -> SourceInventory {
    #[cfg(windows)]
    {
        msix_inventory(&windows::msix_snapshot())
    }
    #[cfg(not(windows))]
    {
        msix_inventory(&RegistrySnapshot {
            hive: "HKCU".into(),
            view: 0,
            outcome: "unsupported".into(),
            entries: vec![],
            errors: vec!["Windows registry is unavailable on this platform".into()],
        })
    }
}

pub fn selected(path: &Path) -> SourceInventory {
    let mut result = SourceInventory::default();
    let selected = path.to_string_lossy().into_owned();
    let absolute = match input::absolute(path) {
        Ok(path) => path,
        Err(e) => {
            result.outcomes.push(observation(
                "selected-metadata",
                &selected,
                "denied",
                &[e.to_string()],
                0,
            ));
            return result;
        }
    };
    let selected = absolute.to_string_lossy().into_owned();
    let bundle = absolute.extension().and_then(|s| s.to_str()) == Some("app");
    let file = if bundle {
        absolute.join("Contents/Info.plist")
    } else {
        absolute.clone()
    };
    let name = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let source = match name {
        "Info.plist" => "macos-bundle",
        "AppxManifest.xml" => "msix-manifest",
        "metadata" => "flatpak-metadata",
        "snap.yaml" => "snap-metadata",
        "manifest.json" => "nix-profile-manifest",
        "METADATA" => "python-dist-info",
        "package.json" => "npm-package-metadata",
        "pom.properties" => "maven-artifact-metadata",
        "packages.lock.json" => "nuget-lock",
        "syft.json" => "selected-syft",
        _ => {
            result.outcomes.push(observation("selected-metadata", &selected, "unsupported", &["Select a supported metadata file or one .app bundle; directories are not searched".into()], 0));
            return result;
        }
    };
    let read = input::read_regular(
        &file,
        if bundle {
            Some(absolute.as_path())
        } else {
            file.parent()
        },
        MAX_METADATA,
        false,
    );
    match read {
        Ok(bytes) => {
            let parsed = if source == "nuget-lock" {
                std::str::from_utf8(&bytes)
                    .map_err(error)
                    .and_then(|text| nuget_lock_report(text, &selected))
            } else {
                parse_metadata(source, &bytes, &selected).map(|packages| (packages, vec![]))
            };
            match parsed {
                Ok((mut packages, issues)) => {
                    let mut evidence = if !issues.is_empty() {
                        observation(source, &selected, "partial", &issues, packages.len())
                    } else if source == "selected-syft" {
                        observation(source,&selected,"partial",&["Imported SBOM producer observation time and completeness are unknown".into()],packages.len())
                    } else {
                        observation(source, &selected, "complete", &[], packages.len())
                    };
                    evidence["metadata_path"] = json!(file);
                    for package in &mut packages {
                        package.extra.insert("metadata_path".into(), json!(file));
                    }
                    result.outcomes.push(evidence);
                    result.packages = packages;
                }
                Err(e) => result.outcomes.push(observation(
                    source,
                    &selected,
                    "malformed",
                    &[e.to_string()],
                    0,
                )),
            }
        }
        Err(e) => {
            let outcome = match std::fs::symlink_metadata(&file) {
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && (!bundle || !absolute.exists()) =>
                {
                    "missing"
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => "denied",
                _ if e.message.contains("Permission denied")
                    || e.message.contains("Access is denied") =>
                {
                    "denied"
                }
                _ => "unknown",
            };
            result
                .outcomes
                .push(observation(source, &selected, outcome, &[e.to_string()], 0));
        }
    }
    result
}

fn field<'a>(data: &'a Value, name: &str) -> &'a str {
    data.get(name).and_then(Value::as_str).unwrap_or("")
}

pub(super) fn nuget_lock_report(text: &str, path: &str) -> Result<(Vec<Package>, Vec<String>)> {
    let parsed = (|| {
        super::lock_validation::format("packages.lock.json", text)?;
        let data: Value = serde_json::from_str(text)?;
        let groups = data
            .get("dependencies")
            .and_then(Value::as_object)
            .ok_or_else(|| error("missing NuGet dependencies map"))?;
        let mut packages = vec![];
        let mut issues = vec![];
        for group in groups.values() {
            let items = group
                .as_object()
                .ok_or_else(|| error("invalid NuGet target map"))?;
            for (name, package) in items {
                let kind = field(package, "type");
                if kind.eq_ignore_ascii_case("project") {
                    continue;
                }
                if !["direct", "transitive", "centraltransitive"]
                    .contains(&kind.to_ascii_lowercase().as_str())
                {
                    issues.push(super::lock_validation::uncheckable(
                        name,
                        &format!("unsupported NuGet dependency type {kind}"),
                    ));
                    continue;
                }
                let version = field(package, "resolved");
                if let Some(issue) = super::lock_validation::entry_issue(name, version, "NuGet") {
                    issues.push(issue);
                } else {
                    packages.push(identified(
                        name,
                        version,
                        "NuGet",
                        path,
                        "nuget-lock",
                        "referenced",
                    ));
                }
            }
        }
        Ok((packages, issues))
    })();
    parsed.map_err(super::lock_validation::file)
}

pub(super) fn parse_metadata(source: &str, bytes: &[u8], path: &str) -> Result<Vec<Package>> {
    if source == "nuget-lock" {
        let text = std::str::from_utf8(bytes).map_err(error)?;
        let (packages, issues) = nuget_lock_report(text, path)?;
        if !issues.is_empty() {
            return Err(error(issues.join("; ")));
        }
        return Ok(packages);
    }
    let mut out = vec![];
    let mut add = |name: &str, version: &str, ecosystem: &str, presence: &str| -> Result<()> {
        if name.trim().is_empty() || name.len() > 4096 || name.chars().any(char::is_control) {
            return Err(error("missing or invalid metadata identity"));
        }
        out.push(identified(name, version, ecosystem, path, source, presence));
        Ok(())
    };
    if source == "macos-bundle" {
        let value = plist::Value::from_reader(Cursor::new(bytes)).map_err(error)?;
        let d = value
            .as_dictionary()
            .ok_or_else(|| error("expected a bundle plist dictionary"))?;
        let get = |key| d.get(key).and_then(plist::Value::as_string).unwrap_or("");
        let name = if get("CFBundleIdentifier").is_empty() {
            get("CFBundleName")
        } else {
            get("CFBundleIdentifier")
        };
        let version = if get("CFBundleShortVersionString").is_empty() {
            get("CFBundleVersion")
        } else {
            get("CFBundleShortVersionString")
        };
        add(name, version, "macOS bundle", "selected-bundle")?;
        return Ok(out);
    }
    if source == "msix-manifest" {
        let mut reader = quick_xml::Reader::from_reader(bytes);
        let mut identity = None;
        loop {
            match reader.read_event().map_err(error)? {
                quick_xml::events::Event::Start(e) | quick_xml::events::Event::Empty(e)
                    if e.local_name().as_ref() == "Identity" =>
                {
                    if identity.is_some() {
                        return Err(error("duplicate MSIX identity"));
                    }
                    let mut fields = std::collections::BTreeMap::new();
                    for attribute in e.attributes() {
                        let a = attribute.map_err(error)?;
                        fields.insert(
                            a.key.as_ref().to_owned(),
                            a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                .map_err(error)?
                                .into_owned(),
                        );
                    }
                    identity = Some(fields);
                }
                quick_xml::events::Event::DocType(_) => {
                    return Err(error("document types in MSIX are unsupported"))
                }
                quick_xml::events::Event::Eof => break,
                _ => {}
            }
        }
        let fields = identity.ok_or_else(|| error("missing MSIX identity"))?;
        let name = fields.get("Name").map(String::as_str).unwrap_or("");
        let version = fields.get("Version").map(String::as_str).unwrap_or("");
        add(name, version, "MSIX package", "selected-manifest")?;
        return Ok(out);
    }
    let text = std::str::from_utf8(bytes).map_err(error)?;
    if source == "selected-syft" {
        let document: Value = serde_json::from_str(text)?;
        if document
            .get("artifacts")
            .and_then(Value::as_array)
            .is_none()
        {
            return Err(error("expected a Syft JSON artifacts array"));
        }
        let packages = super::super::outputs::syft_packages(&document, path)?;
        return packages
            .into_iter()
            .map(|p| {
                if p.name.trim().is_empty() || p.name.chars().any(char::is_control) {
                    return Err(error("missing or invalid SBOM package identity"));
                }
                let mut selected = identified(
                    &p.name,
                    &p.version,
                    &p.ecosystem,
                    path,
                    source,
                    "imported-metadata",
                );
                selected.extra.extend(p.extra);
                selected
                    .extra
                    .insert("producer_observed".into(), Value::Null);
                selected
                    .extra
                    .insert("producer_age".into(), json!("unknown"));
                Ok(selected)
            })
            .collect();
    }
    match source {
        "npm-package-metadata" => {
            let d: Value = serde_json::from_str(text)?;
            add(
                field(&d, "name"),
                field(&d, "version"),
                "npm",
                "selected-metadata",
            )?;
        }
        "snap-metadata" => {
            let d: Value = serde_norway::from_str(text).map_err(error)?;
            let version = d
                .get("version")
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default();
            add(field(&d, "name"), &version, "Snap", "selected-metadata")?;
        }
        "python-dist-info" => {
            let headers: Vec<_> = text
                .lines()
                .take_while(|line| !line.trim().is_empty())
                .collect();
            let get = |key: &str| {
                headers
                    .iter()
                    .find_map(|line| line.strip_prefix(key))
                    .unwrap_or("")
                    .trim()
            };
            if get("Metadata-Version:").is_empty() {
                return Err(error("missing Python Metadata-Version"));
            }
            add(get("Name:"), get("Version:"), "PyPI", "selected-metadata")?;
        }
        "maven-artifact-metadata" => {
            let get = |key: &str| {
                text.lines()
                    .filter(|line| !line.trim_start().starts_with(['#', '!']))
                    .find_map(|line| {
                        line.split_once('=')
                            .filter(|(k, _)| k.trim() == key)
                            .map(|(_, v)| v.trim())
                    })
                    .unwrap_or("")
            };
            if get("groupId").is_empty() || get("artifactId").is_empty() {
                return Err(error("missing Maven groupId/artifactId"));
            }
            if text.contains('\\') {
                return Err(error(
                    "escaped Java properties require an explicit SBOM export",
                ));
            }
            add(
                &format!("{}:{}", get("groupId"), get("artifactId")),
                get("version"),
                "Maven",
                "selected-metadata",
            )?;
        }
        "flatpak-metadata" => {
            let mut section = "";
            let mut name = "";
            let mut runtime = "";
            for line in text.lines().map(str::trim) {
                if line.starts_with('[') && line.ends_with(']') {
                    section = &line[1..line.len() - 1];
                }
                if let Some((key, value)) = line.split_once('=') {
                    if ["Application", "Runtime"].contains(&section) && key == "name" {
                        name = value;
                    }
                    if section == "Application" && key == "runtime" {
                        runtime = value;
                    }
                }
            }
            add(name, "", "Flatpak", "selected-metadata")?;
            if !runtime.is_empty() {
                add(runtime, "", "Flatpak runtime", "referenced")?;
            }
        }
        "nix-profile-manifest" => {
            let d: Value = serde_json::from_str(text)?;
            if !matches!(d.get("version").and_then(Value::as_u64), Some(1..=3)) {
                return Err(error("unsupported Nix manifest version"));
            }
            let elements = d
                .get("elements")
                .ok_or_else(|| error("missing Nix profile elements"))?;
            let entries: Vec<(&str, &Value)> = if let Some(items) = elements.as_object() {
                items.iter().map(|(k, v)| (k.as_str(), v)).collect()
            } else if let Some(items) = elements.as_array() {
                items.iter().map(|v| ("", v)).collect()
            } else {
                return Err(error("invalid Nix profile elements"));
            };
            for (name, p) in entries {
                match p.get("active").and_then(Value::as_bool) {
                    Some(false) => continue,
                    Some(true) => {}
                    None => return Err(error("missing or invalid Nix active flag")),
                }
                let name = if name.is_empty() {
                    field(p, "attrPath")
                } else {
                    name
                };
                let stores = p
                    .get("storePaths")
                    .and_then(Value::as_array)
                    .ok_or_else(|| error("missing Nix store references"))?;
                if stores.is_empty() || stores.iter().any(|v| v.as_str().is_none_or(str::is_empty))
                {
                    return Err(error("invalid Nix store references"));
                }
                add(name, "", "Nix", "referenced")?;
            }
        }
        _ => return Err(error("unsupported selected metadata")),
    }
    Ok(out)
}

#[cfg(windows)]
mod windows {
    use super::{RegistryEntry, RegistrySnapshot};
    use std::{
        ffi::c_void,
        ptr::null_mut,
        time::{Duration, Instant},
    };
    type Hkey = *mut c_void;
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            key: Hkey,
            subkey: *const u16,
            options: u32,
            access: u32,
            result: *mut Hkey,
        ) -> i32;
        fn RegEnumKeyExW(
            key: Hkey,
            index: u32,
            name: *mut u16,
            count: *mut u32,
            reserved: *mut u32,
            class: *mut u16,
            class_count: *mut u32,
            time: *mut c_void,
        ) -> i32;
        fn RegQueryValueExW(
            key: Hkey,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            bytes: *mut u32,
        ) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }
    struct Key(Hkey);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    fn open(parent: Hkey, name: &str, view: u32, access: u32) -> std::result::Result<Key, i32> {
        let mut key = null_mut();
        let status =
            unsafe { RegOpenKeyExW(parent, wide(name).as_ptr(), 0, access | view, &mut key) };
        if status == 0 {
            Ok(Key(key))
        } else {
            Err(status)
        }
    }
    fn value(key: &Key, name: &str) -> std::result::Result<String, String> {
        let mut data = vec![0u16; 4096];
        let mut bytes = (data.len() * 2) as u32;
        let mut kind = 0;
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                wide(name).as_ptr(),
                null_mut(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status == 2 {
            return Ok(String::new());
        }
        if status != 0 {
            return Err(format!("{name}: registry error {status}"));
        }
        if ![1, 2].contains(&kind) || bytes % 2 != 0 || bytes as usize > data.len() * 2 {
            return Err(format!("{name}: unsupported registry value"));
        }
        let count = bytes as usize / 2;
        let text =
            String::from_utf16(&data[..count]).map_err(|_| format!("{name}: invalid UTF-16"))?;
        let text = text.trim_end_matches('\0');
        if text.chars().any(char::is_control) {
            return Err(format!("{name}: control characters in metadata"));
        }
        Ok(text.into())
    }
    pub fn msix_snapshot() -> RegistrySnapshot {
        let mut snapshot = RegistrySnapshot {
            hive: "HKCU".into(),
            view: 0,
            outcome: "complete".into(),
            entries: vec![],
            errors: vec![],
        };
        let root = match open(
            0x80000001u32 as i32 as isize as Hkey,
            "Software\\Classes\\ActivatableClasses\\Package",
            0,
            0x0008,
        ) {
            Ok(key) => key,
            Err(code) => {
                snapshot.outcome = match code {
                    2 | 3 => "missing",
                    5 => "denied",
                    _ => "unknown",
                }
                .into();
                if ![2, 3].contains(&code) {
                    snapshot.errors.push(format!("registry error {code}"));
                }
                return snapshot;
            }
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut total = 0usize;
        for index in 0..10_000 {
            if Instant::now() >= deadline || total >= 4_000_000 {
                snapshot
                    .errors
                    .push("MSIX enumeration time/metadata limit reached".into());
                break;
            }
            let mut name = [0u16; 256];
            let mut length = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    root.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if status == 259 {
                if !snapshot.errors.is_empty() {
                    snapshot.outcome = "partial".into();
                }
                return snapshot;
            }
            if status != 0 {
                snapshot
                    .errors
                    .push(format!("Subkey {index}: registry error {status}"));
                break;
            }
            match String::from_utf16(&name[..length as usize]) {
                Ok(key) => {
                    total += key.len();
                    snapshot.entries.push(RegistryEntry {
                        key,
                        ..Default::default()
                    });
                }
                Err(_) => snapshot
                    .errors
                    .push("invalid UTF-16 package identity".into()),
            }
        }
        snapshot.outcome = "partial".into();
        if snapshot.errors.is_empty() {
            snapshot.errors.push("MSIX subkey limit reached".into());
        }
        snapshot
    }
    pub fn snapshots() -> Vec<RegistrySnapshot> {
        let mut out = vec![];
        for (hive, id) in [("HKCU", 0x80000001u32), ("HKLM", 0x80000002u32)] {
            for (view, flag) in [(32, 0x0200), (64, 0x0100)] {
                let mut snapshot = RegistrySnapshot {
                    hive: hive.into(),
                    view,
                    outcome: "complete".into(),
                    entries: vec![],
                    errors: vec![],
                };
                let root = match open(
                    id as i32 as isize as Hkey,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    flag,
                    0x0008,
                ) {
                    Ok(key) => key,
                    Err(code) => {
                        snapshot.outcome = match code {
                            2 | 3 => "missing",
                            5 => "denied",
                            87 => "unsupported",
                            _ => "unknown",
                        }
                        .into();
                        if ![2, 3].contains(&code) {
                            snapshot.errors.push(format!("registry error {code}"));
                        }
                        out.push(snapshot);
                        continue;
                    }
                };
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut total = 0usize;
                let mut exhausted = false;
                for index in 0..10_000 {
                    if Instant::now() >= deadline || total > 4_000_000 {
                        snapshot
                            .errors
                            .push("registry enumeration time/metadata limit reached".into());
                        break;
                    }
                    let mut name = [0u16; 256];
                    let mut length = name.len() as u32;
                    let status = unsafe {
                        RegEnumKeyExW(
                            root.0,
                            index,
                            name.as_mut_ptr(),
                            &mut length,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    };
                    if status == 259 {
                        exhausted = true;
                        break;
                    }
                    if status != 0 {
                        snapshot
                            .errors
                            .push(format!("Subkey {index}: registry error {status}"));
                        break;
                    }
                    let name = match String::from_utf16(&name[..length as usize]) {
                        Ok(name) => name,
                        Err(_) => {
                            snapshot.errors.push("invalid UTF-16 subkey".into());
                            continue;
                        }
                    };
                    let key = match open(root.0, &name, flag, 0x0001) {
                        Ok(key) => key,
                        Err(code) => {
                            snapshot
                                .errors
                                .push(format!("{name}: registry error {code}"));
                            continue;
                        }
                    };
                    let mut item = RegistryEntry {
                        key: name,
                        ..Default::default()
                    };
                    let mut get = |field| match value(&key, field) {
                        Ok(value) => value,
                        Err(e) => {
                            item.errors.push(e);
                            String::new()
                        }
                    };
                    item.name = get("DisplayName");
                    // Non-application keys have no DisplayName; do not read their other values.
                    if !item.name.is_empty() {
                        item.version = get("DisplayVersion");
                        item.publisher = get("Publisher");
                        item.install_location = get("InstallLocation");
                    }
                    total += item.key.len()
                        + item.name.len()
                        + item.version.len()
                        + item.publisher.len()
                        + item.install_location.len();
                    snapshot.entries.push(item);
                }
                if !exhausted && snapshot.errors.is_empty() {
                    snapshot.errors.push("registry subkey limit reached".into());
                }
                if !snapshot.errors.is_empty()
                    || snapshot.entries.iter().any(|e| !e.errors.is_empty())
                {
                    snapshot.outcome = "partial".into();
                }
                out.push(snapshot);
            }
        }
        out
    }
}
