use super::{array, error, feeds::FeedSource, input, string};
use crate::{domain::Package, Result};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

fn layout(name: &str) -> bool {
    regex::Regex::new(
        r"^(chrome|chrome-headless-shell)-(linux64|linux|mac-arm64|mac-x64|mac|win64|win32|win)$",
    )
    .unwrap()
    .is_match(name)
}
fn exact_version(v: &str) -> bool {
    regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+$")
        .unwrap()
        .is_match(v)
}
fn exe_for(dir: &Path) -> Option<PathBuf> {
    for n in [
        "chrome",
        "chrome-headless-shell",
        "headless_shell",
        "chromium",
        "chrome.exe",
        "chrome-headless-shell.exe",
        "headless_shell.exe",
        "chromium.exe",
    ] {
        let p = dir.join(n);
        if p.is_file() {
            return Some(p);
        }
    }
    for app in fs::read_dir(dir).ok()?.flatten() {
        if app.path().extension().is_some_and(|s| s == "app") {
            for e in fs::read_dir(app.path().join("Contents/MacOS"))
                .ok()?
                .flatten()
            {
                if e.path().is_file() {
                    return Some(e.path());
                }
            }
        }
    }
    None
}
pub fn version(dir: &Path, exe: &Path) -> Result<String> {
    input::refuse_links(exe)?;
    for f in fs::read_dir(dir).map_err(error)? {
        let f = f.map_err(error)?;
        if f.path().extension().is_some_and(|e| e == "manifest") {
            let stem = f
                .path()
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if exact_version(&stem) {
                return Ok(stem);
            }
        }
        if f.path().extension().is_some_and(|e| e == "app") {
            let path = f.path().join("Contents/Info.plist");
            if path.exists() {
                let bytes = input::read_regular(&path, None, input::MAX_FILE, false)?;
                let plist =
                    plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(error)?;
                if let Some(v) = plist
                    .as_dictionary()
                    .and_then(|p| p.get("CFBundleShortVersionString"))
                    .and_then(plist::Value::as_string)
                {
                    if exact_version(v) {
                        return Ok(v.into());
                    }
                }
            }
        }
    }
    let bytes = input::read_regular(exe, None, 512_000_000, false)?;
    if exe.extension().is_some_and(|e| e == "exe") {
        let key: Vec<_> = "VS_VERSION_INFO"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        if let Some(pos) = bytes.windows(key.len()).rposition(|b| b == key) {
            let end = (pos + 128).min(bytes.len());
            if let Some(sig) = bytes[pos..end]
                .windows(4)
                .position(|b| b == [0xbd, 0x04, 0xef, 0xfe])
            {
                let offset = pos + sig;
                if let (Some(ms), Some(ls)) = (
                    bytes.get(offset + 8..offset + 12),
                    bytes.get(offset + 12..offset + 16),
                ) {
                    let ms = u32::from_le_bytes(ms.try_into().unwrap());
                    let ls = u32::from_le_bytes(ls.try_into().unwrap());
                    return Ok(format!(
                        "{}.{}.{}.{}",
                        ms >> 16,
                        ms & 65535,
                        ls >> 16,
                        ls & 65535
                    ));
                }
            }
        }
        return Ok("unknown".into());
    }
    if !bytes.starts_with(b"\x7fELF") {
        return Ok("unknown".into());
    }
    let re =
        regex::bytes::Regex::new(r"\x00([0-9]{2,3}\.0\.[0-9]{4,5}\.[1-9][0-9]{0,2})\x00").unwrap();
    let versions: BTreeSet<_> = re
        .captures_iter(&bytes)
        .map(|c| String::from_utf8_lossy(&c[1]).into_owned())
        .collect();
    Ok(if versions.len() == 1 {
        versions.into_iter().next().unwrap()
    } else {
        "unknown".into()
    })
}
pub fn collect(roots: &[PathBuf], cache: Option<&Path>) -> (Vec<Value>, Vec<String>) {
    let mut errors = Vec::new();
    let mut builds = BTreeMap::new();
    let cache_path = cache.map(|p| p.join("versions.json"));
    let mut versions: Value = cache_path
        .as_ref()
        .filter(|p| p.exists())
        .and_then(
            |p| match input::text(p).and_then(|s| serde_json::from_str(&s).map_err(error)) {
                Ok(v) => Some(v),
                Err(e) => {
                    errors.push(format!("{}: {e}", p.display()));
                    None
                }
            },
        )
        .unwrap_or(json!({}));
    if !versions.is_object() {
        errors.push("invalid browser version cache".into());
        versions = json!({});
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default();
    let mut selected: Vec<_> = roots
        .iter()
        .map(|p| (p.clone(), "chrome for testing (unpacked)"))
        .collect();
    let mut defaults = vec![home.join(".cache/puppeteer")];
    let playwright = if cfg!(windows) {
        home.join("AppData/Local/ms-playwright")
    } else if cfg!(target_os = "macos") {
        home.join("Library/Caches/ms-playwright")
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"))
            .join("ms-playwright")
    };
    defaults.push(playwright);
    for var in ["PLAYWRIGHT_BROWSERS_PATH", "PUPPETEER_CACHE_DIR"] {
        if let Some(v) = std::env::var_os(var) {
            if v != "0" {
                defaults.push(v.into());
            }
        }
    }
    selected.extend(
        defaults
            .into_iter()
            .filter(|p| p.exists())
            .map(|p| (p, "browser cache")),
    );
    for (root, source) in selected {
        let root = match input::absolute(&root).and_then(|p| {
            input::refuse_links(&p)?;
            Ok(p)
        }) {
            Ok(p) => p,
            Err(e) => {
                errors.push(e.to_string());
                continue;
            }
        };
        if !root.is_dir() {
            if source != "browser cache" {
                errors.push(format!("{}: does not exist", root.display()));
            }
            continue;
        }
        let mut stack = vec![(root.clone(), 0)];
        let mut work = 0;
        while let Some((dir, depth)) = stack.pop() {
            let name = dir.file_name().unwrap_or_default().to_string_lossy();
            if layout(&name) {
                if let Some(exe) = exe_for(&dir) {
                    let key = exe.to_string_lossy().into_owned();
                    let v = match version_stamp(&dir, &exe).and_then(|stamp| {
                        let old = &versions[&key];
                        let v = if old["stamp"] == stamp {
                            string(old, "version").to_owned()
                        } else {
                            version_with_trust(&dir, &exe, source == "browser cache")?
                        };
                        versions[&key] = json!({"stamp":stamp,"version":v});
                        Ok(v)
                    }) {
                        Ok(v) => v,
                        Err(e) => {
                            errors.push(format!("{}: {e}", exe.display()));
                            "unknown".into()
                        }
                    };
                    let platform = name.split_once('-').map(|(_, p)| p);
                    builds.insert(dir.clone(),json!({"path":exe,"version":if v=="unknown"{Value::Null}else{json!(v)},"source":source,"label":name,"layout_dir":dir,"root":root,"platform":platform,"kind":if name.contains("headless"){"chrome-headless-shell"}else{"chrome"},"version_source":"static metadata or trusted cache probe"}));
                }
                continue;
            }
            if depth >= 10 {
                continue;
            }
            let entries = match fs::read_dir(&dir) {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("{}: {e}", dir.display()));
                    continue;
                }
            };
            for e in entries {
                work += 1;
                if work > 100_000 {
                    errors.push(format!("{}: traversal work limit exceeded", root.display()));
                    stack.clear();
                    break;
                }
                match e {
                    Ok(e) => {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if [
                            ".git",
                            ".hg",
                            ".svn",
                            "__pycache__",
                            "proc",
                            "sys",
                            "dev",
                            ".Trash",
                            "$Recycle.Bin",
                        ]
                        .contains(&name.as_str())
                        {
                            continue;
                        }
                        if input::linked(&e.path()) {
                            continue;
                        }
                        if dir.file_name().is_some_and(|n| n == "node_modules")
                            && !name.starts_with('@')
                            && ![
                                "playwright",
                                "playwright-core",
                                "patchright",
                                "patchright-core",
                                "puppeteer",
                                "puppeteer-core",
                                ".pnpm",
                            ]
                            .contains(&name.as_str())
                        {
                            continue;
                        }
                        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            stack.push((e.path(), depth + 1));
                        }
                    }
                    Err(e) => errors.push(e.to_string()),
                }
            }
        }
    }
    let mut out: Vec<_> = builds.into_values().collect();
    let dotted = regex::Regex::new(r"\d+\.\d+\.\d+\.\d+").unwrap();
    for name in [
        "google-chrome-stable",
        "google-chrome",
        "chromium",
        "chromium-browser",
    ] {
        if let Some(path) = super::inventory::which(name) {
            let mut v: String = "unknown".into();
            for argv in [
                vec!["dpkg-query", "-W", "-f=${Version}", name],
                vec!["pacman", "-Q", name],
            ] {
                if super::inventory::which(argv[0]).is_some() {
                    if let Ok(text) = super::inventory::run(&argv, 5) {
                        if let Some(m) = dotted.find(&text) {
                            v = m.as_str().into();
                            break;
                        }
                    }
                }
            }
            out.push(json!({"name":name,"path":path,"version":v}));
        }
    }
    #[cfg(windows)]
    for env in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(env) {
            for rel in [
                "Google/Chrome/Application/chrome.exe",
                "Chromium/Application/chrome.exe",
            ] {
                let exe = PathBuf::from(&base).join(rel);
                if exe.is_file() {
                    let v =
                        version(exe.parent().unwrap(), &exe).unwrap_or_else(|_| "unknown".into());
                    out.push(json!({"name":"Chrome","path":exe,"version":v}));
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    for base in [PathBuf::from("/Applications"), home.join("Applications")] {
        for name in ["Google Chrome.app", "Chromium.app"] {
            let app = base.join(name);
            let plist_path = app.join("Contents/Info.plist");
            let executables = fs::read_dir(app.join("Contents/MacOS"));
            if let Ok(executables) = executables {
                if let Some(exe) = executables
                    .flatten()
                    .map(|e| e.path())
                    .find(|p| p.is_file())
                {
                    let metadata = input::read_regular(&plist_path, None, input::MAX_FILE, false)
                        .and_then(|b| {
                            plist::Value::from_reader(std::io::Cursor::new(b)).map_err(error)
                        });
                    let version = metadata
                        .ok()
                        .and_then(|p| {
                            p.as_dictionary()
                                .and_then(|d| d.get("CFBundleShortVersionString"))
                                .and_then(plist::Value::as_string)
                                .map(str::to_owned)
                        })
                        .filter(|v| exact_version(v))
                        .unwrap_or("unknown".into());
                    out.push(json!({"name":name,"path":exe,"version":version}));
                }
            }
        }
    }
    if let Some(path) = cache_path {
        let saved = (|| -> Result<()> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(error)?;
            }
            crate::store::atomic(&path, &serde_json::to_string(&versions)?)
        })();
        if let Err(e) = saved {
            errors.push(e.to_string());
        }
    }
    (out, errors)
}
fn version_stamp(dir: &Path, exe: &Path) -> Result<Value> {
    let info = fs::metadata(exe).map_err(error)?;
    let modified = info
        .modified()
        .map_err(error)?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error)?
        .as_nanos();
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::MetadataExt;
        info.mode()
    };
    #[cfg(not(unix))]
    let mode = 0;
    let mut manifests = Vec::new();
    for entry in fs::read_dir(dir).map_err(error)? {
        let entry = entry.map_err(error)?;
        if entry.path().extension().is_some_and(|e| e == "manifest") {
            input::refuse_links(&entry.path())?;
            let time = entry
                .metadata()
                .map_err(error)?
                .modified()
                .map_err(error)?
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(error)?
                .as_nanos();
            manifests.push((entry.file_name().to_string_lossy().into_owned(), time));
        }
    }
    manifests.sort();
    Ok(json!([info.len(), modified, mode, manifests]))
}
fn version_with_trust(dir: &Path, exe: &Path, trusted: bool) -> Result<String> {
    let static_version = version(dir, exe)?;
    if static_version != "unknown" || !trusted {
        return Ok(static_version);
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let mut file = input::open_regular(exe, None, 512_000_000)?;
        let mut magic = [0; 4];
        file.read_exact(&mut magic).map_err(error)?;
        let info = file.metadata().map_err(error)?;
        if magic == *b"\x7fELF"
            && info.uid() == unsafe { libc::getuid() }
            && info.mode() & 0o22 == 0
        {
            if let Ok(text) = super::inventory::run(&[&exe.to_string_lossy(), "--version"], 30) {
                if let Some(m) = regex::Regex::new(r"\d+\.\d+\.\d+\.\d+")
                    .unwrap()
                    .find(&text)
                {
                    return Ok(m.as_str().into());
                }
            }
        }
    }
    Ok(static_version)
}
fn tuple(v: &str) -> Option<Vec<u64>> {
    v.split('.').map(|s| s.parse().ok()).collect()
}
fn parse_cve(cve: &Value) -> Option<Value> {
    let desc = array(&cve["descriptions"])
        .iter()
        .find(|d| d["lang"] == "en")
        .map(|d| string(d, "value"))
        .unwrap_or("");
    let re = regex::Regex::new(
        r"Google Chrome (?:on (?:on )?([A-Za-z ]+?) )?prior to (\d+\.\d+\.\d+\.\d+)",
    )
    .unwrap();
    let mut platform = Value::Null;
    let mut ranges = Vec::new();
    let mut supported = true;
    let configs = array(&cve["configurations"]);
    if configs.is_empty() {
        let c = re.captures(desc)?;
        if let Some(p) = c.get(1) {
            platform = json!(p.as_str().trim().to_lowercase());
        }
        ranges.push(json!({"versionEndExcluding":&c[2]}));
    } else {
        for config in configs {
            if config["negate"] == true || config["operator"] == "AND" {
                supported = false;
            }
            for node in array(&config["nodes"]) {
                if node["negate"] == true
                    || node["operator"] == "AND"
                    || !array(&node["nodes"]).is_empty()
                {
                    supported = false;
                }
                for m in array(&node["cpeMatch"]) {
                    if m["vulnerable"] != true
                        || string(m, "criteria") != "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
                    {
                        supported = false;
                        continue;
                    }
                    if [
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    ]
                    .iter()
                    .any(|k| m.get(*k).is_some() && !exact_version(string(m, k)))
                        || string(m, "versionEndExcluding").is_empty()
                    {
                        supported = false;
                    }
                    ranges.push(m.clone());
                }
            }
        }
    }
    supported &= !ranges.is_empty();
    let fixed = ranges
        .iter()
        .filter_map(|r| r["versionEndExcluding"].as_str())
        .max_by_key(|v| tuple(v));
    let severity = regex::Regex::new(r"Chromium security severity:\s*(\w+)")
        .unwrap()
        .captures(desc)
        .map(|c| c[1].to_lowercase())
        .or_else(|| {
            ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]
                .iter()
                .flat_map(|k| array(&cve["metrics"][k]))
                .map(|r| string(&r["cvssData"], "baseSeverity"))
                .find(|v| !v.is_empty())
                .map(str::to_lowercase)
        })
        .unwrap_or("unknown".into());
    Some(
        json!({"id":cve["id"],"fixed":fixed,"platform":platform,"severity":severity,"ranges":ranges,"applicability":if supported {"supported"}else{"unsupported"}}),
    )
}
#[allow(clippy::too_many_arguments)] // shares its signature with the sibling feed functions: inputs plus output accumulators; a params struct would only move them
pub fn advisories(
    packages: &[Package],
    fetch: &mut dyn FeedSource,
    kev: &BTreeSet<String>,
    have_kev: bool,
    findings: &mut Vec<Value>,
    _covered: &mut BTreeSet<String>,
    resolutions: &mut Vec<Value>,
    errors: &mut Vec<Value>,
    sources: &mut Vec<Value>,
) -> Result<()> {
    let packages: Vec<_> = packages
        .iter()
        .filter(|p| p.ecosystem == "Chromium")
        .collect();
    if packages.is_empty() {
        return Ok(());
    }
    let cache = fetch.cache_root().map(|p| p.join("chromium/data.json"));
    let old = cache
        .as_ref()
        .and_then(|p| input::read_regular(p, None, 128_000_000, false).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .unwrap_or(json!({}));
    let mut cves: BTreeMap<_, _> = array(&old["cves"])
        .iter()
        .map(|c| (string(c, "id").to_string(), c.clone()))
        .collect();
    let mut nvd_at = old["nvd_at"].as_f64().unwrap_or(0.0);
    let valid_cache = cves
        .values()
        .all(|c| c.get("applicability").is_some() && !string(c, "id").is_empty());
    if !valid_cache {
        cves.clear();
        nvd_at = 0.0;
    }
    let live = !fetch.offline() && !cves.is_empty() && super::now() - nvd_at <= 86400.0;
    if fetch.offline() {
        errors.push(json!({"source":"nvd","error":"offline mode: no live data fetched"}));
    } else if !live {
        let result = fetch_nvd(fetch);
        match result {
            Ok(fresh) => {
                cves = fresh;
                nvd_at = super::now();
                if let Some(path) = &cache {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).map_err(error)?;
                    }
                    let data = json!({"cves":cves.values().collect::<Vec<_>>(),"nvd_at":nvd_at,"cft":old["cft"],"cft_at":old["cft_at"]});
                    crate::store::atomic(path, &serde_json::to_string(&data)?)?;
                }
            }
            Err(e) => errors.push(json!({"source":"nvd","error":format!("NVD fetch failed: {e}")})),
        }
    }
    let authoritative =
        !fetch.offline() && nvd_at > 0.0 && (0.0..=86400.0).contains(&(super::now() - nvd_at));
    let fetched_at = if nvd_at > 0.0 {
        json!(super::outputs::timestamp_at(nvd_at))
    } else {
        Value::Null
    };
    if nvd_at > 0.0 {
        sources.push(json!({"source_url":"https://services.nvd.nist.gov/rest/json/cves/2.0","fetched_at":fetched_at}));
    }
    errors.push(json!({"source":"nvd","coverage":"limited-history","error":"Chrome data covers only the latest 119 publication days; older applicability is unknown"}));
    for p in packages {
        if p.version == "unknown" || tuple(&p.version).is_none() {
            errors.push(json!({"source":"chromium","error":format!("{}: no trusted version evidence",p.path)}));
            continue;
        }
        let os = if cfg!(windows) {
            "windows"
        } else if cfg!(target_os = "macos") {
            "mac"
        } else {
            "linux"
        };
        let aid = crate::store::asset(p)?;
        let mut applicable = Vec::new();
        for c in cves.values() {
            let platform = string(c, "platform");
            if !platform.is_empty()
                && platform != os
                && !(os == "mac" && ["macos", "mac os"].contains(&platform))
            {
                continue;
            }
            if c["applicability"] != "supported" {
                errors.push(json!({"source":"nvd","advisory":c["id"],"error":"unsupported Chrome applicability configuration"}));
                continue;
            }
            let ranges = array(&c["ranges"]);
            if authoritative
                && !ranges.is_empty()
                && ranges.iter().all(|r| {
                    tuple(string(r, "versionEndExcluding"))
                        .is_some_and(|fixed| tuple(&p.version).is_some_and(|v| v >= fixed))
                })
            {
                resolutions.push(json!({"package":p,"advisory":c["id"]}));
            }
            if ranges.iter().any(|r| {
                let v = tuple(&p.version);
                (string(r, "versionStartIncluding").is_empty()
                    || v >= tuple(string(r, "versionStartIncluding")))
                    && (string(r, "versionStartExcluding").is_empty()
                        || v > tuple(string(r, "versionStartExcluding")))
                    && (string(r, "versionEndIncluding").is_empty()
                        || v <= tuple(string(r, "versionEndIncluding")))
                    && (string(r, "versionEndExcluding").is_empty()
                        || v < tuple(string(r, "versionEndExcluding")))
            }) {
                applicable.push(c);
            }
        }
        if applicable.is_empty() {
            errors.push(json!({"source":"chromium","error":format!("{}: unknown outside limited history",p.path)}));
        } else {
            for c in applicable {
                let cid = string(c, "id");
                findings.push(json!({"key":crate::store::identity(&json!([aid,cid]))?,"asset":aid,"title":format!("{} {}: {cid}",p.name,p.version),"package":p,"advisory":cid,"kev":if have_kev{json!(kev.contains(cid))}else{Value::Null},"severity":c["severity"],"source_url":format!("https://nvd.nist.gov/vuln/detail/{cid}"),"fetched_at":fetched_at,"fixed":c["fixed"],"affected_ranges":c["ranges"],"coverage":"limited-history"}));
            }
        }
    }
    Ok(())
}
fn fetch_nvd(fetch: &mut dyn FeedSource) -> Result<BTreeMap<String, Value>> {
    let mut cves = BTreeMap::new();
    let end = super::outputs::timestamp().replace('Z', ".000");
    let start = super::outputs::timestamp_at(super::now() - 119.0 * 86400.0).replace('Z', ".000");
    let mut first = true;
    for query in [
        "virtualMatchString=cpe%3A2.3%3Aa%3Agoogle%3Achrome",
        "keywordSearch=Google+Chrome+prior+to&keywordExactMatch",
    ] {
        let mut index: u64 = 0;
        let mut pages = 0;
        loop {
            if !first {
                std::thread::sleep(fetch.nvd_pause());
            }
            first = false;
            let url=format!("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=2000&{query}&startIndex={index}");
            let response = fetch.get(&url, None)?;
            let d = &response["data"];
            let rows = d["vulnerabilities"]
                .as_array()
                .ok_or_else(|| error("invalid Chrome CVE schema"))?;
            for row in rows {
                if let Some(c) = parse_cve(&row["cve"]) {
                    cves.insert(string(&c, "id").into(), c);
                }
            }
            let count = d["resultsPerPage"]
                .as_u64()
                .ok_or_else(|| error("invalid NVD page count"))?;
            let total = d["totalResults"]
                .as_u64()
                .ok_or_else(|| error("invalid NVD result count"))?;
            if count != rows.len() as u64 || count == 0 && index < total {
                return Err(error("incomplete NVD page"));
            }
            index = index
                .checked_add(count)
                .ok_or_else(|| error("NVD page count overflowed"))?;
            pages += 1;
            if index >= total {
                break;
            }
            if pages >= 100 {
                return Err(error("NVD pagination did not complete"));
            }
        }
    }
    if cves.len() < 20 {
        return Err(error(format!(
            "only {} Chrome CVEs returned; refusing an implausible feed",
            cves.len()
        )));
    }
    Ok(cves)
}
