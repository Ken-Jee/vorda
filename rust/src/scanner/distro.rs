use super::{error, source_name, source_version};
use crate::{domain::Package, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub fn ecosystem(release: &str, alpine: &str) -> String {
    let data: BTreeMap<_, _> = release
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k, v.trim_matches(['\'', '"'])))
        .collect();
    let name = data.get("ID").copied().unwrap_or("");
    let v = data.get("VERSION_ID").copied().unwrap_or("");
    let ubuntu = |v: &str| {
        format!(
            "Ubuntu:{v}{}",
            if v.ends_with(".04")
                && v.split('.')
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_some_and(|n| n % 2 == 0)
            {
                ":LTS"
            } else {
                ""
            }
        )
    };
    if name == "ubuntu" {
        return ubuntu(v);
    }
    if let Some(v) = data.get("UBUNTU_CODENAME").and_then(|c| match *c {
        "xenial" => Some("16.04"),
        "bionic" => Some("18.04"),
        "focal" => Some("20.04"),
        "jammy" => Some("22.04"),
        "noble" => Some("24.04"),
        "resolute" => Some("26.04"),
        _ => None,
    }) {
        return ubuntu(v);
    }
    let major = v.split('.').next().unwrap_or("");
    match name {
        "debian" if ["10", "11", "12", "13"].contains(&major) => format!("Debian:{major}"),
        "alpine" if regex::Regex::new(r"^\d+\.\d+").unwrap().is_match(alpine) => format!(
            "Alpine:v{}",
            alpine
                .trim()
                .trim_start_matches('v')
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        ),
        "rocky" if !v.is_empty() => format!("Rocky Linux:{major}"),
        "almalinux" if !v.is_empty() => format!("AlmaLinux:{major}"),
        _ => format!("Unknown distro:{name}"),
    }
}

/// The OS package ("name version") that owns an installed binary, when dpkg or rpm on this host
/// claims the path or its resolved target. Such a binary may carry distro backports that an
/// upstream version match cannot see.
pub fn owner(binary: &std::path::Path) -> Option<String> {
    use super::inventory::{run, which};
    // The real file first: a symlink such as python3 -> python3.12 belongs to a different
    // package (python3-minimal) than the binary that runs (python3.12-minimal).
    let mut paths = vec![binary.to_path_buf()];
    if let Ok(real) = binary.canonicalize() {
        if real != binary {
            paths.insert(0, real);
        }
    }
    let dpkg = which("dpkg-query").is_some();
    let rpm = which("rpm").is_some();
    for path in paths.iter().filter_map(|p| p.to_str()) {
        if dpkg {
            if let Ok(out) = run(&["dpkg-query", "-S", path], 15) {
                let name = out
                    .lines()
                    .filter(|l| !l.starts_with("diversion "))
                    .find_map(|l| l.split_once(": "))
                    .and_then(|(names, _)| names.split(',').next())
                    .map(str::trim);
                if let Some(name) = name.filter(|n| !n.is_empty()) {
                    let version =
                        run(&["dpkg-query", "-W", "-f=${Version}", name], 15).unwrap_or_default();
                    return Some(format!("{name} {version}").trim().into());
                }
            }
        }
        if rpm {
            if let Ok(out) = run(&["rpm", "-qf", "--qf", "%{NAME} %{EVR}\\n", path], 15) {
                if let Some(line) = out.lines().next().filter(|l| !l.is_empty()) {
                    return Some(line.trim().into());
                }
            }
        }
    }
    None
}

pub fn compare(installed: &str, fixed: &str, ecosystem: &str) -> Result<Option<bool>> {
    if ecosystem.starts_with("Alpine:") {
        let re = regex::Regex::new(r"^(\d+(?:\.\d+)*)(?:-r(\d+))?$").unwrap();
        let mut versions = Vec::new();
        for value in [installed, fixed] {
            let Some(c) = re.captures(value) else {
                return Ok(None);
            };
            let mut core = c[1]
                .split('.')
                .map(|v| v.parse::<u64>().map_err(error))
                .collect::<Result<Vec<_>>>()?;
            let revision = c
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("0")
                .parse::<u64>()
                .map_err(error)?;
            core.push(revision);
            versions.push(core);
        }
        let width = versions.iter().map(Vec::len).max().unwrap_or(1);
        for v in &mut versions {
            let revision = v.pop().unwrap_or(0);
            v.resize(width - 1, 0);
            v.push(revision);
        }
        return Ok(Some(versions[0] < versions[1]));
    }
    if ecosystem.starts_with("Debian") || ecosystem.starts_with("Ubuntu") {
        for value in [installed, fixed] {
            if value.chars().any(char::is_whitespace) {
                return Err(error("invalid Debian version: whitespace"));
            }
            if let Some((epoch, _)) = value.split_once(':') {
                if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(error("invalid Debian version epoch"));
                }
            }
        }
        return Ok(Some(
            debian_order(installed, fixed) == std::cmp::Ordering::Less,
        ));
    }
    Ok(None)
}
fn debian_order(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(v: &str) -> (&str, &str, &str) {
        let (epoch, v) = v
            .split_once(':')
            .map(|(e, v)| (e.trim_start_matches('0'), v))
            .unwrap_or(("", v));
        let (upstream, revision) = v.rsplit_once('-').unwrap_or((v, "0"));
        (epoch, upstream, revision)
    }
    fn order(c: Option<u8>) -> i32 {
        match c {
            Some(b'~') => -1,
            Some(c) if c.is_ascii_digit() => 0,
            None => 0,
            Some(c) if c.is_ascii_alphabetic() => c as i32,
            Some(c) => c as i32 + 256,
        }
    }
    fn compare_part(a: &str, b: &str) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let (mut i, mut j) = (0, 0);
        while i < a.len() || j < b.len() {
            while a.get(i).is_some_and(|c| !c.is_ascii_digit())
                || b.get(j).is_some_and(|c| !c.is_ascii_digit())
            {
                let (x, y) = (order(a.get(i).copied()), order(b.get(j).copied()));
                if x != y {
                    return x.cmp(&y);
                }
                if i < a.len() {
                    i += 1;
                }
                if j < b.len() {
                    j += 1;
                }
            }
            while a.get(i) == Some(&b'0') {
                i += 1;
            }
            while b.get(j) == Some(&b'0') {
                j += 1;
            }
            let (si, sj) = (i, j);
            while a.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            let cmp = (i - si)
                .cmp(&(j - sj))
                .then_with(|| a[si..i].cmp(&b[sj..j]));
            if cmp != Ordering::Equal {
                return cmp;
            }
        }
        Ordering::Equal
    }
    let (ae, au, ar) = parts(a);
    let (be, bu, br) = parts(b);
    ae.len()
        .cmp(&be.len())
        .then_with(|| ae.cmp(be))
        .then_with(|| compare_part(au, bu))
        .then_with(|| compare_part(ar, br))
}
pub fn debian(packages: &[Package], tracker: &Value) -> Result<(Vec<Value>, BTreeSet<String>)> {
    let mut findings = Vec::new();
    let mut covered = BTreeSet::new();
    for p in packages {
        let release = match p.ecosystem.as_str() {
            "Debian:11" => "bullseye",
            "Debian:12" => "bookworm",
            "Debian:13" => "trixie",
            _ => continue,
        };
        let aid = crate::store::asset(p)?;
        let Some(records) = tracker
            .get(source_name(p).split(':').next().unwrap_or(""))
            .and_then(Value::as_object)
        else {
            continue;
        };
        covered.insert(aid.clone());
        for (cid, cve) in records {
            let Some(r) = cve["releases"].get(release) else {
                covered.remove(&aid);
                continue;
            };
            if r["status"] == "undetermined" {
                covered.remove(&aid);
                continue;
            }
            let fixed = super::string(r, "fixed_version");
            if fixed == "0" {
                continue;
            }
            if r["status"] == "open"
                || !fixed.is_empty()
                    && compare(source_version(p), fixed, &p.ecosystem)? == Some(true)
            {
                findings.push(json!({"key":crate::store::identity(&json!([aid,cid]))?,"asset":aid,"title":format!("{} {}: {cid}",p.name,p.version),"package":p,"advisory":cid,"aliases":[cid],"fixed":if fixed.is_empty(){vec![]}else{vec![fixed]},"severity":r.get("urgency").cloned().unwrap_or(json!("unknown")),"source_url":format!("https://security-tracker.debian.org/tracker/{cid}")}));
            }
        }
    }
    Ok((findings, covered))
}
pub fn ubuntu_records(bytes: &[u8]) -> Result<Value> {
    use quick_xml::{events::Event, Reader};
    let mut reader = Reader::from_reader(bytes);
    let (mut records, mut cves, mut criteria) =
        (Vec::new(), Vec::<String>::new(), Vec::<String>::new());
    let mut severity = "unknown".to_string();
    let mut in_severity = false;
    let mut text = String::new();
    let re = regex::Regex::new(r"^(\S+) (?:source )?package in (\S+?)(?:,)? (.*)").unwrap();
    let fix = regex::Regex::new(r"has been fixed.*note: '([^']+)'").unwrap();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = e.local_name();
                if name.as_ref() == "definition" {
                    cves.clear();
                    criteria.clear();
                    severity = "unknown".into();
                }
                if name.as_ref() == "severity" {
                    in_severity = true;
                    text.clear();
                }
                let attrs: BTreeMap<_, _> = e
                    .attributes()
                    .map(|a| {
                        a.map_err(error).and_then(|a| {
                            Ok((
                                a.key.as_ref().to_owned(),
                                a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                    .map_err(error)?
                                    .into_owned(),
                            ))
                        })
                    })
                    .collect::<Result<_>>()?;
                if name.as_ref() == "reference" && attrs.get("source").is_some_and(|v| v == "CVE") {
                    if let Some(v) = attrs.get("ref_id") {
                        cves.push(v.clone());
                    }
                }
                if name.as_ref() == "criterion" {
                    if let Some(v) = attrs.get("comment") {
                        criteria.push(v.clone());
                    }
                }
            }
            // The parser splits text at every `&...;` reference.
            Ok(Event::Text(t)) if in_severity => text.push_str(&t.xml10_content()),
            Ok(Event::GeneralRef(r)) if in_severity => match r.resolve_char_ref().map_err(error)? {
                Some(c) => text.push(c),
                None => text.push_str(
                    quick_xml::escape::resolve_predefined_entity(r.as_ref())
                        .ok_or_else(|| error("unknown entity in Ubuntu severity"))?,
                ),
            },
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == "severity" {
                    in_severity = false;
                    severity = text.trim().to_lowercase();
                }
                if e.local_name().as_ref() == "definition" {
                    for text in &criteria {
                        if let Some(c) = re.captures(text) {
                            if let Some(f) = fix.captures(&c[3]) {
                                if !cves.is_empty() {
                                    records.push(json!({"name":&c[1],"release":&c[2],"cves":cves,"fixed":&f[1],"severity":severity}));
                                }
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(error(e)),
            _ => {}
        }
    }
    if records.is_empty() {
        return Err(error(
            "Ubuntu tracker schema changed: no fixed package criteria",
        ));
    }
    Ok(json!(records))
}
