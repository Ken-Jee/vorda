use super::{array, error, feeds::FeedSource, source_name, source_version, string};
use crate::{domain::Package, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub fn source_alias(name: &str) -> &str {
    match name {
        "zlib1g" => "zlib",
        "libssl3" | "libcrypto3" => "openssl",
        "musl-utils" => "musl",
        "busybox-binsh" | "ssl_client" => "busybox",
        _ => name,
    }
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(Vec<u64>, String, u64);
pub fn version(value: &str) -> Result<Version> {
    let re = regex::Regex::new(r"^(\d+(?:\.\d+)*)([a-z]*)(?:-(\d+))?$").unwrap();
    let c = re
        .captures(value)
        .ok_or_else(|| error(format!("unsupported upstream version: {value}")))?;
    let mut parts = c[1]
        .split('.')
        .map(|v| v.parse::<u64>().map_err(error))
        .collect::<Result<Vec<_>>>()?;
    parts.resize(parts.len().max(8), 0);
    Ok(Version(
        parts,
        c[2].into(),
        c.get(3)
            .map(|v| v.as_str())
            .unwrap_or("0")
            .parse()
            .map_err(error)?,
    ))
}
pub fn in_range(installed: &str, item: &Value) -> Result<bool> {
    let v = version(installed)?;
    for (key, inclusive, lower) in [
        ("versionStartIncluding", true, true),
        ("versionStartExcluding", false, true),
        ("versionEndIncluding", true, false),
        ("versionEndExcluding", false, false),
    ] {
        if let Some(bound) = item.get(key) {
            let bound = version(
                bound
                    .as_str()
                    .ok_or_else(|| error("invalid version bound"))?,
            )?;
            if if lower {
                v < bound || !inclusive && v == bound
            } else {
                v > bound || !inclusive && v == bound
            } {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
pub fn upstream(
    packages: &[Package],
    fetch: &mut dyn FeedSource,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let (mut findings, mut errors, mut documents) =
        (Vec::new(), Vec::new(), BTreeMap::<String, Value>::new());
    let distro_suffix = regex::Regex::new(r"(?:\+|\.)dfsg|\+deb|\+ubuntu").unwrap();
    let plain_version = regex::Regex::new(r"^\d+(?:\.\d+)*$").unwrap();
    for p in packages {
        let source = source_alias(source_name(p));
        let (vendor, product) = match source {
            "busybox" => ("busybox", "busybox"),
            "musl" => ("musl-libc", "musl"),
            "zlib" => ("zlib", "zlib"),
            "openssl" => ("openssl", "openssl"),
            _ => continue,
        };
        if !["Alpine:", "Debian:", "Ubuntu:"]
            .iter()
            .any(|e| p.ecosystem.starts_with(e))
        {
            continue;
        }
        let installed = source_version(p)
            .rsplit(':')
            .next()
            .unwrap_or("")
            .split('-')
            .next()
            .unwrap_or("");
        let installed = distro_suffix.split(installed).next().unwrap_or("");
        let result = (|| -> Result<()> {
            version(installed)?;
            if !documents.contains_key(source) {
                let url=format!("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}&resultsPerPage=2000");
                let response = fetch.get(&url, None)?;
                let data = &response["data"];
                let rows = data["vulnerabilities"]
                    .as_array()
                    .ok_or_else(|| error("invalid NVD vulnerabilities"))?;
                if data["totalResults"]
                    .as_u64()
                    .ok_or_else(|| error("invalid NVD count"))?
                    > rows.len() as u64
                {
                    return Err(error(format!(
                        "NVD keyword results were truncated: {source}"
                    )));
                }
                documents.insert(source.into(), response);
            }
            let response = &documents[source];
            let mut candidates = Vec::new();
            for entry in array(&response["data"]["vulnerabilities"]) {
                let cve = &entry["cve"];
                if cve["vulnStatus"] == "Rejected" {
                    continue;
                }
                let mut evidence = Vec::new();
                for config in array(&cve["configurations"]) {
                    for node in array(&config["nodes"]) {
                        if config["negate"] == true || node["negate"] == true {
                            continue;
                        }
                        for m in array(&node["cpeMatch"]) {
                            let parts: Vec<_> = string(m, "criteria").split(':').collect();
                            if m["vulnerable"] == true
                                && parts.get(3) == Some(&vendor)
                                && parts.get(4) == Some(&product)
                                && in_range(installed, m)?
                                && parts.get(5).is_some_and(|v| *v == "*" || *v == installed)
                            {
                                evidence.push(json!({"source":"nvd","range":m}));
                            }
                        }
                    }
                }
                let cid = string(cve, "id");
                let pieces: Vec<_> = cid.split('-').collect();
                if pieces.len() != 3 || pieces[2].is_empty() {
                    return Err(error("invalid CVE identifier"));
                }
                let number = pieces[2];
                let bucket = if number.len() > 3 {
                    &number[..number.len() - 3]
                } else {
                    "0"
                };
                let url=format!("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{}/{bucket}xxx/{cid}.json",pieces[1]);
                if !evidence.is_empty() || array(&cve["configurations"]).is_empty() {
                    candidates.push((cve, evidence, cid, url));
                }
            }
            let urls: Vec<_> = candidates.iter().map(|c| c.3.clone()).collect();
            for ((cve, mut evidence, cid, url), cna) in
                candidates.into_iter().zip(fetch.get_many(&urls))
            {
                let cna = cna?;
                let cna = &cna["data"]["containers"]["cna"];
                for a in array(&cna["affected"]) {
                    let name = string(a, "product").to_lowercase();
                    if name != product && !(source == "musl" && name == "libc") {
                        continue;
                    }
                    for item in array(&a["versions"]) {
                        if item["status"] != "affected" {
                            continue;
                        }
                        let start = string(item, "version");
                        if !plain_version.is_match(start) {
                            continue;
                        }
                        let mut bounds = json!({"versionStartIncluding":start});
                        if let Some(v) = item.get("lessThan") {
                            bounds["versionEndExcluding"] = v.clone();
                        } else {
                            bounds["versionEndIncluding"] =
                                item.get("lessThanOrEqual").cloned().unwrap_or(json!(start));
                        }
                        if in_range(installed, &bounds)? {
                            evidence.push(json!({"source":"cna","range":item}));
                        }
                    }
                }
                if !evidence.is_empty() {
                    evidence.push(json!({"source":"cna","affected":cna.get("affected").cloned().unwrap_or(json!([])),"descriptions":cna.get("descriptions").cloned().unwrap_or(json!([]))}));
                    let aid = crate::store::asset(p)?;
                    findings.push(json!({"key":crate::store::identity(&json!([aid,cid]))?,"asset":aid,"package":p,"advisory":cid,"aliases":[cid],"title":format!("{} {}: {cid} [upstream-version]",p.name,p.version),"confidence":"upstream-version","evidence":evidence,"fixed":[],"kev":false,"epss":0,"severity":[],"published":cve["published"],"source_url":[format!("https://nvd.nist.gov/vuln/detail/{cid}"),url],"fetched_at":response["fetched_at"]}));
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            errors.push(json!({"source":format!("cpe:{}",p.name),"error":e.to_string()}));
        }
    }
    Ok((findings, errors))
}

pub fn authoritative(
    findings: &[Value],
    fetch: &mut dyn FeedSource,
) -> Result<(Vec<Value>, Vec<Value>, Vec<Value>)> {
    let (mut confirmed, mut audit, mut errors, mut cache) = (
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::<String, std::result::Result<Value, String>>::new(),
    );
    let cve_re = regex::Regex::new(r"CVE-\d{4}-\d+").unwrap();
    // Ubuntu findings read OSV's copy of the Canonical record for the fixed version and
    // priority. Those that did not come from a Canonical record (upstream matches) are decided
    // first by that record, then by the raw Canonical tracker when that record has no fixed
    // version for this release. Both are fetched several at once.
    let ubuntu: Vec<(&Value, Package, String)> = findings
        .iter()
        .filter(|f| string(&f["package"], "ecosystem").starts_with("Ubuntu:"))
        .filter(|f| f["detail_status"] != "vendor-fixed-criterion")
        .filter_map(|f| {
            let cve = cve_re.find(string(f, "advisory"))?.as_str().to_owned();
            Some((f, serde_json::from_value(f["package"].clone()).ok()?, cve))
        })
        .collect();
    let upstream: Vec<_> = ubuntu
        .iter()
        .filter(|(f, _, _)| canonical(f).is_none())
        .collect();
    let records: Vec<_> = ubuntu
        .iter()
        .map(|(_, _, cve)| record_url(cve))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // A record that could not be read (other than "no such record") is remembered: findings
    // that came from it must not claim "fix not known yet", and the scan is not complete.
    let (mut ubuntu_records, mut unread) = (BTreeMap::new(), BTreeSet::new());
    for (url, response) in records.iter().zip(fetch.get_many(&records)) {
        if let Err(e) = &response {
            if !e.message.contains("HTTP Error 404:") {
                unread.insert(url.clone());
            }
        }
        ubuntu_records.insert(url.clone(), response.ok().map(|v| v["data"].clone()));
    }
    if !unread.is_empty() {
        errors.push(json!({"source":"native:ubuntu-records","error":format!("{} Canonical records could not be read; fix versions and priorities not shown; the result is unknown, not clean", unread.len())}));
    }
    let pages: Vec<_> = upstream
        .iter()
        .filter(|(_, p, cve)| {
            ubuntu_entry(&ubuntu_records, cve, p)
                .and_then(|e| fixed_verdict(&e, p).ok().flatten())
                .is_none()
        })
        .map(|(_, _, cve)| tracker_url(cve, false))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut prefetched = BTreeMap::new();
    for (url, response) in pages.iter().zip(fetch.get_many(&pages)) {
        prefetched.insert(url.clone(), response.map(|v| v["data"].clone()));
    }
    for f in findings {
        let p: Package = serde_json::from_value(f["package"].clone())?;
        let Some(cve) = cve_re.find(string(f, "advisory")) else {
            confirmed.push(f.clone());
            continue;
        };
        let cve = cve.as_str();
        if !["Alpine:", "Debian:", "Ubuntu:"]
            .iter()
            .any(|e| p.ecosystem.starts_with(e))
        {
            confirmed.push(f.clone());
            continue;
        }
        let source = source_alias(source_name(&p));
        let installed = source_version(&p);
        let mut url = String::new();
        let mut from_record = false;
        let result = (|| -> Result<Option<Value>> {
            // One request per URL per scan: a failure is remembered too, so a large feed that
            // cannot be read is not downloaded again for every finding.
            let mut get = |url: &str| -> Result<Value> {
                if let Some(v) = cache.get(url) {
                    return v.clone().map_err(error);
                }
                let response = match prefetched.remove(url) {
                    Some(response) => response,
                    None => fetch.get(url, None).map(|v| v["data"].clone()),
                };
                let data = match response {
                    Ok(v) => Ok(v),
                    Err(e) if e.message.contains("HTTP Error 404:") => Ok(json!({})),
                    Err(e) => Err(e.message),
                };
                cache.insert(url.into(), data.clone());
                data.map_err(error)
            };
            if p.ecosystem.starts_with("Debian:") {
                url = super::feeds::DEBIAN.into();
                let release = match p.ecosystem.split(':').nth(1) {
                    Some("11") => "bullseye",
                    Some("12") => "bookworm",
                    Some("13") => "trixie",
                    _ => "",
                };
                let data = get(&url)?;
                let r = &data[source][cve]["releases"][release];
                if r.is_null() {
                    return Ok(None);
                }
                let mut v = r.clone();
                let fixed = string(r, "fixed_version");
                let status = string(r, "status");
                if fixed == "0" {
                    v["decision"] = json!("drop");
                } else if !fixed.is_empty() {
                    v["decision"] =
                        json!(if super::distro::compare(installed, fixed, &p.ecosystem)?
                            == Some(true)
                        {
                            "confirmed"
                        } else {
                            "drop"
                        });
                } else {
                    set_status(&mut v, status, r["nodsa_reason"] == "ignored", false);
                }
                Ok(Some(v))
            } else if p.ecosystem.starts_with("Ubuntu:") {
                let entry = ubuntu_entry(&ubuntu_records, cve, &p);
                if let Some(native) = canonical(f) {
                    url = native;
                    if f["detail_status"] == "vendor-fixed-criterion" {
                        return Ok(Some(json!({"decision":"confirmed"})));
                    }
                    // The finding came from this record: it also names the fix, if one is known.
                    from_record = true;
                    return Ok(Some(
                        entry
                            .as_ref()
                            .map(|e| fixed_verdict(e, &p))
                            .transpose()?
                            .flatten()
                            .unwrap_or(json!({"decision":"confirmed"})),
                    ));
                }
                if let Some(v) = entry
                    .as_ref()
                    .map(|e| fixed_verdict(e, &p))
                    .transpose()?
                    .flatten()
                {
                    url = record_url(cve);
                    return Ok(Some(v));
                }
                url = tracker_url(cve, false);
                let release = match p.ecosystem.split(':').nth(1) {
                    Some("20.04") => "focal",
                    Some("22.04") => "jammy",
                    Some("24.04") => "noble",
                    Some("26.04") => "resolute",
                    _ => "",
                };
                let data = match get(&url) {
                    Ok(data) => data,
                    // The Canonical record lists this release as affected with no fix yet.
                    Err(_) if entry.is_some() => {
                        url = record_url(cve);
                        return Ok(Some(json!({"decision":"confirmed"})));
                    }
                    Err(e) => return Err(e),
                };
                let data = if data.is_object() && data.as_object().is_some_and(|v| v.is_empty()) {
                    url = tracker_url(cve, true);
                    get(&url)?
                } else {
                    data
                };
                tracker_verdict(&data, cve, release, source, installed, &p.ecosystem)
            } else {
                let release = p.ecosystem.split(':').nth(1).unwrap_or("");
                let release = if release.starts_with('v') {
                    release.into()
                } else {
                    format!("v{release}")
                };
                for repo in ["main", "community"] {
                    url = format!("https://secdb.alpinelinux.org/{release}/{repo}.json");
                    let data = get(&url)?;
                    let mut verdict = None;
                    for item in array(&data["packages"]) {
                        let pkg = &item["pkg"];
                        if pkg["name"] != source {
                            continue;
                        }
                        if let Some(fixes) = pkg["secfixes"].as_object() {
                            for (fixed, cves) in fixes {
                                if array(cves).iter().any(|c| c == cve) {
                                    let affected = if fixed == "0" {
                                        Some(false)
                                    } else {
                                        super::distro::compare(installed, fixed, &p.ecosystem)?
                                    };
                                    let affected = if affected.is_none()
                                        && f["confidence"] != "upstream-version"
                                    {
                                        Some(true)
                                    } else {
                                        affected
                                    };
                                    verdict = Some(
                                        json!({"fixed":fixed,"decision":match affected{Some(true)=>"confirmed",Some(false)=>"drop",None=>"audit"}}),
                                    );
                                }
                            }
                        }
                    }
                    if verdict.is_some() {
                        return Ok(verdict);
                    }
                }
                Ok(None)
            }
        })();
        match result {
            Ok(None) => {
                let mut visible = f.clone();
                visible["confidence"] = json!("upstream only, distro status not confirmed");
                confirmed.push(visible.clone());
                audit.push(json!({"finding":visible,"reason":"No native release verdict","source_url":url,"visible_upstream":true}));
            }
            Ok(Some(v)) if v["decision"] == "confirmed" => {
                let mut f = f.clone();
                f["native_verdict"] = v.clone();
                f["native_source"] = json!(url);
                f["confidence"] = v
                    .get("confidence")
                    .or_else(|| f.get("confidence"))
                    .cloned()
                    .unwrap_or(json!("distro: affected"));
                if p.ecosystem.starts_with("Ubuntu:") {
                    let mut fixed: BTreeSet<_> = array(&f["fixed"])
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect();
                    fixed.extend(v["fixed"].as_str().map(str::to_owned));
                    if from_record && !unread.contains(&record_url(cve)) {
                        f["confidence"] = json!(match v["fixed"]
                            .as_str()
                            .or(fixed.first().map(String::as_str))
                        {
                            Some(fix) => format!("distro: fix available {fix}"),
                            None => "distro: fix not known yet".into(),
                        });
                    }
                    f["fixed"] = json!(fixed);
                    if let Some(r) = ubuntu_records
                        .get(&record_url(cve))
                        .and_then(Option::as_ref)
                    {
                        if array(&f["severity"]).is_empty() && !array(&r["severity"]).is_empty() {
                            f["severity"] = r["severity"].clone();
                        }
                    }
                }
                confirmed.push(f);
            }
            Ok(Some(v)) => audit.push(
                json!({"finding":f,"reason":v["decision"],"native_verdict":v,"source_url":url}),
            ),
            Err(e) => {
                audit.push(json!({"finding":f,"reason":"Native authority unavailable","error":e.to_string()}));
                errors.push(json!({"source":format!("native:{source}"),"error":e.to_string()}));
            }
        }
    }
    Ok((confirmed, audit, errors))
}
/// The Canonical record an Ubuntu finding already came from, if any: an OSV `UBUNTU-CVE-*`
/// record (Canonical's tracker data, matched by OSV against the installed dpkg version) or a
/// USN OVAL fixed-version criterion. Such a finding already carries the distro's verdict, so
/// it needs no per-CVE ubuntu.com page.
fn canonical(f: &Value) -> Option<String> {
    let advisory = string(f, "advisory");
    let ubuntu = format!("UBUNTU-{advisory}");
    if array(&f["aliases"]).iter().any(|a| *a == *ubuntu) {
        return Some(format!("{}/vulns/{ubuntu}", super::feeds::OSV));
    }
    if f["detail_status"] == "vendor-fixed-criterion" {
        return array(&f["source_url"])
            .first()
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    None
}
fn record_url(cve: &str) -> String {
    format!("{}/vulns/UBUNTU-{cve}", super::feeds::OSV)
}
fn tracker_url(cve: &str, retired: bool) -> String {
    format!(
        "https://git.launchpad.net/ubuntu-cve-tracker/plain/{}/{cve}",
        if retired { "retired" } else { "active" }
    )
}
fn tracker_verdict(
    data: &Value,
    cve: &str,
    release: &str,
    source: &str,
    installed: &str,
    ecosystem: &str,
) -> Result<Option<Value>> {
    let invalid = || {
        error("invalid ubuntu-cve-tracker record schema: missing or malformed source package/release status; leaving status unknown")
    };
    let text = data.as_str().ok_or_else(invalid)?;
    if !text.lines().any(|line| line == format!("Candidate: {cve}")) || release.is_empty() {
        return Err(invalid());
    }
    let key = format!("{release}_{source}: ");
    let statuses: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix(&key))
        .collect();
    let [status] = statuses[..] else {
        return Err(invalid());
    };
    let (state, detail) = match status.split_once(" (") {
        Some((state, detail)) => (state, Some(detail.strip_suffix(')').ok_or_else(invalid)?)),
        None => (status, None),
    };
    let mut verdict = json!({"status":state});
    match state {
        "not-affected" | "DNE" => verdict["decision"] = json!("drop"),
        "released" => {
            let fixed = detail.ok_or_else(invalid)?;
            let version = regex::Regex::new(r"^(?:[0-9]+:)?[0-9][A-Za-z0-9.+~\-]*$").unwrap();
            if !version.is_match(fixed) || !version.is_match(installed) {
                return Err(invalid());
            }
            verdict["fixed"] = json!(fixed);
            verdict["confidence"] = json!(format!("distro: fix available {fixed}"));
            verdict["decision"] =
                json!(match super::distro::compare(installed, fixed, ecosystem)? {
                    Some(true) => "confirmed",
                    Some(false) => "drop",
                    None => "audit",
                });
        }
        "needed" | "pending" | "deferred" | "ignored" | "needs-triage" => {
            set_status(&mut verdict, state, false, true)
        }
        _ => return Err(invalid()),
    }
    Ok(Some(verdict))
}
/// The Canonical record's affected entry for this package's release and source package.
fn ubuntu_entry(
    records: &BTreeMap<String, Option<Value>>,
    cve: &str,
    p: &Package,
) -> Option<Value> {
    let source = source_alias(source_name(p));
    array(&records.get(&record_url(cve))?.as_ref()?["affected"])
        .iter()
        .find(|a| a["package"]["ecosystem"] == p.ecosystem && a["package"]["name"] == source)
        .cloned()
}
/// A verdict from the entry's fixed version, or `None` when the entry names no fix.
fn fixed_verdict(entry: &Value, p: &Package) -> Result<Option<Value>> {
    let fixed: Vec<_> = array(&entry["ranges"])
        .iter()
        .flat_map(|r| array(&r["events"]))
        .filter_map(|e| e["fixed"].as_str())
        .collect();
    let [fixed] = fixed[..] else {
        return Ok(None);
    };
    let affected = super::distro::compare(source_version(p), fixed, &p.ecosystem)? == Some(true);
    Ok(Some(
        json!({"fixed":fixed,"decision":if affected {"confirmed"} else {"drop"}}),
    ))
}
fn set_status(v: &mut Value, status: &str, ignored: bool, ubuntu: bool) {
    if ignored || ["ignored", "will-not-fix", "wont-fix"].contains(&status) {
        v["decision"] = json!("confirmed");
        v["confidence"] = json!("distro: won't fix");
    } else if ["undetermined", "needs-triage"].contains(&status) {
        v["decision"] = json!("confirmed");
        v["confidence"] = json!("distro: needs triage");
    } else {
        v["decision"] = json!(
            if ["open", "deferred", "postponed", "pending"].contains(&status)
                || ubuntu && status == "needed"
            {
                "confirmed"
            } else {
                "audit"
            }
        );
    }
}
pub fn resolve(
    mut findings: Vec<Value>,
    audit: &[Value],
    mut covered: BTreeSet<String>,
    mut errors: Vec<Value>,
) -> (Vec<Value>, BTreeSet<String>, Vec<Value>) {
    if errors.iter().any(|e| {
        ["native:", "cpe:", "distro-veto:"]
            .iter()
            .any(|p| string(e, "source").starts_with(p))
    }) {
        covered.clear();
    }
    for entry in audit {
        if entry["reason"] == "drop" {
            continue;
        }
        let f = &entry["finding"];
        covered.remove(string(f, "asset"));
        if entry["visible_upstream"] == true {
            continue;
        }
        findings.push(json!({"key":format!("audit:{}",string(f,"key")),"asset":f["asset"],"kind":"health","title":format!("Review required: {}",string(f,"title")),"package":f["package"],"audit":entry}));
        errors.push(json!({"source":format!("native-audit:{}",string(f,"key")),"error":format!("Native verdict is uncertain: {}",string(entry,"reason"))}));
    }
    (findings, covered, errors)
}
