use super::{array, error, record, source_name, source_version, string};
use crate::{
    domain::{Package, Record},
    Result,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

pub const OSV: &str = "https://api.osv.dev/v1";
pub const KEV: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const EPSS: &str = "https://api.first.org/data/v1/epss";
pub const ARCH: &str = "https://security.archlinux.org/all.json";
pub const DEBIAN: &str = "https://security-tracker.debian.org/tracker/data/json";
pub const CFT:&str="https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";
pub const RELEASES: &str =
    "https://chromereleases.googleblog.com/feeds/posts/default?alt=json&max-results=10";
const CAP: u64 = 128_000_000;
const COPY_NO_VERSION: &str = "No trusted installed version to match against advisories";
const COPY_NO_MAPPING: &str = "No verified advisory mapping for this package manager";

/// The name OSV records a package under: PyPI names are compared in their PEP 503 form, so
/// `Django`, `Flask_Cors` and `zope.interface` match `django`, `flask-cors`, `zope-interface`;
/// crates.io names as the registry does, so `Deno` and `block_buffer` match `deno`, `block-buffer`.
pub(crate) fn osv_name(ecosystem: &str, name: &str) -> String {
    if ecosystem == "crates.io" {
        return name.to_ascii_lowercase().replace('_', "-");
    }
    if ecosystem != "PyPI" {
        return name.into();
    }
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

pub trait FeedSource {
    fn get(&mut self, url: &str, body: Option<&Value>) -> Result<Value>;
    /// GET every URL; results are in the same order. Real feeds fetch several at once.
    fn get_many(&mut self, urls: &[String]) -> Vec<Result<Value>> {
        urls.iter().map(|url| self.get(url, None)).collect()
    }
    /// True once a request was refused because the scan's feed time budget ran out.
    fn budget_exhausted(&self) -> bool {
        false
    }
    fn select_packages(&mut self, _: &[Package]) {}
    fn offline(&self) -> bool {
        false
    }
    fn cache_root(&self) -> Option<&Path> {
        None
    }
    /// True for the offline advisory database: EPSS is not looked up.
    fn local_db(&self) -> bool {
        false
    }
    /// Wait between NVD page requests. Fixture feeds return zero; real feeds keep NVD's rate limit.
    fn nvd_pause(&self) -> Duration {
        nvd_pause(std::env::var("NVD_API_KEY").is_ok_and(|key| !key.is_empty()))
    }
}
pub(crate) fn nvd_pause(has_key: bool) -> Duration {
    Duration::from_millis(if has_key { 1000 } else { 6500 })
}
pub struct Fetch {
    root: PathBuf,
    pub offline: bool,
    pub ttl: f64,
    packages: BTreeSet<(String, String)>,
    deadline: Instant,
    exhausted: AtomicBool,
}
/// Total time one scan may spend on feed requests, unless `VORDA_FEED_BUDGET_SECONDS` says otherwise.
pub const FEED_BUDGET_SECONDS: u64 = 300;
/// Feed requests in flight at once.
const PARALLEL: usize = 8;
impl Fetch {
    pub fn new(root: &Path, offline: bool) -> Self {
        let budget = std::env::var("VORDA_FEED_BUDGET_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(FEED_BUDGET_SECONDS);
        Self {
            root: root.into(),
            offline,
            ttl: 3600.0,
            packages: BTreeSet::new(),
            deadline: Instant::now() + Duration::from_secs(budget),
            exhausted: AtomicBool::new(false),
        }
    }
    fn fetch(&self, url: &str, body: Option<&Value>) -> Result<Value> {
        let detail = url.contains("/vulns/");
        // The full Debian tracker is larger than the state store's per-file budget.
        let tracker = url == DEBIAN && !self.packages.is_empty();
        let key = if detail || tracker {
            json!([url, body, self.packages])
        } else {
            json!([url, body])
        };
        let path = self
            .root
            .join(format!("{}.json", crate::store::identity(&key)?));
        // An unreadable cache entry (corrupt, oversized, hard-linked) is a miss, so the
        // next successful fetch replaces it instead of failing this feed forever.
        let old = super::input::read_regular(&path, None, CAP, false)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(Value::is_object);
        if self.offline {
            return Err(error(format!("offline: {url}")));
        }
        if let Some(old) = &old {
            if super::now() - old["checked"].as_f64().unwrap_or(0.0) < self.ttl {
                return Ok(old.clone());
            }
        }
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            self.exhausted.store(true, Ordering::Relaxed);
            return Err(error(format!("feed time budget exhausted: {url}")));
        }
        let nvd_key = url::Url::parse(url)
            .ok()
            .filter(|u| u.scheme() == "https" && u.host_str() == Some("services.nvd.nist.gov"))
            .and_then(|_| std::env::var("NVD_API_KEY").ok())
            .filter(|s| !s.is_empty());
        let mut builder = reqwest::blocking::Client::builder()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .timeout(remaining.min(Duration::from_secs(30)));
        if nvd_key.is_some() {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }
        let client = builder.build().map_err(error)?;
        let mut last = String::new();
        for attempt in 0..3 {
            let mut request = client
                .request(
                    if body.is_some() {
                        reqwest::Method::POST
                    } else {
                        reqwest::Method::GET
                    },
                    url,
                )
                .header("User-Agent", "vorda/0.1")
                .header("Accept", "application/json")
                .header("Accept-Encoding", "gzip");
            if let Some(key) = &nvd_key {
                let mut value = reqwest::header::HeaderValue::from_str(key)
                    .map_err(|_| error("invalid NVD_API_KEY header"))?;
                value.set_sensitive(true);
                request = request.header("apiKey", value);
            }
            if let Some(b) = body {
                request = request.json(b);
            }
            if let Some(old) = &old {
                if let Some(v) = old["etag"].as_str() {
                    request = request.header("If-None-Match", v);
                }
                if let Some(v) = old["modified"].as_str() {
                    request = request.header("If-Modified-Since", v);
                }
            }
            let response = (|| -> Result<Value> {
                let response = request.send().map_err(error)?;
                if response.status().as_u16() == 304 {
                    if let Some(mut old) = old.clone() {
                        old["checked"] = json!(super::now());
                        crate::store::atomic(&path, &serde_json::to_string(&old)?)?;
                        return Ok(old);
                    }
                }
                if !response.status().is_success() {
                    return Err(error(format!(
                        "HTTP Error {}: {url}",
                        response.status().as_u16()
                    )));
                }
                let etag = response
                    .headers()
                    .get("ETag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let modified = response
                    .headers()
                    .get("Last-Modified")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let gzip = response
                    .headers()
                    .get("Content-Encoding")
                    .is_some_and(|v| v == "gzip");
                let mut bytes = Vec::new();
                response
                    .take(CAP + 1)
                    .read_to_end(&mut bytes)
                    .map_err(error)?;
                if bytes.len() as u64 > CAP {
                    return Err(error(format!("feed exceeds 128MB cap: {url}")));
                }
                if gzip {
                    let mut expanded = Vec::new();
                    flate2::read::GzDecoder::new(bytes.as_slice())
                        .take(CAP + 1)
                        .read_to_end(&mut expanded)
                        .map_err(error)?;
                    if expanded.len() as u64 > CAP {
                        return Err(error("expanded feed exceeds 128MB cap"));
                    }
                    bytes = expanded;
                }
                let mut data = if url.ends_with(".oval.xml.bz2") {
                    let mut expanded = Vec::new();
                    bzip2::read::BzDecoder::new(bytes.as_slice())
                        .take(CAP + 1)
                        .read_to_end(&mut expanded)
                        .map_err(error)?;
                    if expanded.len() as u64 > CAP {
                        return Err(error("Ubuntu tracker exceeds expanded size cap"));
                    }
                    super::distro::ubuntu_records(&expanded)?
                } else if url.starts_with("https://git.launchpad.net/ubuntu-cve-tracker/plain/") {
                    json!(String::from_utf8(bytes).map_err(error)?)
                } else {
                    serde_json::from_slice::<Value>(&bytes)?
                };
                if tracker {
                    select_debian_sources(&mut data, &self.packages);
                }
                if detail && !self.packages.is_empty() {
                    if data.is_object() && data.get("affected").is_none() {
                        data["affected"] = json!([]);
                    }
                    let affected = data
                        .get_mut("affected")
                        .and_then(Value::as_array_mut)
                        .ok_or_else(|| error(format!("OSV detail schema changed: {url}")))?;
                    affected.retain(|a| {
                        let ecosystem = string(&a["package"], "ecosystem");
                        self.packages.contains(&(
                            ecosystem.into(),
                            osv_name(ecosystem, string(&a["package"], "name")),
                        ))
                    });
                    for a in affected {
                        if let Some(a) = a.as_object_mut() {
                            a.remove("versions");
                        }
                    }
                }
                let r = json!({"source_url":url,"fetched_at":super::outputs::timestamp(),"checked":super::now(),"etag":etag,"modified":modified,"data":data});
                std::fs::create_dir_all(&self.root).map_err(error)?;
                crate::store::atomic(&path, &serde_json::to_string(&r)?)?;
                Ok(r)
            })();
            match response {
                Ok(r) => return Ok(r),
                Err(e) => {
                    last = e.to_string();
                    if last.starts_with("HTTP Error ")
                        && !["429", "500", "502", "503", "504"]
                            .iter()
                            .any(|c| last.starts_with(&format!("HTTP Error {c}:")))
                    {
                        return Err(e);
                    }
                }
            }
            if attempt < 2 {
                std::thread::sleep(Duration::from_millis(250 * (1 << attempt)));
            }
        }
        Err(error(format!("{last}: {url}")))
    }
}
impl FeedSource for Fetch {
    fn get(&mut self, url: &str, body: Option<&Value>) -> Result<Value> {
        self.fetch(url, body)
    }
    fn get_many(&mut self, urls: &[String]) -> Vec<Result<Value>> {
        let this = &*self;
        let next = AtomicUsize::new(0);
        let slots: Vec<Mutex<Option<Result<Value>>>> =
            urls.iter().map(|_| Mutex::new(None)).collect();
        std::thread::scope(|s| {
            for _ in 0..PARALLEL.min(urls.len()) {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(url) = urls.get(i) else { break };
                    let result = this.fetch(url, None);
                    if let Ok(mut slot) = slots[i].lock() {
                        *slot = Some(result);
                    }
                });
            }
        });
        slots
            .into_iter()
            .map(|slot| {
                slot.into_inner()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| Err(error("feed request did not run")))
            })
            .collect()
    }
    fn budget_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Relaxed)
    }
    fn select_packages(&mut self, packages: &[Package]) {
        self.packages = packages
            .iter()
            .map(|p| (p.ecosystem.clone(), osv_name(&p.ecosystem, source_name(p))))
            .collect();
    }
    fn offline(&self) -> bool {
        self.offline
    }
    fn cache_root(&self) -> Option<&Path> {
        Some(&self.root)
    }
}
fn source(
    fetch: &mut dyn FeedSource,
    sources: &mut Vec<Value>,
    url: &str,
    body: Option<&Value>,
) -> Result<Value> {
    let r = fetch.get(url, body)?;
    sources.push(json!({"source_url":r["source_url"],"fetched_at":r["fetched_at"]}));
    r.get("data")
        .cloned()
        .ok_or_else(|| error("feed is missing data"))
}
/// Keep only the Debian tracker entries for the selected Debian source packages, under both
/// the source name and the alias the native check looks up.
pub fn select_debian_sources(tracker: &mut Value, packages: &BTreeSet<(String, String)>) {
    let names: BTreeSet<&str> = packages
        .iter()
        .filter(|(ecosystem, _)| ecosystem.starts_with("Debian:"))
        .flat_map(|(_, name)| {
            let name = name.split(':').next().unwrap_or("");
            [name, super::cpe::source_alias(name)]
        })
        .collect();
    if let Some(tracker) = tracker.as_object_mut() {
        tracker.retain(|name, _| names.contains(name.as_str()));
    }
}
/// `source` for several GET URLs at once, in order.
fn sources_many(
    fetch: &mut dyn FeedSource,
    sources: &mut Vec<Value>,
    urls: &[String],
) -> Vec<Result<Value>> {
    fetch
        .get_many(urls)
        .into_iter()
        .map(|r| {
            let r = r?;
            sources.push(json!({"source_url":r["source_url"],"fetched_at":r["fetched_at"]}));
            r.get("data")
                .cloned()
                .ok_or_else(|| error("feed is missing data"))
        })
        .collect()
}
fn mapped(e: &str) -> bool {
    if [
        "npm",
        "PyPI",
        "crates.io",
        "Go",
        "RubyGems",
        "Packagist",
        "Maven",
        "NuGet",
        "Bitnami",
        "Debian:10",
        "Debian:11",
        "Debian:12",
        "Debian:13",
    ]
    .contains(&e)
    {
        return true;
    }
    if let Some(v) = e.strip_prefix("Alpine:v3.") {
        return v.parse::<u32>().is_ok_and(|v| v < 25);
    }
    if ["Rocky Linux:", "AlmaLinux:"].iter().any(|p| {
        e.strip_prefix(p)
            .is_some_and(|v| ["8", "9", "10"].contains(&v))
    }) {
        return true;
    }
    if let Some(v) = e.strip_prefix("Ubuntu:") {
        return [
            "16.04:LTS",
            "18.04:LTS",
            "20.04:LTS",
            "22.04:LTS",
            "24.04:LTS",
            "26.04:LTS",
            "22.10",
            "23.04",
            "23.10",
            "24.10",
            "25.04",
            "25.10",
            "26.10",
        ]
        .contains(&v);
    }
    false
}

fn validate_row(row: &Value) -> Result<()> {
    if let Some(vulns) = row.get("vulns") {
        let rows = vulns
            .as_array()
            .ok_or_else(|| error("invalid OSV vulnerability list"))?;
        if rows
            .iter()
            .any(|v| !v.is_object() || string(v, "id").is_empty())
        {
            return Err(error("invalid OSV vulnerability ID"));
        }
    }
    if row
        .get("next_page_token")
        .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return Err(error("invalid OSV page token"));
    }
    Ok(())
}
pub fn merge_aliases(records: &[Value]) -> Vec<(BTreeSet<String>, Vec<Value>)> {
    let mut groups: Vec<(BTreeSet<String>, Vec<Value>)> = Vec::new();
    for r in records {
        let aliases: BTreeSet<_> = array(&r["aliases"])
            .iter()
            .chain(array(&r["upstream"]))
            .filter_map(Value::as_str)
            .chain(std::iter::once(string(r, "id")))
            .map(str::to_owned)
            .collect();
        let matches: Vec<_> = groups
            .iter()
            .enumerate()
            .filter(|(_, g)| !g.0.is_disjoint(&aliases))
            .map(|(i, _)| i)
            .collect();
        if matches.is_empty() {
            groups.push((aliases, vec![r.clone()]));
        } else {
            let first = matches[0];
            groups[first].0.extend(aliases);
            groups[first].1.push(r.clone());
            for i in matches.into_iter().skip(1).rev() {
                let other = groups.remove(i);
                groups[first].0.extend(other.0);
                groups[first].1.extend(other.1);
            }
        }
    }
    groups
}

pub fn scan(packages: &[Package], fetch: &mut dyn FeedSource) -> Result<Record> {
    fetch.select_packages(packages);
    let (mut findings, mut errors, mut sources, mut covered) = (
        Vec::<Value>::new(),
        Vec::<Value>::new(),
        Vec::new(),
        BTreeSet::<String>::new(),
    );
    let mut enrichment = BTreeMap::new();
    let mut targets = Vec::new();
    if !packages.is_empty() {
        targets.push(("kev", KEV));
    }
    if packages.iter().any(|p| p.ecosystem == "Chromium") {
        targets.extend([("cft", CFT), ("releases", RELEASES)]);
    }
    for (name, url) in targets {
        match source(fetch, &mut sources, url, None) {
            Ok(v)
                if v.is_object()
                    && (name != "kev"
                        || v["vulnerabilities"].as_array().is_some_and(|rows| {
                            rows.iter().all(|r| !string(r, "cveID").is_empty())
                        })) =>
            {
                enrichment.insert(name, v);
            }
            Ok(_) => {
                errors.push(json!({"source":name,"error":format!("Invalid {name} feed schema")}))
            }
            Err(e) => errors.push(json!({"source":name,"error":e.to_string()})),
        }
    }
    let kev: BTreeSet<_> = enrichment
        .get("kev")
        .map(|v| {
            array(&v["vulnerabilities"])
                .iter()
                .filter_map(|r| r["cveID"].as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let have_kev = enrichment.contains_key("kev");
    let mut grouped: BTreeMap<(String, String, String), Vec<&Package>> = BTreeMap::new();
    // What Vorda cannot assess by design, by (source, reason): listed, never an error.
    let mut not_assessed = BTreeMap::<(String, String), Vec<String>>::new();
    // The same packages by address in `packages`, for the per-ecosystem counts.
    let mut skipped = BTreeSet::<*const Package>::new();
    for p in packages {
        if p.version.is_empty() || p.version == "unknown" {
            not_assessed
                .entry(("coverage:version".into(), COPY_NO_VERSION.into()))
                .or_default()
                .push(p.name.clone());
            skipped.insert(p);
            continue;
        }
        if mapped(&p.ecosystem) {
            grouped
                .entry((
                    p.ecosystem.clone(),
                    source_name(p).into(),
                    source_version(p).into(),
                ))
                .or_default()
                .push(p);
        } else if !["Chromium", "Arch Linux"].contains(&p.ecosystem.as_str()) {
            not_assessed
                .entry((format!("coverage:{}", p.ecosystem), COPY_NO_MAPPING.into()))
                .or_default()
                .push(format!("{} {}", p.name, p.version));
            skipped.insert(p);
        }
    }
    let unique: Vec<_> = grouped.values().map(|p| p[0]).collect();
    let mut results = Vec::<(&Package, Value)>::new();
    let mut unknown = BTreeMap::<(String, String), Vec<String>>::new();
    let mut unmatched = BTreeMap::<String, Vec<String>>::new();
    for batch in unique.chunks(200) {
        let query = json!({"queries":batch.iter().map(|p|json!({"package":{"name":source_name(p),"ecosystem":p.ecosystem},"version":source_version(p)})).collect::<Vec<_>>()});
        let rows = (|| -> Result<Vec<Value>> {
            let response = source(
                fetch,
                &mut sources,
                &format!("{OSV}/querybatch"),
                Some(&query),
            )?;
            let mut rows = response["results"]
                .as_array()
                .cloned()
                .ok_or_else(|| error("invalid OSV result schema"))?;
            if rows.len() != batch.len() || rows.iter().any(|r| !r.is_object()) {
                return Err(error(
                    "OSV result count does not match or schema is invalid",
                ));
            }
            for (i, row) in rows.iter_mut().enumerate() {
                validate_row(row)?;
                let mut seen = BTreeSet::new();
                while let Some(token) = row["next_page_token"]
                    .as_str()
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                {
                    if !seen.insert(token.clone()) || seen.len() > 100 {
                        return Err(error("OSV pagination did not complete"));
                    }
                    let mut request = query["queries"][i].clone();
                    request["page_token"] = json!(token);
                    let page = source(
                        fetch,
                        &mut sources,
                        &format!("{OSV}/querybatch"),
                        Some(&json!({"queries":[request]})),
                    )?;
                    let p = page["results"]
                        .as_array()
                        .filter(|a| a.len() == 1)
                        .and_then(|a| a.first())
                        .filter(|p| p.is_object())
                        .ok_or_else(|| error("invalid OSV pagination schema"))?;
                    validate_row(p)?;
                    let mut vulns = array(&row["vulns"]).to_vec();
                    vulns.extend_from_slice(array(&p["vulns"]));
                    row["vulns"] = json!(vulns);
                    row["next_page_token"] = p["next_page_token"].clone();
                }
            }
            Ok(rows)
        })();
        match rows {
            Ok(rows) => {
                for (p, row) in batch.iter().zip(&rows) {
                    // The offline database marks a row it could not fully answer.
                    if let Some(why) = row["unknown"].as_str() {
                        let label = format!("{} {}", source_name(p), source_version(p));
                        if why.starts_with(super::osvdb::NOT_OFFLINE) {
                            not_assessed
                                .entry((format!("offline-db:{}", p.ecosystem), why.to_owned()))
                                .or_default()
                                .push(label);
                            skipped.extend(
                                grouped[&(
                                    p.ecosystem.clone(),
                                    source_name(p).into(),
                                    source_version(p).into(),
                                )]
                                    .iter()
                                    .map(|p| *p as *const Package),
                            );
                        } else {
                            unknown
                                .entry((p.ecosystem.clone(), why.to_owned()))
                                .or_default()
                                .push(label);
                        }
                    }
                    for why in array(&row["unmatched"]).iter().filter_map(Value::as_str) {
                        unmatched.entry(why.to_owned()).or_default().push(format!(
                            "{} {}",
                            source_name(p),
                            source_version(p)
                        ));
                    }
                }
                for (p, row) in batch.iter().zip(rows) {
                    for p in &grouped[&(
                        p.ecosystem.clone(),
                        source_name(p).into(),
                        source_version(p).into(),
                    )] {
                        results.push((p, row.clone()));
                    }
                }
            }
            Err(e) => errors.push(json!({"source":"osv","error":e.to_string()})),
        }
    }
    for ((ecosystem, why), packages) in &unknown {
        let shown = packages
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = packages.len().saturating_sub(5);
        errors.push(json!({"source":format!("offline-db:{ecosystem}"),"error":format!(
            "{why}: {} not checked ({shown}{}); the result is unknown, not clean",
            if packages.len() == 1 { "1 package".to_owned() } else { format!("{} packages", packages.len()) },
            if more > 0 { format!(" and {more} more") } else { String::new() }
        )}));
    }
    let warnings: Vec<_> = unmatched
        .iter()
        .map(|(why, packages)| {
            let more = packages.len().saturating_sub(5);
            format!(
                "offline-db: {why} (OSV version queries do not match it either): {}{}",
                packages[..packages.len().min(5)].join(", "),
                if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                }
            )
        })
        .collect();
    let ids: BTreeSet<_> = results
        .iter()
        .flat_map(|(_, r)| array(&r["vulns"]))
        .filter_map(|v| v["id"].as_str())
        .map(str::to_owned)
        .collect();
    let mut records = BTreeMap::new();
    let deferred = regex::Regex::new(r"^(?:UBUNTU-|DEBIAN-)(CVE-\d{4}-\d+)$").unwrap();
    let mut details = Vec::new();
    for id in ids {
        if let Some(c) = deferred.captures(&id) {
            records.insert(
                id.clone(),
                json!({"id":id,"upstream":[&c[1]],"detail_status":"deferred","affected":[]}),
            );
        } else {
            details.push(id);
        }
    }
    let urls: Vec<_> = details
        .iter()
        .map(|id| format!("{OSV}/vulns/{}", super::outputs::quote(id, false)))
        .collect();
    for (id, response) in details
        .into_iter()
        .zip(sources_many(fetch, &mut sources, &urls))
    {
        match response {
            Ok(r) if r.is_object() && r["id"].is_string() => {
                records.insert(id, r);
            }
            Ok(_) => errors.push(json!({"source":id,"error":"Invalid OSV detail schema"})),
            Err(e) => errors.push(json!({"source":id,"error":e.to_string()})),
        }
    }
    let cves: BTreeSet<_> = records
        .values()
        .flat_map(|r| {
            array(&r["aliases"])
                .iter()
                .chain(array(&r["upstream"]))
                .filter_map(Value::as_str)
                .chain(std::iter::once(string(r, "id")))
        })
        .filter(|a| a.starts_with("CVE-"))
        .map(str::to_owned)
        .collect();
    let mut epss = epss(fetch, &cves, &mut sources, &mut errors);
    for (p, row) in results {
        let aid = crate::store::asset(p)?;
        let vulns = array(&row["vulns"]);
        if vulns.iter().all(|v| records.contains_key(string(v, "id")))
            && have_kev
            && row.get("unknown").is_none()
        {
            covered.insert(aid.clone());
        }
        let rs: Vec<_> = vulns
            .iter()
            .filter_map(|v| records.get(string(v, "id")))
            .cloned()
            .collect();
        for (aliases, rs) in merge_aliases(&rs) {
            if rs.iter().all(|r| {
                r.get("withdrawn")
                    .is_some_and(|w| !w.is_null() && w != false)
            }) {
                continue;
            }
            let canonical = aliases
                .iter()
                .find(|a| a.starts_with("CVE-"))
                .or_else(|| aliases.first())
                .ok_or_else(|| error("missing advisory ID"))?;
            let active_identifiers: BTreeSet<String> = rs
                .iter()
                .filter(|r| r.get("withdrawn").is_none_or(|v| v.is_null() || v == false))
                .flat_map(|r| {
                    array(&r["aliases"])
                        .iter()
                        .chain(array(&r["upstream"]))
                        .filter_map(Value::as_str)
                        .chain(std::iter::once(string(r, "id")))
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .collect();
            let mut fixed = BTreeSet::new();
            let mut ranges = Vec::new();
            for r in &rs {
                if r.get("withdrawn")
                    .is_some_and(|v| !v.is_null() && v != false)
                {
                    continue;
                }
                let mut own = Vec::new();
                for a in array(&r["affected"]) {
                    if a["package"]["ecosystem"] == p.ecosystem
                        && osv_name(&p.ecosystem, string(&a["package"], "name"))
                            == osv_name(&p.ecosystem, source_name(p))
                    {
                        for range in array(&a["ranges"]) {
                            if ["SEMVER", "ECOSYSTEM"].contains(&string(range, "type")) {
                                own.push(range.clone());
                                for ev in array(&range["events"]) {
                                    if let Some(v) = ev["fixed"].as_str() {
                                        fixed.insert(v.to_owned());
                                    }
                                }
                            }
                        }
                    }
                }
                if own.is_empty() {
                    own.push(json!({}));
                }
                ranges.extend(own);
            }
            let timestamp = sources
                .iter()
                .find(|s| {
                    string(s, "source_url").trim_start_matches("offline-db:")
                        == format!("{OSV}/vulns/{}", string(&rs[0], "id"))
                })
                .or_else(|| sources.first())
                .map(|s| s["fetched_at"].clone())
                .unwrap_or(Value::Null);
            let severity: Vec<_> = rs
                .iter()
                .filter(|r| r.get("withdrawn").is_none_or(|v| v.is_null() || v == false))
                .flat_map(|r| array(&r["severity"]))
                .cloned()
                .collect();
            let advisory_severity = rs
                .iter()
                .filter(|r| r.get("withdrawn").is_none_or(|v| v.is_null() || v == false))
                .filter_map(|r| r["database_specific"]["severity"].as_str())
                .max_by_key(|s| {
                    ["LOW", "MODERATE", "HIGH", "CRITICAL"]
                        .iter()
                        .position(|l| l == s)
                });
            let published = rs.iter().filter_map(|r| r["published"].as_str()).min();
            let score = active_identifiers
                .iter()
                .filter_map(|a| epss.get(a).copied())
                .reduce(f64::max);
            findings.push(json!({"key":crate::store::identity(&json!([aid,canonical]))?,"asset":aid,"title":format!("{} {}: {canonical}",p.name,p.version),"package":p,"advisory":canonical,"aliases":aliases,"kev":if have_kev{json!(!active_identifiers.is_disjoint(&kev))}else{Value::Null},"epss":score,"severity":severity,"fixed":fixed,"detail_status":if rs.iter().all(|r|r["detail_status"]=="deferred"){"deferred"}else{"complete"},"source_url":rs.iter().map(|r|format!("{OSV}/vulns/{}",string(r,"id"))).collect::<Vec<_>>(),"fetched_at":timestamp,"affected_ranges":ranges,"fixed_applicability":"candidate-versions-require-compatible-branch-and-rescan","alias_provenance":rs.iter().map(|r|json!({"id":r["id"],"aliases":r["aliases"],"withdrawn":r["withdrawn"]})).collect::<Vec<_>>(),"published":published,"summary":rs.iter().find_map(|r|r["summary"].as_str())}));
            if let (Some(label), Some(f)) = (advisory_severity, findings.last_mut()) {
                f["advisory_severity"] = json!(label);
            }
        }
    }
    vendor(
        packages,
        fetch,
        &kev,
        have_kev,
        &mut findings,
        &mut covered,
        &mut errors,
        &mut sources,
    )?;
    let mut resolutions = Vec::new();
    super::browsers::advisories(
        packages,
        fetch,
        &kev,
        have_kev,
        &mut findings,
        &mut covered,
        &mut resolutions,
        &mut errors,
        &mut sources,
    )?;
    let browser_cves = findings
        .iter()
        .filter(|f| f["package"]["ecosystem"] == "Chromium")
        .filter_map(|f| f["advisory"].as_str())
        .map(str::to_owned)
        .collect();
    epss.extend(self::epss(fetch, &browser_cves, &mut sources, &mut errors));
    for f in &mut findings {
        if f["package"]["ecosystem"] == "Chromium" {
            f["epss"] = json!(epss.get(string(f, "advisory")));
        }
    }
    let (fallback, extra) = super::cpe::upstream(packages, fetch)?;
    errors.extend(extra);
    let known: BTreeSet<_> = findings
        .iter()
        .flat_map(|f| {
            array(&f["aliases"])
                .iter()
                .filter_map(Value::as_str)
                .map(|a| (string(f, "asset").to_owned(), a.to_owned()))
                .collect::<Vec<_>>()
        })
        .collect();
    findings.extend(fallback.into_iter().filter(|f| {
        !known.contains(&(string(f, "asset").into(), string(f, "advisory").into()))
            && !known.contains(&(
                string(f, "asset").into(),
                format!("ALPINE-{}", string(f, "advisory")),
            ))
    }));
    let (confirmed, audit, extra) = super::cpe::authoritative(&findings, fetch)?;
    errors.extend(extra);
    let (mut findings, covered, mut errors) =
        super::cpe::resolve(confirmed, &audit, covered, errors);
    if fetch.budget_exhausted() {
        let assets = packages
            .iter()
            .map(crate::store::asset)
            .collect::<Result<BTreeSet<_>>>()?;
        let unchecked = assets.iter().filter(|a| !covered.contains(*a)).count();
        errors.push(json!({"source":"feed-budget","error":format!("Feed time budget ran out: {unchecked} of {} packages were not fully checked; the result is unknown, not clean", assets.len())}));
    }
    let (by_design, errors): (Vec<_>, Vec<_>) = errors.into_iter().partition(|e| {
        e["not_assessed"] == true || string(e, "error").contains(super::osvdb::NEEDS_NETWORK)
    });
    for e in by_design {
        // A browser gap names the browser's path; an Arch feed gap covers every Arch package.
        skipped.extend(
            packages
                .iter()
                .filter(|p| match e["package"].as_str() {
                    Some(path) => p.ecosystem == "Chromium" && p.path == path,
                    None => e["source"] == "arch" && p.ecosystem == "Arch Linux",
                })
                .map(|p| p as *const Package),
        );
        not_assessed
            .entry((string(&e, "source").into(), string(&e, "error").into()))
            .or_default()
            .extend(e["package"].as_str().map(str::to_owned));
    }
    let not_assessed: Vec<_> = not_assessed
        .into_iter()
        .map(|((source, reason), packages)| json!({"source":source,"reason":reason,"packages":packages}))
        .collect();
    let mut ecosystems = BTreeMap::<&str, (usize, usize)>::new();
    for p in packages {
        let (found, skip) = ecosystems.entry(&p.ecosystem).or_default();
        *found += 1;
        *skip += usize::from(skipped.contains(&(p as *const Package)));
    }
    let ecosystems: Record = ecosystems
        .into_iter()
        .map(|(e, (found, skip))| {
            (
                e.to_owned(),
                json!({"found":found,"assessed":found - skip,"not_assessed":skip}),
            )
        })
        .collect();
    for f in &mut findings {
        // An upstream version match on a binary an OS package owns: the distro may have
        // backported the fix, which Vorda cannot see.
        if let Some(owner) = f["package"]["distro_package"].as_str().map(str::to_owned) {
            f["upstream_only"] = json!(true);
            f["confidence"] = json!(format!(
                "upstream only: the OS package {owner} may already carry a backported fix"
            ));
            f["title"] = json!(format!("{} [upstream only]", string(f, "title")));
        }
        f["priority"] = super::priority::priority(f);
    }
    let findings: BTreeMap<_, _> = findings
        .into_iter()
        .map(|f| (string(&f, "key").to_owned(), f))
        .collect();
    let cve_re = regex::Regex::new(r"CVE-\d{4}-\d+").unwrap();
    let notes:Vec<_>=enrichment.get("releases").map(|r|array(&r["feed"]["entry"]).iter().map(|e|json!({"title":e["title"]["$t"],"updated":e["updated"]["$t"],"cves":cve_re.find_iter(string(&e["content"],"$t")).map(|m|m.as_str()).collect::<BTreeSet<_>>()})).collect()).unwrap_or_default();
    let mut result = json!({"findings":findings.into_values().collect::<Vec<_>>(),"audit":audit,"resolutions":resolutions,"covered":covered,"errors":errors,"sources":sources,"packages":packages,"not_assessed":not_assessed,"ecosystems":ecosystems,"browser_fixed_version":enrichment.get("cft").map(|v|v["channels"]["Stable"]["version"].clone()).unwrap_or(Value::Null),"chrome_release_notes":notes});
    if fetch.local_db() {
        result["advisory_source"] = json!("offline-db");
        result["warnings"] = json!(warnings);
        result["not_checked"] = json!([
            "EPSS scores are not looked up with the offline database; each finding's epss is null"
        ]);
    }
    Ok(record(result))
}
fn epss(
    fetch: &mut dyn FeedSource,
    cves: &BTreeSet<String>,
    sources: &mut Vec<Value>,
    errors: &mut Vec<Value>,
) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    // Offline, EPSS is not looked up: every finding's epss stays null (not checked).
    if fetch.local_db() {
        return out;
    }
    let cves: Vec<_> = cves.iter().cloned().collect();
    let urls: Vec<_> = cves
        .chunks(100)
        .map(|batch| format!("{EPSS}?cve={}", batch.join(",")))
        .collect();
    for response in sources_many(fetch, sources, &urls) {
        match response {
            Ok(v) => {
                for r in array(&v["data"]) {
                    if let Some(score) = r["epss"]
                        .as_f64()
                        .or_else(|| r["epss"].as_str().and_then(|s| s.parse().ok()))
                    {
                        if score.is_finite()
                            && (0.0..=1.0).contains(&score)
                            && !string(r, "cve").is_empty()
                        {
                            out.insert(string(r, "cve").into(), score);
                        } else {
                            errors.push(json!({"source":"epss","error":"Invalid EPSS score"}));
                        }
                    } else {
                        errors.push(json!({"source":"epss","error":"Invalid EPSS score"}));
                    }
                }
                if !v["data"].is_array() {
                    errors.push(json!({"source":"epss","error":"Invalid EPSS feed schema"}));
                }
            }
            Err(e) => errors.push(json!({"source":"epss","error":e.to_string()})),
        }
    }
    out
}
#[allow(clippy::too_many_arguments)] // shares its signature with the sibling feed functions: inputs plus output accumulators; a params struct would only move them
fn vendor(
    packages: &[Package],
    fetch: &mut dyn FeedSource,
    kev: &BTreeSet<String>,
    have_kev: bool,
    findings: &mut Vec<Value>,
    covered: &mut BTreeSet<String>,
    errors: &mut Vec<Value>,
    sources: &mut Vec<Value>,
) -> Result<()> {
    if packages.iter().any(|p| p.ecosystem == "Arch Linux") {
        let result = (|| -> Result<()> {
            let advisories = source(fetch, sources, ARCH, None)?;
            let advisories = advisories
                .as_array()
                .ok_or_else(|| error("invalid Arch feed"))?;
            for p in packages.iter().filter(|p| p.ecosystem == "Arch Linux") {
                let aid = crate::store::asset(p)?;
                let mut assessed = true;
                for a in advisories {
                    if !array(&a["packages"]).iter().any(|n| n == &p.name)
                        || a["status"] == "Not affected"
                    {
                        continue;
                    }
                    let fixed = string(a, "fixed");
                    if fixed.is_empty() && string(a, "affected").is_empty() {
                        assessed = false;
                        errors.push(json!({"source":"arch","not_assessed":true,"package":format!("{} {}", p.name, p.version),"error":format!("Arch advisory {} names no affected or fixed version", string(a, "name"))}));
                        continue;
                    }
                    // With no fix released, every build is still affected, including ones
                    // newer than the build the advisory lists.
                    if fixed.is_empty()
                        || super::inventory::run(&["vercmp", &p.version, fixed], 5)?
                            .parse::<i32>()
                            .map_err(error)?
                            < 0
                    {
                        let mut aliases: Vec<_> = array(&a["issues"]).to_vec();
                        aliases.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                        let cid = aliases
                            .first()
                            .and_then(Value::as_str)
                            .unwrap_or(string(a, "name"));
                        findings.push(json!({"key":crate::store::identity(&json!([aid,cid]))?,"asset":aid,"title":format!("{} {}: {cid}",p.name,p.version),"package":p,"advisory":cid,"aliases":aliases,"kev":if have_kev{json!(aliases.iter().filter_map(Value::as_str).any(|a|kev.contains(a)))}else{Value::Null},"fixed":if fixed.is_empty(){vec![]}else{vec![fixed]},"source_url":ARCH,"fetched_at":sources.iter().find(|s|s["source_url"]==ARCH).map(|s|s["fetched_at"].clone())}));
                    }
                }
                if have_kev && assessed {
                    covered.insert(aid);
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            errors.push(json!({"source":"arch","error":e.to_string()}));
        }
    }
    if packages.iter().any(|p| p.ecosystem.starts_with("Debian:")) {
        let result = (|| -> Result<()> {
            let tracker = source(fetch, sources, DEBIAN, None)?;
            let (extra, complete) = super::distro::debian(packages, &tracker)?;
            for mut f in extra {
                let cid = string(&f, "advisory");
                f["kev"] = if have_kev {
                    json!(kev.contains(cid))
                } else {
                    Value::Null
                };
                f["fetched_at"] = sources
                    .iter()
                    .find(|s| s["source_url"] == DEBIAN)
                    .map(|s| s["fetched_at"].clone())
                    .unwrap_or(Value::Null);
                if let Some(previous) = findings.iter_mut().find(|v| v["key"] == f["key"]) {
                    previous["severity"] = f["severity"].clone();
                    let mut fixed: BTreeSet<_> = array(&previous["fixed"])
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect();
                    fixed.extend(
                        array(&f["fixed"])
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned),
                    );
                    previous["fixed"] = json!(fixed);
                    let mut urls: BTreeSet<_> = array(&previous["source_url"])
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect();
                    urls.insert(DEBIAN.into());
                    previous["source_url"] = json!(urls);
                } else {
                    findings.push(f);
                }
            }
            if have_kev {
                covered.extend(complete);
            }
            Ok(())
        })();
        if let Err(e) = result {
            errors.push(json!({"source":"debian","error":e.to_string()}));
            for p in packages
                .iter()
                .filter(|p| p.ecosystem.starts_with("Debian:"))
            {
                covered.remove(&crate::store::asset(p)?);
            }
        }
    }
    let releases: BTreeSet<_> = packages
        .iter()
        .filter_map(|p| {
            p.ecosystem
                .strip_prefix("Ubuntu:")
                .and_then(|v| v.split(':').next())
        })
        .collect();
    for release in releases {
        let codename = match release {
            "20.04" => "focal",
            "22.04" => "jammy",
            "24.04" => "noble",
            "26.04" => "resolute",
            _ => continue,
        };
        let url = format!(
            "https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.usn.oval.xml.bz2"
        );
        let result = (|| -> Result<()> {
            let records = source(fetch, sources, &url, None)?;
            let records = records
                .as_array()
                .ok_or_else(|| error("invalid Ubuntu tracker schema"))?;
            for r in records {
                if r["release"] != codename {
                    continue;
                }
                for p in packages.iter().filter(|p| {
                    p.ecosystem.starts_with(&format!("Ubuntu:{release}:"))
                        && source_name(p) == string(r, "name")
                }) {
                    if super::distro::compare(source_version(p), string(r, "fixed"), &p.ecosystem)?
                        != Some(true)
                    {
                        continue;
                    }
                    for cid in array(&r["cves"]).iter().filter_map(Value::as_str) {
                        let aid = crate::store::asset(p)?;
                        let key = crate::store::identity(&json!([aid, cid]))?;
                        if let Some(f) = findings.iter_mut().find(|f| f["key"] == key) {
                            let mut fixed: BTreeSet<_> = array(&f["fixed"])
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect();
                            fixed.insert(string(r, "fixed").into());
                            f["fixed"] = json!(fixed);
                            if r["severity"] != "unknown" && !r["severity"].is_null() {
                                f["severity"] = r["severity"].clone();
                            }
                        } else {
                            findings.push(json!({"key":key,"asset":aid,"title":format!("{} {}: {cid}",p.name,p.version),"package":p,"advisory":cid,"aliases":[cid],"kev":if have_kev{json!(kev.contains(cid))}else{Value::Null},"fixed":[r["fixed"]],"source_url":[url],"fetched_at":sources.iter().find(|s|s["source_url"]==url).map(|s|s["fetched_at"].clone()),"detail_status":"vendor-fixed-criterion","severity":r.get("severity").cloned().unwrap_or(json!("unknown"))}));
                        }
                    }
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            errors.push(json!({"source":"ubuntu","error":e.to_string()}));
            for p in packages
                .iter()
                .filter(|p| p.ecosystem.starts_with(&format!("Ubuntu:{release}:")))
            {
                covered.remove(&crate::store::asset(p)?);
            }
        }
    }
    Ok(())
}
