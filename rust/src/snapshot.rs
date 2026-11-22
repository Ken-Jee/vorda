//! Bounded saved inventory reader. Supplied snapshots and grants are trusted inputs,
//! not credentials. This module performs no collection, persistence or I/O.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const VERSION: &str = "m0b-derived-1";
const AXES: [&str; 8] = [
    "tenant",
    "site",
    "device",
    "generation",
    "scope",
    "source",
    "evidence_class",
    "evidence",
];
type Dimensions = BTreeMap<String, String>;
type Clause = BTreeMap<String, Vec<String>>;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadError {
    IntegrityFailure,
    InvalidGrant,
    InvalidQuery,
    ScopeWideningRefused,
    NotFoundOrNotAuthorized,
}
type Result<T> = std::result::Result<T, ReadError>;

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Header {
    snapshot_id: String,
    snapshot_revision: u64,
    catalog_id: String,
    catalog_revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    contract_version: String,
    header: Header,
    catalog_tuples: Vec<Dimensions>,
    assessment_bindings: Vec<Assessment>,
    records: Vec<Record>,
    evidence: Vec<Evidence>,
    retained_payload_utf8: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assessment {
    assessment_id: String,
    revision: u64,
    input_sha256: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Time {
    #[serde(deserialize_with = "nullable")]
    value: Option<String>,
    #[serde(deserialize_with = "nullable")]
    null_reason: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Times {
    observed_at: Time,
    assessment_completed_at: Time,
    advisory_checked_at: Time,
    received_at: Time,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoverageState {
    state: String,
    #[serde(deserialize_with = "nullable")]
    reason: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    inventory: CoverageState,
    advisories: CoverageState,
    osv: String,
    kev: String,
    #[serde(deserialize_with = "nullable")]
    epss: Option<String>,
    global_clean: bool,
    fix_verified: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Package {
    ecosystem: String,
    #[serde(deserialize_with = "nullable")]
    namespace: Option<String>,
    name: String,
    version: String,
    #[serde(skip_serializing)]
    qualifiers: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Alias {
    namespace: String,
    value: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    record_id: String,
    component_id: String,
    assessment_id: String,
    revision: u64,
    dimensions: Dimensions,
    package: Package,
    #[serde(skip_serializing)]
    location_ref: String,
    #[serde(skip_serializing)]
    legacy_aliases: Vec<Alias>,
    times: Times,
    #[serde(default)]
    coverage: Coverage,
    source_sha256: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Producer {
    name: String,
    source_pin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    evidence_id: String,
    class: String,
    source_sha256: String,
    source_byte_length: usize,
    producer: Producer,
    record_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    snapshot_id: String,
    snapshot_revision: u64,
    catalog_id: String,
    catalog_revision: u64,
    grant_revision: u64,
    clauses: Vec<Clause>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageFilter {
    ecosystem: String,
    name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    List,
    Count,
    Detail,
    Evidence,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    op: Op,
    id: Option<String>,
    scope_filter: Option<Clause>,
    package: Option<PackageFilter>,
}

// Value's normal deserializer accepts duplicate keys. Walk every object before
// typed deserialization, including maps whose keys are supplied by producers.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(
                    "bounded JSON without duplicate keys or numbers other than unsigned integers",
                )
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut m = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if m.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                    m.insert(k, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(m)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element::<Unique>()? {
                    v.push(x.0);
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(s)))
            }
            fn visit_bool<E: serde::de::Error>(self, b: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(b)))
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(n)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(Visitor)
    }
}
fn nullable<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::deserialize(d)
}
fn bounded(v: &Value, depth: usize) -> bool {
    if depth > 24 {
        return false;
    }
    match v {
        Value::String(s) => s.len() <= 4096,
        Value::Array(a) => a.len() <= 2000 && a.iter().all(|v| bounded(v, depth + 1)),
        Value::Object(m) => {
            m.len() <= 2000
                && m.iter().all(|(k, v)| {
                    k.len() <= 128
                        && if depth == 0 && k == "retained_payload_utf8" {
                            retained_payloads(v)
                        } else {
                            bounded(v, depth + 1)
                        }
                })
        }
        _ => true,
    }
}
/// The retained artifact texts are whole lockfile captures, so they may be as large as the snapshot
/// itself (the 4 MiB snapshot bound still applies); every other string stays at 4096 bytes.
fn retained_payloads(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|m| m.len() <= 2000 && m.iter().all(|(k, v)| k.len() <= 128 && v.is_string()))
}
fn parse(bytes: &[u8], limit: usize) -> Option<Value> {
    if bytes.len() > limit {
        return None;
    }
    let v = serde_json::from_slice::<Unique>(bytes).ok()?.0;
    bounded(&v, 0).then_some(v)
}
fn id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s
            .chars()
            .any(|c| c.is_control() || "*?[](){}|^$\\".contains(c))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn hash(s: &[u8]) -> String {
    format!("{:x}", Sha256::digest(s))
}
fn dimensions(d: &Dimensions) -> bool {
    d.len() == 8
        && AXES.iter().all(|a| d.get(*a).is_some_and(|s| id(s)))
        && d["evidence_class"] == "inventory_projection"
}
fn matches(d: &Dimensions, c: &Clause) -> bool {
    AXES.iter().all(|a| c[*a].contains(&d[*a]))
}
fn decimal(s: &str) -> Option<(u128, usize)> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || s.ends_with('.')
        || whole.len() > 18
        || frac.len() > 18
        || !whole
            .bytes()
            .chain(frac.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((format!("{whole}{frac}").parse().ok()?, frac.len()))
}
fn age(now: &str, then: &str) -> Option<String> {
    let (a, ap) = decimal(now)?;
    let (b, bp) = decimal(then)?;
    let p = ap.max(bp);
    let n = a
        .checked_mul(10u128.pow((p - ap) as u32))?
        .checked_sub(b.checked_mul(10u128.pow((p - bp) as u32))?)?;
    if p == 0 {
        return Some(n.to_string());
    }
    let s = format!("{:0width$}", n, width = p + 1);
    let (w, f) = s.split_at(s.len() - p);
    let f = f.trim_end_matches('0');
    Some(if f.is_empty() {
        w.to_string()
    } else {
        format!("{w}.{f}")
    })
}
fn time(t: &Time) -> bool {
    match (&t.value, &t.null_reason) {
        (Some(v), None) => decimal(v).is_some(),
        (None, Some(r)) => [
            "producer_time_unavailable",
            "legacy_observation_time_unavailable",
            "not_requested",
            "not_received",
        ]
        .contains(&r.as_str()),
        _ => false,
    }
}
impl Default for Coverage {
    fn default() -> Self {
        let unknown = || CoverageState {
            state: "unknown".into(),
            reason: Some("producer_coverage_unavailable".into()),
        };
        Self {
            inventory: unknown(),
            advisories: unknown(),
            osv: "unknown".into(),
            kev: "unknown".into(),
            epss: None,
            global_clean: false,
            fix_verified: false,
        }
    }
}
fn coverage(c: &Coverage) -> bool {
    [&c.inventory, &c.advisories]
        .iter()
        .all(|s| match s.state.as_str() {
            "complete" => s.reason.is_none(),
            "partial" | "failed" | "unavailable" | "unsupported" | "not_requested" | "unknown" => {
                s.reason.as_ref().is_some_and(|s| !s.is_empty())
            }
            _ => false,
        })
        && ["available", "unavailable", "unknown", "not_requested"].contains(&c.osv.as_str())
        && ["true", "false", "unknown"].contains(&c.kev.as_str())
        && c.epss.as_ref().is_none_or(|s| decimal(s).is_some())
        && !c.global_clean
        && !c.fix_verified
}
impl Snapshot {
    fn valid(&self) -> bool {
        if self.contract_version != VERSION
            || !id(&self.header.snapshot_id)
            || !id(&self.header.catalog_id)
            || self.header.snapshot_revision == 0
            || self.header.catalog_revision == 0
            || self.catalog_tuples.len() > 128
            || self.evidence.len() > 128
        {
            return false;
        }
        let catalog: BTreeSet<_> = self.catalog_tuples.iter().collect();
        if catalog.len() != self.catalog_tuples.len() || !catalog.iter().all(|d| dimensions(d)) {
            return false;
        }
        let mut bindings = BTreeMap::new();
        for a in &self.assessment_bindings {
            if !id(&a.assessment_id)
                || a.revision == 0
                || !digest(&a.input_sha256)
                || bindings
                    .insert((&a.assessment_id, a.revision), &a.input_sha256)
                    .is_some()
            {
                return false;
            }
        }
        let mut records = BTreeMap::new();
        for r in &self.records {
            if !id(&r.record_id)
                || !id(&r.component_id)
                || !id(&r.assessment_id)
                || !id(&r.location_ref)
                || r.revision == 0
                || !catalog.contains(&r.dimensions)
                || bindings.get(&(&r.assessment_id, r.revision)) != Some(&&r.source_sha256)
                || !digest(&r.source_sha256)
                || !coverage(&r.coverage)
                || ![
                    &r.times.observed_at,
                    &r.times.assessment_completed_at,
                    &r.times.advisory_checked_at,
                    &r.times.received_at,
                ]
                .iter()
                .all(|t| time(t))
                || r.package.ecosystem.is_empty()
                || r.package.name.is_empty()
                || r.package.version.is_empty()
                || r.legacy_aliases
                    .iter()
                    .any(|a| a.namespace.is_empty() || a.value.is_empty())
                || records.insert(&r.record_id, r).is_some()
            {
                return false;
            }
        }
        let mut evidence = BTreeSet::new();
        let mut members = BTreeSet::new();
        for e in &self.evidence {
            let Some(payload) = self.retained_payload_utf8.get(&e.evidence_id) else {
                return false;
            };
            if !id(&e.evidence_id)
                || e.class != "inventory_projection"
                || !digest(&e.source_sha256)
                || payload.len() != e.source_byte_length
                || hash(payload.as_bytes()) != e.source_sha256
                || e.producer.name.is_empty()
                || e.producer.source_pin.is_empty()
                || !evidence.insert(&e.evidence_id)
            {
                return false;
            }
            let mut tuple = None;
            for rid in &e.record_ids {
                let Some(r) = records.get(rid) else {
                    return false;
                };
                if !members.insert(rid)
                    || r.source_sha256 != e.source_sha256
                    || r.dimensions["evidence"] != e.evidence_id
                    || r.dimensions["evidence_class"] != e.class
                    || tuple.is_some_and(|d| d != &r.dimensions)
                {
                    return false;
                }
                tuple = Some(&r.dimensions);
            }
        }
        members.len() == records.len() && self.retained_payload_utf8.len() == evidence.len()
    }
}
fn canonical(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let ordered: BTreeMap<_, _> = m.into_iter().map(|(k, v)| (k, canonical(v))).collect();
            json!(ordered)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(canonical).collect()),
        v => v,
    }
}

/// Serialized response of the saved-reader boundary; no raw artifact fields.
#[derive(Debug, Deserialize, Serialize)]
pub struct ReadResponse {
    contract_version: String,
    effective_scope: EffectiveScope,
    as_of: String,
    snapshot_id: String,
    snapshot_revision: u64,
    coverage_basis: String,
    coverage_assessment_ids: Vec<String>,
    authorized_coverage: Vec<AuthorizedCoverage>,
    warnings: Vec<String>,
    global_clean: bool,
    fix_verified: bool,
    #[serde(flatten)]
    view: View,
}
#[derive(Debug, Deserialize, Serialize)]
struct EffectiveScope {
    clauses: Vec<Clause>,
}
#[derive(Debug, Deserialize, Serialize)]
struct AuthorizedCoverage {
    assessment_id: String,
    revision: u64,
    dimensions: Dimensions,
    coverage: Coverage,
}
#[derive(Debug, Deserialize, Serialize)]
struct Counts {
    records: usize,
    components: usize,
    packages: usize,
    devices: usize,
    evidence: usize,
}
#[derive(Debug, Deserialize, Serialize)]
struct SafePackage {
    ecosystem: String,
    namespace: Option<String>,
    name: String,
    version: String,
}
#[derive(Debug, Deserialize, Serialize)]
struct SafeRecord {
    record_id: String,
    component_id: String,
    assessment_id: String,
    revision: u64,
    dimensions: Dimensions,
    package: SafePackage,
    times: Times,
    coverage: Coverage,
    source_sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
struct Projection {
    contract_version: String,
    evidence_id: String,
    records: Vec<SafeRecord>,
    source_sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)] // rarely-built variant on a short-lived per-request value; boxing would be a larger diff for no gain
enum View {
    List {
        record_ids: Vec<String>,
        counts: Counts,
        records: Vec<SafeRecord>,
    },
    Count {
        counts: Counts,
    },
    Detail {
        record_ids: Vec<String>,
        record: SafeRecord,
        record_id: String,
        times: Times,
        observed_at: Time,
        coverage: Coverage,
        inventory_state: String,
        advisory_state: String,
        kev: String,
        epss: Option<String>,
        freshness: String,
        age_seconds: Option<String>,
    },
    Evidence {
        record_ids: Vec<String>,
        evidence_id: String,
        producer: Producer,
        source_sha256: String,
        raw_source_returned: bool,
        projection: Projection,
        projection_utf8: String,
        projection_sha256: String,
    },
}

/// Validates all three JSON inputs before returning any view. `as_of` must come
/// from the trusted caller's clock. Errors contain no entity diagnostics.
/// Limits: 4 MiB snapshot, 64 KiB grant, 16 KiB query; depth 24, strings
/// 4096 bytes, arrays 2000, 128 catalog tuples/evidence, decimal precision 18.
pub fn read(snapshot: &[u8], grant: &[u8], query: &[u8], as_of: &str) -> Result<ReadResponse> {
    let s: Snapshot = serde_json::from_value(
        parse(snapshot, 4 * 1024 * 1024).ok_or(ReadError::IntegrityFailure)?,
    )
    .map_err(|_| ReadError::IntegrityFailure)?;
    if !s.valid() {
        return Err(ReadError::IntegrityFailure);
    }
    let g: Grant = serde_json::from_value(parse(grant, 64 * 1024).ok_or(ReadError::InvalidGrant)?)
        .map_err(|_| ReadError::InvalidGrant)?;
    if g.grant_revision == 0
        || g.snapshot_id != s.header.snapshot_id
        || g.snapshot_revision != s.header.snapshot_revision
        || g.catalog_id != s.header.catalog_id
        || g.catalog_revision != s.header.catalog_revision
        || g.clauses.len() > 128
    {
        return Err(ReadError::InvalidGrant);
    }
    for c in &g.clauses {
        if c.len() != 8
            || !AXES.iter().all(|a| {
                c.get(*a).is_some_and(|vs| {
                    vs.iter()
                        .all(|v| id(v) && s.catalog_tuples.iter().any(|d| d[*a] == *v))
                })
            })
        {
            return Err(ReadError::InvalidGrant);
        }
    }
    let qv = parse(query, 16 * 1024).ok_or(ReadError::InvalidQuery)?;
    if ["id", "scope_filter", "package"]
        .iter()
        .any(|k| qv.get(k).is_some_and(Value::is_null))
        || decimal(as_of).is_none()
    {
        return Err(ReadError::InvalidQuery);
    }
    let q: Query = serde_json::from_value(qv).map_err(|_| ReadError::InvalidQuery)?;
    if matches!(q.op, Op::Detail | Op::Evidence) != q.id.is_some()
        || q.id.as_ref().is_some_and(|s| !id(s))
    {
        return Err(ReadError::InvalidQuery);
    }
    let mut clauses = g.clauses;
    if let Some(f) = q.scope_filter {
        for (a, vs) in &f {
            if !AXES.contains(&a.as_str()) || !vs.iter().all(|v| id(v)) {
                return Err(ReadError::InvalidQuery);
            }
            if !vs.iter().all(|v| clauses.iter().any(|c| c[a].contains(v))) {
                return Err(ReadError::ScopeWideningRefused);
            }
        }
        for c in &mut clauses {
            for (a, vs) in &f {
                c.get_mut(a).unwrap().retain(|v| vs.contains(v));
            }
        }
    }
    for c in &mut clauses {
        for vs in c.values_mut() {
            vs.sort();
            vs.dedup();
        }
    }
    let authorized: Vec<_> = s
        .records
        .iter()
        .filter(|r| clauses.iter().any(|c| matches(&r.dimensions, c)))
        .collect();
    let matched: Vec<_> = authorized
        .iter()
        .copied()
        .filter(|r| {
            q.package
                .as_ref()
                .is_none_or(|p| p.ecosystem == r.package.ecosystem && p.name == r.package.name)
        })
        .collect();
    let mut selected = matched.clone();
    match q.op {
        Op::Detail => selected.retain(|r| Some(&r.record_id) == q.id.as_ref()),
        Op::Evidence => selected.retain(|r| Some(&r.dimensions["evidence"]) == q.id.as_ref()),
        _ => (),
    }
    if matches!(q.op, Op::Detail | Op::Evidence) && selected.is_empty() {
        return Err(ReadError::NotFoundOrNotAuthorized);
    }
    selected.sort_by_key(|r| &r.record_id);
    let coverage_ids: BTreeSet<_> = authorized.iter().map(|r| &r.assessment_id).collect();
    let mut out = json!({"contract_version":VERSION,"effective_scope":{"clauses":clauses},"as_of":as_of,"snapshot_id":s.header.snapshot_id,"snapshot_revision":s.header.snapshot_revision,"coverage_basis":"authorized_pre_package_filter","coverage_assessment_ids":coverage_ids,"authorized_coverage":[],"warnings":[],"global_clean":false,"fix_verified":false});
    // Keep distinct coverage when assessment IDs span multiple scope bindings.
    let cov:BTreeSet<_>=authorized.iter().map(|r| serde_json::to_string(&canonical(json!({"assessment_id":r.assessment_id,"revision":r.revision,"dimensions":r.dimensions,"coverage":r.coverage}))).unwrap()).collect();
    out["authorized_coverage"] = json!(cov
        .iter()
        .map(|c| serde_json::from_str::<Value>(c).unwrap())
        .collect::<Vec<_>>());
    if !matches!(q.op, Op::Count) {
        out["record_ids"] = json!(selected.iter().map(|r| &r.record_id).collect::<Vec<_>>());
    }
    match q.op {
        Op::List | Op::Count => {
            let components: BTreeSet<_> = selected.iter().map(|r| &r.component_id).collect();
            let packages: BTreeSet<_> = selected
                .iter()
                .map(|r| {
                    (
                        &r.package.ecosystem,
                        &r.package.namespace,
                        &r.package.name,
                        &r.package.version,
                        &r.package.qualifiers,
                    )
                })
                .collect();
            let devices: BTreeSet<_> = selected
                .iter()
                .map(|r| {
                    (
                        &r.dimensions["tenant"],
                        &r.dimensions["device"],
                        &r.dimensions["generation"],
                    )
                })
                .collect();
            let evidence: BTreeSet<_> =
                selected.iter().map(|r| &r.dimensions["evidence"]).collect();
            out["counts"] = json!({"records":selected.len(),"components":components.len(),"packages":packages.len(),"devices":devices.len(),"evidence":evidence.len()});
            if matches!(q.op, Op::List) {
                out["records"] = json!(selected);
            }
        }
        Op::Detail => {
            let r = selected[0];
            out["record"] = json!(r);
            out["record_id"] = json!(r.record_id);
            out["times"] = json!(r.times);
            out["observed_at"] = json!(r.times.observed_at);
            out["coverage"] = json!(r.coverage);
            out["inventory_state"] = json!(r.coverage.inventory.state);
            out["advisory_state"] = json!(r.coverage.advisories.state);
            out["kev"] = json!(r.coverage.kev);
            out["epss"] = json!(r.coverage.epss);
            let seconds = r
                .times
                .observed_at
                .value
                .as_ref()
                .and_then(|t| age(as_of, t));
            out["freshness"] = json!(if r.times.observed_at.value.is_none() {
                "unknown"
            } else if seconds.is_none() {
                "clock_skew"
            } else {
                "not_evaluated"
            });
            out["age_seconds"] = json!(seconds);
        }
        Op::Evidence => {
            let e = s
                .evidence
                .iter()
                .find(|e| Some(&e.evidence_id) == q.id.as_ref())
                .unwrap();
            let projection = canonical(
                json!({"contract_version":VERSION,"evidence_id":e.evidence_id,"records":selected,"source_sha256":e.source_sha256}),
            );
            let bytes = serde_json::to_string(&projection).unwrap();
            out["evidence_id"] = json!(e.evidence_id);
            out["producer"] = json!(e.producer);
            out["source_sha256"] = json!(e.source_sha256);
            out["raw_source_returned"] = json!(false);
            out["projection"] = projection;
            out["projection_utf8"] = json!(bytes);
            out["projection_sha256"] = json!(hash(bytes.as_bytes()));
        }
    }
    out["op"] = json!(match q.op {
        Op::List => "list",
        Op::Count => "count",
        Op::Detail => "detail",
        Op::Evidence => "evidence",
    });
    serde_json::from_value(out).map_err(|_| ReadError::IntegrityFailure)
}
