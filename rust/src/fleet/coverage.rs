//! Status, coverage, freshness and inventory over the hub's v2 tables, inside a reader's grant.
//! Every query starts from the devices the grant, intersected with the caller's filters, covers,
//! and reaches v2 rows only through that device set (tenant, site, device).
//! Freshness is computed here, at query time, under a policy the response declares; nothing is
//! written and no stored time is replaced by another.
use super::auth::AuthorizedScope;
use super::cursor::{self, Binding};
use super::query::{
    check_sizes, device_row, effective_scope, has_v2, legacy_visible, page_limit, readonly,
    sources_unavailable, visible, DeviceFilter, PageRequest, CONTRACT, ENVELOPE_BYTES,
    MAX_FILTER_SOURCES, MAX_FILTER_TEXT, PAGE_BYTES,
};
use super::untrusted::{self, ident, ident_str, moment, quoted};
use crate::link::storage::Hub;
use crate::{Error, Result};
use rusqlite::{params_from_iter, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// An observation dated later than this beyond the clock is labelled, never treated as fresh.
const SKEW_SECS: f64 = 300.0;
const MIN_FRESH_SECS: u64 = 60;
const MAX_FRESH_SECS: u64 = 90 * 86400;
/// Authorities (device, scope, source) one query will work through. A device can open a few more
/// with every batch, so a view beyond this is refused with advice to narrow it, never truncated.
pub const MAX_AUTHORITIES: usize = 1000;

/// How old an observation or check-in may be and still count as fresh. The default is a day and a
/// half, which tolerates one missed daily run.
#[derive(Debug, Clone, Copy)]
pub struct FreshnessPolicy {
    pub fresh_for_secs: u64,
}
impl Default for FreshnessPolicy {
    fn default() -> Self {
        Self {
            fresh_for_secs: 36 * 3600,
        }
    }
}
impl FreshnessPolicy {
    pub(super) fn check(&self) -> Result<()> {
        if !(MIN_FRESH_SECS..=MAX_FRESH_SECS).contains(&self.fresh_for_secs) {
            return Err(Error::rejected(
                400,
                "freshness window must be 60 seconds to 90 days",
            ));
        }
        Ok(())
    }
    pub(super) fn declared(&self) -> Value {
        json!({"id":"age-v1","fresh_for_seconds":self.fresh_for_secs,"observation_basis":"observed_at",
            "checkin_basis":"received_at","future_skew_seconds":SKEW_SECS})
    }
    /// `(state, age)`: an unknown time is `unknown`, never replaced by the receipt time.
    pub(super) fn classify(&self, time: Option<f64>, now: f64) -> (&'static str, Option<f64>) {
        match time {
            None => ("unknown", None),
            Some(t) if t > now + SKEW_SECS => ("future", Some(now - t)),
            Some(t) if now - t <= self.fresh_for_secs as f64 => ("fresh", Some(now - t)),
            Some(t) => ("stale", Some(now - t)),
        }
    }
}

/// One v2 authority (device, scope, source) inside the grant, with its current evidence.
pub(super) struct Authority {
    pub(super) authority: String,
    pub(super) device: String,
    pub(super) org: String,
    pub(super) site: String,
    pub(super) scope: String,
    pub(super) source: String,
    pub(super) revoked: bool,
    frontier: i64,
    publication: i64,
    delivery_frontier: i64,
    last_received: Option<f64>,
    pub(super) observed_at: Value,
    advisory_checked_at: Value,
    pub(super) coverage: Value,
    inputs_complete: i64,
    inputs_failed: i64,
    /// The current components; loaded only for the inventory, which is the one list that shows them.
    pub(super) records: Vec<Value>,
    record_count: i64,
}
pub(super) fn time_of(v: &Value) -> Option<f64> {
    // Admission only stores plain decimals, so a non-finite time cannot arrive that way; this is
    // defence in depth over rows already stored.
    v["value"]
        .as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|t| t.is_finite())
}
impl Authority {
    /// A source its device retired is neither fresh nor stale: it stopped on purpose.
    fn retired(&self) -> bool {
        self.state("inventory") == "retired"
    }
    fn source_row(&self, policy: &FreshnessPolicy, now: f64) -> Value {
        let (freshness, age) = policy.classify(time_of(&self.observed_at), now);
        let freshness = if self.retired() { "retired" } else { freshness };
        json!({"device":self.device,"org":self.org,"site":self.site,"revoked":self.revoked,"scope":ident_str(&self.scope),"source":ident_str(&self.source),
            "assessment_revision":(self.frontier > 0).then_some(self.frontier),
            "observed_at":moment(&self.observed_at),"age_seconds":age,"freshness":freshness,
            "advisory_checked_at":moment(&self.advisory_checked_at),"last_received":self.last_received,
            "coverage":{"inventory":untrusted::coverage(&self.coverage["inventory"]),"advisories":untrusted::coverage(&self.coverage["advisories"]),
                "inputs":{"complete":self.inputs_complete,"failed":self.inputs_failed}},
            "records":self.record_count})
    }
    fn state(&self, which: &str) -> String {
        untrusted::state(self.coverage[which]["state"].as_str().unwrap_or_default()).to_string()
    }
}

/// How much of each authority a list needs, so that one that needs little does not pay for the
/// frontier artifact and the coverage counts.
#[derive(Clone, Copy, PartialEq)]
enum Detail {
    /// Only who it is and where it stands: what the revision digest and a list of changes use.
    Identity,
    /// Plus its current evidence and coverage counts.
    Status,
    /// Plus its current components.
    Inventory,
}

/// The authorities of the devices in `cond`, restricted to the granted sources and, when the
/// caller names any, to those too, so that the cap below counts only what the caller asked about.
fn authorities(
    db: &Connection,
    scope: &AuthorizedScope,
    cond: &str,
    args: &[String],
    wanted: &[String],
    detail: Detail,
) -> Result<Vec<Authority>> {
    if !has_v2(db)? {
        return Ok(vec![]);
    }
    let mut sql = format!(
        "SELECT a.authority,a.source,a.frontier,a.delivery_frontier,a.publication,d.id,d.org,d.site,d.revoked \
         FROM v2_authorities a JOIN devices d ON json_extract(a.authority,'$[2]')=d.id \
         AND json_extract(a.authority,'$[0]')=d.org AND json_extract(a.authority,'$[1]')=d.site WHERE {cond}"
    );
    let mut args = args.to_vec();
    if let Some(sources) = scope.sources() {
        sql += &format!(" AND a.source IN ({})", vec!["?"; sources.len()].join(","));
        args.extend(sources.iter().cloned());
    }
    if !wanted.is_empty() {
        sql += &format!(" AND a.source IN ({})", vec!["?"; wanted.len()].join(","));
        args.extend(wanted.iter().cloned());
    }
    // One more than the cap, to tell "at the cap" from "over it".
    sql += &format!(" ORDER BY a.authority LIMIT {}", MAX_AUTHORITIES + 1);
    let rows = db
        .prepare(&sql)?
        .query_map(params_from_iter(&args), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, bool>(8)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() > MAX_AUTHORITIES {
        return Err(Error::rejected(
            413,
            format!("the view holds more than {MAX_AUTHORITIES} sources: narrow it by site, device or source"),
        ));
    }
    let unknown = |reason: &str| json!({"value":null,"null_reason":reason});
    rows.into_iter()
        .map(|(authority, source, frontier, delivery_frontier, publication, device, org, site, revoked)| {
            let tuple: Value = serde_json::from_str(&authority)?;
            if detail == Detail::Identity {
                return Ok(Authority {
                    authority,
                    device,
                    org,
                    site,
                    scope: tuple[4].as_str().unwrap_or_default().to_string(),
                    source,
                    revoked,
                    frontier,
                    publication,
                    delivery_frontier,
                    last_received: None,
                    observed_at: Value::Null,
                    advisory_checked_at: Value::Null,
                    coverage: Value::Null,
                    inputs_complete: 0,
                    inputs_failed: 0,
                    records: vec![],
                    record_count: 0,
                });
            }
            let last_received: Option<f64> = db.query_row(
                "SELECT MAX(CAST(received AS REAL)) FROM v2_assessments WHERE authority=?",
                [&authority],
                |r| r.get(0),
            )?;
            let artifact: Option<Vec<u8>> = db
                .query_row(
                    "SELECT artifact FROM v2_assessments WHERE authority=? AND revision=?",
                    rusqlite::params![authority, frontier],
                    |r| r.get(0),
                )
                .optional()?;
            let artifact: Option<Value> = artifact
                .map(|raw| {
                    serde_json::from_slice::<Head>(&raw).map(|h| json!({"times":h.times,"coverage":h.coverage}))
                })
                .transpose()?;
            let (mut complete, mut failed) = (0, 0);
            for state in db
                .prepare("SELECT payload FROM v2_coverage WHERE authority=?")?
                .query_map([&authority], |r| r.get::<_, Vec<u8>>(0))?
            {
                let payload: Value = serde_json::from_slice(&state?)?;
                if payload["state"] == "complete" {
                    complete += 1;
                } else {
                    failed += 1;
                }
            }
            let record_count: i64 = db.query_row(
                "SELECT COUNT(*) FROM v2_current WHERE authority=?",
                [&authority],
                |r| r.get(0),
            )?;
            let records = if detail != Detail::Inventory {
                vec![]
            } else {
                db
                .prepare("SELECT o.payload FROM v2_current c JOIN v2_observations o ON o.authority=c.authority AND o.record=c.record WHERE c.authority=? ORDER BY c.path")?
                .query_map([&authority], |r| r.get::<_, Vec<u8>>(0))?
                .map(|raw| Ok(serde_json::from_slice::<Value>(&raw?)?))
                .collect::<Result<Vec<_>>>()?
            };
            let times = artifact.as_ref().map(|a| a["times"].clone());
            Ok(Authority {
                authority,
                device,
                org,
                site,
                scope: tuple[4].as_str().unwrap_or_default().to_string(),
                source,
                revoked,
                frontier,
                publication,
                delivery_frontier,
                last_received,
                observed_at: times.as_ref().map_or_else(|| unknown("no_published_assessment"), |t| t["observed_at"].clone()),
                advisory_checked_at: times.as_ref().map_or_else(|| unknown("no_published_assessment"), |t| t["advisory_checked_at"].clone()),
                coverage: artifact.as_ref().map_or_else(
                    || json!({"inventory":{"state":"unknown","reason":"no_published_assessment"},"advisories":{"state":"unknown","reason":"no_published_assessment"}}),
                    |a| a["coverage"].clone(),
                ),
                inputs_complete: complete,
                inputs_failed: failed,
                records,
                record_count,
            })
        })
        .collect()
}

/// The parts of a frontier artifact a view reads. The rest (lockfile text, records) is skipped
/// while reading, not built into a value: it can be megabytes.
#[derive(serde::Deserialize)]
struct Head {
    #[serde(default)]
    times: Value,
    #[serde(default)]
    coverage: Value,
}

/// `(id, org, site, revoked, v1 receipt)` of one device in a view.
type DeviceRow = (String, String, String, bool, Option<f64>);

/// Everything a v2 query needs once the grant, filters, snapshot and cursor are settled.
pub(super) struct Snapshot {
    pub(super) authorities: Vec<Authority>,
    /// Each device in the view.
    devices: Vec<DeviceRow>,
    revision: String,
    pub(super) eval_now: f64,
    key: [u8; 32],
    issued: u64,
    pub(super) offset: u64,
    kind: &'static str,
    query: String,
    /// The connection and read transaction the revision was digested in: whatever a list reads
    /// next sees the same hub state the revision names.
    pub(super) db: Connection,
}
/// What a caller narrows a view by, on top of the grant.
#[derive(Clone, Copy)]
pub(super) struct Narrow<'a> {
    pub(super) devices: &'a DeviceFilter,
    /// Sources the caller names; none means all of the grant's.
    pub(super) sources: &'a [String],
}
/// Open one read transaction over the grant's view, digest it into a revision, and settle the
/// cursor. Freshness is evaluated at the time the walk started, so pages of one walk agree.
pub(super) fn snapshot(
    hub: &Hub,
    scope: &AuthorizedScope,
    narrow: Narrow,
    kind: &'static str,
    query: &str,
    page: &PageRequest,
    now: f64,
) -> Result<Option<Snapshot>> {
    let Some((cond, args)) = visible(scope, narrow.devices) else {
        if page.cursor.is_some() {
            return Err(cursor::invalid());
        }
        return Ok(None);
    };
    let db = readonly(hub)?;
    if sources_unavailable(&db, scope)? {
        if page.cursor.is_some() {
            return Err(cursor::invalid());
        }
        return Ok(None);
    }
    // The key is read from the reader store and the hub's first device through other connections.
    // Read inside the transaction below, that second read of the hub would wait for a committing
    // writer, which waits for this transaction: both give up after their 200 ms.
    let key = scope.cursor_key(hub)?;
    // Left open on the snapshot: it ends with the connection, never committed. A caller that is
    // done reading from it before it does slow work must roll it back, as `fleet_changes` does.
    db.execute_batch("BEGIN")?;
    let detail = match kind {
        "changes" => Detail::Identity,
        "inventory" => Detail::Inventory,
        _ => Detail::Status,
    };
    // The device list never shows authorities, so a view with more of them than the cap must
    // still list its devices; the device rows alone carry every change it can show.
    let authorities = if kind == "devices" {
        vec![]
    } else {
        authorities(&db, scope, &cond, &args, narrow.sources, detail)?
    };
    let rows = db
        .prepare(&format!(
            "SELECT d.id,d.sequence,d.revoked,d.received,d.org,d.site FROM devices d WHERE {cond} ORDER BY d.id"
        ))?
        .query_map(params_from_iter(&args), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, Option<f64>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // Legacy (v1) receipts only count for readers who may see version 1 evidence at all; for the
    // others they are neither returned nor allowed to move the revision.
    let legacy = legacy_visible(scope);
    let rows: Vec<_> = rows
        .into_iter()
        .map(|(id, sequence, revoked, received, org, site)| {
            let (sequence, received) = if legacy {
                (sequence, received)
            } else {
                (0, None)
            };
            (id, sequence, revoked, received, org, site)
        })
        .collect();
    let mut hash = Sha256::new();
    hash.update(kind.as_bytes());
    for (id, sequence, revoked, received, _, _) in &rows {
        hash.update(
            json!([id, sequence, revoked, received])
                .to_string()
                .as_bytes(),
        );
    }
    for a in &authorities {
        hash.update(
            json!([
                a.device,
                a.scope,
                a.source,
                a.frontier,
                a.delivery_frontier,
                a.publication
            ])
            .to_string()
            .as_bytes(),
        );
    }
    let revision = format!("{:x}", hash.finalize());
    let grant = scope.grant_digest();
    let binding = Binding {
        reader: scope.reader(),
        grant: &grant,
        query,
        revision: &revision,
    };
    let (offset, issued) = match page.cursor {
        Some(c) => cursor::open(&key, &binding, c, now)?,
        None => (0, now as u64),
    };
    let devices = rows
        .into_iter()
        .map(|(id, _, revoked, received, org, site)| (id, org, site, revoked, received))
        .collect();
    Ok(Some(Snapshot {
        authorities,
        devices,
        revision,
        eval_now: issued as f64,
        key,
        issued,
        offset,
        kind,
        query: query.to_string(),
        db,
    }))
}

pub(super) fn digest(parts: Value) -> String {
    format!("{:x}", Sha256::digest(parts.to_string().as_bytes()))
}
pub(super) fn sorted(v: &[String]) -> BTreeSet<&String> {
    v.iter().collect()
}
fn tally(values: impl Iterator<Item = String>) -> Value {
    let mut counts = std::collections::BTreeMap::<String, i64>::new();
    for v in values {
        *counts.entry(v).or_default() += 1;
    }
    json!(counts)
}

/// Finish a list: apply the cursor offset, page limit and byte budget to fully rendered rows.
pub(super) fn page_of(
    snap: &Snapshot,
    scope: &AuthorizedScope,
    page: &PageRequest,
    rows: Vec<Value>,
    policy: &FreshnessPolicy,
    notes: Value,
) -> Result<Value> {
    let total = rows.len();
    let mut rows = rows.into_iter().skip(snap.offset as usize);
    page_rendered(
        snap,
        scope,
        page,
        total,
        |_| rows.next().unwrap_or_default(),
        policy,
        notes,
    )
}

/// Like `page_of`, for a list that is costly to render: `render(i)` is called, in order, only for
/// the rows of the requested page.
pub(super) fn page_rendered(
    snap: &Snapshot,
    scope: &AuthorizedScope,
    page: &PageRequest,
    total: usize,
    mut render: impl FnMut(usize) -> Value,
    policy: &FreshnessPolicy,
    notes: Value,
) -> Result<Value> {
    let limit = page_limit(page)?;
    let total = total as u64;
    if snap.offset > total {
        return Err(cursor::invalid());
    }
    let effective = effective_scope(scope);
    let mut bytes = effective.to_string().len() + ENVELOPE_BYTES;
    let mut out = vec![];
    let mut cut = false;
    let last = total.min(snap.offset.saturating_add(limit as u64));
    for i in snap.offset..last {
        let row = render(i as usize);
        bytes += row.to_string().len();
        if bytes > PAGE_BYTES && !out.is_empty() {
            cut = true;
            break;
        }
        out.push(row);
    }
    let end = snap.offset + out.len() as u64;
    let grant = scope.grant_digest();
    let binding = Binding {
        reader: scope.reader(),
        grant: &grant,
        query: &snap.query,
        revision: &snap.revision,
    };
    let next = (end < total).then(|| cursor::issue(&snap.key, &binding, end, snap.issued));
    let page_end = match (&next, cut) {
        (None, _) => "last",
        (_, true) => "bytes",
        _ => "limit",
    };
    let mut response = json!({"contract_version":CONTRACT,"effective_scope":effective,"revision":snap.revision,
        "as_of":snap.eval_now,"freshness_policy":policy.declared(),"total":total,"limit":limit,
        "page_end":page_end,"next_cursor":next,"data_notice":untrusted::NOTICE});
    response[snap.kind] = json!(out);
    for (k, v) in notes.as_object().into_iter().flatten() {
        response[k] = v.clone();
    }
    Ok(response)
}

pub(super) fn empty_response(
    scope: &AuthorizedScope,
    kind: &str,
    policy: &FreshnessPolicy,
    now: f64,
) -> Value {
    let mut response = json!({"contract_version":CONTRACT,"effective_scope":effective_scope(scope),"revision":"0",
        "as_of":now,"freshness_policy":policy.declared(),"total":0,"page_end":"last","next_cursor":null,"data_notice":untrusted::NOTICE});
    response[kind] = json!([]);
    response
}

#[derive(Default)]
pub struct SourceFilter {
    pub sites: Vec<String>,
    pub devices: Vec<String>,
    pub sources: Vec<String>,
    /// One of `fresh`, `stale`, `unknown`, `future`, `retired`.
    pub freshness: Option<String>,
    /// An inventory coverage state, such as `complete` or `partial`.
    pub inventory_state: Option<String>,
}

/// Source filters are bounded like the other filter lists: in count and in the length of each value.
pub(super) fn check_sources(sources: &[String]) -> Result<()> {
    if sources.len() > MAX_FILTER_SOURCES
        || sources.iter().any(|s| s.chars().count() > MAX_FILTER_TEXT)
    {
        return Err(Error::rejected(400, "too many or too long filter values"));
    }
    Ok(())
}

/// Which sources report for which devices and scopes, how fresh each is under the declared policy,
/// and what each covered: the stale, partial, failed and unassessed ones stay in the list.
pub fn visible_sources(
    hub: &Hub,
    scope: &AuthorizedScope,
    filter: &SourceFilter,
    policy: &FreshnessPolicy,
    page: &PageRequest,
    now: f64,
) -> Result<Value> {
    scope.check(hub)?;
    policy.check()?;
    check_sizes(&filter.sites, &filter.devices)?;
    check_sources(&filter.sources)?;
    if filter
        .freshness
        .as_deref()
        .is_some_and(|f| !["fresh", "stale", "unknown", "future", "retired"].contains(&f))
    {
        return Err(Error::rejected(400, "unknown freshness state"));
    }
    // An unknown state would match nothing, which a reader takes for "none of those".
    if filter
        .inventory_state
        .as_deref()
        .is_some_and(|s| untrusted::state(s) != s)
    {
        return Err(Error::rejected(400, "unknown inventory state"));
    }
    let devices = DeviceFilter {
        sites: filter.sites.clone(),
        devices: filter.devices.clone(),
    };
    let query = digest(
        json!({"kind":"sources","sites":sorted(&filter.sites),"devices":sorted(&filter.devices),
        "sources":sorted(&filter.sources),"freshness":filter.freshness,"inventory":filter.inventory_state,
        "policy":policy.fresh_for_secs}),
    );
    let narrow = Narrow {
        devices: &devices,
        sources: &filter.sources,
    };
    let Some(snap) = snapshot(hub, scope, narrow, "sources", &query, page, now)? else {
        return Ok(empty_response(scope, "sources", policy, now));
    };
    let rows: Vec<Value> = snap
        .authorities
        .iter()
        .map(|a| a.source_row(policy, snap.eval_now))
        .filter(|r| {
            filter
                .freshness
                .as_deref()
                .is_none_or(|f| r["freshness"] == f)
        })
        .filter(|r| {
            filter
                .inventory_state
                .as_deref()
                .is_none_or(|s| r["coverage"]["inventory"]["state"] == s)
        })
        .collect();
    page_of(&snap, scope, page, rows, policy, json!({}))
}

#[derive(Default)]
pub struct InventoryFilter {
    pub sites: Vec<String>,
    pub devices: Vec<String>,
    pub sources: Vec<String>,
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

/// One current component of `a` as the inventory and a finding show it. A component kept from an
/// earlier assessment keeps that assessment's time.
pub(super) fn inventory_row(
    a: &Authority,
    r: &Value,
    policy: &FreshnessPolicy,
    eval_now: f64,
) -> Value {
    let p = &r["package"];
    let observed = &r["times"]["observed_at"];
    let (freshness, age) = policy.classify(time_of(observed), eval_now);
    json!({"device":a.device,"org":a.org,"site":a.site,"revoked":a.revoked,"scope":ident_str(&a.scope),"source":ident_str(&a.source),
        "component_id":ident(&r["component_id"]),"record_id":ident(&r["record_id"]),"location_ref":ident(&r["location_ref"]),"evidence":ident_str(&format!("{}/{}", a.device, r["dimensions"]["evidence"].as_str().unwrap_or_default())),
        "package":{"ecosystem":quoted(&p["ecosystem"]),"namespace":quoted(&p["namespace"]),"name":quoted(&p["name"]),"version":quoted(&p["version"])},
        "observed_at":moment(observed),"age_seconds":age,"freshness":freshness,
        "inventory_coverage":untrusted::coverage(&a.coverage["inventory"]),"advisory_coverage":untrusted::coverage(&a.coverage["advisories"])})
}

/// Components observed in the grant's current evidence, including ones with no finding. An empty
/// list is only meaningful next to `view_coverage`: it says how much of the view was fully collected.
pub fn visible_inventory(
    hub: &Hub,
    scope: &AuthorizedScope,
    filter: &InventoryFilter,
    policy: &FreshnessPolicy,
    page: &PageRequest,
    now: f64,
) -> Result<Value> {
    scope.check(hub)?;
    policy.check()?;
    check_sizes(&filter.sites, &filter.devices)?;
    check_sources(&filter.sources)?;
    if [&filter.ecosystem, &filter.name, &filter.version]
        .iter()
        .any(|v| {
            v.as_ref()
                .is_some_and(|v| v.chars().count() > MAX_FILTER_TEXT)
        })
    {
        return Err(Error::rejected(400, "too many or too long filter values"));
    }
    let devices = DeviceFilter {
        sites: filter.sites.clone(),
        devices: filter.devices.clone(),
    };
    let query = digest(
        json!({"kind":"inventory","sites":sorted(&filter.sites),"devices":sorted(&filter.devices),
        "sources":sorted(&filter.sources),"ecosystem":filter.ecosystem,"name":filter.name,"version":filter.version,
        "policy":policy.fresh_for_secs}),
    );
    let narrow = Narrow {
        devices: &devices,
        sources: &filter.sources,
    };
    let Some(snap) = snapshot(hub, scope, narrow, "inventory", &query, page, now)? else {
        return Ok(empty_response(scope, "inventory", policy, now));
    };
    let wanted = |field: &Option<String>, actual: &Value| {
        field.as_deref().is_none_or(|w| actual.as_str() == Some(w))
    };
    let mut rows = vec![];
    for a in &snap.authorities {
        for r in &a.records {
            let p = &r["package"];
            if !(wanted(&filter.ecosystem, &p["ecosystem"])
                && wanted(&filter.name, &p["name"])
                && wanted(&filter.version, &p["version"]))
            {
                continue;
            }
            rows.push(inventory_row(a, r, policy, snap.eval_now));
        }
    }
    let covered = &snap.authorities;
    let notes = json!({"view_coverage":{
        "sources":covered.len(),
        "inventory_states":tally(covered.iter().map(|a| a.state("inventory"))),
        "advisory_states":tally(covered.iter().map(|a| a.state("advisories"))),
        "note":"inventory lists observed components whether or not they have a finding; a component missing from it is only absent where inventory coverage is complete"}});
    page_of(&snap, scope, page, rows, policy, notes)
}

/// The devices the grant covers, one page at a time, each with its version 1 finding count and
/// coverage.
pub fn visible_devices(
    hub: &Hub,
    scope: &AuthorizedScope,
    filter: &DeviceFilter,
    page: &PageRequest,
    now: f64,
) -> Result<Value> {
    scope.check(hub)?;
    check_sizes(&filter.sites, &filter.devices)?;
    let policy = FreshnessPolicy::default();
    let query = digest(
        json!({"kind":"devices","sites":sorted(&filter.sites),"devices":sorted(&filter.devices)}),
    );
    let narrow = Narrow {
        devices: filter,
        sources: &[],
    };
    let Some(snap) = snapshot(hub, scope, narrow, "devices", &query, page, now)? else {
        return Ok(empty_response(scope, "devices", &policy, now));
    };
    let db = readonly(hub)?;
    let legacy = legacy_visible(scope);
    let rows = snap
        .devices
        .iter()
        .map(|(id, org, site, revoked, received)| {
            device_row(&db, id, org, site, *revoked, *received, legacy)
        })
        .collect::<Result<Vec<_>>>()?;
    page_of(&snap, scope, page, rows, &policy, json!({}))
}

/// Counts for the grant's view, each stating what it counts. Revoked devices are not expected to
/// check in; they are counted apart and stay visible.
pub fn fleet_status(
    hub: &Hub,
    scope: &AuthorizedScope,
    filter: &DeviceFilter,
    policy: &FreshnessPolicy,
    now: f64,
) -> Result<Value> {
    scope.check(hub)?;
    policy.check()?;
    check_sizes(&filter.sites, &filter.devices)?;
    let request = PageRequest::default();
    let narrow = Narrow {
        devices: filter,
        sources: &[],
    };
    Ok(
        match snapshot(hub, scope, narrow, "status", "status", &request, now)? {
            Some(snap) => status_body(
                scope,
                &snap.revision,
                policy,
                now,
                &snap.devices,
                &snap.authorities,
            ),
            None => status_body(scope, "0", policy, now, &[], &[]),
        },
    )
}

/// One response shape for every view, empty or not.
fn status_body(
    scope: &AuthorizedScope,
    revision: &str,
    policy: &FreshnessPolicy,
    now: f64,
    devices: &[DeviceRow],
    authorities: &[Authority],
) -> Value {
    let (mut expected, mut revoked, mut fresh, mut stale, mut ahead, mut never) =
        (0, 0, 0, 0, 0, 0);
    for (id, _, _, is_revoked, v1_received) in devices {
        if *is_revoked {
            revoked += 1;
            continue;
        }
        expected += 1;
        let last = authorities
            .iter()
            .filter(|a| &a.device == id)
            .filter_map(|a| a.last_received)
            .chain(*v1_received)
            .fold(None, |m: Option<f64>, t| Some(m.map_or(t, |m| m.max(t))));
        match policy.classify(last, now).0 {
            "unknown" => never += 1,
            "future" => ahead += 1,
            "fresh" => fresh += 1,
            _ => stale += 1,
        }
    }
    let by_freshness = tally(
        authorities
            .iter()
            .filter(|a| !a.retired())
            .map(|a| policy.classify(time_of(&a.observed_at), now).0.to_string()),
    );
    json!({"contract_version":CONTRACT,"effective_scope":effective_scope(scope),"revision":revision,
        "as_of":now,"freshness_policy":policy.declared(),
        "devices":{"enrolled":devices.len(),"revoked":revoked,"expected_to_check_in":expected,
            "checked_in_fresh":fresh,"checked_in_stale":stale,"checked_in_clock_ahead":ahead,"never_checked_in":never},
        "sources":{"total":authorities.len(),"retired":authorities.iter().filter(|a| a.retired()).count(),"by_observation_freshness":by_freshness,
            "by_inventory_state":tally(authorities.iter().map(|a| a.state("inventory"))),
            "by_advisory_state":tally(authorities.iter().map(|a| a.state("advisories"))),
            "with_failed_inputs":authorities.iter().filter(|a| a.inputs_failed > 0).count(),
            "from_revoked_devices":authorities.iter().filter(|a| a.revoked).count()},
        "data_notice":untrusted::NOTICE,"counting":{"devices":"enrolled devices in the authorized view; revoked devices are excluded from the check-in counts",
            "sources":"authorities (device, scope, source) with at least one delivery, in the authorized view, including those of revoked devices (each source row says which)",
            "checkin":"time of the last accepted delivery; it is a check-in, not an observation time"}})
}
