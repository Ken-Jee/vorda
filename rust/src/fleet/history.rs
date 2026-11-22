//! What changed, from the assessment history the hub retains, and evidence detail by reference.
//! Both reach v2 rows only through the grant's device set and sources. Everything an endpoint
//! wrote as text is untrusted data: it is returned inside `quoted` fields with its length and
//! truncation stated, never as free text a reader could take for an instruction.
use super::auth::AuthorizedScope;
use super::coverage::{
    check_sources, digest, empty_response, page_rendered, snapshot, sorted, Authority,
    FreshnessPolicy, Narrow, Snapshot,
};
use super::query::{
    check_sizes, effective_scope, has_v2, not_found, page_limit, readonly, visible, DeviceFilter,
    PageRequest, CONTRACT,
};
use super::untrusted::{self, ident, ident_str, moment, quoted, MAX_QUOTED_CHARS};
use crate::link::change_log::{self, replay, Assessment, Entry, Summary};
use crate::link::native::MAX_ASSESSMENTS_PER_AUTHORITY;
use crate::link::storage::Hub;
use crate::{Error, Result};
use rusqlite::params_from_iter;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Distinct windows named as unavailable in one answer; the total is stated.
const MAX_WINDOWS_LISTED: usize = 50;
/// Records of one assessment an evidence answer lists; the total is stated and the cut flagged. The
/// cut is by count, not by size: it keeps the answer within the response bound for an honest
/// device, whose records are small, but a device can make its own evidence too large to read (the
/// answer then fails with `response_limit`) by sending records with very long names or versions.
const MAX_EVIDENCE_RECORDS: usize = 100;
/// The start of the comparison window.
#[derive(Debug, Clone, Copy)]
pub enum Since {
    /// Every retained change, from the first retained assessment.
    Start,
    /// Changes introduced by assessments the hub received after this time (epoch seconds).
    Time(f64),
}
impl Since {
    fn label(&self) -> Value {
        match self {
            Since::Start => json!("start"),
            Since::Time(t) => json!(t),
        }
    }
}

#[derive(Default)]
pub struct ChangeFilter {
    pub sites: Vec<String>,
    pub devices: Vec<String>,
    pub sources: Vec<String>,
}

/// Authorities named in an answer, with the total and the cut stated.
#[derive(Default)]
struct Named {
    total: usize,
    listed: Vec<Value>,
}
impl Named {
    fn push(&mut self, entry: Value) {
        self.total += 1;
        if self.listed.len() < MAX_WINDOWS_LISTED {
            self.listed.push(entry);
        }
    }
}

/// What the retained history can say about a window, authority by authority.
#[derive(Default)]
struct Window {
    available: usize,
    assessed: usize,
    late: usize,
    unavailable: Named,
    full: Named,
}
impl Window {
    fn notes(&self, since: &Since) -> Value {
        json!({
            "window":{"since":since.label(),"available":self.available,
                "assessed_in_window":self.assessed,
                "unavailable_total":self.unavailable.total,
                "unavailable_truncated":self.unavailable.total > self.unavailable.listed.len(),
                "unavailable":self.unavailable.listed,
                "at_retention_limit_total":self.full.total,
                "at_retention_limit_truncated":self.full.total > self.full.listed.len(),
                "at_retention_limit":self.full.listed},
            "retention":{"assessments_per_authority":MAX_ASSESSMENTS_PER_AUTHORITY,
                "pruning":"none: an authority at the limit refuses new assessments instead of dropping history",
                "at_retention_limit":"an authority listed under window.at_retention_limit has stopped receiving assessments: nothing after its last_received is known",
                "late_assessments":self.late,
                "late_assessments_note":"assessments whose revision arrived below the frontier are compared in capture order; their rows carry late:true, and rows are ordered and windowed by receipt time, so a since-window can show a late row alone"},
            "reading":"a change is a difference between two retained inventory assessments; it does not prove what is deployed, and a failed or partial collection resolves nothing"})
    }
}

/// An authority named in `Window`: where it is and why.
fn named(a: &Authority, reason: &str) -> Value {
    json!({"device":a.device,"org":a.org,"site":a.site,"revoked":a.revoked,
        "scope":ident_str(&a.scope),"source":ident_str(&a.source),"reason":reason})
}

/// Whether an assessment received at `at` falls inside the window; one with no readable receipt
/// time is in the walk from the start only.
fn inside(since: &Since, at: Option<f64>) -> bool {
    match (since, at) {
        (Since::Start, _) => true,
        (Since::Time(t), Some(at)) => at > *t,
        (Since::Time(_), None) => false,
    }
}

/// A change and the authority (index into the view) it belongs to, kept compact until its page is
/// rendered.
struct Event {
    authority: usize,
    entry: Entry,
}
fn render(a: &Authority, e: &Entry) -> Value {
    let p = &e.package;
    json!({"kind":e.kind,"reason":e.reason,"device":a.device,"org":a.org,"site":a.site,"revoked":a.revoked,
        "scope":ident_str(&a.scope),"source":ident_str(&a.source),"component_id":ident_str(&e.component_id),
        "location_ref":ident(&e.location_ref),
        "package":{"ecosystem":quoted(&p["ecosystem"]),"namespace":quoted(&p["namespace"]),"name":quoted(&p["name"]),"version":quoted(&p["version"])},
        "previous_version":e.previous_version.as_ref().map_or(Value::Null, quoted),
        "assessment_revision":e.revision,"previous_assessment_revision":e.previous_revision,
        "received_at":e.received,"late":e.late,"observed_at":moment(&e.observed_at),
        "evidence":ident_str(&format!("{}/{}", a.device, e.evidence))})
}

/// What changed in the grant's evidence since a point in time, from the retained assessment
/// history. An authority whose retained history cannot answer the window is named, not guessed at,
/// and so is one that has reached the retention limit: the hub refuses its newer assessments, so a
/// window that reaches past its last receipt may be missing changes. `now` is the service's
/// clock: `since` must not lie beyond it and a cursor expires an hour after the second its walk
/// began; the transport passes the server's time, never one from a request.
pub fn fleet_changes(
    hub: &Hub,
    scope: &AuthorizedScope,
    filter: &ChangeFilter,
    since: &Since,
    page: &PageRequest,
    now: f64,
) -> Result<Value> {
    scope.check(hub)?;
    check_sizes(&filter.sites, &filter.devices)?;
    check_sources(&filter.sources)?;
    if let Since::Time(t) = since {
        if !t.is_finite() || *t < 0.0 || *t > now {
            return Err(Error::rejected(400, "since must be a past time"));
        }
    }
    let policy = FreshnessPolicy::default();
    let devices = DeviceFilter {
        sites: filter.sites.clone(),
        devices: filter.devices.clone(),
    };
    let query = digest(
        json!({"kind":"changes","sites":sorted(&filter.sites),"devices":sorted(&filter.devices),
        "sources":sorted(&filter.sources),"since":since.label()}),
    );
    let narrow = Narrow {
        devices: &devices,
        sources: &filter.sources,
    };
    let Some(snap) = snapshot(hub, scope, narrow, "changes", &query, page, now)? else {
        let mut empty = empty_response(scope, "changes", &policy, now);
        let notes = Window::default().notes(since);
        for (k, v) in notes.as_object().into_iter().flatten() {
            empty[k] = v.clone();
        }
        return Ok(empty);
    };
    let db = &snap.db;
    let names: Vec<&str> = snap
        .authorities
        .iter()
        .map(|a| a.authority.as_str())
        .collect();
    // A hub with a log, whose saved states all follow today's replay rules and whose receipt
    // index sorts like the replay, answers from the log. Any other hub, and a log that cannot
    // speak for every authority in the view, is replayed: the same answer, found the slow way.
    let logged = if change_log::exists(db)? && change_log::index_orders_like_replay(db)? {
        change_log::summaries(db, &names)?
    } else {
        None
    };
    let replayed = if logged.is_some() {
        vec![]
    } else {
        // Every retained row is read inside the snapshot, then the read transaction ends: the
        // parse and the replay that follow take seconds on a large hub, and a rollback-journal
        // database cannot commit an admission while any reader holds its lock.
        let raw = retained_rows(db, &names)?;
        db.execute_batch("ROLLBACK")?;
        retained(raw)?
    };
    let summaries = logged
        .clone()
        .unwrap_or_else(|| replayed.iter().map(|(s, _)| s.clone()).collect());
    let (window, available) = window_of(&snap, since, &summaries);
    let (total, events) = if logged.is_some() {
        let listed: Vec<&str> = available.iter().map(|&i| names[i]).collect();
        let after = match since {
            Since::Start => None,
            Since::Time(t) => Some(*t),
        };
        let limit = page_limit(page)?;
        let (total, rows) = change_log::page(db, &listed, after, snap.offset, limit)?;
        let index: HashMap<&str, usize> = names.iter().enumerate().map(|(i, n)| (*n, i)).collect();
        let events = rows
            .into_iter()
            .map(|(authority, entry)| Event {
                authority: index[authority.as_str()],
                entry,
            })
            .collect();
        (total as usize, events)
    } else {
        let mut events: Vec<Event> = vec![];
        for &index in &available {
            let published = &replayed[index].1;
            for (n, change) in replay(published) {
                let assessment = &published[n];
                if !inside(since, assessment.received) {
                    continue;
                }
                let previous = n.checked_sub(1).map(|p| published[p].revision);
                events.push(Event {
                    authority: index,
                    entry: Entry::replayed(&change, assessment, previous),
                });
            }
        }
        // Oldest first; an assessment with no usable receipt time sorts first. The sort is
        // stable, so changes that share a time keep their order: by authority, then as the
        // replay found them.
        events.sort_by(|x, y| {
            x.entry
                .received
                .unwrap_or(0.0)
                .total_cmp(&y.entry.received.unwrap_or(0.0))
        });
        (events.len(), events)
    };
    // A page of the log holds only the rows from the cursor's offset on.
    let first = if logged.is_some() {
        snap.offset as usize
    } else {
        0
    };
    let mut short = false;
    let answer = page_rendered(
        &snap,
        scope,
        page,
        total,
        |i| {
            events.get(i - first).map_or_else(
                || {
                    short = true;
                    Value::Null
                },
                |e| render(&snap.authorities[e.authority], &e.entry),
            )
        },
        &policy,
        window.notes(since),
    )?;
    // Fewer rows than the count promised would otherwise leave `null` rows in the page.
    if short {
        return Err(Error::new("changes page came up short of its count"));
    }
    Ok(answer)
}

/// One retained assessment as stored: revision, receipt, result, evidence id and artifact bytes.
type StoredAssessment = (i64, String, String, String, Vec<u8>);

/// Each authority's stored assessments, in the order asked. Reads only; nothing is parsed here,
/// so the read transaction that holds the snapshot can end right after.
fn retained_rows(db: &rusqlite::Connection, names: &[&str]) -> Result<Vec<Vec<StoredAssessment>>> {
    names
        .iter()
        .map(|authority| {
            Ok(db
                .prepare_cached("SELECT revision,received,result,evidence,artifact FROM v2_assessments WHERE authority=? ORDER BY revision")?
                .query_map([authority], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?)
        })
        .collect()
}

/// Each authority's retained assessments with their artifacts and its summary, for a hub that has
/// to replay them.
fn retained(stored: Vec<Vec<StoredAssessment>>) -> Result<Vec<(Summary, Vec<Assessment>)>> {
    stored
        .into_iter()
        .map(|rows| {
            let mut published = Vec::with_capacity(rows.len());
            for (revision, received, result, evidence, raw) in rows {
                published.push(Assessment {
                    late: result != "published",
                    revision,
                    received: received.parse::<f64>().ok().filter(|t| t.is_finite()),
                    evidence,
                    artifact: change_log::replayable(&raw)?,
                });
            }
            Ok((Summary::of(&published), published))
        })
        .collect()
}

/// What the retained history can say about the window, and which authorities (by index into the
/// view) can answer it. Without the whole chain from revision 1, what came before cannot be
/// known, so nothing after it is called new, changed or resolved.
fn window_of(snap: &Snapshot, since: &Since, summaries: &[Summary]) -> (Window, Vec<usize>) {
    let mut window = Window::default();
    let mut available = vec![];
    for (index, (a, s)) in snap.authorities.iter().zip(summaries).enumerate() {
        window.late += s.late as usize;
        // Admission refuses every assessment past the limit and nothing prunes, so this
        // authority's history ends at its last receipt however long the window is.
        if s.assessments as usize >= MAX_ASSESSMENTS_PER_AUTHORITY {
            let mut entry = named(a, "retention_limit_reached_newer_assessments_refused");
            entry["last_received"] = json!(s.max_received);
            window.full.push(entry);
        }
        let why = match (s.first_revision, s.last_revision) {
            (None, _) | (_, None) => Some("no_retained_assessments"),
            (Some(first), _) if first != 1 => Some("history_before_the_oldest_retained_assessment"),
            (_, Some(last)) if last != s.assessments => Some("retained_history_has_a_gap"),
            _ => None,
        };
        if let Some(reason) = why {
            window.unavailable.push(named(a, reason));
            continue;
        }
        window.available += 1;
        available.push(index);
        let assessed = match since {
            Since::Start => true,
            Since::Time(t) => s.max_received.is_some_and(|m| m > *t),
        };
        window.assessed += usize::from(assessed);
    }
    (window, available)
}

/// One retained assessment as evidence, found by the reference other answers carry. A reference
/// outside the grant answers exactly like one that does not exist. The retained lockfile body and
/// local paths are not returned; text the endpoint wrote comes back as quoted, bounded data. At most
/// `MAX_EVIDENCE_RECORDS` records are returned, with their total and whether the list was cut (the
/// inventory lists every current package, a page at a time).
pub fn fleet_evidence(hub: &Hub, scope: &AuthorizedScope, reference: &str) -> Result<Value> {
    scope.check(hub)?;
    let Some((cond, mut args)) = visible(scope, &DeviceFilter::default()) else {
        return Err(not_found());
    };
    let db = readonly(hub)?;
    if !has_v2(&db)? {
        return Err(not_found());
    }
    // A reference is `<device>/<evidence id>`, so the detail can only be of the device it names.
    let (named_device, evidence_id) = reference.split_once('/').ok_or_else(not_found)?;
    let mut sql = format!(
        "SELECT s.authority,a.source,s.revision,s.received,s.result,s.digest,s.artifact,d.id,d.org,d.site,d.revoked \
         FROM v2_assessments s JOIN v2_authorities a ON a.authority=s.authority \
         JOIN devices d ON json_extract(s.authority,'$[2]')=d.id AND json_extract(s.authority,'$[0]')=d.org \
         AND json_extract(s.authority,'$[1]')=d.site WHERE s.evidence=? AND d.id=? AND {cond}"
    );
    let mut all = vec![evidence_id.to_string(), named_device.to_string()];
    all.append(&mut args);
    if let Some(sources) = scope.sources() {
        sql += &format!(" AND a.source IN ({})", vec!["?"; sources.len()].join(","));
        all.extend(sources.iter().cloned());
    }
    sql += " ORDER BY s.authority LIMIT 2";
    let mut rows = db
        .prepare(&sql)?
        .query_map(params_from_iter(&all), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, bool>(10)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // Two assessments of one device under one id would be ambiguous: refuse rather than choose.
    let row = match (rows.pop(), rows.is_empty()) {
        (Some(row), true) => row,
        _ => return Err(not_found()),
    };
    let (
        authority,
        source,
        revision,
        received,
        result,
        assessment_digest,
        raw,
        device,
        org,
        site,
        revoked,
    ) = row;
    let artifact: Value = serde_json::from_slice(&raw)?;
    let tuple: Value = serde_json::from_str(&authority)?;
    let records = artifact["records"].as_array().cloned().unwrap_or_default();
    let shown: Vec<Value> = records
        .iter()
        .take(MAX_EVIDENCE_RECORDS)
        .map(|r| {
            let p = &r["package"];
            json!({"record_id":ident(&r["record_id"]),"component_id":ident(&r["component_id"]),"location_ref":ident(&r["location_ref"]),
                "package":{"ecosystem":quoted(&p["ecosystem"]),"namespace":quoted(&p["namespace"]),
                    "name":quoted(&p["name"]),"version":quoted(&p["version"])}})
        })
        .collect();
    let inputs: Vec<Value> = artifact["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, i)| {
            // The digest and size of the withheld source file would let a reader confirm a guess
            // at its contents, so neither is returned.
            json!({"index":index,"state":if i["error"].is_null() {"complete"} else {"failed"},
                "error":quoted(&i["error"]),"body":"withheld","path":"withheld"})
        })
        .collect();
    Ok(
        json!({"contract_version":CONTRACT,"effective_scope":effective_scope(scope),
        "evidence":{"reference":ident_str(reference),"class":"inventory_projection",
            "device":device,"org":org,"site":site,"revoked":revoked,"scope":ident(&tuple[4]),"source":ident_str(&source),
            "assessment_revision":revision,"result":result,"assessment_digest":assessment_digest,
            "received_at":received.parse::<f64>().ok(),
            "observed_at":moment(&artifact["times"]["observed_at"]),
            "completed_at":moment(&artifact["times"]["assessment_completed_at"]),
            "advisory_checked_at":moment(&artifact["times"]["advisory_checked_at"]),
            "producer":{"name":quoted(&artifact["producer"]["name"]),"source_pin":quoted(&artifact["producer"]["source_pin"])},
            "coverage":evidence_coverage(&artifact["coverage"]),"inputs":inputs,
            "records":shown,
            "records_total":records.len(),"records_truncated":records.len() > MAX_EVIDENCE_RECORDS,"max_quoted_chars":MAX_QUOTED_CHARS},
        "data_notice":untrusted::NOTICE}),
    )
}
/// A label the endpoint reported (osv, kev, epss): an identifier, a flag, or nothing.
fn label(v: &Value) -> Value {
    match v {
        Value::String(_) => ident(v),
        Value::Bool(_) => v.clone(),
        _ => Value::Null,
    }
}
fn evidence_coverage(c: &Value) -> Value {
    json!({"inventory":untrusted::coverage(&c["inventory"]),"advisories":untrusted::coverage(&c["advisories"]),
        "osv":label(&c["osv"]),"kev":label(&c["kev"]),"epss":label(&c["epss"]),
        "global_clean":c["global_clean"].as_bool(),"fix_verified":c["fix_verified"].as_bool()})
}
