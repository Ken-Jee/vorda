use super::auth::AuthorizedScope;
use super::cursor::{self, Binding};
use super::untrusted::{ident, ident_str, quoted, state, NOTICE};
use crate::link::storage::Hub;
use crate::{Error, Result};
use rusqlite::{params_from_iter, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Findings shown in one device detail. The rest are counted in `finding_count`, not returned.
pub const MAX_DETAIL_FINDINGS: usize = 100;
/// Coverage scopes shown per device, as many as one batch may carry. The rest are counted in
/// `coverage_count`, not returned.
pub const MAX_COVERAGE: usize = 128;
/// Longest filter lists a query accepts; longer ones are refused, not truncated.
pub const MAX_FILTER_SITES: usize = 64;
pub const MAX_FILTER_DEVICES: usize = 256;

/// A caller's narrowing. It can only shrink the grant: a name outside the grant matches nothing.
#[derive(Default)]
pub struct DeviceFilter {
    pub sites: Vec<String>,
    pub devices: Vec<String>,
}

/// Longest a read connection may run before sqlite interrupts it. The caller sees the same `503`
/// as for any other storage failure.
const READ_BUDGET: Duration = Duration::from_secs(5);

/// Queries never write: they open the hub read-only.
pub(super) fn readonly(hub: &Hub) -> Result<Connection> {
    readonly_with(hub, READ_BUDGET)
}
/// `readonly` with the budget given, so tests need not wait the real one out. Any statement on
/// the connection still running `budget` after it opened is interrupted.
fn readonly_with(hub: &Hub, budget: Duration) -> Result<Connection> {
    let mut db = Connection::open_with_flags(&hub.database.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::from_millis(200))?;
    let deadline = Instant::now() + budget;
    db.progress_handler(1000, Some(move || Instant::now() >= deadline))?;
    Ok(db)
}
pub(super) fn not_found() -> Error {
    // The same answer for an id that does not exist and one the grant does not cover.
    Error::rejected(404, "not found")
}
/// `(sql condition, parameters)` for the devices the grant, intersected with `filter`, covers. The
/// grant is the only source of the allowed sets; the filter can only remove from them. `None` is
/// an empty intersection: nothing to query.
pub(super) fn visible(
    scope: &AuthorizedScope,
    filter: &DeviceFilter,
) -> Option<(String, Vec<String>)> {
    let narrow = |granted: &BTreeSet<String>, asked: &[String]| -> BTreeSet<String> {
        if asked.is_empty() {
            granted.clone()
        } else {
            asked
                .iter()
                .filter(|v| granted.contains(*v))
                .cloned()
                .collect()
        }
    };
    let sites: Vec<_> = scope
        .sites()
        .iter()
        .filter(|s| filter.sites.is_empty() || filter.sites.contains(&s.site))
        .collect();
    let devices = match scope.devices() {
        Some(granted) => Some(narrow(granted, &filter.devices)),
        None if filter.devices.is_empty() => None,
        None => Some(filter.devices.iter().cloned().collect()),
    };
    if sites.is_empty() || devices.as_ref().is_some_and(|d| d.is_empty()) {
        return None;
    }
    let mut sql = format!(
        "({})",
        vec!["(d.org=? AND d.site=?)"; sites.len()].join(" OR ")
    );
    let mut args: Vec<String> = sites
        .into_iter()
        .flat_map(|s| [s.org.clone(), s.site.clone()])
        .collect();
    if let Some(devices) = devices {
        sql += &format!(" AND d.id IN ({})", vec!["?"; devices.len()].join(","));
        args.extend(devices);
    }
    if let Some(sources) = scope.sources() {
        // Only devices that report through a granted source are visible at all.
        sql += &format!(
            " AND EXISTS (SELECT 1 FROM v2_authorities a WHERE json_extract(a.authority,'$[2]')=d.id AND json_extract(a.authority,'$[0]')=d.org AND json_extract(a.authority,'$[1]')=d.site AND a.source IN ({}))",
            vec!["?"; sources.len()].join(",")
        );
        args.extend(sources.iter().cloned());
    }
    Some((sql, args))
}
pub(super) fn device_row(
    db: &Connection,
    id: &str,
    org: &str,
    site: &str,
    revoked: bool,
    received: Option<f64>,
    legacy: bool,
) -> Result<Value> {
    if !legacy {
        return Ok(
            json!({"device":id,"org":org,"site":site,"revoked":revoked,"received":null,"finding_count":null,"coverage":[]}),
        );
    }
    // Scope names are endpoint text, so coverage is a list rather than a map keyed by them.
    let coverage: Vec<Value> = db
        .prepare(&format!(
            "SELECT scope,state FROM coverage WHERE device=? ORDER BY scope LIMIT {MAX_COVERAGE}"
        ))?
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .map(|row| {
            let (scope, st) = row?;
            Ok(json!({"scope":ident_str(&scope),"state":state(&st)}))
        })
        .collect::<Result<_>>()?;
    let count = |table: &str| -> Result<i64> {
        Ok(db.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE device=?"),
            [id],
            |r| r.get(0),
        )?)
    };
    let (findings, covered) = (count("findings")?, count("coverage")?);
    Ok(
        json!({"device":id,"org":org,"site":site,"revoked":revoked,"received":received,
        "finding_count":findings,"coverage_count":covered,
        "coverage_truncated":covered > coverage.len() as i64,"coverage":coverage}),
    )
}

pub use super::coverage::visible_devices;

/// One visible device with up to `MAX_DETAIL_FINDINGS` of its active findings, each reduced to its
/// key, scope, advisory, ecosystem, name and version (`source` and `location` are not returned).
/// An id outside the grant gets the same answer as an id that does not exist.
pub fn device_detail(hub: &Hub, scope: &AuthorizedScope, device: &str) -> Result<Value> {
    scope.check(hub)?;
    let filter = DeviceFilter {
        sites: vec![],
        devices: vec![device.to_string()],
    };
    let (cond, args) = visible(scope, &filter).ok_or_else(not_found)?;
    let db = readonly(hub)?;
    if sources_unavailable(&db, scope)? {
        return Err(not_found());
    }
    let tx = db.unchecked_transaction()?;
    let (org, site, revoked, received) = tx
        .query_row(
            &format!("SELECT d.org,d.site,d.revoked,d.received FROM devices d WHERE {cond}"),
            params_from_iter(&args),
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, Option<f64>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(not_found)?;
    let legacy = legacy_visible(scope);
    let mut row = device_row(&tx, device, &org, &site, revoked, received, legacy)?;
    if !legacy {
        row["findings"] = json!([]);
        row["findings_truncated"] = json!(false);
        row["data_notice"] = json!(NOTICE);
        return Ok(row);
    }
    let findings = tx
        .prepare(&format!(
            "SELECT payload FROM findings WHERE device=? ORDER BY key LIMIT {MAX_DETAIL_FINDINGS}"
        ))?
        .query_map([device], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .map(|raw| {
            let f: Value = serde_json::from_slice(raw)?;
            Ok(json!({"key":ident(&f["key"]),"scope":ident(&f["scope"]),"advisory":quoted(&f["advisory"]),"ecosystem":quoted(&f["ecosystem"]),"name":quoted(&f["name"]),"version":quoted(&f["version"])}))
        })
        .collect::<Result<Vec<_>>>()?;
    row["findings_truncated"] =
        json!(row["finding_count"].as_i64().unwrap_or(0) > findings.len() as i64);
    row["findings"] = json!(findings);
    row["data_notice"] = json!(NOTICE);
    Ok(row)
}

const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 100;
/// Serialized finding rows per page. A page ends early at the budget (never mid-row, never empty)
/// and the cursor continues from there, so nothing is dropped.
pub(super) const PAGE_BYTES: usize = 64 * 1024;
/// What the rest of a response (names, counts, the cursor) may add to the rows and scope.
pub(super) const ENVELOPE_BYTES: usize = 1024;
pub(super) const CONTRACT: &str = "m3-fleet-1";
/// Longest advisory, package name or source filter value, like the list bounds above.
pub(super) const MAX_FILTER_TEXT: usize = 256;
pub(super) const MAX_FILTER_SOURCES: usize = 64;

/// Rows wanted: 50 when absent, at most 100, at least 1.
pub(super) fn page_limit(page: &PageRequest) -> Result<usize> {
    match page.limit.unwrap_or(DEFAULT_PAGE) {
        0 => Err(Error::rejected(400, "limit must be at least 1")),
        n => Ok(n.min(MAX_PAGE)),
    }
}
/// Filter lists are bounded like the grant they narrow.
pub(super) fn check_sizes(sites: &[String], devices: &[String]) -> Result<()> {
    if sites.len() > MAX_FILTER_SITES || devices.len() > MAX_FILTER_DEVICES {
        return Err(Error::rejected(400, "too many filter values"));
    }
    Ok(())
}
/// Version 1 evidence carries no source, so a source-restricted grant sees none of it.
pub(super) fn legacy_visible(scope: &AuthorizedScope) -> bool {
    scope.sources().is_none()
}
/// A grant that names sources needs the v2 tables to say what it covers; on a hub rolled back to
/// version 1 it covers nothing, which is the empty view rather than an SQL error.
pub(super) fn sources_unavailable(db: &Connection, scope: &AuthorizedScope) -> Result<bool> {
    Ok(scope.sources().is_some() && !has_v2(db)?)
}
/// Version 1 hubs have no v2 tables; every v2 view of one is empty.
pub(super) fn has_v2(db: &Connection) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_authorities')",
        [],
        |r| r.get(0),
    )?)
}

/// Narrowing for the findings list. Like every filter it can only remove from the grant.
#[derive(Default)]
pub struct FindingFilter {
    pub sites: Vec<String>,
    pub devices: Vec<String>,
    /// Exact advisory alias.
    pub advisory: Option<String>,
    /// Exact package name.
    pub name: Option<String>,
}
#[derive(Default)]
pub struct PageRequest<'a> {
    /// Rows wanted: 50 when absent, at most 100, at least 1.
    pub limit: Option<usize>,
    /// The `next_cursor` of the previous page of the same query.
    pub cursor: Option<&'a str>,
}

/// What the grant covers, stated in every response.
pub(super) fn effective_scope(scope: &AuthorizedScope) -> Value {
    json!({
        "sites": scope.sites().iter().map(|s| json!({"org":s.org,"site":s.site})).collect::<Vec<_>>(),
        "devices": scope.devices().map_or(json!("all"), |d| json!(d.len())),
        "sources": scope.sources().map_or(json!("all"), |s| json!(s)),
    })
}
/// The query as a cursor sees it: filters in a canonical order, so equal queries bind equally.
fn canonical_query(filter: &FindingFilter) -> String {
    fn set(v: &[String]) -> BTreeSet<&String> {
        v.iter().collect()
    }
    let q = json!({"sites":set(&filter.sites),"devices":set(&filter.devices),"advisory":filter.advisory,"name":filter.name});
    format!("{:x}", Sha256::digest(q.to_string().as_bytes()))
}

/// Active findings the reader may see, one page at a time. The grant is intersected with the
/// filters before anything is counted or paged; `total` is that view's exact size. `now` is the
/// service's clock: a cursor expires an hour after the second its walk began, and the transport
/// passes the server's time, never one taken from a request.
pub fn visible_findings(
    hub: &Hub,
    scope: &AuthorizedScope,
    filter: &FindingFilter,
    page: &PageRequest,
    now: f64,
) -> Result<Value> {
    scope.check(hub)?;
    check_sizes(&filter.sites, &filter.devices)?;
    if [&filter.advisory, &filter.name].iter().any(|v| {
        v.as_ref()
            .is_some_and(|v| v.chars().count() > MAX_FILTER_TEXT)
    }) {
        return Err(Error::rejected(400, "too many or too long filter values"));
    }
    let limit = page_limit(page)?;
    let devices = DeviceFilter {
        sites: filter.sites.clone(),
        devices: filter.devices.clone(),
    };
    let effective = effective_scope(scope);
    let Some((cond, mut args)) = visible(scope, &devices).filter(|_| legacy_visible(scope)) else {
        // No cursor can have been issued for a view that is empty.
        if page.cursor.is_some() {
            return Err(cursor::invalid());
        }
        return Ok(
            json!({"contract_version":CONTRACT,"effective_scope":effective,"revision":"0","as_of":null,
            "total":0,"limit":limit,"page_end":"last","findings":[],"next_cursor":null,"data_notice":NOTICE}),
        );
    };
    let device_args = args.len();
    let mut extra = String::new();
    for (field, wanted) in [("advisory", &filter.advisory), ("name", &filter.name)] {
        if let Some(wanted) = wanted {
            extra += &format!(" AND json_extract(CAST(f.payload AS TEXT),'$.{field}')=?");
            args.push(wanted.clone());
        }
    }
    let db = readonly(hub)?;
    // One read transaction, so the revision, the count and the rows describe the same snapshot.
    let tx = db.unchecked_transaction()?;
    // The revision is a digest of the view's own rows, so it moves when anything in the view moves
    // (every accepted batch changes a sequence and a receipt time) and never for another site's
    // evidence. It is a digest, not arithmetic: a device may choose any positive sequence.
    let mut hash = Sha256::new();
    let mut as_of: Option<f64> = None;
    for (id, sequence, revoked, received, findings) in tx
        .prepare(&format!("SELECT d.id,d.sequence,d.revoked,d.received,(SELECT COUNT(*) FROM findings WHERE device=d.id) FROM devices d WHERE {cond} ORDER BY d.id"))?
        .query_map(params_from_iter(&args[..device_args]), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<f64>>(3)?, r.get::<_, i64>(4)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    {
        hash.update(json!([id, sequence, revoked, received, findings]).to_string().as_bytes());
        as_of = match (as_of, received) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }
    let revision = format!("{:x}", hash.finalize());
    let query = canonical_query(filter);
    let grant = scope.grant_digest();
    let key = scope.cursor_key(hub)?;
    let binding = Binding {
        reader: scope.reader(),
        grant: &grant,
        query: &query,
        revision: &revision,
    };
    let (offset, issued) = match page.cursor {
        Some(c) => cursor::open(&key, &binding, c, now)?,
        None => (0, now as u64),
    };
    let from = "FROM findings f JOIN devices d ON d.id=f.device";
    let total: i64 = tx.query_row(
        &format!("SELECT COUNT(*) {from} WHERE {cond}{extra}"),
        params_from_iter(&args),
        |r| r.get(0),
    )?;
    if offset > total as u64 {
        return Err(cursor::invalid());
    }
    let rows = tx
        .prepare(&format!(
            "SELECT d.id,d.org,d.site,f.payload {from} WHERE {cond}{extra} ORDER BY d.id,f.key LIMIT {limit} OFFSET {offset}"
        ))?
        .query_map(params_from_iter(&args), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Vec<u8>>(3)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut findings = vec![];
    let mut bytes = effective.to_string().len() + ENVELOPE_BYTES;
    let mut cut_by_bytes = false;
    for (device, org, site, raw) in rows {
        let f: Value = serde_json::from_slice(&raw)?;
        let row = json!({"device":device,"org":org,"site":site,"key":ident(&f["key"]),"scope":ident(&f["scope"]),"advisory":quoted(&f["advisory"]),"ecosystem":quoted(&f["ecosystem"]),"name":quoted(&f["name"]),"version":quoted(&f["version"])});
        bytes += row.to_string().len();
        if bytes > PAGE_BYTES && !findings.is_empty() {
            cut_by_bytes = true;
            break;
        }
        findings.push(row);
    }
    let end = offset + findings.len() as u64;
    let next = (end < total as u64).then(|| cursor::issue(&key, &binding, end, issued));
    // `next_cursor` is the only signal that more exists; `page_end` says why this page stopped.
    let page_end = match (&next, cut_by_bytes) {
        (None, _) => "last",
        (_, true) => "bytes",
        _ => "limit",
    };
    let mut response = json!({"contract_version":CONTRACT,"effective_scope":effective,"revision":revision,"as_of":as_of,
        "total":total,"limit":limit,"page_end":page_end,"findings":findings,"next_cursor":next,"data_notice":NOTICE});
    if filter.advisory.is_some() {
        response["filter_semantics"] = json!({"advisory":"exact match on the stored advisory field; aliases (CVE, GHSA) are not resolved, so a total of 0 does not mean unaffected"});
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::ErrorCode;

    const SLOW: &str = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 50000000) SELECT count(*) FROM n";

    fn hub_in(dir: &tempfile::TempDir) -> Hub {
        Hub::open(&dir.path().join("hub.db")).unwrap()
    }

    #[test]
    fn a_read_connection_is_interrupted_past_its_budget_and_a_short_read_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let hub = hub_in(&dir);
        let db = readonly_with(&hub, Duration::from_millis(50)).unwrap();
        let started = Instant::now();
        let slow = db.query_row(SLOW, [], |r| r.get::<_, i64>(0));
        assert!(
            matches!(&slow, Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::OperationInterrupted),
            "expected an interrupt, got {slow:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        // The connection the real path opens is unaffected for a normal read.
        let db = readonly(&hub).unwrap();
        assert_eq!(
            db.query_row("SELECT 7", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            7
        );
    }
}
