//! One finding, opened by the `key` that `findings` shows: every occurrence the grant covers, each
//! with its device and site, the version 1 receipt and freshness of the device's latest batch, the
//! coverage that batch declared for the finding's scope, and the native inventory rows on that
//! device that hold the same package.
//!
//! The join to native inventory is on `(ecosystem, name, version)` within one device. Advisory
//! aliases are never used. The v1 key is a digest of the scan scope and the finding key, so one
//! finding on two devices shares a key only where the devices name their scopes alike.
//!
//! A key the grant does not cover answers exactly like one that does not exist.
use super::auth::AuthorizedScope;
use super::coverage::{digest, inventory_row, snapshot, FreshnessPolicy, Narrow};
use super::query::{
    effective_scope, legacy_visible, not_found, readonly, visible, DeviceFilter, PageRequest,
    CONTRACT, MAX_FILTER_TEXT,
};
use super::untrusted::{self, ident, ident_str, quoted, NOTICE};
use crate::link::storage::Hub;
use crate::{Error, Result};
use rusqlite::{params_from_iter, Connection, OptionalExtension};
use serde_json::{json, Value};

/// Occurrences shown. The rest are counted in `occurrences_total`, not returned.
pub const MAX_OCCURRENCES: usize = 50;
/// Native rows shown per occurrence. The rest are counted in `matches_total`.
pub const MAX_MATCHES: usize = 20;
/// Serialized occurrences per answer. An answer ends early at this budget (never empty).
const OCCURRENCE_BYTES: usize = 128 * 1024;

const JOIN: &str = "native inventory rows are matched to the finding on ecosystem, name and version within the same device; advisory aliases are not used, and a version 1 finding never says which source held the package";

/// The stored occurrences of `key` in the devices `cond` selects, and how many there are.
fn occurrences(
    db: &Connection,
    cond: &str,
    args: &[String],
    key: &str,
) -> Result<(Vec<Occurrence>, i64)> {
    let from = format!("FROM findings f JOIN devices d ON d.id=f.device WHERE f.key=? AND {cond}");
    let mut all = vec![key.to_string()];
    all.extend_from_slice(args);
    let total = db.query_row(
        &format!("SELECT COUNT(*) {from}"),
        params_from_iter(&all),
        |r| r.get(0),
    )?;
    let rows = db
        .prepare(&format!(
            "SELECT d.id,d.org,d.site,d.revoked,d.received,f.payload {from} ORDER BY d.id LIMIT {MAX_OCCURRENCES}"
        ))?
        .query_map(params_from_iter(&all), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<f64>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let rows = rows
        .into_iter()
        .map(|(device, org, site, revoked, received, raw)| {
            Ok(Occurrence {
                device,
                org,
                site,
                revoked,
                received,
                finding: serde_json::from_slice(&raw)?,
            })
        })
        .collect::<Result<_>>()?;
    Ok((rows, total))
}

struct Occurrence {
    device: String,
    org: String,
    site: String,
    revoked: bool,
    received: Option<f64>,
    finding: Value,
}

/// The finding stored under `key` on every device the grant covers.
pub fn fleet_finding(
    hub: &Hub,
    scope: &AuthorizedScope,
    key: &str,
    policy: &FreshnessPolicy,
    now: f64,
) -> Result<Value> {
    scope.check(hub)?;
    policy.check()?;
    if key.is_empty() || key.chars().count() > MAX_FILTER_TEXT {
        return Err(Error::rejected(400, "invalid field: key"));
    }
    // Version 1 evidence carries no source, so a source-restricted grant sees none of it.
    if !legacy_visible(scope) {
        return Err(not_found());
    }
    let (cond, args) = visible(scope, &DeviceFilter::default()).ok_or_else(not_found)?;
    let holders: Vec<String> = occurrences(&readonly(hub)?, &cond, &args, key)?
        .0
        .into_iter()
        .map(|o| o.device)
        .collect();
    if holders.is_empty() {
        return Err(not_found());
    }
    // The occurrences are read again inside the snapshot, so they and the native rows are one view.
    let narrow = DeviceFilter {
        sites: vec![],
        devices: holders,
    };
    let query = digest(json!({"kind":"finding","key":key}));
    let narrowed = Narrow {
        devices: &narrow,
        sources: &[],
    };
    let snap = snapshot(
        hub,
        scope,
        narrowed,
        "inventory",
        &query,
        &PageRequest::default(),
        now,
    )?
    .ok_or_else(not_found)?;
    let (found, total) = occurrences(&snap.db, &cond, &args, key)?;
    if found.is_empty() {
        return Err(not_found());
    }
    let mut shown = vec![];
    let mut bytes = 0;
    for o in &found {
        let row = occurrence_row(&snap, o, policy)?;
        bytes += row.to_string().len();
        if bytes > OCCURRENCE_BYTES && !shown.is_empty() {
            break;
        }
        shown.push(row);
    }
    Ok(
        json!({"contract_version":CONTRACT,"effective_scope":effective_scope(scope),
        "as_of":snap.eval_now,"freshness_policy":policy.declared(),
        "key":ident_str(key),"occurrences_total":total,"occurrences_truncated":(shown.len() as i64) < total,
        "occurrences":shown,"join":JOIN,"data_notice":NOTICE}),
    )
}

fn occurrence_row(
    snap: &super::coverage::Snapshot,
    o: &Occurrence,
    policy: &FreshnessPolicy,
) -> Result<Value> {
    let f = &o.finding;
    let (freshness, age) = policy.classify(o.received, snap.eval_now);
    // The batch's own word on the finding's scope; none if it declared nothing for it.
    let declared: Option<String> = snap
        .db
        .query_row(
            "SELECT state FROM coverage WHERE device=? AND scope=?",
            [&o.device, f["scope"].as_str().unwrap_or_default()],
            |r| r.get(0),
        )
        .optional()?;
    let wanted = ["ecosystem", "name", "version"].map(|field| f[field].as_str());
    let mut matches = vec![];
    let mut matches_total = 0;
    for a in snap.authorities.iter().filter(|a| a.device == o.device) {
        for r in &a.records {
            let p = &r["package"];
            let same = ["ecosystem", "name", "version"]
                .iter()
                .zip(wanted)
                .all(|(field, want)| want.is_some() && p[field].as_str() == want);
            if same {
                matches_total += 1;
                if matches.len() < MAX_MATCHES {
                    matches.push(inventory_row(a, r, policy, snap.eval_now));
                }
            }
        }
    }
    Ok(
        json!({"device":o.device,"org":o.org,"site":o.site,"revoked":o.revoked,
        "scope":ident(&f["scope"]),"advisory":quoted(&f["advisory"]),
        "ecosystem":quoted(&f["ecosystem"]),"name":quoted(&f["name"]),"version":quoted(&f["version"]),
        "v1":{"basis":"received_at","received_at":o.received,"age_seconds":age,"freshness":freshness},
        "coverage":declared.map(|s| json!({"scope":ident(&f["scope"]),"state":untrusted::state(&s)})),
        "inventory":{"matches_total":matches_total,"matches_truncated":matches_total > matches.len(),"matches":matches}}),
    )
}
