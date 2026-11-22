//! The change log of schema 3: each authority's replayed change rows, kept beside its retained
//! assessments so a later page can be read instead of replayed.
//!
//! The replay itself lives here and is the only definition of what a change is: `fleet::history`
//! replays with it when a hub has no log, and the hub writes its rows with the same rules. An
//! in-order (published) admission continues from the authority's stored replay state; a late one
//! recomputes that authority from revision 1. Rows carry nothing that depends on who reads them
//! (device, site, revocation), only what the assessments say.
use super::native::{canonical, records_by_input, CURRENT_SEPARATOR};
use crate::{Error, Result};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// One retained assessment of an authority.
pub(crate) struct Assessment {
    pub revision: i64,
    pub received: Option<f64>,
    /// Arrived below the frontier: replayed in capture order, but not the newest state.
    pub late: bool,
    pub evidence: String,
    pub artifact: Value,
}
#[derive(Clone)]
pub(crate) struct Held {
    pub component_id: String,
    pub location_ref: Value,
    pub package: Value,
}
pub(crate) struct Change {
    pub kind: &'static str,
    pub reason: &'static str,
    pub held: Held,
    pub previous_version: Option<Value>,
}

/// The version of `State::apply` and of the rows it produces, stored with each saved state. Raise
/// it whenever a change to the replay rules would make rows or state differ from what an older hub
/// wrote: admission then recomputes the authority and a list falls back to replaying.
///
/// 4 added the `retired` kind. A state saved under 3 describes a history without retirements, for
/// which the two rules give the same rows and state, so `verify_all` still accepts it; admission
/// recomputes such an authority before extending it, and a list replays it.
const REPLAY_VERSION: i64 = 4;
/// The previous version, accepted by `verify_all` only.
const PREVIOUS_REPLAY_VERSION: i64 = 3;

/// What a list of changes says about an authority's whole retained history without reading it:
/// the receipt time and result of an assessment sit behind its artifact in the row, so they
/// cannot be had cheaply from the assessments themselves.
#[derive(Default, Clone, PartialEq, Debug)]
pub(crate) struct Summary {
    pub assessments: i64,
    pub first_revision: Option<i64>,
    pub last_revision: Option<i64>,
    /// Assessments that arrived below the frontier.
    pub late: i64,
    /// The latest receipt time among those that have a readable one.
    pub max_received: Option<f64>,
}
impl Summary {
    fn add(&mut self, a: &Assessment) {
        self.assessments += 1;
        self.first_revision.get_or_insert(a.revision);
        self.last_revision = Some(a.revision);
        self.late += i64::from(a.late);
        self.max_received = match (self.max_received, a.received) {
            (Some(m), Some(r)) if r.total_cmp(&m).is_le() => Some(m),
            (_, Some(r)) => Some(r),
            (m, None) => m,
        };
    }
    /// The summary a saved state carries; `None` when it is not one this release wrote.
    fn from_value(state: &Value) -> Option<Self> {
        Some(Self {
            assessments: state["assessments"].as_i64()?,
            first_revision: state["first_revision"].as_i64(),
            last_revision: state["last_revision"].as_i64(),
            late: state["late"].as_i64()?,
            max_received: state["max_received"].as_f64(),
        })
    }
    /// The summary of assessments in revision order.
    pub(crate) fn of(published: &[Assessment]) -> Self {
        let mut summary = Self::default();
        published.iter().for_each(|a| summary.add(a));
        summary
    }
}

/// What the replay carries from one assessment to the next.
#[derive(Default)]
pub(crate) struct State {
    current: BTreeMap<String, Held>,
    resolved: BTreeSet<String>,
    summary: Summary,
}
impl State {
    /// Replay one assessment as the hub applies it: an input that was read replaces what its path
    /// held, an input that failed to read has no record and so changes nothing. A component leaves
    /// only when a different one is read at the same input, so a partial or failed collection never
    /// resolves anything.
    fn apply(&mut self, a: &Assessment) -> Vec<Change> {
        // A device-sent retirement: every current component leaves, in location order. None is
        // resolved, so a component seen again after the source reopens is new, not reopened.
        if a.artifact["retired"] == true {
            return std::mem::take(&mut self.current)
                .into_values()
                .map(|held| Change {
                    kind: "retired",
                    reason: "source_retired_by_device",
                    held,
                    previous_version: None,
                })
                .collect();
        }
        let mut out = vec![];
        let by_input = records_by_input(&a.artifact);
        for input in a.artifact["inputs"].as_array().into_iter().flatten() {
            let Some(path) = input["path"].as_str() else {
                continue;
            };
            let Some(records) = by_input.get(path) else {
                continue;
            };
            // What the input held is each package at its location; an input read again is
            // replaced as a whole.
            let prefix = format!("{path}{CURRENT_SEPARATOR}");
            let key =
                |r: &Value| format!("{prefix}{}", r["location_ref"].as_str().unwrap_or_default());
            let now: BTreeSet<String> = records.iter().map(|r| key(r)).collect();
            let before: Vec<String> = self
                .current
                .range(prefix.clone()..)
                .take_while(|(k, _)| k.starts_with(&prefix))
                .map(|(k, _)| k.clone())
                .collect();
            let replaced = now.iter().any(|k| !self.current.contains_key(k));
            for gone in before.into_iter().filter(|k| !now.contains(k)) {
                let old = self.current.remove(&gone).expect("a key just listed");
                self.resolved.insert(old.component_id.clone());
                out.push(Change {
                    kind: "resolved",
                    reason: if replaced {
                        "replaced_by_a_different_component_at_the_same_covered_input"
                    } else {
                        "no_longer_in_the_covered_input"
                    },
                    held: old,
                    previous_version: None,
                });
            }
            for r in records {
                let held = Held {
                    component_id: r["component_id"].as_str().unwrap_or_default().to_string(),
                    location_ref: r["location_ref"].clone(),
                    package: r["package"].clone(),
                };
                let appeared = |resolved: &BTreeSet<String>| {
                    if resolved.contains(&held.component_id) {
                        ("reopened", "observed_again_after_resolution")
                    } else {
                        ("added", "new_component")
                    }
                };
                match self.current.get(&key(r)).cloned() {
                    None => {
                        let (kind, reason) = appeared(&self.resolved);
                        out.push(Change {
                            kind,
                            reason,
                            held: held.clone(),
                            previous_version: None,
                        });
                    }
                    Some(old) if old.component_id == held.component_id => {
                        if old.package["version"] != held.package["version"] {
                            out.push(Change {
                                kind: "changed",
                                reason: "version_changed",
                                held: held.clone(),
                                previous_version: Some(old.package["version"].clone()),
                            });
                        }
                    }
                    Some(old) => {
                        self.resolved.insert(old.component_id.clone());
                        out.push(Change {
                            kind: "resolved",
                            reason: "replaced_by_a_different_component_at_the_same_covered_input",
                            held: old,
                            previous_version: None,
                        });
                        let (kind, reason) = appeared(&self.resolved);
                        out.push(Change {
                            kind,
                            reason,
                            held: held.clone(),
                            previous_version: None,
                        });
                    }
                }
                self.current.insert(key(r), held);
            }
        }
        out
    }
    /// The rows of the next assessment in revision order, numbered from `ordinal`.
    fn step(&mut self, a: &Assessment, ordinal: &mut i64) -> Vec<LogRow> {
        let previous_revision = self.summary.last_revision;
        self.summary.add(a);
        self.apply(a)
            .into_iter()
            .map(|change| {
                *ordinal += 1;
                LogRow {
                    ordinal: *ordinal - 1,
                    received_real: a.received,
                    revision: a.revision,
                    previous_revision,
                    late: a.late,
                    kind: change.kind.into(),
                    reason: change.reason.into(),
                    row: row_bytes(&change, a),
                }
            })
            .collect()
    }
    fn to_bytes(&self) -> Vec<u8> {
        let current: BTreeMap<&String, Value> = self
            .current
            .iter()
            .map(|(path, h)| {
                (
                    path,
                    json!({"component_id":h.component_id,"location_ref":h.location_ref,"package":h.package}),
                )
            })
            .collect();
        canonical(
            &json!({"assessments":self.summary.assessments,"current":current,"first_revision":self.summary.first_revision,
                "last_revision":self.summary.last_revision,"late":self.summary.late,"max_received":self.summary.max_received,
                "replay_version":REPLAY_VERSION,"resolved":self.resolved}),
        )
    }
    fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = || Error::rejected(503, "change_log_state_invalid");
        let v: Value = serde_json::from_slice(b)?;
        let mut state = State::default();
        for (path, h) in v["current"].as_object().ok_or_else(bad)? {
            state.current.insert(
                path.clone(),
                Held {
                    component_id: h["component_id"].as_str().ok_or_else(bad)?.to_string(),
                    location_ref: h["location_ref"].clone(),
                    package: h["package"].clone(),
                },
            );
        }
        for r in v["resolved"].as_array().ok_or_else(bad)? {
            state
                .resolved
                .insert(r.as_str().ok_or_else(bad)?.to_string());
        }
        state.summary = Summary::from_value(&v).ok_or_else(bad)?;
        Ok(state)
    }
}

/// Replay an authority's assessments in revision order from nothing: every change, with the index
/// of the assessment that produced it.
pub(crate) fn replay(published: &[Assessment]) -> Vec<(usize, Change)> {
    let mut state = State::default();
    let mut out = vec![];
    for (n, a) in published.iter().enumerate() {
        out.extend(state.apply(a).into_iter().map(|change| (n, change)));
    }
    out
}

/// One stored change: the ordering and filter columns, and the reader-independent part of the row
/// as canonical JSON.
#[derive(Debug, PartialEq)]
pub struct LogRow {
    pub ordinal: i64,
    pub received_real: Option<f64>,
    pub revision: i64,
    pub previous_revision: Option<i64>,
    pub late: bool,
    pub kind: String,
    pub reason: String,
    pub row: Vec<u8>,
}
fn row_bytes(c: &Change, a: &Assessment) -> Vec<u8> {
    let mut row = json!({"component_id":c.held.component_id,"location_ref":c.held.location_ref,
        "package":c.held.package,"observed_at":a.artifact["times"]["observed_at"],"evidence":a.evidence});
    if let Some(v) = &c.previous_version {
        row["previous_version"] = v.clone();
    }
    canonical(&row)
}

/// The replay version a saved state carries; `None` for a state that has none or is not JSON.
fn saved_version(state: &[u8]) -> Option<i64> {
    serde_json::from_slice::<Value>(state).ok()?["replay_version"].as_i64()
}
/// A saved state as the current rules would write it: the same content under the current version.
fn at_current_version(state: &[u8]) -> Option<Vec<u8>> {
    let mut v: Value = serde_json::from_slice(state).ok()?;
    v["replay_version"] = json!(REPLAY_VERSION);
    Some(canonical(&v))
}
/// The parts of a stored artifact the replay reads: the paths of its inputs, its records and the
/// observation time. The inputs' lockfile text is megabytes in a full assessment and is skipped
/// while reading, not built into a value.
pub(crate) fn replayable(raw: &[u8]) -> Result<Value> {
    #[derive(Deserialize)]
    struct Input {
        #[serde(default)]
        path: Value,
    }
    #[derive(Deserialize, Default)]
    struct Times {
        #[serde(default)]
        observed_at: Value,
    }
    #[derive(Deserialize, Default)]
    struct Inventory {
        #[serde(default)]
        state: Value,
    }
    #[derive(Deserialize, Default)]
    struct Coverage {
        #[serde(default)]
        inventory: Inventory,
    }
    #[derive(Deserialize)]
    struct Lean {
        #[serde(default)]
        inputs: Vec<Input>,
        #[serde(default)]
        records: Vec<Value>,
        #[serde(default)]
        times: Times,
        #[serde(default)]
        coverage: Coverage,
    }
    let lean: Lean = serde_json::from_slice(raw)?;
    Ok(json!({
        "retired": lean.coverage.inventory.state == "retired",
        "inputs": lean.inputs.into_iter().map(|i| json!({"path": i.path})).collect::<Vec<_>>(),
        "records": lean.records,
        "times": {"observed_at": lean.times.observed_at},
    }))
}
fn mismatch() -> Error {
    Error::rejected(503, "change_log_mismatch")
}
fn load(db: &Connection, authority: &str) -> Result<Vec<Assessment>> {
    let rows = db
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
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(revision, received, result, evidence, raw)| {
            Ok(Assessment {
                revision,
                received: received.parse::<f64>().ok().filter(|t| t.is_finite()),
                late: result != "published",
                evidence,
                artifact: replayable(&raw)?,
            })
        })
        .collect()
}
fn fold(published: &[Assessment]) -> (State, Vec<LogRow>) {
    let mut state = State::default();
    let mut ordinal = 0;
    let mut rows = vec![];
    for a in published {
        rows.extend(state.step(a, &mut ordinal));
    }
    (state, rows)
}
fn insert(db: &Connection, authority: &str, rows: &[LogRow]) -> Result<()> {
    let mut statement = db.prepare_cached("INSERT INTO v2_changes VALUES(?,?,?,?,?,?,?,?,?)")?;
    for r in rows {
        statement.execute(params![
            authority,
            r.ordinal,
            r.received_real,
            r.revision,
            r.previous_revision,
            r.late,
            r.kind,
            r.reason,
            r.row
        ])?;
    }
    Ok(())
}
fn save_state(db: &Connection, authority: &str, state: &State) -> Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO v2_change_state VALUES(?,?)",
        params![authority, state.to_bytes()],
    )?;
    Ok(())
}

/// Recompute one authority's rows from revision 1 and replace what was stored. A late assessment
/// does this; so does an authority that has no replay state yet.
pub(crate) fn rebuild(db: &Connection, authority: &str) -> Result<()> {
    let (state, rows) = fold(&load(db, authority)?);
    db.execute("DELETE FROM v2_changes WHERE authority=?", [authority])?;
    insert(db, authority, &rows)?;
    save_state(db, authority, &state)
}
/// Append the rows of an assessment that arrived above everything the authority holds, from the
/// stored replay state: the cost is this one artifact. The assessment must already be stored.
pub(crate) fn append(db: &Connection, authority: &str, a: &Assessment) -> Result<()> {
    let saved: Option<Vec<u8>> = db
        .query_row(
            "SELECT state FROM v2_change_state WHERE authority=?",
            [authority],
            |r| r.get(0),
        )
        .optional()?;
    let Some(saved) = saved else {
        return rebuild(db, authority);
    };
    if saved_version(&saved) != Some(REPLAY_VERSION) {
        return rebuild(db, authority);
    }
    let mut state = State::from_bytes(&saved)?;
    if state
        .summary
        .last_revision
        .is_some_and(|last| last >= a.revision)
    {
        return rebuild(db, authority);
    }
    let mut ordinal: i64 = db.query_row(
        "SELECT COALESCE(MAX(ordinal)+1,0) FROM v2_changes WHERE authority=?",
        [authority],
        |r| r.get(0),
    )?;
    let rows = state.step(a, &mut ordinal);
    insert(db, authority, &rows)?;
    save_state(db, authority, &state)
}
/// The published assessment an admission has just stored, as `append` wants it.
pub(crate) fn admitted(
    revision: i64,
    received: &str,
    evidence: &str,
    raw: &str,
) -> Result<Assessment> {
    Ok(Assessment {
        revision,
        received: received.parse::<f64>().ok().filter(|t| t.is_finite()),
        late: false,
        evidence: evidence.into(),
        artifact: replayable(raw.as_bytes())?,
    })
}

/// Every authority's rows and replay state, computed and not yet written.
pub(crate) struct Plan(Vec<(String, Vec<u8>, Vec<LogRow>)>);
impl Plan {
    pub(crate) fn of(db: &Connection) -> Result<Self> {
        let authorities = authorities(db)?;
        let mut all = Vec::with_capacity(authorities.len());
        for authority in authorities {
            let (state, rows) = fold(&load(db, &authority)?);
            all.push((authority, state.to_bytes(), rows));
        }
        Ok(Self(all))
    }
    /// What the log will add to the file, with room for pages and the index: an upper-ish guess
    /// that errs toward refusing.
    pub(crate) fn estimated_bytes(&self) -> u64 {
        let payload: usize = self
            .0
            .iter()
            .map(|(authority, state, rows)| {
                authority.len()
                    + state.len()
                    + rows
                        .iter()
                        .map(|r| r.row.len() + r.kind.len() + r.reason.len() + authority.len() + 96)
                        .sum::<usize>()
            })
            .sum();
        payload as u64 * 5 / 4 + 65536
    }
    pub(crate) fn write(&self, db: &Connection) -> Result<()> {
        for (authority, state, rows) in &self.0 {
            insert(db, authority, rows)?;
            db.execute(
                "INSERT INTO v2_change_state VALUES(?,?)",
                params![authority, state],
            )?;
        }
        Ok(())
    }
}
fn authorities(db: &Connection) -> Result<Vec<String>> {
    Ok(db
        .prepare("SELECT authority FROM v2_authorities ORDER BY authority")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?)
}

/// The rows the in-memory replay finds for an authority's retained assessments, numbered and
/// linked the way the log numbers and links them. This is the oracle the stored rows must equal.
pub fn replayed(db: &Connection, authority: &str) -> Result<Vec<LogRow>> {
    let published = load(db, authority)?;
    Ok(replay(&published)
        .into_iter()
        .enumerate()
        .map(|(ordinal, (n, change))| LogRow {
            ordinal: ordinal as i64,
            received_real: published[n].received,
            revision: published[n].revision,
            previous_revision: n.checked_sub(1).map(|p| published[p].revision),
            late: published[n].late,
            kind: change.kind.into(),
            reason: change.reason.into(),
            row: row_bytes(&change, &published[n]),
        })
        .collect())
}
/// The rows stored for an authority, in ordinal order.
pub fn stored(db: &Connection, authority: &str) -> Result<Vec<LogRow>> {
    Ok(db
        .prepare_cached("SELECT ordinal,received_real,revision,previous_revision,late,kind,reason,row FROM v2_changes WHERE authority=? ORDER BY ordinal")?
        .query_map([authority], |r| {
            Ok(LogRow {
                ordinal: r.get(0)?,
                received_real: r.get(1)?,
                revision: r.get(2)?,
                previous_revision: r.get(3)?,
                late: r.get(4)?,
                kind: r.get(5)?,
                reason: r.get(6)?,
                row: r.get(7)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?)
}
/// One change as a list shows it, found by the in-memory replay or read back from the log.
pub(crate) struct Entry {
    pub received: Option<f64>,
    pub revision: i64,
    pub previous_revision: Option<i64>,
    pub late: bool,
    pub kind: String,
    pub reason: String,
    pub component_id: String,
    pub location_ref: Value,
    pub package: Value,
    pub previous_version: Option<Value>,
    /// The artifact's `times.observed_at`, as it stands.
    pub observed_at: Value,
    pub evidence: String,
}
impl Entry {
    pub(crate) fn replayed(
        change: &Change,
        a: &Assessment,
        previous_revision: Option<i64>,
    ) -> Self {
        Self {
            received: a.received,
            revision: a.revision,
            previous_revision,
            late: a.late,
            kind: change.kind.into(),
            reason: change.reason.into(),
            component_id: change.held.component_id.clone(),
            location_ref: change.held.location_ref.clone(),
            package: change.held.package.clone(),
            previous_version: change.previous_version.clone(),
            observed_at: a.artifact["times"]["observed_at"].clone(),
            evidence: a.evidence.clone(),
        }
    }
}

/// Whether this hub has a change log at all (schema 3).
pub(crate) fn exists(db: &Connection) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_changes')",
        [],
        |r| r.get(0),
    )?)
}
/// What each authority's saved replay state says of its history, in the order asked. `None` when
/// any has no state or one written under other replay rules: the log cannot speak for it, and the
/// caller replays instead.
pub(crate) fn summaries(db: &Connection, authorities: &[&str]) -> Result<Option<Vec<Summary>>> {
    let mut statement = db.prepare_cached("SELECT state FROM v2_change_state WHERE authority=?")?;
    let mut out = Vec::with_capacity(authorities.len());
    for authority in authorities {
        let saved: Option<Vec<u8>> = statement.query_row([authority], |r| r.get(0)).optional()?;
        let state = saved.and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
        let summary = state
            .filter(|v| v["replay_version"].as_i64() == Some(REPLAY_VERSION))
            .and_then(|v| Summary::from_value(&v));
        match summary {
            Some(s) => out.push(s),
            None => return Ok(None),
        }
    }
    Ok(Some(out))
}
/// Whether the receipt index lists rows in the order the in-memory replay sorts them. A change
/// whose assessment has no readable receipt time sorts as time 0 there but first here, so any
/// such row, or any at or before 0, means the page must be replayed to come out the same.
pub(crate) fn index_orders_like_replay(db: &Connection) -> Result<bool> {
    let first: Option<Option<f64>> = db
        .query_row(
            "SELECT received_real FROM v2_changes INDEXED BY v2_changes_received ORDER BY received_real LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(first.is_none_or(|t| t.is_some_and(|t| t > 0.0)))
}
/// The changes of `authorities` received after `after` (all of them when `None`), oldest first,
/// as the in-memory sort orders them: by receipt time, then authority, then replay order. Returns
/// how many there are and the `limit` of them from `offset`, each with its authority.
pub(crate) fn page(
    db: &Connection,
    authorities: &[&str],
    after: Option<f64>,
    offset: u64,
    limit: usize,
) -> Result<(u64, Vec<(String, Entry)>)> {
    let mut args: Vec<rusqlite::types::Value> = vec![serde_json::to_string(authorities)?.into()];
    let mut filter = "authority IN (SELECT value FROM json_each(?1))".to_string();
    if let Some(t) = after {
        args.push(t.into());
        filter += " AND received_real > ?2";
    }
    let total: u64 = db.query_row(
        &format!("SELECT COUNT(*) FROM v2_changes INDEXED BY v2_changes_received WHERE {filter}"),
        params_from_iter(&args),
        |r| r.get(0),
    )?;
    let rows = db
        .prepare(&format!(
            "SELECT authority,received_real,revision,previous_revision,late,kind,reason,row \
             FROM v2_changes INDEXED BY v2_changes_received WHERE {filter} \
             ORDER BY received_real,authority,ordinal LIMIT {limit} OFFSET {offset}"
        ))?
        .query_map(params_from_iter(&args), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<f64>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let entries = rows
        .into_iter()
        .map(
            |(authority, received, revision, previous_revision, late, kind, reason, raw)| {
                let mut row: Value = serde_json::from_slice(&raw)?;
                let mut take = |key: &str| row.get_mut(key).map_or(Value::Null, Value::take);
                let (location_ref, package, observed_at) =
                    (take("location_ref"), take("package"), take("observed_at"));
                let text = |key: &str| row[key].as_str().unwrap_or_default().to_string();
                Ok((
                    authority,
                    Entry {
                        received,
                        revision,
                        previous_revision,
                        late,
                        kind,
                        reason,
                        component_id: text("component_id"),
                        location_ref,
                        package,
                        previous_version: row.get("previous_version").cloned(),
                        observed_at,
                        evidence: text("evidence"),
                    },
                ))
            },
        )
        .collect::<Result<Vec<_>>>()?;
    Ok((total, entries))
}

/// Every authority's stored rows and replay state equal the replay of its retained assessments,
/// and the log holds nothing for an authority the hub does not have.
pub(crate) fn verify_all(db: &Connection) -> Result<()> {
    for authority in authorities(db)? {
        let state: Option<Vec<u8>> = db
            .query_row(
                "SELECT state FROM v2_change_state WHERE authority=?",
                [&authority],
                |r| r.get(0),
            )
            .optional()?;
        if state.as_deref().is_some_and(|s| {
            !matches!(
                saved_version(s),
                Some(REPLAY_VERSION | PREVIOUS_REPLAY_VERSION)
            )
        }) {
            return Err(Error::rejected(503, "change_log_replay_version"));
        }
        if stored(db, &authority)? != replayed(db, &authority)? {
            return Err(mismatch());
        }
        if state.as_deref().and_then(at_current_version)
            != Some(fold(&load(db, &authority)?).0.to_bytes())
        {
            return Err(mismatch());
        }
    }
    let orphans: i64 = db.query_row(
        "SELECT (SELECT count(*) FROM v2_changes WHERE authority NOT IN (SELECT authority FROM v2_authorities)) + (SELECT count(*) FROM v2_change_state WHERE authority NOT IN (SELECT authority FROM v2_authorities))",
        [],
        |r| r.get(0),
    )?;
    if orphans != 0 {
        return Err(mismatch());
    }
    Ok(())
}
