use crate::domain::{Package, Record, CATEGORIES};
use crate::store::{asset, identity, now, Store};
use crate::{Error, Result};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn category(record: &Value) -> (&'static str, String, bool) {
    let origin = record["origin"].as_str().unwrap_or("");
    let kind = record["bom_kind"].as_str().unwrap_or("");
    if origin == "os" {
        return ("Environments", "os-package".into(), true);
    }
    if origin == "tool"
        || [
            "mcp",
            "mcp-config",
            "plugin",
            "skill",
            "hook",
            "settings-env",
            "command",
            "subagent",
            "cli",
            "mcp-package",
            "ide-extension",
            "model",
        ]
        .contains(&kind)
    {
        return (
            "Developer Tools",
            if kind.is_empty() { "tool" } else { kind }.into(),
            true,
        );
    }
    if ["project", "browser", "image", "installed"].contains(&origin) {
        return ("Applications", origin.into(), true);
    }
    ("Applications", "unknown".into(), false)
}
pub fn observations(
    packages: &[Package],
    items: &[Record],
    host: Option<&str>,
) -> Result<Vec<Record>> {
    let local = crate::store::hostname()?;
    let host = host.unwrap_or(&local);
    let item_by_id: HashMap<_, _> = items
        .iter()
        .filter_map(|i| i.get("asset").and_then(Value::as_str).map(|a| (a, i)))
        .collect();
    let direct: HashSet<_> = packages
        .iter()
        .filter(|p| p.extra.get("dependency") != Some(&Value::Bool(true)))
        .filter_map(|p| p.extra.get("bom_asset").and_then(Value::as_str))
        .collect();
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    let mut order = Vec::new();
    for item in items {
        let Some(item_asset) = item.get("asset").and_then(Value::as_str) else {
            return Err(Error::new("a BOM asset is required"));
        };
        if direct.contains(item_asset) {
            continue;
        }
        let (category, subtype, known) = category(&json!({"bom_kind":item.get("kind")}));
        let id = identity(&json!([host, item_asset]))?;
        if !out.contains_key(&id) {
            order.push(id.clone());
        }
        out.insert(id.clone(),json!({"id":id,"host":host,"category":category,"subtype":subtype,"known":known,"evidence":"configured","record":item,"aliases":[item_asset],"checked":false}));
    }
    for p in packages {
        let asset = asset(p)?;
        let id = identity(&json!([host, asset]))?;
        let record = serde_json::to_value(p)?;
        let (category, subtype, known) = category(&record);
        let mut aliases = vec![asset.clone(), identity(&json!(["agentbom", host, asset]))?];
        let bom_asset = record["bom_asset"].as_str();
        if let Some(bom_asset) = bom_asset {
            if record["dependency"] != true {
                aliases.push(bom_asset.into());
            }
        }
        let mut contexts = out
            .get(&id)
            .and_then(|v| v["contexts"].as_array())
            .cloned()
            .unwrap_or_default();
        if let Some(item) = bom_asset.and_then(|a| item_by_id.get(a)) {
            contexts.push(Value::Object((*item).clone()));
        }
        if let Some(prior) = out.get(&id) {
            aliases.extend(strings(&prior["aliases"]));
        }
        aliases.sort();
        aliases.dedup();
        let installed = ["os", "tool", "browser", "installed"]
            .contains(&record["origin"].as_str().unwrap_or(""));
        if !out.contains_key(&id) {
            order.push(id.clone());
        }
        out.insert(id.clone(),json!({"id":id,"host":host,"category":category,"subtype":subtype,"known":known,"contexts":contexts,"evidence":if installed {"installed"} else {"selected"},"record":record,"aliases":aliases,"checked":false}));
    }
    Ok(order
        .into_iter()
        .filter_map(|key| out.remove(&key))
        .map(|v| v.as_object().unwrap().clone())
        .collect())
}
pub fn save(
    store: &mut Store,
    scope: &str,
    rows: &[Record],
    covered: &BTreeSet<String>,
    complete: bool,
    observed: Option<f64>,
) -> Result<()> {
    save_selected(store, scope, rows, covered, complete, observed, false)
}
pub(crate) fn save_selected(
    store: &mut Store,
    scope: &str,
    rows: &[Record],
    covered: &BTreeSet<String>,
    complete: bool,
    observed: Option<f64>,
    captured: bool,
) -> Result<()> {
    let observed = observed.unwrap_or_else(now);
    let tx = store.db.savepoint()?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS asset_observations(scope TEXT,id TEXT,payload TEXT,observed REAL,complete INTEGER,PRIMARY KEY(scope,id)); CREATE TABLE IF NOT EXISTS asset_scopes(scope TEXT PRIMARY KEY,observed REAL);")?;
    tx.execute(
        "INSERT OR REPLACE INTO asset_scopes VALUES(?,?)",
        params![scope, observed],
    )?;
    if complete {
        tx.execute("DELETE FROM asset_observations WHERE scope=?", [scope])?;
    } else if !captured {
        tx.execute(
            "UPDATE asset_observations SET complete=0 WHERE scope=?",
            [scope],
        )?;
    }
    if captured {
        // Once per path: a captured lockfile contributes many rows from the same path.
        let mut paths = BTreeSet::new();
        for row in rows {
            paths.insert(
                row["record"]["path"]
                    .as_str()
                    .ok_or_else(|| Error::new("captured path required"))?,
            );
        }
        for path in paths {
            tx.execute("DELETE FROM asset_observations WHERE scope=? AND json_extract(payload,'$.record.path')=?", params![scope,path])?;
        }
    }
    for row in rows {
        let mut row = Value::Object(row.clone());
        row["checked"] = json!(
            row["record"].get("path").is_some()
                && strings(&row["aliases"]).iter().any(|a| covered.contains(a))
        );
        let id = row["id"]
            .as_str()
            .ok_or_else(|| Error::new("observation id required"))?;
        tx.execute(
            "INSERT OR REPLACE INTO asset_observations VALUES(?,?,?,?,?)",
            params![scope, id, serde_json::to_string(&row)?, observed, complete],
        )?;
    }
    tx.commit()?;
    Ok(())
}
pub fn source_contains(source: &Value, path: &str) -> bool {
    let Some(selected) = source["path"].as_str() else {
        return false;
    };
    path == selected
        || ["windows-uninstall", "windows-msix"].contains(&source["source"].as_str().unwrap_or(""))
            && path
                .strip_prefix(selected)
                .is_some_and(|p| p.starts_with('/'))
}
/// Only explicit completed metadata sources can retire absent observations.
pub fn retire_absent_sources(
    store: &mut Store,
    scope: &str,
    packages: &[Package],
    sources: &[Value],
) -> Result<()> {
    if sources.is_empty() {
        return Ok(());
    }
    let rows = store
        .db
        .prepare("SELECT id,payload FROM asset_observations WHERE scope=?")?
        .query_map([scope], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (id, payload) in rows {
        let row: Value = serde_json::from_str(&payload)?;
        if let Some(path) = row["record"]["path"].as_str() {
            if !packages.iter().any(|p| p.path == path)
                && sources.iter().any(|s| source_contains(s, path))
            {
                store.db.execute(
                    "DELETE FROM asset_observations WHERE scope=? AND id=?",
                    params![scope, id],
                )?;
            }
        }
    }
    Ok(())
}

fn has_table(db: &Connection, name: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name=?)",
        [name],
        |r| r.get(0),
    )?)
}
pub fn summary(
    db: &Connection,
    observed: Option<f64>,
    selected: Option<&BTreeSet<String>>,
) -> Result<Value> {
    let observed = observed.unwrap_or_else(now);
    let scopes = if let Some(selected) = selected {
        selected.clone()
    } else if has_table(db, "asset_scopes")? {
        db.prepare("SELECT scope FROM asset_scopes ORDER BY observed DESC LIMIT 1")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?
    } else {
        BTreeSet::new()
    };
    let mut rows: BTreeMap<String, Value> = BTreeMap::new();
    let mut order = Vec::new();
    if has_table(db, "asset_observations")? {
        let raw: Vec<(String,String,String,f64,bool)> = db.prepare("SELECT scope,id,payload,observed,complete FROM asset_observations ORDER BY observed")?.query_map([],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?.collect::<std::result::Result<_,_>>()?;
        for (scope, key, payload, at, complete) in raw {
            if !scopes.contains(&scope) {
                continue;
            }
            let mut row: Value = serde_json::from_str(&payload)?;
            row["scope"] = json!(scope);
            row["observed"] = json!(at);
            row["complete"] = json!(complete);
            if let Some(prior) = rows.get(&key) {
                row["complete"] = json!(complete && prior["complete"] == true);
                row["checked"] = json!(row["checked"] == true && prior["checked"] == true);
                row["observed"] = json!(at.min(prior["observed"].as_f64().unwrap_or(at)));
                let mut aliases = strings(&row["aliases"]);
                aliases.extend(strings(&prior["aliases"]));
                aliases.sort();
                aliases.dedup();
                row["aliases"] = json!(aliases);
                if prior["record"]["origin"] == "project" {
                    for field in ["category", "subtype", "known"] {
                        row[field] = prior[field].clone();
                    }
                }
            }
            if !rows.contains_key(&key) {
                order.push(key.clone());
            }
            rows.insert(key, row);
        }
    }
    let local = crate::store::hostname()?;
    let mut by_asset: HashMap<(String, String), Vec<Value>> = HashMap::new();
    let mut health = HashSet::new();
    for payload in db
        .prepare("SELECT payload FROM findings WHERE active=1")?
        .query_map([], |r| r.get::<_, String>(0))?
    {
        let Ok(f) = serde_json::from_str::<Value>(&payload?) else {
            continue;
        };
        if !f.is_object() {
            continue;
        }
        let host = f["host"].as_str().unwrap_or(&local).to_string();
        if f["kind"] == "health" {
            health.insert((host, f["scan_scope"].as_str().map(str::to_string)));
        } else {
            by_asset
                .entry((host, f["asset"].as_str().unwrap_or("").into()))
                .or_default()
                .push(f);
        }
    }
    let mut categories: Vec<Value> = CATEGORIES.iter().map(|c| json!({"category":c,"total":0,"critical":0,"needs_review":0,"flags":0,"items_scanned":0,"healthy":0})).collect();
    let mut matched = HashSet::new();
    for row in rows.values_mut() {
        let host = row["host"].as_str().unwrap_or("").to_string();
        let mut findings = BTreeMap::new();
        for alias in strings(&row["aliases"]) {
            if let Some(items) = by_asset.get(&(host.clone(), alias)) {
                for f in items {
                    findings.insert(f["key"].as_str().unwrap_or("").to_string(), f);
                }
            }
        }
        matched.extend(findings.keys().cloned());
        let problem = health.contains(&(host.clone(), None))
            || health.contains(&(host, row["scope"].as_str().map(str::to_string)));
        let stale = observed - row["observed"].as_f64().unwrap_or(0.0) > 2.0 * 86400.0;
        let critical = findings
            .values()
            .any(|f| crate::scanner::priority::priority(f)["level"] == "critical");
        let status = if critical {
            "critical"
        } else if !findings.is_empty()
            || stale
            || problem
            || row["known"] != true
            || row["checked"] != true
            || row["complete"] != true
        {
            "needs_review"
        } else {
            "healthy"
        };
        row["status"] = json!(status);
        row["stale"] = json!(stale);
        row["finding_count"] = json!(findings.len());
        let index = CATEGORIES
            .iter()
            .position(|c| row["category"] == *c)
            .ok_or_else(|| Error::new("unknown asset category"))?;
        let counts = &mut categories[index];
        for (field, add) in [
            ("total", true),
            (status, true),
            ("flags", status != "healthy"),
            ("items_scanned", row["checked"] == true && !stale),
        ] {
            if add {
                counts[field] = json!(counts[field].as_u64().unwrap_or(0) + 1);
            }
        }
    }
    let items: Vec<_> = order
        .into_iter()
        .filter_map(|key| rows.remove(&key))
        .collect();
    let mut result = json!({"schema":1,"scopes":scopes,"categories":categories,"finding_count":matched.len(),"items":items});
    for field in [
        "total",
        "critical",
        "needs_review",
        "flags",
        "items_scanned",
        "healthy",
    ] {
        result[field] = json!(categories
            .iter()
            .map(|c| c[field].as_u64().unwrap_or(0))
            .sum::<u64>());
    }
    Ok(result)
}

pub fn restrict(db: &Connection, assets: &Value) -> Result<()> {
    let items = assets["items"].as_array().cloned().unwrap_or_default();
    let mut aliases = HashSet::new();
    let mut hosts = HashSet::new();
    let scopes: HashSet<_> = strings(&assets["scopes"]).into_iter().collect();
    let local = crate::store::hostname()?;
    for item in &items {
        let host = item["host"].as_str().unwrap_or("").to_string();
        hosts.insert(host.clone());
        for alias in strings(&item["aliases"]) {
            aliases.insert((host.clone(), alias));
        }
    }
    let belongs = |payload: &str| -> bool {
        let Ok(f) = serde_json::from_str::<Value>(payload) else {
            return false;
        };
        if !f.is_object() {
            return false;
        }
        let host = f["host"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(&local);
        aliases.contains(&(host.into(), f["asset"].as_str().unwrap_or("").into()))
            || f["scan_scope"].as_str().is_some_and(|s| scopes.contains(s))
            || f["kind"] == "health"
                && f.get("scan_scope").is_none_or(|v| v.is_null() || v == "")
                && hosts.contains(host)
    };
    let mut keys = HashSet::<String>::new();
    let mut message_ids = HashSet::new();
    let mut readers = HashSet::<String>::new();
    let mut contexts: Vec<Value> = Vec::new();
    for item in &items {
        contexts.extend(item["contexts"].as_array().cloned().unwrap_or_default());
        contexts.push(item["record"].clone());
    }
    for name in [
        "findings", "messages", "fixes", "scans", "bom", "receipts", "readers",
    ] {
        if !has_table(db, name)? {
            continue;
        }
        let mut statement = db.prepare(&format!("SELECT * FROM main.{name}"))?;
        let columns: Vec<String> = statement.column_names().map(|s| s.to_string()).collect();
        let mut rows = statement.query([])?;
        let mut selected = Vec::new();
        while let Some(row) = rows.next()? {
            let values: Vec<rusqlite::types::Value> = (0..columns.len())
                .map(|i| row.get(i))
                .collect::<std::result::Result<_, _>>()?;
            let get = |key: &str| {
                columns
                    .iter()
                    .position(|k| k == key)
                    .and_then(|i| values.get(i))
            };
            let text = |key: &str| match get(key) {
                Some(rusqlite::types::Value::Text(s)) => Some(s.as_str()),
                _ => None,
            };
            let keep = match name {
                "findings" | "messages" => {
                    let keep = text("payload").is_some_and(belongs);
                    if keep {
                        if let Some(key) = text("key") {
                            keys.insert(key.to_string());
                        }
                        if name == "messages" {
                            if let Some(rusqlite::types::Value::Integer(id)) = get("id") {
                                message_ids.insert(*id);
                            }
                        }
                    }
                    keep
                }
                "fixes" => text("key").is_some_and(|k| keys.contains(k)),
                "receipts" => {
                    let keep = matches!(get("message"),Some(rusqlite::types::Value::Integer(id)) if message_ids.contains(id));
                    if keep {
                        if let Some(reader) = text("reader") {
                            readers.insert(reader.to_owned());
                        }
                    }
                    keep
                }
                "readers" => {
                    text("name").is_some_and(|name| readers.contains(name))
                        || matches!(get("cursor"),Some(rusqlite::types::Value::Integer(id)) if message_ids.contains(id))
                }
                "scans" => text("scan_scope")
                    .or_else(|| text("scope"))
                    .is_some_and(|scope| scopes.contains(scope)),
                "bom" => contexts.iter().any(|c| {
                    ["host", "kind", "name", "source"]
                        .iter()
                        .all(|k| c[*k].as_str() == text(k))
                }),
                _ => false,
            };
            if keep {
                let mut values = values;
                if name == "readers" {
                    if let Some(i) = columns.iter().position(|c| c == "cursor") {
                        if !matches!(&values[i],rusqlite::types::Value::Integer(id) if message_ids.contains(id))
                        {
                            values[i] = rusqlite::types::Value::Integer(0);
                        }
                    }
                }
                selected.push(values);
            }
        }
        drop(rows);
        drop(statement);
        db.execute_batch(&format!(
            "CREATE TEMP TABLE {name} AS SELECT * FROM main.{name} WHERE 0"
        ))?;
        let placeholders = vec!["?"; columns.len()].join(",");
        for row in selected {
            db.execute(
                &format!("INSERT INTO temp.{name} VALUES({placeholders})"),
                rusqlite::params_from_iter(row),
            )?;
        }
    }
    Ok(())
}

pub fn bom_records(rows: &[Value]) -> BTreeMap<(String, String, String, String, String), String> {
    let mut records = BTreeMap::new();
    for row in rows {
        let confidence = if row["complete"] != true {
            "unknown"
        } else if row["stale"] == true {
            "stale"
        } else {
            "observed"
        };
        let mut contexts = row["contexts"].as_array().cloned().unwrap_or_default();
        contexts.push(row["record"].clone());
        for item in contexts {
            if item["kind"]
                .as_str()
                .is_none_or(|s| s.is_empty() || s == "mcp-config")
            {
                continue;
            }
            let get = |k| item[k].as_str().unwrap_or("").to_string();
            let key = (
                get("host"),
                get("kind"),
                get("name"),
                get("version"),
                get("source"),
            );
            if records.get(&key).is_none_or(|v| v != "unknown") {
                records.insert(key, confidence.into());
            }
        }
    }
    records
}
