use super::english::*;
use crate::{Error, Result};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::{Component, Path, PathBuf},
    time::Duration,
};
pub fn gid(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))[..12].into()
}
pub fn query(db: &Connection, sql: &str) -> Result<Vec<Value>> {
    let mut stmt = db.prepare(sql)?;
    let names: Vec<_> = stmt.column_names().map(|s| s.to_string()).collect();
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut value = json!({});
        for (i, name) in names.iter().enumerate() {
            value[name] = match row.get_ref(i)? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(n) => json!(n),
                ValueRef::Real(n) => json!(n),
                ValueRef::Text(s) => json!(String::from_utf8_lossy(s)),
                ValueRef::Blob(_) => return Err(Error::new("unexpected binary mailbox field")),
            };
        }
        out.push(value);
    }
    Ok(out)
}
pub fn load(value: &Value) -> Value {
    let mut f = if let Some(text) = value.as_str() {
        serde_json::from_str::<Value>(text).unwrap_or(json!({}))
    } else {
        value.clone()
    };
    if !f.is_object() {
        return json!({});
    }
    if !f["package"].is_object() {
        f["package"] = json!({});
    }
    for key in ["aliases", "source_url", "fixed"] {
        f[key] = if let Some(v) = f[key].as_array() {
            json!(v
                .iter()
                .filter(|v| v.is_string() || v.is_number())
                .map(|v| if let Some(s) = v.as_str() {
                    s.to_string()
                } else {
                    v.to_string()
                })
                .collect::<Vec<_>>())
        } else if f[key].is_string() || f[key].is_number() {
            json!([if let Some(s) = f[key].as_str() {
                s.to_string()
            } else {
                f[key].to_string()
            }])
        } else {
            json!([])
        };
    }
    if !f["severity"].is_array() {
        f["severity"] = json!([]);
    }
    if !f["priority"].is_object() {
        f["priority"] = json!({});
    }
    f["kev"] = json!(f["kev"] == true);
    f["epss"] = json!(f["epss"]
        .as_f64()
        .or_else(|| f["epss"].as_str().and_then(|s| s.parse().ok()))
        .filter(|f| f.is_finite())
        .unwrap_or(0.));
    f
}
fn scan_errors(last: &Value) -> Value {
    last["errors"]
        .as_str()
        .map(|s| serde_json::from_str::<Value>(s).unwrap_or(json!([s])))
        .unwrap_or_else(|| last["errors"].clone())
}
pub fn scan_state(last: &Value, now: f64, problem: bool) -> &str {
    if !last.is_object() {
        return "never";
    }
    let errors = scan_errors(last);
    if problem || errors.as_array().is_none_or(|a| !a.is_empty()) || last["status"] == "unknown" {
        "failed"
    } else if now - number(last, "finished") > 172800. {
        "stale"
    } else {
        "ok"
    }
}
fn issue(t: &str, host: &str, key: &str, items: &[Value], seen: f64) -> Value {
    let sev = items
        .iter()
        .map(severity)
        .min_by_key(|v| SEVERITIES.iter().position(|s| s == v))
        .unwrap_or("unrated");
    let kev = items.iter().any(|i| i["kev"] == true);
    let epss = items.iter().map(|i| number(i, "epss")).fold(0., f64::max);
    let dev = items
        .iter()
        .all(|i| i["package"]["scope"] == "likely-dev-only");
    let needs = t != "health"
        && (kev || !dev && (t == "browser" || ["critical", "high"].contains(&sev) || epss >= 0.1));
    let mut advs:Vec<_>=items.iter().filter(|i| !static_observation(i)).map(|i|json!({"id":s(i,"advisory"),"key":s(i,"key"),"aliases":a(i,"aliases"),"kev":i["kev"],"severity":severity(i),"basis":if SEVERITIES.contains(&s(&i["priority"],"level")){String::new()}else{scored(i).1},"confidence":s(i,"confidence"),"package":format!("{} {}",s(&i["package"],"name"),s(&i["package"],"version")).trim(),"sources":a(i,"source_url").iter().filter(|v|v.as_str().is_some_and(|s|s.starts_with("https://")||s.starts_with("http://"))).collect::<Vec<_>>()})).collect();
    advs.sort_by_key(|a| {
        (
            a["kev"] != true,
            SEVERITIES
                .iter()
                .position(|s| *s == super::english::s(a, "severity")),
            super::english::s(a, "id").to_string(),
        )
    });
    let mut result = json!({"id":gid(key),"type":t,"host":host,"kev":kev,"severity":sev,"epss":epss,"dev_only":dev,"needs":needs,"count":items.len(),"seen":seen,"why":if t=="health"{""}else{why(t,kev,sev,epss,dev)},"keys":items.iter().map(|i|s(i,"key")).collect::<Vec<_>>(),"advisories":advs,"path":s(&items[0]["package"],"path"),"installed":"","target":""});
    result
        .as_object_mut()
        .unwrap()
        .extend(describe(t, items).as_object().unwrap().clone());
    result["packages"] = json!(items
        .iter()
        .map(|i| package_id(&i["package"]))
        .collect::<Vec<_>>());
    result
}
// An asset's identity, so two package lists that name one file keep their findings apart.
fn package_id(p: &Value) -> Value {
    json!([
        lexical(s(p, "path")),
        s(p, "ecosystem"),
        s(p, "name"),
        s(p, "version")
    ])
}
fn fixed_title(f: &Value) -> String {
    let p = &f["package"];
    if s(p, "name").is_empty() {
        return s(f, "title").into();
    }
    let target = target(std::slice::from_ref(f));
    if target.is_empty() {
        format!("{} {} removed", s(p, "name"), s(p, "version"))
    } else {
        format!("{} → {target}", s(p, "name"))
    }
}
pub(super) fn iso(value: &str) -> Option<f64> {
    // Compiled once: every page reads each saved alert through here.
    static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let r = R.get_or_init(|| {
        regex::Regex::new(
            r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)?$",
        )
        .unwrap()
    });
    let c = r.captures(value)?;
    let get = |i| c.get(i)?.as_str().parse::<i64>().ok();
    let (y, m, d, h, min, sec) = (get(1)?, get(2)?, get(3)?, get(4)?, get(5)?, get(6)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || min > 59 || sec > 59 {
        return None;
    }
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let days =
        era * 146097 + (yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5 + d - 1) - 719468;
    let mut timestamp = (days * 86400 + h * 3600 + min * 60 + sec) as f64;
    if let Some(f) = c.get(7) {
        timestamp += format!("0.{}", f.as_str()).parse::<f64>().ok()?;
    }
    if let Some(tz) = c.get(8).filter(|s| s.as_str() != "Z") {
        let tz = tz.as_str();
        let offset = tz[1..3].parse::<i64>().ok()? * 3600 + tz[4..].parse::<i64>().ok()? * 60;
        timestamp -= if tz.starts_with('+') { offset } else { -offset } as f64;
    }
    Some(timestamp)
}

// `Path::starts_with` compares components, so resolve `.` and `..` before any prefix test.
fn lexical(path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for part in Path::new(path).components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}
pub(super) fn belongs_to_project(issue: &Value, project: &Value) -> bool {
    issue["host"] == project["host"]
        && if project["inferred"] == true
            || issue["type"] == "health"
            || s(issue, "path").is_empty()
        {
            issue["scan_scope"] == project["scope"]
        } else if project["imported"] == true {
            // Any scan that saw one of this list's packages outside its roots, so the card
            // stays true when a later scan of the same list under another scope took the finding.
            let own = a(project, "packages");
            a(issue, "packages").iter().any(|id| own.contains(id))
        } else {
            lexical(s(issue, "path")).starts_with(s(project, "root"))
        }
}
struct Fact<'a> {
    host: &'a str,
    health: bool,
    path: &'a str,
    lexical: PathBuf,
    scope: Option<&'a str>,
    id: String,
}
fn projects(
    db: &Connection,
    tables: &BTreeSet<String>,
    scans: &BTreeMap<String, Vec<Value>>,
    groups: &BTreeMap<String, Vec<Value>>,
    grouped: &dyn Fn(&str, &[Value]) -> Value,
    now: f64,
    local: &str,
) -> Result<Vec<Value>> {
    let checkpoints: BTreeMap<_, _> = if tables.contains("assessment_checkpoints") {
        query(db, "SELECT scope,payload FROM assessment_checkpoints")?
            .into_iter()
            .map(|r| (s(&r, "scope").to_string(), load(&r["payload"])))
            .collect()
    } else {
        BTreeMap::new()
    };
    let mut latest = BTreeMap::new();
    for run in scans.values().flatten() {
        latest.insert((s(run, "host"), s(run, "scan_scope")), run);
    }
    // What a card needs from each finding, read once: building a one-finding issue per card
    // made every page cost cards × findings issue builds.
    let facts: Vec<Vec<Fact>> = groups
        .values()
        .map(|items| {
            items
                .iter()
                .map(|i| {
                    let path = if static_observation(i) {
                        s(i, "path")
                    } else {
                        s(&i["package"], "path")
                    };
                    Fact {
                        host: s(i, "host"),
                        health: finding_type(i) == "health",
                        path,
                        lexical: lexical(path),
                        scope: i["scan_scope"].as_str(),
                        id: package_id(&i["package"]).to_string(),
                    }
                })
                .collect()
        })
        .collect();
    let mut by_root = BTreeMap::new();
    for ((host, scope), run) in latest {
        let saved = checkpoints.get(scope).cloned().unwrap_or(Value::Null);
        let errors = scan_errors(run);
        let mut roots: Vec<String> = a(&saved, "scan_roots")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let inferred = roots.is_empty();
        if inferred {
            // Older checkpoints saved input paths, but not the selected root. Keep that evidence labelled.
            let paths: Vec<_> = a(&saved["coverage_evidence"], "observations")
                .iter()
                .filter_map(|v| v["path"].as_str())
                .filter(|p| Path::new(p).is_absolute())
                .collect();
            if let Some(first) = paths.first() {
                let mut common = Path::new(first).parent().unwrap_or(Path::new(first));
                for path in &paths[1..] {
                    while !Path::new(path).starts_with(common) {
                        let Some(parent) = common.parent() else { break };
                        common = parent;
                    }
                }
                roots.push(common.to_string_lossy().into_owned());
            }
        }
        if roots.is_empty() {
            roots.push(String::new());
        }
        // Packages that did not come from walking a scan root (an imported list, OS packages)
        // are kept as their own card, found and judged by scan scope.
        let versioned: Vec<&Value> = a(&saved, "packages")
            .iter()
            .filter(|p| !s(p, "version").is_empty())
            .collect();
        let in_roots = |p: &Value| roots.iter().any(|r| lexical(s(p, "path")).starts_with(r));
        let outside_packages: Vec<&Value> =
            versioned.iter().copied().filter(|p| !in_roots(p)).collect();
        let outside = !inferred && !outside_packages.is_empty();
        let mut sources: Vec<&str> = outside_packages
            .iter()
            .map(|p| match s(p, "origin") {
                "image" => "Container image",
                "os" => "OS packages",
                "tool" => "Installed tools",
                "installed" => "Installed apps",
                "browser" => "Browsers",
                _ => "Imported package list",
            })
            .collect();
        sources.sort();
        sources.dedup();
        let source = if sources.contains(&"Imported package list") {
            "Imported package list".to_string()
        } else {
            sources.join(" and ")
        };
        let walked = versioned.iter().any(|p| in_roots(p));
        let roots_json = json!(roots);
        let mut entries: Vec<(String, bool)> = if outside && !walked {
            vec![]
        } else {
            roots.iter().map(|r| (r.clone(), false)).collect()
        };
        if outside {
            entries.push((String::new(), true));
        }
        for (root, imported) in entries {
            let mut project = json!({"root":root,"scope":scope,"host":host,"inferred":inferred,"imported":imported,"roots":roots_json});
            let ids: HashSet<String> = if imported {
                outside_packages
                    .iter()
                    .map(|p| package_id(p).to_string())
                    .collect()
            } else {
                HashSet::new()
            };
            if imported {
                project["packages"] = json!(outside_packages
                    .iter()
                    .map(|p| package_id(p))
                    .collect::<Vec<_>>());
                project["source"] = json!(&source);
            }
            // The rule of `belongs_to_project`, on one finding's facts.
            let belongs = |f: &Fact| {
                f.host == host
                    && if inferred || f.health || f.path.is_empty() {
                        f.scope == Some(scope)
                    } else if imported {
                        ids.contains(&f.id)
                    } else {
                        f.lexical.starts_with(&root)
                    }
            };
            // Judge each finding, so a group mixing packages counts only this card's own.
            let mine: Vec<Value> = groups
                .iter()
                .zip(&facts)
                .filter_map(|((key, items), facts)| {
                    let own: Vec<Value> = items
                        .iter()
                        .zip(facts)
                        .filter(|(_, f)| belongs(f))
                        .map(|(i, _)| i.clone())
                        .collect();
                    (!own.is_empty()).then(|| grouped(key, &own))
                })
                .collect();
            let missing = !inferred && !imported && host == local && !Path::new(&root).exists();
            // The scan's own words about this folder, so an unconfirmed card says why.
            // Inside the root, or about the root itself ("ROOT: why").
            let about = |t: &str, root: &str| {
                t.strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with(['/', '\\']) || rest.starts_with(": "))
            };
            let mut problems: Vec<&str> = if missing || imported || root.is_empty() {
                vec![]
            } else {
                errors
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e["error"].as_str().or(e.as_str()))
                    .filter(|t| about(t, &root))
                    // A longer sibling root that also matches ("proj: evil" beside "proj") owns it.
                    .filter(|t| {
                        !roots.iter().any(|other| {
                            other.len() > root.len()
                                && !Path::new(other).starts_with(&root)
                                && about(t, other)
                        })
                    })
                    .collect()
            };
            // Nested roots save one error twice. Keep the first reason and how many distinct
            // ones there are; the card shows one line.
            let mut seen = HashSet::new();
            problems.retain(|t| seen.insert(*t));
            let problem_count = problems.len();
            problems.truncate(1);
            let nothing_checked = !imported
                && saved["packages"].as_array().is_some_and(Vec::is_empty)
                || (!inferred
                    && !imported
                    && !a(&saved, "packages").iter().any(|p| {
                        !s(p, "version").is_empty() && lexical(s(p, "path")).starts_with(&root)
                    }));
            let scan = scan_state(
                run,
                now,
                missing || nothing_checked || mine.iter().any(|i| i["type"] == "health"),
            );
            let open: usize = mine
                .iter()
                .filter(|i| i["type"] != "health")
                .map(|i| number(i, "count") as usize)
                .sum();
            let urgent = mine.iter().filter(|i| i["needs"] == true).count();
            let short: String = if scope.is_empty() { host } else { scope }
                .chars()
                .take(8)
                .collect();
            let name = if imported {
                format!("{source} {short}")
            } else if root.is_empty() {
                format!("Saved scan {short}")
            } else {
                Path::new(&root)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            };
            project.as_object_mut().unwrap().extend(
                json!({"name":name,"last":run,"scan":scan,"missing":missing,"nothing_checked":nothing_checked,"problems":problems,"problem_count":problem_count,"open":open,"urgent":urgent})
                    .as_object().unwrap().clone(),
            );
            let key = (
                host.to_string(),
                if inferred || root.is_empty() {
                    scope.to_string()
                } else {
                    root
                },
            );
            if by_root
                .get(&key)
                .is_none_or(|p: &Value| number(&p["last"], "finished") <= number(run, "finished"))
            {
                by_root.insert(key, project);
            }
        }
    }
    Ok(by_root.into_values().collect())
}
pub fn snapshot(state: &Path, now: f64, scopes: Option<&BTreeSet<String>>) -> Result<Value> {
    let db = Connection::open_with_flags(state.join("mail.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::from_secs(5))?;
    let tables: BTreeSet<_> = query(&db, "SELECT name FROM sqlite_master WHERE type='table'")?
        .iter()
        .map(|r| s(r, "name").to_string())
        .collect();
    for (name, cols) in [
        ("findings", "key TEXT,payload TEXT,active INTEGER"),
        (
            "messages",
            "id INTEGER,key TEXT,kind TEXT,payload TEXT,created REAL",
        ),
        ("readers", "name TEXT,cursor INTEGER"),
        (
            "receipts",
            "reader TEXT,message INTEGER,ack INTEGER,snooze REAL",
        ),
    ] {
        if !tables.contains(name) {
            db.execute_batch(&format!("CREATE TEMP TABLE {name}({cols})"))?;
        }
    }
    let has_scans = if tables.contains("scans") {
        number(
            &query(&db, "SELECT COUNT(*) AS count FROM scans")?[0],
            "count",
        ) > 0.
    } else {
        state.join("last-scan.json").exists()
    };
    let all_scopes = if tables.contains("asset_scopes") {
        query(&db, "SELECT scope FROM asset_scopes")?
            .iter()
            .map(|r| s(r, "scope").to_string())
            .collect()
    } else {
        BTreeSet::new()
    };
    let assets = crate::assets::summary(&db, Some(now), Some(scopes.unwrap_or(&all_scopes)))?;
    if scopes.is_some() {
        crate::assets::restrict(&db, &assets)?;
    }
    let local = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "localhost".into())
                .trim()
                .into()
        });
    let first: BTreeMap<_, _> = query(
        &db,
        "SELECT key,MIN(created) AS first_seen FROM messages GROUP BY key",
    )?
    .iter()
    .map(|r| (s(r, "key").to_string(), number(r, "first_seen")))
    .collect();
    let mut groups: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for row in query(&db, "SELECT key,payload FROM findings WHERE active=1")? {
        let mut f = load(&row["payload"]);
        if f.as_object().is_none_or(|o| o.is_empty()) {
            continue;
        }
        let host = if s(&f, "host").is_empty() {
            local.clone()
        } else {
            s(&f, "host").into()
        };
        f["host"] = json!(host);
        let key = group_key(&f, &host);
        let key = if s(&f, "scan_scope").is_empty() {
            key
        } else {
            format!("{}|{key}", s(&f, "scan_scope"))
        };
        groups.entry(key).or_default().push(f);
    }
    let grouped = |key: &str, items: &[Value]| {
        let seen = items
            .iter()
            .map(|i| first.get(s(i, "key")).copied().unwrap_or(now))
            .fold(now, f64::min);
        let mut result = issue(
            finding_type(&items[0]),
            s(&items[0], "host"),
            key,
            items,
            seen,
        );
        result["scan_scope"] = items[0]["scan_scope"].clone();
        result
    };
    let mut issues: Vec<_> = groups
        .iter()
        .map(|(key, items)| grouped(key, items))
        .collect();
    issues.sort_by(|x, y| {
        (
            x["kev"] != true,
            x["needs"] != true,
            x["type"] == "health",
            SEVERITIES
                .iter()
                .position(|s| *s == super::english::s(x, "severity")),
        )
            .cmp(&(
                y["kev"] != true,
                y["needs"] != true,
                y["type"] == "health",
                SEVERITIES
                    .iter()
                    .position(|s| *s == super::english::s(y, "severity")),
            ))
            .then_with(|| number(y, "epss").total_cmp(&number(x, "epss")))
            .then_with(|| number(y, "count").total_cmp(&number(x, "count")))
    });
    let mut scans: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    if tables.contains("scans") {
        for r in query(&db, "SELECT * FROM scans ORDER BY finished")? {
            scans.entry(s(&r, "host").into()).or_default().push(r);
        }
    } else {
        let last = state.join("last-scan.json");
        if last.exists() {
            let data = crate::repair::commands::read_json(&last)
                .unwrap_or(json!({"errors":["last-scan.json could not be read"]}));
            let finished = std::fs::metadata(last)?
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            if a(&assets, "scopes")
                .iter()
                .any(|scope| data.get("scan_scope") == Some(scope))
            {
                scans.insert(local.clone(),vec![json!({"host":local,"started":finished-number(&data,"seconds"),"finished":finished,"status":data.get("status").unwrap_or(&json!("unknown")),"seconds":data["seconds"],"findings":a(&data,"findings").len(),"errors":data.get("errors").unwrap_or(&json!([])).to_string()})]);
            }
        }
    }
    let projects = projects(&db, &tables, &scans, &groups, &grouped, now, &local)?;
    let names: BTreeSet<_> = scans
        .keys()
        .cloned()
        .chain(issues.iter().map(|i| s(i, "host").to_string()))
        .collect();
    let hosts:Vec<_>=names.into_iter().map(|host|{let runs=scans.get(&host).cloned().unwrap_or_default();let runs=runs[runs.len().saturating_sub(14)..].to_vec();let last=runs.last().cloned().unwrap_or(Value::Null);let mine:Vec<_>=issues.iter().filter(|i|i["host"]==host && i["type"]!="health").collect();let problems:BTreeSet<_>=issues.iter().filter(|i|i["host"]==host && i["type"]=="health").map(|i|s(i,"title")).collect();let scan=scan_state(&last,now,!problems.is_empty());let health=if mine.iter().any(|i|i["kev"]==true){"critical"}else if scan!="ok"||!mine.is_empty(){"warning"}else{"good"};json!({"host":host,"last":last,"runs":runs,"health":health,"scan":scan,"problems":problems,"open":mine.len(),"needs":mine.iter().filter(|i|i["needs"]==true).count()})}).collect();
    let mut hosts = hosts;
    for host in &mut hosts {
        if host["scan"] == "ok"
            && projects
                .iter()
                .any(|p| p["host"] == host["host"] && p["scan"] != "ok")
        {
            host["scan"] = json!("unconfirmed");
            if host["health"] == "good" {
                host["health"] = json!("warning");
            }
        }
    }
    let mut fixes = vec![];
    if tables.contains("fixes") {
        for r in query(&db,"SELECT x.*,f.payload FROM fixes x LEFT JOIN findings f ON f.key=x.key ORDER BY x.at DESC")?{let p=load(&r["payload"]);fixes.push(json!({"id":r["id"],"key":r["key"],"at":r["at"],"host":if s(&r,"host").is_empty(){s(&p,"host")}else{s(&r,"host")},"actor":if s(&r,"actor").is_empty(){"unknown"}else{s(&r,"actor")},"actor_kind":s(&r,"actor_kind"),"command":s(&r,"command"),"undo":s(&r,"undo"),"proof":r["proof_scan"],"what":fixed_title(&p),"eyebrow":describe(finding_type(&p),std::slice::from_ref(&p))["eyebrow"],"advisory":s(&p,"advisory")}));}
    } else {
        for r in query(
            &db,
            "SELECT id,payload,created FROM messages WHERE kind='closed' ORDER BY id DESC",
        )? {
            let p = load(&r["payload"]);
            if finding_type(&p) == "health" {
                continue;
            }
            fixes.push(json!({"id":r["id"],"key":p["key"],"at":r["created"],"host":if s(&p,"host").is_empty(){&local}else{s(&p,"host")},"actor":"re-scan","actor_kind":"","command":"","undo":"","proof":null,"what":fixed_title(&p),"eyebrow":describe(finding_type(&p),std::slice::from_ref(&p))["eyebrow"],"advisory":s(&p,"advisory")}));
        }
    }
    let mut hit: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for i in &issues {
        for adv in a(i, "advisories") {
            for id in std::iter::once(s(adv, "id"))
                .chain(a(adv, "aliases").iter().filter_map(Value::as_str))
            {
                hit.entry(id.into())
                    .or_default()
                    .insert(s(i, "host").into());
            }
        }
    }
    let feed = super::feed::saved(state, now, &hit)?;
    let news = feed["items"].clone();
    let mut delays = vec![];
    let mut by_type: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut buckets = vec![
        json!(["< 1 h", 0]),
        json!(["1-6 h", 0]),
        json!(["6-24 h", 0]),
        json!(["1-7 d", 0]),
        json!(["> 7 d", 0]),
    ];
    for r in query(
        &db,
        "SELECT payload,created FROM messages WHERE kind IN ('finding','changed') ORDER BY id",
    )? {
        let p = load(&r["payload"]);
        if let Some(published) = iso(s(&p, "published")) {
            let delay = number(&r, "created") - published;
            if delay >= 0. {
                delays.push(delay);
                by_type
                    .entry(finding_type(&p).into())
                    .or_default()
                    .push(delay);
                let k = [3600., 21600., 86400., 604800., f64::INFINITY]
                    .iter()
                    .position(|limit| delay < *limit)
                    .unwrap();
                buckets[k][1] = json!(buckets[k][1].as_u64().unwrap() + 1);
            }
        }
    }
    let mut by_type: Vec<_> = by_type
        .into_iter()
        .map(|(t, v)| json!([t, median(&v), v.len()]))
        .collect();
    by_type.sort_by(|a, b| {
        a[1].as_f64()
            .unwrap_or(0.)
            .total_cmp(&b[1].as_f64().unwrap_or(0.))
    });
    let speed = json!({"median":median(&delays),"count":delays.len(),"buckets":buckets,"delays":delays,"by_type":by_type});
    let mut spans: Vec<_> = issues
        .iter()
        .filter(|i| i["type"] != "health")
        .flat_map(|i| a(i, "keys"))
        .map(|k| {
            (
                first.get(k.as_str().unwrap_or("")).copied().unwrap_or(now),
                None,
            )
        })
        .collect();
    spans.extend(fixes.iter().filter_map(|f| {
        first
            .get(s(f, "key"))
            .map(|at| (*at, Some(number(f, "at"))))
    }));
    let start = now - 13. * 86400.;
    let counts: Vec<_> = (0..14)
        .map(|i| {
            let t = start + i as f64 * 86400.;
            spans
                .iter()
                .filter(|(a, b)| *a <= t && b.is_none_or(|b| b > t))
                .count()
        })
        .collect();
    let exposure = json!({"start":start,"counts":counts,"fixes":fixes.iter().filter(|f|number(f,"at")>=start && number(f,"at")<=now).collect::<Vec<_>>()});
    let mut weekly = vec![0; 8];
    for f in &fixes {
        let age = ((now - number(f, "at")) / 604800.).floor() as i64;
        if (0..8).contains(&age) {
            weekly[7 - age as usize] += 1;
        }
    }
    let receipt_columns = query(&db, "PRAGMA table_info(receipts)")?;
    let seen = if receipt_columns.iter().any(|r| r["name"] == "seen") {
        "COALESCE(x.seen,0)=0"
    } else {
        "m.id>r.cursor"
    };
    let readers=query(&db,&format!("SELECT r.name,r.cursor,(SELECT COUNT(*) FROM messages m LEFT JOIN receipts x ON x.message=m.id AND x.reader=r.name WHERE COALESCE(x.ack,0)=0 AND COALESCE(x.snooze,0)<={now} AND {seen}) AS unread,(SELECT COUNT(*) FROM receipts x WHERE x.reader=r.name AND x.ack=1) AS acked,(SELECT created FROM messages WHERE id=r.cursor) AS last_read FROM readers r ORDER BY r.name"))?;
    let mut bom = vec![];
    if tables.contains("bom") {
        let confidence = crate::assets::bom_records(a(&assets, "items"));
        for mut r in query(
            &db,
            "SELECT host,kind,name,version,source FROM bom ORDER BY host,kind,name",
        )? {
            let key = (
                s(&r, "host").into(),
                s(&r, "kind").into(),
                s(&r, "name").into(),
                s(&r, "version").into(),
                s(&r, "source").into(),
            );
            r["confidence"] = json!(confidence
                .get(&key)
                .map(String::as_str)
                .unwrap_or("unknown"));
            bom.push(r);
        }
    }
    let new_today = issues
        .iter()
        .filter(|i| i["type"] != "health" && now - number(i, "seen") < 86400.)
        .count();
    Ok(
        json!({"now":now,"has_scans":has_scans,"assets":assets,"projects":projects,"issues":issues,"hosts":hosts,"fixes":fixes,"fixes_weekly":weekly,"speed":speed,"bom":bom,"readers":readers,"news":news,"feed":feed,"new_today":new_today,"exposure":exposure}),
    )
}
fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    Some(if values.len().is_multiple_of(2) {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.
    } else {
        values[values.len() / 2]
    })
}
