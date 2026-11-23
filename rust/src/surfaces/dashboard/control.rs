use super::{
    data::{gid, query},
    english::*,
};
use crate::{
    policy::{Modes, ACTIONS},
    repair::{commands::read_json, digest, Repairs},
    Error, Result,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::Path};
pub fn config(path: Option<&Path>) -> Result<Value> {
    let data = path.map(read_json).transpose()?.unwrap_or(json!({}));
    if !data.is_object() {
        return Err(Error::new("fix config must be an object"));
    }
    Ok(data)
}
pub fn fleet(conf: &Value) -> Result<Modes> {
    if let Some(path) = conf["fleet"].as_str().filter(|p| Path::new(p).exists()) {
        Modes::load(Path::new(path))
    } else {
        Ok(Modes::default())
    }
}
pub fn fleet_note(conf: &Value) -> String {
    let Some(path) = conf["fleet"].as_str() else {
        return "Read-only: add \"fleet\" to the fix config to change modes here.".into();
    };
    if [Some("yaml"), Some("yml")].contains(&Path::new(path).extension().and_then(|s| s.to_str())) {
        format!(
            "Edit {} to change modes; the dashboard only writes JSON fleet files.",
            super::english::basename(path)
        )
    } else {
        String::new()
    }
}
fn summary(answers: &[Value]) -> String {
    let mode = s(&answers[0], "mode");
    let yes: Vec<_> = answers
        .iter()
        .zip(ACTIONS)
        .filter(|(r, _)| r["answer"] == "yes")
        .map(|(_, a)| a)
        .collect();
    let ask: Vec<_> = answers
        .iter()
        .zip(ACTIONS)
        .filter(|(r, _)| r["answer"] == "ask")
        .map(|(_, a)| a)
        .collect();
    if mode == "watch" {
        "Alerts only".into()
    } else if mode == "advise" || !ask.is_empty() && yes.is_empty() {
        "Fixes after your OK".into()
    } else if yes.is_empty() {
        "Changes nothing".into()
    } else if yes.len() == ACTIONS.len() {
        "Fixes on its own".into()
    } else {
        format!(
            "Fixes {} on its own{}",
            words(&yes),
            if ask.is_empty() {
                String::new()
            } else if yes.len() + ask.len() == ACTIONS.len() {
                "; asks for the rest".into()
            } else {
                format!("; asks for {}", words(&ask))
            }
        )
    }
}
fn words(actions: &[&str]) -> String {
    let actions: Vec<_> = actions
        .iter()
        .map(|s| match *s {
            "os-packages" => "system packages",
            "agent-tools" => "agent tools",
            s => s,
        })
        .collect();
    if actions.len() < 2 {
        actions.join("")
    } else {
        format!(
            "{} and {}",
            actions[..actions.len() - 1].join(", "),
            actions.last().unwrap()
        )
    }
}
pub fn drafts(state: &Path, modes: Option<&Modes>) -> Result<Vec<Value>> {
    if !state.join("repairs.db").exists() {
        return Ok(vec![]);
    }
    let db =
        Connection::open_with_flags(state.join("repairs.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let rows=query(&db,"SELECT d.item,d.payload,c.agent,c.status,c.approved,c.plan FROM drafts d LEFT JOIN claims c ON c.item=d.item WHERE d.dismissed=0 ORDER BY d.rowid DESC")?;
    let approvals = query(&db, "SELECT item,actor,kind,channel FROM approvals")?;
    let publications = query(
        &db,
        "SELECT item,payload FROM audit WHERE event='pr-opened' ORDER BY rowid",
    )?;
    let mut out = Vec::new();
    for r in rows {
        let Ok(d) = serde_json::from_str::<Value>(s(&r, "payload")) else {
            continue;
        };
        let plan = &d["changes"];
        if !plan.is_object() || !d["digest"].is_string() {
            continue;
        }
        let claimed = serde_json::from_str::<Value>(s(&r, "plan")).unwrap_or(Value::Null);
        let matches = claimed == *plan && digest(plan)? == s(&d, "digest");
        let item = s(&r, "item");
        let votes = approvals
            .iter()
            .filter(|a| {
                a["item"] == item
                    && modes.is_some_and(|m| {
                        m.approval_allowed(s(a, "actor"), s(a, "kind"), s(a, "channel"))
                    })
            })
            .count();
        // Apply and publish recount votes against the current fleet; the cached
        // claims.approved column only stands in when no fleet is configured.
        let approved = modes.map_or(r["approved"] == 1, |m| m.enough(votes));
        let status = if !matches {
            "stale"
        } else if r["status"] == "planned" {
            if approved {
                "approved"
            } else {
                "waiting"
            }
        } else if r["status"] == "verified" {
            "fixed"
        } else if [
            "applying",
            "denied",
            "failed",
            "rolled-back",
            "rollback-failed",
            "published",
            "pr-pushed",
        ]
        .contains(&s(&r, "status"))
        {
            s(&r, "status")
        } else {
            "stale"
        };
        let publication = publications
            .iter()
            .rev()
            .find(|p| p["item"] == item)
            .and_then(|p| serde_json::from_str::<Value>(s(p, "payload")).ok())
            .unwrap_or(json!({}));
        out.push(json!({"id":gid(&format!("draft:{item}")),"item":item,"agent":s(&r,"agent"),"state":status,"votes":votes,"needed":modes.map(|m|m.quorum()).unwrap_or(json!(1)),"digest":d["digest"],"kind":plan["kind"],"locked":plan.get("locked").is_some(),"publication":publication,"package":s(plan,"package"),"old":s(plan,"old"),"new":s(plan,"new"),"where":if plan["kind"]=="repo"{super::english::basename(s(plan,"root"))}else{String::new()},"why":s(&d,"why"),"risk":s(&d,"risk"),"test":if d["test_result"].is_string(){s(&d,"test_result").into()}else{d["test_result"].to_string()},"commands":if plan["kind"]=="repo"{String::new()}else{cmd(&plan["apply"])},"diff":s(&d,"diff"),"branch":s(&d,"branch"),"commit":s(&d,"commit"),"undo":cmd(plan.get("undo").unwrap_or(&d["undo"]))}));
    }
    Ok(out)
}
fn cmd(v: &Value) -> String {
    if v.is_array() {
        a(&json!({"v":v}), "v")
            .iter()
            .filter_map(Value::as_str)
            .map(super::super::advice::quote)
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        s(&json!({"v":v}), "v").into()
    }
}
pub fn augment(
    snapshot: &mut Value,
    state: &Path,
    config_path: Option<&Path>,
    writable: bool,
) -> Result<()> {
    let result = config(config_path).and_then(|c| fleet(&c).map(|m| (c, m)));
    let (conf, modes, error) = match result {
        Ok((c, m)) => (c, Some(m), String::new()),
        Err(e) => (json!({}), None, e.to_string()),
    };
    let mut machines: BTreeSet<String> = a(snapshot, "hosts")
        .iter()
        .map(|h| s(h, "host").into())
        .collect();
    let mut agents: BTreeSet<String> = a(snapshot, "readers")
        .iter()
        .map(|r| s(r, "name").into())
        .collect();
    if let Some(m) = &modes {
        machines.extend(
            m.data["machines"]
                .as_object()
                .into_iter()
                .flat_map(|o| o.keys())
                .cloned(),
        );
        agents.extend(
            m.data["agents"]
                .as_object()
                .into_iter()
                .flat_map(|o| o.keys())
                .cloned(),
        );
    }
    machines.remove("");
    agents.remove("");
    agents.remove("*");
    let machines: Vec<_> = machines.into_iter().collect();
    let agents: Vec<_> = agents.into_iter().collect();
    let mut rows = Vec::new();
    let mut matrix = Vec::new();
    if let Some(m) = &modes {
        for (scope, name) in std::iter::once(("fleet", "".to_string()))
            .chain(machines.iter().cloned().map(|s| ("machine", s)))
            .chain(agents.iter().cloned().map(|s| ("agent", s)))
        {
            let agent = if scope == "agent" { name.as_str() } else { "*" };
            let machine = if scope == "machine" {
                Some(name.as_str())
            } else {
                None
            };
            let answers = ACTIONS
                .iter()
                .map(|a| m.can(agent, a, machine, None))
                .collect::<Result<Vec<_>>>()?;
            let mode = s(&answers[0], "mode");
            let own = if scope == "fleet" {
                m.data["mode"].as_str()
            } else {
                m.data[format!("{scope}s")][&name]["mode"].as_str()
            };
            let mut why = if own.is_some_and(|s| s != mode) {
                format!("Held at {} by policy", super::views::capitalize(mode))
            } else {
                summary(&answers)
            };
            let mut extras = Vec::new();
            if scope != "agent" {
                for other in &agents {
                    let mut more = Vec::new();
                    for (a, answer) in ACTIONS.iter().zip(&answers) {
                        if answer["answer"] != "yes"
                            && m.can(other, a, machine, None)?["answer"] == "yes"
                        {
                            more.push(*a);
                        }
                    }
                    if !more.is_empty() {
                        extras.push(format!(
                            "{other} can still fix {}{}",
                            words(&more),
                            if machine.is_some() { " here" } else { "" }
                        ));
                    }
                }
            }
            if scope != "fleet"
                && own.is_none()
                && rows
                    .first()
                    .is_some_and(|r: &Value| r["mode"] == mode && r["why"] == why)
                && (scope == "agent" || extras.is_empty())
            {
                why = "Same as the fleet".into();
                extras.clear();
            }
            if !extras.is_empty() {
                why.push_str(&format!(", but {}", extras.join("; ")));
            }
            rows.push(json!({"scope":scope,"name":name,"mode":mode,"why":why}));
        }
        for agent in agents
            .iter()
            .map(String::as_str)
            .chain(std::iter::once("*"))
        {
            let mut cells = Vec::new();
            for host in &machines {
                let answers = ACTIONS
                    .iter()
                    .map(|a| m.can(agent, a, Some(host), None))
                    .collect::<Result<Vec<_>>>()?;
                let yes = answers.iter().find(|a| a["answer"] == "yes");
                let ask = answers.iter().find(|a| a["answer"] == "ask");
                let first = &answers[0];
                let (word, rule) = if let Some(yes) = yes {
                    ("Fixes", yes)
                } else if first["mode"] == "watch" {
                    ("Watch", first)
                } else if ask.is_some() || first["mode"] == "advise" {
                    ("Asks", ask.unwrap_or(first))
                } else {
                    ("Never", first)
                };
                let why = s(rule, "why")
                    .replace("agents:*", "all agents")
                    .replace("agents:", "agent ")
                    .replace("machines:", "machine ")
                    .replace("groups:", "group ");
                cells.push(json!([word, super::views::capitalize(&why)]));
            }
            matrix.push(json!([agent, cells]));
        }
    }
    let mut drafts = drafts(state, modes.as_ref()).unwrap_or_default();
    for d in &mut drafts {
        let issue = a(snapshot, "issues")
            .iter()
            .find(|i| a(i, "keys").contains(&d["item"]));
        d["host"] = json!(issue.map(|i| s(i, "host")).unwrap_or(""));
        d["title"] = json!(format!(
            "Update {}{}",
            s(d, "package"),
            if !s(d, "where").is_empty() {
                format!(" in {}", s(d, "where"))
            } else if !s(d, "host").is_empty() {
                format!(" on {}", s(d, "host"))
            } else {
                String::new()
            }
        ));
        d["finding"] = json!(issue.map(|i| s(i, "id")).unwrap_or(""));
        if let Some(issue) = issue {
            if let Some(adv) = a(issue, "advisories")
                .iter()
                .find(|a| a["key"] == d["item"])
            {
                d["why"] = json!(format!(
                    "Fixes {} in {} on {}. {}",
                    s(adv, "id"),
                    s(d, "package"),
                    s(d, "host"),
                    s(issue, "why")
                )
                .trim());
            }
        }
        if d["state"] == "approved" {
            let permission = modes
                .as_ref()
                .map(|m| {
                    m.can(
                        s(d, "agent"),
                        if d["kind"] == "repo" {
                            "lockfiles"
                        } else {
                            "os-packages"
                        },
                        conf["machine"].as_str(),
                        conf["group"].as_str(),
                    )
                })
                .transpose()?;
            let reason = if !writable || config_path.is_none() {
                "Read-only: restart the dashboard with --allow-writes and a fix config.".into()
            } else if permission.as_ref().is_some_and(|p| p["answer"] == "no") {
                s(permission.as_ref().unwrap(), "why").into()
            } else if modes
                .as_ref()
                .is_some_and(|m| !m.enough(number(d, "votes") as usize))
            {
                "The current approval quorum has not been met.".into()
            } else {
                error.clone()
            };
            d["action_reason"] = json!(reason);
            d["publish_reason"] = json!(if d["kind"] != "repo" || d["locked"] == true {
                "Open PR supports npm manifest drafts only.".to_string()
            } else if !reason.is_empty() {
                reason
            } else {
                github_ready()
            });
        }
    }
    let default = rows.first().map(|r| s(r, "mode")).unwrap_or("advise");
    for issue in snapshot["issues"].as_array_mut().unwrap() {
        issue["mode"] = json!(rows
            .iter()
            .find(|r| r["scope"] == "machine" && r["name"] == issue["host"])
            .map(|r| s(r, "mode"))
            .unwrap_or(default));
        issue["draft"] = drafts
            .iter()
            .find(|d| d["state"] == "waiting" && a(issue, "keys").contains(&d["item"]))
            .cloned()
            .unwrap_or(Value::Null);
        issue["needs"] = json!(issue["needs"] == true || !issue["draft"].is_null());
    }
    snapshot["issues"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|i| (i["kev"] != true, i["needs"] != true));
    snapshot["can_decide"] = json!(
        writable
            && config_path.is_some()
            && modes.as_ref().is_some_and(|m| super::super::reviewer(m)
                .is_ok_and(|actor| m.approval_allowed(&actor, "human", "dashboard")))
    );
    snapshot["control_error"] = json!(error);
    snapshot["fleet_note"] = json!(if modes.is_some() {
        fleet_note(&conf)
    } else {
        String::new()
    });
    snapshot["modes"] = json!(rows);
    snapshot["matrix"] = json!(matrix);
    snapshot["known"] = json!([machines, agents]);
    snapshot["drafts"] = json!(drafts);
    snapshot["repairs_on"] = json!(config_path.is_some());
    snapshot["conf"] = conf;
    let exe = std::env::current_exe()?;
    snapshot["fix_cli"] = json!(format!(
        "{} --state {} repair --config {}",
        super::super::advice::quote(&exe.to_string_lossy()),
        super::super::advice::quote(&state.to_string_lossy()),
        super::super::advice::quote(
            &config_path
                .unwrap_or(Path::new("FIX.json"))
                .to_string_lossy()
        )
    ));
    Ok(())
}
pub fn github_ready() -> String {
    use crate::repair::commands::*;
    if run(
        &strings(&["gh", "auth", "status", "--hostname", "github.com"]),
        None,
    )
    .is_ok()
    {
        String::new()
    } else {
        "Install and authenticate the GitHub CLI to open a PR.".into()
    }
}
pub fn write(state: &Path, config_path: Option<&Path>, path: &str, form: &Value) -> Result<String> {
    let config_path = config_path.ok_or_else(|| Error::rejected(403, "fix config is required"))?;
    let conf = config(Some(config_path))?;
    if path == "/mode" {
        let note = fleet_note(&conf);
        if !note.is_empty() {
            return Err(Error::new(note));
        }
        let mut snapshot = super::data::snapshot(state, crate::store::now(), None)?;
        augment(&mut snapshot, state, Some(config_path), true)?;
        let scope = s(form, "scope");
        let name = s(form, "name");
        let mut m = fleet(&conf)?;
        let known = &snapshot["known"];
        let (machine, agent) = match scope {
            "fleet" => (None, None),
            "machine" if a(&json!({"x":&known[0]}), "x").contains(&json!(name)) => {
                (Some(name), None)
            }
            "agent" if a(&json!({"x":&known[1]}), "x").contains(&json!(name)) => (None, Some(name)),
            _ => return Err(Error::new("unknown machine or agent")),
        };
        m.set_mode(s(form, "mode"), machine, agent, true)?;
        Modes::new(m.data.clone())?;
        crate::store::atomic(
            Path::new(s(&conf, "fleet")),
            &format!("{}\n", serde_json::to_string_pretty(&m.data)?),
        )?;
        return Ok("/policy".into());
    }
    let mut repairs = Repairs::open(state, config_path)?;
    let item = super::super::text(form, "item")?;
    let reviewed = super::super::text(form, "digest")?;
    let actor = super::super::reviewer(&repairs.fleet()?)?;
    if !repairs
        .fleet()?
        .approval_allowed(&actor, "human", "dashboard")
    {
        return Err(Error::rejected(403, "reviewer or channel is not permitted"));
    }
    let row = repairs.row(item)?;
    let draft = repairs
        .drafts()?
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["item"] == item)
        .cloned()
        .ok_or_else(|| Error::new("an active draft is required"))?;
    if row["status"] != "planned"
        || draft["changes"] != row["plan"]
        || draft["digest"] != reviewed
        || digest(&row["plan"])? != reviewed
    {
        return Err(Error::rejected(
            403,
            "draft changed; reload and review again",
        ));
    }
    match (path, s(form, "decision")) {
        ("/review", "approve") => {
            repairs.approve(item, true, &actor, "dashboard", reviewed)?;
        }
        ("/review", "dismiss") => {
            if repairs.fleet()?.enough(repairs.approval_count(item)?) {
                return Err(Error::rejected(
                    403,
                    "only a draft awaiting approval may be dismissed",
                ));
            }
            repairs.dispatch("dismiss",&json!({"item":item,"agent":row["agent"],"reason":format!("dismissed by {actor} in dashboard: {}",s(form,"reason")).chars().take(500).collect::<String>()}))?;
        }
        ("/repair", "apply") => {
            if !repairs.fleet()?.enough(repairs.approval_count(item)?) {
                return Err(Error::rejected(403, "approval quorum is required"));
            }
            repairs.dispatch(
                "apply",
                &json!({"item":item,"agent":row["agent"],"dry_run":false}),
            )?;
        }
        ("/repair", "publish") => {
            crate::repair::publish::publish(
                &repairs,
                item,
                reviewed,
                s(form, "repository"),
                s(form, "base"),
                s(form, "branch"),
            )?;
        }
        _ => return Err(Error::new("unknown decision")),
    }
    Ok(format!("/review/{}", gid(&format!("draft:{item}"))))
}
