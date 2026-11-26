pub mod browser;
pub mod commands;
pub mod locked;
pub mod publish;
use crate::{
    domain::{InventoryOptions, ScanOptions},
    policy::{Modes, Policy},
    store::Store,
    Error, Result,
};
use commands::*;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

pub fn digest(plan: &Value) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(crate::store::python_json(plan, true)?.as_bytes())
    ))
}
fn policy_action(plan: &Value) -> &'static str {
    if plan["kind"] == "repo" {
        "patch"
    } else {
        "os-upgrade"
    }
}

fn draft_bytes(root: &Path, depth: usize) -> Result<u64> {
    if depth > 64 {
        return Err(Error::new(
            "draft source nesting exceeds storage admission limit",
        ));
    }
    let mut bytes = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let size = if metadata.is_dir() {
            draft_bytes(&entry.path(), depth + 1)?
        } else {
            metadata.len().max(4096)
        };
        bytes = bytes
            .checked_add(size + 4096)
            .ok_or_else(|| Error::new("draft storage size overflowed"))?;
        if bytes > 64 * 1024 * 1024 {
            return Err(Error::new(
                "draft source exceeds 64MiB admission limit; use manual repair",
            ));
        }
    }
    Ok(bytes)
}

pub struct Repairs {
    pub state: PathBuf,
    pub config: Value,
    pub db: Connection,
    pub changes: usize,
}
impl Repairs {
    pub fn open(state: &Path, config: &Path) -> Result<Self> {
        let mut config = read_json(config)?;
        field(&config, "policy")?;
        let mut repositories = json!({});
        if let Some(roots) = config.get("repositories") {
            for (root, check) in roots
                .as_object()
                .ok_or_else(|| Error::new("repositories must be a mapping"))?
            {
                vector(check)?;
                repositories[fs::canonicalize(root)?.to_string_lossy().as_ref()] = check.clone();
            }
        }
        config["repositories"] = repositories;
        crate::store::private_dir(state)?;
        crate::store::storage_admit(state, 4 * 1024 * 1024)?;
        let db = Connection::open(state.join("repairs.db"))?;
        let page_size: u64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        db.pragma_update(None, "max_page_count", (256 * 1024 * 1024_u64) / page_size)?;
        db.busy_timeout(Duration::from_secs(30))?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS claims(item TEXT PRIMARY KEY,agent TEXT,status TEXT,plan TEXT,approved INTEGER DEFAULT 0,proof TEXT);CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,item TEXT,event TEXT,payload TEXT,created REAL);CREATE TABLE IF NOT EXISTS drafts(item TEXT PRIMARY KEY,payload TEXT,dismissed INTEGER DEFAULT 0);CREATE TABLE IF NOT EXISTS approvals(item TEXT,actor TEXT,kind TEXT,channel TEXT,PRIMARY KEY(item,actor,kind));")?;
        Ok(Self {
            state: state.into(),
            config,
            db,
            changes: 0,
        })
    }
    pub fn fleet(&self) -> Result<Modes> {
        if let Some(path) = self.config.get("fleet").and_then(Value::as_str) {
            Modes::load(Path::new(path))
        } else {
            Ok(Modes::default())
        }
    }
    pub fn policy(&self) -> Result<Policy> {
        Policy::load(Path::new(field(&self.config, "policy")?))
    }
    pub fn audit(&self, item: &str, event: &str, payload: &Value) -> Result<()> {
        crate::store::storage_admit(&self.state, payload.to_string().len() as u64 * 2 + 65536)?;
        self.db.execute(
            "INSERT INTO audit(item,event,payload,created) VALUES(?,?,?,?)",
            params![item, event, payload.to_string(), crate::store::now()],
        )?;
        Ok(())
    }
    pub fn row(&self, item: &str) -> Result<Value> {
        self.db.query_row("SELECT agent,status,plan,approved,proof FROM claims WHERE item=?",[item],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,bool>(3)?,r.get::<_,Option<String>>(4)?))).optional()?.map(|(agent,status,plan,approved,proof)|->Result<Value>{Ok(json!({"agent":agent,"status":status,"plan":plan.map(|s|serde_json::from_str::<Value>(&s)).transpose()?,"approved":approved,"proof":proof.map(|s|serde_json::from_str::<Value>(&s)).transpose()?}))}).transpose()?.ok_or_else(||Error::rejected(403,"claim owner is required"))
    }
    pub fn owned(&self, item: &str, agent: &str) -> Result<Value> {
        let row = self.row(item)?;
        if row["agent"] != agent {
            return Err(Error::rejected(403, "claim owner is required"));
        }
        Ok(row)
    }
    pub fn can(&self, agent: &str, action: &str) -> Result<Value> {
        self.fleet()?.can(
            agent,
            action,
            self.config["machine"].as_str(),
            self.config["group"].as_str(),
        )
    }
    pub fn approval_count(&self, item: &str) -> Result<usize> {
        let modes = self.fleet()?;
        let mut stmt = self
            .db
            .prepare("SELECT actor,kind,channel FROM approvals WHERE item=?")?;
        let rows = stmt.query_map([item], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut count = 0;
        for row in rows {
            let (a, k, c) = row?;
            count += usize::from(modes.approval_allowed(&a, &k, &c));
        }
        Ok(count)
    }
    pub fn validate(&self, item: &str, plan: &Value) -> Result<Value> {
        let store = Store::open(&self.state)?;
        let payload: Option<String> = store
            .db
            .query_row(
                "SELECT payload FROM findings WHERE key=? AND active=1",
                [item],
                |r| r.get(0),
            )
            .optional()?;
        let finding: Value = serde_json::from_str(
            &payload.ok_or_else(|| Error::new("an active finding is required"))?,
        )?;
        let package = &finding["package"];
        if package["name"] != plan["package"] || package["version"] != plan["old"] {
            return Err(Error::new("plan package/version does not match finding"));
        }
        if plan["kind"] == "repo" {
            let filename = if plan.get("locked").is_some() {
                "package-lock.json"
            } else {
                "package.json"
            };
            if package["ecosystem"] != "npm"
                || fs::canonicalize(field(package, "path")?)?
                    != Path::new(field(plan, "root")?).join(filename)
            {
                return Err(Error::new("finding is not in the repaired manifest"));
            }
        } else if package["path"] != "dpkg-query"
            || !field(package, "ecosystem")?.starts_with("Debian:")
                && !field(package, "ecosystem")?.starts_with("Ubuntu:")
        {
            return Err(Error::new("apt plans require a local dpkg finding"));
        }
        Ok(finding)
    }
    pub fn generated_plan(&self, request: &Value) -> Result<Value> {
        if request["kind"] == "os" {
            return os_plan(
                field(request, "manager")?,
                field(request, "package")?,
                field(request, "old")?,
                field(request, "new")?,
            );
        }
        if request["kind"] != "repo" {
            return Err(Error::new("unsupported repair kind"));
        }
        let root = fs::canonicalize(field(request, "root")?)?;
        let check = self.config["repositories"]
            .get(root.to_string_lossy().as_ref())
            .ok_or_else(|| {
                Error::rejected(403, "repository and check must be configured by host")
            })?;
        if request.get("check").is_some_and(|v| v != check) {
            return Err(Error::rejected(
                403,
                "check command must be configured by host",
            ));
        }
        let locked = if request.get("locked").is_some() {
            Some(self.locked_plan(&root, field(request, "package")?, field(request, "new")?)?)
        } else {
            None
        };
        repo_plan(
            &root,
            field(request, "package")?,
            field(request, "old")?,
            field(request, "new")?,
            check,
            locked.as_ref(),
        )
    }
    pub fn locked_plan(&self, root: &Path, package: &str, new: &str) -> Result<Value> {
        let candidate = locked::resolve(
            root,
            package,
            new,
            &self.policy()?,
            self.config.get("runtime"),
            |clone| {
                let temp = tempfile::tempdir()?;
                let mut store = Store::open(temp.path())?;
                let options = ScanOptions {
                    inventory: InventoryOptions {
                        roots: vec![clone.join("package-lock.json")],
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let result = Value::Object(crate::cli::check(&options, &mut store)?);
                let complete = result["coverage_evidence"]["status"] == "complete"
                    && result["errors"].as_array().is_some_and(|e| e.is_empty());
                Ok(
                    json!({"coverage":if complete{"complete"}else{"unknown"},"findings":result["findings"]}),
                )
            },
        )?;
        if candidate["status"] != "resolved"
            || candidate["findings"].as_array().is_none_or(|f| {
                f.iter()
                    .any(|finding| finding["package"]["name"] == package)
            })
        {
            return Err(Error::new(format!(
                "locked resolution refused: {}",
                candidate["errors"]
            )));
        }
        Ok(
            json!({"before":{"package.json":fs::read_to_string(root.join("package.json"))?,"package-lock.json":fs::read_to_string(root.join("package-lock.json"))?},"after":{"package.json":format!("{}\n",serde_json::to_string_pretty(&candidate["manifest"])?),"package-lock.json":format!("{}\n",serde_json::to_string_pretty(&candidate["lockfile"])?)},"package_delta":candidate["package_delta"]}),
        )
    }
    pub fn draft(&self, item: &str, agent: &str) -> Result<Value> {
        let row = self.owned(item, agent)?;
        if row["status"] != "planned" {
            return Err(Error::new("a planned repair is required"));
        }
        if self.can(agent, "config")?["mode"] == "watch" {
            return Err(Error::rejected(403, "watch mode does not suggest changes"));
        }
        let prior: Option<(String, bool)> = self
            .db
            .query_row(
                "SELECT payload,dismissed FROM drafts WHERE item=?",
                [item],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let plan = &row["plan"];
        let mut replaced = None;
        if let Some((payload, dismissed)) = prior {
            let draft: Value = serde_json::from_str(&payload)?;
            if draft["changes"] == *plan {
                if dismissed {
                    return Err(Error::rejected(403, "draft was dismissed or changed"));
                }
                return Ok(draft);
            }
            if !dismissed {
                return Err(Error::rejected(403, "draft was dismissed or changed"));
            }
            // A dismissed draft refuses only its own plan; a different plan replaces it.
            replaced = Some(draft["digest"].clone());
        }
        if self.was_dismissed(item, &digest(plan)?)? {
            return Err(Error::rejected(403, "draft was dismissed or changed"));
        }
        if self.policy()?.decision(
            field(plan, "package")?,
            policy_action(plan),
            &json!(1),
            None,
        ) == "deny"
        {
            return Err(Error::rejected(403, "policy denies draft"));
        }
        let mut draft = json!({"item":item,"changes":plan,"why":"Repair claimed vulnerability","risk":"Runs host-configured checks and changes one dependency","undo":plan.get("undo"),"digest":digest(plan)?});
        if plan["kind"] == "repo" {
            let source = Path::new(field(plan, "root")?);
            if source.join(".git/objects/info/alternates").exists()
                || !run(
                    &strings(&[
                        "git",
                        "config",
                        "--get-regexp",
                        "^(extensions\\.partialclone|remote\\..*\\.promisor)$",
                    ]),
                    Some(source),
                )
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(Error::new(
                    "draft storage cannot admit alternate or partial repositories",
                ));
            }
            let reserve = draft_bytes(source, 0)?
                .checked_mul(2)
                .and_then(|n| n.checked_add(4 * 1024 * 1024))
                .ok_or_else(|| Error::new("draft storage size overflowed"))?;
            crate::store::storage_admit(&self.state, reserve)?;
            let scratch = self
                .state
                .join(format!("draft-{}", uuid::Uuid::new_v4().simple()));
            crate::store::private_dir(&scratch)?;
            let target = scratch.join("repo");
            let source = clone_source(field(plan, "root")?)?;
            let destination = clone_source(&target.to_string_lossy())?;
            run(
                &strings(&[
                    "git",
                    "clone",
                    "--no-hardlinks",
                    "--no-checkout",
                    "--",
                    &source,
                    &destination,
                ]),
                None,
            )?;
            for key in ["user.name", "user.email"] {
                let value = identity(Path::new(field(plan, "root")?), key)?;
                run(
                    &strings(&["git", "config", "--local", key, &value]),
                    Some(&target),
                )?;
            }
            run(
                &strings(&["git", "checkout", "-b", "draft-base", field(plan, "head")?]),
                Some(&target),
            )?;
            let copy = repo_plan(
                &target,
                field(plan, "package")?,
                field(plan, "old")?,
                field(plan, "new")?,
                &plan["check"],
                plan.get("locked"),
            )?;
            let outcome = apply_repo(
                &copy,
                &format!("vorda/draft-{}", uuid::Uuid::new_v4().simple()),
            )?;
            draft["repository"] = json!(target);
            draft["branch"] = outcome["branch"].clone();
            draft["commit"] =
                json!(run(&strings(&["git", "rev-parse", "HEAD"]), Some(&target))?.trim());
            draft["diff"] = json!(run(
                &strings(&[
                    "git",
                    "diff",
                    "--no-textconv",
                    "--no-ext-diff",
                    field(plan, "head")?,
                    "HEAD",
                    "--",
                    "package.json",
                    "package-lock.json"
                ]),
                Some(&target)
            )?);
            draft["test_result"] = json!("passed");
            draft["undo"] = json!(["git", "switch", "draft-base"]);
        } else {
            draft["test_result"] = json!(os_dry_run(plan)?);
        }
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        if let Some(old) = &replaced {
            self.db
                .execute("DELETE FROM drafts WHERE item=? AND dismissed=1", [item])?;
            self.audit(item, "dismissed-draft-replaced", &json!({"digest":old}))?;
        }
        self.db.execute(
            "INSERT INTO drafts(item,payload) VALUES(?,?)",
            params![item, draft.to_string()],
        )?;
        self.audit(item, "draft", &draft)?;
        self.db.execute_batch("COMMIT")?;
        Ok(draft)
    }
    /// A dismissed plan stays refused after its draft row is replaced or released.
    fn was_dismissed(&self, item: &str, plan_digest: &str) -> Result<bool> {
        let mut stmt = self.db.prepare(
            "SELECT payload FROM audit WHERE item=? AND event IN ('dismiss','dismissed-draft-replaced')",
        )?;
        let payloads = stmt
            .query_map([item], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(payloads
            .iter()
            .any(|p| serde_json::from_str::<Value>(p).is_ok_and(|v| v["digest"] == plan_digest)))
    }
    /// Operator recovery for claims that otherwise have no exit. The claim becomes
    /// `failed` (then releasable); the prior status stays in the audit trail.
    pub fn recover(&self, item: &str, operator: &str, os_user: &str) -> Result<Value> {
        let result = (|| {
            if !self.fleet()?.is_human(operator) {
                return Err(Error::rejected(403, "reviewer is not permitted"));
            }
            self.db.execute_batch("BEGIN IMMEDIATE")?;
            let row = self.row(item)?;
            let from = row["status"].as_str().unwrap_or_default().to_string();
            if !["applying", "rollback-failed", "pr-pushed"].contains(&from.as_str()) {
                return Err(Error::new(
                    "only an applying, rollback-failed or pr-pushed claim can be recovered",
                ));
            }
            self.db
                .execute("UPDATE claims SET status='failed' WHERE item=?", [item])?;
            self.audit(
                item,
                "recover",
                &json!({"operator":operator,"os_user":os_user,"from":from}),
            )?;
            self.db.execute_batch("COMMIT")?;
            Ok(json!({"item":item,"status":"failed","recovered_from":from}))
        })();
        self.finish(item, "recover", result)
    }
    pub fn drafts(&self) -> Result<Value> {
        let mut stmt = self
            .db
            .prepare("SELECT payload FROM drafts WHERE dismissed=0")?;
        let values = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .map(|s| -> Result<Value> { Ok(serde_json::from_str(&s?)?) })
            .collect::<Result<Vec<_>>>()?;
        Ok(json!(values))
    }
    pub fn approve(
        &self,
        item: &str,
        allow: bool,
        actor: &str,
        channel: &str,
        reviewed: &str,
    ) -> Result<Value> {
        let result = (|| {
            self.db.execute_batch("BEGIN IMMEDIATE")?;
            let modes = self.fleet()?;
            if !modes.approval_allowed(actor, "human", channel) {
                return Err(Error::rejected(403, "reviewer or channel is not permitted"));
            }
            let row = self.row(item)?;
            if row["status"] != "planned" {
                return Err(Error::new("there is no planned repair"));
            }
            if digest(&row["plan"])? != reviewed {
                return Err(Error::rejected(
                    403,
                    "approval must name the reviewed plan digest",
                ));
            }
            if allow {
                self.db.execute(
                    "INSERT OR REPLACE INTO approvals VALUES(?,?,?,?)",
                    params![item, actor, "human", channel],
                )?;
            } else {
                self.db
                    .execute("DELETE FROM approvals WHERE item=?", [item])?;
            }
            let approved = allow && modes.enough(self.approval_count(item)?);
            self.db.execute(
                "UPDATE claims SET approved=?,status=? WHERE item=?",
                params![approved, if allow { "planned" } else { "denied" }, item],
            )?;
            self.audit(
                item,
                if allow { "approve" } else { "deny" },
                &json!({"actor":actor,"kind":"human","channel":channel}),
            )?;
            self.db.execute_batch("COMMIT")?;
            Ok(json!({"item":item,"approved":approved,"plan":row["plan"]}))
        })();
        self.finish(item, "approve", result)
    }
    fn finish(&self, item: &str, stage: &str, result: Result<Value>) -> Result<Value> {
        if let Err(e) = &result {
            let _ = self.db.execute_batch("ROLLBACK");
            self.audit(
                item,
                "refused",
                &json!({"stage":stage,"error":e.to_string()}),
            )?;
        }
        result
    }
    pub fn dispatch(&mut self, name: &str, args: &Value) -> Result<Value> {
        let item = args["item"].as_str().unwrap_or("");
        let agent = args["agent"].as_str().unwrap_or("");
        let result = (|| -> Result<Value> {
            match name {
                "claim" => {
                    if item.is_empty() || agent.is_empty() {
                        return Err(Error::new("item and agent are required"));
                    }
                    self.db.execute_batch("BEGIN IMMEDIATE")?;
                    self.db.execute(
                        "INSERT INTO claims(item,agent,status) VALUES(?,?,'claimed')",
                        params![item, agent],
                    )?;
                    self.audit(item, "claim", &json!({"agent":agent}))?;
                    self.db.execute_batch("COMMIT")?;
                    Ok(json!({"status":"claimed"}))
                }
                "can" => self.can(agent, field(args, "action")?),
                "drafts" => self.drafts(),
                "draft" => self.draft(item, agent),
                "plan" => {
                    let plan = &args["plan"];
                    let expected = self.generated_plan(plan)?;
                    if &expected != plan {
                        return Err(Error::new("plan differs from the generated plan"));
                    }
                    self.validate(item, plan)?;
                    let decision = self.policy()?.decision(
                        field(plan, "package")?,
                        policy_action(plan),
                        &json!(1),
                        None,
                    );
                    self.audit(item, "policy", &json!({"decision":decision}))?;
                    if decision == "deny" {
                        return Err(Error::rejected(403, "policy denies repair"));
                    }
                    self.db.execute_batch("BEGIN IMMEDIATE")?;
                    if self.owned(item, agent)?["status"] != "claimed" {
                        return Err(Error::new("claim is not awaiting a plan"));
                    }
                    self.db.execute(
                        "UPDATE claims SET status='planned',plan=?,approved=0 WHERE item=?",
                        params![plan.to_string(), item],
                    )?;
                    self.db.execute_batch("COMMIT")?;
                    Ok(json!({"status":"planned","decision":decision,"plan":plan}))
                }
                "verify" => {
                    let row = self.owned(item, agent)?;
                    Ok(json!({"status":row["status"],"proof":row["proof"]}))
                }
                "release" => {
                    self.db.execute_batch("BEGIN IMMEDIATE")?;
                    let row = self.owned(item, agent)?;
                    if ["applying", "rollback-failed", "pr-pushed"]
                        .iter()
                        .any(|s| row["status"] == *s)
                    {
                        return Err(Error::new("repair requires recovery before release"));
                    }
                    self.db.execute("DELETE FROM claims WHERE item=?", [item])?;
                    self.db
                        .execute("DELETE FROM approvals WHERE item=?", [item])?;
                    self.db
                        .execute("DELETE FROM drafts WHERE item=? AND dismissed=0", [item])?;
                    self.audit(item, "release", &json!({"agent":agent}))?;
                    self.db.execute_batch("COMMIT")?;
                    Ok(json!({"status":"released"}))
                }
                "dismiss" => {
                    self.db.execute_batch("BEGIN IMMEDIATE")?;
                    let row = self.owned(item, agent)?;
                    if row["status"] != "planned" {
                        return Err(Error::new("only a planned draft can be dismissed"));
                    }
                    if self.db.execute(
                        "UPDATE drafts SET dismissed=1 WHERE item=? AND dismissed=0",
                        [item],
                    )? != 1
                    {
                        return Err(Error::new("there is no active draft"));
                    }
                    self.db
                        .execute("UPDATE claims SET status='dismissed' WHERE item=?", [item])?;
                    self.audit(
                        item,
                        "dismiss",
                        &json!({"agent":agent,"reason":args["reason"],"digest":digest(&row["plan"])?}),
                    )?;
                    self.db.execute_batch("COMMIT")?;
                    Ok(json!({"status":"dismissed"}))
                }
                "apply" => {
                    let dry_run = args
                        .get("dry_run")
                        .unwrap_or(&Value::Bool(true))
                        .as_bool()
                        .ok_or_else(|| Error::new("dry_run must be boolean"))?;
                    self.apply_inner(item, agent, dry_run)
                }
                _ => Err(Error::new("unknown MCP repair tool")),
            }
        })();
        self.finish(item, name, result)
    }
    fn rescan(&self, item: &str, plan: &Value) -> Result<Value> {
        let mut store = Store::open(&self.state)?;
        let _lock = store.locked()?;
        let finding = self.validate(item, plan)?;
        let mut package: crate::domain::Package =
            serde_json::from_value(finding["package"].clone())?;
        if plan["kind"] == "repo" {
            let manifest = read_json(&Path::new(field(plan, "root")?).join("package.json"))?;
            package.version =
                field(&manifest[field(plan, "section")?], field(plan, "package")?)?.into();
        } else {
            let inventory = crate::scanner::inventory(&InventoryOptions {
                os_packages: true,
                ..Default::default()
            })?;
            let packages: Vec<crate::domain::Package> =
                serde_json::from_value(inventory["packages"].clone())?;
            let matches: Vec<_> = packages
                .into_iter()
                .filter(|p| {
                    p.name == package.name
                        && p.path == "dpkg-query"
                        && p.ecosystem == package.ecosystem
                })
                .collect();
            if inventory["errors"].as_array().is_none_or(|e| !e.is_empty()) || matches.len() != 1 {
                return Err(Error::new("installed package coverage is unknown"));
            }
            package = matches.into_iter().next().unwrap();
        }
        if package.name != plan["package"] || package.version != plan["new"] {
            return Err(Error::new(
                "installed package does not match repaired asset/version",
            ));
        }
        // A repair proves only the claimed package. It must not retire other
        // findings sharing its manifest or publish a complete scan for that path.
        let packages = std::slice::from_ref(&package);
        let result = Value::Object(if crate::scanner::osvdb::configured(&self.state)? {
            crate::scanner::feeds::scan(
                packages,
                &mut crate::scanner::osvdb::LocalDb::new(&crate::scanner::osvdb::root()),
            )?
        } else {
            crate::scanner::scan(packages, &store.root.join("cache"), false)?
        });
        let new_asset = crate::store::asset(&package)?;
        if result["errors"].as_array().is_none_or(|e| !e.is_empty())
            || result["covered"]
                .as_array()
                .is_none_or(|a| !a.contains(&json!(new_asset)))
        {
            return Err(Error::new(
                "repair is unverified because advisory coverage is unknown",
            ));
        }
        if result["findings"].as_array().is_none_or(|findings| {
            findings.iter().any(|f| {
                f["key"] == item
                    || finding["advisory"].is_string()
                        && (f["advisory"] == finding["advisory"]
                            || f["aliases"]
                                .as_array()
                                .is_some_and(|a| a.contains(&finding["advisory"])))
            })
        }) {
            return Err(Error::new("the finding persists after repair"));
        }
        let mut findings = store
            .active()?
            .into_iter()
            .filter(|f| {
                f.get("key") != Some(&json!(item)) && f.get("asset") != finding.get("asset")
            })
            .collect::<Vec<_>>();
        findings.extend(serde_json::from_value::<Vec<crate::domain::Record>>(
            result["findings"].clone(),
        )?);
        let covered =
            std::collections::BTreeSet::from([new_asset, field(&finding, "asset")?.into()]);
        store.reconcile(&findings, &covered, &[])?;
        Ok(json!({"item":item,"status":"fixed","version":plan["new"],"scan":result}))
    }
    pub fn apply(&mut self, item: &str, agent: &str, dry_run: bool) -> Result<Value> {
        let result = self.apply_inner(item, agent, dry_run);
        self.finish(item, "apply", result)
    }
    fn apply_inner(&mut self, item: &str, agent: &str, dry_run: bool) -> Result<Value> {
        let row = self.owned(item, agent)?;
        self.validate(item, &row["plan"])?;
        self.draft(item, agent)?;
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let row = self.owned(item, agent)?;
        let plan = &row["plan"];
        if row["status"] != "planned"
            || self.db.query_row(
                "SELECT COUNT(*) FROM claims WHERE status IN ('applying','rollback-failed')",
                [],
                |r| r.get::<_, i64>(0),
            )? > 0
        {
            return Err(Error::rejected(
                403,
                "repair is not planned or another repair requires recovery",
            ));
        }
        let draft: Value = serde_json::from_str(&self.db.query_row(
            "SELECT payload FROM drafts WHERE item=? AND dismissed=0",
            [item],
            |r| r.get::<_, String>(0),
        )?)?;
        if draft["changes"] != *plan || draft["digest"] != digest(plan)? {
            return Err(Error::rejected(
                403,
                "current plan has no matching reviewed draft",
            ));
        }
        let approved = self.fleet()?.enough(self.approval_count(item)?);
        let permission = self.can(
            agent,
            if plan["kind"] == "repo" {
                "lockfiles"
            } else {
                "os-packages"
            },
        )?;
        if plan.get("locked").is_some() && !approved
            || !dry_run
                && (permission["answer"] == "no" || permission["answer"] == "ask" && !approved)
        {
            return Err(Error::rejected(
                403,
                "policy or human approval refuses repair",
            ));
        }
        let decision = self.policy()?.decision(
            field(plan, "package")?,
            policy_action(plan),
            &json!(self.changes + 1),
            None,
        );
        self.audit(
            item,
            "policy",
            &json!({"decision":decision,"dry_run":dry_run}),
        )?;
        if decision == "deny" || decision == "approve" && !approved {
            return Err(Error::rejected(
                403,
                "policy or human approval refuses repair",
            ));
        }
        if dry_run {
            if plan["kind"] == "os" {
                os_dry_run(plan)?;
            }
            self.db.execute_batch("COMMIT")?;
            return Ok(json!({"status":"dry-run","plan":plan}));
        }
        self.db
            .execute("UPDATE claims SET status='applying' WHERE item=?", [item])?;
        self.audit(item, "snapshot", plan)?;
        self.db.execute_batch("COMMIT")?;
        self.changes += 1;
        let mut undo = None;
        let attempt = (|| -> Result<Value> {
            if plan["kind"] == "repo" {
                undo = Some(apply_repo(
                    plan,
                    &format!("vorda/{}", uuid::Uuid::new_v4().simple()),
                )?);
            } else {
                if run(
                    &strings(&[
                        "dpkg-query",
                        "-W",
                        "-f=${Version}",
                        "--",
                        field(plan, "package")?,
                    ]),
                    None,
                )?
                .trim()
                    != field(plan, "old")?
                {
                    return Err(Error::new("installed version changed since planning"));
                }
                os_dry_run(plan)?;
                undo = Some(json!({"undo":plan["undo"]}));
                run(&vector(&plan["apply"])?, None)?;
            }
            let proof = self.rescan(item, plan)?;
            self.db.execute_batch("BEGIN IMMEDIATE")?;
            let updated = self.db.execute(
                "UPDATE claims SET status='verified',proof=? WHERE item=? AND status='applying'",
                params![proof.to_string(), item],
            )?;
            if updated == 0 {
                self.audit(item, "late-result-ignored", &json!({"outcome":"verified"}))?;
                self.db.execute_batch("COMMIT")?;
                let mut late = Error::new("claim changed while applying; result ignored");
                late.class = "late-result-ignored".into();
                return Err(late);
            }
            self.audit(item, "verified", &json!({"proof":proof,"undo":undo}))?;
            self.db.execute_batch("COMMIT")?;
            Ok(json!({"status":"verified","proof":proof,"snapshot":undo}))
        })();
        if let Err(error) = attempt {
            let _ = self.db.execute_batch("ROLLBACK");
            if error.class == "late-result-ignored" {
                return Err(error);
            }
            let mut status = if ["rolled-back", "rollback-failed"].contains(&error.class.as_str()) {
                error.class.clone()
            } else {
                "failed".into()
            };
            let mut message = error.to_string();
            if let Some(undo) = undo {
                let rollback = (|| -> Result<()> {
                    run(
                        &vector(&undo["undo"])?,
                        plan["root"].as_str().map(Path::new),
                    )?;
                    if plan["kind"] == "os"
                        && run(
                            &strings(&[
                                "dpkg-query",
                                "-W",
                                "-f=${Version}",
                                "--",
                                field(plan, "package")?,
                            ]),
                            None,
                        )?
                        .trim()
                            != field(plan, "old")?
                    {
                        return Err(Error::new("rollback did not restore the installed version"));
                    }
                    Ok(())
                })();
                if let Err(e) = rollback {
                    status = "rollback-failed".into();
                    message.push_str(&format!("; rollback: {e}"));
                } else {
                    status = "rolled-back".into();
                }
            }
            self.db.execute_batch("BEGIN IMMEDIATE")?;
            let updated = self.db.execute(
                "UPDATE claims SET status=? WHERE item=? AND status='applying'",
                params![status, item],
            )?;
            if updated == 0 {
                let late = json!({"outcome":status,"error":message});
                self.audit(item, "late-result-ignored", &late)?;
            } else {
                self.audit(item, &status, &json!({"error":message}))?;
            }
            self.db.execute_batch("COMMIT")?;
            let mut e = Error::new(message);
            e.class = status;
            return Err(e);
        }
        attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repair_verification_refuses_a_finding_closed_during_apply() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let finding = json!({"key":"item","asset":"asset","title":"package advisory",
            "package":{"name":"example","version":"1","ecosystem":"Debian:12","path":"dpkg-query"}});
        store
            .reconcile(
                &[finding.as_object().unwrap().clone()],
                &Default::default(),
                &[],
            )
            .unwrap();
        let config = temp.path().join("repair.json");
        fs::write(&config, json!({"policy":"unused"}).to_string()).unwrap();
        let repairs = Repairs::open(temp.path(), &config).unwrap();
        let plan = json!({"kind":"os","package":"example","old":"1","new":"2"});
        assert!(repairs.validate("item", &plan).is_ok());
        store
            .reconcile(
                &[],
                &std::collections::BTreeSet::from(["asset".into()]),
                &[],
            )
            .unwrap();
        let error = repairs.rescan("item", &plan).unwrap_err();
        assert_eq!(error.to_string(), "an active finding is required");
        assert!(store.active().unwrap().is_empty());
    }
}
