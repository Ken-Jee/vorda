use super::{array, error, input, record, string};
use crate::{domain::Package, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub mod discover;
pub mod rules;

#[derive(Serialize)]
pub struct Bom {
    pub home: PathBuf,
    pub host: String,
    pub scope: String,
    pub items: Vec<Value>,
    pub findings: Vec<Value>,
    pub packages: Vec<Package>,
    pub errors: Vec<Value>,
    pub posture: Vec<Value>,
    pub assets: BTreeSet<String>,
    pub unsure_sources: BTreeSet<String>,
    pub unsure_assets: BTreeSet<String>,
    pub skip_kinds: BTreeSet<String>,
    pub read_files: BTreeSet<String>,
    pub incomplete: bool,
    #[serde(skip)]
    scoped: bool,
    #[serde(skip)]
    roots: Vec<PathBuf>,
    #[serde(skip)]
    seen_files: BTreeSet<(PathBuf, String)>,
    #[serde(skip)]
    package_keys: BTreeSet<(String, String, String, String)>,
    #[serde(skip)]
    text_cache: BTreeMap<(PathBuf, String, String), (Vec<Value>, bool)>,
    #[serde(skip)]
    text_deadline: Instant,
    #[serde(skip)]
    model_deadline: Instant,
    #[serde(skip)]
    plugin_sources: BTreeMap<String, String>,
    /// Stands in for `/` when set, so tests never read machine-wide installs.
    #[serde(skip)]
    system: Option<PathBuf>,
}
impl Bom {
    fn new(home: PathBuf, host: &str, roots: &[PathBuf], include_home: bool) -> Result<Self> {
        let mut selected: Vec<_> = roots
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        selected.sort();
        Ok(Self {
            scope: crate::store::identity(&json!([home, selected, include_home]))?,
            home,
            host: host.into(),
            items: vec![],
            findings: vec![],
            packages: vec![],
            errors: vec![],
            posture: vec![],
            assets: BTreeSet::new(),
            unsure_sources: BTreeSet::new(),
            unsure_assets: BTreeSet::new(),
            skip_kinds: BTreeSet::new(),
            read_files: BTreeSet::new(),
            incomplete: false,
            scoped: false,
            roots: roots.to_vec(),
            seen_files: BTreeSet::new(),
            package_keys: BTreeSet::new(),
            text_cache: BTreeMap::new(),
            text_deadline: Instant::now() + Duration::from_secs(90),
            model_deadline: Instant::now() + Duration::from_secs(60),
            plugin_sources: BTreeMap::new(),
            system: None,
        })
    }
    #[allow(clippy::too_many_arguments)] // argument list mirrors the report fields; a params struct would only move them
    fn item(
        &mut self,
        kind: &str,
        name: &str,
        version: &str,
        source: &Path,
        client: &str,
        ecosystem: &str,
        uid: &str,
        mut detail: Value,
    ) -> Result<Value> {
        let source = source.to_string_lossy();
        let mut key = json!(["agentbom", self.host, kind, client, name, source]);
        if !uid.is_empty() {
            key.as_array_mut().unwrap().push(json!(uid));
        }
        let aid = crate::store::identity(&key)?;
        let found_at = self
            .plugin_sources
            .get(client)
            .cloned()
            .or_else(|| {
                detail
                    .as_object_mut()
                    .and_then(|d| d.remove("found_at"))
                    .and_then(|v| v.as_str().map(str::to_owned))
            })
            .unwrap_or(source.to_string());
        let it = json!({"kind":kind,"name":name,"version":version,"ecosystem":ecosystem,"source":source,"client":client,"host":self.host,"detail":detail,"asset":aid,"found_at":found_at});
        self.assets.insert(aid);
        self.items.push(it.clone());
        Ok(it)
    }
    fn failed(&mut self, label: &str, path: &Path, e: impl ToString) {
        self.unsure_sources.insert(path.to_string_lossy().into());
        self.errors.push(json!({"source":format!("agentbom:{label}"),"error":format!("{}: {}",path.display(),rules::scrub(&e.to_string()).chars().take(160).collect::<String>())}));
    }
    fn partial(&mut self, it: &Value) {
        let aid = string(it, "asset");
        if self.unsure_assets.insert(aid.into()) {
            self.errors.push(json!({"source":"agentbom:partial","error":format!("{} {}: incomplete coverage",string(it,"kind"),repr(string(it,"name")))}));
        }
    }
    fn flag(&mut self, it: &Value, mut f: Value, path: &Path) -> Result<()> {
        let rule = string(&f, "rule");
        let stable = f
            .get("fingerprint")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                if rule.starts_with("AB-C") {
                    string(&f, "evidence")
                } else {
                    ""
                }
            });
        let key = crate::store::identity(&json!([it["asset"], rule, stable, path]))?;
        let kind = string(it, "kind");
        let label = match kind {
            "mcp" => "MCP server",
            "ide-extension" => "IDE extension",
            _ => kind,
        };
        let title = format!(
            "{label} {}: {}",
            repr(string(it, "name")),
            string(&f, "title")
        );
        let fields = record(
            json!({"key":key,"asset":it["asset"],"kind":it["kind"],"host":self.host,"home":self.home,"scan":self.scope,"source":"agentbom","source_file":it["source"],"item":it["name"],"client":it["client"],"found_at":it["found_at"],"path":path,"title":title}),
        );
        f.as_object_mut()
            .ok_or_else(|| error("invalid rule result"))?
            .extend(fields);
        self.findings.push(f);
        Ok(())
    }
    fn add_package(
        &mut self,
        it: &Value,
        name: &str,
        version: &str,
        ecosystem: &str,
        path: &Path,
        dependency: bool,
    ) {
        let v = version.trim_start_matches('v');
        let key = (
            string(it, "asset").into(),
            ecosystem.into(),
            name.into(),
            v.into(),
        );
        if !name.is_empty()
            && discover::exact(version)
            && ["npm", "PyPI"].contains(&ecosystem)
            && self.package_keys.insert(key)
        {
            self.packages.push(Package{name:name.into(),version:v.into(),ecosystem:ecosystem.into(),path:path.to_string_lossy().into(),scope:"reachable-unknown".into(),extra:record(json!({"bom_asset":it["asset"],"found_at":it["found_at"],"bom_kind":it["kind"],"bom_item":it["name"],"bom_client":it["client"],"bom_source":it["source"],"dependency":dependency}))});
        }
    }
    fn load(&mut self, path: &Path, fmt: &str) -> Option<Value> {
        if !path.exists() && !input::linked(path) {
            return None;
        }
        match discover::parse(path, fmt) {
            Ok(data) => {
                self.read_files.insert(path.to_string_lossy().into());
                Some(data)
            }
            Err(e) => {
                self.failed("unreadable", path, e);
                None
            }
        }
    }
    fn files(
        &mut self,
        it: &Value,
        root: &Path,
        suffixes: Option<&BTreeSet<String>>,
        limit: usize,
        depth: usize,
    ) -> Vec<PathBuf> {
        let found = discover::files_under(root, suffixes, limit, depth);
        if !found.complete {
            self.partial(it);
        }
        found.paths
    }
    fn scan_text(
        &mut self,
        it: &Value,
        path: &Path,
        context: &str,
        where_: &str,
        code_only: bool,
    ) -> Result<()> {
        let key = (path.to_path_buf(), context.into(), where_.into());
        let (found, complete) = if let Some(r) = self.text_cache.get(&key) {
            r.clone()
        } else {
            let result = if Instant::now() > self.text_deadline {
                (vec![], false)
            } else {
                match input::read_regular(path, None, 1_000_000, true) {
                    Ok(bytes) => {
                        let complete = bytes.len() < 1_000_000;
                        let text = String::from_utf8_lossy(&bytes);
                        let mut found = rules::text_findings(&text, context);
                        found.extend(rules::secret_findings(&text, where_, &BTreeMap::new()));
                        (found, complete)
                    }
                    Err(_) => (vec![], false),
                }
            };
            self.text_cache.insert(key, result.clone());
            result
        };
        if !complete {
            self.partial(it);
        }
        for f in found {
            if !code_only || ["AB-P1", "AB-P2", "AB-P9"].contains(&string(&f, "rule")) {
                self.flag(it, f, path)?;
            }
        }
        Ok(())
    }
    fn dependencies(
        &mut self,
        it: &Value,
        where_: &Path,
        ecosystem: &str,
        local: bool,
    ) -> Result<()> {
        let locks = if ecosystem == "npm" {
            if local {
                vec![where_.join("package-lock.json")]
            } else {
                let parent = where_.parent().unwrap_or(where_);
                let modules = if parent
                    .file_name()
                    .is_some_and(|p| p.to_string_lossy().starts_with('@'))
                {
                    parent.parent().unwrap_or(parent)
                } else {
                    parent
                };
                vec![
                    modules
                        .parent()
                        .unwrap_or(modules)
                        .join("package-lock.json"),
                    where_.join("package-lock.json"),
                ]
            }
        } else if local {
            ["uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt"]
                .iter()
                .map(|n| where_.join(n))
                .collect()
        } else {
            vec![]
        };
        for path in locks {
            if path.exists() {
                match super::inventory::lockfile_report(&path, None) {
                    Ok((packages, issues)) => {
                        for issue in issues {
                            self.incomplete = true;
                            self.partial(it);
                            self.failed("lockfile", &path, issue);
                        }
                        for p in packages {
                            self.add_package(it, &p.name, &p.version, &p.ecosystem, &path, true);
                        }
                    }
                    Err(e) => {
                        self.incomplete = true;
                        self.partial(it);
                        self.failed("lockfile", &path, e);
                    }
                }
                return Ok(());
            }
        }
        if ecosystem == "PyPI" && !local {
            for (n, v) in discover::dist_infos(where_)? {
                self.add_package(it, &n, &v, "PyPI", where_, true);
            }
        }
        Ok(())
    }
    fn scan_code(&mut self, it: &Value, root: &Path) -> Result<()> {
        let suffixes = [".js", ".mjs", ".cjs", ".ts", ".py", ".json", ".md"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for path in self.files(it, root, Some(&suffixes), 300, 6) {
            self.scan_text(
                it,
                &path,
                if path.extension().is_some_and(|e| e == "md") {
                    "instructions"
                } else {
                    "source"
                },
                "server file",
                true,
            )?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // argument list mirrors the report fields; a params struct would only move them
    fn server(
        &mut self,
        client: &str,
        path: &Path,
        scope: &str,
        name: &str,
        raw: &Value,
        project: bool,
        loose: bool,
    ) -> Result<BTreeSet<String>> {
        let s = discover::normalize(name, raw);
        let args: Vec<_> = array(&s["args"])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let mut pkg = discover::launcher(string(&s, "command"), &args);
        let mut installs = vec![];
        if pkg["ecosystem"] == "npm" && !self.scoped {
            installs =
                discover::npm_installs(&self.home, self.system.as_deref(), string(&pkg, "name"))?;
        } else if pkg["ecosystem"] == "PyPI" && !self.scoped {
            installs = discover::pypi_installs(&self.home, string(&pkg, "name"))?;
        } else if !string(&pkg, "local").is_empty() {
            let spec = string(&pkg, "local");
            let home = self.home.to_string_lossy();
            let expanded = spec
                .replace("${HOME}", &home)
                .replace("$HOME", &home)
                .replace("%USERPROFILE%", &home);
            let local = if let Some(rest) = expanded
                .strip_prefix("~/")
                .or_else(|| expanded.strip_prefix("~\\"))
            {
                self.home.join(rest)
            } else {
                PathBuf::from(expanded)
            };
            let target = if local.is_absolute() {
                local
            } else {
                path.parent().unwrap_or(path).join(local)
            };
            input::refuse_links(&target)?;
            let target = input::absolute(&target)?;
            let boundary = if self.scoped {
                Some(
                    self.roots
                        .iter()
                        .filter(|r| target.starts_with(r))
                        .max_by_key(|r| r.components().count())
                        .ok_or_else(|| error("referenced component is outside configured roots"))?
                        .as_path(),
                )
            } else {
                None
            };
            if target.exists() {
                if let Some((where_, name, version, ecosystem)) =
                    discover::nearest_manifest_bounded(&target, &self.home, boundary)?
                {
                    pkg["ecosystem"] = json!(ecosystem);
                    pkg["name"] = json!(name);
                    pkg["version"] = json!(if discover::exact(&version) {
                        version
                    } else {
                        String::new()
                    });
                    pkg["code"] = json!(where_);
                }
            }
        }
        let pinned = string(&pkg, "version").to_string();
        installs.retain(|(_, v)| pinned.is_empty() || v == &pinned);
        let versions = if pinned.is_empty() {
            installs
                .iter()
                .map(|(_, v)| v.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(",")
        } else {
            pinned.clone()
        };
        let command = if string(&s, "command").is_empty() {
            String::new()
        } else {
            format!(
                "{}{} ({} args)",
                program(string(&s, "command")),
                if string(&pkg, "spec").is_empty() {
                    String::new()
                } else {
                    format!(" {}", rules::safe_spec(string(&pkg, "spec")))
                },
                args.len()
            )
        };
        let url = if string(&s, "url").is_empty() {
            String::new()
        } else {
            url::Url::parse(string(&s, "url"))
                .map(|u| {
                    format!(
                        "{}://{}{}",
                        u.scheme(),
                        u.host_str().unwrap_or(""),
                        u.port().map(|p| format!(":{p}")).unwrap_or_default()
                    )
                })
                .unwrap_or("unparseable".into())
        };
        let it=self.item("mcp",name,&versions,path,client,string(&pkg,"ecosystem"),scope,json!({"scope":scope,"transport":s["transport"],"package":pkg.get("name").cloned().unwrap_or(json!("")),"command":command,"url":url,"env":s["env"].as_object().map(|e|e.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),"disabled":s["disabled"],"pinned":!pinned.is_empty(),"installed":installs.iter().map(|(p,_)|p).collect::<Vec<_>>()}))?;
        if !pinned.is_empty() {
            self.add_package(
                &it,
                string(&pkg, "name"),
                &pinned,
                string(&pkg, "ecosystem"),
                Path::new(&format!(
                    "{}#{}{}",
                    path.display(),
                    if scope.is_empty() {
                        String::new()
                    } else {
                        format!("{scope}/")
                    },
                    name
                )),
                false,
            );
        }
        for (where_, v) in installs {
            self.add_package(
                &it,
                string(&pkg, "name"),
                &v,
                string(&pkg, "ecosystem"),
                &where_,
                false,
            );
            self.dependencies(&it, &where_, string(&pkg, "ecosystem"), false)?;
            if pkg["ecosystem"] == "npm" {
                self.scan_code(&it, &where_)?;
            }
        }
        if let Some(code) = pkg["code"].as_str() {
            self.dependencies(&it, Path::new(code), string(&pkg, "ecosystem"), true)?;
            self.scan_code(&it, Path::new(code))?;
        }
        for f in rules::server_findings(&s, &pkg, &self.home) {
            self.flag(&it, f, path)?;
        }
        let description = string(&s, "description");
        if description.len() > 8192 {
            self.partial(&it);
        }
        let description = description.chars().take(8192).collect::<String>();
        for f in rules::text_findings(&description, "instructions") {
            self.flag(&it, f, path)?;
        }
        let mut named = BTreeMap::new();
        for map in [&s["env"], &s["headers"]] {
            if let Some(map) = map.as_object() {
                for (k, v) in map {
                    named.insert(k.clone(), v.as_str().unwrap_or("").into());
                }
            }
        }
        if let Ok(u) = url::Url::parse(string(&s, "url")) {
            named.extend(
                u.query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned())),
            );
        }
        for pair in args.windows(2) {
            if pair[0].starts_with('-') {
                named.insert(pair[0].trim_start_matches('-').into(), pair[1].clone());
            }
        }
        for a in &args {
            if a.starts_with('-') {
                if let Some((k, v)) = a.trim_start_matches('-').split_once('=') {
                    named.insert(k.into(), v.into());
                }
            }
        }
        let blob = json!({"env":s["env"],"headers":s["headers"],"args":s["args"],"url":s["url"]})
            .to_string();
        let mut prints = BTreeSet::new();
        for mut f in rules::secret_findings(&blob, "MCP server config", &named) {
            prints.insert(string(&f, "fingerprint").into());
            exposure(&mut f, project, loose);
            self.flag(&it, f, path)?;
        }
        Ok(prints)
    }
    fn config(
        &mut self,
        client: &str,
        path: &Path,
        fmt: &str,
        keys: &[Value],
        project: bool,
        plugin: &str,
    ) -> Result<()> {
        if !self.seen_files.insert((path.into(), client.into())) {
            return Ok(());
        }
        let Some(data) = self.load(path, fmt) else {
            return Ok(());
        };
        let cfg = self.item(
            "mcp-config",
            &path.file_name().unwrap_or_default().to_string_lossy(),
            "",
            path,
            client,
            "",
            "",
            json!({"project":project}),
        )?;
        #[cfg(unix)]
        let loose = {
            use std::os::unix::fs::MetadataExt;
            let mode = fs::metadata(path).map_err(error)?.mode();
            mode & 0o44 != 0 && mode & 0o777 != 0o777
        };
        #[cfg(not(unix))]
        let loose = false;
        let mut prints = BTreeSet::new();
        for key in keys {
            for (scope, servers) in discover::walk_keys(&data, array(key)) {
                for (name, raw) in servers.as_object().unwrap() {
                    if discover::server_like(raw) {
                        let client = if plugin.is_empty() {
                            client.into()
                        } else {
                            format!("plugin:{plugin}")
                        };
                        match self.server(&client, path, &scope, name, raw, project, loose) {
                            Ok(found) => prints.extend(found),
                            Err(e) => self.failed(client.as_str(), path, e),
                        }
                    }
                }
            }
        }
        let text = input::text(path)?;
        for mut f in rules::secret_findings(
            &text,
            &format!(
                "agent config {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
            &BTreeMap::new(),
        ) {
            if !prints.contains(string(&f, "fingerprint")) {
                exposure(&mut f, project, loose);
                self.flag(&cfg, f, path)?;
            }
        }
        Ok(())
    }
    fn hooks(&mut self, client: &str, path: &Path, plugin: &str) -> Result<()> {
        if !self.seen_files.insert((path.into(), "hooks".into())) {
            return Ok(());
        }
        let Some(data) = self.load(path, "jsonc") else {
            return Ok(());
        };
        let client = if plugin.is_empty() {
            client.into()
        } else {
            format!("plugin:{plugin}")
        };
        if let Some(env) = data["env"].as_object() {
            let it = self.item(
                "settings-env",
                &path.file_name().unwrap_or_default().to_string_lossy(),
                "",
                path,
                &client,
                "",
                "",
                json!({"keys":env.keys().collect::<Vec<_>>()}),
            )?;
            let assignments = env
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").into()))
                .collect();
            for f in
                rules::secret_findings(&data["env"].to_string(), "agent settings env", &assignments)
            {
                self.flag(&it, f, path)?;
            }
        }
        if plugin.is_empty()
            && client == "claude-code"
            && (data["permissions"]["defaultMode"] == "bypassPermissions"
                || data["skipDangerousModePermissionPrompt"] == true)
        {
            self.posture.push(json!({"client":client,"path":path,"setting":if data["permissions"]["defaultMode"]=="bypassPermissions"{"bypassPermissions"}else{"skipDangerousModePermissionPrompt"}}));
        }
        let mut commands = vec![];
        find_commands(&data["hooks"], vec![], &mut commands);
        for k in [
            "apiKeyHelper",
            "awsAuthRefresh",
            "awsCredentialExport",
            "otelHeadersHelper",
        ] {
            if let Some(cmd) = data[k].as_str() {
                commands.push((vec![k.into()], cmd.into()));
            }
        }
        if let Some(cmd) = data["statusLine"]["command"].as_str() {
            commands.push((vec!["statusLine".into()], cmd.into()));
        }
        for (trail, cmd) in commands {
            let event = trail.first().map(String::as_str).unwrap_or("hook");
            let it = self.item(
                "hook",
                event,
                "",
                path,
                &client,
                "",
                &trail.join("/"),
                json!({"command":format!("{} ({} chars)",program(&cmd),cmd.chars().count())}),
            )?;
            let mut findings = rules::text_findings(&cmd, "shell");
            findings.extend(rules::secret_findings(
                &cmd,
                "hook command",
                &BTreeMap::new(),
            ));
            for f in findings {
                self.flag(&it, f, path)?;
            }
        }
        Ok(())
    }
    fn skill(&mut self, path: &Path, client: &str) -> Result<()> {
        let bytes = input::read_regular(path, None, 1_000_000, true)?;
        let meta = discover::frontmatter(&String::from_utf8_lossy(&bytes));
        let source = path.parent().unwrap_or(path);
        let name = meta.get("name").cloned().unwrap_or_else(|| {
            source
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into()
        });
        let it = self.item(
            "skill",
            &name,
            meta.get("version").map(String::as_str).unwrap_or(""),
            source,
            client,
            "",
            "",
            json!({"found_at":source,"sha256":format!("{:x}",Sha256::digest(&bytes)),"also":[]}),
        )?;
        for f in self.files(&it, source, Some(&text_suffixes()), 200, 6) {
            self.scan_text(&it, &f, context(&f), "skill file", false)?;
        }
        Ok(())
    }
    fn skills(&mut self, base: &Path, client: &str) -> Result<()> {
        for entry in discover::listing(base)? {
            self.read_files.insert(entry.to_string_lossy().into());
            let path = entry.join("SKILL.md");
            if path.exists() || input::linked(&path) {
                if let Err(e) = self.skill(&path, client) {
                    self.failed("skill", &entry, e);
                }
            }
        }
        Ok(())
    }
    fn model(&mut self, path: &Path) -> Result<()> {
        let (found, verified) = rules::model_scan(path, self.model_deadline);
        let ext = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if found.is_empty()
            && ["bin", "npy"].contains(&ext.as_str())
            && !regex::Regex::new("(?i)model|pytorch|weights|checkpoint|ckpt")
                .unwrap()
                .is_match(&name)
        {
            return Ok(());
        }
        let it = self.item(
            "model",
            &name,
            "",
            path,
            "file",
            &ext,
            "",
            json!({"bytes":fs::metadata(path).map_err(error)?.len()}),
        )?;
        if !verified {
            self.skip_kinds.insert("model".into());
            self.partial(&it);
        }
        for f in found {
            self.flag(&it, f, path)?;
        }
        Ok(())
    }
}
fn exposure(f: &mut Value, project: bool, loose: bool) {
    if project || loose {
        f["severity"] = json!("high");
        let why = string(f, "why");
        f["why"] = json!(format!(
            "{why}{}",
            if project {
                " This file is in a project folder and may be committed or shared."
            } else {
                " The file is readable by other users on this machine."
            }
        ));
    }
}
fn find_commands(node: &Value, trail: Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
    if let Some(map) = node.as_object() {
        if node.get("type").is_none_or(|v| v == "command") {
            if let Some(cmd) = node["command"].as_str() {
                out.push((trail.clone(), cmd.into()));
            }
        }
        for (k, v) in map {
            if k != "command" {
                let mut t = trail.clone();
                t.push(k.clone());
                find_commands(v, t, out);
            }
        }
    } else if let Some(items) = node.as_array() {
        for (i, v) in items.iter().enumerate() {
            let mut t = trail.clone();
            t.push(i.to_string());
            find_commands(v, t, out);
        }
    }
}
fn repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}
pub fn program(command: &str) -> String {
    let first = command.split_whitespace().next().unwrap_or("");
    first
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(80)
        .collect()
}
fn context(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "sh" | "bash" | "ps1" => "shell",
        "py" | "js" | "mjs" | "ts" => "source",
        _ => "instructions",
    }
}
fn text_suffixes() -> BTreeSet<String> {
    [
        ".md", ".txt", ".toml", ".yaml", ".yml", ".json", ".sh", ".bash", ".ps1", ".py", ".js",
        ".mjs", ".ts",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
pub fn collect(
    home: &Path,
    roots: &[PathBuf],
    host: &str,
    models: bool,
    include_home: bool,
) -> Result<Bom> {
    collect_inner(home, roots, host, models, include_home, false, None)
}

/// `collect` with machine-wide paths (`/usr/lib/node_modules`, `/etc/...`) rebased onto `system`.
#[cfg(test)]
pub fn collect_under(
    system: &Path,
    home: &Path,
    roots: &[PathBuf],
    host: &str,
    models: bool,
) -> Result<Bom> {
    collect_inner(home, roots, host, models, true, false, Some(system))
}

pub fn collect_scoped(home: &Path, roots: &[PathBuf], host: &str) -> Result<Bom> {
    if roots.is_empty() {
        return Err(error("configured roots are required"));
    }
    collect_inner(home, roots, host, false, false, true, None)
}

fn collect_inner(
    home: &Path,
    roots: &[PathBuf],
    host: &str,
    models: bool,
    include_home: bool,
    scoped: bool,
    system: Option<&Path>,
) -> Result<Bom> {
    let home = input::absolute(home)?;
    input::refuse_links(&home)?;
    let roots = roots
        .iter()
        .map(|p| {
            input::absolute(p).or_else(|_| {
                Ok::<_, crate::Error>(if p.is_absolute() {
                    p.clone()
                } else {
                    std::env::current_dir().map_err(error)?.join(p)
                })
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let include_home = include_home || roots.is_empty();
    let mut bom = Bom::new(home.clone(), host, &roots, include_home)?;
    bom.scoped = scoped;
    bom.system = system.map(Path::to_path_buf);
    if include_home && !home.is_dir() {
        bom.incomplete = true;
        bom.failed("home", &home, "Selected home is missing or not a directory");
        return Ok(bom);
    }
    if !models {
        bom.skip_kinds.insert("model".into());
    }
    let mut projects = BTreeSet::new();
    for root in &roots {
        if let Err(e) = input::refuse_links(root) {
            bom.incomplete = true;
            bom.failed("projects", root, e);
            continue;
        }
        if !root.is_dir() {
            bom.incomplete = true;
            bom.failed(
                "projects",
                root,
                "selected root is missing or not a directory",
            );
            continue;
        }
        let mut stack = vec![(root.clone(), 0)];
        while let Some((p, depth)) = stack.pop() {
            if projects.len() > 20000 {
                bom.incomplete = true;
                bom.failed("projects", root, "more than 20000 folders; rest unchecked");
                break;
            }
            projects.insert(p.clone());
            match discover::listing(&p) {
                Ok(entries) => {
                    for e in entries {
                        let name = e
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned();
                        if discover::SKIP.contains(&name.as_str())
                            || name.starts_with('.')
                                && ![".claude", ".cursor", ".vscode", ".gemini", ".zed"]
                                    .contains(&name.as_str())
                        {
                            continue;
                        }
                        if input::linked(&e) {
                            bom.incomplete = true;
                            bom.unsure_sources.insert(e.to_string_lossy().into());
                            continue;
                        }
                        if e.is_dir() {
                            if depth >= 5 {
                                bom.incomplete = true;
                                bom.failed(
                                    "projects",
                                    &e,
                                    "depth limit of 5; descendants unchecked",
                                );
                            } else {
                                stack.push((e, depth + 1));
                            }
                        }
                    }
                }
                Err(e) => {
                    bom.incomplete = true;
                    bom.failed("projects", &p, e);
                }
            }
        }
    }
    let catalog = discover::catalog();
    if include_home {
        for t in array(&catalog["clients"])
            .iter()
            .chain(array(&catalog["system"]))
        {
            let path = discover::locate(&home, bom.system.as_deref(), t[1].as_str().unwrap());
            if let Err(e) = bom.config(
                t[0].as_str().unwrap(),
                &path,
                t[2].as_str().unwrap(),
                array(&t[3]),
                false,
                "",
            ) {
                bom.failed("config", &path, e);
            }
        }
        for t in array(&catalog["hook_files"]) {
            let path = home.join(t[1].as_str().unwrap());
            if let Err(e) = bom.hooks(t[0].as_str().unwrap(), &path, "") {
                bom.failed("hooks", &path, e);
            }
        }
    }
    for p in &projects {
        for t in array(&catalog["project"]) {
            let path = p.join(t[1].as_str().unwrap());
            if let Err(e) = bom.config(
                t[0].as_str().unwrap(),
                &path,
                t[2].as_str().unwrap(),
                array(&t[3]),
                true,
                "",
            ) {
                bom.failed("config", &path, e);
            }
        }
        for rel in [".claude/settings.json", ".claude/settings.local.json"] {
            let path = p.join(rel);
            if let Err(e) = bom.hooks("claude-code", &path, "") {
                bom.failed("hooks", &path, e);
            }
        }
        let base = p.join(".claude/skills");
        if let Err(e) = bom.skills(&base, "project") {
            bom.skip_kinds.insert("skill".into());
            bom.failed("skills", &base, e);
        }
    }
    if include_home {
        let codex = home.join(".codex/config.toml");
        if let Some(data) = bom.load(&codex, "toml") {
            if data["sandbox_mode"] == "danger-full-access" || data["approval_policy"] == "never" {
                bom.posture.push(json!({"client":"codex","path":codex,"setting":format!("sandbox_mode={} approval_policy={}",string(&data,"sandbox_mode"),string(&data,"approval_policy"))}));
            }
        }
        for rel in array(&catalog["skill_dirs"])
            .iter()
            .filter_map(Value::as_str)
        {
            let base = home.join(rel);
            if let Err(e) = bom.skills(
                &base,
                rel.split('/').next().unwrap_or("").trim_start_matches('.'),
            ) {
                bom.skip_kinds.insert("skill".into());
                bom.failed("skills", &base, e);
            }
        }
        for t in array(&catalog["text_dirs"]) {
            let kind = t[0].as_str().unwrap();
            let rel = t[1].as_str().unwrap();
            let base = home.join(rel);
            let suffixes = [".md".into(), ".toml".into()].into_iter().collect();
            let found = discover::files_under(&base, Some(&suffixes), 300, 3);
            if !found.complete {
                bom.skip_kinds.insert(kind.into());
            }
            for p in found.paths {
                let result = (|| -> Result<()> {
                    let bytes = input::read_regular(&p, None, 1_000_000, true)?;
                    let it = bom.item(
                        kind,
                        &p.file_stem().unwrap_or_default().to_string_lossy(),
                        "",
                        &p,
                        rel.split('/').next().unwrap_or("").trim_start_matches('.'),
                        "",
                        "",
                        json!({"sha256":format!("{:x}",Sha256::digest(bytes))}),
                    )?;
                    bom.scan_text(&it, &p, "instructions", &format!("{kind} file"), false)
                })();
                if let Err(e) = result {
                    bom.failed(kind, &p, e);
                }
            }
        }
        if let Err(e) = bom.home_inventory() {
            bom.incomplete = true;
            bom.failed("home-inventory", &home, e);
        }
    }
    if models {
        let suffixes = array(&catalog["model_ext"])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        for root in &roots {
            if !projects.contains(root) {
                continue;
            }
            let found = discover::files_under(root, Some(&suffixes), 2000, 6);
            if !found.complete {
                bom.skip_kinds.insert("model".into());
            }
            for path in found.paths {
                if let Err(e) = bom.model(&path) {
                    bom.failed("model", &path, e);
                }
            }
        }
        if include_home {
            if let Err(e) = bom.home_models() {
                bom.skip_kinds.insert("model".into());
                bom.failed("models", &home, e);
            }
        }
    }
    Ok(bom)
}
impl Bom {
    fn home_inventory(&mut self) -> Result<()> {
        let home = self.home.clone();
        let catalog = discover::catalog();
        let mut plugins = BTreeMap::<PathBuf, (String, String)>::new();
        let index = home.join(".claude/plugins/installed_plugins.json");
        if let Some(data) = self.load(&index, "json") {
            fn paths(node: &Value, out: &mut BTreeMap<PathBuf, (String, String)>) {
                if let Some(p) = node["installPath"].as_str() {
                    out.insert(
                        p.into(),
                        ("claude-code".into(), string(node, "version").into()),
                    );
                }
                if let Some(map) = node.as_object() {
                    for v in map.values() {
                        paths(v, out);
                    }
                } else {
                    for v in array(node) {
                        paths(v, out);
                    }
                }
            }
            paths(&data, &mut plugins);
        }
        for p in discover::listing(&home.join(".gemini/extensions"))? {
            if p.join("gemini-extension.json").exists() {
                plugins.insert(p, ("gemini".into(), String::new()));
            }
        }
        for (root, (client, version)) in plugins {
            let result = (|| -> Result<()> {
                input::refuse_links(&root)?;
                let manifest = root.join(if client == "claude-code" {
                    ".claude-plugin/plugin.json"
                } else {
                    "gemini-extension.json"
                });
                let meta = self.load(&manifest, "json").unwrap_or(json!({}));
                let name = if string(&meta, "name").is_empty() {
                    root.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                } else {
                    string(&meta, "name").into()
                };
                let found_at = if client == "claude-code" {
                    index.clone()
                } else {
                    manifest.clone()
                };
                let plugin = format!("plugin:{name}");
                self.plugin_sources
                    .insert(plugin.clone(), found_at.to_string_lossy().into());
                let it = self.item(
                    "plugin",
                    &name,
                    if string(&meta, "version").is_empty() {
                        &version
                    } else {
                        string(&meta, "version")
                    },
                    &root,
                    &client,
                    "",
                    "",
                    json!({"found_at":found_at}),
                )?;
                let suffixes = [".md", ".json", ".sh", ".toml"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                for f in self.files(&it, &root, Some(&suffixes), 200, 6) {
                    if !f.components().any(|c| c.as_os_str() == "skills") {
                        self.scan_text(
                            &it,
                            &f,
                            if f.extension().is_some_and(|e| e == "sh") {
                                "shell"
                            } else {
                                "instructions"
                            },
                            "plugin file",
                            false,
                        )?;
                    }
                }
                if let Some(servers) = meta["mcpServers"].as_object() {
                    for (name, raw) in servers {
                        if discover::server_like(raw) {
                            self.server(&plugin, &manifest, "", name, raw, false, false)?;
                        }
                    }
                }
                self.config(
                    &client,
                    &root.join(".mcp.json"),
                    "json",
                    &[json!(["mcpServers"])],
                    false,
                    &name,
                )?;
                self.hooks(&client, &root.join("hooks/hooks.json"), &name)?;
                self.skills(&root.join("skills"), &plugin)?;
                Ok(())
            })();
            if let Err(e) = result {
                self.incomplete = true;
                self.failed("plugin", &root, e);
            }
        }
        for root in discover::npm_roots(&home, self.system.as_deref())? {
            let mut packages = Vec::new();
            for entry in discover::listing(&root)? {
                if entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .starts_with('@')
                {
                    packages.extend(discover::listing(&entry)?);
                } else {
                    packages.push(entry);
                }
            }
            for p in packages {
                let name = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                if catalog["agent_clis"].get(&name).is_none()
                    && !name.to_lowercase().contains("mcp")
                {
                    continue;
                }
                let path = p.join("package.json");
                if let Some(data) = self.load(&path, "json") {
                    let version = string(&data, "version");
                    if discover::exact(version) {
                        let it = self.item(
                            if catalog["agent_clis"].get(&name).is_some() {
                                "cli"
                            } else {
                                "mcp-package"
                            },
                            &name,
                            version,
                            &p,
                            "npm-global",
                            "npm",
                            "",
                            json!({"stale":false}),
                        )?;
                        self.add_package(&it, &name, version, "npm", &p, false);
                    }
                }
            }
        }
        let mise = home.join(".local/share/mise/installs");
        for tool in discover::listing(&mise)? {
            let tool_name = tool.file_name().unwrap_or_default().to_string_lossy();
            let name = catalog["agent_clis"].as_object().and_then(|clis| {
                clis.iter()
                    .find(|(n, v)| {
                        v.as_str() == Some(tool_name.as_ref())
                            || format!("npm-{}", n.trim_start_matches('@').replace('/', "-"))
                                == tool_name
                    })
                    .map(|(n, _)| n.clone())
            });
            if let Some(name) = name {
                for path in discover::listing(&tool)? {
                    let version = path.file_name().unwrap_or_default().to_string_lossy();
                    if input::linked(&path)
                        || !discover::exact(&version)
                        || version.matches('.').count() < 2
                    {
                        continue;
                    }
                    let version = version.trim_start_matches('v');
                    let it = self.item(
                        "cli",
                        &name,
                        version,
                        &path,
                        "mise",
                        "npm",
                        "",
                        json!({"stale":false}),
                    )?;
                    self.add_package(&it, &name, version, "npm", &path, false);
                }
            }
        }
        let mut native = discover::listing(&home.join(".local/share/claude/versions"))?;
        native.retain(|p| discover::exact(&p.file_name().unwrap_or_default().to_string_lossy()));
        native.sort_by_key(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .split(['.', '+', '-'])
                .map(|v| v.parse::<u64>().unwrap_or(0))
                .collect::<Vec<_>>()
        });
        let latest = native.last().cloned();
        for p in native {
            let name = "@anthropic-ai/claude-code";
            let version = p.file_name().unwrap_or_default().to_string_lossy();
            let stale = Some(&p) != latest.as_ref();
            let it = self.item(
                "cli",
                name,
                &version,
                &p,
                "claude-native",
                "npm",
                "",
                json!({"stale":stale}),
            )?;
            if !stale {
                self.add_package(&it, name, &version, "npm", &p, false);
            }
        }
        for (site, version) in discover::pypi_installs(&home, "aider-chat")? {
            let it = self.item(
                "cli",
                "aider-chat",
                &version,
                &site,
                "python-tool",
                "PyPI",
                "",
                json!({"stale":false}),
            )?;
            self.add_package(&it, "aider-chat", &version, "PyPI", &site, false);
        }
        let ai=regex::Regex::new("(?i)copilot|claude|anthropic|codex|openai|continue|cline|roo-?cline|kilo|cody|tabnine|codeium|windsurf|gemini|aider|supermaven|amazon-q|codewhisperer|cursor|mcp").unwrap();
        for rel in array(&catalog["extension_dirs"])
            .iter()
            .filter_map(Value::as_str)
        {
            for root in discover::listing(&home.join(rel))? {
                let path = root.join("package.json");
                if let Some(meta) = self.load(&path, "json") {
                    let name = format!("{}.{}", string(&meta, "publisher"), string(&meta, "name"));
                    if name == "." {
                        continue;
                    }
                    self.item("ide-extension",&name.to_lowercase(),string(&meta,"version"),&root,rel.split('/').next().unwrap_or("").trim_start_matches('.'),"VSCode","",json!({"ai":ai.is_match(&format!("{name} {}",meta["categories"])),"mcp_provider":meta["contributes"].get("mcpServerDefinitionProviders").is_some_and(|v|!v.is_null()&&v!=false)}))?;
                }
            }
        }
        Ok(())
    }
    fn home_models(&mut self) -> Result<()> {
        let home = self.home.clone();
        let machine = |p: &str| match &self.system {
            Some(system) => system.join(&p[1..]),
            None => PathBuf::from(p),
        };
        for base in [
            home.join(".ollama/models/manifests"),
            machine("/usr/share/ollama/.ollama/models/manifests"),
            machine("/var/lib/ollama/.ollama/models/manifests"),
        ] {
            if !base.is_dir() {
                continue;
            }
            let found = discover::files_under(&base, None, 500, 5);
            if !found.complete {
                self.skip_kinds.insert("model".into());
            }
            for tag in found.paths {
                let parts: Vec<_> = tag
                    .strip_prefix(&base)
                    .map_err(error)?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                if parts.len() >= 3 {
                    self.item(
                        "model",
                        &parts[1..parts.len() - 1].join("/"),
                        parts.last().unwrap(),
                        &tag,
                        "ollama",
                        "Ollama",
                        "",
                        json!({"registry":parts[0]}),
                    )?;
                }
            }
        }
        let mut hubs = vec![home.join(".cache/huggingface/hub")];
        if let Some(p) = std::env::var_os("HF_HOME") {
            hubs.push(PathBuf::from(p).join("hub"));
        }
        for base in hubs {
            for repo in discover::listing(&base)? {
                let name = repo
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let Some(name) = name.strip_prefix("models--") else {
                    continue;
                };
                for snap in discover::listing(&repo.join("snapshots"))? {
                    let it = self.item(
                        "model",
                        &name.replace("--", "/"),
                        &snap
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .chars()
                            .take(12)
                            .collect::<String>(),
                        &snap,
                        "huggingface",
                        "HuggingFace",
                        "",
                        json!({}),
                    )?;
                    for f in self.files(&it, &snap, None, 200, 3) {
                        let (found, verified) = rules::model_scan(&f, self.model_deadline);
                        if !verified {
                            self.partial(&it);
                        }
                        for finding in found {
                            self.flag(&it, finding, &f)?;
                        }
                    }
                }
            }
        }
        let suffixes = array(&discover::catalog()["model_ext"])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        for base in [
            home.join(".lmstudio/models"),
            home.join(".cache/lm-studio/models"),
        ] {
            let found = discover::files_under(&base, Some(&suffixes), 2000, 6);
            if !found.complete {
                self.skip_kinds.insert("model".into());
            }
            for f in found.paths {
                self.model(&f)?;
            }
        }
        Ok(())
    }
}

pub fn own_asset(host: &str, asset: &str) -> Result<String> {
    crate::store::identity(&json!(["agentbom", host, asset]))
}
pub fn match_packages(
    bom: &Bom,
    fetch: &mut dyn super::feeds::FeedSource,
) -> Result<serde_json::Map<String, Value>> {
    if bom.packages.is_empty() {
        return Ok(record(
            json!({"findings":[],"covered":[],"errors":[],"sources":[]}),
        ));
    }
    let mut result = super::feeds::scan(&bom.packages, fetch)?;
    let mut covered = Vec::new();
    for a in array(result.get("covered").unwrap_or(&Value::Null)) {
        if let Some(a) = a.as_str() {
            covered.push(own_asset(&bom.host, a)?);
        }
    }
    result.insert("covered".into(), json!(covered));
    if let Some(findings) = result.get_mut("findings").and_then(Value::as_array_mut) {
        for f in findings {
            let p = f["package"].clone();
            let asset = own_asset(&bom.host, string(f, "asset"))?;
            f["asset"] = json!(asset);
            f["key"] = json!(crate::store::identity(&json!([asset, f["advisory"]]))?);
            let title = format!(
                "{} {}: {}{}",
                if p["bom_kind"] == "mcp" {
                    "MCP server"
                } else {
                    string(&p, "bom_kind")
                },
                repr(string(&p, "bom_item")),
                string(f, "title"),
                if p["dependency"] == true {
                    " (dependency)"
                } else {
                    ""
                }
            );
            f.as_object_mut().ok_or_else(||error("invalid finding"))?.extend(record(json!({"bom_asset":p["bom_asset"],"found_at":p["found_at"],"source":"agentbom","source_file":p["bom_source"],"home":bom.home,"scan":bom.scope,"kind":p["bom_kind"],"host":bom.host,"item":p["bom_item"],"client":p["bom_client"],"title":title})));
        }
    }
    Ok(result)
}
pub fn covered(bom: &Bom, cves: &Value, previous: &[Value]) -> Result<BTreeSet<String>> {
    let mut unsure = bom.unsure_assets.clone();
    for it in &bom.items {
        if bom.unsure_sources.contains(string(it, "source")) {
            unsure.insert(string(it, "asset").into());
        }
    }
    let mut present = bom.assets.clone();
    for p in &bom.packages {
        let asset = own_asset(&bom.host, &crate::store::asset(p)?)?;
        present.insert(asset.clone());
        if bom.unsure_sources.contains(
            p.extra
                .get("bom_source")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ) || bom.unsure_assets.contains(
            p.extra
                .get("bom_asset")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ) {
            unsure.insert(asset);
        }
    }
    let mut complete = bom.assets.clone();
    complete.extend(
        array(&cves["covered"])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
    complete.retain(|a| !unsure.contains(a));
    if !bom.incomplete {
        for f in previous {
            let source = f
                .get("found_at")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(string(f, "source_file"));
            let aid = string(f, "asset");
            if f["source"] != "agentbom"
                || f["host"] != bom.host
                || f["scan"] != bom.scope
                || present.contains(aid)
                || bom.unsure_sources.contains(source)
                || bom.unsure_sources.contains(string(f, "source_file"))
                || bom.unsure_assets.contains(string(f, "bom_asset"))
                || bom.skip_kinds.contains(string(f, "kind"))
            {
                continue;
            }
            if bom.read_files.contains(source)
                || fs::symlink_metadata(source)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                complete.insert(aid.into());
            }
        }
    }
    Ok(complete)
}
