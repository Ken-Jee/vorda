use super::super::{array, error, input, string};
use crate::Result;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};
pub(crate) const SKIP: &[&str] = &[
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "target",
    "__pycache__",
    ".cache",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
];
pub fn catalog() -> &'static Value {
    static C: OnceLock<Value> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(include_str!("discovery.json")).unwrap())
}
pub fn exact(s: &str) -> bool {
    regex::Regex::new(r"^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
        .unwrap()
        .is_match(s)
}
pub fn listing(path: &Path) -> Result<Vec<PathBuf>> {
    input::refuse_links(path)?;
    match fs::read_dir(path) {
        Ok(entries) => {
            let mut paths = entries
                .map(|e| e.map(|e| e.path()).map_err(error))
                .collect::<Result<Vec<_>>>()?;
            paths.sort();
            Ok(paths)
        }
        Err(e)
            if [
                std::io::ErrorKind::NotFound,
                std::io::ErrorKind::NotADirectory,
            ]
            .contains(&e.kind()) =>
        {
            Ok(vec![])
        }
        Err(e) => Err(error(format!("{}: {e}", path.display()))),
    }
}
pub fn parse(path: &Path, fmt: &str) -> Result<Value> {
    let text = input::text(path)?;
    let text = text.trim_start_matches('\u{feff}');
    if fmt == "toml" {
        let value: toml::Value = toml::from_str(text).map_err(error)?;
        return serde_json::to_value(value).map_err(error);
    }
    if fmt == "jsonc" {
        jsonc(text)
    } else {
        serde_json::from_str(text).map_err(error)
    }
}
pub fn jsonc(src: &str) -> Result<Value> {
    let mut out = String::new();
    let mut chars = src.chars().peekable();
    let mut string = false;
    while let Some(c) = chars.next() {
        if string {
            out.push(c);
            if c == '\\' {
                if let Some(c) = chars.next() {
                    out.push(c);
                }
            } else if c == '"' {
                string = false;
            }
        } else if c == '"' {
            string = true;
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for c in chars.by_ref() {
                if c == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = ' ';
            for c in chars.by_ref() {
                if prev == '*' && c == '/' {
                    break;
                }
                prev = c;
            }
        } else {
            out.push(c);
        }
    }
    let chars: Vec<_> = out.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut quoted = false;
    while i < chars.len() {
        let c = chars[i];
        if quoted {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                i += 1;
                out.push(chars[i]);
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            out.push(c);
        } else if c == ',' {
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j >= chars.len() || !['}', ']'].contains(&chars[j]) {
                out.push(c);
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    serde_json::from_str(&out).map_err(error)
}
pub fn walk_keys<'a>(data: &'a Value, keys: &[Value]) -> Vec<(String, &'a Value)> {
    fn go<'a>(data: &'a Value, keys: &[Value], scope: String, out: &mut Vec<(String, &'a Value)>) {
        if keys.is_empty() {
            if data.is_object() {
                out.push((scope, data));
            }
            return;
        }
        if let Some(map) = data.as_object() {
            let key = keys[0].as_str().unwrap_or("");
            if key == "*" {
                for (k, v) in map {
                    go(
                        v,
                        &keys[1..],
                        if scope.is_empty() {
                            k.clone()
                        } else {
                            format!("{scope}/{k}")
                        },
                        out,
                    );
                }
            } else if let Some(v) = map.get(key) {
                go(v, &keys[1..], scope, out);
            }
        }
    }
    let mut out = vec![];
    go(data, keys, String::new(), &mut out);
    out
}
pub fn server_like(v: &Value) -> bool {
    v.is_object()
        && [
            "command",
            "url",
            "serverUrl",
            "httpUrl",
            "type",
            "transport",
        ]
        .iter()
        .any(|k| v.get(k).is_some())
}
fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(py_string).collect(),
        Value::String(s) => vec![s.clone()],
        Value::Number(n) => vec![n.to_string()],
        _ => vec![],
    }
}
fn py_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        _ => v.to_string(),
    }
}
pub fn normalize(name: &str, raw: &Value) -> Value {
    let mut command = raw["command"].clone();
    let mut args = strings(&raw["args"]);
    if command.is_object() {
        let mut a = strings(&command["args"]);
        a.extend(args);
        args = a;
        command = command["path"].clone();
    }
    if let Some(c) = command.as_array() {
        let mut a = c.iter().skip(1).map(py_string).collect::<Vec<_>>();
        a.extend(args);
        args = a;
        command = c.first().cloned().unwrap_or(Value::Null);
    }
    if !command.is_string() {
        command = Value::Null;
    }
    let env = raw
        .get("env")
        .filter(|v| !v.is_null())
        .or_else(|| raw.get("environment"))
        .unwrap_or(&Value::Null);
    let headers = raw
        .get("headers")
        .or_else(|| raw.get("http_headers"))
        .or_else(|| raw["requestInit"].get("headers"))
        .unwrap_or(&Value::Null);
    let map = |v: &Value| {
        v.as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), json!(py_string(v))))
                    .collect::<serde_json::Map<_, _>>()
            })
            .unwrap_or_default()
    };
    let url = raw
        .get("url")
        .or_else(|| raw.get("serverUrl"))
        .or_else(|| raw.get("httpUrl"))
        .cloned()
        .unwrap_or(Value::Null);
    let transport = raw
        .get("type")
        .or_else(|| raw.get("transport"))
        .cloned()
        .unwrap_or(json!(if command.is_string() {
            "stdio"
        } else if url.is_string() {
            "http"
        } else {
            "unknown"
        }));
    json!({"name":name,"command":command,"args":args,"url":url,"env":map(env),"headers":map(headers),"transport":transport,"disabled":raw["disabled"]==true||raw["enabled"]==false,"description":raw.get("description").map(py_string).unwrap_or_default()})
}
pub fn split_spec(spec: &str, ecosystem: &str) -> (String, String) {
    let mut spec = spec.trim();
    if spec.contains("://")
        || ["git+", "file:", ".", "/"]
            .iter()
            .any(|p| spec.starts_with(p))
    {
        let spec = spec
            .split(['?', '#'])
            .next()
            .unwrap_or("")
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("")
            .split('@')
            .next()
            .unwrap_or("")
            .trim_end_matches(".git")
            .to_lowercase();
        return (spec.chars().take(80).collect(), String::new());
    }
    let (name, version) = if ecosystem == "npm" {
        if let Some((_, v)) = spec.split_once("@npm:") {
            spec = v;
        }
        match spec.rfind('@') {
            Some(i) if i > 0 => (spec[..i].into(), spec[i + 1..].into()),
            _ => (spec.into(), String::new()),
        }
    } else {
        let re =
            regex::Regex::new(r"^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*(?:(?:==|@)\s*([^\s;,]+))?")
                .unwrap();
        let Some(c) = re.captures(spec) else {
            return (spec.into(), String::new());
        };
        (
            regex::Regex::new("[-_.]+")
                .unwrap()
                .replace_all(&c[1].to_lowercase(), "-")
                .into_owned(),
            c.get(2).map(|m| m.as_str()).unwrap_or("").into(),
        )
    };
    let version = if exact(&version) {
        version.trim_start_matches('v').into()
    } else {
        String::new()
    };
    (name, version)
}
fn first_positional<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--" {
            return args.get(i + 1).map(String::as_str);
        }
        if args[i].starts_with('-') {
            if !args[i].contains('=') && flags.contains(&args[i].as_str()) {
                i += 1;
            }
        } else {
            return Some(&args[i]);
        }
        i += 1;
    }
    None
}
fn shell_split(s: &str) -> Option<Vec<String>> {
    let (mut out, mut word, mut quote, mut escape) = (vec![], String::new(), None, false);
    for c in s.chars() {
        if escape {
            word.push(c);
            escape = false;
        } else if c == '\\' && quote != Some('\'') {
            escape = true;
        } else if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
        } else if c.is_whitespace() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if quote.is_some() || escape {
        return None;
    }
    if !word.is_empty() {
        out.push(word);
    }
    Some(out)
}
pub fn launcher(command: &str, args: &[String]) -> Value {
    launch(command, args, 0)
}
fn launch(command: &str, args: &[String], depth: usize) -> Value {
    if command.is_empty() || depth > 16 {
        return json!({});
    }
    let path = command.replace('\\', "/");
    let exe = path.rsplit('/').next().unwrap_or("").to_lowercase();
    let exe = regex::Regex::new(r"\.(cmd|exe|bat|ps1)$")
        .unwrap()
        .replace(&exe, "")
        .into_owned();
    let mut argv = args;
    if ["env", "sudo", "doas", "nice", "nohup", "exec", "time"].contains(&exe.as_str()) {
        let mut i = 0;
        while i < argv.len() && (argv[i].starts_with('-') || exe == "env" && argv[i].contains('='))
        {
            i += 1;
        }
        return argv
            .get(i)
            .map(|cmd| launch(cmd, &argv[i + 1..], depth + 1))
            .unwrap_or(json!({}));
    }
    if ["cmd", "powershell", "pwsh", "sh", "bash", "zsh", "dash"].contains(&exe.as_str())
        && argv.first().is_some_and(|a| {
            regex::Regex::new(r"(?i)^(?:/[ck]|-\w*c|-command|-noprofile|-nologo)$")
                .unwrap()
                .is_match(a)
        })
    {
        let mut i = 1;
        let shell_flag = regex::Regex::new(
            r"(?i)^(?:-\w*c|-command|-noprofile|-nologo|-executionpolicy|bypass)$",
        )
        .unwrap();
        while i < argv.len() && shell_flag.is_match(&argv[i]) {
            i += 1;
        }
        let rest = if argv.len() - i == 1 {
            shell_split(&argv[i]).unwrap_or_default()
        } else {
            argv[i..].to_vec()
        };
        return rest
            .first()
            .map(|c| launch(c, &rest[1..], depth + 1))
            .unwrap_or(json!({}));
    }
    if exe == "workstation" || exe == "wsl" {
        let mut i = 0;
        while i < argv.len()
            && ["-d", "--distribution", "-u", "--user", "--cd"].contains(&argv[i].as_str())
        {
            i += 2;
        }
        if argv
            .get(i)
            .is_some_and(|a| ["-e", "--exec", "--"].contains(&a.as_str()))
        {
            i += 1;
        }
        return argv
            .get(i)
            .map(|cmd| launch(cmd, &argv[i + 1..], depth + 1))
            .unwrap_or(json!({}));
    }
    let npm = ["npx", "bunx", "pnpx"].contains(&exe.as_str())
        || ["pnpm", "yarn", "bun"].contains(&exe.as_str())
            && argv
                .first()
                .is_some_and(|a| ["dlx", "x"].contains(&a.as_str()))
        || exe == "npm"
            && argv
                .first()
                .is_some_and(|a| ["exec", "x"].contains(&a.as_str()));
    let pypi = exe == "uvx"
        || exe == "uv" && argv.starts_with(&["tool".into(), "run".into()])
        || exe == "pipx" && argv.first().is_some_and(|a| a == "run");
    if npm || pypi {
        if ["pnpm", "yarn", "bun", "npm", "pipx"].contains(&exe.as_str()) {
            argv = &argv[1..];
        }
        if exe == "uv" {
            argv = &argv[2..];
        }
        let flags = if npm {
            vec!["-p", "--package", "-c", "--call", "--registry", "--cache"]
        } else {
            vec![
                "--from",
                "--spec",
                "--with",
                "--python",
                "-p",
                "--index-url",
                "--index",
                "-w",
            ]
        };
        let explicit_flags = if npm {
            vec!["-p", "--package"]
        } else {
            vec!["--from", "--spec"]
        };
        let explicit = argv
            .windows(2)
            .find(|a| explicit_flags.contains(&a[0].as_str()))
            .map(|a| a[1].as_str())
            .or_else(|| {
                argv.iter().find_map(|a| {
                    a.split_once('=')
                        .filter(|(k, _)| explicit_flags.contains(k))
                        .map(|(_, v)| v)
                })
            });
        if let Some(spec) = explicit.or_else(|| first_positional(argv, &flags)) {
            let ecosystem = if npm { "npm" } else { "PyPI" };
            let (name, version) = split_spec(spec, ecosystem);
            return json!({"ecosystem":ecosystem,"name":name,"version":version,"fetches":true,"runner":exe,"spec":spec});
        }
    }
    if ["docker", "podman", "nerdctl"].contains(&exe.as_str()) {
        if let Some(i) = argv.iter().position(|a| a == "run") {
            let flags = [
                "-e",
                "--env",
                "-v",
                "--volume",
                "--name",
                "--network",
                "--net",
                "-p",
                "--publish",
                "--mount",
                "--env-file",
                "-w",
                "--workdir",
                "-u",
                "--user",
                "--entrypoint",
                "--platform",
                "-l",
                "--label",
                "--add-host",
                "--cap-add",
                "--cap-drop",
                "--memory",
                "-m",
                "--cpus",
                "--pull",
                "--security-opt",
                "--hostname",
                "-h",
                "--gpus",
                "--device",
                "--runtime",
                "--ipc",
                "--shm-size",
                "--ulimit",
                "--tmpfs",
                "--dns",
                "--log-driver",
                "--restart",
                "--stop-signal",
                "--pid",
                "--userns",
                "--cgroupns",
                "--group-add",
                "--expose",
                "--label-file",
                "--cidfile",
                "--volumes-from",
                "--link",
                "--creds",
                "--authfile",
                "--secret",
                "--decryption-key",
                "--cert-dir",
                "--health-cmd",
            ];
            if let Some(image) = first_positional(&argv[i + 1..], &flags) {
                if regex::Regex::new(
                    r"^[a-z0-9][a-z0-9._/-]{0,200}(?::[\w.-]{1,128})?(?:@sha256:[0-9a-f]{64})?$",
                )
                .unwrap()
                .is_match(image)
                {
                    let (name, version) = if let Some((n, v)) = image.split_once('@') {
                        (n, v)
                    } else if image.rsplit('/').next().unwrap_or("").contains(':') {
                        image.rsplit_once(':').unwrap()
                    } else {
                        (image, "")
                    };
                    return json!({"ecosystem":"OCI","name":name,"version":version,"fetches":true,"runner":exe,"spec":image});
                }
            }
        }
    }
    let script =
        if ["node", "python", "python3", "deno", "bun", "tsx", "ts-node"].contains(&exe.as_str()) {
            argv.iter()
                .find(|a| !a.starts_with('-') && *a != "run")
                .map(String::as_str)
        } else if command.contains('/') || command.contains('\\') {
            Some(command)
        } else {
            None
        };
    script.map(|s| json!({"local":s})).unwrap_or(json!({}))
}
pub struct Files {
    pub paths: Vec<PathBuf>,
    pub complete: bool,
}
pub fn files_under(
    root: &Path,
    suffixes: Option<&BTreeSet<String>>,
    limit: usize,
    depth: usize,
) -> Files {
    let mut out = Files {
        paths: vec![],
        complete: true,
    };
    if !root.exists() {
        return out;
    }
    let mut stack = vec![(root.to_path_buf(), 0)];
    let mut work = 0;
    while let Some((dir, d)) = stack.pop() {
        let entries = match listing(&dir) {
            Ok(v) => v,
            Err(_) => {
                out.complete = false;
                continue;
            }
        };
        work += 1 + entries.len();
        if work > 100_000 {
            out.complete = false;
            break;
        }
        for p in entries {
            if input::linked(&p) {
                out.complete = false;
                continue;
            }
            let meta = match fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => {
                    out.complete = false;
                    continue;
                }
            };
            if meta.is_dir() {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                if SKIP.contains(&name.as_ref()) {
                    continue;
                }
                if d >= depth {
                    out.complete = false;
                } else {
                    stack.push((p, d + 1));
                }
            } else {
                let ext = format!(
                    ".{}",
                    p.extension()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase()
                );
                if suffixes.is_none_or(|s| s.contains(&ext)) {
                    if out.paths.len() >= limit {
                        out.complete = false;
                        return out;
                    }
                    out.paths.push(p);
                }
            }
        }
    }
    out.paths.sort();
    out
}
pub fn frontmatter(src: &str) -> BTreeMap<String, String> {
    if !src.starts_with("---") {
        return BTreeMap::new();
    }
    let end = src.get(3..).and_then(|s| s.find("\n---")).map(|i| i + 3);
    let Some(end) = end.filter(|i| *i < 8192) else {
        return BTreeMap::new();
    };
    regex::Regex::new(r"(?m)^([\w-]{1,64})[ \t]*:[ \t]*(.{0,500})$")
        .unwrap()
        .captures_iter(&src[3..end])
        .map(|c| {
            (
                c[1].trim().into(),
                c[2].trim().trim_matches(['\'', '"']).into(),
            )
        })
        .collect()
}
pub fn nearest_manifest(
    start: &Path,
    home: &Path,
) -> Result<Option<(PathBuf, String, String, String)>> {
    nearest_manifest_bounded(start, home, None)
}

pub fn nearest_manifest_bounded(
    start: &Path,
    home: &Path,
    boundary: Option<&Path>,
) -> Result<Option<(PathBuf, String, String, String)>> {
    let mut dir = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent().unwrap_or(start).to_path_buf()
    };
    for _ in 0..4 {
        if boundary.is_some_and(|root| !dir.starts_with(root)) {
            break;
        }
        if dir == home || dir.parent().is_none() {
            break;
        }
        for (name, eco) in [("package.json", "npm"), ("pyproject.toml", "PyPI")] {
            let p = dir.join(name);
            if p.exists() {
                let data = parse(&p, if eco == "npm" { "json" } else { "toml" })?;
                let data = if eco == "PyPI" {
                    data.get("project")
                        .or_else(|| data["tool"].get("poetry"))
                        .cloned()
                        .unwrap_or(json!({}))
                } else {
                    data
                };
                if !string(&data, "name").is_empty() {
                    return Ok(Some((
                        dir,
                        string(&data, "name").into(),
                        string(&data, "version").into(),
                        eco.into(),
                    )));
                }
            }
        }
        if dir.join(".git").exists() {
            break;
        }
        dir = dir.parent().unwrap_or(&dir).to_path_buf();
    }
    Ok(None)
}
/// Resolves a catalog path: relative entries sit under `home`, and absolute
/// ones are machine-wide unless `system` rebases them (tests use an empty root).
pub fn locate(home: &Path, system: Option<&Path>, path: &str) -> PathBuf {
    match (system, path.strip_prefix('/')) {
        (Some(system), Some(rel)) => system.join(rel),
        _ => home.join(path),
    }
}
pub fn npm_roots(home: &Path, system: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for rel in array(&catalog()["npm_roots"])
        .iter()
        .filter_map(Value::as_str)
    {
        out.push(locate(home, system, rel));
    }
    for pattern in array(&catalog()["npm_root_globs"])
        .iter()
        .filter_map(Value::as_str)
    {
        let (base, tail) = pattern.split_once('*').unwrap();
        for entry in listing(&home.join(base.trim_end_matches('/')))? {
            out.push(entry.join(tail.trim_start_matches('/')));
        }
    }
    Ok(out)
}
pub fn npm_installs(
    home: &Path,
    system: Option<&Path>,
    name: &str,
) -> Result<Vec<(PathBuf, String)>> {
    let mut roots = npm_roots(home, system)?;
    for cache in array(&catalog()["npx_caches"])
        .iter()
        .filter_map(Value::as_str)
    {
        for e in listing(&home.join(cache))? {
            roots.push(e.join("node_modules"));
        }
    }
    let mut candidates: Vec<_> = roots.into_iter().map(|r| r.join(name)).collect();
    for entry in listing(&home.join(".bun/install/cache"))? {
        if entry
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .starts_with(&format!("{name}@"))
        {
            candidates.push(entry);
        }
    }
    let mut out = Vec::new();
    for candidate in candidates {
        let path = candidate.join("package.json");
        if path.exists() {
            let data = parse(&path, "json")?;
            let version = string(&data, "version");
            if exact(version) && data["name"] == name {
                out.push((path.parent().unwrap().into(), version.into()));
            }
        }
    }
    Ok(out)
}
pub fn dist_infos(site: &Path) -> Result<Vec<(String, String)>> {
    let re = regex::Regex::new(r"^(.+?)-(\d[^-]*)\.dist-info$").unwrap();
    let sep = regex::Regex::new("[-_.]+").unwrap();
    let mut out = Vec::new();
    for entry in listing(site)? {
        let name = entry.file_name().unwrap_or_default().to_string_lossy();
        if let Some(c) = re.captures(&name) {
            out.push((
                sep.replace_all(&c[1].to_lowercase(), "-").into_owned(),
                c[2].into(),
            ));
        }
    }
    Ok(out)
}
fn unix_sites(base: &Path) -> Result<Vec<PathBuf>> {
    Ok(listing(&base.join("lib"))?
        .into_iter()
        .filter(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with("python")
        })
        .map(|p| p.join("site-packages"))
        .collect())
}
pub fn pypi_installs(home: &Path, name: &str) -> Result<Vec<(PathBuf, String)>> {
    let mut sites = Vec::new();
    for base in [
        ".local/share/uv/tools",
        ".local/share/pipx/venvs",
        ".local/pipx/venvs",
        "AppData/Roaming/uv/tools",
    ] {
        for venv in listing(&home.join(base))? {
            sites.extend(unix_sites(&venv)?);
            sites.push(venv.join("Lib/site-packages"));
        }
    }
    for entry in listing(&home.join(".cache/uv/archive-v0"))? {
        sites.extend(unix_sites(&entry)?);
        sites.push(entry);
    }
    let mut out = Vec::new();
    for site in sites {
        for (n, v) in dist_infos(&site)? {
            if n == name {
                out.push((site.clone(), v));
            }
        }
    }
    Ok(out)
}
