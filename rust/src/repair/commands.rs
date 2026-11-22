use crate::{Error, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn run(argv: &[String], cwd: Option<&Path>) -> Result<String> {
    execute(argv, cwd, None, true)
}
pub fn search_path() -> std::ffi::OsString {
    #[cfg(windows)]
    {
        let current = std::env::current_dir().ok();
        let paths = std::env::var_os("PATH").unwrap_or_default();
        std::env::join_paths(
            std::env::split_paths(&paths)
                .filter(|p| p.is_absolute() && current.as_ref() != Some(p)),
        )
        .unwrap_or_else(|_| "C:\\Windows\\System32".into())
    }
    #[cfg(not(windows))]
    {
        "/usr/local/bin:/usr/bin:/bin".into()
    }
}
pub fn execute(
    argv: &[String],
    cwd: Option<&Path>,
    input: Option<&str>,
    checked: bool,
) -> Result<String> {
    if argv.is_empty() || argv.iter().any(|a| a.contains('\0')) {
        return Err(Error::new("command is empty or contains a null byte"));
    }
    let git = argv[0] == "git";
    if git {
        if let Some(root) = cwd {
            if !root.join(".git").is_dir() || root.join(".gitmodules").exists() {
                return Err(Error::new(
                    "repair root must be a standalone repository without submodules",
                ));
            }
            let out = plain(
                &strings(&[
                    "git",
                    "config",
                    "--null",
                    "--show-origin",
                    "--show-scope",
                    "--list",
                    "--includes",
                ]),
                Some(root),
                None,
                true,
                true,
            )?;
            let parts: Vec<_> = out.split('\0').collect();
            for fields in parts.as_chunks::<3>().0 {
                let key = fields[2].split('\n').next().unwrap_or("").to_lowercase();
                if ["filter.", "gpg.", "diff."]
                    .iter()
                    .any(|p| key.starts_with(p))
                    || [
                        "core.sshcommand",
                        "core.pager",
                        "core.editor",
                        "core.worktree",
                    ]
                    .contains(&key.as_str())
                {
                    return Err(Error::new(format!("repair refused executable Git setting {key}; use manual updates or a separate repair environment")));
                }
            }
        }
    }
    let mut args = argv.to_vec();
    let hooks = if git {
        Some(tempfile::tempdir()?)
    } else {
        None
    };
    if git {
        args = strings(&[
            "git",
            "-c",
            &format!(
                "core.hooksPath={}",
                hooks.as_ref().unwrap().path().display()
            ),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "diff.ignoreSubmodules=all",
        ]);
        args.extend_from_slice(&argv[1..]);
        if argv.get(1).is_some_and(|x| x == "status") {
            args.push("--ignore-submodules=all".into());
        }
    }
    plain(&args, cwd, input, checked, git)
}
fn plain(
    argv: &[String],
    cwd: Option<&Path>,
    input: Option<&str>,
    checked: bool,
    isolated_git: bool,
) -> Result<String> {
    let empty_global = if isolated_git {
        Some(tempfile::NamedTempFile::new()?)
    } else {
        None
    };
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .env_clear()
        .env("PATH", search_path())
        .env("LANG", "C.UTF-8")
        .env("HOME", home())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(global) = &empty_global {
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", global.path());
    }
    #[cfg(windows)]
    for name in [
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "ProgramFiles",
        "ProgramFiles(x86)",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(path) = cwd {
        command.current_dir(path);
    }
    checked_output(bounded_output(command, input, 120)?, checked)
}
pub fn identity(root: &Path, key: &str) -> Result<String> {
    let value = plain(
        &strings(&["git", "--no-pager", "config", "--get", key]),
        Some(root),
        None,
        true,
        false,
    )?;
    if value.trim().is_empty() {
        return Err(Error::new("set a Git identity in the repair repository"));
    }
    Ok(value.trim().into())
}
pub fn clone_source(path: &str) -> Result<String> {
    #[cfg(windows)]
    if let Some(drive) = path.strip_prefix(r"\\?\") {
        if drive.as_bytes().get(1) == Some(&b':') {
            return Ok(drive.into());
        }
        return Err(Error::new("repair clone requires a local drive path"));
    }
    Ok(path.into())
}
fn checked_output(output: std::process::Output, checked: bool) -> Result<String> {
    if checked && !output.status.success() {
        return Err(Error::new(format!(
            "command failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
pub fn bounded(command: Command, seconds: u64) -> Result<String> {
    checked_output(bounded_output(command, None, seconds)?, true)
}
pub fn bounded_status(command: Command, seconds: u64) -> Result<std::process::Output> {
    bounded_output(command, None, seconds)
}
fn bounded_output(
    mut command: Command,
    input: Option<&str>,
    seconds: u64,
) -> Result<std::process::Output> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    if let Some(input) = input {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    for (is_error, stream) in [
        (false, Box::new(stdout) as Box<dyn Read + Send>),
        (true, Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let tx = tx.clone();
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stream.take(8_000_001).read_to_end(&mut bytes);
            let _ = tx.send((is_error, result, bytes));
        });
    }
    drop(tx);
    let start = Instant::now();
    let mut output = None;
    let mut errors = None;
    let mut status = None;
    loop {
        while let Ok((is_error, result, bytes)) = rx.try_recv() {
            result?;
            if is_error {
                errors = Some(bytes);
            } else {
                output = Some(bytes);
            }
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        if status.is_some() && output.is_some() && errors.is_some() {
            break;
        }
        let overflow = output.as_ref().is_some_and(|v| v.len() > 8_000_000)
            || errors.as_ref().is_some_and(|v| v.len() > 8_000_000);
        if overflow || start.elapsed() > Duration::from_secs(seconds) {
            #[cfg(unix)]
            {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::new(if overflow {
                "command output exceeds limit"
            } else {
                "Command timed out"
            }));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let (o, e, status) = (output.unwrap(), errors.unwrap(), status.unwrap());
    if o.len() > 8_000_000 || e.len() > 8_000_000 {
        return Err(Error::new("command output exceeds limit"));
    }
    Ok(std::process::Output {
        status,
        stdout: o,
        stderr: e,
    })
}

pub fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}
pub fn home() -> PathBuf {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
pub fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}
pub fn regular(path: &Path, limit: u64) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.len() > limit {
        return Err(Error::new("needs a regular file within the size limit"));
    }
    Ok(())
}
pub fn os_plan(manager: &str, package: &str, old: &str, new: &str) -> Result<Value> {
    let re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9+_.:@~%\-]*$").unwrap();
    if ![package, old, new].iter().all(|s| re.is_match(s)) {
        return Err(Error::new("invalid package or version"));
    }
    if manager != "apt" {
        return Err(Error::new("only apt has a verified upgrade-only adapter"));
    }
    Ok(
        json!({"kind":"os","manager":manager,"package":package,"old":old,"new":new,
        "dry_run":["apt-get","--simulate","install","--only-upgrade","--",format!("{package}={new}")],
        "apply":["apt-get","-y","--no-remove","-o","Dpkg::Options::=--force-confdef","-o","Dpkg::Options::=--force-confold","install","--only-upgrade","--",format!("{package}={new}")],
        "undo":["apt-get","-y","--no-remove","-o","Dpkg::Options::=--force-confdef","-o","Dpkg::Options::=--force-confold","install","--only-upgrade","--allow-downgrades","--",format!("{package}={old}")]}),
    )
}
pub fn vector(v: &Value) -> Result<Vec<String>> {
    v.as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| Error::new("command requires an explicit argument list"))?
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty())
                .map(String::from)
                .ok_or_else(|| Error::new("command arguments must be strings"))
        })
        .collect()
}
pub fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::new(format!("{key} required")))
}
pub fn os_dry_run(plan: &Value) -> Result<String> {
    let (package, old, new) = (
        field(plan, "package")?,
        field(plan, "old")?,
        field(plan, "new")?,
    );
    let available = run(&strings(&["apt-cache", "madison", "--", package]), None)?;
    if !available
        .lines()
        .any(|l| l.split('|').nth(1).is_some_and(|s| s.trim() == old))
    {
        return Err(Error::new(
            "rollback version is unavailable; refusing upgrade",
        ));
    }
    if run(
        &strings(&["dpkg-query", "-W", "-f=${Package}", "--", package]),
        None,
    )?
    .trim()
        != package
    {
        return Err(Error::new("an exact installed package name is required"));
    }
    run(
        &strings(&["dpkg", "--compare-versions", new, "gt", old]),
        None,
    )?;
    let result = run(&vector(&plan["dry_run"])?, None)?;
    for line in result.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words
            .first()
            .is_some_and(|s| ["Inst", "Remv", "Conf"].contains(s))
            && (words[0] == "Remv"
                || words.get(1).map(|s| s.split(':').next().unwrap())
                    != Some(package.split(':').next().unwrap()))
        {
            return Err(Error::new("upgrade would change another package"));
        }
    }
    Ok(result)
}
pub fn patch_versions(old: &str, new: &str) -> Result<()> {
    fn parse(s: &str) -> Option<Vec<(usize, String)>> {
        if !regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$")
            .unwrap()
            .is_match(s)
        {
            return None;
        }
        Some(
            s.split('.')
                .map(|v| {
                    let v = v.trim_start_matches('0');
                    (v.len(), v.to_string())
                })
                .collect(),
        )
    }
    let (a, b) = (
        parse(old).ok_or_else(|| Error::new("exact stable versions are required"))?,
        parse(new).ok_or_else(|| Error::new("exact stable versions are required"))?,
    );
    if a[..2] != b[..2] || b <= a {
        return Err(Error::new("only increasing patch bumps are supported"));
    }
    Ok(())
}
pub fn repo_plan(
    root: &Path,
    package: &str,
    old: &str,
    new: &str,
    check: &Value,
    locked: Option<&Value>,
) -> Result<Value> {
    let root = fs::canonicalize(root)?;
    if run(&strings(&["git", "ls-files", "--stage"]), Some(&root))?
        .lines()
        .any(|l| l.starts_with("160000 "))
    {
        return Err(Error::new("repositories with gitlinks are unsupported"));
    }
    if !run(&strings(&["git", "status", "--porcelain"]), Some(&root))?
        .trim()
        .is_empty()
    {
        return Err(Error::new("repository must be clean"));
    }
    if !regex::Regex::new(r"^[A-Za-z0-9@/_.\-]+$")
        .unwrap()
        .is_match(package)
    {
        return Err(Error::new("invalid package name"));
    }
    patch_versions(old, new)?;
    vector(check)?;
    regular(&root.join("package.json"), 4_000_000)?;
    if locked.is_none()
        && [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lock",
            "bun.lockb",
        ]
        .iter()
        .any(|p| root.join(p).exists())
    {
        return Err(Error::new("lockfile repair requires an ecosystem resolver"));
    }
    let data = read_json(&root.join("package.json"))?;
    let sections: Vec<_> = ["dependencies", "devDependencies"]
        .into_iter()
        .filter(|s| data[s][package] == old)
        .collect();
    if sections.len() != 1 {
        return Err(Error::new("expected exactly one exact dependency version"));
    }
    let mut plan = json!({"kind":"repo","root":root,"package":package,"old":old,"new":new,"head":run(&strings(&["git","rev-parse","HEAD"]),Some(&root))?.trim(),"section":sections[0],"check":check});
    if let Some(locked) = locked {
        if locked.as_object().map(|o| o.len()) != Some(3)
            || locked.get("package_delta").is_none()
            || locked["before"].as_object().map(|o| o.len()) != Some(2)
            || locked["after"].as_object().map(|o| o.len()) != Some(2)
        {
            return Err(Error::new(
                "expected an exact manifest and lockfile candidate",
            ));
        }
        for name in ["package.json", "package-lock.json"] {
            regular(&root.join(name), 4_000_000)?;
            if Some(fs::read_to_string(root.join(name))?.as_str())
                != locked["before"][name].as_str()
            {
                return Err(Error::new("locked repository changed since resolution"));
            }
        }
        let mut expected = data;
        expected[sections[0]][package] = json!(new);
        let manifest: Value = serde_json::from_str(field(&locked["after"], "package.json")?)?;
        let lock: Value = serde_json::from_str(field(&locked["after"], "package-lock.json")?)?;
        if manifest != expected
            || lock["packages"][format!("node_modules/{package}")]["version"] != new
        {
            return Err(Error::new("locked candidate differs from requested repair"));
        }
        plan["locked"] = locked.clone();
    }
    Ok(plan)
}
pub fn apply_repo(plan: &Value, branch: &str) -> Result<Value> {
    let root = Path::new(field(plan, "root")?);
    if repo_plan(
        root,
        field(plan, "package")?,
        field(plan, "old")?,
        field(plan, "new")?,
        &plan["check"],
        plan.get("locked"),
    )? != *plan
    {
        return Err(Error::new("repository changed since planning"));
    }
    let previous = run(
        &strings(&["git", "symbolic-ref", "--short", "HEAD"]),
        Some(root),
    )?
    .trim()
    .to_string();
    let names = if plan.get("locked").is_some() {
        vec!["package.json", "package-lock.json"]
    } else {
        vec!["package.json"]
    };
    let originals: Vec<_> = names
        .iter()
        .map(|n| fs::read(root.join(n)))
        .collect::<std::io::Result<_>>()?;
    run(&strings(&["git", "switch", "-c", branch]), Some(root))?;
    let mutation = (|| -> Result<()> {
        if let Some(locked) = plan.get("locked") {
            for name in &names {
                fs::write(root.join(name), field(&locked["after"], name)?)?;
            }
        } else {
            let mut data: Value = serde_json::from_slice(&originals[0])?;
            data[field(plan, "section")?][field(plan, "package")?] = plan["new"].clone();
            fs::write(
                root.join("package.json"),
                format!("{}\n", serde_json::to_string_pretty(&data)?),
            )?;
        }
        run(&vector(&plan["check"])?, Some(root))?;
        if read_json(&root.join("package.json"))?[field(plan, "section")?][field(plan, "package")?]
            != plan["new"]
        {
            return Err(Error::new("check command changed the dependency"));
        }
        if let Some(locked) = plan.get("locked") {
            for name in &names {
                if fs::read_to_string(root.join(name))? != field(&locked["after"], name)? {
                    return Err(Error::new(
                        "check command changed the reviewed locked candidate",
                    ));
                }
            }
        }
        let mut add = strings(&["git", "add", "--"]);
        add.extend(names.iter().map(|s| s.to_string()));
        run(&add, Some(root))?;
        let author = identity(root, "user.name")?;
        let email = identity(root, "user.email")?;
        run(
            &strings(&[
                "git",
                "-c",
                &format!("user.name={author}"),
                "-c",
                &format!("user.email={email}"),
                "commit",
                "-m",
                &format!(
                    "Bump {} to {}",
                    field(plan, "package")?,
                    field(plan, "new")?
                ),
            ]),
            Some(root),
        )?;
        Ok(())
    })();
    if let Err(error) = mutation {
        let rollback = (|| -> Result<()> {
            for (name, bytes) in names.iter().zip(originals) {
                fs::write(root.join(name), bytes)?;
            }
            let mut args = strings(&["git", "restore", "--staged", "--"]);
            args.extend(names.iter().map(|s| s.to_string()));
            run(&args, Some(root))?;
            run(&strings(&["git", "switch", &previous]), Some(root))?;
            Ok(())
        })();
        let mut e = Error::new(match &rollback {
            Ok(_) => error.to_string(),
            Err(r) => format!("{error}; rollback: {r}"),
        });
        e.class = if rollback.is_ok() {
            "rolled-back"
        } else {
            "rollback-failed"
        }
        .into();
        return Err(e);
    }
    Ok(
        json!({"branch":branch,"previous":previous,"head":plan["head"],"undo":["git","switch",previous]}),
    )
}
