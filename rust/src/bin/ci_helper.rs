//! Development-only checks for an explicitly supplied executable or release package.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn sha(path: &Path) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}
fn ensure(ok: bool, msg: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(msg.into())
    }
}
fn command(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<String> {
    let mut c = Command::new(program);
    c.args(args);
    if let Some(cwd) = cwd {
        c.current_dir(cwd);
    }
    let out = c.output()?;
    ensure(out.status.success(), "command failed")?;
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}
fn call(
    child: &mut Child,
    rx: &mpsc::Receiver<String>,
    id: u32,
    method: &str,
    params: Value,
) -> Result<(Value, f64)> {
    let start = Instant::now();
    writeln!(
        child.stdin.as_mut().ok_or("closed stdin")?,
        "{}",
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
    )?;
    child.stdin.as_mut().unwrap().flush()?;
    let line = rx.recv_timeout(Duration::from_secs(30))?;
    let value: Value = serde_json::from_str(&line)?;
    ensure(value["id"] == id, "MCP id mismatch")?;
    Ok((value, start.elapsed().as_secs_f64()))
}
fn tool(
    child: &mut Child,
    rx: &mpsc::Receiver<String>,
    id: u32,
    name: &str,
    args: Value,
) -> Result<(Value, f64)> {
    call(
        child,
        rx,
        id,
        "tools/call",
        json!({"name":name,"arguments":args}),
    )
}
fn wait(child: &mut Child, deadline: Instant) -> Result<()> {
    loop {
        if let Some(status) = child.try_wait()? {
            return ensure(status.success(), "child failed");
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("child timeout".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn smoke(binary: &Path) -> Result<()> {
    let binary = fs::canonicalize(binary)?;
    let tmp = tempfile::tempdir()?;
    let scratch = fs::canonicalize(tmp.path())?;
    let project = scratch.join("project");
    fs::create_dir(&project)?;
    fs::write(project.join("requirements.txt"), "requests==2.0.0\n")?;
    let state = scratch.join("state");
    fs::create_dir(&state)?;
    fs::write(
        state.join("config.json"),
        json!({"roots":[project]}).to_string(),
    )?;
    let start = Instant::now();
    let mut help = Command::new(&binary)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait(&mut help, start + Duration::from_secs(30))?;
    let startup = start.elapsed().as_secs_f64();
    let mut child = Command::new(&binary)
        .args(["--state", state.to_str().ok_or("non-UTF8 state")?, "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(s) => {
                    if tx.send(s).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let checked = (|| -> Result<Value> {
        let (r, init) = call(
            &mut child,
            &rx,
            1,
            "initialize",
            json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ci","version":"1"}}),
        )?;
        ensure(r.get("result").is_some(), "initialize rejected")?;
        let (r, _) = tool(&mut child, &rx, 2, "check", json!({"offline":true}))?;
        let inventory: Value = serde_json::from_str(
            r["result"]["content"][0]["text"]
                .as_str()
                .ok_or("no inventory")?,
        )?;
        ensure(
            inventory["packages"]
                .as_array()
                .ok_or("no packages")?
                .iter()
                .any(|p| p["name"] == "requests"),
            "requests missing",
        )?;
        ensure(inventory["status"] == "unknown", "offline status changed")?;
        for (id, name, args) in [
            (3, "check", json!({"offline":true,"roots":[scratch]})),
            (4, "list", json!({})),
            (5, "ack", json!({"reader":"ci"})),
        ] {
            let (r, _) = tool(&mut child, &rx, id, name, args)?;
            ensure(r.get("error").is_some(), "unauthorized call accepted")?;
        }
        let mut timings = Vec::new();
        for id in 6..17 {
            let (r, t) = tool(&mut child, &rx, id, "list", json!({"reader":"ci"}))?;
            ensure(r.get("result").is_some(), "reader list failed")?;
            timings.push(t);
        }
        let (r, _) = call(&mut child, &rx, 17, "ping", json!({}))?;
        ensure(r.get("result").is_some(), "ping failed")?;
        child.stdin.take();
        wait(&mut child, Instant::now() + Duration::from_secs(30))?;
        let warm = &timings[1..];
        let mut sorted = warm.to_vec();
        sorted.sort_by(f64::total_cmp);
        Ok(
            json!({"binary_sha256":sha(&binary)?,"help_startup_seconds":startup,"initialize_seconds":init,"list_first_seconds":timings[0],"list_warm_median_seconds":(sorted[4] + sorted[5]) / 2.0,"list_warm_samples_seconds":warm,"behavior":"pass"}),
        )
    })();
    if child.try_wait()?.is_none() {
        child.kill()?;
        child.wait()?;
    }
    println!("{}", serde_json::to_string_pretty(&checked?)?);
    Ok(())
}
fn files(root: &Path, dir: &Path, out: &mut serde_json::Map<String, Value>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            files(root, &path, out)?;
        } else if path.file_name().unwrap() != "SHA256SUMS"
            && path.file_name().unwrap() != "BUILD-MANIFEST.json"
        {
            out.insert(
                path.strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                json!(sha(&path)?),
            );
        }
    }
    Ok(())
}
fn provenance(package: &Path) -> Result<()> {
    let manifest = package.join("BUILD-MANIFEST.json");
    match fs::symlink_metadata(&manifest) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(_) => return Err("provenance requires a fresh package".into()),
    }
    let checksums = fs::read_to_string(package.join("SHA256SUMS"))?;
    ensure(
        !checksums.lines().any(|line| {
            line.split_whitespace().nth(1).is_some_and(|name| {
                matches!(
                    name.trim_start_matches('*'),
                    "BUILD-MANIFEST.json" | "./BUILD-MANIFEST.json"
                )
            })
        }),
        "provenance checksum already exists",
    )?;
    let names = fs::read_dir(package)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let artifacts: Vec<_> = names
        .iter()
        .filter(|name| name.to_string_lossy().starts_with("vorda-"))
        .collect();
    ensure(
        artifacts.len() == 1
            && artifacts[0]
                .to_string_lossy()
                .ends_with("-x86_64-unknown-linux-gnu"),
        "provenance supports only the x86_64 Linux GNU release/default workflow package",
    )?;
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("repo missing")?
        .to_path_buf();
    let lock = repo.join("rust/Cargo.lock");
    let mut artifacts = serde_json::Map::new();
    files(package, package, &mut artifacts)?;
    let parsed: toml::Value = toml::from_str(&fs::read_to_string(&lock)?)?;
    let metadata = json!({"schema":"vorda-candidate-v1","source_commit":command("git", &["rev-parse","HEAD"],Some(&repo))?,"rustc":command("rustc", &["-Vv"],None)?,"target":"x86_64-unknown-linux-gnu","profile":"release","features":"default","lock_sha256":sha(&lock)?,"run_id":env::var("GITHUB_RUN_ID").ok(),"run_attempt":env::var("GITHUB_RUN_ATTEMPT").ok(),"artifacts":artifacts,"dependencies":parsed.get("package").ok_or("no packages")?});
    fs::write(
        &manifest,
        format!("{}\n", serde_json::to_string_pretty(&metadata)?),
    )?;
    let mut checksums = fs::OpenOptions::new()
        .append(true)
        .open(package.join("SHA256SUMS"))?;
    writeln!(checksums, "{}  BUILD-MANIFEST.json", sha(&manifest)?)?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    ensure(args.len() == 3, "usage: ci_helper smoke|provenance PATH")?;
    let path = Path::new(&args[2]);
    match args[1].to_str() {
        Some("smoke") => smoke(path),
        Some("provenance") => provenance(path),
        _ => Err("unknown mode".into()),
    }
}
