use fs2::FileExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime},
};

const MIB: u64 = 1024 * 1024;
const OWNER: &str = "vorda-cargo-cache/v1";
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}
fn bad(s: impl Into<String>) -> io::Error {
    io::Error::other(s.into())
}
fn owned(p: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(p)?;
    if !m.file_type().is_dir() || m.uid() != unsafe { libc::geteuid() } {
        return Err(bad(format!("unsafe cache directory: {}", p.display())));
    }
    Ok(())
}
fn ensure_dir(p: &Path) -> io::Result<()> {
    if !p.exists() {
        fs::create_dir(p)?;
    }
    owned(p)
}
fn atomic(p: &Path, v: &Value) -> io::Result<()> {
    let tmp = p.with_extension("pending");
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    let result = (|| {
        f.write_all(v.to_string().as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, p)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
fn walk(root: &Path, deadline: Instant, count: &mut usize) -> io::Result<u64> {
    let mut bytes = 0;
    if !root.exists() {
        return Ok(0);
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    for entry in entries {
        if *count >= 50_000 || Instant::now() >= deadline {
            return Err(bad("cache accounting bound exceeded"));
        }
        *count += 1;
        let entry = entry?;
        let m = match fs::symlink_metadata(entry.path()) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if m.file_type().is_symlink() {
            return Err(bad("cache contains symlink"));
        }
        if m.file_type().is_dir() {
            bytes += walk(&entry.path(), deadline, count)?;
        } else if m.file_type().is_file() {
            bytes += m.len();
        } else {
            return Err(bad("cache contains nonregular entry"));
        }
    }
    Ok(bytes)
}
fn size(p: &Path) -> io::Result<u64> {
    let secs = env::var("VORDA_CACHE_SCAN_SECONDS")
        .ok()
        .map(|s| s.parse::<u64>())
        .transpose()
        .map_err(|_| bad("bad scan deadline"))?
        .unwrap_or(5);
    if !(1..=30).contains(&secs) {
        return Err(bad("scan deadline must be 1-30 seconds"));
    }
    walk(p, Instant::now() + Duration::from_secs(secs), &mut 0)
}
fn free(p: &Path) -> io::Result<u64> {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c.as_ptr(), s.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let s = unsafe { s.assume_init() };
    Ok(s.f_bavail * s.f_frsize)
}
fn reclaim(cache: &Path, active: &Path) -> io::Result<()> {
    let mut entries = Vec::new();
    for e in fs::read_dir(cache)? {
        let p = e?.path();
        if !p.is_dir() {
            continue;
        }
        owned(&p)?;
        let marker = p.join("owner.json");
        let v: Value =
            serde_json::from_slice(&fs::read(&marker)?).map_err(|_| bad("unknown cache owner"))?;
        if v["owner"] != OWNER {
            return Err(bad("unknown cache owner"));
        }
        let age = fs::metadata(&marker)?.modified()?;
        entries.push((age, p));
    }
    entries.sort_by_key(|(age, _)| *age);
    let mut total = 0;
    for (_, p) in &entries {
        total += size(p)?;
    }
    for (age, p) in entries {
        if p == active || p.join("PIN").exists() || p.join("EVIDENCE").exists() {
            continue;
        }
        let old = SystemTime::now().duration_since(age).unwrap_or_default()
            > Duration::from_secs(7 * 86400);
        if old || total > 3 * 1024 * MIB || free(cache)? < 256 * MIB {
            let amount = size(&p)?;
            fs::remove_dir_all(&p)?;
            total = total.saturating_sub(amount);
            println!(
                "{}",
                json!({"event":"evicted","namespace":p.file_name().unwrap().to_string_lossy(),"bytes":amount})
            );
        }
    }
    if total > 3 * 1024 * MIB || free(cache)? < 256 * MIB {
        return Err(bad(
            "cache budget/free-space floor; protected data retained",
        ));
    }
    Ok(())
}
fn source_digest(root: &Path) -> io::Result<String> {
    let o = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()?;
    if !o.status.success() {
        return Err(bad("source inventory failed"));
    }
    let mut names: Vec<&[u8]> = o
        .stdout
        .split(|b| *b == 0)
        .filter(|n| !n.is_empty())
        .collect();
    names.sort();
    names.dedup();
    if names.len() > 10_000 {
        return Err(bad("source file-count budget"));
    }
    let mut hash = Sha256::new();
    let mut total = 0;
    for name in names {
        use std::os::unix::ffi::OsStrExt;
        let p = root.join(std::ffi::OsStr::from_bytes(name));
        hash.update(name);
        hash.update([0]);
        match fs::symlink_metadata(&p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => hash.update(b"deleted"),
            Err(e) => return Err(e),
            Ok(m) => {
                if !m.file_type().is_file() {
                    return Err(bad("nonregular source"));
                }
                total += m.len();
                if total > 64 * MIB {
                    return Err(bad("source byte budget"));
                }
                hash.update(format!("{}", m.mode() & 0o777));
                let mut f = File::open(p)?;
                let mut buf = [0u8; 65536];
                loop {
                    let n = f.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buf[..n]);
                }
            }
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}
/// Process groups of every live process in session `sid`. The command runs under `setsid`, but
/// nextest moves each test into its own group, so the child's group alone misses them.
/// `None` when `/proc` cannot be listed. Group ids found here cannot have been reused: Linux keeps
/// a pid or pgid number allocated while any member is alive, so `kill(-group)` stays in the session.
fn session_groups(sid: i32) -> Option<Vec<i32>> {
    let mut groups = Vec::new();
    // The override exists so a test can make /proc unreadable.
    let proc_root = env::var("VORDA_CONTROLLER_PROC").unwrap_or_else(|_| "/proc".into());
    for entry in fs::read_dir(proc_root).ok()?.flatten() {
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Fields after the parenthesised command name: state ppid pgrp session.
        let mut fields = stat.rsplit(')').next().unwrap_or("").split_whitespace();
        let (state, _ppid, pgrp, session) =
            (fields.next(), fields.next(), fields.next(), fields.next());
        if let (Some(state), Some(pgrp), Some(session)) = (state, pgrp, session) {
            let pgrp: i32 = pgrp.parse().unwrap_or(0);
            if state != "Z" && session.parse() == Ok(sid) && pgrp > 0 && !groups.contains(&pgrp) {
                groups.push(pgrp);
            }
        }
    }
    Some(groups)
}
fn stop(child: &mut Child) -> io::Result<()> {
    let sid = child.id() as i32;
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        let mut sent = vec![sid];
        unsafe {
            libc::kill(-sid, signal);
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            let _ = child.try_wait()?;
            // Without /proc, fall back to the spawned command's own group: wait for it to go.
            let groups = match session_groups(sid) {
                Some(groups) => groups,
                None if unsafe { libc::kill(-sid, 0) } != 0 => vec![],
                None => vec![sid],
            };
            if groups.is_empty() {
                let _ = child.wait();
                return Ok(());
            }
            for group in groups {
                if !sent.contains(&group) {
                    unsafe {
                        libc::kill(-group, signal);
                    }
                    sent.push(group);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Err(bad("process group failed to stop"))
}
fn run(
    args: &[String],
    cwd: &Path,
    envs: &[(String, String)],
    log: &File,
    log_path: &Path,
    namespace: &Path,
    cache: &Path,
) -> io::Result<()> {
    let mut c = Command::new(&args[0]);
    c.args(&args[1..])
        .current_dir(cwd)
        .stdout(log.try_clone()?)
        .stderr(Stdio::from(log.try_clone()?));
    for (k, v) in envs {
        c.env(k, v);
    }
    unsafe {
        c.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = c.spawn()?;
    let start = Instant::now();
    let mut sampled = Instant::now() - Duration::from_secs(2);
    loop {
        if STOP.load(Ordering::SeqCst) {
            stop(&mut child)?;
            return Err(bad("acceptance interrupted"));
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                stop(&mut child)?;
                return Err(error);
            }
        };
        if let Some(status) = status {
            if status.success() {
                stop(&mut child)?;
                return Ok(());
            }
            stop(&mut child)?;
            return Err(bad(format!("command failed: {status}")));
        }
        if start.elapsed() > Duration::from_secs(600) {
            stop(&mut child)?;
            return Err(bad("command exceeded ten minutes"));
        }
        if sampled.elapsed() >= Duration::from_secs(2) {
            let check = (|| {
                if fs::metadata(log_path)?.len() > 8 * MIB {
                    return Err(bad("command log exceeds eight MiB"));
                }
                if size(namespace)? > 2 * 1024 * MIB {
                    return Err(bad("active namespace exceeds two GiB"));
                }
                reclaim(cache, namespace)
            })();
            if let Err(e) = check {
                stop(&mut child)?;
                return Err(e);
            }
            sampled = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn main_run() -> io::Result<()> {
    unsafe {
        libc::signal(libc::SIGINT, interrupt as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, interrupt as *const () as libc::sighandler_t);
    }
    let args: Vec<String> = env::args().skip(1).collect();
    let mut invalidation_error = None;
    for pair in args.windows(2) {
        if pair[0] == "--result-file" && !pair[1].starts_with("--") {
            match fs::remove_file(&pair[1]) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => {
                    invalidation_error.get_or_insert(e);
                }
            }
        }
    }
    if let Some(e) = invalidation_error {
        return Err(e);
    }
    if args.is_empty() || !["local", "ci"].contains(&args[0].as_str()) {
        return Err(bad(
            "usage: vorda-ci-controller local|ci [--compile-only] [--fresh] [--result-file PATH]",
        ));
    }
    let compile_only = args.contains(&"--compile-only".into());
    let fresh = args.contains(&"--fresh".into());
    let mut result_file = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--compile-only" | "--fresh" => i += 1,
            "--result-file" => {
                if result_file.is_some() {
                    return Err(bad("duplicate result path"));
                }
                result_file = Some(PathBuf::from(
                    args.get(i + 1)
                        .filter(|p| !p.starts_with("--"))
                        .ok_or_else(|| bad("missing result path"))?,
                ));
                i += 2;
            }
            _ => return Err(bad("unknown option")),
        }
    }
    if let Some(p) = &result_file {
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    if args[0] == "local"
        && !fs::read_to_string("/proc/self/cgroup")?.contains("/vorda-rust-build-")
    {
        return Err(bad("local requires capacity launcher cgroup"));
    }
    let started = Instant::now();
    unsafe {
        libc::umask(0o077);
    }
    let root = fs::canonicalize(
        env::var("VORDA_SOURCE_ROOT").map_err(|_| bad("VORDA_SOURCE_ROOT absent"))?,
    )?;
    let base =
        PathBuf::from(env::var("CARGO_TARGET_DIR").map_err(|_| bad("CARGO_TARGET_DIR absent"))?);
    ensure_dir(&base)?;
    let cache = base.join("acceptance-v2");
    ensure_dir(&cache)?;
    let lock = OpenOptions::new()
        .create(true)
        .append(true)
        .open(cache.join("lock"))?;
    lock.lock_exclusive()?;
    let compiler = Command::new("rustc").arg("-vV").output()?;
    if !compiler.status.success() {
        return Err(bad("rustc identity failed"));
    }
    let compiler = String::from_utf8(compiler.stdout).map_err(|_| bad("rustc identity invalid"))?;
    let host = compiler
        .lines()
        .find_map(|s| s.strip_prefix("host: "))
        .ok_or_else(|| bad("rustc host absent"))?;
    let config: Vec<_> = [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_INCREMENTAL",
        "CARGO_PROFILE_DEV_DEBUG",
        "CARGO_PROFILE_TEST_DEBUG",
    ]
    .map(|k| (k, env::var(k).unwrap_or_default()))
    .to_vec();
    let identity = json!({"root":root,"compiler":compiler,"target":host,"profile":"debug","features":"default","config":config});
    let key = format!("{:x}", Sha256::digest(identity.to_string().as_bytes()))[..24].to_string();
    let ns = cache.join(&key);
    reclaim(&cache, &ns)?;
    ensure_dir(&ns)?;
    atomic(
        &ns.join("owner.json"),
        &json!({"owner":OWNER,"identity":identity}),
    )?;
    let report = ns.join(if compile_only {
        "last-seed.json"
    } else {
        "last-check.json"
    });
    for p in [ns.join("last-check.json"), report.clone()] {
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    let target = ns.join("target");
    if target.exists() && (fresh || size(&ns)? >= 1536 * MIB) {
        if ns.join("PIN").exists() || ns.join("EVIDENCE").exists() {
            return Err(bad("pinned target cannot be cleared"));
        }
        owned(&target)?;
        let bytes = size(&target)?;
        fs::remove_dir_all(&target)?;
        println!(
            "{}",
            json!({"event":"target-reclaimed","bytes":bytes,"reason":if fresh{"explicit-fresh"}else{"build-headroom"}})
        );
    }
    let before = source_digest(&root)?;
    let log_path = ns.join(if compile_only {
        "seed.log"
    } else {
        "check.log"
    });
    let log = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)?;
    println!(
        "{}",
        json!({"event":if compile_only{"seed-start"}else{"acceptance-start"},"log":log_path})
    );
    let envs = vec![
        (
            "CARGO_TARGET_DIR".into(),
            target.to_string_lossy().into_owned(),
        ),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
        ("GIT_AUTHOR_NAME".into(), "Fixture".into()),
        ("GIT_AUTHOR_EMAIL".into(), "fixture@example.invalid".into()),
        ("GIT_COMMITTER_NAME".into(), "Fixture".into()),
        (
            "GIT_COMMITTER_EMAIL".into(),
            "fixture@example.invalid".into(),
        ),
    ];
    // Acceptance runs nextest at four threads with no retries; seeds only compile.
    let mut cmd: Vec<String> = if compile_only {
        ["cargo", "test", "--no-run", "--message-format=json"]
            .map(Into::into)
            .to_vec()
    } else {
        [
            "cargo",
            "nextest",
            "run",
            "--cargo-message-format=json",
            "--test-threads=4",
            "--retries=0",
        ]
        .map(Into::into)
        .to_vec()
    };
    cmd.extend(["--locked", "--offline", "--target", host].map(String::from));
    run(
        &cmd,
        &root.join("rust"),
        &envs,
        &log,
        &log_path,
        &ns,
        &cache,
    )?;
    if !compile_only {
        // nextest does not run doctests.
        run(
            &[
                "cargo".into(),
                "test".into(),
                "--doc".into(),
                "--locked".into(),
                "--offline".into(),
                "--target".into(),
                host.into(),
            ],
            &root.join("rust"),
            &envs,
            &log,
            &log_path,
            &ns,
            &cache,
        )?;
        run(
            &[
                "cargo".into(),
                "build".into(),
                "--locked".into(),
                "--offline".into(),
                "--target".into(),
                host.into(),
                "--bin".into(),
                "ci_helper".into(),
            ],
            &root.join("rust"),
            &envs,
            &log,
            &log_path,
            &ns,
            &cache,
        )?;
        run(
            &[
                target
                    .join(host)
                    .join("debug/ci_helper")
                    .to_string_lossy()
                    .into_owned(),
                "smoke".into(),
                target
                    .join(host)
                    .join("debug/vorda")
                    .to_string_lossy()
                    .into_owned(),
            ],
            &root,
            &envs,
            &log,
            &log_path,
            &ns,
            &cache,
        )?;
    }
    if size(&ns)? > 2 * 1024 * MIB {
        return Err(bad("active namespace exceeds two GiB"));
    }
    if source_digest(&root)? != before {
        return Err(bad("source changed while commands ran"));
    }
    let mut built = 0;
    let mut fresh_units = 0;
    for line in fs::read_to_string(&log_path)?.lines() {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v["reason"] == "compiler-artifact" {
                if v["fresh"] == true {
                    fresh_units += 1
                } else {
                    built += 1
                }
            }
        }
    }
    let mut result = json!({"status":if compile_only{"compiled"}else{"passed"},"source_digest":before,"namespace":key,"log":log_path,"compiled_units":built,"fresh_units":fresh_units,"test_results_reused":false,"seconds":started.elapsed().as_secs_f64(),"cache_bytes":size(&cache)?});
    if compile_only {
        result["tests_executed"] = json!(false);
    } else {
        result["binary"] = json!(target.join(host).join("debug/vorda"));
    }
    if let Some(p) = result_file {
        atomic(&p, &result)?;
    }
    atomic(&report, &result)?;
    println!("{result}");
    Ok(())
}
fn main() {
    if let Err(e) = main_run() {
        println!("{}", json!({"status":"failed","error":e.to_string()}));
        std::process::exit(1)
    }
}
