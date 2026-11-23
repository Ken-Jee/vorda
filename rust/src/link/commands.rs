use super::{
    client::{request, sign_receipt, Outbox},
    encode, exact_fields, export_result,
    server::Server,
    storage::{Hub, DEFAULT_MAX_DB_BYTES},
    validate, MAX_BATCH,
};
use crate::fleet::auth::{DeviceGrant, GrantRequest, ReaderStore, Site, SourceGrant};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
};

/// Largest `--max-db-mib`: 1 TiB.
const MAX_DB_MIB: u64 = 1024 * 1024;

fn read_json(path: &Path) -> Result<Value> {
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_BATCH + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_BATCH {
        return Err(Error::new("file too large"));
    }
    Ok(serde_json::from_slice(&raw)?)
}
/// Advisory lock on a file beside the hub database: shared for hub commands, exclusive for migrate/restore.
fn lock(db: &Path, suffix: &str, exclusive: bool, refusal: &str) -> Result<std::fs::File> {
    let mut name = db.as_os_str().to_os_string();
    name.push(suffix);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(name)?;
    let locked = if exclusive {
        fs2::FileExt::try_lock_exclusive(&file)
    } else {
        fs2::FileExt::try_lock_shared(&file)
    };
    locked.map_err(|_| refusal_error(refusal))?;
    Ok(file)
}
fn refusal_error(message: &str) -> Error {
    // `vorda link` reports only the error class, so the instruction has to live there.
    Error {
        message: message.into(),
        class: message.into(),
        http_status: None,
        usage: false,
        busy: false,
    }
}
fn operator(
    action: &str,
    db: &Path,
    discard: bool,
    change_log: bool,
    max_db_bytes: u64,
) -> Result<Value> {
    let fail = |e: Error| refusal_error(&format!("{action} failed: {}", e.message));
    let _idle = lock(
        db,
        ".serve-lock",
        true,
        "hub is in use: stop link serve first",
    )?;
    if action == "migrate" {
        // An upgraded hub is only verified; traffic since the upgrade differs from the backup.
        if super::native::schema_version(db).is_ok_and(|v| matches!(v, 2 | 3)) {
            super::native::verify_upgraded(db).map_err(fail)?;
        } else {
            super::native::migrate_with_limit(db, max_db_bytes).map_err(fail)?;
        }
        // The change log (schema 3) is opt-in: a schema 2 hub keeps serving without it.
        if change_log {
            super::native::migrate_change_log_with_limit(db, max_db_bytes).map_err(fail)?;
        }
        let schema = super::native::schema_version(db).map_err(fail)?;
        return Ok(json!({"migrated":true,"schema":schema}));
    }
    let file = super::native::db_lock_file(db)?;
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| refusal_error("hub database is locked by another process"))?;
    // A schema 3 hub goes back to schema 2 by dropping its derived change log; nothing is lost.
    if super::native::schema_version(db).is_ok_and(|v| v == 3) {
        if discard {
            return Err(refusal_error(
                "--discard-post-upgrade does not apply to a schema 3 hub: run restore without it to drop the change log",
            ));
        }
        super::native::restore_change_log(db).map_err(fail)?;
        return Ok(json!({"restored":true,"schema":2}));
    }
    if !discard && super::native::post_upgrade_writes(db).map_err(fail)? {
        return Err(refusal_error(
            "restore would drop post-upgrade writes: rerun with --discard-post-upgrade to keep them only in the .failed-v2 copy",
        ));
    }
    super::native::restore(db).map_err(fail)?;
    Ok(json!({"restored":true,"schema":1}))
}
pub fn run(args: &[String]) -> Result<i32> {
    if args.is_empty() || args.iter().any(|s| s == "--help" || s == "-h") {
        println!("Usage: vorda link --db FILE {{invite,serve,enroll,revoke,rotate,snapshot,export,queue,queue-native,send,health,bundle,bind,enroll-local,import,ack,migrate,restore,reader-grant,reader-revoke,capture-allow,capture-deny}} [options]");
        return Ok(0);
    }
    let actions = [
        "invite",
        "serve",
        "enroll",
        "revoke",
        "rotate",
        "snapshot",
        "export",
        "queue",
        "queue-native",
        "send",
        "health",
        "bundle",
        "bind",
        "enroll-local",
        "import",
        "ack",
        "migrate",
        "restore",
        "reader-grant",
        "reader-revoke",
        "capture-allow",
        "capture-deny",
    ];
    let mut values: HashMap<String, Vec<String>> = HashMap::new();
    let mut flags = HashSet::new();
    let mut action = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if actions.contains(&arg.as_str()) && action.is_none() {
            action = Some(arg.as_str());
            continue;
        }
        if arg == "--consent" || arg == "--discard-post-upgrade" || arg == "--change-log" {
            flags.insert(arg.as_str());
            continue;
        }
        if ![
            "--db",
            "--invite-env",
            "--org",
            "--site",
            "--ttl",
            "--bind",
            "--port",
            "--cert",
            "--key",
            "--hub",
            "--ca-file",
            "--credential-env",
            "--device",
            "--overlap",
            "--result",
            "--deny-package",
            "--identity",
            "--batch",
            "--receipt",
            "--reader-env",
            "--reader",
            "--source",
            "--label",
            "--capture",
            "--max-db-mib",
        ]
        .contains(&arg.as_str())
        {
            return Err(Error::usage(format!(
                "unrecognized linking argument: {arg}"
            )));
        }
        values.entry(arg.clone()).or_default().push(
            iter.next()
                .filter(|value| !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V"))
                .ok_or_else(|| Error::usage(format!("{arg} requires a value")))?
                .clone(),
        );
    }
    let get = |name: &str| values.get(name).and_then(|v| v.last()).map(String::as_str);
    let required =
        |name: &str| get(name).ok_or_else(|| Error::usage(format!("{name} is required")));
    let secret = |name: &str| -> Result<String> {
        std::env::var(required(name)?)
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::new("required credential environment variable is unset"))
    };
    let action = action.ok_or_else(|| Error::usage("link action is required"))?;
    let (allowed, needs): (&[&str], &[&str]) = match action {
        "invite" => (
            &["--invite-env", "--org", "--site", "--ttl", "--max-db-mib"],
            &["--invite-env", "--org", "--site"],
        ),
        "serve" => (
            &["--bind", "--port", "--cert", "--key", "--max-db-mib"],
            &[],
        ),
        "migrate" => (&["--max-db-mib"], &[]),
        "enroll" => (
            &["--hub", "--ca-file", "--invite-env", "--credential-env"],
            &["--hub", "--invite-env", "--credential-env"],
        ),
        "revoke" | "snapshot" => (&["--device", "--max-db-mib"], &["--device"]),
        "rotate" => (
            &["--device", "--credential-env", "--overlap", "--max-db-mib"],
            &["--device", "--credential-env"],
        ),
        "export" | "queue" => (&["--result", "--deny-package"], &["--result"]),
        "queue-native" => (&["--capture"], &["--capture"]),
        "send" => (
            &["--hub", "--ca-file", "--credential-env"],
            &["--hub", "--credential-env"],
        ),
        "bind" => (&["--identity"], &["--identity"]),
        "reader-grant" => (
            &[
                "--reader-env",
                "--label",
                "--org",
                "--site",
                "--device",
                "--source",
                "--ttl",
                "--max-db-mib",
            ],
            &["--reader-env", "--label", "--org", "--site", "--ttl"],
        ),
        "reader-revoke" => (&["--reader", "--max-db-mib"], &["--reader"]),
        "capture-allow" | "capture-deny" => (&["--device", "--source"], &["--device", "--source"]),
        "enroll-local" => (
            &["--invite-env", "--credential-env", "--max-db-mib"],
            &["--invite-env", "--credential-env"],
        ),
        "import" => (
            &["--batch", "--credential-env", "--max-db-mib"],
            &["--batch", "--credential-env"],
        ),
        "ack" => (
            &["--receipt", "--credential-env"],
            &["--receipt", "--credential-env"],
        ),
        _ => (&[], &[]),
    };
    for name in values.keys() {
        if name != "--db" && !allowed.contains(&name.as_str()) {
            return Err(Error::usage(format!(
                "unrecognized {action} argument: {name}"
            )));
        }
    }
    for name in needs {
        required(name)?;
    }
    if ["export", "queue", "queue-native"].contains(&action) {
        if !flags.contains("--consent") {
            return Err(Error::usage("--consent is required"));
        }
        if flags.iter().any(|f| *f != "--consent") {
            return Err(Error::usage("flag not allowed for this action"));
        }
    } else if flags.iter().any(|f| {
        !matches!(
            (*f, action),
            ("--discard-post-upgrade", "restore") | ("--change-log", "migrate")
        )
    }) {
        return Err(Error::usage("flag not allowed for this action"));
    }
    let path = PathBuf::from(required("--db")?);
    let max_db_bytes = match get("--max-db-mib") {
        None => DEFAULT_MAX_DB_BYTES,
        Some(mib) => mib
            .parse::<u64>()
            .ok()
            .filter(|mib| (1..=MAX_DB_MIB).contains(mib))
            .map(|mib| mib * 1024 * 1024)
            .ok_or_else(|| Error {
                usage: true,
                ..refusal_error(&format!(
                    "--max-db-mib must be a whole number of MiB from 1 to {MAX_DB_MIB}"
                ))
            })?,
    };
    let ca = get("--ca-file").map(Path::new);
    let number = |name: &str, default: i64| -> Result<f64> {
        let value = match get(name) {
            Some(value) => crate::domain::integer(value).map_err(|e| Error::usage(e.message))?,
            None => default.into(),
        };
        value
            .as_f64()
            .filter(|v| v.is_finite())
            .ok_or_else(|| Error::usage("integer out of range"))
    };
    let result = if ["migrate", "restore"].contains(&action) {
        operator(
            action,
            &path,
            flags.contains("--discard-post-upgrade"),
            flags.contains("--change-log"),
            max_db_bytes,
        )?
    } else if [
        "enroll",
        "export",
        "queue",
        "queue-native",
        "send",
        "health",
        "bind",
        "bundle",
        "ack",
    ]
    .contains(&action)
    {
        let box_ = Outbox::open(&path)?;
        match action {
            "enroll" => {
                if box_.identity()?.is_some() {
                    return Err(Error::new(
                        "already enrolled; use a new outbox for re-enrollment",
                    ));
                }
                let identity = request(
                    required("--hub")?,
                    "/v1/enroll",
                    &secret("--invite-env")?,
                    &json!({"credential":secret("--credential-env")?}),
                    ca,
                )?;
                let device = identity["device"]
                    .as_str()
                    .ok_or_else(|| Error::new("invalid identity"))?;
                let generation = identity["generation"]
                    .as_str()
                    .ok_or_else(|| Error::new("invalid identity"))?;
                box_.bind(device, generation)?;
                identity
            }
            "bind" => {
                let identity = read_json(Path::new(required("--identity")?))?;
                if !exact_fields(&identity, &["device", "generation"])
                    || !identity
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                {
                    return Err(Error::new("invalid identity"));
                }
                box_.bind(
                    identity["device"].as_str().unwrap(),
                    identity["generation"].as_str().unwrap(),
                )?;
                identity
            }
            "bundle" => box_.bundle()?,
            "ack" => {
                box_.confirm(
                    &read_json(Path::new(required("--receipt")?))?,
                    &secret("--credential-env")?,
                )?;
                box_.health()?
            }
            "export" | "queue" => {
                if !flags.contains("--consent") {
                    return Err(Error::usage("--consent is required"));
                }
                let identity = box_
                    .identity()?
                    .or_else(|| {
                        if action == "export" {
                            Some(json!({"device":"offline","generation":"offline"}))
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| Error::new("enrollment required for queue"))?;
                let result = Path::new(required("--result")?);
                let denies = values.get("--deny-package").cloned().unwrap_or_default();
                let batch = export_result(
                    &serde_json::from_slice(&std::fs::read(result)?)?,
                    identity["device"].as_str().unwrap(),
                    identity["generation"].as_str().unwrap(),
                    &denies,
                )?;
                validate(&batch)?;
                if action == "queue" {
                    box_.enqueue(&batch)?
                } else {
                    batch
                }
            }
            "queue-native" => {
                let mut raw = Vec::new();
                let limit = super::native::REQUEST_LIMIT;
                std::fs::File::open(required("--capture")?)?
                    .take(limit as u64 + 1)
                    .read_to_end(&mut raw)?;
                if raw.len() > limit {
                    return Err(Error::instruction(
                        "capture file too large; nothing was queued",
                    ));
                }
                box_.enqueue_native(&serde_json::from_slice(&raw)?)?
            }
            "send" => {
                let ack = box_.deliver(required("--hub")?, &secret("--credential-env")?, ca)?;
                let mut health = box_.health()?;
                health["delivered"] = json!(ack.is_some());
                if let Some(ack) = ack {
                    health["ack"] = ack;
                }
                health
            }
            _ => box_.health()?,
        }
    } else {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            crate::store::private_dir(parent)?; // as Hub::open does, but before the lock file needs it
        }
        let _lease = lock(
            &path,
            ".serve-lock",
            false,
            "hub is being migrated or restored",
        )?;
        let hub = Hub::with_limit(&path, max_db_bytes)?;
        match action {
            "invite" => {
                hub.invite(
                    &secret("--invite-env")?,
                    required("--org")?,
                    required("--site")?,
                    number("--ttl", 600)?,
                )?;
                json!({"invite":"registered"})
            }
            "enroll-local" => {
                let credential = secret("--credential-env")?;
                crate::fleet::auth::refuse_reader_secret(&path, &credential)
                    .map_err(|e| refusal_error(&e.message))?;
                hub.enroll(&secret("--invite-env")?, &credential)?
            }
            "import" => {
                let credential = secret("--credential-env")?;
                let ack: Value = serde_json::from_slice(
                    &hub.ingest(&credential, &read_json(Path::new(required("--batch")?))?)?,
                )?;
                json!({"signature":sign_receipt(&ack,&credential)?,"ack":ack})
            }
            "serve" => {
                let port = number("--port", 7781)?;
                if !(0.0..=65535.0).contains(&port) {
                    return Err(Error::usage("port out of range"));
                }
                let admission = match super::native::schema_version(&path)? {
                    1 => None,
                    2 | 3 => Some(
                        super::native::Admission::open_with_limit(&path, vec![], max_db_bytes)?
                            .with_grants(
                                super::grants::CaptureGrants::open(&path)
                                    .map_err(|e| refusal_error(&e.message))?,
                            ),
                    ),
                    _ => return Err(Error::new("unsupported link schema")),
                };
                let server = Server::bind(
                    hub,
                    get("--bind").unwrap_or("127.0.0.1"),
                    port as u16,
                    get("--cert").map(Path::new),
                    get("--key").map(Path::new),
                )?;
                match &admission {
                    Some(admission) => server.serve_with_admission(admission)?,
                    None => server.serve()?,
                }
                return Ok(0);
            }
            "revoke" => {
                hub.revoke(required("--device")?)?;
                json!({"revoked":true})
            }
            "reader-grant" => {
                let org = required("--org")?;
                let sites: Vec<Site> = values["--site"]
                    .iter()
                    .map(|site| Site {
                        org: org.into(),
                        site: site.clone(),
                    })
                    .collect();
                let devices = values.get("--device").cloned().unwrap_or_default();
                let sources = values.get("--source").cloned().unwrap_or_default();
                let ttl = number("--ttl", 0)?;
                let reader = ReaderStore::grant(
                    &hub,
                    &secret("--reader-env")?,
                    &GrantRequest {
                        label: required("--label")?,
                        sites: &sites,
                        devices: if devices.is_empty() {
                            DeviceGrant::All
                        } else {
                            DeviceGrant::Listed(&devices)
                        },
                        sources: if sources.is_empty() {
                            SourceGrant::All
                        } else {
                            SourceGrant::Listed(&sources)
                        },
                        ttl,
                    },
                )
                .map_err(|e| refusal_error(&e.message))?;
                json!({"reader":reader,"expires_in":ttl})
            }
            "capture-allow" | "capture-deny" => {
                let (device, source) = (required("--device")?, required("--source")?);
                if action == "capture-allow" {
                    super::grants::CaptureGrants::allow(&path, device, source)
                } else {
                    super::grants::CaptureGrants::deny(&path, device, source)
                }
                .map_err(|e| refusal_error(&e.message))?;
                json!({"capture":action.trim_start_matches("capture-"),"device":device,"source":source})
            }
            "reader-revoke" => {
                if !ReaderStore::exists(&path) {
                    return Err(refusal_error("no reader store for this hub"));
                }
                ReaderStore::open(&path)
                    .and_then(|store| store.revoke(required("--reader")?))
                    .map_err(|e| refusal_error(&e.message))?;
                json!({"revoked":true})
            }
            "rotate" => {
                hub.rotate(
                    required("--device")?,
                    &secret("--credential-env")?,
                    number("--overlap", 300)?,
                )?;
                json!({"rotated":true})
            }
            _ => hub.snapshot(required("--device")?)?,
        }
    };
    println!(
        "{}",
        String::from_utf8(encode(&result)?).map_err(|_| Error::new("invalid JSON encoding"))?
    );
    Ok(0)
}
