//! Shared fixtures for the fleet tests: a schema-2 hub with devices in two organizations and sites,
//! and reader grants over it.
#![allow(dead_code)]
pub mod tls;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use tempfile::TempDir;
use vorda::{
    fleet::auth::{AuthorizedScope, DeviceGrant, GrantRequest, ReaderStore, Site, SourceGrant},
    link::{
        native::{self, Admission, TrustedCapture},
        storage::Hub,
    },
    store::{capture, Store},
};

pub const ORG: &str = "org-synthetic";
pub const READER_A: &str = "synthetic-reader-a-tests-only-000000";
pub const READER_B: &str = "synthetic-reader-b-tests-only-000000";

pub fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

pub fn canonical(v: &Value) -> Vec<u8> {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => json!(m
                .iter()
                .map(|(k, v)| (k, sorted(v)))
                .collect::<std::collections::BTreeMap<_, _>>()),
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sorted(v)).unwrap()
}

pub fn status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

pub fn body(response: &[u8]) -> &[u8] {
    let n = response.windows(4).position(|p| p == b"\r\n\r\n").unwrap() + 4;
    &response[n..]
}

pub fn ingest_secret(tag: &str) -> String {
    format!("synthetic-ingest-{tag}-tests-only-0000000")
}
pub fn invite_secret(tag: &str) -> String {
    format!("synthetic-invite-{tag}-tests-only-0000000")
}

/// Devices `a1` (2 findings) and `a2` (1) in `site-a`, `b1` (3) in `site-b`, and `x1` (2) in
/// `site-a` of `org-other`, on a hub upgraded to schema 2.
pub struct World {
    pub tmp: TempDir,
    pub db: PathBuf,
    pub hub: Hub,
    pub a1: String,
    pub a2: String,
    pub b1: String,
    pub x1: String,
}
/// Enrolls a device and ingests one finding per key.
pub fn enroll(hub: &Hub, org: &str, site: &str, tag: &str, keys: &[&str]) -> String {
    hub.invite(&invite_secret(tag), org, site, 600.0).unwrap();
    let identity = hub
        .enroll(&invite_secret(tag), &ingest_secret(tag))
        .unwrap();
    let mut batch: Value = serde_json::from_str(include_str!("../fixtures/link-v1.json")).unwrap();
    batch["device"] = identity["device"].clone();
    batch["generation"] = identity["generation"].clone();
    batch["scan"] = json!(uuid::Uuid::new_v4().to_string());
    batch["observed"] = json!(vorda::store::now());
    batch["findings"] = json!(keys
        .iter()
        .map(|k| {
            let mut f = batch["findings"][0].clone();
            f["key"] = json!(k);
            f["name"] = json!(format!("package-of-{k}"));
            f
        })
        .collect::<Vec<_>>());
    hub.ingest(&ingest_secret(tag), &batch).unwrap();
    identity["device"].as_str().unwrap().to_string()
}
pub fn world() -> World {
    world_at(true)
}
/// A hub of the same shape, upgraded to schema 2 only when `upgrade` is set.
pub fn world_at(upgrade: bool) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("hub.db");
    let hub = Hub::open(&db).unwrap();
    let a1 = enroll(&hub, ORG, "site-a", "a1", &["finding-a1-x", "finding-a1-y"]);
    let a2 = enroll(&hub, ORG, "site-a", "a2", &["finding-a2-x"]);
    let b1 = enroll(
        &hub,
        ORG,
        "site-b",
        "b1",
        &["finding-b1-x", "finding-b1-y", "finding-b1-z"],
    );
    let x1 = enroll(
        &hub,
        "org-other",
        "site-a",
        "x1",
        &["finding-x1-x", "finding-x1-y"],
    );
    if upgrade {
        native::migrate(&db).unwrap();
    }
    World {
        tmp,
        db,
        hub,
        a1,
        a2,
        b1,
        x1,
    }
}

pub fn sites(pairs: &[(&str, &str)]) -> Vec<Site> {
    pairs
        .iter()
        .map(|(org, site)| Site {
            org: org.to_string(),
            site: site.to_string(),
        })
        .collect()
}
/// Grants `secret` the devices of the named sites (or only the listed devices) for `ttl` seconds.
pub fn try_grant(
    w: &World,
    secret: &str,
    sites: &[Site],
    devices: Option<&[String]>,
    ttl: f64,
) -> vorda::Result<String> {
    try_grant_sources(w, secret, sites, devices, None, ttl)
}
/// Like `try_grant`, restricted to the listed sources when `sources` is given.
pub fn try_grant_sources(
    w: &World,
    secret: &str,
    sites: &[Site],
    devices: Option<&[String]>,
    sources: Option<&[String]>,
    ttl: f64,
) -> vorda::Result<String> {
    ReaderStore::grant(
        &w.hub,
        secret,
        &GrantRequest {
            label: "synthetic reader",
            sites,
            devices: devices.map_or(DeviceGrant::All, DeviceGrant::Listed),
            sources: sources.map_or(SourceGrant::All, SourceGrant::Listed),
            ttl,
        },
    )
}
/// A grant for sites of the default organization, on every device or only the listed ones.
pub fn grant(w: &World, secret: &str, site_names: &[&str], devices: &[&str], ttl: f64) -> String {
    let pairs: Vec<_> = site_names.iter().map(|s| (ORG, *s)).collect();
    let listed: Vec<String> = devices.iter().map(|d| d.to_string()).collect();
    try_grant(
        w,
        secret,
        &sites(&pairs),
        (!listed.is_empty()).then_some(&listed[..]),
        ttl,
    )
    .unwrap()
}
pub fn authorize(w: &World, secret: &str) -> vorda::Result<AuthorizedScope> {
    ReaderStore::open(&w.db)?.authorize(secret)
}

/// One v2 delivery: a capture of `inputs` (directories holding a lock file; `absent` is missing and
/// `empty` holds an empty lock) bound to `(org, site, device, scope, source)`, admitted by the hub.
pub struct Delivery<'a> {
    pub device: &'a str,
    pub org: &'a str,
    pub site: &'a str,
    pub scope: &'a str,
    pub source: &'a str,
    /// Epoch seconds of the observation. `None` uses one fixed, arbitrary time.
    pub observed: Option<f64>,
    pub inputs: &'a [&'a str],
}
impl World {
    pub fn deliver(&self, d: &Delivery, sequence: i64) -> vorda::Result<()> {
        self.deliver_lock(d, sequence, include_bytes!("../fixtures/capture/L1.json"))
    }
    /// Like `deliver`, with the lockfile text that every present, non-empty input holds.
    pub fn deliver_lock(&self, d: &Delivery, sequence: i64, lock_text: &[u8]) -> vorda::Result<()> {
        self.deliver_inputs(d, sequence, lock_text, &[])
    }
    /// Like `deliver_lock`, with some inputs holding their own file text instead.
    pub fn deliver_inputs(
        &self,
        d: &Delivery,
        sequence: i64,
        lock_text: &[u8],
        own: &[(&str, &[u8])],
    ) -> vorda::Result<()> {
        let (binding, evidence, raw, wire) = self.v2_request_with(d, sequence, lock_text, own);
        Admission::open(
            &self.db,
            vec![TrustedCapture {
                binding,
                evidence_id: evidence,
                artifact_utf8: raw,
            }],
        )?
        .admit(&wire)
        .map(|_| ())
    }
    /// The wire request of a v2 delivery, with the binding, evidence id and artifact it carries.
    pub fn v2_request(
        &self,
        d: &Delivery,
        sequence: i64,
        lock_text: &[u8],
    ) -> (Value, String, String, Vec<u8>) {
        self.v2_request_with(d, sequence, lock_text, &[])
    }
    pub fn v2_request_with(
        &self,
        d: &Delivery,
        sequence: i64,
        lock_text: &[u8],
        own: &[(&str, &[u8])],
    ) -> (Value, String, String, Vec<u8>) {
        let tag = format!("{}-{}-{}", &d.device[..8], d.scope, d.source);
        let root = self.tmp.path().join(format!("root-{tag}"));
        for input in d.inputs {
            if *input == "absent" {
                continue;
            }
            fs::create_dir_all(root.join(input)).unwrap();
            // An empty own text means the file is gone: the input fails to read.
            if own
                .iter()
                .any(|(name, text)| name == input && text.is_empty())
            {
                let _ = fs::remove_file(root.join(input).join("package-lock.json"));
                continue;
            }
            let lock: &[u8] = match own.iter().find(|(name, _)| name == input) {
                Some((_, text)) => text,
                None if *input == "empty" => include_bytes!("../fixtures/capture/empty.json"),
                None => lock_text,
            };
            fs::write(root.join(input).join("package-lock.json"), lock).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        let inputs = d
            .inputs
            .iter()
            .map(|i| format!("{i}/package-lock.json"))
            .collect();
        self.capture_wire(d, sequence, &tag, &root, inputs)
    }
    /// Like `v2_request`, with each input a lockfile of any supported kind, given as
    /// `(path under the root, file text)`; `d.inputs` is not used.
    pub fn v2_request_files(
        &self,
        d: &Delivery,
        sequence: i64,
        files: &[(&str, &[u8])],
    ) -> (Value, String, String, Vec<u8>) {
        let tag = format!("{}-{}-{}", &d.device[..8], d.scope, d.source);
        let root = self.tmp.path().join(format!("root-{tag}"));
        fs::create_dir_all(&root).unwrap();
        for (path, text) in files {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, text).unwrap();
        }
        let inputs = files.iter().map(|f| f.0.to_string()).collect();
        self.capture_wire(d, sequence, &tag, &root, inputs)
    }
    /// Captures `inputs` under `root` through the device capture path and wraps the saved artifact
    /// as the wire request a device would send.
    fn capture_wire(
        &self,
        d: &Delivery,
        sequence: i64,
        tag: &str,
        root: &std::path::Path,
        inputs: Vec<String>,
    ) -> (Value, String, String, Vec<u8>) {
        let generation = self.hub.snapshot(d.device).unwrap()["device"]["generation"].clone();
        let binding = json!({"tenant":d.org,"site":d.site,"device":d.device,"generation":generation,"scope":d.scope,"source":d.source});
        let mut store = Store::open(&self.tmp.path().join(format!("producer-{tag}"))).unwrap();
        let mut request = json!({"token":format!("token-{tag}-{sequence}"),"binding":binding,"root":root.canonicalize().unwrap(),
            "inputs":inputs,"completed_at":"1793898285.5764945"});
        request["observed_at"] = d
            .observed
            .map_or(json!("1793898285.4219873"), |t| json!(format!("{t:.4}")));
        let outcome = capture::capture(&mut store, &serde_json::to_vec(&request).unwrap()).unwrap();
        let export = self
            .tmp
            .path()
            .join(format!("export-{tag}-{sequence}.json"));
        capture::export(
            &mut store,
            outcome["snapshot_id"].as_str().unwrap(),
            &export,
        )
        .unwrap();
        let view: Value = serde_json::from_slice(&fs::read(export).unwrap()).unwrap();
        // The view holds the evidence of every current record, which after a second assessment
        // is more than one entry in no particular order: take the new assessment's own.
        let evidence = view["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["assessment_id"] == outcome["assessment_id"])
            .and_then(|r| r["dimensions"]["evidence"].as_str())
            .unwrap()
            .to_string();
        let raw = view["retained_payload_utf8"][&evidence]
            .as_str()
            .unwrap()
            .to_string();
        let wire = canonical(
            &json!({"schema":2,"binding":binding,"sequence":sequence,"evidence_id":evidence,
            "artifact_sha256":hash(raw.as_bytes()),"artifact_byte_length":raw.len(),"artifact_utf8":raw}),
        );
        (binding, evidence, raw, wire)
    }
}
pub fn device_ids(view: &Value) -> Vec<String> {
    view["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["device"].as_str().unwrap().to_string())
        .collect()
}

pub fn standard_deliveries(w: &World) {
    let t = vorda::store::now();
    for (device, org, site, scope, source) in [
        (&w.a1, ORG, "site-a", "scope-1", "npm-a"),
        (&w.a1, ORG, "site-a", "scope-2", "pip-a"),
        (&w.a2, ORG, "site-a", "scope-1", "npm-a"),
        (&w.b1, ORG, "site-b", "scope-1", "npm-a"),
        (&w.x1, "org-other", "site-a", "scope-1", "npm-a"),
    ] {
        let delivery = Delivery {
            device,
            org,
            site,
            scope,
            source,
            observed: Some(t - 60.0),
            inputs: &["one"],
        };
        w.deliver(&delivery, 1).unwrap();
    }
}

pub const L1: &[u8] = include_bytes!("../fixtures/capture/L1.json"); // samepackage 1.0.0

/// A grant for the sites of the default organization restricted to the listed sources.
pub fn grant_sources(w: &World, secret: &str, site_names: &[&str], sources: &[&str]) -> String {
    let pairs: Vec<_> = site_names.iter().map(|s| (ORG, *s)).collect();
    let listed: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
    try_grant_sources(w, secret, &sites(&pairs), None, Some(&listed), 3600.0).unwrap()
}

/// A schema 3 hub: the same shape as `world`, upgraded with its change log before any delivery.
pub fn world_logged() -> World {
    let w = world();
    native::migrate_change_log(&w.db).unwrap();
    w
}

/// SHA-256 over every schema object except the change log's and every row of every other table in
/// rowid order, typed, as `.dump` would list them. Equal digests mean the schema 2 part of two
/// hubs is the same byte for byte.
pub fn dump_digest(db: &std::path::Path) -> String {
    use rusqlite::{types::ValueRef, Connection, OpenFlags};
    let c = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut digest = Sha256::new();
    let objects: Vec<(String, String, String)> = c
        .prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND name NOT IN ('v2_changes','v2_changes_received','v2_change_state') ORDER BY rowid")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for (kind, name, sql) in objects {
        digest.update(format!("{kind}|{name}|{sql}\n"));
        if kind != "table" {
            continue;
        }
        let mut statement = c
            .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..columns {
                let cell = match row.get_ref(i).unwrap() {
                    ValueRef::Null => "null".to_string(),
                    ValueRef::Integer(v) => format!("i{v}"),
                    ValueRef::Real(v) => format!("r{}", v.to_bits()),
                    ValueRef::Text(b) => format!("t{}", hash(b)),
                    ValueRef::Blob(b) => format!("b{}", hash(b)),
                };
                digest.update(format!("{cell}|"));
            }
            digest.update("\n");
        }
    }
    format!("{:x}", digest.finalize())
}

/// Every authority's stored change rows equal the in-memory replay of its assessments, row for row,
/// and so does its replay state. Returns the number of stored rows.
pub fn assert_log_equals_replay(db: &std::path::Path) -> usize {
    use vorda::link::change_log::{replayed, stored};
    let c = rusqlite::Connection::open(db).unwrap();
    let authorities: Vec<String> = c
        .prepare("SELECT authority FROM v2_authorities ORDER BY authority")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut total = 0;
    for authority in authorities {
        let log = stored(&c, &authority).unwrap();
        assert_eq!(log, replayed(&c, &authority).unwrap(), "{authority}");
        total += log.len();
    }
    native::verify_change_log(db).unwrap();
    total
}

/// Enrolls a device in `site` that has delivered nothing, version 1 or version 2.
pub fn enroll_without_evidence(w: &World, site: &str, tag: &str) -> String {
    let invite = format!("synthetic-invite-{tag}-tests-only-0000000");
    w.hub.invite(&invite, ORG, site, 600.0).unwrap();
    let identity = w
        .hub
        .enroll(
            &invite,
            &format!("synthetic-ingest-{tag}-tests-only-0000000"),
        )
        .unwrap();
    identity["device"].as_str().unwrap().to_string()
}

/// `(name, version)` of the first `n` packages of the synthetic application lockfile.
pub fn synthetic_packages(n: usize) -> Vec<(String, String)> {
    (1..=n)
        .map(|i| {
            (
                format!("synthetic-pkg-{i:04}"),
                format!("1.{}.{}", i % 50, i % 9),
            )
        })
        .collect()
}
/// A realistic npm v3 lockfile of `packages`: a named root entry, the usual per-package fields
/// (`resolved`, `integrity`, `dependencies`, `engines`) and `padding` extra bytes per package.
pub fn synthetic_lock(packages: &[(String, String)], padding: usize) -> String {
    let mut entries = serde_json::Map::new();
    entries.insert(
        "".into(),
        json!({"name":"synthetic-app","version":"1.0.0","dependencies":{"synthetic-pkg-0001":"^1.0.0"}}),
    );
    for (name, version) in packages {
        let integrity = hash(format!("{name}{version}").as_bytes());
        entries.insert(
            format!("node_modules/{name}"),
            json!({"version":version,
                "resolved":format!("https://registry.example.invalid/{name}/-/{name}-{version}.tgz"),
                "integrity":format!("sha512-{integrity}{}", &hash(integrity.as_bytes())[..24]),
                "license":"MIT","dependencies":{"synthetic-pkg-0001":"^1.0.0","synthetic-pkg-0002":"~1.2.0"},
                "engines":{"node":">=18"},"description":"x".repeat(padding)}),
        );
    }
    serde_json::to_string_pretty(
        &json!({"name":"synthetic-app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":entries}),
    )
    .unwrap()
}
