use crate::{store::capture, Error, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
/// The (scope, source) authorities one device may hold at the hub.
pub const MAX_AUTHORITIES_PER_DEVICE: usize = 64;
/// Assessments the hub keeps per authority; it refuses more (413) rather than dropping any.
pub const MAX_ASSESSMENTS_PER_AUTHORITY: usize = 64;
/// Inputs and records one assessment may carry, and records one authority may currently hold; more
/// is refused (413). These are the device capture's own bounds, so what it commits is admitted.
pub const MAX_INPUTS_PER_ASSESSMENT: usize = capture::INPUT_LIMIT;
pub const MAX_RECORDS_PER_ASSESSMENT: usize = capture::PACKAGE_LIMIT;
/// The longest input path, request, artifact and lockfile text the hub takes. A request carries
/// the artifact escaped once, so it is no longer than the saved view of the same capture.
pub(crate) const REQUEST_LIMIT: usize = capture::VIEW_LIMIT + 64 * 1024;
/// Time an admission may take from the moment its request is complete.
const ADMISSION_BUDGET: Duration = Duration::from_millis(1000);
const ARTIFACT_LIMIT: usize = capture::VIEW_LIMIT;
/// Ecosystems the scanner's lockfile readers name.
const ECOSYSTEMS: [&str; 7] = [
    "npm",
    "PyPI",
    "crates.io",
    "Go",
    "RubyGems",
    "Packagist",
    "NuGet",
];
const DDL: &str = include_str!("native_schema.sql");
/// Schema 3 adds the change log to schema 2; see `change_log`.
const DDL3: &str = include_str!("native_schema_v3.sql");
const OLD: &str = include_str!("hub_schema.sql");
fn storage_failure(e: Error) -> Error {
    if e.http_status.is_none() {
        err(503, "storage_failure")
    } else {
        e
    }
}
fn err(code: u16, tag: &str) -> Error {
    Error::rejected(code, tag)
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
/// `v` as compact JSON with every object's keys in byte order. Written straight from `v` (a full
/// assessment's view is megabytes, so copying it to sort it would cost as much as writing it).
pub(super) fn canonical(v: &Value) -> Vec<u8> {
    fn write(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::Object(m) => {
                let mut entries: Vec<_> = m.iter().collect();
                entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
                out.push(b'{');
                for (n, (k, v)) in entries.into_iter().enumerate() {
                    if n > 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, k).unwrap();
                    out.push(b':');
                    write(v, out);
                }
                out.push(b'}');
            }
            Value::Array(a) => {
                out.push(b'[');
                for (n, v) in a.iter().enumerate() {
                    if n > 0 {
                        out.push(b',');
                    }
                    write(v, out);
                }
                out.push(b']');
            }
            _ => serde_json::to_writer(&mut *out, v).unwrap(),
        }
    }
    let mut out = Vec::new();
    write(v, &mut out);
    out
}
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "bounded JSON")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut m: M,
            ) -> std::result::Result<Strict, M::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = m.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate_input_key"));
                    }
                    out.insert(k, m.next_value::<Strict>()?.0);
                }
                Ok(Strict(Value::Object(out)))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut s: S,
            ) -> std::result::Result<Strict, S::Error> {
                let mut out = vec![];
                while let Some(v) = s.next_element::<Strict>()? {
                    out.push(v.0);
                }
                Ok(Strict(json!(out)))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(s)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                s: String,
            ) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(s)))
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(n)))
            }
            fn visit_i64<E: serde::de::Error>(self, n: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(n)))
            }
            fn visit_bool<E: serde::de::Error>(self, b: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(b)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
        }
        d.deserialize_any(Visitor)
    }
}

/// Longest string under `key`: the artifact and the lockfile text it carries are large, everything
/// else is short.
fn string_limit(key: &str) -> usize {
    match key {
        "artifact_utf8" | "bytes_utf8" => ARTIFACT_LIMIT,
        _ => 4096,
    }
}
/// Most elements of the array under `key`.
fn array_limit(key: &str) -> usize {
    match key {
        "records" => MAX_RECORDS_PER_ASSESSMENT,
        "inputs" => MAX_INPUTS_PER_ASSESSMENT,
        _ => 128,
    }
}
fn bounds(v: &Value, depth: usize, key: &str) -> Result<()> {
    if depth > 16 && (v.is_array() || v.is_object()) {
        return Err(err(413, "depth_limit"));
    }
    match v {
        Value::Object(m) => {
            if m.len() > 32 {
                return Err(err(413, "object_limit"));
            }
            for (k, v) in m {
                if k.len() > 4096 {
                    return Err(err(413, "string_limit"));
                }
                bounds(v, depth + 1, k)?;
            }
        }
        Value::Array(a) => {
            if a.len() > array_limit(key) {
                return Err(err(413, "array_limit"));
            }
            for v in a {
                bounds(v, depth + 1, "")?;
            }
        }
        Value::String(s) => {
            if s.len() > string_limit(key) {
                return Err(err(413, "string_limit"));
            }
        }
        Value::Number(n) if n.as_i64().is_none() => {
            return Err(err(400, "invalid_number"));
        }
        _ => {}
    }
    Ok(())
}
fn preflight(b: &[u8]) -> Result<()> {
    fn space(b: &[u8], i: &mut usize) {
        while b.get(*i).is_some_and(u8::is_ascii_whitespace) {
            *i += 1;
        }
    }
    fn string(b: &[u8], i: &mut usize, max: usize) -> Result<()> {
        if b.get(*i) != Some(&b'"') {
            return Err(err(400, "invalid_json"));
        }
        *i += 1;
        let mut size = 0;
        loop {
            let c = *b.get(*i).ok_or_else(|| err(400, "invalid_json"))?;
            *i += 1;
            if c == b'"' {
                return Ok(());
            }
            let add = if c == b'\\' {
                let escape = *b.get(*i).ok_or_else(|| err(400, "invalid_json"))?;
                *i += 1;
                if escape == b'u' {
                    let digits = b.get(*i..*i + 4).ok_or_else(|| err(400, "invalid_json"))?;
                    let code = u16::from_str_radix(
                        std::str::from_utf8(digits).map_err(|_| err(400, "invalid_json"))?,
                        16,
                    )
                    .map_err(|_| err(400, "invalid_json"))?;
                    *i += 4;
                    if (0xd800..=0xdbff).contains(&code) {
                        if b.get(*i..*i + 2) != Some(b"\\u") {
                            return Err(err(400, "invalid_json"));
                        }
                        let digits = b
                            .get(*i + 2..*i + 6)
                            .ok_or_else(|| err(400, "invalid_json"))?;
                        let low = u16::from_str_radix(
                            std::str::from_utf8(digits).map_err(|_| err(400, "invalid_json"))?,
                            16,
                        )
                        .map_err(|_| err(400, "invalid_json"))?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(err(400, "invalid_json"));
                        }
                        *i += 6;
                        4
                    } else if (0xdc00..=0xdfff).contains(&code) {
                        return Err(err(400, "invalid_json"));
                    } else if code < 128 {
                        1
                    } else if code < 2048 {
                        2
                    } else {
                        3
                    }
                } else if b"\"\\/bfnrt".contains(&escape) {
                    1
                } else {
                    return Err(err(400, "invalid_json"));
                }
            } else if c < 32 {
                return Err(err(400, "invalid_json"));
            } else {
                1
            };
            size += add;
            if size > max {
                return Err(err(413, "string_limit"));
            }
        }
    }
    fn value(b: &[u8], i: &mut usize, depth: usize, key: &str) -> Result<()> {
        space(b, i);
        match b.get(*i) {
            Some(b'{') | Some(b'[') => {
                if depth > 16 {
                    return Err(err(413, "depth_limit"));
                }
                let object = b[*i] == b'{';
                let close = if object { b'}' } else { b']' };
                *i += 1;
                space(b, i);
                if b.get(*i) == Some(&close) {
                    *i += 1;
                    return Ok(());
                }
                let mut count = 0;
                loop {
                    count += 1;
                    if count > if object { 32 } else { array_limit(key) } {
                        return Err(err(
                            413,
                            if object {
                                "object_limit"
                            } else {
                                "array_limit"
                            },
                        ));
                    }
                    let mut name = String::new();
                    if object {
                        space(b, i);
                        let start = *i;
                        string(b, i, 4096)?;
                        name = serde_json::from_slice(&b[start..*i])
                            .map_err(|_| err(400, "invalid_json"))?;
                        space(b, i);
                        if b.get(*i) != Some(&b':') {
                            return Err(err(400, "invalid_json"));
                        }
                        *i += 1;
                    }
                    value(b, i, depth + 1, &name)?;
                    space(b, i);
                    match b.get(*i) {
                        Some(c) if *c == close => {
                            *i += 1;
                            return Ok(());
                        }
                        Some(b',') => {
                            *i += 1;
                        }
                        _ => return Err(err(400, "invalid_json")),
                    }
                }
            }
            Some(b'"') => string(b, i, string_limit(key)),
            Some(_) => {
                let start = *i;
                while b.get(*i).is_some_and(|c| !b",]} \r\n\t".contains(c)) {
                    *i += 1;
                }
                if *i == start {
                    return Err(err(400, "invalid_json"));
                }
                Ok(())
            }
            None => Err(err(400, "invalid_json")),
        }
    }
    let mut i = 0;
    value(b, &mut i, 1, "")?;
    space(b, &mut i);
    if i != b.len() {
        return Err(err(400, "invalid_json"));
    }
    Ok(())
}
fn parse(b: &[u8], max: usize) -> Result<Value> {
    if b.len() > max {
        return Err(err(413, "byte_limit"));
    }
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for &byte in b {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 16 {
                        return Err(err(413, "depth_limit"));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    preflight(b)?;
    let v = serde_json::from_slice::<Strict>(b)
        .map_err(|_| err(400, "invalid_json"))?
        .0;
    bounds(&v, 1, "")?;
    Ok(v)
}
fn fields(v: &Value, keys: &[&str]) -> Result<()> {
    if !super::exact_fields(v, keys) {
        return Err(err(400, "invalid_shape"));
    }
    Ok(())
}
/// An identifier or an input path: the device refuses input paths longer than the same bound.
fn id(v: &Value) -> Result<&str> {
    if v.as_str().is_some_and(|s| s.len() > capture::PATH_LIMIT) {
        return Err(err(413, "id_limit"));
    }
    v.as_str()
        .filter(|s| !s.is_empty() && s.len() <= capture::PATH_LIMIT && !s.chars().any(|c| c < ' '))
        .ok_or_else(|| err(400, "invalid_id"))
}
fn positive(v: &Value) -> Result<i64> {
    v.as_i64()
        .filter(|n| *n > 0)
        .ok_or_else(|| err(400, "invalid_integer"))
}
fn decimal(s: &str) -> bool {
    s.len() <= 32
        && !s.is_empty()
        && s.split('.').count() <= 2
        && s.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}
fn authority_tuple(v: &Value) -> Value {
    json!([
        v["tenant"],
        v["site"],
        v["device"],
        v["generation"],
        v["scope"]
    ])
}
fn binding(v: &Value) -> Result<String> {
    fields(
        v,
        &["tenant", "site", "device", "generation", "scope", "source"],
    )?;
    for k in ["tenant", "site", "device", "generation", "scope", "source"] {
        id(&v[k])?;
    }
    Ok(String::from_utf8(canonical(&authority_tuple(v))).unwrap())
}
pub(crate) fn schema(db: &Connection, version: i64) -> Result<()> {
    let actual: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if actual != version {
        return Err(err(422, "unsupported_link_schema"));
    }
    if db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))? != "ok" {
        return Err(err(503, "migration_integrity_failure"));
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(OLD)?;
    if version >= 2 {
        expected.execute_batch(DDL)?;
    }
    if version == 3 {
        expected.execute_batch(DDL3)?;
    }
    fn objects(c: &Connection) -> Result<Vec<(String, String, String)>> {
        Ok(c.prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect::<std::result::Result<_,_>>()?)
    }
    if objects(db)? != objects(&expected)? {
        return Err(err(422, "unsupported_link_schema"));
    }
    Ok(())
}
pub fn schema_version(p: &Path) -> Result<i64> {
    Ok(readonly(p)?.pragma_query_value(None, "user_version", |r| r.get(0))?)
}
/// Checks a schema 2 or 3 hub against its exact DDL and returns which it is.
pub(crate) fn native_schema(db: &Connection) -> Result<i64> {
    let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if !matches!(version, 2 | 3) {
        return Err(err(422, "unsupported_link_schema"));
    }
    schema(db, version)?;
    Ok(version)
}
fn readonly(p: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        p,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?)
}
fn sync_parent(p: &Path) -> Result<()> {
    File::open(p.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}
fn private_write(p: &Path, b: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    sync_parent(p)
}
fn side(p: &Path, s: &str) -> PathBuf {
    let mut n = p.as_os_str().to_os_string();
    n.push(s);
    n.into()
}
fn old_manifest(db: &Connection) -> Result<Value> {
    let mut out = BTreeMap::new();
    for table in [
        "invites",
        "devices",
        "credentials",
        "batches",
        "scans",
        "findings",
        "coverage",
        "audit",
    ] {
        let mut statement = db.prepare(&format!("SELECT * FROM {table}"))?;
        let n = statement.column_count();
        let mut rows = statement.query([])?;
        let mut values = vec![];
        while let Some(row) = rows.next()? {
            let mut v = vec![];
            for i in 0..n {
                use rusqlite::types::ValueRef;
                v.push(match row.get_ref(i)? {
                    ValueRef::Null => json!(["null"]),
                    ValueRef::Integer(n) => json!(["integer", n]),
                    ValueRef::Real(n) => json!(["real", n.to_bits().to_string()]),
                    ValueRef::Text(b) => json!(["text", b]),
                    ValueRef::Blob(b) => json!(["blob", b]),
                });
            }
            values.push(canonical(&json!(v)));
        }
        values.sort();
        out.insert(table, values);
    }
    Ok(json!(out))
}
fn verified_old(path: &Path, backup: &Path) -> Result<()> {
    if old_manifest(&readonly(path)?)? != old_manifest(&readonly(backup)?)? {
        return Err(err(503, "migration_integrity_failure"));
    }
    Ok(())
}
pub fn migrate(path: &Path) -> Result<()> {
    migrate_with_limit(path, super::storage::DEFAULT_MAX_DB_BYTES)
}
/// Like `migrate`, for a hub whose database may not grow past `max_bytes`: a hub already past it is
/// refused before anything is written.
pub fn migrate_with_limit(path: &Path, max_bytes: u64) -> Result<()> {
    if fs::metadata(path)?.len() > max_bytes {
        return Err(err(503, "migration_storage_failure"));
    }
    let migration_lock = OpenOptions::new().read(true).write(true).open(path)?;
    fs2::FileExt::try_lock_exclusive(&migration_lock)
        .map_err(|_| err(503, "migration_storage_failure"))?;
    let header = fs::read(path)?;
    if header.len() < 100
        || !matches!(
            u32::from_be_bytes(header[60..64].try_into().unwrap()),
            1 | 2
        )
    {
        return Err(err(422, "unsupported_link_schema"));
    }
    let backup = side(path, ".v1-backup");
    let receipt = side(path, ".v2-operation");
    if side(path, "-journal").exists() {
        let r: Value = serde_json::from_slice(
            &fs::read(&receipt).map_err(|_| err(503, "migration_recovery_required"))?,
        )?;
        if r["path"] != path.to_string_lossy().as_ref()
            || r["target"] != 2
            || r["backup_sha256"] != hash(&fs::read(&backup)?)
        {
            return Err(err(503, "migration_recovery_required"));
        }
        schema(&readonly(&backup)?, 1)?;
        let c = Connection::open(path)?;
        let _: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        drop(c);
    }
    let db = readonly(path)?;
    let v: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if v == 2 {
        schema(&db, 2)?;
        drop(db);
        return verified_old(path, &backup);
    }
    if v != 1 {
        return Err(err(422, "unsupported_link_schema"));
    }
    schema(&db, 1)?;
    drop(db);
    fault("before-backup-verified");
    let mut db = Connection::open(path)?;
    db.busy_timeout(Duration::from_millis(200))?;
    set_page_ceiling(&db, max_bytes)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE;")?;
    let bytes = fs::read(path)?;
    if !backup.exists() {
        private_write(&backup, &bytes)?;
    }
    if fs::read(&backup)? != bytes {
        return Err(err(503, "backup_integrity_failure"));
    }
    schema(&readonly(&backup)?, 1)?;
    let r = canonical(
        &json!({"path":path.to_string_lossy(),"target":2,"backup_sha256":hash(&bytes),"backup_byte_length":bytes.len(),"schema_version":1,"old_manifest":old_manifest(&db)?,"exclusive_writer_shutdown":true}),
    );
    if receipt.exists() {
        if fs::read(&receipt)? != r {
            return Err(err(503, "migration_recovery_required"));
        }
    } else {
        private_write(&receipt, &r)?;
    }
    fault("after-backup-before-begin");
    db.execute_batch("COMMIT")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (i, sql) in DDL.split(';').filter(|s| !s.trim().is_empty()).enumerate() {
        tx.execute_batch(sql)?;
        if i == 0 {
            fault("after-first-create");
        }
    }
    fault("after-all-create");
    tx.pragma_update(None, "user_version", 2)?;
    fault("after-version-before-commit");
    schema(&tx, 2)?;
    tx.commit()?;
    fault("after-commit-before-verification");
    drop(db);
    schema(&readonly(path)?, 2)?;
    verified_old(path, &backup)
}
pub fn restore(path: &Path) -> Result<()> {
    let backup = side(path, ".v1-backup");
    let b = fs::read(&backup)?;
    let r: Value = serde_json::from_slice(&fs::read(side(path, ".v2-operation"))?)?;
    if r["backup_sha256"] != hash(&b) {
        return Err(err(503, "backup_integrity_failure"));
    }
    schema(&readonly(&backup)?, 1)?;
    private_write(&side(path, ".failed-v2"), &fs::read(path)?)?;
    let journal = side(path, "-journal");
    if journal.exists() {
        private_write(&side(path, ".failed-v2-journal"), &fs::read(&journal)?)?;
        return Err(err(503, "migration_recovery_required"));
    }
    let temp = side(path, ".restore");
    private_write(&temp, &b)?;
    fs::rename(temp, path)?;
    sync_parent(path)?;
    schema(&readonly(path)?, 1)?;
    verified_old(path, &backup)
}
pub fn verify_upgraded(path: &Path) -> Result<()> {
    let db = readonly(path)?;
    if native_schema(&db)? == 3 {
        super::change_log::verify_all(&db)?;
    }
    drop(db);
    let r: Value = serde_json::from_slice(&fs::read(side(path, ".v2-operation"))?)?;
    if r["backup_sha256"] != hash(&fs::read(side(path, ".v1-backup"))?) {
        return Err(err(503, "backup_integrity_failure"));
    }
    Ok(())
}
pub fn post_upgrade_writes(path: &Path) -> Result<bool> {
    let live = readonly(path)?;
    if old_manifest(&live)? != old_manifest(&readonly(&side(path, ".v1-backup"))?)? {
        return Ok(true);
    }
    let tables = live
        .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'v2\\_%' ESCAPE '\\'",
        )?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for table in tables {
        if live.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |r| {
            r.get(0)
        })? {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Every table schema 2 defines (the eight of schema 1 and the seven native ones).
const SCHEMA2_TABLES: [&str; 15] = [
    "invites",
    "devices",
    "credentials",
    "batches",
    "scans",
    "findings",
    "coverage",
    "audit",
    "v2_authorities",
    "v2_assessments",
    "v2_observations",
    "v2_current",
    "v2_coverage",
    "v2_deliveries",
    "v2_views",
];
/// A digest of each schema 2 table's rows in rowid order, typed and length-framed, so two
/// databases agree exactly when every row of every schema 2 table is the same.
fn table_digests(db: &Connection) -> Result<BTreeMap<&'static str, String>> {
    use rusqlite::types::ValueRef;
    let mut out = BTreeMap::new();
    for table in SCHEMA2_TABLES {
        let mut statement = db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        let mut digest = Sha256::new();
        while let Some(row) = rows.next()? {
            for i in 0..columns {
                match row.get_ref(i)? {
                    ValueRef::Null => digest.update([0u8]),
                    ValueRef::Integer(n) => {
                        digest.update([1u8]);
                        digest.update(n.to_le_bytes());
                    }
                    ValueRef::Real(n) => {
                        digest.update([2u8]);
                        digest.update(n.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(b) => {
                        digest.update([3u8]);
                        digest.update((b.len() as u64).to_le_bytes());
                        digest.update(b);
                    }
                    ValueRef::Blob(b) => {
                        digest.update([4u8]);
                        digest.update((b.len() as u64).to_le_bytes());
                        digest.update(b);
                    }
                }
            }
            digest.update([255u8]);
        }
        out.insert(table, format!("{:x}", digest.finalize()));
    }
    Ok(out)
}
fn verified_tables(path: &Path, backup: &Path) -> Result<()> {
    if table_digests(&readonly(path)?)? != table_digests(&readonly(backup)?)? {
        return Err(err(503, "migration_integrity_failure"));
    }
    Ok(())
}
/// SHA-256 and length of a file, read in chunks (a hub can be hundreds of MiB).
fn file_digest(p: &Path) -> Result<(String, u64)> {
    let mut file = File::open(p)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut length = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            return Ok((format!("{:x}", digest.finalize()), length));
        }
        digest.update(&buffer[..n]);
        length += n as u64;
    }
}
/// Copies `from` to a new private file `to`, through a temporary name so a crash never leaves a
/// partial `to`.
fn private_copy(from: &Path, to: &Path) -> Result<()> {
    let temp = side(to, ".partial");
    let _ = fs::remove_file(&temp);
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut out = o.open(&temp)?;
    std::io::copy(&mut File::open(from)?, &mut out)?;
    out.sync_all()?;
    fs::rename(&temp, to)?;
    sync_parent(to)
}
fn log_storage_failure(e: Error) -> Error {
    if e.http_status.is_none() {
        err(503, "migration_storage_failure")
    } else {
        e
    }
}
pub fn migrate_change_log(path: &Path) -> Result<()> {
    migrate_change_log_with_limit(path, super::storage::DEFAULT_MAX_DB_BYTES)
}
/// Upgrades a schema 2 hub to schema 3: copies it to `.v2-backup`, writes `.v3-operation`, builds
/// every authority's change log in one exclusive transaction and checks it against the in-memory
/// replay before setting the version. Nothing is written when the log cannot fit under
/// `max_bytes`. On a schema 3 hub it only verifies.
pub fn migrate_change_log_with_limit(path: &Path, max_bytes: u64) -> Result<()> {
    if fs::metadata(path)?.len() > max_bytes {
        return Err(err(503, "migration_storage_failure"));
    }
    let migration_lock = OpenOptions::new().read(true).write(true).open(path)?;
    fs2::FileExt::try_lock_exclusive(&migration_lock)
        .map_err(|_| err(503, "migration_storage_failure"))?;
    let backup = side(path, ".v2-backup");
    let receipt = side(path, ".v3-operation");
    if side(path, "-journal").exists() {
        let r: Value = serde_json::from_slice(
            &fs::read(&receipt).map_err(|_| err(503, "migration_recovery_required"))?,
        )?;
        if r["path"] != path.to_string_lossy().as_ref()
            || r["target"] != 3
            || r["backup_sha256"] != file_digest(&backup)?.0
        {
            return Err(err(503, "migration_recovery_required"));
        }
        // Opening the database rolls the interrupted transaction back.
        let c = Connection::open(path)?;
        let _: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    }
    let db = readonly(path)?;
    if native_schema(&db)? == 3 {
        drop(db);
        return verify_change_log(path);
    }
    let plan = super::change_log::Plan::of(&db)?;
    drop(db);
    if fs::metadata(path)?
        .len()
        .saturating_add(plan.estimated_bytes())
        > max_bytes
    {
        return Err(err(503, "migration_storage_failure"));
    }
    fault("log-before-backup-verified");
    let mut db = Connection::open(path)?;
    db.busy_timeout(Duration::from_millis(200))?;
    set_page_ceiling(&db, max_bytes)?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE;")?;
    let (sha256, length) = file_digest(path)?;
    if !backup.exists() {
        private_copy(path, &backup)?;
    }
    if file_digest(&backup)? != (sha256.clone(), length) {
        return Err(err(503, "backup_integrity_failure"));
    }
    schema(&readonly(&backup)?, 2)?;
    let r = canonical(
        &json!({"path":path.to_string_lossy(),"target":3,"backup_sha256":sha256,"backup_byte_length":length,"schema_version":2,"exclusive_writer_shutdown":true}),
    );
    if receipt.exists() {
        if fs::read(&receipt)? != r {
            return Err(err(503, "migration_recovery_required"));
        }
    } else {
        private_write(&receipt, &r)?;
    }
    fault("log-after-backup-before-begin");
    db.execute_batch("COMMIT")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (i, sql) in DDL3.split(';').filter(|s| !s.trim().is_empty()).enumerate() {
        tx.execute_batch(sql)
            .map_err(|e| log_storage_failure(e.into()))?;
        if i == 0 {
            fault("log-after-first-create");
        }
    }
    fault("log-after-all-create");
    plan.write(&tx).map_err(log_storage_failure)?;
    fault("log-after-rows");
    tx.pragma_update(None, "user_version", 3)?;
    fault("log-after-version-before-commit");
    schema(&tx, 3)?;
    super::change_log::verify_all(&tx)?;
    tx.commit().map_err(|e| log_storage_failure(e.into()))?;
    fault("log-after-commit-before-verification");
    drop(db);
    schema(&readonly(path)?, 3)?;
    verified_tables(path, &backup)
}
/// Takes a schema 3 hub back to schema 2 by dropping the change log, which is derived from the
/// assessments: nothing else changes, so assessments admitted since the upgrade stay.
pub fn restore_change_log(path: &Path) -> Result<()> {
    let mut db = Connection::open(path)?;
    db.busy_timeout(Duration::from_millis(200))?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    schema(&tx, 3)?;
    tx.execute_batch(
        "DROP INDEX v2_changes_received; DROP TABLE v2_changes; DROP TABLE v2_change_state",
    )?;
    fault("log-restore-before-version");
    tx.pragma_update(None, "user_version", 2)?;
    schema(&tx, 2)?;
    tx.commit()?;
    fault("log-restore-after-commit");
    drop(db);
    schema(&readonly(path)?, 2)
}
/// Checks that a schema 3 hub's stored change log equals the in-memory replay of its retained
/// assessments, authority by authority.
pub fn verify_change_log(path: &Path) -> Result<()> {
    let db = readonly(path)?;
    if native_schema(&db)? != 3 {
        return Err(err(422, "unsupported_link_schema"));
    }
    super::change_log::verify_all(&db)
}
pub struct TrustedCapture {
    pub binding: Value,
    pub evidence_id: String,
    pub artifact_utf8: String,
}
pub struct Admission {
    path: PathBuf,
    captures: Vec<TrustedCapture>,
    /// What an authenticated post is trusted by: the operator's grants of (device, source). The
    /// exact captures above belong to trusted-local admission only.
    grants: Option<super::grants::CaptureGrants>,
    max_bytes: u64,
    active: Mutex<()>,
    budget: Duration,
}
/// Bounds the database at `max_bytes` (a page-count ceiling, so the file cannot grow past it).
fn set_page_ceiling(db: &Connection, max_bytes: u64) -> Result<()> {
    let page_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    db.pragma_update(None, "max_page_count", (max_bytes / page_size).max(16))?;
    Ok(())
}
impl Admission {
    pub fn open(path: &Path, captures: Vec<TrustedCapture>) -> Result<Self> {
        Self::open_with_limit(path, captures, super::storage::DEFAULT_MAX_DB_BYTES)
    }
    /// Admission against a database that may not grow past `max_bytes`; a full one answers 503
    /// `storage_failure` and keeps what it holds.
    pub fn open_with_limit(
        path: &Path,
        captures: Vec<TrustedCapture>,
        max_bytes: u64,
    ) -> Result<Self> {
        native_schema(&readonly(path)?)?;
        let mut authorities = BTreeMap::new();
        for c in &captures {
            let a = binding(&c.binding)?;
            if authorities
                .insert(a, c.binding["source"].clone())
                .is_some_and(|s| s != c.binding["source"])
            {
                return Err(err(403, "source_mismatch"));
            }
        }
        if authorities.len() > 3 {
            return Err(err(413, "authority_limit"));
        }
        Ok(Self {
            path: path.into(),
            captures,
            grants: None,
            max_bytes,
            active: Mutex::new(()),
            budget: ADMISSION_BUDGET,
        })
    }
    /// Trust authenticated posts for the (device, source) pairs in `grants`. Without it none is.
    pub fn with_grants(mut self, grants: super::grants::CaptureGrants) -> Self {
        self.grants = Some(grants);
        self
    }
    fn connect(&self, deadline: Option<Instant>) -> Result<Connection> {
        let db = Connection::open(&self.path)?;
        db_wait(&db, deadline)?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db_wait(&db, deadline)?;
        set_page_ceiling(&db, self.max_bytes)?;
        #[cfg(feature = "native-admission-test")]
        if std::env::var("VORDA_NATIVE_PAGE_LIMIT").ok().as_deref() == Some("current") {
            let count: i64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
            db.pragma_update(None, "max_page_count", count)?;
        }
        Ok(db)
    }
    /// Allows an admission `budget` from the moment its request is complete instead of one second.
    /// A hub serves with the default; this is for unoptimised builds, which parse a full assessment
    /// slower than the default allows. It stays public but hidden from the docs: the tests that use
    /// it are integration tests, which cannot see `cfg(test)`, and gating it behind the
    /// `native-admission-test` feature would stop the full-assessment tests running in the plain test run.
    #[doc(hidden)]
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }
    pub fn saved_view(&self, b: &Value) -> Result<Vec<u8>> {
        if !self.captures.iter().any(|c| c.binding == *b) {
            return Err(err(403, "identity_unbound"));
        }
        let a = binding(b)?;
        Ok(self.connect(None)?.query_row(
            "SELECT payload FROM v2_views WHERE authority=? ORDER BY publication DESC LIMIT 1",
            [a],
            |r| r.get(0),
        )?)
    }
    pub fn admit(&self, request: &[u8]) -> Result<Vec<u8>> {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| err(503, "clock_failure"))?;
        self.admit_at(request, &format!("{}.{:09}", t.as_secs(), t.subsec_nanos()))
    }
    pub fn admit_at(&self, request: &[u8], received: &str) -> Result<Vec<u8>> {
        self.admit_inner(request, received, None)
            .map_err(storage_failure)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn admit_authenticated(
        &self,
        request: &[u8],
        credential: &str,
        start: Instant,
    ) -> Result<Vec<u8>> {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| err(503, "clock_failure"))?;
        self.admit_inner(
            request,
            &format!("{}.{:09}", t.as_secs(), t.subsec_nanos()),
            Some((credential, start)),
        )
        .map_err(storage_failure)
    }
    fn admit_inner(
        &self,
        request: &[u8],
        received: &str,
        authenticated: Option<(&str, Instant)>,
    ) -> Result<Vec<u8>> {
        let _guard = self.active.try_lock().map_err(|_| err(503, "busy"))?;
        let lock_file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        fs2::FileExt::try_lock_exclusive(&lock_file).map_err(|_| err(503, "busy"))?;
        fault("admission-held");
        let start = authenticated.map_or_else(Instant::now, |(_, start)| start);
        if !decimal(received) {
            return Err(err(400, "invalid_receipt"));
        }
        let q = parse(request, REQUEST_LIMIT)?;
        fields(
            &q,
            &[
                "schema",
                "binding",
                "sequence",
                "evidence_id",
                "artifact_sha256",
                "artifact_byte_length",
                "artifact_utf8",
            ],
        )?;
        if q["schema"] != 2 {
            return Err(err(422, "unsupported_schema"));
        }
        if canonical(&q) != request {
            return Err(err(400, "noncanonical_request"));
        }
        let a = binding(&q["binding"])?;
        let seq = positive(&q["sequence"])?;
        let e = id(&q["evidence_id"])?;
        let raw = q["artifact_utf8"]
            .as_str()
            .ok_or_else(|| err(400, "invalid_artifact"))?;
        let artifact = parse(raw.as_bytes(), ARTIFACT_LIMIT)?;
        let source_sha = hash(raw.as_bytes());
        if authenticated.is_some() {
            artifact_structure(&artifact)?;
            if !q["artifact_sha256"].as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }) || q["artifact_byte_length"].as_u64().is_none()
            {
                return Err(err(400, "invalid_integrity_fields"));
            }
        } else {
            validate_artifact(&artifact)?;
        }
        let deadline = start + self.budget;
        let mut db = self.connect(Some(deadline))?;
        db_wait(&db, Some(deadline))?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(503, "storage_failure"))?;
        if let Some((credential, _)) = authenticated {
            let verifier =
                super::storage::verifier(credential).map_err(|_| err(401, "invalid_credential"))?;
            let identity: Option<(String, String, String, String)> = tx.query_row(
                "SELECT d.org,d.site,d.id,d.generation FROM devices d JOIN credentials c ON c.device=d.id WHERE c.verifier=? AND c.expires>? AND d.revoked=0",
                params![verifier, crate::store::now()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            let identity = identity.ok_or_else(|| err(401, "invalid_credential"))?;
            for (key, value) in [
                ("tenant", identity.0),
                ("site", identity.1),
                ("device", identity.2),
                ("generation", identity.3),
            ] {
                if q["binding"][key].as_str() != Some(value.as_str()) {
                    return Err(err(403, "identity_mismatch"));
                }
            }
        }
        // The cheap check of whether the operator trusts this device for this source comes before
        // the parse of the lockfile text, so an ungranted device cannot make the hub read the lockfile texts inside the artifact.
        if authenticated.is_some() {
            let granted = match &self.grants {
                Some(grants) => grants
                    .allows(id(&q["binding"]["device"])?, id(&q["binding"]["source"])?)
                    .map_err(|_| err(503, "grants_unavailable"))?,
                None => false,
            };
            if !granted {
                return Err(err(403, "capture_unapproved"));
            }
        }
        if authenticated.is_some() {
            validate_artifact(&artifact)?;
        }
        if q["artifact_byte_length"].as_u64() != Some(raw.len() as u64)
            || q["artifact_sha256"] != source_sha
        {
            return Err(err(422, "artifact_integrity"));
        }
        if authenticated.is_none() && !self.captures.iter().any(|c| c.binding == q["binding"]) {
            return Err(err(403, "identity_unbound"));
        }
        if artifact["binding"] != q["binding"] {
            return Err(err(403, "binding_mismatch"));
        }
        let assessment = id(&artifact["assessment_id"])?;
        let revision = positive(&artifact["revision"])?;
        let source = id(&q["binding"]["source"])?;
        let digest = hash(request);
        if start.elapsed() > self.budget {
            return Err(err(503, "admission_deadline"));
        }
        if let Some((d,ack))=tx.query_row("SELECT digest,ack FROM v2_deliveries WHERE authority=? AND source=? AND sequence=?",params![a,source,seq],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?))).optional()? {if d!=digest{return Err(err(409,"delivery_conflict"))}return Ok(ack)}
        let state=tx.query_row("SELECT frontier,delivery_frontier,publication FROM v2_authorities WHERE authority=?",[&a],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?))).optional()?.unwrap_or((0,0,0));
        let saved_source: Option<String> = tx
            .query_row(
                "SELECT source FROM v2_authorities WHERE authority=?",
                [&a],
                |r| r.get(0),
            )
            .optional()?;
        if saved_source.as_deref().is_some_and(|s| s != source) {
            return Err(err(403, "source_mismatch"));
        }
        if seq <= state.1 {
            return Err(err(409, "delivery_frontier"));
        }
        if tx.query_row(
            "SELECT count(*) FROM v2_deliveries WHERE authority=?",
            [&a],
            |r| r.get::<_, i64>(0),
        )? >= 128
        {
            return Err(err(413, "delivery_limit"));
        }
        let mut ack;
        if let Some((old, original, evidence)) = tx
            .query_row(
                "SELECT artifact,header,evidence FROM v2_assessments WHERE authority=? AND assessment=?",
                params![a, assessment],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, String>(2)?)),
            )
            .optional()?
        {
            if old != raw.as_bytes() || evidence != e {
                return Err(err(409, "assessment_conflict"));
            }
            ack = serde_json::from_slice::<Value>(&original)?;
        } else {
            if tx.query_row(
                "SELECT count(*) FROM v2_assessments WHERE authority=?",
                [&a],
                |r| r.get::<_, i64>(0),
            )? >= MAX_ASSESSMENTS_PER_AUTHORITY as i64
            {
                return Err(err(413, "assessment_limit"));
            }
            if tx.query_row("SELECT EXISTS(SELECT 1 FROM v2_assessments WHERE authority=? AND (revision=? OR evidence=?))",params![a,revision,e],|r|r.get::<_,bool>(0))?{return Err(err(409,"assessment_conflict"))}
            // Authenticated posts are trusted by the operator's grant, already checked above; the
            // exact captured text is the trusted-local rule.
            if authenticated.is_none() {
                let trusted = self
                    .captures
                    .iter()
                    .find(|c| c.binding == q["binding"] && c.evidence_id == e)
                    .ok_or_else(|| err(422, "captured_member_mismatch"))?;
                if trusted.artifact_utf8 != raw {
                    return Err(err(422, "captured_observation_mismatch"));
                }
            }
            let published = revision > state.0;
            let p = state.2 + i64::from(published);
            let members = members(&artifact, e, received, &source_sha)?;
            // One device generation may not open an unbounded number of (scope, source) pairs: each
            // one is work for every reader query over its site. Earlier generations are left out
            // on purpose (history is not pruned).
            let device = id(&q["binding"]["device"])?;
            let generation = id(&q["binding"]["generation"])?;
            let known = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM v2_authorities WHERE authority=?)",
                [&a],
                |r| r.get::<_, bool>(0),
            )?;
            // Only a source the hub has seen can be retired.
            if !known && retired(&artifact) {
                return Err(err(422, "invalid_retirement"));
            }
            if !known
                && tx.query_row(
                    "SELECT count(*) FROM v2_authorities WHERE json_extract(authority,'$[2]')=? AND json_extract(authority,'$[3]')=?",
                    [device, generation],
                    |r| r.get::<_, usize>(0),
                )? >= MAX_AUTHORITIES_PER_DEVICE
            {
                return Err(err(413, "device_authority_limit"));
            }
            tx.execute(
                "INSERT OR IGNORE INTO v2_authorities VALUES(?,?,0,0,0,NULL)",
                params![a, source],
            )?;
            // Each record's bytes are written once: the observation row holds them, and the
            // assessment's list of members is these rows joined.
            let mut member_bytes = vec![b'['];
            let mut insert = tx.prepare_cached("INSERT INTO v2_observations VALUES(?,?,?,?)")?;
            for r in &members {
                let bytes = canonical(r);
                insert.execute(params![a, id(&r["record_id"])?, assessment, bytes])?;
                if member_bytes.len() > 1 {
                    member_bytes.push(b',');
                }
                member_bytes.extend(bytes);
            }
            member_bytes.push(b']');
            drop(insert);
            let header = if published {
                let sid = format!(
                    "hub-{}",
                    hash(&canonical(&json!([
                        authority_tuple(&q["binding"]),
                        source,
                        p,
                        digest
                    ])))
                );
                json!({"snapshot_id":sid,"snapshot_revision":p,"catalog_id":format!("catalog-{sid}"),"catalog_revision":p})
            } else {
                let raw: Vec<u8> = tx.query_row(
                    "SELECT header FROM v2_views WHERE authority=? AND publication=?",
                    params![a, p],
                    |r| r.get(0),
                )?;
                serde_json::from_slice(&raw)?
            };
            ack = json!({"schema":2,"binding":q["binding"],"sequence":seq,"digest":digest,"assessment_id":assessment,"revision":revision,"artifact_sha256":q["artifact_sha256"],"received_at":received,"result":if published{"published"}else{"historical_only"},"snapshot_id":header["snapshot_id"],"snapshot_revision":header["snapshot_revision"],"catalog_id":header["catalog_id"],"catalog_revision":header["catalog_revision"]});
            tx.execute(
                "INSERT INTO v2_assessments VALUES(?,?,?,?,?,?,?,?,?,?)",
                params![
                    a,
                    assessment,
                    revision,
                    e,
                    source_sha,
                    raw.as_bytes(),
                    member_bytes,
                    received,
                    if published {
                        "published"
                    } else {
                        "historical_only"
                    },
                    canonical(&ack)
                ],
            )?;
            // Schema 3 keeps each authority's replayed changes beside its assessments: an in-order
            // assessment continues the stored replay, a late one recomputes this authority only.
            if tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? == 3 {
                if published {
                    let stored = super::change_log::admitted(revision, received, e, raw)?;
                    super::change_log::append(&tx, &a, &stored)?;
                } else {
                    super::change_log::rebuild(&tx, &a)?;
                }
            }
            if published {
                if retired(&artifact) {
                    // The device stopped observing this source: nothing is current for it and no
                    // input state remains. The change log calls the leaving rows retired, not resolved.
                    tx.execute("DELETE FROM v2_current WHERE authority=?", [&a])?;
                    tx.execute("DELETE FROM v2_coverage WHERE authority=?", [&a])?;
                }
                let by_input = records_by_input(&artifact);
                for input in artifact["inputs"].as_array().unwrap() {
                    let path = id(&input["path"])?;
                    let failed = !input["error"].is_null();
                    tx.execute("INSERT OR REPLACE INTO v2_coverage VALUES(?,?,?,?)",params![a,path,assessment,canonical(&json!({"state":if failed{"failed"}else{"complete"},"reason":input["error"]}))])?;
                    if !failed {
                        // A read input replaces everything the authority held for it, whether
                        // that was one record under the path or one per package.
                        let prefix = format!("{path}{CURRENT_SEPARATOR}");
                        tx.execute(
                            "DELETE FROM v2_current WHERE authority=?1 AND (path=?2 OR substr(path,1,length(?3))=?3)",
                            params![a, path, prefix],
                        )?;
                        let held = by_input
                            .get(path)
                            .filter(|rs| !rs.is_empty())
                            .ok_or_else(|| err(422, "captured_member_mismatch"))?;
                        let mut insert =
                            tx.prepare_cached("INSERT INTO v2_current VALUES(?,?,?)")?;
                        for r in held {
                            insert.execute(params![
                                a,
                                format!("{prefix}{}", id(&r["location_ref"])?),
                                id(&r["record_id"])?
                            ])?;
                        }
                    }
                }
                let view = build_view(&tx, &a, &header)?;
                let bytes = canonical(&view);
                if bytes.len() > capture::VIEW_LIMIT {
                    return Err(err(413, "view_limit"));
                }
                tx.execute(
                    "INSERT INTO v2_views VALUES(?,?,?,?)",
                    params![a, p, canonical(&header), bytes],
                )?;
                tx.execute("UPDATE v2_authorities SET frontier=?,publication=?,current_view=? WHERE authority=?",params![revision,p,header["snapshot_id"].as_str(),a])?;
            }
        }
        ack["sequence"] = json!(seq);
        ack["digest"] = json!(digest);
        let bytes = canonical(&ack);
        if bytes.len() > 4096 {
            return Err(err(413, "ack_limit"));
        }
        tx.execute(
            "INSERT INTO v2_deliveries VALUES(?,?,?,?,?)",
            params![a, source, seq, digest, bytes],
        )?;
        tx.execute(
            "UPDATE v2_authorities SET delivery_frontier=? WHERE authority=?",
            params![seq, a],
        )?;
        if start.elapsed() > self.budget {
            return Err(err(503, "admission_deadline"));
        }
        fault("before-commit");
        db_wait(&tx, Some(deadline))?;
        if tx.commit().is_err() {
            drop(db);
            let reopened = self.connect(Some(deadline))?;
            let saved:Option<(String,Vec<u8>)>=reopened.query_row("SELECT digest,ack FROM v2_deliveries WHERE authority=? AND source=? AND sequence=?",params![a,source,seq],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            return match saved {
                Some((d, ack)) if d == digest => Ok(ack),
                _ => Err(err(503, "storage_failure")),
            };
        }
        fault("after-commit-before-response");
        Ok(bytes)
    }
}
fn db_wait(db: &Connection, deadline: Option<Instant>) -> Result<()> {
    let remaining = match deadline {
        Some(deadline) => deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| err(503, "admission_deadline"))?,
        None => Duration::from_millis(200),
    };
    db.busy_timeout(remaining.min(Duration::from_millis(200)))?;
    Ok(())
}
fn members(a: &Value, e: &str, received: &str, source_sha: &str) -> Result<Vec<Value>> {
    a["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let mut r = r.clone();
            r.as_object_mut().unwrap().remove("input_path");
            let mut d = a["binding"].clone();
            d["evidence"] = json!(e);
            d["evidence_class"] = json!("inventory_projection");
            r["dimensions"] = d;
            r["assessment_id"] = a["assessment_id"].clone();
            r["revision"] = a["revision"].clone();
            r["times"] = a["times"].clone();
            r["times"]["received_at"] = json!({"value":received,"null_reason":null});
            r["coverage"] = a["coverage"].clone();
            r["source_sha256"] = json!(source_sha);
            Ok(r)
        })
        .collect()
}
fn build_view(db: &Connection, a: &str, header: &Value) -> Result<Value> {
    let blobs=db.prepare("SELECT o.payload,o.assessment FROM v2_current c JOIN v2_observations o ON o.authority=c.authority AND o.record=c.record WHERE c.authority=? ORDER BY c.record")?.query_map([a],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
    if blobs.len() > MAX_RECORDS_PER_ASSESSMENT {
        return Err(err(413, "current_limit"));
    }
    /// An assessment's artifact, read and hashed once however many current records it holds.
    struct Source {
        evidence: String,
        sha: String,
        length: usize,
        producer: Value,
        text: String,
    }
    #[derive(Deserialize)]
    struct Head {
        producer: Value,
    }
    let mut sources = BTreeMap::<String, Source>::new();
    let mut records = vec![];
    let mut evidence = BTreeMap::<String, Value>::new();
    let mut payloads = BTreeMap::new();
    let mut tuples = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    for (b, assessment) in blobs {
        if !sources.contains_key(&assessment) {
            let (e, raw): (String, Vec<u8>) = db.query_row(
                "SELECT evidence,artifact FROM v2_assessments WHERE authority=? AND assessment=?",
                params![a, assessment],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            sources.insert(
                assessment.clone(),
                Source {
                    evidence: e,
                    sha: hash(&raw),
                    length: raw.len(),
                    producer: serde_json::from_slice::<Head>(&raw)?.producer,
                    text: String::from_utf8(raw).map_err(|_| err(503, "storage_failure"))?,
                },
            );
        }
        let source = &sources[&assessment];
        let mut r: Value = serde_json::from_slice(&b)?;
        r["source_sha256"] = json!(source.sha);
        let ev=evidence.entry(source.evidence.clone()).or_insert_with(||json!({"evidence_id":source.evidence,"class":"inventory_projection","source_sha256":source.sha,"source_byte_length":source.length,"producer":source.producer,"record_ids":[]}));
        ev["record_ids"]
            .as_array_mut()
            .unwrap()
            .push(r["record_id"].clone());
        bindings.insert(id(&r["assessment_id"])?.to_string(),json!({"assessment_id":r["assessment_id"],"revision":r["revision"],"input_sha256":r["source_sha256"]}));
        tuples.insert(
            String::from_utf8(canonical(&r["dimensions"])).unwrap(),
            r["dimensions"].clone(),
        );
        payloads
            .entry(source.evidence.clone())
            .or_insert_with(|| source.text.clone());
        records.push(r);
    }
    Ok(
        json!({"contract_version":"m0b-derived-1","header":header,"records":records,"evidence":evidence.into_values().collect::<Vec<_>>(),"retained_payload_utf8":payloads,"catalog_tuples":tuples.into_values().collect::<Vec<_>>(),"assessment_bindings":bindings.into_values().collect::<Vec<_>>()}),
    )
}
fn artifact_identity(a: &Value) -> Result<()> {
    fields(
        a,
        &[
            "assessment_id",
            "revision",
            "binding",
            "capture_token",
            "inputs",
            "provider",
            "producer",
            "records",
            "times",
            "coverage",
            "legacy_import",
        ],
    )?;
    id(&a["assessment_id"])?;
    positive(&a["revision"])?;
    id(&a["capture_token"])?;
    binding(&a["binding"])?;
    Ok(())
}
fn artifact_structure(a: &Value) -> Result<()> {
    fn text_or_null(v: &Value) -> Result<()> {
        if v.is_string() || v.is_null() {
            Ok(())
        } else {
            Err(err(400, "invalid_type"))
        }
    }
    artifact_identity(a)?;
    if !a["legacy_import"].is_boolean() {
        return Err(err(400, "invalid_type"));
    }
    fields(&a["producer"], &["name", "source_pin"])?;
    id(&a["producer"]["name"])?;
    id(&a["producer"]["source_pin"])?;
    let inputs = a["inputs"]
        .as_array()
        .ok_or_else(|| err(400, "invalid_inputs"))?;
    let records = a["records"]
        .as_array()
        .ok_or_else(|| err(400, "invalid_records"))?;
    if inputs.len() > MAX_INPUTS_PER_ASSESSMENT || records.len() > MAX_RECORDS_PER_ASSESSMENT {
        return Err(err(413, "input_limit"));
    }
    fields(
        &a["times"],
        &[
            "observed_at",
            "assessment_completed_at",
            "advisory_checked_at",
            "received_at",
        ],
    )?;
    for key in [
        "observed_at",
        "assessment_completed_at",
        "advisory_checked_at",
        "received_at",
    ] {
        fields(&a["times"][key], &["value", "null_reason"])?;
        text_or_null(&a["times"][key]["value"])?;
        text_or_null(&a["times"][key]["null_reason"])?;
    }
    fields(
        &a["coverage"],
        &[
            "inventory",
            "advisories",
            "osv",
            "kev",
            "epss",
            "global_clean",
            "fix_verified",
        ],
    )?;
    for key in ["inventory", "advisories"] {
        fields(&a["coverage"][key], &["state", "reason"])?;
        id(&a["coverage"][key]["state"])?;
        text_or_null(&a["coverage"][key]["reason"])?;
    }
    for key in ["osv", "kev"] {
        id(&a["coverage"][key])?;
    }
    for key in ["global_clean", "fix_verified"] {
        if !a["coverage"][key].is_boolean() {
            return Err(err(400, "invalid_type"));
        }
    }
    for r in records {
        fields(
            r,
            &[
                "record_id",
                "component_id",
                "location_ref",
                "package",
                "legacy_aliases",
                "input_path",
            ],
        )?;
        for key in ["record_id", "component_id", "location_ref", "input_path"] {
            id(&r[key])?;
        }
        fields(
            &r["package"],
            &["ecosystem", "namespace", "name", "version", "qualifiers"],
        )?;
        for key in ["ecosystem", "name", "version"] {
            if !r["package"][key].is_string() {
                return Err(err(400, "invalid_type"));
            }
        }
        text_or_null(&r["package"]["namespace"])?;
        if !r["package"]["qualifiers"].is_object() {
            return Err(err(400, "invalid_type"));
        }
        for alias in r["legacy_aliases"]
            .as_array()
            .ok_or_else(|| err(400, "invalid_aliases"))?
        {
            fields(alias, &["namespace", "value"])?;
            id(&alias["namespace"])?;
            id(&alias["value"])?;
        }
    }
    for input in inputs {
        let mut keys = vec!["path", "sha256", "bytes_utf8", "error"];
        if input.get("detail").is_some() {
            keys.push("detail");
            text_or_null(&input["detail"])?;
        }
        fields(input, &keys)?;
        id(&input["path"])?;
        text_or_null(&input["error"])?;
        text_or_null(&input["sha256"])?;
        if input["error"].is_null() {
            // The text is read by the lockfile parser only once the request is known to come from
            // the device it names (`validate_artifact`).
            if !input["bytes_utf8"].is_string() {
                return Err(err(400, "invalid_input"));
            }
        } else {
            text_or_null(&input["bytes_utf8"])?;
        }
    }
    Ok(())
}
/// Separates an input path from a package location in a `v2_current` key (the device keeps its own
/// rows the same way). Input paths cannot hold control characters, so the key splits unambiguously.
pub(super) const CURRENT_SEPARATOR: char = '\u{1f}';
/// The records of an artifact grouped by the input they came from, in artifact order.
pub(super) fn records_by_input(a: &Value) -> BTreeMap<&str, Vec<&Value>> {
    let mut out: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for r in a["records"].as_array().into_iter().flatten() {
        if let Some(path) = r["input_path"].as_str() {
            out.entry(path).or_default().push(r);
        }
    }
    out
}
/// The records an input carries are exactly the packages the scanner's own reader finds in the
/// input's text, one record for each: a record the text does not hold, one missing, one twice or
/// one of another ecosystem or version is refused. The reader is the device's (`capture`), so the
/// device and the hub cannot read one lockfile two ways.
fn input_matches(path: &str, text: &str, records: &[&Value]) -> Result<()> {
    let file = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let found = capture::lock_packages(file, text.as_bytes()).map_err(|(code, _)| {
        if code.starts_with("duplicate_input_key") {
            err(422, "duplicate_input_key")
        } else {
            err(422, "unsupported_input")
        }
    })?;
    let mut have = BTreeSet::new();
    for r in records {
        let field = |k: &str| r["package"][k].as_str().unwrap_or_default().to_string();
        if !have.insert((field("ecosystem"), field("name"), field("version"))) {
            return Err(err(422, "captured_member_mismatch"));
        }
    }
    if have.into_iter().collect::<Vec<_>>() != found {
        return Err(err(422, "captured_member_mismatch"));
    }
    Ok(())
}
/// Whether the artifact says its source is retired. Only the device can say so: it is the one that
/// knows it stopped observing the source.
fn retired(a: &Value) -> bool {
    a["coverage"]["inventory"]["state"] == "retired"
}
/// The coverage a device-sent retirement states, and the only one the hub accepts for it.
fn retirement_coverage() -> Value {
    json!({"inventory":{"state":"retired","reason":"source_retired_by_device"},"advisories":{"state":"not_requested","reason":"provider_disabled"},"osv":"not_requested","kev":"unknown","epss":null,"global_clean":false,"fix_verified":false})
}
/// A retirement observes nothing: no inputs, no records, no provider, an observation time, and
/// exactly the retirement coverage. Conclusions about the fleet stay the reader's.
fn validate_retirement(a: &Value, inputs: &[Value], records: &[Value]) -> Result<()> {
    if !inputs.is_empty() || !records.is_empty() || !a["provider"].is_null() {
        return Err(err(422, "invalid_retirement"));
    }
    producer_and_times(a)?;
    if a["times"]["observed_at"]["value"].is_null() {
        return Err(err(422, "invalid_time"));
    }
    if a["coverage"] != retirement_coverage() {
        return Err(err(422, "unsupported_coverage"));
    }
    Ok(())
}
/// The provider outcome an artifact carries, if any. Only an unsuccessful one is admitted
/// (the provider was asked and did not answer); its time is the artifact's advisory check time.
/// Returns whether there is one.
fn provider_outcome(a: &Value) -> Result<bool> {
    let p = &a["provider"];
    if p.is_null() {
        return Ok(false);
    }
    let invalid = || err(422, "invalid_provider");
    fields(
        p,
        &[
            "name",
            "request",
            "status",
            "checked_at",
            "response_utf8",
            "sha256",
            "null_reason",
        ],
    )?;
    let (request, checked) = (p["request"].as_str(), p["checked_at"].as_str());
    if p["name"] != "osv" || p["status"] != "unavailable" || request.is_none() {
        return Err(invalid());
    }
    if !checked.is_some_and(decimal)
        || a["times"]["advisory_checked_at"] != json!({"value":checked,"null_reason":null})
    {
        return Err(invalid());
    }
    let response = match &p["response_utf8"] {
        Value::Null => None,
        Value::String(s) => Some(s.as_str()),
        _ => return Err(invalid()),
    };
    let (sha256, null_reason) = match response {
        Some(s) => (json!(hash(s.as_bytes())), Value::Null),
        None => (Value::Null, json!("no_response")),
    };
    if p["sha256"] != sha256 || p["null_reason"] != null_reason {
        return Err(invalid());
    }
    Ok(true)
}
fn validate_artifact(a: &Value) -> Result<()> {
    artifact_identity(a)?;
    if a["legacy_import"] != false {
        return Err(err(422, "unsupported_artifact"));
    }
    let inputs = a["inputs"]
        .as_array()
        .ok_or_else(|| err(400, "invalid_inputs"))?;
    let records = a["records"]
        .as_array()
        .ok_or_else(|| err(400, "invalid_records"))?;
    if inputs.len() > MAX_INPUTS_PER_ASSESSMENT || records.len() > MAX_RECORDS_PER_ASSESSMENT {
        return Err(err(413, "input_limit"));
    }
    if retired(a) {
        return validate_retirement(a, inputs, records);
    }
    if inputs.is_empty() || records.is_empty() {
        return Err(err(422, "zero_fresh"));
    }
    producer_and_times(a)?;
    let unavailable = provider_outcome(a)?;
    let partial = inputs.iter().any(|i| !i["error"].is_null());
    let advisories = if unavailable {
        json!({"state":"unavailable","reason":"provider_unavailable"})
    } else {
        json!({"state":"not_requested","reason":"provider_disabled"})
    };
    let expected = json!({"inventory":{"state":if partial{"partial"}else{"complete"},"reason":if partial{json!("input_read_failed")}else{Value::Null}},"advisories":advisories,"osv":if unavailable{"unavailable"}else{"not_requested"},"kev":"unknown","epss":null,"global_clean":false,"fix_verified":false});
    if a["coverage"] != expected {
        return Err(err(422, "unsupported_coverage"));
    }
    validate_members(a, inputs, records)
}
/// The producer and the four times every admitted artifact states.
fn producer_and_times(a: &Value) -> Result<()> {
    fields(&a["producer"], &["name", "source_pin"])?;
    id(&a["producer"]["name"])?;
    id(&a["producer"]["source_pin"])?;
    fields(
        &a["times"],
        &[
            "observed_at",
            "assessment_completed_at",
            "advisory_checked_at",
            "received_at",
        ],
    )?;
    for k in [
        "observed_at",
        "assessment_completed_at",
        "advisory_checked_at",
        "received_at",
    ] {
        let t = &a["times"][k];
        fields(t, &["value", "null_reason"])?;
        if t["value"].is_null() {
            if !matches!(
                t["null_reason"].as_str(),
                Some(
                    "producer_time_unavailable"
                        | "legacy_observation_time_unavailable"
                        | "not_requested"
                        | "not_received"
                )
            ) {
                return Err(err(422, "invalid_time"));
            }
        } else if !t["value"].as_str().is_some_and(decimal) || !t["null_reason"].is_null() {
            return Err(err(422, "invalid_time"));
        }
    }
    Ok(())
}
/// Every record is one package of one input, the inputs read are exactly what their text holds,
/// and a record belongs to an input the artifact names.
fn validate_members(a: &Value, inputs: &[Value], records: &[Value]) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut locations = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for r in records {
        fields(
            r,
            &[
                "record_id",
                "component_id",
                "location_ref",
                "package",
                "legacy_aliases",
                "input_path",
            ],
        )?;
        for k in ["record_id", "component_id", "location_ref", "input_path"] {
            id(&r[k])?;
        }
        if !ids.insert(id(&r["record_id"])?) {
            return Err(err(422, "duplicate_record"));
        }
        fields(
            &r["package"],
            &["ecosystem", "namespace", "name", "version", "qualifiers"],
        )?;
        let p = &r["package"];
        if !ECOSYSTEMS.iter().any(|e| p["ecosystem"] == *e)
            || !p["namespace"].is_null()
            || p["qualifiers"] != json!({})
            || p["name"].as_str().is_none_or(str::is_empty)
            || p["version"].as_str().is_none_or(str::is_empty)
        {
            return Err(err(422, "unsupported_package"));
        }
        // A location is one package of one input: the hub's current rows are keyed by it.
        if !locations.insert((
            r["input_path"].as_str().unwrap_or_default(),
            r["location_ref"].as_str().unwrap_or_default(),
        )) {
            return Err(err(422, "duplicate_record"));
        }
        for alias in r["legacy_aliases"]
            .as_array()
            .ok_or_else(|| err(400, "invalid_aliases"))?
        {
            fields(alias, &["namespace", "value"])?;
            id(&alias["namespace"])?;
            id(&alias["value"])?;
        }
    }
    let by_input = records_by_input(a);
    for i in inputs {
        let path = id(&i["path"])?;
        if i["error"].is_null() {
            fields(i, &["path", "sha256", "bytes_utf8", "error"])?;
            let text = i["bytes_utf8"]
                .as_str()
                .ok_or_else(|| err(400, "invalid_input"))?;
            if i["sha256"] != hash(text.as_bytes()) {
                return Err(err(422, "input_digest"));
            }
            input_matches(
                path,
                text,
                by_input.get(path).map_or(&[][..], |v| v.as_slice()),
            )?;
        } else if i["error"] != "input_read_failed"
            || !i["sha256"].is_null()
            || !i["bytes_utf8"].is_null()
        {
            return Err(err(422, "unsupported_input"));
        }
        if !i["error"].is_null() {
            let mut keys = vec!["path", "sha256", "bytes_utf8", "error"];
            if i.get("detail").is_some() {
                keys.push("detail");
            }
            fields(i, &keys)?;
            if by_input.contains_key(path) {
                return Err(err(422, "captured_member_mismatch"));
            }
        }
        if !paths.insert(path)
            || Path::new(path)
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(err(422, "input_path"));
        }
    }
    if records
        .iter()
        .any(|r| !paths.contains(r["input_path"].as_str().unwrap()))
    {
        return Err(err(422, "captured_member_mismatch"));
    }
    Ok(())
}

fn fault(point: &str) {
    #[cfg(feature = "native-admission-test")]
    if point == "admission-held" {
        if let Ok(path) = std::env::var("VORDA_NATIVE_HOLD_FIFO") {
            use std::io::Read;
            println!("held");
            let mut byte = [0];
            let _ = File::open(path).and_then(|mut f| f.read_exact(&mut byte));
        }
    }
    #[cfg(feature = "native-admission-test")]
    if std::env::var("VORDA_NATIVE_FAULT").ok().as_deref() == Some(point) {
        std::process::exit(86)
    }
    let _ = point;
}
pub fn validate_ack(request: &[u8], ack: &[u8]) -> Result<()> {
    validate_ack_inner(request, ack).map_err(|_| err(422, "invalid_v2_ack"))
}
fn validate_ack_inner(request: &[u8], ack: &[u8]) -> Result<()> {
    let q = parse(request, REQUEST_LIMIT)?;
    let a = parse(ack, 4096)?;
    fields(
        &a,
        &[
            "schema",
            "binding",
            "sequence",
            "digest",
            "assessment_id",
            "revision",
            "artifact_sha256",
            "received_at",
            "result",
            "snapshot_id",
            "snapshot_revision",
            "catalog_id",
            "catalog_revision",
        ],
    )?;
    let artifact = parse(
        q["artifact_utf8"]
            .as_str()
            .ok_or_else(|| err(400, "invalid_request"))?
            .as_bytes(),
        ARTIFACT_LIMIT,
    )?;
    if canonical(&a) != ack
        || a["schema"] != 2
        || a["binding"] != q["binding"]
        || a["sequence"] != q["sequence"]
        || a["digest"] != hash(request)
        || a["assessment_id"] != artifact["assessment_id"]
        || a["revision"] != artifact["revision"]
        || a["artifact_sha256"] != q["artifact_sha256"]
        || !a["received_at"].as_str().is_some_and(decimal)
        || !matches!(a["result"].as_str(), Some("published" | "historical_only"))
        || a["snapshot_revision"] != a["catalog_revision"]
        || positive(&a["snapshot_revision"]).is_err()
        || a["catalog_id"] != format!("catalog-{}", id(&a["snapshot_id"])?)
    {
        return Err(err(422, "invalid_v2_ack"));
    }
    Ok(())
}
