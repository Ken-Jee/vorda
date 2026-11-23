pub mod capture;
use crate::domain::{Package, Record};
use crate::{Error, Result};
use fs2::FileExt;
use rusqlite::{params, Connection};
use serde_json::{json, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How many unread messages `mail list` and the MCP `list` tool return by default.
pub const MAIL_PAGE: usize = 20;

/// Messages with an id above `after`, at most `limit` of them, and how many were left out.
pub fn page(messages: Value, after: i64, limit: usize) -> (Vec<Value>, usize) {
    let mut rest: Vec<Value> = match messages {
        Value::Array(all) => all
            .into_iter()
            .filter(|m| m["id"].as_i64().is_some_and(|id| id > after))
            .collect(),
        _ => Vec::new(),
    };
    let more = rest.len().saturating_sub(limit);
    rest.truncate(limit);
    (rest, more)
}

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub fn hostname() -> Result<String> {
    #[cfg(unix)]
    {
        let mut bytes = [0u8; 256];
        if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..end].to_vec()).map_err(|_| Error::new("invalid hostname"))
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").map_err(|_| Error::new("hostname unavailable"))
    }
}

pub fn private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

/// Reports only the explicitly selected state tree. Never follows symlinks or deletes evidence.
pub fn storage_report(root: &Path) -> Result<Value> {
    let policy = root.join("storage-policy.json");
    let config: Value = if policy.exists() {
        serde_json::from_slice(&fs::read(policy)?)?
    } else {
        json!({})
    };
    let max_bytes = config
        .get("max_bytes")
        .map(|v| {
            v.as_u64()
                .filter(|n| *n > 0)
                .ok_or_else(|| Error::new("invalid storage max_bytes"))
        })
        .transpose()?
        .unwrap_or(512 * 1024 * 1024);
    let max_file_bytes = config
        .get("max_file_bytes")
        .map(|v| {
            v.as_u64()
                .filter(|n| *n > 0)
                .ok_or_else(|| Error::new("invalid storage max_file_bytes"))
        })
        .transpose()?
        .unwrap_or(64 * 1024 * 1024);
    let mut pending = vec![root.to_path_buf()];
    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut categories = serde_json::Map::new();
    while let Some(dir) = pending.pop() {
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let metadata = match entry.path().symlink_metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            files += 1;
            if files > 100_000 {
                return Err(Error::new(
                    "state accounting entry limit exceeded; archive explicitly",
                ));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| Error::new("state size overflowed"))?;
                let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
                let category = relative
                    .components()
                    .next()
                    .unwrap()
                    .as_os_str()
                    .to_string_lossy()
                    .into_owned();
                let prior = categories
                    .get(&category)
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                categories.insert(category, json!(prior + metadata.len()));
            }
        }
    }
    Ok(
        json!({"bytes":bytes,"entries":files,"max_bytes":max_bytes,"max_file_bytes":max_file_bytes,"categories":categories,"admitted":bytes <= max_bytes,"dry_run":true,"policy":"refuse-growth; preserve unresolved evidence and every scope checkpoint; explicit operator archive only"}),
    )
}

pub fn storage_admit(root: &Path, reserve: u64) -> Result<()> {
    let report = storage_report(root)?;
    if report["bytes"].as_u64().unwrap().saturating_add(reserve)
        > report["max_bytes"].as_u64().unwrap()
    {
        return Err(Error::new("State storage budget exceeded; evidence retained; inspect storage report and explicitly archive or raise storage-policy.json limits"));
    }
    Ok(())
}

pub fn atomic(path: &Path, text: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("path needs a parent"))?;
    fs::create_dir_all(parent)?;
    if let Some(root) = parent
        .ancestors()
        .find(|p| p.join("mail.db").exists() || p.join("storage-policy.json").exists())
    {
        let report = storage_report(root)?;
        if text.len() as u64 > report["max_file_bytes"].as_u64().unwrap() {
            return Err(Error::new(
                "State file exceeds storage file budget; existing evidence retained",
            ));
        }
        storage_admit(root, text.len() as u64)?;
    }
    let temp = parent.join(format!(".vorda-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if temp.exists() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if !(' '..'\u{7f}').contains(&c) => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn python_number(number: &Number) -> Result<String> {
    let raw = number.to_string();
    if !raw.contains(['.', 'e', 'E']) {
        return Ok(raw);
    }
    let n: f64 = raw.parse().map_err(|_| Error::new("invalid JSON number"))?;
    if !n.is_finite() {
        return Err(Error::new(
            "out of range float values are not JSON compliant",
        ));
    }
    let shortest = serde_json::to_string(&n)?;
    let negative = shortest.starts_with('-');
    let unsigned = shortest.trim_start_matches('-');
    let (mantissa, exponent) = unsigned
        .split_once('e')
        .map_or((unsigned, 0), |(m, e)| (m, e.parse::<i32>().unwrap_or(0)));
    let dot = mantissa.find('.').unwrap_or(mantissa.len()) as i32;
    let all = mantissa.replace('.', "");
    let leading = all.bytes().take_while(|b| *b == b'0').count();
    let digits = all[leading..].trim_end_matches('0');
    let sign = if negative { "-" } else { "" };
    if digits.is_empty() {
        return Ok(format!("{sign}0.0"));
    }
    let exp = dot - leading as i32 - 1 + exponent;
    if !(-4..16).contains(&exp) {
        let tail = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        return Ok(format!(
            "{sign}{}{tail}e{}{abs:02}",
            &digits[..1],
            if exp < 0 { '-' } else { '+' },
            abs = exp.abs()
        ));
    }
    let point = exp + 1;
    let body = if point <= 0 {
        format!("0.{}{}", "0".repeat((-point) as usize), digits)
    } else if point as usize >= digits.len() {
        format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
    } else {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    };
    Ok(format!("{sign}{body}"))
}

pub fn python_json(value: &Value, compact: bool) -> Result<String> {
    fn write(value: &Value, compact: bool, out: &mut String) -> Result<()> {
        let comma = if compact { "," } else { ", " };
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::String(s) => string(s, out),
            Value::Number(n) => out.push_str(&python_number(n)?),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(comma);
                    }
                    write(item, compact, out)?;
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                let keys: BTreeSet<_> = map.keys().collect();
                for (i, key) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push_str(comma);
                    }
                    string(key, out);
                    out.push_str(if compact { ":" } else { ": " });
                    write(&map[*key], compact, out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    write(value, compact, &mut out)?;
    Ok(out)
}

pub fn identity(value: &Value) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(python_json(value, false)?.as_bytes())
    )[..24]
        .into())
}

pub fn asset(package: &Package) -> Result<String> {
    identity(&json!([
        package.path,
        package.ecosystem,
        package.name,
        package.version
    ]))
}

pub fn semantic(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| {
                    ![
                        "fetched_at",
                        "epss",
                        "kev",
                        "priority",
                        "published",
                        // Display text: a new or edited advisory title is not a new finding.
                        "summary",
                        "inventory_observed_at",
                        "advisories_checked_at",
                    ]
                    .contains(&k.as_str())
                })
                .map(|(k, v)| (k.clone(), semantic(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(semantic).collect()),
        other => other.clone(),
    }
}

pub struct Store {
    pub root: PathBuf,
    pub db: Connection,
}
pub struct ScanLock(File);
impl Drop for ScanLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        private_dir(root)?;
        let path = root.join("mail.db");
        #[cfg(unix)]
        {
            // The folder may predate Vorda with wider permissions; the mailbox holds the
            // vulnerability inventory, so both stay owner-only.
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(&path)?;
            for (item, mode) in [(root, 0o700), (path.as_path(), 0o600)] {
                if fs::metadata(item)?.permissions().mode() & 0o777 != mode {
                    fs::set_permissions(item, fs::Permissions::from_mode(mode))?;
                }
            }
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(30))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > 3 {
            return Err(Error::new("mailbox schema is newer than this tool"));
        }
        let journal: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        if journal != "wal" {
            let started = Instant::now();
            loop {
                match db.pragma_update(None, "journal_mode", "WAL") {
                    Err(rusqlite::Error::SqliteFailure(code, _))
                        if matches!(
                            code.code,
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        ) && started.elapsed() < Duration::from_secs(30) =>
                    {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    result => {
                        result?;
                        break;
                    }
                }
            }
        }
        if version < 3 {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if version > 3 {
                return Err(Error::new("mailbox schema is newer than this tool"));
            }
            if version < 3 {
                tx.execute_batch("CREATE TABLE IF NOT EXISTS findings(key TEXT PRIMARY KEY,payload TEXT,active INTEGER);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,key TEXT,kind TEXT,payload TEXT,created REAL);
        CREATE TABLE IF NOT EXISTS readers(name TEXT PRIMARY KEY,cursor INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS receipts(reader TEXT,message INTEGER,ack INTEGER DEFAULT 0,snooze REAL DEFAULT 0,PRIMARY KEY(reader,message));
        CREATE TABLE IF NOT EXISTS outbox(message INTEGER,channel TEXT,attempts INTEGER DEFAULT 0,last_error TEXT,next_attempt REAL DEFAULT 0,delivered INTEGER DEFAULT 0,PRIMARY KEY(message,channel));
        CREATE TABLE IF NOT EXISTS delivery_channels(channel TEXT PRIMARY KEY,watermark INTEGER NOT NULL);")?;
                let columns: Vec<String> = tx
                    .prepare("PRAGMA table_info(receipts)")?
                    .query_map([], |r| r.get(1))?
                    .collect::<std::result::Result<_, _>>()?;
                if !columns.iter().any(|c| c == "seen") {
                    tx.execute_batch("ALTER TABLE receipts ADD COLUMN seen INTEGER DEFAULT 0")?;
                }
                tx.execute_batch("CREATE INDEX IF NOT EXISTS messages_key_id ON messages(key,id); CREATE TABLE IF NOT EXISTS assessment_checkpoints(scope TEXT PRIMARY KEY,payload TEXT,sequence INTEGER); CREATE TABLE IF NOT EXISTS state_generation(id INTEGER PRIMARY KEY CHECK(id=1),generation INTEGER NOT NULL); INSERT OR IGNORE INTO state_generation VALUES(1,0);")?;
                tx.pragma_update(None, "user_version", 3)?;
            }
            tx.commit()?;
        }
        let page_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
        // Never shrink an existing database. Refuse further growth once its own ceiling is reached.
        db.pragma_update(
            None,
            "max_page_count",
            pages.max(256 * 1024 * 1024 / page_size),
        )?;
        db.pragma_update(None, "wal_autocheckpoint", 64)?;
        let store = Self {
            root: root.into(),
            db,
        };
        store.recover_exports()?;
        Ok(store)
    }

    pub fn locked(&mut self) -> Result<ScanLock> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(self.root.join("scan.lock"))?;
        if file.metadata()?.len() == 0 {
            file.write_all(b"0")?;
            file.flush()?;
        }
        let start = Instant::now();
        loop {
            if file.try_lock_exclusive().is_ok() {
                return Ok(ScanLock(file));
            }
            if start.elapsed() >= Duration::from_secs(300) {
                let mut active = self.active()?;
                active.push(json!({"key":"health:lock","asset":"health:lock","kind":"health","title":"Scanner lock timed out"}).as_object().unwrap().clone());
                self.reconcile(&active, &BTreeSet::new(), &[])?;
                return Err(Error::new("scanner lock timed out; health mail recorded"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn active(&self) -> Result<Vec<Record>> {
        let raw: Vec<String> = self
            .db
            .prepare("SELECT payload FROM findings WHERE active=1")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        raw.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }

    pub fn reconcile(
        &mut self,
        findings: &[Record],
        covered: &BTreeSet<String>,
        channels: &[String],
    ) -> Result<Vec<Record>> {
        self.reconcile_resolved(findings, covered, &BTreeSet::new(), channels)
    }

    pub fn reconcile_resolved(
        &mut self,
        findings: &[Record],
        covered: &BTreeSet<String>,
        resolved: &BTreeSet<String>,
        channels: &[String],
    ) -> Result<Vec<Record>> {
        storage_admit(&self.root, 64 * 1024)?;
        let tx = self.db.savepoint()?;
        let watermark: i64 =
            tx.query_row("SELECT COALESCE(MAX(id),0) FROM messages", [], |r| r.get(0))?;
        for channel in channels {
            tx.execute(
                "INSERT OR IGNORE INTO delivery_channels VALUES(?,?)",
                params![channel, watermark],
            )?;
        }
        let old: HashMap<String, String> = tx
            .prepare("SELECT key,payload FROM findings WHERE active=1")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let mut unique = Vec::<Record>::new();
        let mut positions = HashMap::new();
        for f in findings {
            let key = f
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::new("finding key required"))?;
            if let Some(i) = positions.get(key) {
                unique[*i] = f.clone();
            } else {
                positions.insert(key.to_string(), unique.len());
                unique.push(f.clone());
            }
        }
        let mut changed = Vec::new();
        let mut current = HashSet::new();
        for mut f in unique {
            let key = f["key"].as_str().unwrap().to_string();
            current.insert(key.clone());
            let previous = old
                .get(&key)
                .map(|s| serde_json::from_str::<Value>(s))
                .transpose()?;
            if let Some(prior) = &previous {
                for field in ["kev", "epss"] {
                    if f.get(field).is_none_or(Value::is_null) {
                        f.insert(field.into(), prior[field].clone());
                    }
                }
            }
            let value = Value::Object(f.clone());
            let payload = python_json(&value, false)?;
            if previous.as_ref().is_some_and(|prior| {
                semantic(prior) == semantic(&value)
                    && !(value["kev"] == true && prior["kev"] != true)
            }) {
                tx.execute(
                    "UPDATE findings SET payload=? WHERE key=?",
                    params![payload, key],
                )?;
                continue;
            }
            let kind = if previous.is_some() {
                "changed"
            } else {
                f.get("kind").and_then(Value::as_str).unwrap_or("finding")
            };
            tx.execute(
                "INSERT OR REPLACE INTO findings VALUES(?,?,1)",
                params![key, payload],
            )?;
            tx.execute(
                "INSERT INTO messages(key,kind,payload,created) VALUES(?,?,?,?)",
                params![key, kind, payload, now()],
            )?;
            changed.push(f);
        }
        for (key, payload) in old {
            let prior: Value = serde_json::from_str(&payload)?;
            if !current.contains(&key)
                && (resolved.contains(&key)
                    || prior["asset"].as_str().is_some_and(|a| covered.contains(a)))
            {
                tx.execute("UPDATE findings SET active=0 WHERE key=?", [&key])?;
                tx.execute(
                    "INSERT INTO messages(key,kind,payload,created) VALUES(?,'closed',?,?)",
                    params![key, payload, now()],
                )?;
            }
        }
        for channel in channels {
            tx.execute("INSERT OR IGNORE INTO outbox(message,channel) SELECT id,? FROM messages WHERE id>(SELECT watermark FROM delivery_channels WHERE channel=?) AND kind IN ('finding','changed','health')",params![channel,channel])?;
        }
        tx.execute(
            "UPDATE state_generation SET generation=generation+1 WHERE id=1",
            [],
        )?;
        tx.commit()?;
        if self.db.is_autocommit() {
            self.mirror()?;
        }
        Ok(changed)
    }

    /// Saved attention is a read-only view. Delivery ACK never resolves a finding.
    pub fn attention(
        &self,
        reader: &str,
        mode: &str,
        scope: Option<&str>,
        after: i64,
        limit: usize,
    ) -> Result<Value> {
        if !["current", "pending"].contains(&mode) || after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::new("invalid attention selection"));
        }
        // Candidate-window pagination bounds work even when every row is outside the requested scope.
        let mut statement = self.db.prepare("SELECT m.id,m.payload,m.kind,m.created,COALESCE(f.active,0),COALESCE(r.ack,0),COALESCE(r.snooze,0),m.id=(SELECT MAX(n.id) FROM messages n WHERE n.key=m.key) FROM messages m LEFT JOIN findings f ON f.key=m.key LEFT JOIN receipts r ON r.message=m.id AND r.reader=? WHERE m.id>? ORDER BY m.id LIMIT 513")?;
        let rows = statement.query_map(params![reader, after], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, f64>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, f64>(6)?,
                r.get::<_, bool>(7)?,
            ))
        })?;
        let mut result = json!({"mode":mode,"scope":scope,"next_cursor":null,"items":[],"scan_performed":false,"delivery_mutated":false,"examined":0});
        let mut cursor = after;
        for (examined, row) in rows.enumerate() {
            let (id, payload, kind, created, active, ack, snooze, latest) = row?;
            if examined == 512 || result["items"].as_array().unwrap().len() == limit {
                result["next_cursor"] = json!(cursor);
                break;
            }
            result["examined"] = json!(examined + 1);
            if (mode == "current" && !(active && latest))
                || (mode == "pending" && (ack || snooze > now()))
            {
                cursor = id;
                continue;
            }
            let mut value: Value = serde_json::from_str(&payload)?;
            if scope.is_some_and(|s| value["scan_scope"].as_str() != Some(s)) {
                cursor = id;
                continue;
            }
            value["id"] = json!(id);
            value["kind"] = json!(kind);
            value["created"] = json!(created);
            value["state"] = json!(if active { "open" } else { "closed" });
            value["next_action"] = json!(if active {
                "inspect-evidence-or-request-repair-plan"
            } else {
                "acknowledge-delivery"
            });
            result["items"].as_array_mut().unwrap().push(value);
            // Include JSON escaping inside the MCP text envelope, leaving room for JSON-RPC framing.
            let envelope = json!({"content":[{"type":"text","text":result.to_string()}]});
            if serde_json::to_vec(&envelope)?.len() > 1_990_000 {
                result["items"].as_array_mut().unwrap().pop();
                if result["items"].as_array().unwrap().is_empty() {
                    return Err(Error::new(
                        "attention item exceeds response budget; inspect saved state locally",
                    ));
                }
                result["next_cursor"] = json!(cursor);
                break;
            }
            cursor = id;
        }
        Ok(result)
    }

    pub fn mail(
        &mut self,
        reader: &str,
        action: &str,
        id: &Number,
        seconds: &Number,
    ) -> Result<Value> {
        storage_admit(&self.root, 64 * 1024)?;
        let message = id
            .as_i64()
            .ok_or_else(|| Error::new("integer is too large to convert to SQLite INTEGER"))?;
        let tx = self.db.transaction()?;
        tx.execute("INSERT OR IGNORE INTO readers(name) VALUES(?)", [reader])?;
        if action == "ack" || action == "snooze" {
            if !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id=?)",
                [message],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(Error::new("no such message"));
            }
            tx.execute(
                "INSERT OR IGNORE INTO receipts(reader,message) VALUES(?,?)",
                params![reader, message],
            )?;
            if action == "ack" {
                tx.execute(
                    "UPDATE receipts SET ack=1 WHERE reader=? AND message=?",
                    params![reader, message],
                )?;
            } else {
                let duration = seconds
                    .as_f64()
                    .filter(|n| n.is_finite())
                    .ok_or_else(|| Error::new("int too large to convert to float"))?;
                tx.execute(
                    "UPDATE receipts SET snooze=?,seen=0 WHERE reader=? AND message=?",
                    params![now() + duration, reader, message],
                )?;
            }
            tx.commit()?;
            let mut result = json!({"message":message});
            result[action] = Value::Bool(true);
            return Ok(result);
        }
        let mut rows: Vec<(i64,String,String,f64,bool)> = tx.prepare("SELECT m.id,m.payload,m.kind,m.created,COALESCE(f.active,0) FROM messages m LEFT JOIN findings f ON f.key=m.key LEFT JOIN receipts r ON r.message=m.id AND r.reader=? WHERE COALESCE(r.ack,0)=0 AND COALESCE(r.snooze,0)<=? AND (?=0 OR m.id=?) AND (? != 'list' OR COALESCE(r.seen,0)=0) ORDER BY m.id")?.query_map(params![reader,now(),message,message,action],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?.collect::<std::result::Result<_,_>>()?;
        if action == "read" && !rows.is_empty() {
            tx.execute(
                "UPDATE readers SET cursor=MAX(cursor,?) WHERE name=?",
                params![rows.last().unwrap().0, reader],
            )?;
            for row in &rows {
                tx.execute("INSERT INTO receipts(reader,message,seen) VALUES(?,?,1) ON CONFLICT(reader,message) DO UPDATE SET seen=1",params![reader,row.0])?;
            }
        }
        let result = rows
            .drain(..)
            .map(|(id, payload, kind, created, active)| {
                let mut value: Value = serde_json::from_str(&payload)?;
                value["id"] = json!(id);
                value["kind"] = json!(kind);
                value["created"] = json!(created);
                value["state"] = json!(if active { "open" } else { "closed" });
                Ok(value)
            })
            .collect::<Result<Vec<_>>>()?;
        tx.commit()?;
        Ok(Value::Array(result))
    }

    pub fn persist_assessment(&self, scope: &str, result: &Value) -> Result<()> {
        self.db.execute(
            "UPDATE state_generation SET generation=generation+1 WHERE id=1",
            [],
        )?;
        self.db.execute("INSERT INTO assessment_checkpoints(scope,payload,sequence) VALUES(?,?,(SELECT generation FROM state_generation WHERE id=1)) ON CONFLICT(scope) DO UPDATE SET payload=excluded.payload,sequence=excluded.sequence", params![scope, result.to_string()])?;
        storage_admit(&self.root, 0)
    }

    pub fn recover_exports(&self) -> Result<()> {
        let generation: i64 = self.db.query_row(
            "SELECT generation FROM state_generation WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        let marker = self.root.join("exports-generation");
        if self.root.join("inbox.jsonl").exists()
            && self.root.join("INBOX.md").exists()
            && (self.root.join("last-scan.json").exists()
                || !self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM assessment_checkpoints)",
                    [],
                    |r| r.get::<_, bool>(0),
                )?)
            && fs::read_to_string(&marker).ok().as_deref() == Some(&generation.to_string())
        {
            return Ok(());
        }
        // Over-budget state stays readable. Recovery is retried after explicit operator action.
        if storage_admit(&self.root, 64 * 1024).is_err() {
            eprintln!("Warning: derived exports await recovery after storage admission; committed SQLite evidence remains authoritative");
            return Ok(());
        }
        let recovery = (|| -> Result<()> {
            self.mirror()?;
            let latest = self
                .db
                .prepare(
                    "SELECT payload FROM assessment_checkpoints ORDER BY sequence DESC LIMIT 1",
                )?
                .query_map([], |r| r.get::<_, String>(0))?
                .next()
                .transpose()?;
            if let Some(payload) = latest {
                atomic(&self.root.join("last-scan.json"), &payload)?;
            }
            atomic(&marker, &generation.to_string())
        })();
        match recovery {
            Err(error)
                if error
                    .message
                    .starts_with("State file exceeds storage file budget")
                    || error.message.starts_with("State storage budget exceeded") =>
            {
                eprintln!("Warning: derived exports await storage admission; SQLite remains authoritative");
                Ok(())
            }
            result => result,
        }
    }

    pub fn mirror(&self) -> Result<()> {
        let rows: Vec<(i64,String,String,f64,bool)> = self.db.prepare("SELECT m.id,m.payload,m.kind,m.created,COALESCE(f.active,0) FROM messages m LEFT JOIN findings f ON f.key=m.key ORDER BY m.id")?.query_map([],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?.collect::<std::result::Result<_,_>>()?;
        let mut lines = String::new();
        let mut markdown = String::from("# Vulnerability mailbox\n\n");
        for (id, payload, kind, created, active) in rows {
            let mut value: Value = serde_json::from_str(&payload)?;
            let state = if active { "open" } else { "closed" };
            value["id"] = json!(id);
            value["kind"] = json!(kind);
            value["created"] = json!(created);
            value["state"] = json!(state);
            lines.push_str(&python_json(&value, false)?);
            lines.push('\n');
            markdown.push_str(&format!(
                "- #{id} [{state}] {kind}: {}\n",
                value["title"]
                    .as_str()
                    .unwrap_or("")
                    .replace(['\r', '\n'], " ")
            ));
        }
        atomic(&self.root.join("inbox.jsonl"), &lines)?;
        atomic(&self.root.join("INBOX.md"), &markdown)
    }
}
