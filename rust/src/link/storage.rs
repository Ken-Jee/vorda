use super::{digest, encode, text, validate};
use crate::store::{now, private_dir};
use crate::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn verifier(credential: &str) -> Result<String> {
    if !(32..=256).contains(&credential.chars().count()) {
        return Err(Error::rejected(
            400,
            "credential must contain 32 to 256 characters",
        ));
    }
    Ok(format!("{:x}", Sha256::digest(credential.as_bytes())))
}

/// The database byte ceiling a hub uses unless the operator sets one (`--max-db-mib`): 1 GiB.
pub const DEFAULT_MAX_DB_BYTES: u64 = 1024 * 1024 * 1024;

pub struct Database {
    pub path: PathBuf,
    pub max_bytes: u64,
}
impl Database {
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                private_dir(parent)?;
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(path)?);
        let result = Self {
            path: path.into(),
            max_bytes,
        };
        let db = result.connect()?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != 0 && version != 1 {
            return Err(Error::new("unsupported linking database version"));
        }
        db.pragma_update(None, "journal_mode", "DELETE")?;
        db.pragma_update(None, "user_version", 1)?;
        Ok(result)
    }
    pub fn connect(&self) -> Result<Connection> {
        let db = Connection::open(&self.path)?;
        db.busy_timeout(Duration::from_millis(200))?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
        db.pragma_update(None, "max_page_count", (self.max_bytes / size).max(16))?;
        Ok(db)
    }
}

pub struct Hub {
    pub database: Database,
}
impl Hub {
    pub fn open(path: &Path) -> Result<Self> {
        Self::with_limit(path, DEFAULT_MAX_DB_BYTES)
    }
    pub fn with_limit(path: &Path, max_bytes: u64) -> Result<Self> {
        if path.exists() {
            let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if matches!(version, 2 | 3) {
                super::native::schema(&db, version)?;
                return Ok(Self {
                    database: Database {
                        path: path.into(),
                        max_bytes,
                    },
                });
            }
        }
        let database = Database::open(path, max_bytes)?;
        database.connect()?.execute_batch("CREATE TABLE IF NOT EXISTS invites(verifier TEXT PRIMARY KEY,org TEXT,site TEXT,expires REAL);
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,generation TEXT,org TEXT,site TEXT,revoked INTEGER DEFAULT 0,sequence INTEGER DEFAULT 0,received REAL);
        CREATE TABLE IF NOT EXISTS credentials(verifier TEXT PRIMARY KEY,device TEXT,expires REAL);
        CREATE TABLE IF NOT EXISTS batches(device TEXT,sequence INTEGER,digest TEXT,ack BLOB,PRIMARY KEY(device,sequence));
        CREATE TABLE IF NOT EXISTS scans(device TEXT,scan TEXT,PRIMARY KEY(device,scan));
        CREATE TABLE IF NOT EXISTS findings(device TEXT,key TEXT,scope TEXT,payload BLOB,PRIMARY KEY(device,key));
        CREATE TABLE IF NOT EXISTS coverage(device TEXT,scope TEXT,state TEXT,PRIMARY KEY(device,scope));
        CREATE TABLE IF NOT EXISTS audit(at REAL,device TEXT,action TEXT);")?;
        Ok(Self { database })
    }
    pub fn invite(&self, credential: &str, org: &str, site: &str, ttl: f64) -> Result<()> {
        if !text(&json!(org)) || !text(&json!(site)) || !(ttl > 0.0 && ttl <= 3600.0) {
            return Err(Error::new("invalid invite scope or lifetime"));
        }
        crate::fleet::auth::refuse_reader_secret(&self.database.path, credential)?;
        self.database.connect()?.execute(
            "INSERT INTO invites VALUES(?,?,?,?)",
            params![verifier(credential)?, org, site, now() + ttl],
        )?;
        Ok(())
    }
    pub fn enroll(&self, invite: &str, credential: &str) -> Result<Value> {
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hashed = verifier(invite)?;
        let (org, site): (String, String) = tx
            .query_row(
                "SELECT org,site FROM invites WHERE verifier=? AND expires>?",
                params![hashed, now()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| Error::rejected(401, "invalid or expired invite"))?;
        let device = uuid::Uuid::new_v4().to_string();
        let generation = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO devices(id,generation,org,site) VALUES(?,?,?,?)",
            params![device, generation, org, site],
        )?;
        tx.execute(
            "INSERT INTO credentials VALUES(?,?,?)",
            params![verifier(credential)?, device, 1e30],
        )?;
        tx.execute("DELETE FROM invites WHERE verifier=?", [hashed])?;
        tx.execute(
            "INSERT INTO audit VALUES(?,?,'enroll')",
            params![now(), device],
        )?;
        tx.commit()?;
        Ok(json!({"device":device,"generation":generation}))
    }
    pub fn revoke(&self, device: &str) -> Result<()> {
        let mut db = self.database.connect()?;
        let tx = db.transaction()?;
        tx.execute("UPDATE devices SET revoked=1 WHERE id=?", [device])?;
        tx.execute(
            "INSERT INTO audit VALUES(?,?,'revoke')",
            params![now(), device],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn rotate(&self, device: &str, credential: &str, overlap: f64) -> Result<()> {
        if !(0.0..=3600.0).contains(&overlap) {
            return Err(Error::new("invalid rotation overlap"));
        }
        crate::fleet::auth::refuse_reader_secret(&self.database.path, credential)?;
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=? AND revoked=0)",
            [device],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(Error::rejected(404, "no active device"));
        }
        tx.execute(
            "UPDATE credentials SET expires=MIN(expires,?) WHERE device=?",
            params![now() + overlap, device],
        )?;
        tx.execute(
            "INSERT INTO credentials VALUES(?,?,?)",
            params![verifier(credential)?, device, 1e30],
        )?;
        tx.execute(
            "INSERT INTO audit VALUES(?,?,'rotate')",
            params![now(), device],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn ingest(&self, credential: &str, batch: &Value) -> Result<Vec<u8>> {
        validate(batch)?;
        let hashed = digest(batch)?;
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device: Option<(String,String,i64)> = tx.query_row("SELECT d.id,d.generation,d.sequence FROM devices d JOIN credentials c ON c.device=d.id WHERE c.verifier=? AND c.expires>? AND d.revoked=0",params![verifier(credential)?,now()],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (device, generation, previous) =
            device.ok_or_else(|| Error::rejected(401, "invalid or revoked credential"))?;
        if batch["device"] != device || batch["generation"] != generation {
            return Err(Error::rejected(403, "credential identity mismatch"));
        }
        let sequence = batch["sequence"].as_i64().unwrap();
        let old: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT digest,ack FROM batches WHERE device=? AND sequence=?",
                params![device, sequence],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((old_digest, ack)) = old {
            if old_digest != hashed {
                return Err(Error::rejected(409, "sequence digest conflict"));
            }
            return Ok(ack);
        }
        if sequence <= previous {
            return Err(Error::rejected(409, "stale sequence"));
        }
        let scan = batch["scan"].as_str().unwrap();
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM scans WHERE device=? AND scan=?)",
            params![device, scan],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(Error::rejected(409, "scan UUID reused"));
        }
        for (scope, state) in batch["coverage"].as_object().unwrap() {
            if state == "complete" {
                tx.execute(
                    "DELETE FROM findings WHERE device=? AND scope=?",
                    params![device, scope],
                )?;
            }
            tx.execute(
                "INSERT OR REPLACE INTO coverage VALUES(?,?,?)",
                params![device, scope, state.as_str().unwrap()],
            )?;
        }
        for f in batch["findings"].as_array().unwrap() {
            let key = f["key"].as_str().unwrap();
            let scope = f["scope"].as_str().unwrap();
            let old_scope: Option<String> = tx
                .query_row(
                    "SELECT scope FROM findings WHERE device=? AND key=?",
                    params![device, key],
                    |r| r.get(0),
                )
                .optional()?;
            if old_scope.is_some_and(|s| s != scope) {
                return Err(Error::rejected(409, "finding scope conflict"));
            }
            tx.execute(
                "INSERT OR REPLACE INTO findings VALUES(?,?,?,?)",
                params![device, key, scope, encode(f)?],
            )?;
        }
        let received = now();
        let ack = encode(
            &json!({"device":device,"generation":generation,"sequence":sequence,"digest":hashed,"received":received}),
        )?;
        tx.execute(
            "INSERT INTO batches VALUES(?,?,?,?)",
            params![device, sequence, hashed, ack],
        )?;
        tx.execute("INSERT INTO scans VALUES(?,?)", params![device, scan])?;
        tx.execute(
            "UPDATE devices SET sequence=?,received=? WHERE id=?",
            params![sequence, received, device],
        )?;
        tx.commit()?;
        Ok(ack)
    }
    pub fn snapshot(&self, device: &str) -> Result<Value> {
        let db = self.database.connect()?;
        let row = db.query_row("SELECT id,generation,org,site,revoked,sequence,received FROM devices WHERE id=?",[device],|r| Ok(json!({"id":r.get::<_,String>(0)?,"generation":r.get::<_,String>(1)?,"org":r.get::<_,String>(2)?,"site":r.get::<_,String>(3)?,"revoked":r.get::<_,i64>(4)?,"sequence":r.get::<_,i64>(5)?,"received":r.get::<_,Option<f64>>(6)?}))).optional()?.ok_or_else(|| Error::rejected(404,"unknown device"))?;
        let raw: Vec<Vec<u8>> = db
            .prepare("SELECT payload FROM findings WHERE device=? ORDER BY key")?
            .query_map([device], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let findings: Vec<Value> = raw
            .iter()
            .map(|r| serde_json::from_slice(r))
            .collect::<std::result::Result<_, _>>()?;
        let coverage: serde_json::Map<String, Value> = db
            .prepare("SELECT scope,state FROM coverage WHERE device=?")?
            .query_map([device], |r| {
                Ok((r.get::<_, String>(0)?, json!(r.get::<_, String>(1)?)))
            })?
            .collect::<std::result::Result<_, _>>()?;
        Ok(json!({"device":row,"findings":findings,"coverage":coverage}))
    }
}
