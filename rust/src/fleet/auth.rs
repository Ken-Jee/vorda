use super::query;
use crate::link::{storage::Hub, text};
use crate::store::{now, private_dir};
use crate::{Error, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SCHEMA: &str = "
CREATE TABLE readers(id TEXT PRIMARY KEY,label TEXT NOT NULL,verifier TEXT NOT NULL UNIQUE,created REAL NOT NULL,expires REAL NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,device_mode TEXT NOT NULL CHECK(device_mode IN ('all','listed')),source_mode TEXT NOT NULL CHECK(source_mode IN ('all','listed')));
CREATE TABLE reader_sources(reader TEXT NOT NULL,source TEXT NOT NULL,PRIMARY KEY(reader,source));
CREATE TABLE reader_sites(reader TEXT NOT NULL,org TEXT NOT NULL,site TEXT NOT NULL,PRIMARY KEY(reader,org,site));
CREATE TABLE reader_devices(reader TEXT NOT NULL,device TEXT NOT NULL,PRIMARY KEY(reader,device));
CREATE TABLE store_meta(hub TEXT NOT NULL);
CREATE TABLE reader_audit(at REAL NOT NULL,reader TEXT NOT NULL,action TEXT NOT NULL);";
/// The layout of the reader store. A store of another version is refused with an error that names
/// it, never opened and misread.
const STORE_VERSION: i64 = 2;
/// A grant is bounded so a forgotten token cannot stay valid forever.
pub const MAX_TTL: f64 = 90.0 * 86400.0;

/// What a reader may see, resolved from a live credential.
#[derive(Debug)]
pub struct AuthorizedScope {
    store: PathBuf,
    reader: String,
    sites: BTreeSet<Site>,
    /// `None` is every device in the granted sites; `Some` is only those devices.
    devices: Option<BTreeSet<String>>,
    /// `None` is every source; `Some` is only those sources (and no source-less version 1 evidence).
    sources: Option<BTreeSet<String>>,
}
impl AuthorizedScope {
    pub fn reader(&self) -> &str {
        &self.reader
    }
    pub fn sites(&self) -> &BTreeSet<Site> {
        &self.sites
    }
    pub fn devices(&self) -> Option<&BTreeSet<String>> {
        self.devices.as_ref()
    }
    pub fn sources(&self) -> Option<&BTreeSet<String>> {
        self.sources.as_ref()
    }
    /// A digest of exactly what this grant covers, so a cursor dies if the grant changes.
    pub(crate) fn grant_digest(&self) -> String {
        let sites: Vec<_> = self.sites.iter().map(|s| [&s.org, &s.site]).collect();
        let canonical =
            serde_json::json!({"sites":sites,"devices":self.devices,"sources":self.sources});
        format!("{:x}", Sha256::digest(canonical.to_string().as_bytes()))
    }
    /// The key that authenticates this reader's cursors, derived from the reader's stored verifier
    /// and the hub's identity, so it needs no new schema: another reader's key differs and a
    /// replaced hub changes it. The reader can derive its own key from its secret, which only lets
    /// it mint cursors for its own grant and queries, still checked against live state.
    pub(crate) fn cursor_key(&self, hub: &Hub) -> Result<[u8; 32]> {
        let store = Connection::open_with_flags(&self.store, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        store.busy_timeout(Duration::from_millis(200))?;
        let verifier: String = store.query_row(
            "SELECT verifier FROM readers WHERE id=?",
            [&self.reader],
            |r| r.get(0),
        )?;
        let identity = ReaderStore::hub_identity(&hub.database.path)?.ok_or_else(unauthorized)?;
        let mut h = Sha256::new();
        for part in ["vorda-cursor-key-v1", &verifier, &identity] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        Ok(h.finalize().into())
    }
    /// Refuse a scope whose reader has expired or been revoked since it was resolved, or that is
    /// now being used against a hub other than the one its store is bound to. Every query calls
    /// this, so holding a scope longer than a request is safe but not useful.
    pub(crate) fn check(&self, hub: &Hub) -> Result<()> {
        let store = Connection::open_with_flags(&self.store, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| unauthorized())?;
        store.busy_timeout(Duration::from_millis(200))?;
        let live: bool = store.query_row(
            "SELECT EXISTS(SELECT 1 FROM readers WHERE id=? AND revoked=0 AND expires>?)",
            params![self.reader, now()],
            |r| r.get(0),
        )?;
        let bound: Option<String> = store
            .query_row("SELECT hub FROM store_meta", [], |r| r.get(0))
            .optional()?;
        let same_hub = bound.is_some() && bound == ReaderStore::hub_identity(&hub.database.path)?;
        (live && same_hub).then_some(()).ok_or_else(unauthorized)
    }
}

/// A site is named within its organization: two organizations may both have a site called `office`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    pub org: String,
    pub site: String,
}

/// Which devices of the granted sites a reader may see. Whether it is every device or a listed set
/// is stored explicitly, so a lost row can only narrow a grant.
#[derive(Debug, Clone, Copy)]
pub enum DeviceGrant<'a> {
    All,
    Listed(&'a [String]),
}

/// Which sources (collectors, as named in v2 bindings) a reader may see. Version 1 evidence has no
/// source, so a listed grant never includes it.
#[derive(Debug, Clone, Copy)]
pub enum SourceGrant<'a> {
    All,
    Listed(&'a [String]),
}

pub struct GrantRequest<'a> {
    pub label: &'a str,
    pub sites: &'a [Site],
    pub devices: DeviceGrant<'a>,
    pub sources: SourceGrant<'a>,
    pub ttl: f64,
}

/// Reader principals and grants, in `<hub>.readers` beside the hub rather than inside it: the hub
/// schema and its migrate/restore story stay as they are, and a restored hub can only show less
/// than a grant names.
pub struct ReaderStore {
    path: PathBuf,
}
pub(crate) fn unauthorized() -> Error {
    // One answer for unknown, expired and revoked credentials: no oracle about which it was.
    Error::rejected(401, "invalid reader credential")
}
/// Owner-side guard for every path that registers an ingest secret (`invite`, `rotate`,
/// `enroll-local`): refuse one that is already a reader's, revoked or not, so one string is never
/// both roles. The network enrollment endpoint must not call this: it would let an invite holder
/// test guesses against reader secrets.
pub fn refuse_reader_secret(hub: &Path, secret: &str) -> Result<()> {
    let path = ReaderStore::side(hub);
    let Ok(verifier) = verifier(secret) else {
        return Ok(()); // the ingest side rejects a secret of the wrong length itself
    };
    if !path.is_file() {
        return Ok(());
    }
    let store = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| unreadable(&path, e))?;
    store.busy_timeout(Duration::from_millis(200))?;
    let version: i64 = store
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| unreadable(&path, e))?;
    if version == 0 {
        return Ok(()); // created but never filled in: it holds no readers
    }
    if store
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM readers WHERE verifier=?)",
            [verifier],
            |r| r.get::<_, bool>(0),
        )
        .map_err(|e| unreadable(&path, e))?
    {
        return Err(Error::rejected(
            400,
            "credential is already a reader credential",
        ));
    }
    Ok(())
}
fn unreadable(path: &Path, why: impl Into<Error>) -> Error {
    let why = why.into();
    Error {
        busy: why.busy,
        ..Error::new(format!(
            "reader store {} is unreadable ({}): repair or remove it",
            path.display(),
            why.message
        ))
    }
}
/// Domain-separated from the ingest verifier (plain SHA-256), so one secret is never both.
fn verifier(secret: &str) -> Result<String> {
    if !(32..=256).contains(&secret.chars().count()) {
        return Err(unauthorized());
    }
    let mut h = Sha256::new();
    h.update(b"vorda-reader-v1\0");
    h.update(secret.as_bytes());
    Ok(format!("{:x}", h.finalize()))
}
impl ReaderStore {
    fn side(hub: &Path) -> PathBuf {
        let mut name = hub.as_os_str().to_os_string();
        name.push(".readers");
        name.into()
    }
    fn connect(&self) -> Result<Connection> {
        #[cfg(unix)]
        {
            // Whatever the file's history, it is private on every connection.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        let db = Connection::open(&self.path)?;
        db.busy_timeout(Duration::from_millis(200))?;
        db.pragma_update(None, "synchronous", "FULL")?;
        Ok(db)
    }
    /// The hub's identity: the id of the first device it ever enrolled. Devices are never deleted
    /// and the id is a random UUID, so it survives a native `restore` of the hub's own older copy but not
    /// a recreated or foreign hub file. It relies on rowid order surviving: no VACUUM or rebuild of
    /// `devices` may renumber it.
    pub(crate) fn hub_identity(hub: &Path) -> Result<Option<String>> {
        let db = Connection::open_with_flags(hub, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        db.busy_timeout(Duration::from_millis(200))?;
        Ok(db
            .query_row("SELECT id FROM devices ORDER BY rowid LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?)
    }
    /// Owner side: create the store beside the hub if it does not exist.
    pub fn create(hub: &Path) -> Result<Self> {
        let identity = Self::hub_identity(hub)?
            .ok_or_else(|| Error::rejected(400, "the hub has no enrolled devices yet"))?;
        let path = Self::side(hub);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            private_dir(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(&path)?);
        let store = Self { path };
        let mut db = store.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? == 0 {
            tx.execute_batch(SCHEMA)?;
            tx.execute("INSERT INTO store_meta VALUES(?)", [&identity])?;
            tx.pragma_update(None, "user_version", STORE_VERSION)?;
        }
        tx.commit()?;
        drop(db);
        store.open_checked(hub).map_err(|e| {
            if e.http_status == Some(401) {
                Error::rejected(400, "the reader store belongs to a different hub")
            } else {
                e
            }
        })
    }
    /// Whether a store file exists beside the hub, whatever state it is in.
    pub fn exists(hub: &Path) -> bool {
        Self::side(hub).is_file()
    }
    /// Reader side: the store must already exist; nothing is created on a read path.
    pub fn open(hub: &Path) -> Result<Self> {
        let path = Self::side(hub);
        if !path.is_file() {
            return Err(unauthorized());
        }
        Self { path }.open_checked(hub)
    }
    fn open_checked(self, hub: &Path) -> Result<Self> {
        let db = self.connect().map_err(|e| unreadable(&self.path, e))?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| unreadable(&self.path, e))?;
        if version != STORE_VERSION {
            return Err(Error::new(format!(
                "reader store {} has version {version}, this build needs {STORE_VERSION}: remove it and grant again",
                self.path.display()
            )));
        }
        let bound: Option<String> = db
            .query_row("SELECT hub FROM store_meta", [], |r| r.get(0))
            .optional()?;
        if bound.is_none() || bound != Self::hub_identity(hub)? {
            return Err(unauthorized());
        }
        Ok(self)
    }
    /// Create a reader whose credential is `secret`. The hub is read to refuse a typo'd site and an
    /// ingest secret; neither check can be made from the reader store alone. Returns the reader id.
    pub fn grant(hub: &Hub, secret: &str, req: &GrantRequest) -> Result<String> {
        let devices = match req.devices {
            DeviceGrant::All => &[],
            DeviceGrant::Listed(devices) => devices,
        };
        // Repeating a source asks for it once.
        let sources: BTreeSet<String> = match req.sources {
            SourceGrant::All => BTreeSet::new(),
            SourceGrant::Listed(sources) => sources.iter().cloned().collect(),
        };
        let verifier = verifier(secret).map_err(|_| {
            Error::rejected(400, "reader credential must contain 32 to 256 characters")
        })?;
        if !text(&serde_json::json!(req.label))
            || req.sites.is_empty()
            || req.sites.len() > 64
            || devices.len() > 256
            || (matches!(req.devices, DeviceGrant::Listed(_)) && devices.is_empty())
            || (matches!(req.sources, SourceGrant::Listed(_)) && sources.is_empty())
            || !req
                .sites
                .iter()
                .flat_map(|s| [&s.org, &s.site])
                .chain(devices)
                .all(|v| text(&serde_json::json!(v)))
            || !(req.ttl > 0.0 && req.ttl <= MAX_TTL)
        {
            return Err(Error::rejected(400, "invalid reader grant"));
        }
        let hubdb = hub.database.connect()?;
        for s in req.sites {
            if !hubdb.query_row(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE org=? AND site=?)",
                [&s.org, &s.site],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(Error::rejected(400, "unknown site"));
            }
        }
        let has_v2 = !sources.is_empty() && query::has_v2(&hubdb)?;
        for source in &sources {
            // A source must already report for one of the granted sites, which also catches typos.
            let seen = has_v2
                && req.sites.iter().try_fold(false, |seen, s| -> Result<bool> {
                    Ok(seen
                        || hubdb.query_row(
                            "SELECT EXISTS(SELECT 1 FROM v2_authorities WHERE source=? AND json_extract(authority,'$[0]')=? AND json_extract(authority,'$[1]')=?)",
                            [source, &s.org, &s.site],
                            |r| r.get::<_, bool>(0),
                        )?)
                })?;
            if !seen {
                return Err(Error::rejected(400, "unknown source"));
            }
        }
        for device in devices {
            let home: Option<(String, String)> = hubdb
                .query_row("SELECT org,site FROM devices WHERE id=?", [device], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let granted = home.is_some_and(|(org, site)| req.sites.contains(&Site { org, site }));
            if !granted {
                return Err(Error::rejected(400, "device is not in a granted site"));
            }
        }
        // The ingest secret of a device or a pending invite must not also be a reader secret.
        let plain = crate::link::storage::verifier(secret)?;
        for table in ["credentials", "invites"] {
            if hubdb.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE verifier=?)"),
                [&plain],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(Error::rejected(
                    400,
                    "credential is already an ingest credential",
                ));
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        // Only now, with the request checked, is a store created if there is none.
        let store = Self::create(&hub.database.path)?;
        let mut db = store.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let at = now();
        tx.execute(
            "INSERT INTO readers(id,label,verifier,created,expires,device_mode,source_mode) VALUES(?,?,?,?,?,?,?)",
            params![
                id,
                req.label,
                verifier,
                at,
                at + req.ttl,
                if devices.is_empty() { "all" } else { "listed" },
                if sources.is_empty() { "all" } else { "listed" }
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                Error::rejected(400, "reader credential already in use")
            }
            other => other.into(),
        })?;
        for s in req.sites {
            tx.execute(
                "INSERT OR IGNORE INTO reader_sites VALUES(?,?,?)",
                params![id, s.org, s.site],
            )?;
        }
        for device in devices {
            tx.execute(
                "INSERT OR IGNORE INTO reader_devices VALUES(?,?)",
                params![id, device],
            )?;
        }
        for source in &sources {
            tx.execute(
                "INSERT OR IGNORE INTO reader_sources VALUES(?,?)",
                params![id, source],
            )?;
        }
        tx.execute(
            "INSERT INTO reader_audit VALUES(?,?,'grant')",
            params![at, id],
        )?;
        tx.commit()?;
        Ok(id)
    }
    pub fn revoke(&self, reader: &str) -> Result<()> {
        let mut db = self.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.execute("UPDATE readers SET revoked=1 WHERE id=?", [reader])? == 0 {
            return Err(Error::rejected(404, "no such reader"));
        }
        tx.execute(
            "INSERT INTO reader_audit VALUES(?,?,'revoke')",
            params![now(), reader],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Resolve a reader credential to its scope, rechecking expiry and revocation now.
    pub fn authorize(&self, secret: &str) -> Result<AuthorizedScope> {
        self.authorize_with_clock(secret, now)
    }
    /// Exercise expiry through the authorization path without waiting on the host clock.
    #[doc(hidden)]
    pub fn authorize_with_clock(
        &self,
        secret: &str,
        clock: impl FnOnce() -> f64,
    ) -> Result<AuthorizedScope> {
        let db = self.connect()?;
        let (reader, mode, source_mode): (String, String, String) = db
            .query_row(
                "SELECT id,device_mode,source_mode FROM readers WHERE verifier=? AND revoked=0 AND expires>?",
                params![verifier(secret)?, clock()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or_else(unauthorized)?;
        let sites = db
            .prepare("SELECT org,site FROM reader_sites WHERE reader=?")?
            .query_map([&reader], |r| {
                Ok(Site {
                    org: r.get(0)?,
                    site: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<_, _>>()?;
        let devices: BTreeSet<String> = db
            .prepare("SELECT device FROM reader_devices WHERE reader=?")?
            .query_map([&reader], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let sources: BTreeSet<String> = db
            .prepare("SELECT source FROM reader_sources WHERE reader=?")?
            .query_map([&reader], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(AuthorizedScope {
            store: self.path.clone(),
            sites,
            devices: (mode == "listed").then_some(devices),
            sources: (source_mode == "listed").then_some(sources),
            reader,
        })
    }
}
