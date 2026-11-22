//! Which sources an enrolled device's credential may capture for, set by the hub operator.
//!
//! The grants live in `<hub>.capture-grants` beside the hub, handled like `<hub>.readers`: private
//! to its owner, bound to the hub's identity, and refused (never misread) when it is of another
//! version. The hub schema and its migrate/restore story stay as they are. A grant names a device
//! and a source; the device's credential, generation and binding are still checked at admission,
//! so revoking the device or changing its generation ends the trust without touching this file.
use super::text;
use crate::fleet::auth::ReaderStore;
use crate::store::private_dir;
use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SCHEMA: &str = "
CREATE TABLE grants(device TEXT NOT NULL,source TEXT NOT NULL,PRIMARY KEY(device,source));
CREATE TABLE store_meta(hub TEXT NOT NULL);";
/// The layout of the grant file. A file of another version is refused with an error that names it.
const STORE_VERSION: i64 = 1;

pub struct CaptureGrants {
    path: PathBuf,
    hub: PathBuf,
}
fn unreadable(path: &Path, why: impl Into<Error>) -> Error {
    let why = why.into();
    Error {
        busy: why.busy,
        ..Error::new(format!(
            "capture grants {} are unreadable ({}): repair or remove the file",
            path.display(),
            why.message
        ))
    }
}
impl CaptureGrants {
    fn side(hub: &Path) -> PathBuf {
        let mut name = hub.as_os_str().to_os_string();
        name.push(".capture-grants");
        name.into()
    }
    fn connect(path: &Path) -> Result<Connection> {
        #[cfg(unix)]
        {
            // Whatever the file's history, it is private on every connection.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_millis(200))?;
        db.pragma_update(None, "synchronous", "FULL")?;
        Ok(db)
    }
    /// The grants of the hub at `hub`, checked once when `link serve` starts: a file of another
    /// version or of another hub is an error. No file means nothing is granted.
    pub fn open(hub: &Path) -> Result<Self> {
        let store = Self {
            path: Self::side(hub),
            hub: hub.to_path_buf(),
        };
        if store.path.is_file() {
            store.checked(hub)?;
        }
        Ok(store)
    }
    fn checked(&self, hub: &Path) -> Result<Connection> {
        let db = Self::connect(&self.path).map_err(|e| unreadable(&self.path, e))?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| unreadable(&self.path, e))?;
        if version != STORE_VERSION {
            return Err(Error::new(format!(
                "capture grants {} have version {version}, this build needs {STORE_VERSION}: remove the file and grant again",
                self.path.display()
            )));
        }
        let bound: Option<String> = db
            .query_row("SELECT hub FROM store_meta", [], |r| r.get(0))
            .optional()
            .map_err(|e| unreadable(&self.path, e))?;
        if bound.is_none() || bound != ReaderStore::hub_identity(hub)? {
            return Err(Error::new(format!(
                "capture grants {} belong to a different hub: remove the file and grant again",
                self.path.display()
            )));
        }
        Ok(db)
    }
    fn valid(value: &str) -> bool {
        text(&serde_json::json!(value))
    }
    /// Operator side: let `device`'s credential capture for `source`. The device must be enrolled.
    pub fn allow(hub: &Path, device: &str, source: &str) -> Result<()> {
        if !Self::valid(device) || !Self::valid(source) {
            return Err(Error::rejected(400, "invalid capture grant"));
        }
        let identity = ReaderStore::hub_identity(hub)?
            .ok_or_else(|| Error::rejected(400, "the hub has no enrolled devices yet"))?;
        let enrolled = Connection::open_with_flags(hub, OpenFlags::SQLITE_OPEN_READ_ONLY)?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?)",
                [device],
                |r| r.get::<_, bool>(0),
            )?;
        if !enrolled {
            return Err(Error::rejected(400, "unknown device"));
        }
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
        let store = Self {
            path,
            hub: hub.to_path_buf(),
        };
        let mut db = Self::connect(&store.path)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Created but never filled in (a crash during the first grant): version 0 holds nothing.
        if tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? == 0 {
            tx.execute_batch(SCHEMA)?;
            tx.execute("INSERT INTO store_meta VALUES(?)", [&identity])?;
            tx.pragma_update(None, "user_version", STORE_VERSION)?;
        }
        tx.commit()?;
        drop(db);
        let db = store.checked(hub)?;
        db.execute(
            "INSERT OR IGNORE INTO grants(device,source) VALUES(?,?)",
            [device, source],
        )?;
        Ok(())
    }
    /// Operator side: end the trust. Denying what was never granted is not an error.
    pub fn deny(hub: &Path, device: &str, source: &str) -> Result<()> {
        let store = Self {
            path: Self::side(hub),
            hub: hub.to_path_buf(),
        };
        if !store.path.is_file() {
            return Ok(());
        }
        store.checked(hub)?.execute(
            "DELETE FROM grants WHERE device=? AND source=?",
            [device, source],
        )?;
        Ok(())
    }
    /// Whether `device` may capture for `source` right now. The file is read for every call, so a
    /// grant or a denial applies to the next post of a serving hub.
    pub(crate) fn allows(&self, device: &str, source: &str) -> Result<bool> {
        if !self.path.is_file() {
            return Ok(false);
        }
        let db = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| unreadable(&self.path, e))?;
        db.busy_timeout(Duration::from_millis(200))?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| unreadable(&self.path, e))?;
        if version != STORE_VERSION {
            return Err(unreadable(&self.path, Error::new("wrong version")));
        }
        let bound: Option<String> = db
            .query_row("SELECT hub FROM store_meta", [], |r| r.get(0))
            .optional()
            .map_err(|e| unreadable(&self.path, e))?;
        if bound.is_none() || bound != ReaderStore::hub_identity(&self.hub)? {
            return Err(unreadable(&self.path, Error::new("another hub's file")));
        }
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM grants WHERE device=? AND source=?)",
            [device, source],
            |r| r.get(0),
        )
        .map_err(|e| unreadable(&self.path, e))
    }
}
