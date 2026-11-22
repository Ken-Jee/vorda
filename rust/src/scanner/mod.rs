use crate::domain::{InventoryOptions, Package, Record};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::path::Path;

pub mod agentbom;
pub mod browsers;
pub mod container;
pub mod cpe;
pub mod distro;
pub mod feeds;
pub mod input;
pub mod inventory;
pub mod osvdb;
pub mod outputs;
pub mod priority;
pub mod versions;

pub fn inventory(options: &InventoryOptions) -> Result<Record> {
    inventory::collect(options)
}

pub fn scan(packages: &[Package], cache: &Path, offline: bool) -> Result<Record> {
    feeds::scan(packages, &mut feeds::Fetch::new(cache, offline))
}

pub(crate) fn error(message: impl ToString) -> Error {
    Error {
        message: message.to_string(),
        class: "ValueError".into(),
        http_status: None,
        usage: false,
        busy: false,
    }
}
pub(crate) fn record(value: Value) -> Record {
    value.as_object().cloned().unwrap_or_default()
}
pub(crate) fn string<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
pub(crate) fn array(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}
pub(crate) fn package(
    name: &str,
    version: &str,
    ecosystem: &str,
    path: &str,
    dev: bool,
    origin: &str,
) -> Package {
    Package {
        name: name.into(),
        version: version.into(),
        ecosystem: ecosystem.into(),
        path: path.into(),
        scope: if dev {
            "likely-dev-only"
        } else {
            "reachable-unknown"
        }
        .into(),
        extra: record(json!({"origin":origin})),
    }
}
pub(crate) fn source_name(p: &Package) -> &str {
    p.extra
        .get("source_name")
        .and_then(Value::as_str)
        .unwrap_or(&p.name)
}
pub(crate) fn source_version(p: &Package) -> &str {
    p.extra
        .get("source_version")
        .and_then(Value::as_str)
        .unwrap_or(&p.version)
}
pub(crate) fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests;
