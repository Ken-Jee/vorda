use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::PathBuf;

pub type Record = Map<String, Value>;

pub const CATEGORIES: [&str; 3] = ["Environments", "Applications", "Developer Tools"];

pub fn integer(text: &str) -> crate::Result<serde_json::Number> {
    let text = text.trim();
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || !digits.bytes().enumerate().all(|(i, c)| {
            c.is_ascii_digit()
                || c == b'_'
                    && i > 0
                    && i + 1 < digits.len()
                    && digits.as_bytes()[i - 1].is_ascii_digit()
                    && digits.as_bytes()[i + 1].is_ascii_digit()
        })
    {
        return Err(crate::Error::new("integer required"));
    }
    let digits = digits.replace('_', "");
    let digits = digits.trim_start_matches('0');
    let normalized = if digits.is_empty() {
        "0".into()
    } else {
        format!("{}{digits}", if negative { "-" } else { "" })
    };
    normalized
        .parse()
        .map_err(|_| crate::Error::new("integer required"))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub path: String,
    pub scope: String,
    #[serde(flatten)]
    pub extra: Record,
}

#[derive(Clone, Debug, Default)]
pub struct InventoryOptions {
    pub roots: Vec<PathBuf>,
    pub os_packages: bool,
    pub tools: bool,
    pub browsers: bool,
    pub installed_apps: bool,
    pub installed_roots: Vec<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub scheduled: bool,
    pub oci: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct ScanOptions {
    pub inventory: InventoryOptions,
    pub offline: bool,
    /// Answer advisory queries from the local database; None follows the configured default.
    pub offline_db: Option<bool>,
    pub inventory_file: Option<PathBuf>,
    pub mcp_scope: bool,
    pub webhook: Option<String>,
    pub ntfy: Option<String>,
    pub desktop: bool,
}
