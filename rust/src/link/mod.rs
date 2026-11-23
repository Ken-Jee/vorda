pub mod change_log;
pub mod client;
mod commands;
pub mod grants;
pub mod native;
mod native_http;
pub mod server;
pub mod storage;
pub use commands::run;

use crate::store::{now, python_json};
use crate::{Error, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MAX_BATCH: usize = 1024 * 1024;
pub const MAX_RECORDS: usize = 2000;

pub fn encode(value: &Value) -> Result<Vec<u8>> {
    Ok(python_json(value, true)?.into_bytes())
}
pub fn digest(value: &Value) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(encode(value)?)))
}
pub fn text(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.chars().count() <= 256 && !s.chars().any(|c| c < ' '))
}
pub fn exact_fields(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.len() == fields.len() && fields.iter().all(|k| m.contains_key(*k)))
}

pub fn validate(batch: &Value) -> Result<()> {
    if !exact_fields(
        batch,
        &[
            "schema",
            "device",
            "generation",
            "sequence",
            "scan",
            "observed",
            "scanner",
            "coverage",
            "findings",
        ],
    ) || batch["schema"].as_i64() != Some(1)
    {
        return Err(Error::rejected(400, "unsupported batch schema"));
    }
    if encode(batch)?.len() > MAX_BATCH {
        return Err(Error::rejected(413, "batch too large"));
    }
    if !["device", "generation", "scanner"]
        .iter()
        .all(|k| text(&batch[k]))
    {
        return Err(Error::rejected(400, "invalid identity"));
    }
    if !batch["scan"]
        .as_str()
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
    {
        return Err(Error::rejected(400, "invalid scan UUID"));
    }
    if !batch["sequence"].as_i64().is_some_and(|n| n > 0) {
        return Err(Error::rejected(400, "invalid sequence"));
    }
    if !batch["observed"]
        .as_f64()
        .is_some_and(|n| n.is_finite() && n >= 0.0 && n <= now() + 300.0)
    {
        return Err(Error::rejected(
            400,
            "observation time is invalid or in the future",
        ));
    }
    let coverage = batch["coverage"]
        .as_object()
        .filter(|c| {
            !c.is_empty()
                && c.len() <= 128
                && c.iter()
                    .all(|(k, v)| text(&json!(k)) && (v == "complete" || v == "partial"))
        })
        .ok_or_else(|| Error::rejected(400, "invalid coverage"))?;
    let findings = batch["findings"]
        .as_array()
        .filter(|f| f.len() <= MAX_RECORDS)
        .ok_or_else(|| Error::rejected(400, "too many findings"))?;
    let mut keys = HashSet::new();
    for f in findings {
        if !exact_fields(
            f,
            &[
                "key",
                "scope",
                "ecosystem",
                "name",
                "version",
                "location",
                "advisory",
                "source",
            ],
        ) || !f.as_object().unwrap().values().all(text)
            || !coverage.contains_key(f["scope"].as_str().unwrap_or(""))
            || !keys.insert(f["key"].as_str())
        {
            return Err(Error::rejected(400, "invalid finding"));
        }
        if !f["location"].as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(Error::rejected(400, "location must be an opaque digest"));
        }
    }
    Ok(())
}

/// The scan's own observation time. A result file's modification time is never used: copying or touching
/// a file must not make an old scan look new.
fn observation_time(result: &Value) -> Result<f64> {
    let observed = result["inventory_observed_at"]
        .as_f64()
        .filter(|t| t.is_finite() && *t > 0.0)
        .ok_or_else(|| Error::instruction("this result has no observation time; scan again"))?;
    if observed > now() + 300.0 {
        return Err(Error::instruction(
            "this result's observation time is in the future; check the clock and scan again",
        ));
    }
    Ok(observed)
}

pub fn export_result(
    result: &Value,
    device: &str,
    generation: &str,
    deny_packages: &[String],
) -> Result<Value> {
    let observed = observation_time(result)?;
    let scope = result["scan_scope"]
        .as_str()
        .ok_or_else(|| Error::new("scan_scope required"))?;
    let mut findings = Vec::new();
    let mut omitted = false;
    for f in result["findings"]
        .as_array()
        .ok_or_else(|| Error::new("findings required"))?
    {
        if f["kind"] == "health" {
            omitted = true;
            continue;
        }
        let p = &f["package"];
        if deny_packages.iter().any(|n| p["name"] == n.as_str()) {
            continue;
        }
        let urls: Vec<&str> = if let Some(s) = f["source_url"].as_str() {
            vec![s]
        } else {
            f["source_url"]
                .as_array()
                .ok_or_else(|| Error::new("source_url required"))?
                .iter()
                .map(|u| u.as_str().ok_or_else(|| Error::new("invalid source URL")))
                .collect::<Result<_>>()?
        };
        let hosts: std::collections::BTreeSet<String> = urls
            .iter()
            .map(|u| {
                url::Url::parse(u)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                    .unwrap_or_else(|| "unknown".into())
            })
            .collect();
        findings.push(json!({"key":digest(&json!([scope,f["key"]]))?,"scope":scope,"ecosystem":p["ecosystem"],"name":p["name"],"version":p["version"],"location":digest(&p["path"])?,"advisory":f["advisory"],"source":hosts.into_iter().collect::<Vec<_>>().join(",")}));
    }
    let complete = result["coverage_evidence"]["status"] == "complete"
        && !omitted
        && deny_packages.is_empty()
        && !result
            .get("errors")
            .is_some_and(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        && ["vulnerable", "no-known-findings"]
            .iter()
            .any(|s| result["status"] == *s);
    let mut coverage = serde_json::Map::new();
    coverage.insert(
        scope.into(),
        json!(if complete { "complete" } else { "partial" }),
    );
    Ok(
        json!({"schema":1,"device":device,"generation":generation,"sequence":1,"scan":uuid::Uuid::new_v4().to_string(),"observed":observed,"scanner":concat!("vorda/", env!("CARGO_PKG_VERSION")),"coverage":coverage,"findings":findings}),
    )
}
