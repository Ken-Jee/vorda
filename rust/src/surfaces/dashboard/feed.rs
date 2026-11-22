use crate::{
    scanner::{feeds::KEV, input},
    store::identity,
    Result,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

/// Public records stay general; private matching uses only the selected saved findings.
pub fn saved(
    state: &Path,
    now: f64,
    matches: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Value> {
    let path = state
        .join("cache")
        .join(format!("{}.json", identity(&json!([KEV, null]))?));
    let cached = input::read_regular(&path, None, 128_000_000, false)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let Some(cached) = cached else {
        return Ok(json!({"status":"unavailable","source_url":KEV,"items":[]}));
    };
    let Some(rows) = cached["data"]["vulnerabilities"].as_array() else {
        return Ok(json!({"status":"invalid","source_url":KEV,"items":[]}));
    };
    let checked = cached["checked"]
        .as_f64()
        .filter(|n| *n <= now && *n >= 0.0);
    let stale = checked.is_none_or(|n| now - n > 86400.0);
    let mut rows = rows
        .iter()
        .filter(|r| r["cveID"].as_str().is_some())
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        b["dateAdded"]
            .as_str()
            .cmp(&a["dateAdded"].as_str())
            .then_with(|| a["cveID"].as_str().cmp(&b["cveID"].as_str()))
    });
    let items=rows.into_iter().take(100).map(|r|{
        let id=r["cveID"].as_str().unwrap();let hosts=matches.get(id).cloned().unwrap_or_default();
        json!({"advisory":id,"text":r["vulnerabilityName"],"published":r["dateAdded"],"at":r["dateAdded"].as_str().and_then(|d|super::data::iso(&format!("{d}T00:00:00Z"))),"fetched_at":checked,"url":format!("https://nvd.nist.gov/vuln/detail/{id}"),"source_url":KEV,"source":"CISA KEV","hosts":hosts,"mine":!hosts.is_empty(),"applicability":if hosts.is_empty(){"no-saved-local-match"}else{"linked-saved-finding"},"stale":stale,"kev":true,"fixed":false,"type":"public-update","name":r["product"]})
    }).collect::<Vec<_>>();
    Ok(
        json!({"status":if stale{"stale"}else{"available"},"source_url":KEV,"fetched_at":checked,"limit":100,"coverage":"CISA KEV catalog only; not all security news","items":items}),
    )
}
