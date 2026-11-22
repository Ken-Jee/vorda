use crate::Result;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn cvss(vector: &str) -> Result<f64> {
    if !vector.starts_with("CVSS:3.0/") && !vector.starts_with("CVSS:3.1/") {
        return Err(super::error("a CVSS 3 vector is required"));
    }
    let fields: BTreeMap<_, _> = vector
        .split('/')
        .skip(1)
        .filter_map(|s| s.split_once(':'))
        .collect();
    let get = |key: &str, values: &[(&str, f64)]| -> Result<f64> {
        let v = fields
            .get(key)
            .ok_or_else(|| super::error("missing CVSS field"))?;
        values
            .iter()
            .find(|(k, _)| k == v)
            .map(|(_, v)| *v)
            .ok_or_else(|| super::error("invalid CVSS field"))
    };
    let mut remaining = 1.0;
    for k in ["C", "I", "A"] {
        remaining *= 1.0 - get(k, &[("H", 0.56), ("L", 0.22), ("N", 0.0)])?;
    }
    let impact = 1.0 - remaining;
    let changed = fields.get("S") == Some(&"C");
    let impact = if changed {
        7.52 * (impact - 0.029) - 3.25 * (impact - 0.02).powi(15)
    } else {
        6.42 * impact
    };
    let exploit = 8.22
        * get("AV", &[("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2)])?
        * get("AC", &[("L", 0.77), ("H", 0.44)])?
        * get(
            "PR",
            &[
                ("N", 0.85),
                ("L", if changed { 0.68 } else { 0.62 }),
                ("H", if changed { 0.5 } else { 0.27 }),
            ],
        )?
        * get("UI", &[("N", 0.85), ("R", 0.62)])?;
    Ok(if impact > 0.0 {
        (((impact + exploit) * if changed { 1.08 } else { 1.0 }).min(10.0) * 10.0 - 1e-8).ceil()
            / 10.0
    } else {
        0.0
    })
}
/// A CVSS 4.0 base score; malformed or incomplete vectors are refused. Threat, environmental
/// and supplemental metrics are dropped, so the score is the base score the docs promise.
pub fn cvss4(vector: &str) -> Result<f64> {
    // Threat, environmental and supplemental metric names; any other part is kept, so a
    // junk part still makes the vector invalid.
    const OTHER: &[&str] = &[
        "E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC",
        "MSI", "MSA", "S", "AU", "R", "V", "RE", "U",
    ];
    vector
        .split('/')
        .filter(|part| {
            !part
                .split_once(':')
                .is_some_and(|(key, _)| OTHER.contains(&key))
        })
        .collect::<Vec<_>>()
        .join("/")
        .parse::<cvss::v4::Vector>()
        .map(|v| v.score().value())
        .map_err(|_| super::error("invalid CVSS 4 vector"))
}

pub fn priority(f: &Value) -> Value {
    let scores = |score: fn(&str) -> Result<f64>| {
        super::array(&f["severity"])
            .iter()
            .filter_map(|s| score(super::string(s, "score")).ok())
            .reduce(f64::max)
    };
    let (v3, v4) = (scores(cvss), scores(cvss4));
    // The higher of the two versions, so a second vector can only raise the priority.
    let score = match (v3, v4) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    // The advisory's own label (GitHub's CRITICAL/HIGH/MODERATE/LOW) when it has no score.
    let label = match super::string(f, "advisory_severity") {
        "CRITICAL" => Some("critical"),
        "HIGH" => Some("high"),
        "MODERATE" | "MEDIUM" => Some("medium"),
        "LOW" => Some("low"),
        _ => None,
    };
    // Canonical's own priority word, used when the record carries no CVSS vector.
    let distro = super::array(&f["severity"])
        .iter()
        .find(|s| s["type"] == "Ubuntu")
        .map(|s| match super::string(s, "score") {
            "negligible" => "low",
            s => s,
        });
    let epss = f["epss"].as_f64();
    let kev = f["kev"].as_bool().unwrap_or(false);
    let level = if kev || score.is_some_and(|v| v >= 9.0) {
        "critical"
    } else if score.is_some_and(|v| v >= 7.0) || epss.is_some_and(|v| v >= 0.5) {
        "high"
    } else if score.is_some_and(|v| v >= 4.0) {
        "medium"
    } else if score.is_some() {
        "low"
    } else {
        let s = distro.or(label).unwrap_or(super::string(f, "severity"));
        if ["critical", "high", "medium", "low"].contains(&s) {
            s
        } else {
            "unknown"
        }
    };
    let reason = if score.is_some() && score == v4 && v3 != v4 {
        "supported-cvss4"
    } else if score.is_some() {
        "supported-cvss3"
    } else if distro.is_some() {
        "distro-priority"
    } else if label.is_some() {
        "advisory-severity-label"
    } else if !super::array(&f["severity"]).is_empty() {
        "unsupported-or-invalid-severity-vector"
    } else {
        "no-supported-severity-score"
    };
    json!({"level":level,"cvss":score,"scoring_reason":reason,"severity_evidence":f.get("severity").unwrap_or(&Value::Null),"kev":f.get("kev").unwrap_or(&Value::Null),"epss":epss})
}
