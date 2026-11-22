use crate::{store::Store, Result};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};
pub fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&c))
    {
        s.into()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}
fn release(s: &str) -> Option<Vec<String>> {
    let s = s.strip_prefix('v').unwrap_or(s);
    if !regex::Regex::new(r"^[0-9]+(?:\.[0-9]+){1,3}$")
        .unwrap()
        .is_match(s)
    {
        return None;
    }
    let mut parts: Vec<_> = s
        .split('.')
        .map(|s| {
            let s = s.trim_start_matches('0');
            if s.is_empty() {
                "0".into()
            } else {
                s.into()
            }
        })
        .collect();
    parts.resize(4, "0".into());
    Some(parts)
}
fn cmp(a: &[String], b: &[String]) -> std::cmp::Ordering {
    for (a, b) in a.iter().zip(b) {
        let c = a.len().cmp(&b.len()).then(a.cmp(b));
        if c.is_ne() {
            return c;
        }
    }
    std::cmp::Ordering::Equal
}
fn safe(version: &str, ranges: &[Value]) -> bool {
    let Some(candidate) = release(version) else {
        return false;
    };
    if ranges.is_empty() {
        return false;
    }
    for range in ranges {
        if ![json!("SEMVER"), json!("ECOSYSTEM")].contains(&range["type"]) {
            return false;
        }
        let Some(events) = range["events"].as_array().filter(|a| !a.is_empty()) else {
            return false;
        };
        let mut vulnerable = false;
        for event in events {
            let Some(map) = event.as_object().filter(|o| o.len() == 1) else {
                return false;
            };
            let (kind, value) = map.iter().next().unwrap();
            let Some(value) = value.as_str() else {
                return false;
            };
            let boundary = if value == "0" {
                Some(vec!["0".into(); 4])
            } else {
                release(value.strip_suffix("-0").unwrap_or(value))
            };
            let Some(boundary) = boundary else {
                return false;
            };
            let order = cmp(&candidate, &boundary);
            match kind.as_str() {
                "introduced" => {
                    if order.is_ge() {
                        vulnerable = true;
                    }
                }
                "fixed" | "limit" => {
                    if order.is_ge() {
                        vulnerable = false;
                    }
                }
                "last_affected" => {
                    if order.is_gt() {
                        vulnerable = false;
                    }
                }
                _ => return false,
            }
        }
        if vulnerable {
            return false;
        }
    }
    true
}
fn strings(v: &Value) -> Vec<String> {
    if let Some(s) = v.as_str() {
        vec![s.into()]
    } else {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect()
    }
}
pub fn fix_commands(store: &Store) -> Result<Value> {
    let mut groups: BTreeMap<String, Value> = BTreeMap::new();
    let mut statement = store
        .db
        .prepare("SELECT payload FROM findings WHERE active=1")?;
    for row in statement.query_map([], |r| r.get::<_, String>(0))? {
        let f: Value = serde_json::from_str(&row?)?;
        if !f["package"].is_object() {
            continue;
        }
        let key = f["asset"].as_str().unwrap_or("").to_string();
        let fixed = strings(&f["fixed"]);
        let ranges = f["affected_ranges"]
            .as_array()
            .filter(|a| !a.is_empty())
            .cloned()
            .unwrap_or(vec![json!({})]);
        if let Some(group) = groups.get_mut(&key) {
            let mut versions = strings(&group["fixed"]);
            versions.extend(fixed);
            versions.sort();
            versions.dedup();
            group["fixed"] = json!(versions);
            group["affected_ranges"]
                .as_array_mut()
                .unwrap()
                .extend(ranges);
        } else {
            let mut f = f;
            f["fixed"] = json!(fixed);
            f["affected_ranges"] = json!(ranges);
            groups.insert(key, f);
        }
    }
    let mut out = vec![];
    for mut finding in groups.into_values() {
        let p = finding["package"].clone();
        if finding["detail_status"] == "deferred" && strings(&finding["fixed"]).is_empty() {
            let urls = strings(&finding["source_url"]);
            if let Some(url) = urls.first() {
                let fetch = (|| -> crate::Result<Value> {
                    use std::io::Read;
                    let client = reqwest::blocking::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(std::time::Duration::from_secs(20))
                        .min_tls_version(reqwest::tls::Version::TLS_1_2)
                        .build()
                        .map_err(|e| crate::Error::new(e.to_string()))?;
                    let response = client
                        .get(url)
                        .send()
                        .and_then(|r| r.error_for_status())
                        .map_err(|e| crate::Error::new(e.to_string()))?;
                    let mut body = String::new();
                    response.take(8_000_001).read_to_string(&mut body)?;
                    if body.len() > 8_000_000 {
                        return Err(crate::Error::new("advisory exceeds limit"));
                    }
                    Ok(serde_json::from_str(&body)?)
                })();
                if let Ok(record) = fetch {
                    let source = p.get("source_name").unwrap_or(&p["name"]);
                    let mut versions = vec![];
                    for affected in record["affected"].as_array().into_iter().flatten() {
                        if affected["package"]["name"] == *source
                            && affected["package"]["ecosystem"] == p["ecosystem"]
                        {
                            for range in affected["ranges"].as_array().into_iter().flatten() {
                                if [json!("SEMVER"), json!("ECOSYSTEM")].contains(&range["type"]) {
                                    for event in range["events"].as_array().into_iter().flatten() {
                                        if let Some(fixed) = event["fixed"].as_str() {
                                            versions.push(fixed.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    versions.sort();
                    versions.dedup();
                    finding["fixed"] = json!(versions);
                }
            }
        }
        let versions: Vec<_> = strings(&finding["fixed"])
            .into_iter()
            .filter(|v| !v.is_empty() && v != "unknown")
            .collect();
        let installed = p["version"].as_str().and_then(release);
        let mut candidates: Vec<_> = versions
            .iter()
            .filter(|v| {
                installed
                    .as_ref()
                    .is_some_and(|i| release(v).is_some_and(|v| cmp(&v, i).is_gt()))
                    && safe(v, finding["affected_ranges"].as_array().unwrap())
            })
            .cloned()
            .collect();
        candidates.sort_by(|a, b| cmp(&release(a).unwrap(), &release(b).unwrap()));
        let mut version = candidates.first().cloned();
        let eco = p["ecosystem"].as_str().unwrap_or("");
        let name = p["name"].as_str().unwrap_or("");
        let path = p["path"].as_str().unwrap_or("");
        if eco == "Go" {
            version = version.map(|s| format!("v{}", s.trim_start_matches('v')));
        }
        let n = quote(name);
        let root = Path::new(path).parent().unwrap_or(Path::new("."));
        let prefix = format!("cd {} && ", quote(&root.to_string_lossy()));
        let file = Path::new(path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let target = quote(&format!(
            "{name}@{}",
            version.as_deref().unwrap_or("latest")
        ));
        let mut command = match eco {
            "npm" => Some(format!(
                "{prefix}{}{target}",
                match file.as_ref() {
                    "pnpm-lock.yaml" => "pnpm add ",
                    "yarn.lock" => "yarn add ",
                    f if f.starts_with("bun.lock") => "bun add ",
                    _ => "npm install ",
                }
            )),
            "PyPI" => Some(format!(
                "{prefix}{}{}",
                match file.as_ref() {
                    "uv.lock" => "uv add ",
                    "poetry.lock" => "poetry add ",
                    "Pipfile.lock" => "pipenv install ",
                    _ => "python -m pip install --upgrade ",
                },
                quote(&format!(
                    "{name}{}",
                    version
                        .as_ref()
                        .map(|s| format!("=={s}"))
                        .unwrap_or_default()
                ))
            )),
            e if e.starts_with("Debian") || e.starts_with("Ubuntu") => {
                Some(format!("sudo apt-get install --only-upgrade {n}"))
            }
            "Arch Linux" => Some("sudo pacman -Syu".into()),
            "Chromium" => Some("vorda fix --chromium --dry-run".into()),
            "crates.io" => Some(format!(
                "{prefix}cargo update -p {n}{}",
                version
                    .as_ref()
                    .map(|s| format!(" --precise {}", quote(s)))
                    .unwrap_or_default()
            )),
            // The standard library ships with the toolchain; `go get` cannot move it alone.
            "Go" if name == "stdlib" => Some(format!(
                "{prefix}go get {}",
                quote(&version.as_ref().map_or("go@latest".into(), |v| format!(
                    "toolchain@go{}",
                    v.trim_start_matches('v')
                )))
            )),
            "Go" => Some(format!("{prefix}go get {target}")),
            "RubyGems" => Some(format!("{prefix}bundle update {n}")),
            "Packagist" => Some(format!(
                "{prefix}composer update {n} --with-all-dependencies"
            )),
            _ => None,
        };
        let verification = if path.starts_with("tool:") {
            command = None;
            format!(
                "Upgrade {name}{} using its own installer or updater, then recheck",
                version
                    .as_ref()
                    .map(|v| format!(" to at least {v}"))
                    .unwrap_or_else(|| "; a safe target version is unknown".into())
            )
        } else {
            "Recheck after updating; resolver constraints or unreleased fixes can prevent remediation".into()
        };
        out.push(json!({"package":p,"command":command,"fixed":versions,"verification":verification,"detail_status":finding.get("detail_status").unwrap_or(&json!("complete"))}));
    }
    Ok(json!(out))
}
