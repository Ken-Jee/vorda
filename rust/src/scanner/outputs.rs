use crate::domain::Package;
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::Path};

pub fn quote(s: &str, slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || slash && b == b'/' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
pub fn purl(p: &Package) -> String {
    let base = p.ecosystem.split(':').next().unwrap_or("");
    let kind = match base {
        "PyPI" => "pypi",
        "npm" => "npm",
        "crates.io" => "cargo",
        "Go" => "golang",
        "RubyGems" => "gem",
        "Packagist" => "composer",
        "Debian" | "Ubuntu" => "deb",
        "Alpine" => "apk",
        "Arch Linux" => "alpm",
        "Rocky Linux" | "AlmaLinux" | "RPM" => "rpm",
        "Homebrew" => "brew",
        _ => "generic",
    };
    let mut name = p.name.clone();
    if kind == "pypi" {
        name = regex::Regex::new("[-_.]+")
            .unwrap()
            .replace_all(&name.to_lowercase(), "-")
            .into_owned();
    }
    if ["deb", "apk", "alpm", "rpm"].contains(&kind) {
        name = format!("{}/{}", base.to_lowercase().replace(" linux", ""), name);
    }
    format!(
        "pkg:{kind}/{}@{}",
        quote(&name, true),
        quote(&p.version, false)
    )
}
fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub fn timestamp() -> String {
    timestamp_at(super::now())
}
pub fn timestamp_at(seconds: f64) -> String {
    let seconds = seconds as i64;
    let days = seconds / 86400;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    if m <= 2 {
        y += 1;
    }
    let t = seconds % 86400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        t / 3600,
        t % 3600 / 60,
        t % 60
    )
}
pub fn cyclonedx(packages: &[Package]) -> Value {
    json!({"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"serialNumber":format!("urn:uuid:{}",uuid()),"components":packages.iter().enumerate().map(|(i,p)|json!({"type":"library","name":p.name,"version":p.version,"bom-ref":format!("component-{i}"),"purl":purl(p)})).collect::<Vec<_>>()})
}
pub fn spdx(packages: &[Package]) -> Value {
    json!({"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"vorda inventory","documentNamespace":format!("https://spdx.org/spdxdocs/vorda-{}",uuid()),"creationInfo":{"creators":["Tool: vorda"],"created":timestamp()},"packages":packages.iter().enumerate().map(|(i,p)|json!({"SPDXID":format!("SPDXRef-Package-{i}"),"name":p.name,"versionInfo":p.version,"downloadLocation":"NOASSERTION","filesAnalyzed":false,"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":purl(p)}]})).collect::<Vec<_>>(),"relationships":(0..packages.len()).map(|i|json!({"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":format!("SPDXRef-Package-{i}")})).collect::<Vec<_>>()})
}
pub fn sarif(result: &Value) -> Value {
    let mut results = Vec::new();
    let mut ids = BTreeSet::new();
    for finding in super::array(&result["findings"]) {
        let evidence = finding
            .get("audit")
            .and_then(|a| a.get("finding"))
            .unwrap_or(finding);
        let aliases = super::array(&evidence["aliases"]);
        let rule = evidence["advisory"]
            .as_str()
            .or_else(|| {
                aliases
                    .iter()
                    .filter_map(Value::as_str)
                    .find(|a| a.starts_with("CVE-"))
            })
            .or_else(|| aliases.first().and_then(Value::as_str))
            .unwrap_or("vorda/coverage");
        ids.insert(rule.to_string());
        let mut row = json!({"ruleId":rule,"message":{"text":finding["title"]}});
        if finding["kind"] == "health" {
            row["level"] = json!("warning");
            row["properties"] = json!({"coverage":"uncertain","reason":finding["audit"].get("reason").cloned().unwrap_or(json!("Coverage unavailable"))});
        }
        if let Some(c) = evidence.get("confidence") {
            if !row["properties"].is_object() {
                row["properties"] = json!({});
            }
            row["properties"]["confidence"] = c.clone();
        }
        if let Some(path) = evidence["package"]["path"].as_str() {
            row["locations"] = if Path::new(path).is_absolute() {
                json!([{"physicalLocation":{"artifactLocation":{"uri":url::Url::from_file_path(path).map(|u|u.to_string()).unwrap_or_else(|_|format!("file://{}",quote(path,true)))}}}])
            } else {
                json!([{"logicalLocations":[{"fullyQualifiedName":path}]}])
            };
        }
        results.push(row);
    }
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"vorda","rules":ids.into_iter().map(|id|json!({"id":id})).collect::<Vec<_>>()}},"results":results}]})
}
pub fn syft_packages(document: &Value, source: &str) -> crate::Result<Vec<Package>> {
    let mut out = Vec::new();
    for item in super::array(&document["artifacts"]) {
        let kind = super::string(item, "type");
        let ecosystem = match kind {
            "npm" => "npm".into(),
            "python" => "PyPI".into(),
            "rust-crate" => "crates.io".into(),
            "go-module" => "Go".into(),
            "gem" => "RubyGems".into(),
            "php-composer" => "Packagist".into(),
            _ => {
                let distro = &document["distro"];
                let id = super::string(distro, "id");
                if ["deb", "apk"].contains(&kind) && ["debian", "ubuntu", "alpine"].contains(&id) {
                    super::distro::ecosystem(
                        &format!(
                            "ID={id}\nVERSION_ID={}",
                            distro
                                .get("versionID")
                                .or_else(|| distro.get("version"))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                        ),
                        distro
                            .get("versionID")
                            .or_else(|| distro.get("version"))
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    )
                } else {
                    format!(
                        "Unmapped:{}",
                        if kind.is_empty() { "unknown" } else { kind }
                    )
                }
            }
        };
        let name = item["name"]
            .as_str()
            .ok_or_else(|| super::error("artifact is missing a name"))?;
        let mut p = super::package(
            name,
            super::string(item, "version"),
            &ecosystem,
            source,
            false,
            "image",
        );
        p.scope = "reachable-unknown".into();
        for (key, field) in if kind == "apk" {
            vec![("originPackage", "source_name")]
        } else if kind == "deb" {
            vec![
                ("source", "source_name"),
                ("sourceVersion", "source_version"),
            ]
        } else {
            vec![]
        } {
            if let Some(v) = item["metadata"].get(key) {
                p.extra.insert(field.into(), v.clone());
            }
        }
        out.push(p);
    }
    Ok(out)
}
