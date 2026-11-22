use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "unrated"];
pub fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
pub fn a<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}
pub fn number(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(Value::as_f64).unwrap_or(0.)
}
pub fn cvss3(vector: &str) -> f64 {
    let m: BTreeMap<_, _> = vector
        .split('/')
        .skip(1)
        .filter_map(|p| p.split_once(':'))
        .collect();
    let result = (|| -> Option<f64> {
        let changed = *m.get("S")? == "C";
        let get = |key: &str, values: &[(&str, f64)]| -> Option<f64> {
            let value = m.get(key)?;
            values.iter().find(|(k, _)| k == value).map(|(_, v)| *v)
        };
        let pr = get(
            "PR",
            &[
                ("N", 0.85),
                ("L", if changed { 0.68 } else { 0.62 }),
                ("H", if changed { 0.5 } else { 0.27 }),
            ],
        )?;
        let mut iss = 1.;
        for key in ["C", "I", "A"] {
            iss *= 1. - get(key, &[("H", 0.56), ("L", 0.22), ("N", 0.)])?;
        }
        let iss = 1. - iss;
        let impact = if changed {
            7.52 * (iss - 0.029) - 3.25 * f64::powi(iss - 0.02, 15)
        } else {
            6.42 * iss
        };
        if impact <= 0. {
            return Some(0.);
        }
        let exploit = 8.22
            * get("AV", &[("N", 0.85), ("A", 0.62), ("L", 0.55), ("P", 0.2)])?
            * get("AC", &[("L", 0.77), ("H", 0.44)])?
            * pr
            * get("UI", &[("N", 0.85), ("R", 0.62)])?;
        let score = (if changed {
            1.08 * (impact + exploit)
        } else {
            impact + exploit
        })
        .min(10.);
        Some(((score * 100000.).round() / 10000.).ceil() / 10.)
    })();
    result.unwrap_or(0.)
}
pub fn scored(f: &Value) -> (f64, String) {
    let v3 = a(f, "severity")
        .iter()
        .filter(|s| s["type"].as_str().is_some_and(|s| s.starts_with("CVSS_V3")))
        .map(|v| cvss3(s(v, "score")))
        .fold(0., f64::max);
    if v3 > 0. {
        return (v3, String::new());
    }
    let v4 = a(f, "severity")
        .iter()
        .filter(|v| v["type"] == "CVSS_V4")
        .map(|v| {
            let m: BTreeMap<_, _> = s(v, "score")
                .split('/')
                .skip(1)
                .filter_map(|s| s.split_once(':'))
                .collect();
            let vector = format!(
                "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:U/C:{}/I:{}/A:{}",
                m.get("AV").unwrap_or(&""),
                m.get("AC").unwrap_or(&""),
                m.get("PR").unwrap_or(&""),
                if m.get("UI") == Some(&"N") { "N" } else { "R" },
                m.get("VC").unwrap_or(&""),
                m.get("VI").unwrap_or(&""),
                m.get("VA").unwrap_or(&"")
            );
            cvss3(&vector)
        })
        .fold(0., f64::max);
    if v4 > 0. {
        return (v4, "estimated from CVSS v4".into());
    }
    let score = match s(&f["database_specific"], "severity")
        .to_uppercase()
        .as_str()
    {
        "CRITICAL" => 9.,
        "HIGH" => 7.,
        "MODERATE" | "MEDIUM" => 4.,
        "LOW" => 0.1,
        _ => 0.,
    };
    (
        score,
        if score > 0. {
            "from the advisory label"
        } else {
            ""
        }
        .into(),
    )
}
pub fn severity(f: &Value) -> &str {
    if SEVERITIES[..4].contains(&s(&f["priority"], "level")) {
        return s(&f["priority"], "level");
    }
    let score = scored(f).0;
    if score >= 9. {
        "critical"
    } else if score >= 7. {
        "high"
    } else if score >= 4. {
        "medium"
    } else if score > 0. {
        "low"
    } else {
        "unrated"
    }
}
pub fn finding_type(f: &Value) -> &str {
    let kind = s(f, "kind");
    if ["health", "mcp", "skill", "cli"].contains(&kind) {
        return kind;
    }
    if s(f, "key").starts_with("health:") {
        return "health";
    }
    let p = &f["package"];
    let eco = s(p, "ecosystem");
    if eco == "Chromium" {
        "browser"
    } else if ["dpkg-query", "rpm", "pacman", "apk", "brew", "choco"].contains(&s(p, "path"))
        || eco.contains(':')
        || ["Arch", "Alpine", "Debian", "Ubuntu"].contains(&eco)
    {
        "os"
    } else {
        "library"
    }
}
pub fn basename(path: &str) -> String {
    path.replace('\\', "/")
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .into()
}
fn project(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut parts: Vec<_> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts.pop();
    parts
        .into_iter()
        .rev()
        .find(|s| {
            ![
                "tests",
                "test",
                "fixtures",
                "fixture",
                "src",
                "app",
                "lib",
                "packages",
                "node_modules",
                "vendor",
            ]
            .contains(&s.to_lowercase().as_str())
        })
        .unwrap_or("A project")
        .into()
}
pub fn browser_name(path: &str) -> &str {
    let p = path.replace('\\', "/").to_lowercase();
    if p.contains("ms-playwright") {
        "Playwright Chromium"
    } else if p.contains("edge") {
        "Edge"
    } else if p.contains("google/chrome")
        || p.ends_with("chrome.exe")
        || p.contains("google-chrome")
    {
        "Chrome"
    } else if p.contains("brave") {
        "Brave"
    } else {
        "Chromium"
    }
}
pub fn static_observation(f: &Value) -> bool {
    s(f, "evidence_basis") == "static-text-pattern" && s(f, "advisory").is_empty()
}
pub fn group_key(f: &Value, host: &str) -> String {
    if static_observation(f) {
        return json!([
            host,
            finding_type(f),
            "static-text-pattern",
            s(f, "asset"),
            s(f, "item"),
            s(f, "source_file"),
            s(f, "path"),
            s(f, "rule")
        ])
        .to_string();
    }
    let t = finding_type(f);
    let p = &f["package"];
    let path = s(p, "path").replace('\\', "/");
    match t {
        "os" => format!("{host}|{t}"),
        "library" => format!(
            "{host}|{t}|{}",
            path.rsplit_once('/').map(|p| p.0).unwrap_or("")
        ),
        "browser" | "mcp" | "skill" | "cli" => {
            format!("{host}|{t}|{}|{}", s(p, "name"), s(p, "path"))
        }
        _ => format!("{host}|{t}|{}", s(f, "key")),
    }
}
fn vkey(s: &str) -> Vec<(bool, usize, String)> {
    regex::Regex::new(r"[0-9]+|[A-Za-z]+")
        .unwrap()
        .find_iter(s)
        .map(|m| {
            let s = m.as_str();
            if s.bytes().all(|b| b.is_ascii_digit()) {
                let trimmed = s.trim_start_matches('0');
                (false, trimmed.len(), trimmed.into())
            } else {
                (true, 0, s.into())
            }
        })
        .collect()
}
pub fn target(items: &[Value]) -> String {
    let mut best = String::new();
    for i in items {
        let installed = vkey(s(&i["package"], "version"));
        let mut above: Vec<_> = a(i, "fixed")
            .iter()
            .filter_map(Value::as_str)
            .filter(|s| vkey(s) > installed)
            .collect();
        above.sort_by_key(|s| vkey(s));
        let Some(first) = above.first() else {
            return String::new();
        };
        if best.is_empty() || vkey(first) > vkey(&best) {
            best = first.to_string();
        }
    }
    best
}
pub fn os_command(p: &Value) -> &str {
    let eco = s(p, "ecosystem");
    for (prefix, command) in [
        ("Arch", "sudo pacman -Syu"),
        ("Alpine", "sudo apk upgrade"),
        ("Red Hat", "sudo dnf upgrade"),
        ("Rocky", "sudo dnf upgrade"),
        ("AlmaLinux", "sudo dnf upgrade"),
        ("Fedora", "sudo dnf upgrade"),
        ("SUSE", "sudo zypper update"),
        ("openSUSE", "sudo zypper update"),
        ("Homebrew", "brew upgrade"),
        ("Chocolatey", "choco upgrade all"),
    ] {
        if eco.starts_with(prefix) {
            return command;
        }
    }
    match s(p, "path") {
        "rpm" => "sudo dnf upgrade",
        "pacman" => "sudo pacman -Syu",
        "apk" => "sudo apk upgrade",
        "brew" => "brew upgrade",
        "choco" => "choco upgrade all",
        _ => "sudo apt upgrade",
    }
}
fn n(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}
pub fn describe(t: &str, items: &[Value]) -> Value {
    let first = &items[0];
    if static_observation(first) {
        return json!({"title":s(first,"title"),"fix":"Review the flagged text in context","eyebrow":"Static observation","why":s(first,"why"),"path":s(first,"path")});
    }
    let p = &first["package"];
    let (name, path, version) = (s(p, "name"), s(p, "path"), s(p, "version"));
    let count = items
        .iter()
        .map(|i| s(i, "advisory"))
        .collect::<BTreeSet<_>>()
        .len();
    let to = target(items);
    match t {
        "browser" => {
            let browser = browser_name(path);
            let fix = match browser {
                "Chrome" => "Open Chrome > About and relaunch",
                "Edge" => "Open Edge > About and relaunch",
                "Brave" => "Open Brave > About and relaunch",
                "Playwright Chromium" => "Run: npx playwright install chromium",
                _ => "Update Chromium with your package manager",
            };
            json!({"title":format!("{browser} is missing {}",n(count,"security fix","security fixes")),"fix":fix,"eyebrow":"Browser","installed":version,"target":to})
        }
        "os" | "library" => {
            let mut packages: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
            for i in items {
                packages
                    .entry(s(&i["package"], "name"))
                    .or_default()
                    .push(i.clone());
            }
            if t == "os" {
                // One finding with a known fix is enough: the update installs it.
                let ready = items
                    .iter()
                    .any(|i| !target(std::slice::from_ref(i)).is_empty());
                json!({"title":format!("{} known flaws",n(packages.len(),"system package has","system packages have")),"fix":if ready{format!("Run: {}",os_command(p))}else{"Fix not known yet; vorda will tell you when one ships".into()},"eyebrow":"System"})
            } else {
                let fixable = packages.iter().find(|(_, v)| !target(v).is_empty());
                let fix = if let Some((lib, values)) = fixable {
                    format!(
                        "Update {lib} to {} in {}{}",
                        target(values),
                        basename(s(&values[0]["package"], "path")),
                        if packages.len() > 1 {
                            format!(", and {} more", packages.len() - 1)
                        } else {
                            String::new()
                        }
                    )
                } else {
                    format!(
                        "No fixed version yet for {}",
                        packages
                            .keys()
                            .take(3)
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                let mut result = json!({"title":format!("{} uses {} with known flaws",project(path),n(packages.len(),"library","libraries")),"fix":fix,"eyebrow":"Project"});
                if packages.len() == 1 {
                    result["installed"] = json!(version);
                    result["target"] = json!(to);
                }
                result
            }
        }
        "mcp" | "skill" | "cli" => {
            json!({"title":format!("{} {name} has {}",match t{"mcp"=>"MCP server","skill"=>"Agent skill",_=>"Agent tool"},n(count,"known flaw","known flaws")),"fix":if to.is_empty(){format!("Turn {name} off until a fix ships")}else{format!("Update {name} to {to}")},"eyebrow":"Agent tool","installed":version,"target":to})
        }
        "health" => {
            let source = first
                .get("asset")
                .and_then(Value::as_str)
                .unwrap_or(s(first, "key"))
                .split_once("health:")
                .map(|s| s.1)
                .unwrap_or("");
            let scope = s(first, "scan_scope");
            let source = if !scope.is_empty() {
                source.strip_prefix(&format!("{scope}:")).unwrap_or(source)
            } else {
                source
            };
            let retry = "It retries on the next scan; findings are kept";
            let (title, fix, eyebrow) = if source.starts_with("delivery:") {
                let channel = s(first, "title")
                    .strip_prefix("Delivery unavailable: ")
                    .unwrap_or("your alert channel");
                (
                    format!("Alerts can't reach {channel}"),
                    format!("Check the {channel} settings; alerts retry while it is in use and stop after 24 failures; a week unused clears this warning but keeps queued alerts for its next use"),
                    "Alerts",
                )
            } else if source == "lock" {
                (
                    "A scan could not start".into(),
                    "Another scan was still running; it retries on the next scan".into(),
                    "Scan",
                )
            } else if source.starts_with("agentbom:") {
                (
                    "Part of the agent tools check could not finish".into(),
                    retry.into(),
                    "Scan",
                )
            } else if let Some(source) = source.strip_prefix("coverage:") {
                (
                    format!("No advisory feed covers {source} yet"),
                    "Nothing to do; results stay unknown for these".into(),
                    "Coverage",
                )
            } else if source == "inventory" {
                // A refused folder or file is refused again; say what the scan found instead.
                let error = s(first, "error");
                (
                    "Part of the scan could not run".into(),
                    if error.is_empty() { retry } else { error }.into(),
                    "Scan",
                )
            } else {
                (
                    format!(
                        "Scan could not reach {}",
                        if source.is_empty() { "a feed" } else { source }
                    ),
                    retry.into(),
                    "Scan",
                )
            };
            json!({"title":title,"fix":fix,"eyebrow":eyebrow})
        }
        _ => json!({"title":s(first,"title"),"fix":"","eyebrow":"Finding"}),
    }
}
pub fn subject(f: &Value) -> &str {
    if finding_type(f) == "browser" {
        browser_name(s(&f["package"], "path"))
    } else {
        let n = s(&f["package"], "name");
        if n.is_empty() {
            "a package"
        } else {
            n
        }
    }
}
pub fn headline(f: &Value, changed: bool) -> String {
    let name = subject(f);
    if changed {
        format!("Advice changed for a flaw in {name}")
    } else if f["kev"] == true {
        format!("Attackers are using a flaw in {name}")
    } else if ["critical", "high"].contains(&severity(f)) {
        format!("Serious flaw found in {name}")
    } else {
        format!("New flaw found in {name}")
    }
}
pub fn why(t: &str, kev: bool, sev: &str, epss: f64, dev: bool) -> &'static str {
    if kev {
        "Attackers are using this right now (CISA known exploited list)."
    } else if t == "browser" {
        "Browsers open untrusted pages all day, so missing fixes are an open door."
    } else if dev {
        "Only in dev or test files, so it is unlikely to be reachable."
    } else if epss >= 0.1 {
        "Likely to be exploited in the next month."
    } else if ["critical", "high"].contains(&sev) {
        "Serious: it could let someone run code or take data."
    } else if sev == "medium" {
        "Could leak data or crash under some conditions."
    } else {
        "Low risk on its own; fix it with your next update."
    }
}
