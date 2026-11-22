use crate::{Error, Result};
use serde_json::{json, Value};
use std::{fs, path::Path};

pub const MODES: [&str; 3] = ["watch", "advise", "fix"];
pub const ACTIONS: [&str; 6] = [
    "browsers",
    "lockfiles",
    "os-packages",
    "containers",
    "agent-tools",
    "config",
];
pub const NEVER: [&str; 4] = ["kernel", "sshd", "bootloader", "package-manager"];
const PROTECTED: &[&str] = &[
    "kernel*",
    "linux*",
    "*openssh*",
    "sshd",
    "apt*",
    "libapt-*",
    "debconf*",
    "dpkg*",
    "dnf",
    "rpm",
    "pacman",
    "apk",
    "brew",
    "winget",
    "choco*",
    "grub*",
    "*bootloader*",
    "systemd*",
    "shim*",
    "efibootmgr",
    "mokutil",
    "initramfs-tools*",
    "refind*",
    "syslinux*",
    "extlinux*",
    "u-boot*",
    "gpgv*",
    "*archive-keyring*",
    "ubuntu-keyring*",
    "dracut*",
    "sudo*",
    "libpam*",
];

pub fn glob(pattern: &str, text: &str) -> bool {
    let mut expression = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => expression.push_str(".*"),
            '?' => expression.push('.'),
            '[' => {
                let mut class = String::new();
                if chars.peek() == Some(&'!') {
                    chars.next();
                    class.push('^');
                }
                for x in chars.by_ref() {
                    if x == ']' {
                        break;
                    }
                    class.push(x);
                }
                if class.is_empty() {
                    expression.push_str("\\[");
                } else {
                    expression.push('[');
                    expression.push_str(&class);
                    expression.push(']');
                }
            }
            _ => expression.push_str(&regex::escape(&c.to_string())),
        }
    }
    expression.push('$');
    regex::Regex::new(&expression).is_ok_and(|r| r.is_match(text))
}
fn list<'a>(data: &'a Value, key: &str) -> impl Iterator<Item = &'a str> {
    data.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}
fn lists_valid(data: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|k| {
        data.get(k).is_none_or(|v| {
            v.as_array()
                .is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty())))
        })
    })
}
fn positive(value: &Value) -> bool {
    value.is_number()
        && value.to_string().bytes().all(|b| b.is_ascii_digit())
        && value.to_string().bytes().any(|b| b != b'0')
}
fn integer_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    let (a, b) = (a.to_string(), b.to_string());
    a.len().cmp(&b.len()).then(a.cmp(&b))
}
#[derive(Clone)]
pub struct Policy {
    pub data: Value,
}
impl Policy {
    pub fn new(data: Value) -> Result<Self> {
        if !data.is_object()
            || data.as_object().unwrap().keys().any(|k| {
                !["allow", "approve", "deny", "windows", "max_changes_per_run"]
                    .contains(&k.as_str())
            })
            || !lists_valid(&data, &["allow", "approve", "deny", "windows"])
            || !positive(&data.get("max_changes_per_run").cloned().unwrap_or(json!(1)))
        {
            return Err(Error::new("invalid policy fields or change limit"));
        }
        let re =
            regex::Regex::new(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]-(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
                .unwrap();
        if list(&data, "windows").any(|s| !re.is_match(s) || s[..5] == s[6..]) {
            return Err(Error::new(
                "windows must have different HH:MM-HH:MM UTC endpoints",
            ));
        }
        Ok(Self { data })
    }
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        if let Ok(data) = serde_json::from_str(&text) {
            return Self::new(data);
        }
        let mut data = json!({});
        let mut key = String::new();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap().trim_end();
            if line.trim().is_empty() {
                continue;
            }
            if !line.starts_with(char::is_whitespace) && line.contains(':') {
                let (k, v) = line.split_once(':').unwrap();
                if !k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') || data.get(k).is_some()
                {
                    return Err(Error::new("duplicate or invalid policy key"));
                }
                key = k.into();
                data[k] = if k == "max_changes_per_run" {
                    serde_json::from_str(v.trim())?
                } else if v.trim().is_empty() || v.trim() == "[]" {
                    json!([])
                } else {
                    return Err(Error::new("use block lists in policy YAML"));
                };
            } else if line.starts_with(char::is_whitespace)
                && line.trim_start().starts_with("- ")
                && data[&key].is_array()
            {
                let v = line.trim_start()[2..].trim();
                let v = if v.len() >= 2
                    && ((v.starts_with('"') && v.ends_with('"'))
                        || (v.starts_with('\'') && v.ends_with('\'')))
                {
                    &v[1..v.len() - 1]
                } else {
                    v
                };
                data[&key].as_array_mut().unwrap().push(json!(v));
            } else {
                return Err(Error::new("unsupported policy YAML"));
            }
        }
        Self::new(data)
    }
    pub fn decision(
        &self,
        package: &str,
        kind: &str,
        count: &Value,
        minute: Option<u32>,
    ) -> &'static str {
        let limit = self
            .data
            .get("max_changes_per_run")
            .cloned()
            .unwrap_or(json!(1));
        if !positive(count) || integer_cmp(count, &limit).is_gt() {
            return "deny";
        }
        let package = package.to_lowercase();
        let package = package.split(':').next().unwrap();
        let matches = |p: &str| glob(p, package) || glob(p, kind);
        if PROTECTED.iter().any(|p| matches(p)) || list(&self.data, "deny").any(matches) {
            return "deny";
        }
        let minute = minute.unwrap_or((crate::store::now() as u64 % 86400 / 60) as u32);
        let windows: Vec<_> = list(&self.data, "windows").collect();
        let parse = |s: &str| s[..2].parse::<u32>().unwrap() * 60 + s[3..5].parse::<u32>().unwrap();
        if !windows.is_empty()
            && !windows.iter().any(|w| {
                let (a, b) = (parse(&w[..5]), parse(&w[6..]));
                if a < b {
                    minute >= a && minute < b
                } else {
                    minute >= a || minute < b
                }
            })
        {
            return "deny";
        }
        if list(&self.data, "approve").any(matches) {
            "approve"
        } else if list(&self.data, "allow").any(matches) {
            "allow"
        } else {
            "approve"
        }
    }
}
#[derive(Clone)]
pub struct Modes {
    pub data: Value,
}
impl Default for Modes {
    fn default() -> Self {
        Self {
            data: json!({"mode":"advise","never":NEVER}),
        }
    }
}
impl Modes {
    pub fn new(data: Value) -> Result<Self> {
        fn rule(v: &Value, nested: bool) -> Result<()> {
            if !v.is_object()
                || v.as_object().unwrap().keys().any(|k| {
                    !["mode", "allow", "ask", "never", "delegate"].contains(&k.as_str())
                        && (nested
                            || !["groups", "machines", "agents", "review"].contains(&k.as_str()))
                })
                || !MODES.contains(&v.get("mode").and_then(Value::as_str).unwrap_or("advise"))
                || v.get("delegate").is_some_and(|x| !x.is_boolean())
                || !lists_valid(v, &["allow", "ask", "never"])
                || ["allow", "ask", "never"]
                    .iter()
                    .any(|k| list(v, k).any(|s| !ACTIONS.contains(&s) && !NEVER.contains(&s)))
            {
                return Err(Error::new("invalid mode rule"));
            }
            Ok(())
        }
        rule(&data, false)?;
        for kind in ["groups", "machines", "agents"] {
            if let Some(scopes) = data.get(kind) {
                for (name, v) in scopes
                    .as_object()
                    .ok_or_else(|| Error::new("scopes must be mappings"))?
                {
                    if name.is_empty() {
                        return Err(Error::new("scope names must not be empty"));
                    }
                    rule(v, true)?;
                }
            }
        }
        if let Some(review) = data.get("review") {
            if !review.is_object()
                || review.as_object().unwrap().keys().any(|k| {
                    ![
                        "humans",
                        "agents",
                        "where",
                        "approvals",
                        "auto_apply_after_hours",
                    ]
                    .contains(&k.as_str())
                })
                || !positive(&review.get("approvals").cloned().unwrap_or(json!(1)))
                || !lists_valid(review, &["humans", "where"])
                || list(review, "where").any(|s| !["cli", "dashboard", "pr"].contains(&s))
                || review
                    .get("auto_apply_after_hours")
                    .is_some_and(|x| !x.is_null() && x != &json!(0))
            {
                return Err(Error::new("invalid review configuration"));
            }
            if let Some(agents) = review.get("agents") {
                if !agents.is_object()
                    || agents.as_object().unwrap().values().any(|v| {
                        !v.is_object()
                            || v.as_object().unwrap().len() != 1
                            || !v["approve"].is_boolean()
                    })
                {
                    return Err(Error::new(
                        "review agents require an explicit approve boolean",
                    ));
                }
            }
        }
        Ok(Self { data })
    }
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let data = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => serde_norway::from_str(&text).map_err(|e| Error::new(e.to_string()))?,
        };
        Self::new(data)
    }
    pub fn can(
        &self,
        agent: &str,
        action: &str,
        machine: Option<&str>,
        group: Option<&str>,
    ) -> Result<Value> {
        if !ACTIONS.contains(&action) && !NEVER.contains(&action) {
            return Err(Error::usage("unrecognized action class"));
        }
        let mut mode = "advise";
        let mut permission = "ask";
        let mut never = NEVER.contains(&action);
        let mut why = "fleet default requires review".to_string();
        let mut scopes = vec![("fleet".to_string(), &self.data)];
        for (kind, name) in [
            ("groups", group),
            ("machines", machine),
            ("agents", Some("*")),
            ("agents", Some(agent)),
        ] {
            if let Some(name) = name {
                if let Some(rule) = self.data.get(kind).and_then(|s| s.get(name)) {
                    scopes.push((format!("{kind}:{name}"), rule));
                }
            }
        }
        for (label, rule) in scopes {
            never |= list(rule, "never").any(|a| a == action);
            let delegated =
                label == "fleet" || self.data["delegate"] == true || rule["delegate"] == true;
            let desired = rule.get("mode").and_then(Value::as_str).unwrap_or(mode);
            if delegated
                || MODES.iter().position(|&m| m == desired) < MODES.iter().position(|&m| m == mode)
            {
                mode = desired;
                why = format!("{label} sets {mode}");
            }
            let candidate = if list(rule, "never").any(|a| a == action) {
                "no"
            } else if list(rule, "ask").any(|a| a == action) {
                "ask"
            } else if list(rule, "allow").any(|a| a == action) {
                "yes"
            } else {
                permission
            };
            if delegated
                || ["no", "ask", "yes"].iter().position(|&p| p == candidate)
                    < ["no", "ask", "yes"].iter().position(|&p| p == permission)
            {
                permission = candidate;
                why = format!("{label} says {candidate}");
            }
        }
        if never {
            permission = "no";
            why = "never rule always wins".into();
        } else if mode != "fix" {
            permission = "no";
            why = format!("{mode} mode does not apply changes");
        }
        Ok(json!({"answer":permission,"mode":mode,"why":why}))
    }
    pub fn set_mode(
        &mut self,
        mode: &str,
        machine: Option<&str>,
        agent: Option<&str>,
        owner: bool,
    ) -> Result<Value> {
        if !owner {
            return Err(Error::rejected(403, "only the fleet owner can edit modes"));
        }
        if !MODES.contains(&mode) || machine.is_some() && agent.is_some() {
            return Err(Error::usage("invalid mode or ambiguous scope"));
        }
        if let Some(name) = machine.or(agent) {
            let kind = if machine.is_some() {
                "machines"
            } else {
                "agents"
            };
            if self.data.get(kind).is_none() {
                self.data[kind] = json!({});
            }
            if self.data[kind].get(name).is_none() {
                self.data[kind][name] = json!({});
            }
            self.data[kind][name]["mode"] = json!(mode);
        } else {
            self.data["mode"] = json!(mode);
        }
        Ok(json!({"mode":mode,"scope":machine.or(agent).unwrap_or("fleet")}))
    }
    pub fn is_human(&self, actor: &str) -> bool {
        self.data["review"]
            .get("humans")
            .cloned()
            .unwrap_or(json!(["local-owner"]))
            .as_array()
            .unwrap()
            .contains(&json!(actor))
    }
    pub fn approval_allowed(&self, actor: &str, kind: &str, channel: &str) -> bool {
        let review = &self.data["review"];
        let channels = review
            .get("where")
            .cloned()
            .unwrap_or(json!(["cli", "dashboard", "pr"]));
        channels.as_array().unwrap().contains(&json!(channel))
            && if kind == "human" {
                self.is_human(actor)
            } else {
                kind == "agent" && review["agents"][actor]["approve"] == true
            }
    }
    pub fn quorum(&self) -> Value {
        self.data["review"]
            .get("approvals")
            .cloned()
            .unwrap_or(json!(1))
    }
    pub fn enough(&self, count: usize) -> bool {
        integer_cmp(&json!(count), &self.quorum()).is_ge()
    }
}
