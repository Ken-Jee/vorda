use super::super::{array, error, input, string};
use crate::Result;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
fn catalog() -> &'static Value {
    static C: OnceLock<Value> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(include_str!("rules.json")).unwrap())
}
fn rx(s: &str) -> Regex {
    static PATTERNS: OnceLock<Mutex<BTreeMap<String, Regex>>> = OnceLock::new();
    let mut patterns = PATTERNS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap();
    patterns
        .entry(s.into())
        .or_insert_with(|| Regex::new(s).expect("accepted static rule expression"))
        .clone()
}
pub fn fingerprint(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))[..12].into()
}
fn redact(s: &str) -> String {
    format!("…({} chars)", s.chars().count())
}
pub fn entropy(s: &str) -> f64 {
    let mut counts = BTreeMap::<char, f64>::new();
    let mut len: f64 = 0.0;
    for c in s.chars().take(4096) {
        *counts.entry(c).or_insert(0.0) += 1.0;
        len += 1.0;
    }
    counts
        .values()
        .map(|n| {
            let p = n / len;
            -p * p.log2()
        })
        .sum()
}
fn random_token(s: &str) -> bool {
    rx(r"^[0-9a-fA-F]{32,}$").is_match(s)
        || entropy(s) >= 4.0
            && s.chars().any(|c| c.is_ascii_digit())
            && s.chars().any(|c| c.is_ascii_alphabetic())
}
fn placeholder(s: &str) -> bool {
    rx(r"(?i)^\$\{?[\w:-]+\}?$|^\{env:[^}]+\}$|^\$env:|^env:|^<[^>]+>$|^%\w+%$|your[_-]|example|changeme|placeholder|^x{4,}$|^\*{3,}$|^\.{3}$|^(?:true|false|none|null)$").is_match(s)
}
fn secret_name(s: &str) -> bool {
    rx(r"(?i)token|secret|passw|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key")
        .is_match(s)
}
pub fn literal_secret(name: &str, value: &str) -> bool {
    let v = value.trim();
    let v = if v.to_lowercase().starts_with("bearer ") {
        v[7..].trim()
    } else {
        v
    };
    secret_name(name)
        && v.chars().count() >= 12
        && !placeholder(v)
        && !v.contains(' ')
        && entropy(v) >= 3.0
}
pub fn scrub(s: &str) -> String {
    let s = if s.chars().count() > 2000 {
        let end = s
            .char_indices()
            .nth(2000)
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{} …", &s[..s[..end].rfind(' ').unwrap_or(0)])
    } else {
        s.into()
    };
    let mut s = s;
    for entry in array(&catalog()["secrets"]) {
        s = rx(string(entry, "pattern"))
            .replace_all(&s, |c: &regex::Captures| {
                if let Some(v) = c.get(1) {
                    c[0].replace(v.as_str(), &redact(v.as_str()))
                } else {
                    redact(&c[0])
                }
            })
            .into_owned();
    }
    for pattern in array(&catalog()["loose"]) {
        s = rx(pattern.as_str().unwrap())
            .replace_all(&s, |c: &regex::Captures| {
                let v = &c[1];
                if v.contains("…(") || placeholder(v) {
                    c[0].into()
                } else {
                    c[0].replace(v, &redact(v))
                }
            })
            .into_owned();
    }
    rx(r"[A-Za-z0-9+/=_-]{20,}")
        .replace_all(&s, |c: &regex::Captures| {
            if random_token(&c[0]) {
                redact(&c[0])
            } else {
                c[0].into()
            }
        })
        .into_owned()
}
pub fn safe_spec(s: &str) -> String {
    scrub(&rx(r"//[^/@\s]*@").replace_all(s, "//…@"))
        .chars()
        .take(160)
        .collect()
}
fn invisible(c: char) -> bool {
    matches!(c as u32,0x200b..=0x200f|0x202a..=0x202e|0x2060..=0x2064|0x2066..=0x2069|0xe0000..=0xe007f)
}
fn mask(s: &str) -> String {
    let vocab: BTreeSet<_> = array(&catalog()["vocab"])
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let words = rx(r"[A-Za-z]+");
    let mut out = Vec::new();
    for w in s.split_whitespace() {
        let p: Vec<_> = words
            .find_iter(w)
            .map(|m| m.as_str().to_lowercase())
            .collect();
        let keep = !p.is_empty()
            && w.len() <= 40
            && !w.chars().any(|c| c.is_ascii_digit())
            && p.iter().all(|p| vocab.contains(p.as_str()));
        if keep {
            out.push(w.into());
        } else if w.chars().count() == 1 && w.chars().any(invisible) {
            out.push(format!("\\u{{{:x}}}", w.chars().next().unwrap() as u32));
        } else if out.last().is_none_or(|s| s != "…") {
            out.push("…".into());
        }
    }
    out.join(" ")
}
fn excerpt(src: &str, start: usize, end: usize) -> String {
    let mut lo = start;
    let mut hi = end;
    while lo > 0 && start - lo < 300 {
        let (i, c) = src[..lo].char_indices().last().unwrap();
        if c.is_whitespace() {
            break;
        }
        lo = i;
    }
    while hi < src.len() && hi - end < 300 {
        let c = src[hi..].chars().next().unwrap();
        if c.is_whitespace() {
            break;
        }
        hi += c.len_utf8();
    }
    let s: String = src[lo..hi]
        .chars()
        .flat_map(|c| {
            if invisible(c) {
                format!(" \\u{{{:x}}} ", c as u32)
                    .chars()
                    .collect::<Vec<_>>()
            } else {
                vec![if c == '\n' { ' ' } else { c }]
            }
        })
        .collect();
    mask(&s).chars().take(200).collect()
}
pub fn text_findings(src: &str, context: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for r in array(&catalog()["text"]) {
        if !array(&r["contexts"]).iter().any(|v| v == context) {
            continue;
        }
        let pattern = format!("(?i){}", string(r, "pattern"));
        if let Some(m) = rx(&pattern).find(src) {
            let rule = string(r, "rule");
            let evidence = if rule == "AB-P7" {
                let words = rx(r"[A-Za-z-]+");
                let first = words.find(m.as_str()).map(|m| m.as_str()).unwrap_or("");
                let last = m.as_str().rsplit_once('|').map(|(_, s)| s).unwrap_or("$(");
                format!(
                    "{first} … | {}",
                    words.find(last).map(|m| m.as_str()).unwrap_or("")
                )
            } else {
                excerpt(src, m.start(), m.end())
            };
            out.push(json!({"rule":rule,"severity":r["severity"],"title":r["title"],"why":r["why"],"evidence":evidence}));
        }
    }
    let hidden: Vec<_> = src.char_indices().filter(|(_, c)| invisible(*c)).collect();
    if !hidden.is_empty() && context != "shell" {
        let tags: String = hidden
            .iter()
            .filter_map(|(_, c)| {
                let n = *c as u32;
                if (0xe0020..=0xe007e).contains(&n) {
                    char::from_u32(n - 0xe0000)
                } else {
                    None
                }
            })
            .collect();
        let mut why = "Characters you cannot see are present; models still read them.".to_string();
        if !tags.is_empty() {
            why.push_str(&format!(
                " Decoded hidden text ({} chars): {:?}",
                tags.chars().count(),
                mask(&tags).chars().take(160).collect::<String>()
            ));
        }
        let (i, c) = hidden[0];
        out.push(json!({"rule":"AB-P9","severity":"high","title":"Invisible characters in agent-readable text","why":why,"evidence":excerpt(src,i,i+c.len_utf8())}));
    }
    for finding in &mut out {
        finding["evidence_basis"] = json!("static-text-pattern");
    }
    out
}
pub fn secret_findings(
    src: &str,
    where_: &str,
    assignments: &BTreeMap<String, String>,
) -> Vec<Value> {
    let (mut out, mut seen) = (Vec::new(), BTreeSet::new());
    for r in array(&catalog()["secrets"]) {
        for c in rx(string(r, "pattern")).captures_iter(src) {
            let value = c.get(1).or_else(|| c.get(0)).unwrap().as_str();
            let fp = fingerprint(value);
            if seen.insert(fp.clone()) {
                let kind = string(r, "kind");
                out.push(json!({"rule":"AB-S1","severity":"high","title":format!("Secret stored in {where_} ({kind})"),"why":format!("A {kind} sits in plain text where any process or backup can read it."),"evidence":redact(value),"fingerprint":fp}));
            }
        }
    }
    for (name, value) in assignments {
        let v = value.trim();
        let v = if v.to_lowercase().starts_with("bearer ") {
            v[7..].trim()
        } else {
            v
        };
        let fp = fingerprint(v);
        if literal_secret(name, value)
            && !seen.contains(&fp)
            && !array(&catalog()["secrets"])
                .iter()
                .any(|r| rx(string(r, "pattern")).is_match(v))
        {
            seen.insert(fp.clone());
            out.push(json!({"rule":"AB-S2","severity":"medium","title":format!("Credential-like value in {where_} ({name})"),"why":format!("The setting {name} holds a literal value instead of a reference to a secret store."),"evidence":format!("{name}={}",redact(v)),"fingerprint":fp}));
        }
    }
    out
}
fn private_host(host: &str) -> Option<bool> {
    if host == "localhost" || host.ends_with(".localhost") {
        return Some(true);
    }
    match host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_loopback() => Some(true),
        Ok(std::net::IpAddr::V4(ip)) => {
            if ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1])
            {
                None
            } else {
                Some(false)
            }
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            if ip.is_unspecified()
                || ip.segments()[0] & 0xfe00 == 0xfc00
                || ip.segments()[0] & 0xffc0 == 0xfe80
            {
                None
            } else {
                Some(false)
            }
        }
        Err(_) => {
            if [".local", ".lan", ".internal", ".ts.net", ".home.arpa"]
                .iter()
                .any(|s| host.ends_with(s))
            {
                None
            } else {
                Some(false)
            }
        }
    }
}
pub fn server_findings(server: &Value, pkg: &Value, home: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    let spec = string(pkg, "spec");
    let vcs = spec
        .split_once("://")
        .is_some_and(|(_, s)| s.split_once('/').is_some_and(|(_, p)| p.contains('@')));
    if pkg["fetches"] == true
        && string(pkg, "version").is_empty()
        && ["npm", "PyPI"].contains(&string(pkg, "ecosystem"))
        && !vcs
    {
        out.push(json!({"rule":"AB-C1","severity":"medium","title":"Unpinned package runs whatever the registry serves","why":format!("{} fetches {} at its newest version on start, so a hijacked release runs with your agent's rights.",string(pkg,"runner"),scrub(string(pkg,"name"))),"fix":format!("Pin an exact version, e.g. {}{}.",scrub(string(pkg,"name")),if pkg["ecosystem"]=="npm"{"@X.Y.Z"}else{"==X.Y.Z"}),"evidence":safe_spec(spec)}));
    }
    if pkg["ecosystem"] == "OCI" && !rx(r"^sha256:[0-9a-f]{64}$").is_match(string(pkg, "version")) {
        out.push(json!({"rule":"AB-C2","severity":"low","title":"Container image not pinned by digest","why":format!("The tag {} can be moved to a different image.",if string(pkg,"version").is_empty(){"latest"}else{string(pkg,"version")}),"fix":"Use image@sha256:<digest>.","evidence":safe_spec(spec)}));
    }
    let mut urls: Vec<_> = array(&server["args"])
        .iter()
        .filter_map(Value::as_str)
        .filter(|a| a.starts_with("http://") || a.starts_with("https://"))
        .collect();
    if !string(server, "url").is_empty() {
        urls.push(string(server, "url"));
    }
    for u in urls {
        if let Ok(u) = url::Url::parse(u) {
            let host = u.host_str().unwrap_or("");
            let private = private_host(host);
            if u.scheme() == "http" && private != Some(true) {
                out.push(json!({"rule":"AB-C3","severity":if private==Some(false){"high"}else{"low"},"title":format!("MCP traffic over plain HTTP{}",if private==Some(false){" to a public host"}else{" on a private network"}),"why":format!("Requests, tool results and any tokens to {host} travel unencrypted."),"fix":"Use https:// or a loopback address.","evidence":format!("{}://{}{}",u.scheme(),host,u.port().map(|p|format!(":{p}")).unwrap_or_default())}));
            }
        }
    }
    let flags: Vec<_> = array(&server["args"])
        .iter()
        .filter_map(Value::as_str)
        .filter(|a| {
            [
                "--allow-http",
                "--insecure",
                "--no-verify",
                "--disable-ssl",
                "-k",
            ]
            .contains(a)
        })
        .collect();
    if server["env"]["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"
        || server["env"]["PYTHONHTTPSVERIFY"] == "0"
        || !flags.is_empty()
    {
        out.push(json!({"rule":"AB-C4","severity":"medium","title":"TLS checks weakened for an MCP server","why":"The server accepts unverified or unencrypted connections, so a network attacker can feed it tools.","fix":format!("Remove {}.",if flags.is_empty(){"the TLS override".into()}else{flags.join(", ")}),"evidence":if flags.is_empty(){"NODE_TLS_REJECT_UNAUTHORIZED=0".into()}else{flags.join(" ")}}));
    }
    if pkg["name"] == "@modelcontextprotocol/server-filesystem" {
        let wide: Vec<_> = array(&server["args"])
            .iter()
            .filter_map(Value::as_str)
            .filter(|a| {
                ["/", "~", "$HOME", "%USERPROFILE%", "C:\\", "C:/"].contains(a)
                    || a.trim_end_matches(['/', '\\']) == home.to_string_lossy()
            })
            .collect();
        if !wide.is_empty() {
            out.push(json!({"rule":"AB-C5","severity":"medium","title":"Filesystem MCP server can read your whole home or disk","why":format!("Any prompt injection that reaches this agent can read {}, including keys and tokens.",wide[0]),"fix":"Give it only the project folders it needs.","evidence":wide.join(" ")}));
        }
    }
    out
}
fn pickle_globals(data: &[u8], deadline: Instant) -> (BTreeSet<(String, String)>, bool) {
    let (mut found, mut strings, mut memo) = (
        BTreeSet::new(),
        Vec::<String>::new(),
        BTreeMap::<u64, String>::new(),
    );
    let (mut i, mut stops, mut stack_global) = (0, 0, false);
    let mut operations = 0;
    fn line<'a>(data: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
        let end = data.get(*i..)?.iter().position(|b| *b == b'\n')? + *i;
        let s = &data[*i..end];
        *i = end + 1;
        Some(s)
    }
    fn bytes<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Option<&'a [u8]> {
        let end = i.checked_add(n)?;
        let b = data.get(*i..end)?;
        *i = end;
        Some(b)
    }
    fn number(data: &[u8], i: &mut usize, width: usize) -> Option<u64> {
        let b = bytes(data, i, width)?;
        let mut n = [0; 8];
        n[..width].copy_from_slice(b);
        Some(u64::from_le_bytes(n))
    }
    while i < data.len() && Instant::now() < deadline {
        operations += 1;
        if operations > 10_000_000 {
            break;
        }
        let op = data[i];
        i += 1;
        let parsed = (|| -> Option<()> {
            match op {
                b'.' => {
                    stops += 1;
                }
                b'c' | b'i' => {
                    let module = String::from_utf8_lossy(line(data, &mut i)?).into_owned();
                    let name = String::from_utf8_lossy(line(data, &mut i)?).into_owned();
                    found.insert((module, name));
                }
                0x93 => {
                    stack_global = true;
                    if strings.len() >= 2 {
                        found.insert((
                            strings[strings.len() - 2].clone(),
                            strings[strings.len() - 1].clone(),
                        ));
                    }
                }
                0x8c | b'U' => {
                    let n = number(data, &mut i, 1)? as usize;
                    let s = bytes(data, &mut i, n)?;
                    strings.push(String::from_utf8_lossy(s).chars().take(200).collect());
                }
                b'X' | b'T' => {
                    let n = number(data, &mut i, 4)?;
                    let n = usize::try_from(n).ok()?;
                    let s = bytes(data, &mut i, n)?;
                    strings.push(String::from_utf8_lossy(s).chars().take(200).collect());
                }
                0x8d => {
                    let n = usize::try_from(number(data, &mut i, 8)?).ok()?;
                    let s = bytes(data, &mut i, n)?;
                    strings.push(String::from_utf8_lossy(s).chars().take(200).collect());
                }
                b'V' | b'S' => {
                    strings.push(
                        String::from_utf8_lossy(line(data, &mut i)?)
                            .trim_matches(['\'', '"'])
                            .chars()
                            .take(200)
                            .collect(),
                    );
                }
                0x94 => {
                    if let Some(s) = strings.last() {
                        memo.insert(memo.len() as u64, s.clone());
                    }
                }
                b'q' | b'r' | b'p' => {
                    let n = if op == b'p' {
                        std::str::from_utf8(line(data, &mut i)?)
                            .ok()?
                            .parse()
                            .ok()?
                    } else {
                        number(data, &mut i, if op == b'q' { 1 } else { 4 })?
                    };
                    if let Some(s) = strings.last() {
                        memo.insert(n, s.clone());
                    }
                }
                b'h' | b'j' | b'g' => {
                    let n = if op == b'g' {
                        std::str::from_utf8(line(data, &mut i)?)
                            .ok()?
                            .parse()
                            .ok()?
                    } else {
                        number(data, &mut i, if op == b'h' { 1 } else { 4 })?
                    };
                    if let Some(s) = memo.get(&n) {
                        strings.push(s.clone());
                    }
                }
                b'I' | b'L' | b'F' | b'P' => {
                    line(data, &mut i)?;
                }
                b'J' => {
                    bytes(data, &mut i, 4)?;
                }
                b'K' | 0x80 | 0x82 => {
                    bytes(data, &mut i, 1)?;
                }
                b'M' | 0x83 => {
                    bytes(data, &mut i, 2)?;
                }
                b'G' | 0x95 => {
                    bytes(data, &mut i, 8)?;
                }
                0x84 => {
                    bytes(data, &mut i, 4)?;
                }
                0x8a => {
                    let n = number(data, &mut i, 1)? as usize;
                    bytes(data, &mut i, n)?;
                }
                0x8b | b'B' => {
                    let n = usize::try_from(number(data, &mut i, 4)?).ok()?;
                    bytes(data, &mut i, n)?;
                }
                b'C' => {
                    let n = number(data, &mut i, 1)? as usize;
                    bytes(data, &mut i, n)?;
                }
                0x8e | 0x96 => {
                    let n = usize::try_from(number(data, &mut i, 8)?).ok()?;
                    bytes(data, &mut i, n)?;
                }
                b'('
                | b')'
                | b']'
                | b'}'
                | b'N'
                | b'0'
                | b'1'
                | b'2'
                | b'a'
                | b'b'
                | b'd'
                | b'e'
                | b'l'
                | b'o'
                | b'R'
                | b's'
                | b't'
                | b'u'
                | b'Q'
                | 0x81
                | 0x85..=0x89
                | 0x8f..=0x92
                | 0x97
                | 0x98 => {}
                _ => return None,
            };
            Some(())
        })();
        if parsed.is_none() {
            break;
        }
        if strings.len() > 1_000_000 || memo.len() > 1_000_000 {
            break;
        }
    }
    if stack_global {
        let never: BTreeSet<_> = array(&catalog()["never_data"])
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for s in strings {
            if never.contains(s.as_str()) {
                found.insert((s, "*".into()));
            }
        }
    }
    (found, stops > 0 && Instant::now() < deadline)
}
fn dangerous(m: &str, n: &str) -> bool {
    let c = catalog();
    if ["builtins", "__builtin__", "__builtins__"].contains(&m) {
        return n == "*" || array(&c["dangerous_builtins"]).iter().any(|v| v == n);
    }
    if array(&c["dangerous_pairs"])
        .iter()
        .any(|p| p[0] == m && p[1] == n)
        || array(&c["never_data"]).iter().any(|v| v == m)
    {
        return true;
    }
    array(&c["dangerous_globals"])
        .iter()
        .filter_map(Value::as_str)
        .any(|g| m == g || m.starts_with(&format!("{g}.")))
}
pub fn model_scan(path: &Path, budget: Instant) -> (Vec<Value>, bool) {
    let ext = path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    if !["pt", "pth", "ckpt", "pkl", "pickle", "joblib", "bin", "npy"].contains(&ext.as_str()) {
        return (vec![], true);
    }
    if fs_regular(path) == Some(false) {
        return (vec![], true);
    }
    let deadline = (Instant::now() + Duration::from_secs(2)).min(budget);
    let mut found = BTreeSet::new();
    let mut file = match input::open_regular(path, None, u64::MAX) {
        Ok(file) => file,
        Err(_) => return (vec![], false),
    };
    let result = (|| -> Result<bool> {
        let mut head = [0; 8];
        let size = file.read(&mut head).map_err(error)?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).map_err(error)?;
        let mut complete = true;
        if head[..size].starts_with(b"PK") {
            let mut archive = zip::ZipArchive::new(file).map_err(error)?;
            let mut remaining = 32_000_000usize;
            let mut count = 0;
            for i in 0..archive.len() {
                let mut member = archive.by_index(i).map_err(error)?;
                match member.name() {
                    Ok(name) if name.ends_with(".pkl") => {}
                    Ok(_) => continue,
                    // A member whose name cannot be read may be a pickle.
                    Err(_) => {
                        complete = false;
                        continue;
                    }
                }
                count += 1;
                if count > 2000 || remaining == 0 {
                    return Ok(false);
                }
                let mut data = Vec::new();
                match member
                    .by_ref()
                    .take(remaining as u64 + 1)
                    .read_to_end(&mut data)
                {
                    Ok(_) => {
                        if data.len() > remaining {
                            complete = false;
                            remaining = 0;
                            continue;
                        }
                        remaining -= data.len();
                        let (globals, parsed) = pickle_globals(&data, deadline);
                        found.extend(globals);
                        complete &= parsed;
                    }
                    Err(_) => complete = false,
                }
                if Instant::now() > deadline {
                    return Ok(false);
                }
            }
            return Ok(complete);
        }
        let mut data = Vec::new();
        file.take(32_000_001)
            .read_to_end(&mut data)
            .map_err(error)?;
        let whole = data.len() <= 32_000_000;
        data.truncate(32_000_000);
        if data.starts_with(b"\x93NUMPY") {
            let (header, size) = if data.get(6) == Some(&1) {
                (10, 2)
            } else {
                (12, 4)
            };
            let Some(bytes) = data.get(8..8 + size) else {
                return Ok(false);
            };
            let mut n = [0; 4];
            n[..size].copy_from_slice(bytes);
            let n = u32::from_le_bytes(n) as usize;
            let Some(h) = data.get(header..header + n) else {
                return Ok(false);
            };
            if !h.windows(4).any(|w| w == b"'|O'") {
                return Ok(true);
            }
            data = data.get(header + n..).unwrap_or(&[]).to_vec();
        } else if ext == "bin" && data.first() != Some(&0x80) {
            return Ok(true);
        }
        let (globals, parsed) = pickle_globals(&data, deadline);
        found.extend(globals);
        Ok(whole && parsed)
    })();
    let complete = result.unwrap_or(false) && Instant::now() < deadline;
    let bad: Vec<_> = found
        .into_iter()
        .filter(|(m, n)| dangerous(m, n))
        .map(|(m, n)| format!("{m}.{n}"))
        .collect();
    if !bad.is_empty() {
        return (
            vec![
                json!({"rule":"AB-M1","severity":"critical","title":"Model file runs code when loaded","why":format!("Its pickle imports {}; loading it with torch.load or pickle executes that code.",bad.iter().take(5).cloned().collect::<Vec<_>>().join(", ")),"fix":"Delete it, or convert from a trusted source to .safetensors.","evidence":bad.iter().take(10).cloned().collect::<Vec<_>>().join(", ")}),
            ],
            true,
        );
    }
    if complete {
        return (vec![], true);
    }
    if Instant::now() >= budget {
        return (vec![], false);
    }
    (
        vec![
            json!({"rule":"AB-M2","severity":"low","title":"Model file could not be fully checked","why":"Part of its pickle data is corrupt, oversized or too slow to parse, which can hide code from scanners.","fix":"Load it only if you trust its source, or convert it to .safetensors.","evidence":path.file_name().unwrap_or_default().to_string_lossy()}),
        ],
        true,
    )
}
fn fs_regular(path: &Path) -> Option<bool> {
    std::fs::symlink_metadata(path).ok().map(|m| m.is_file())
}
