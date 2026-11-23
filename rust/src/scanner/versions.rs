//! Version ordering and OSV range evaluation for the offline advisory database.
//!
//! Only ecosystems whose ordering is implemented here are matched locally: npm, crates.io and
//! Go (SemVer 2.0) and PyPI (PEP 440). Anything this module cannot order is reported as
//! unknown, never as "not affected".
use serde_json::Value;

/// Ecosystems the offline database can match.
pub const ECOSYSTEMS: [&str; 4] = ["npm", "PyPI", "crates.io", "Go"];

/// The most events one range may carry before the record is treated as unreadable.
pub const MAX_EVENTS: usize = 1_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Semver,
    Pep440,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    Num(u64),
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// major, minor, patch, then "no pre-release" sorts after any pre-release.
    Semver(u64, u64, u64, bool, Vec<Ident>),
    Pep440(Box<Pep>),
}

/// PEP 440 sort key, in the order the specification compares the parts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Pep {
    epoch: u64,
    release: Vec<u64>,
    /// (0, ..) a dev-only release before any pre-release, (1, phase, n) a pre-release, (2, ..) none.
    pre: (u8, u8, u64),
    /// None sorts before any post-release.
    post: Option<u64>,
    /// (0, n) a dev release, (1, 0) none: dev releases sort first.
    dev: (u8, u64),
    /// None sorts before any local label; numeric parts sort after text parts.
    local: Option<Vec<(u8, u64, String)>>,
}

fn scheme(ecosystem: &str, range_type: &str) -> Option<Scheme> {
    match (range_type, ecosystem) {
        ("SEMVER", _) | ("ECOSYSTEM", "npm" | "crates.io" | "Go") => Some(Scheme::Semver),
        ("ECOSYSTEM", "PyPI") => Some(Scheme::Pep440),
        _ => None,
    }
}

fn number(s: &str) -> Option<u64> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

fn semver(version: &str) -> Option<Key> {
    let v = version.strip_prefix('v').unwrap_or(version);
    let v = v.split('+').next()?;
    let (core, pre) = match v.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (v, None),
    };
    let mut parts: Vec<u64> = core.split('.').map(number).collect::<Option<_>>()?;
    // A partial version such as `0.10` or Go's `1.21` is padded with zeros, as OSV does.
    if (1..3).contains(&parts.len()) {
        parts.resize(3, 0);
    }
    let [major, minor, patch] = parts[..] else {
        return None;
    };
    let pre = match pre {
        None => Vec::new(),
        Some(pre) => pre
            .split('.')
            .map(|p| {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    None
                } else if p.bytes().all(|b| b.is_ascii_digit()) {
                    number(p).map(Ident::Num)
                } else {
                    Some(Ident::Text(p.into()))
                }
            })
            .collect::<Option<_>>()?,
    };
    Some(Key::Semver(major, minor, patch, pre.is_empty(), pre))
}

fn pep440(version: &str) -> Option<Key> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"(?x)^v?
            (?:(?P<epoch>[0-9]+)!)?
            (?P<release>[0-9]+(?:\.[0-9]+)*)
            (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
            (?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
            (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
            (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$",
        )
        .unwrap()
    });
    let lower = version.trim().to_ascii_lowercase();
    let c = re.captures(&lower)?;
    let n = |name: &str| c.name(name).map(|m| number(m.as_str()));
    let epoch = n("epoch").unwrap_or(Some(0))?;
    let mut release: Vec<u64> = c["release"].split('.').map(number).collect::<Option<_>>()?;
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let pre = match c.name("pre_l").map(|l| l.as_str()) {
        Some(label) => Some((
            match label {
                "alpha" | "a" => 0,
                "beta" | "b" => 1,
                _ => 2,
            },
            n("pre_n").unwrap_or(Some(0))?,
        )),
        None => None,
    };
    let post = match (n("post_n1"), c.name("post_l")) {
        (Some(v), _) => Some(v?),
        (None, Some(_)) => Some(n("post_n2").unwrap_or(Some(0))?),
        _ => None,
    };
    let dev = match c.name("dev_l") {
        Some(_) => Some(n("dev_n").unwrap_or(Some(0))?),
        None => None,
    };
    let pre = match (pre, post, dev) {
        (None, None, Some(_)) => (0, 0, 0),
        (Some((phase, n)), _, _) => (1, phase, n),
        (None, _, _) => (2, 0, 0),
    };
    let local = match c.name("local") {
        Some(l) => Some(
            l.as_str()
                .split(['-', '_', '.'])
                .map(|p| match number(p) {
                    Some(n) => Some((1, n, String::new())),
                    None if p.bytes().all(|b| b.is_ascii_digit()) => None,
                    None => Some((0, 0, p.to_owned())),
                })
                .collect::<Option<_>>()?,
        ),
        None => None,
    };
    Some(Key::Pep440(Box::new(Pep {
        epoch,
        release,
        pre,
        post,
        dev: dev.map_or((1, 0), |d| (0, d)),
        local,
    })))
}

fn parse(scheme: Scheme, version: &str) -> Option<Key> {
    match scheme {
        Scheme::Semver => semver(version),
        Scheme::Pep440 => pep440(version),
    }
}

/// True when `version` can be ordered for this ecosystem's ECOSYSTEM ranges.
pub fn orderable(ecosystem: &str, version: &str) -> bool {
    scheme(ecosystem, "ECOSYSTEM").is_some_and(|s| parse(s, version).is_some())
}

/// The fixed versions an upgrade from `installed` can use, lowest first. Each advisory's
/// fixes count only above `installed`, kept to its release line (same major; for SemVer below
/// 1.0, same minor) when that advisory has a fix there. None when this ecosystem or any of the
/// versions cannot be ordered.
pub fn upgrades<'a>(
    ecosystem: &str,
    installed: &str,
    advisories: &[Vec<&'a str>],
) -> Option<Vec<&'a str>> {
    let scheme = scheme(ecosystem, "ECOSYSTEM")?;
    let line = |key: &Key| match key {
        Key::Semver(0, minor, ..) => (0, 0, *minor),
        Key::Semver(major, ..) => (0, *major, u64::MAX),
        Key::Pep440(p) => (p.epoch, p.release.first().copied().unwrap_or(0), u64::MAX),
    };
    let own = parse(scheme, installed)?;
    let mut out = std::collections::BTreeMap::new();
    for fixed in advisories {
        let mut above: Vec<(Key, &str)> = fixed
            .iter()
            .map(|v| parse(scheme, v).map(|key| (key, *v)))
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .filter(|(key, _)| *key > own)
            .collect();
        if above.iter().any(|(key, _)| line(key) == line(&own)) {
            above.retain(|(key, _)| line(key) == line(&own));
        }
        out.extend(above);
    }
    Some(out.into_values().collect())
}

/// What one advisory says about one installed version.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Affected,
    NotAffected,
    /// Not matched, because the entry gives nothing a version query can match (OSV version
    /// queries do not match it either); the text says why, for a warning.
    Unmatched(String),
    Unknown(String),
}

/// Evaluate one OSV `affected[]` entry (already matched to the package) for `version`,
/// following the OSV schema: an exact `versions` list, SEMVER and ECOSYSTEM ranges with
/// introduced / fixed / last_affected / limit events. A GIT range is ignored when a
/// version list or another range covers the package. An entry with only GIT ranges, or
/// with neither versions nor ranges, cannot match any version. A version is affected if it
/// is listed or in any range, so a range that cannot be read is unknown even when the
/// entry also lists versions: the list alone never clears a version.
pub fn evaluate(ecosystem: &str, version: &str, id: &str, entry: &Value) -> Verdict {
    let listed: Vec<&str> = entry["versions"]
        .as_array()
        .map(|v| v.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let own = scheme(ecosystem, "ECOSYSTEM").and_then(|s| parse(s, version));
    let same = |other: &str| {
        other == version
            || own.is_some() && scheme(ecosystem, "ECOSYSTEM").and_then(|s| parse(s, other)) == own
    };
    if listed.iter().any(|v| same(v)) {
        return Verdict::Affected;
    }
    let ranges = entry["ranges"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut evaluated = !listed.is_empty();
    let mut git = false;
    for range in ranges {
        let kind = range["type"].as_str().unwrap_or("");
        if kind == "GIT" {
            git = true;
            continue;
        }
        let Some(scheme) = scheme(ecosystem, kind) else {
            return Verdict::Unknown(format!(
                "{} has a {kind:?} range that cannot be evaluated for {ecosystem}",
                id
            ));
        };
        let Some(installed) = parse(scheme, version) else {
            return Verdict::Unknown(format!("version {version:?} cannot be ordered"));
        };
        match in_range(scheme, &installed, range) {
            Ok(true) => return Verdict::Affected,
            Ok(false) => evaluated = true,
            Err(why) => return Verdict::Unknown(format!("{}: {why}", id)),
        }
    }
    if evaluated {
        // A range read around an event that cannot be ordered must still cover every listed
        // version: a listed version it clears shows the event means something else.
        if let Some(value) = ranges.iter().find_map(|r| unorderable(ecosystem, r)) {
            let cleared = |listed: &str| {
                ranges.iter().filter(|r| r["type"] != "GIT").all(|r| {
                    let scheme = scheme(ecosystem, r["type"].as_str().unwrap_or(""));
                    scheme.and_then(|s| Some(in_range(s, &parse(s, listed)?, r))) == Some(Ok(false))
                })
            };
            // Each listed version re-reads every range: bound the work.
            let events: usize = ranges
                .iter()
                .map(|r| r["events"].as_array().map_or(0, Vec::len))
                .sum();
            if listed.len() * events > 100_000 || listed.iter().any(|v| cleared(v)) {
                return Verdict::Unknown(format!("{id}: {}", unordered(value)));
            }
        }
        Verdict::NotAffected
    } else if git {
        Verdict::Unmatched(format!(
            "{id} gives only git commit ranges, so no version can match it"
        ))
    } else {
        Verdict::Unmatched(format!(
            "{id} lists no affected versions or ranges, so no version can match it"
        ))
    }
}

fn unordered(value: &str) -> String {
    format!("event version {value:?} cannot be ordered")
}

/// The first event version in an ECOSYSTEM or SEMVER range that cannot be ordered.
fn unorderable<'a>(ecosystem: &str, range: &'a Value) -> Option<&'a str> {
    let scheme = scheme(ecosystem, range["type"].as_str()?)?;
    range["events"]
        .as_array()?
        .iter()
        .filter_map(|e| e.as_object()?.values().next()?.as_str())
        .find(|v| !matches!(*v, "0" | "*") && parse(scheme, v).is_none())
}

fn trimmed(mut release: Vec<u64>) -> Vec<u64> {
    while release.last() == Some(&0) {
        release.pop();
    }
    release
}

/// The release a version belongs to, for comparing with `within`; None with a PEP 440 epoch.
fn release(key: &Key) -> Option<Vec<u64>> {
    match key {
        Key::Semver(major, minor, patch, ..) => Some(vec![*major, *minor, *patch]),
        Key::Pep440(p) if p.epoch == 0 => Some(trimmed(p.release.clone())),
        Key::Pep440(_) => None,
    }
}

/// The release named by an event version that cannot be ordered but starts with three or
/// more numbers and then a letter, `-`, `_` or `+`, as `2.6.0-NA`, `2.6.0-cu124` or
/// `9.6.0b1`. However the rest is read in this scheme (a pre-, post- or dev release, a local
/// label, build metadata), the version sorts after every earlier release and before every
/// later one; only versions of that release itself stay undecided.
fn within(scheme: Scheme, value: &str) -> Option<Vec<u64>> {
    let v = value.trim();
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    let (head, rest) = v.split_at(v.find(|c: char| !(c.is_ascii_digit() || c == '.'))?);
    if !rest.starts_with(|c: char| c.is_ascii_alphabetic() || matches!(c, '-' | '_' | '+')) {
        return None;
    }
    let parts: Vec<u64> = head.split('.').map(number).collect::<Option<_>>()?;
    match scheme {
        Scheme::Semver if parts.len() == 3 => Some(parts),
        Scheme::Pep440 if parts.len() >= 3 => Some(trimmed(parts)),
        _ => None,
    }
}

/// Where an event version sits: exactly, or somewhere inside one release (`within`).
enum At {
    Exact(Key),
    Within(Vec<u64>),
}

fn in_range(scheme: Scheme, installed: &Key, range: &Value) -> Result<bool, String> {
    let events = range["events"].as_array().ok_or("range without events")?;
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err(format!("range with {} events", events.len()));
    }
    // (where; None is the "0" introduced event, below every version), kind, version text
    let mut parsed: Vec<(Option<At>, &str, &str)> = Vec::with_capacity(events.len());
    let mut limits = Vec::new();
    for event in events {
        let object = event.as_object().ok_or("event is not an object")?;
        if object.len() != 1 {
            return Err("event with other than one key".into());
        }
        let (kind, value) = object.iter().next().ok_or("empty event")?;
        let value = value.as_str().ok_or("event version is not text")?;
        match kind.as_str() {
            "introduced" if value == "0" => parsed.push((None, "introduced", value)),
            "limit" if value == "*" => {}
            "introduced" | "fixed" | "last_affected" | "limit" => {
                let at = match parse(scheme, value) {
                    Some(key) => At::Exact(key),
                    None => At::Within(within(scheme, value).ok_or_else(|| unordered(value))?),
                };
                if kind == "limit" {
                    limits.push((at, value));
                } else {
                    parsed.push((Some(at), kind, value));
                }
            }
            other => return Err(format!("unknown event {other:?}")),
        }
    }
    // With an event known only by its release, every version is placed by release: the
    // installed one must be of another release than any such event, and an epoch (which
    // sorts above every release) cannot be placed at all.
    let vague = parsed
        .iter()
        .map(|(at, _, value)| (at.as_ref(), *value))
        .chain(limits.iter().map(|(at, value)| (Some(at), *value)))
        .find_map(|(at, value)| matches!(at, Some(At::Within(_))).then_some(value));
    // Several such events of different kinds have no order the readings below agree on.
    let mut kinds = parsed.iter().filter(|e| matches!(e.0, Some(At::Within(_))));
    if let (Some(value), Some(first)) = (vague, kinds.next()) {
        if kinds.any(|e| e.1 != first.1) {
            return Err(unordered(value));
        }
    }
    let own = match vague {
        Some(value) => release(installed).ok_or_else(|| unordered(value))?,
        None => Vec::new(),
    };
    let class = |at: &At, value: &str| -> Result<Vec<u64>, String> {
        match at {
            At::Within(r) if *r == own => Err(unordered(value)),
            At::Within(r) => Ok(r.clone()),
            At::Exact(_) if vague.is_none() => Ok(Vec::new()),
            At::Exact(k) => release(k).ok_or_else(|| unordered(value)),
        }
    };
    // (release, None for the "0" introduced event; exact key; passed; kind; version text)
    let mut placed = Vec::with_capacity(parsed.len());
    for (at, kind, value) in &parsed {
        let Some(at) = at else {
            placed.push((None, None, true, *kind, *value));
            continue;
        };
        let class = class(at, value)?;
        let (key, passed) = match at {
            At::Exact(k) if *kind == "last_affected" => (Some(k), installed > k),
            At::Exact(k) => (Some(k), installed >= k),
            At::Within(r) => (None, *r < own),
        };
        placed.push((Some(class), key, passed, *kind, *value));
    }
    // A stable sort, as the OSV spec says: events at one version keep their input order.
    placed.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    // Events in one release with one known only by its release can come in any order, which
    // gives one answer only when they are all of one kind.
    for group in placed.chunk_by(|a, b| a.0 == b.0) {
        if let Some(value) = group.iter().find(|e| e.1.is_none() && e.0.is_some()) {
            if group.iter().any(|e| e.3 != value.3) {
                return Err(unordered(value.4));
            }
        }
    }
    let mut within_limit = limits.is_empty();
    for (at, value) in &limits {
        class(at, value)?;
        within_limit |= match at {
            At::Exact(l) => installed < l,
            At::Within(r) => own < *r,
        };
    }
    let seq: Vec<(bool, &str)> = placed.iter().map(|e| (e.2, e.3)).collect();
    let affected = walk(&seq) && within_limit;
    // The OSV service sorts such an event below every version. A version is cleared only
    // when that reading clears it too.
    if let (Some(value), false) = (vague, affected) {
        let mut low: Vec<(Option<&Key>, bool, &str)> = parsed
            .iter()
            .map(|(at, kind, _)| match at {
                Some(At::Exact(k)) if *kind == "last_affected" => (Some(k), installed > k, *kind),
                Some(At::Exact(k)) => (Some(k), installed >= k, *kind),
                _ => (None, true, *kind),
            })
            .collect();
        low.sort_by(|a, b| a.0.cmp(&b.0));
        let seq: Vec<(bool, &str)> = low.iter().map(|e| (e.1, e.2)).collect();
        let limit = limits.is_empty()
            || limits
                .iter()
                .any(|(at, _)| matches!(at, At::Exact(l) if installed < l));
        if walk(&seq) && limit {
            return Err(unordered(value));
        }
    }
    Ok(affected)
}

/// Whether the installed version is in the range, given each event's kind and whether the
/// installed version is past it, in event order.
fn walk(events: &[(bool, &str)]) -> bool {
    let opens = |kind: &str| kind == "introduced";
    let mut affected = false;
    let mut i = 0;
    while i < events.len() {
        let (passed, kind) = events[i];
        if opens(kind) {
            affected |= passed;
            i += 1;
            continue;
        }
        // A run of closing events with no introduced between them. With a fixed in it, the
        // first event passed closes the range (the spec); a run of only last_affected
        // matches up to its highest, as osv.dev does.
        let end = events[i..]
            .iter()
            .position(|(_, k)| opens(k))
            .map_or(events.len(), |n| i + n);
        let run = &events[i..end];
        let mut passed = run.iter().map(|(passed, _)| *passed);
        if run.iter().any(|(_, k)| *k == "fixed") {
            affected &= !passed.any(|p| p);
        } else {
            affected &= !passed.all(|p| p);
        }
        i = end;
    }
    affected
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verdict(ecosystem: &str, version: &str, entry: Value) -> Verdict {
        evaluate(ecosystem, version, "TEST-1", &entry)
    }
    fn range(kind: &str, events: Value) -> Value {
        json!({"ranges":[{"type":kind,"events":events}]})
    }

    #[test]
    fn semver_ranges_follow_precedence_and_event_kinds() {
        let fixed = range("SEMVER", json!([{"introduced":"0"},{"fixed":"1.2.4"}]));
        for (version, expected) in [
            ("1.2.3", Verdict::Affected),
            ("1.2.4-rc.1", Verdict::Affected),
            ("1.2.4", Verdict::NotAffected),
            ("1.2.4+build.7", Verdict::NotAffected),
            ("1.10.0", Verdict::NotAffected),
        ] {
            assert_eq!(
                verdict("npm", version, fixed.clone()),
                expected,
                "{version}"
            );
        }
        let two = range(
            "SEMVER",
            json!([{"introduced":"1.0.0"},{"fixed":"1.5.0"},{"introduced":"2.0.0-alpha.2"},{"last_affected":"2.3.0"}]),
        );
        for (version, expected) in [
            ("0.9.9", Verdict::NotAffected),
            ("1.4.9", Verdict::Affected),
            ("1.5.0", Verdict::NotAffected),
            ("2.0.0-alpha.10", Verdict::Affected),
            ("2.0.0-alpha.1", Verdict::NotAffected),
            ("2.3.0", Verdict::Affected),
            ("2.3.1", Verdict::NotAffected),
        ] {
            assert_eq!(
                verdict("crates.io", version, two.clone()),
                expected,
                "{version}"
            );
        }
        let limited = range("SEMVER", json!([{"introduced":"0"},{"limit":"3.0.0"}]));
        assert_eq!(verdict("npm", "2.9.9", limited.clone()), Verdict::Affected);
        assert_eq!(verdict("npm", "3.0.0", limited), Verdict::NotAffected);
        // A partial version in an advisory is padded with zeros, as OSV does.
        let partial = range("ECOSYSTEM", json!([{"introduced":"0"},{"fixed":"0.10"}]));
        assert_eq!(
            verdict("crates.io", "0.9.1", partial.clone()),
            Verdict::Affected
        );
        assert_eq!(
            verdict("crates.io", "0.10.0", partial),
            Verdict::NotAffected
        );
    }

    #[test]
    fn go_versions_accept_the_v_prefix_pseudo_versions_and_toolchain_releases() {
        let entry = range("SEMVER", json!([{"introduced":"0"},{"fixed":"0.17.0"}]));
        assert_eq!(verdict("Go", "v0.16.0", entry.clone()), Verdict::Affected);
        assert_eq!(
            verdict("Go", "v0.0.0-20230101000000-abcdef123456", entry.clone()),
            Verdict::Affected
        );
        assert_eq!(
            verdict("Go", "v0.17.0+incompatible", entry),
            Verdict::NotAffected
        );
        let stdlib = range(
            "SEMVER",
            json!([{"introduced":"1.21.0"},{"fixed":"1.21.5"}]),
        );
        assert_eq!(verdict("Go", "1.21", stdlib.clone()), Verdict::Affected);
        assert_eq!(verdict("Go", "1.21.5", stdlib), Verdict::NotAffected);
    }

    #[test]
    fn pypi_ranges_use_pep_440_ordering_and_normal_forms() {
        let entry = range("ECOSYSTEM", json!([{"introduced":"0"},{"fixed":"2.0"}]));
        for (version, expected) in [
            ("1.9", Verdict::Affected),
            ("2.0rc1", Verdict::Affected),
            ("2.0.dev3", Verdict::Affected),
            ("2.0a1.post2", Verdict::Affected),
            ("2.0.0", Verdict::NotAffected),
            ("2.0.post1", Verdict::NotAffected),
            ("2.0+local.1", Verdict::NotAffected),
            ("1!0.1", Verdict::NotAffected),
            ("10.0", Verdict::NotAffected),
        ] {
            assert_eq!(
                verdict("PyPI", version, entry.clone()),
                expected,
                "{version}"
            );
        }
        let listed = json!({"versions":["1.0.0","1.1"]});
        assert_eq!(verdict("PyPI", "1.0", listed.clone()), Verdict::Affected);
        assert_eq!(verdict("PyPI", "1.1.0", listed.clone()), Verdict::Affected);
        assert_eq!(verdict("PyPI", "1.2", listed), Verdict::NotAffected);
    }

    #[test]
    fn upgrades_stay_on_the_installed_release_line_lowest_first() {
        let up = |eco, installed, fixes: &[&[&'static str]]| {
            upgrades(
                eco,
                installed,
                &fixes.iter().map(|f| f.to_vec()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            up("npm", "2.3.0", &[&["1.20.9", "2.4.0"]]),
            Some(vec!["2.4.0"])
        );
        assert_eq!(
            up("npm", "1.19.17", &[&["2.1.3", "1.19.18"], &["2.1.6"]]),
            Some(vec!["1.19.18", "2.1.6"])
        );
        assert_eq!(
            up("npm", "5.3.1", &[&["6.2.1", "6.2.4", "6.2.3"]]),
            Some(vec!["6.2.1", "6.2.3", "6.2.4"])
        );
        assert_eq!(
            up("npm", "0.4.1", &[&["0.5.0", "0.4.3"]]),
            Some(vec!["0.4.3"])
        );
        assert_eq!(
            up("PyPI", "2.31", &[&["2.32.0", "3.0"]]),
            Some(vec!["2.32.0"])
        );
        assert_eq!(up("npm", "1.0.0", &[&["next"]]), None);
        assert_eq!(up("Maven", "1.0", &[&["2.0"]]), None);
    }

    #[test]
    fn anything_that_cannot_be_ordered_is_unknown_not_clean() {
        let entry = range("ECOSYSTEM", json!([{"introduced":"0"},{"fixed":"2.0"}]));
        for (ecosystem, version, entry) in [
            ("npm", "latest", entry.clone()),
            ("PyPI", "2004d", entry.clone()),
            (
                "npm",
                "1.0.0",
                range("ECOSYSTEM", json!([{"introduced":"0"},{"fixed":"next"}])),
            ),
            (
                "npm",
                "1.0.0",
                range("ECOSYSTEM", json!([{"introduced":"0"},{"fixed":"1.0.0.1"}])),
            ),
            (
                "npm",
                "1.0.0",
                range("ECOSYSTEM", json!([{"introduced":"0"},{"unfixed":"2.0.0"}])),
            ),
            ("npm", "1.0.0", range("ECOSYSTEM", json!([]))),
            ("npm", "1.0.0", range("CUSTOM", json!([{"introduced":"0"}]))),
        ] {
            assert!(
                matches!(
                    verdict(ecosystem, version, entry.clone()),
                    Verdict::Unknown(_)
                ),
                "{ecosystem} {version} {entry}"
            );
        }
        // A git range next to an evaluable range is ignored.
        let both = json!({"ranges":[{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc"}]},{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]});
        assert_eq!(verdict("npm", "1.0.0", both.clone()), Verdict::Affected);
        assert_eq!(verdict("npm", "1.0.1", both), Verdict::NotAffected);
        // Nothing a version query can match: not a finding, but said in a warning.
        for entry in [
            range("GIT", json!([{"introduced":"0"},{"fixed":"abc"}])),
            json!({}),
        ] {
            assert!(
                matches!(
                    verdict("npm", "1.0.0", entry.clone()),
                    Verdict::Unmatched(_)
                ),
                "{entry}"
            );
        }
        // An event known only by its release decides other releases; its own stays unknown.
        let listed = json!({"versions":["2.9.0rc1"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.9.0-NA"}]}]});
        for (version, expected) in [
            ("2.9.0rc1", Some(Verdict::Affected)),
            ("1.10.0", Some(Verdict::Affected)),
            ("2.9.1", Some(Verdict::NotAffected)),
            ("2.9", None),
            ("2.9.0.post1", None),
            ("1!1.0", None),
        ] {
            let got = verdict("PyPI", version, listed.clone());
            match expected {
                Some(expected) => assert_eq!(got, expected, "{version}"),
                None => assert!(matches!(got, Verdict::Unknown(_)), "{version}: {got:?}"),
            }
        }
        let unknown = |ecosystem: &str, version: &str, entry: Value| {
            let got = verdict(ecosystem, version, entry);
            assert!(matches!(got, Verdict::Unknown(_)), "{version}: {got:?}");
        };
        // Two such events of different kinds, listed out of release order.
        unknown(
            "PyPI",
            "3.0",
            range(
                "ECOSYSTEM",
                json!([{"introduced":"5.0.0-NA"},{"fixed":"2.0.0-NA"}]),
            ),
        );
        // Kinds that could come in either order within that release.
        unknown(
            "PyPI",
            "3.0.0",
            range(
                "ECOSYSTEM",
                json!([{"introduced":"0"},{"fixed":"2.0.0-x"},{"introduced":"2.0.0rc1"}]),
            ),
        );
        // A listed version the reading clears: the event means something else.
        unknown(
            "PyPI",
            "3.0.0",
            json!({"versions":["2.0.0"],"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.0.0-NA"}]}]}),
        );
        // Cleared by release but affected as the OSV service reads it, below every version.
        unknown(
            "PyPI",
            "2.0",
            range(
                "ECOSYSTEM",
                json!([{"introduced":"1.0"},{"fixed":"1.5.0-NA"}]),
            ),
        );
        let redis = range(
            "ECOSYSTEM",
            json!([{"introduced":"9.6.0b1"},{"fixed":"9.6.3"}]),
        );
        for version in ["v9.6.0", "v9.5.0"] {
            unknown("Go", version, redis.clone());
        }
        assert_eq!(verdict("Go", "v9.6.2", redis.clone()), Verdict::Affected);
        assert_eq!(verdict("Go", "v9.16.0", redis), Verdict::NotAffected);
        let limited = range("ECOSYSTEM", json!([{"introduced":"0"},{"limit":"2.0.0-x"}]));
        assert_eq!(verdict("PyPI", "1.0", limited.clone()), Verdict::Affected);
        assert_eq!(verdict("PyPI", "3.0", limited), Verdict::NotAffected);
        // Not a release followed by a suffix, or beside an epoch: no place at all.
        for value in ["2.6.x", "2.6-NA", "next", "1!2.0.0-x"] {
            let entry = range("ECOSYSTEM", json!([{"introduced":"0"},{"fixed":value}]));
            unknown("PyPI", "9.0.0", entry);
        }
        unknown(
            "PyPI",
            "9.0.0",
            range(
                "ECOSYSTEM",
                json!([{"introduced":"1!1.0"},{"last_affected":"2.0.0-x"}]),
            ),
        );
    }

    #[test]
    fn odd_event_sequences_are_affected_or_unknown_never_clean() {
        let check = |events: Value, rows: &[(&str, Option<bool>)]| {
            for (version, expected) in rows {
                let got = verdict("PyPI", version, range("ECOSYSTEM", events.clone()));
                let ok = match expected {
                    Some(true) => got == Verdict::Affected,
                    Some(false) => got == Verdict::NotAffected,
                    None => matches!(got, Verdict::Unknown(_)),
                };
                assert!(ok, "{events} at {version}: {got:?}");
            }
        };
        // Several last_affected after one introduced: OSV matches up to the highest.
        check(
            json!([{"introduced":"0"},{"last_affected":"1.0.0"},{"last_affected":"2.0.0"}]),
            &[
                ("0.5", Some(true)),
                ("1.5.0", Some(true)),
                ("2.0.0", Some(true)),
                ("2.0.1", Some(false)),
            ],
        );
        // A run of closing events with a fixed in it closes at the first one passed.
        for events in [
            json!([{"introduced":"0"},{"fixed":"1.0.0"},{"last_affected":"2.0.0"}]),
            json!([{"introduced":"0"},{"fixed":"1.0.0"},{"fixed":"2.0.0"}]),
            json!([{"introduced":"0"},{"last_affected":"1.0.0"},{"fixed":"2.0.0"}]),
        ] {
            check(
                events,
                &[
                    ("0.5", Some(true)),
                    ("1.5.0", Some(false)),
                    ("2.0.1", Some(false)),
                ],
            );
        }
        // PYSEC-2022-43170 (tryton): the fixed events of each branch come at the end.
        check(
            json!([{"introduced":"5.0.0"},{"fixed":"5.0.12"},{"introduced":"6.0.0"},{"fixed":"6.0.5"},
                   {"introduced":"6.2.0"},{"fixed":"6.2.2"},{"fixed":"6.2.6"},{"fixed":"6.0.16"},{"fixed":"5.0.46"}]),
            &[
                ("5.0.11", Some(true)),
                ("5.0.20", Some(false)),
                ("6.0.10", Some(false)),
                ("6.2.1", Some(true)),
                ("6.2.4", Some(false)),
            ],
        );
        // Several introduced before one fixed, and events in any order.
        for events in [
            json!([{"introduced":"0"},{"introduced":"1.0.0"},{"fixed":"2.0.0"}]),
            json!([{"fixed":"2.0.0"},{"introduced":"1.0.0"},{"introduced":"0"}]),
        ] {
            check(
                events,
                &[
                    ("0.5", Some(true)),
                    ("1.5.0", Some(true)),
                    ("2.0.0", Some(false)),
                ],
            );
        }
        check(
            json!([{"fixed":"2.0.0"},{"introduced":"1.0.0"}]),
            &[
                ("0.5", Some(false)),
                ("1.5.0", Some(true)),
                ("2.0.0", Some(false)),
            ],
        );
        // Events at one version keep their input order, as the OSV spec sorts.
        check(
            json!([{"last_affected":"1.0.0"},{"introduced":"1.0.0"}]),
            &[
                ("0.5", Some(false)),
                ("1.0.0", Some(true)),
                ("1.5.0", Some(true)),
            ],
        );
        check(
            json!([{"introduced":"1.0.0"},{"fixed":"1.0.0"}]),
            &[
                ("0.5", Some(false)),
                ("1.0.0", Some(false)),
                ("1.5.0", Some(false)),
            ],
        );
        // RUSTSEC-2024-0399 (rustls): `introduced X, fixed X` marks an unaffected branch.
        check(
            json!([{"introduced":"0.23.0"},{"fixed":"0.23.0"},{"introduced":"0.23.13"},{"fixed":"0.23.18"}]),
            &[
                ("0.22.4", Some(false)),
                ("0.23.0", Some(false)),
                ("0.23.5", Some(false)),
                ("0.23.13", Some(true)),
                ("0.23.17", Some(true)),
                ("0.23.18", Some(false)),
                ("0.23.20", Some(false)),
            ],
        );
        // PYSEC-2024-258 (scrapy): `fixed X, introduced X` is affected again from X.
        check(
            json!([{"introduced":"0"},{"fixed":"2.0.0"},{"introduced":"2.0.0"},{"fixed":"2.11.2"}]),
            &[
                ("1.8.0", Some(true)),
                ("2.0.0", Some(true)),
                ("2.5.0", Some(true)),
                ("2.11.2", Some(false)),
                ("2.13.3", Some(false)),
            ],
        );
    }
}
