use super::{error, rx};
use crate::{Error, Result};
use serde_json::Value;

pub(super) fn display(s: &str) -> String {
    let mut text: String = s.chars().take(96).collect();
    if s.chars().nth(96).is_some() {
        text.push_str("...");
    }
    format!("{text:?}")
}

pub(super) fn invalid(name: &str, version: &str) -> Error {
    error(format!(
        "invalid package entry: name {}, version {}",
        display(name),
        display(version)
    ))
}

fn simple(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub(super) fn name(name: &str, version: &str, ecosystem: &str) -> Result<()> {
    let component = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    };
    let valid_name = match ecosystem {
        "npm" => {
            let n = name.strip_prefix('@').unwrap_or(name);
            if name.starts_with('@') {
                n.split_once('/')
                    .is_some_and(|(scope, package)| component(scope) && component(package))
            } else {
                component(n)
            }
        }
        "Packagist" => name
            .split_once('/')
            .is_some_and(|(vendor, package)| component(vendor) && component(package)),
        "crates.io" | "PyPI" | "RubyGems" | "NuGet" => component(name),
        "Go" => !name.starts_with('/') && !name.ends_with('/') && name.split('/').all(component),
        _ => true,
    };
    if !simple(name, 1024) || !valid_name {
        return Err(invalid(name, version));
    }
    Ok(())
}

pub(super) fn entry(name: &str, version: &str, ecosystem: &str) -> Result<()> {
    self::name(name, version, ecosystem)?;
    let exact = version
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"._-+!".contains(&c))
        && version.bytes().any(|c| c.is_ascii_digit())
        && !version.starts_with(['.', '-', '+', '_']);
    // Composer also locks branch versions such as dev-main and 1.x-dev.
    let exact = exact
        || ecosystem == "Packagist"
            && version.starts_with("dev-")
            && version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-+/".contains(&c));
    let core = version
        .strip_prefix('v')
        .unwrap_or(version)
        .split(['-', '+'])
        .next()
        .unwrap_or("");
    let numeric_core = core
        .split('.')
        .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()));
    let exact = exact
        && match ecosystem {
            "npm" | "crates.io" | "Go" => core.split('.').count() == 3 && numeric_core,
            "NuGet" => (1..=4).contains(&core.split('.').count()) && numeric_core,
            "PyPI" => {
                static VERSION: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
                VERSION.get_or_init(|| rx(r"(?ix)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$")).is_match(version)
            }
            "Packagist" => version.starts_with("dev-") || version.ends_with("-dev") || numeric_core,
            _ => true,
        };
    if !simple(version, 256) || !exact {
        return Err(invalid(name, version));
    }
    Ok(())
}

/// Entry-level problem: this entry is not queried; the file's other entries still are.
pub(super) fn uncheckable(name: &str, source: &str) -> String {
    format!(
        "Entry-level: Uncheckable package entry {}, version/source {}: not an exact registry name@version, so it was not checked; check this dependency by hand",
        display(name),
        display(source)
    )
}

/// A requirements line naming a package with no exact version: not queried.
pub(super) fn unpinned(name: &str, line: usize, file: &str) -> String {
    format!("line {line}: {name} was not checked because it is not pinned to one version. Fix: pin it as {name}==VERSION, or generate a lockfile (example: `uv pip compile {file}`).")
}

fn malformed(name: &str, version: &str) -> String {
    format!(
        "Entry-level: Uncheckable package entry {}, version {}: name or version fails validation, so it was not checked; regenerate the lockfile or check this dependency by hand",
        display(name),
        display(version)
    )
}

pub(super) fn entry_issue(name: &str, version: &str, ecosystem: &str) -> Option<String> {
    if source(version) {
        Some(uncheckable(name, version))
    } else {
        entry(name, version, ecosystem)
            .err()
            .map(|_| malformed(name, version))
    }
}

pub(super) fn file(problem: Error) -> Error {
    if problem.message.starts_with("File-level:") {
        problem
    } else {
        error(format!(
            "File-level: {}; regenerate the lockfile with a supported tool version",
            problem.message
        ))
    }
}

/// A lockfile-relative path that stays inside the project (a workspace member or the root).
pub(super) fn inside_project(path: &str) -> bool {
    !path.starts_with(['/', '\\'])
        && !path.contains(':')
        && !path.split(['/', '\\']).any(|part| part == "..")
}

/// Wildcard `workspaces` patterns one root may list. Each costs a compare per member key;
/// real monorepos list a handful (`packages/*`, `apps/*`). Exact folder names are looked up,
/// not compared; up to the per-input cap of those is fine.
pub(super) const MAX_WORKSPACE_PATTERNS: usize = 128;
/// Path segments in one wildcard pattern (`a/b/*` is three).
const MAX_PATTERN_SEGMENTS: usize = 16;

/// The members named by a root entry's `workspaces` globs (an array, or an object with a
/// `packages` array), compiled once per lock. `!` globs exclude. Globs come from the file, so
/// matching stays linear: one `*` per segment, `**` only at the end; anything else matches
/// nothing and the entry stays uncheckable.
#[derive(Default)]
pub(super) struct Workspaces {
    exact: std::collections::HashSet<String>,
    excluded: std::collections::HashSet<String>,
    /// (exclude, segments, ends in `**`)
    patterns: Vec<(bool, Vec<String>, bool)>,
}

impl Workspaces {
    /// `Err` holds the reason when the list is over the pattern bounds, so members cannot be
    /// told apart and coverage is unknown.
    pub(super) fn new(root: Option<&Value>) -> std::result::Result<Self, String> {
        let globs = root
            .and_then(|r| r.get("workspaces"))
            .map(|w| w.get("packages").unwrap_or(w));
        let mut out = Self::default();
        let mut seen = std::collections::HashSet::new();
        let over = || {
            format!("File-level: the root `workspaces` lists more than {MAX_WORKSPACE_PATTERNS} wildcard patterns, or one longer than {MAX_PATTERN_SEGMENTS} folders, so workspace members cannot be told apart; none of its packages were checked; coverage is unknown")
        };
        for glob in globs.and_then(Value::as_array).into_iter().flatten() {
            let Some(glob) = glob.as_str() else { continue };
            let (exclude, glob) = match glob.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, glob),
            };
            let glob = glob.trim_start_matches("./").trim_end_matches('/');
            if !glob.contains('*') {
                // A lock holds at most the per-input cap of members, so a longer list of folder
                // names is not a real workspace and is not copied.
                if out.exact.len() + out.excluded.len() >= super::MAX_INPUT_PACKAGES {
                    return Err(format!("File-level: the root `workspaces` lists more folder names than the per-input cap of {}, so workspace members cannot be told apart; none of its packages were checked; coverage is unknown", super::MAX_INPUT_PACKAGES));
                }
                let set = if exclude {
                    &mut out.excluded
                } else {
                    &mut out.exact
                };
                set.insert(glob.to_owned());
                continue;
            }
            if glob.matches('/').count() >= MAX_PATTERN_SEGMENTS {
                return Err(over());
            }
            let mut segments: Vec<String> = glob.split('/').map(str::to_owned).collect();
            let rest = segments.last().is_some_and(|s| s == "**");
            if rest {
                segments.pop();
            }
            // Duplicates cost a compare each and match nothing new.
            let pattern = (exclude, segments, rest);
            if seen.insert(pattern.clone()) {
                if out.patterns.len() == MAX_WORKSPACE_PATTERNS {
                    return Err(over());
                }
                out.patterns.push(pattern);
            }
        }
        Ok(out)
    }

    pub(super) fn member(&self, key: &str) -> bool {
        fn segment(glob: &str, part: &str) -> bool {
            match glob.split_once('*') {
                None => glob == part,
                Some((head, tail)) => {
                    !tail.contains('*')
                        && part.len() >= head.len() + tail.len()
                        && part.starts_with(head)
                        && part.ends_with(tail)
                }
            }
        }
        if self.excluded.contains(key) {
            return false;
        }
        let parts: Vec<_> = key.split('/').collect();
        let mut member = self.exact.contains(key);
        for (exclude, glob, rest) in &self.patterns {
            if member && !exclude {
                continue;
            }
            let fits = if *rest {
                parts.len() >= glob.len()
            } else {
                parts.len() == glob.len()
            };
            if fits && glob.iter().zip(&parts).all(|(g, p)| segment(g, p)) {
                if *exclude {
                    return false;
                }
                member = true;
            }
        }
        member
    }
}

pub(super) fn source(version: &str) -> bool {
    [
        "git+",
        "git:",
        "git@",
        "ssh:",
        "http:",
        "https:",
        "file:",
        "path:",
        "workspace:",
        "github:",
        "gitlab:",
        "bitbucket:",
        "link:",
        "portal:",
        "../",
        "./",
        "/",
    ]
    .iter()
    .any(|prefix| version.starts_with(prefix))
}

pub(super) fn locator(key: &str) -> Option<(&str, &str)> {
    let offset = usize::from(key.starts_with('@'));
    let split = key.get(offset..)?.find('@')? + offset;
    Some((&key[..split], &key[split + 1..]))
}

/// Largest TOML or YAML lockfile read. Real-shaped locks at the package cap measured up to 31 MB.
pub(super) const MAX_LOCK_BYTES: usize = 48_000_000;
/// The TOML parser builds its whole document before anything sees it, so a TOML file is
/// weighed first: 1 for each `=`, `,` and line, 3 for `[`, 6 for `{` and each dot of a
/// dotted key: every node the parser makes starts at one of these. Real-shaped locks at the
/// package cap measured up to 2.1 million.
pub(super) const MAX_TOML_COST: usize = 3_000_000;
/// Most items in one TOML array or inline table. The parser holds one huge collection at
/// several times the weight above; real-shaped locks at the package cap stay far below it.
const MAX_TOML_ITEMS: usize = 10_000;
/// Deepest nesting read; deep flow nesting is slow to scan, and no lockfile needs it.
pub(super) const MAX_LOCK_DEPTH: usize = 64;
/// Estimated bytes the YAML parser may hold for one file: the file text, its buffered events
/// and the document built from them, all counted as they are made. Real-shaped pnpm locks
/// at the package cap are charged up to 76% of it.
const MAX_YAML_MEMORY: usize = 768_000_000;
/// Longest a YAML lockfile may take to parse; the event walk gets half of it, as the
/// parser's own pass over the same events takes about as long again.
const MAX_YAML_SECONDS: u64 = 30;
/// Most lines starting with `%` (YAML directives) in a pnpm lockfile; pnpm writes none, and
/// the parser checks each `%TAG` against every earlier one.
const MAX_YAML_DIRECTIVES: usize = 8;
/// serde_norway buffers each parser event in a 96-byte slot of a growing Vec.
const EVENT_BYTES: usize = 128;
/// The least a heap allocation costs, beyond its bytes.
const ALLOC_BYTES: usize = 32;
/// What serde_norway's two anchor maps keep for each anchored node.
const ANCHOR_BYTES: usize = 64;

fn too_large(detail: &str) -> Error {
    error(format!("File-level: too large or too deeply nested to read safely ({detail}); none of its packages were checked; coverage is unknown"))
}

fn byte_cap(text: &str) -> Result<()> {
    if text.len() > MAX_LOCK_BYTES {
        return Err(error(format!("File-level: {} bytes, too large to read safely (limit {MAX_LOCK_BYTES} bytes for a TOML or YAML lockfile); none of its packages were checked; coverage is unknown", text.len())));
    }
    Ok(())
}

/// Refuse a TOML document too large or too deeply nested to parse within bounds.
pub(super) fn toml_bounded(text: &str) -> Result<()> {
    byte_cap(text)?;
    let bytes = text.as_bytes();
    let mut cost = 0usize;
    for &b in bytes {
        cost += match b {
            b'{' => 6,
            b'[' => 3,
            b',' | b'=' | b'\n' => 1,
            _ => 0,
        };
    }
    // Brackets inside strings and comments are text, not nesting.
    let (dots, items, deepest) = toml_structure(bytes);
    cost += 6 * dots;
    if cost > MAX_TOML_COST || deepest > MAX_LOCK_DEPTH {
        return Err(too_large(&format!(
            "weight {cost}, nesting {deepest}; limits {MAX_TOML_COST} and {MAX_LOCK_DEPTH}"
        )));
    }
    if items > MAX_TOML_ITEMS {
        return Err(too_large(&format!(
            "one array or inline table holds over {MAX_TOML_ITEMS} items"
        )));
    }
    Ok(())
}

/// Parser memory and time a YAML file may still use. Memory is charged as each event and
/// each value is made, so whatever the syntax (aliases, tags, flow pairs, merge keys),
/// nothing is built past it; every charge also checks the clock.
struct Budget {
    left: std::cell::Cell<Option<usize>>,
    deadline: std::cell::Cell<std::time::Instant>,
    slow: std::cell::Cell<bool>,
}

impl Budget {
    fn charge(&self, bytes: usize) -> bool {
        if std::time::Instant::now() > self.deadline.get() {
            self.slow.set(true);
            self.left.set(None);
        }
        let left = self.left.get().and_then(|left| left.checked_sub(bytes));
        self.left.set(left);
        left.is_some()
    }

    fn exceeded(&self) -> Error {
        if self.slow.get() {
            return error(format!("File-level: too slow to read safely (parsing ran over {MAX_YAML_SECONDS} seconds); none of its packages were checked; coverage is unknown"));
        }
        too_large(&format!("parsing would hold over {MAX_YAML_MEMORY} bytes"))
    }
}

/// What a heap copy of `len` bytes costs.
fn heap(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len + ALLOC_BYTES
    }
}

/// Walk the YAML stream with libyaml, the parser serde_norway runs, and charge each event it
/// would buffer, with its value, tag and anchor bytes. Nothing is kept. A syntax error ends
/// the walk; serde_norway then reports it, having buffered no more than was charged here.
fn yaml_events(text: &str, budget: &Budget) -> Result<()> {
    use std::{ffi::CStr, mem::MaybeUninit};
    use unsafe_libyaml_norway as unsafe_yaml;
    struct Parser(Box<MaybeUninit<unsafe_yaml::yaml_parser_t>>);
    impl Drop for Parser {
        fn drop(&mut self) {
            // SAFETY: built only after `yaml_parser_initialize` succeeded.
            unsafe { unsafe_yaml::yaml_parser_delete(self.0.as_mut_ptr()) }
        }
    }
    let mut slot = Box::new(MaybeUninit::uninit());
    // SAFETY: the parser lives in a box, so the pointer it keeps to itself stays valid, and it
    // reads `text`, which outlives it.
    if !unsafe { unsafe_yaml::yaml_parser_initialize(slot.as_mut_ptr()) }.ok {
        return Err(error(
            "File-level: the YAML parser could not start; coverage is unknown",
        ));
    }
    let mut parser = Parser(slot);
    let p = parser.0.as_mut_ptr();
    unsafe {
        unsafe_yaml::yaml_parser_set_encoding(p, unsafe_yaml::YAML_UTF8_ENCODING);
        unsafe_yaml::yaml_parser_set_input_string(p, text.as_ptr(), text.len() as _);
    }
    let text_len = |ptr: *const u8| {
        if ptr.is_null() {
            return 0;
        }
        // SAFETY: libyaml's anchors and tags are null or NUL-terminated.
        heap(unsafe { CStr::from_ptr(ptr.cast()) }.to_bytes().len())
    };
    let mut depth = 0usize;
    loop {
        let mut event = MaybeUninit::<unsafe_yaml::yaml_event_t>::uninit();
        let e = event.as_mut_ptr();
        // SAFETY: a parsed event is read by its type's union field, then freed once.
        let (cost, opens, done) = unsafe {
            if !unsafe_yaml::yaml_parser_parse(p, e).ok {
                return Ok(());
            }
            let data = &(*e).data;
            let none = std::ptr::null_mut();
            // (anchor, tag, value length, nesting change) of each event serde_norway keeps.
            let kept = match (*e).type_ {
                unsafe_yaml::YAML_SCALAR_EVENT => {
                    let s = data.scalar;
                    Some((s.anchor, s.tag, s.length as usize, 0))
                }
                unsafe_yaml::YAML_SEQUENCE_START_EVENT => {
                    let s = data.sequence_start;
                    Some((s.anchor, s.tag, 0, 1))
                }
                unsafe_yaml::YAML_MAPPING_START_EVENT => {
                    let s = data.mapping_start;
                    Some((s.anchor, s.tag, 0, 1))
                }
                unsafe_yaml::YAML_SEQUENCE_END_EVENT | unsafe_yaml::YAML_MAPPING_END_EVENT => {
                    Some((none, none, 0, -1))
                }
                unsafe_yaml::YAML_ALIAS_EVENT => Some((none, none, 0, 0)),
                _ => None,
            };
            let step = kept.map_or((0, 0), |(anchor, tag, len, opens)| {
                let anchor = text_len(anchor);
                let anchor = anchor + anchor.min(1) * ANCHOR_BYTES;
                (EVENT_BYTES + heap(len) + text_len(tag) + anchor, opens)
            });
            let done = (*e).type_ == unsafe_yaml::YAML_STREAM_END_EVENT;
            unsafe_yaml::yaml_event_delete(e);
            (step.0, step.1, done)
        };
        depth = depth.saturating_add_signed(opens);
        if depth > MAX_LOCK_DEPTH {
            return Err(too_large(&format!("nesting over {MAX_LOCK_DEPTH}")));
        }
        if !budget.charge(cost) {
            return Err(budget.exceeded());
        }
        if done {
            return Ok(());
        }
    }
}

/// Builds a serde_norway `Value` exactly as its own `Deserialize` does, charging each node,
/// string and tag to the budget before making it. An alias replays its anchor's events
/// through here, so every copy is charged.
#[derive(Clone, Copy)]
struct Budgeted<'b>(&'b Budget);

impl Budgeted<'_> {
    fn take<E: serde::de::Error>(self, bytes: usize) -> std::result::Result<(), E> {
        if self.0.charge(bytes) {
            Ok(())
        } else {
            Err(E::custom("over the memory budget"))
        }
    }
}

const VALUE: usize = std::mem::size_of::<serde_norway::Value>();
/// A sequence slot, or one map entry (key, value, hash and index), with room to grow; the
/// first element also pays for the least a sequence (4 slots) or a map (3 entries) allocates.
const SLOT_BYTES: usize = 2 * VALUE;
const FIRST_SLOT_BYTES: usize = 4 * VALUE + ALLOC_BYTES;
const ENTRY_BYTES: usize = 2 * (2 * VALUE + 16);
const FIRST_ENTRY_BYTES: usize = 3 * (2 * VALUE + 8) + 64 + 2 * ALLOC_BYTES;

impl<'de> serde::de::DeserializeSeed<'de> for Budgeted<'_> {
    type Value = serde_norway::Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for Budgeted<'_> {
    type Value = serde_norway::Value;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any YAML value")
    }
    fn visit_bool<E>(self, b: bool) -> std::result::Result<Self::Value, E> {
        Ok(serde_norway::Value::Bool(b))
    }
    fn visit_i64<E>(self, n: i64) -> std::result::Result<Self::Value, E> {
        Ok(serde_norway::Value::Number(n.into()))
    }
    fn visit_u64<E>(self, n: u64) -> std::result::Result<Self::Value, E> {
        Ok(serde_norway::Value::Number(n.into()))
    }
    fn visit_f64<E>(self, n: f64) -> std::result::Result<Self::Value, E> {
        Ok(serde_norway::Value::Number(n.into()))
    }
    fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<Self::Value, E> {
        self.take(heap(s.len()))?;
        Ok(serde_norway::Value::String(s.to_owned()))
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_norway::Value::Null)
    }
    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(serde_norway::Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Self::Value, D::Error> {
        serde::de::DeserializeSeed::deserialize(self, d)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = {
            self.take(if items.is_empty() {
                FIRST_SLOT_BYTES
            } else {
                SLOT_BYTES
            })?;
            seq.next_element_seed(self)?
        } {
            items.push(item);
        }
        Ok(serde_norway::Value::Sequence(items))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        use serde_norway::mapping::Entry;
        let mut mapping = serde_norway::Mapping::new();
        while let Some(key) = {
            self.take(if mapping.is_empty() {
                FIRST_ENTRY_BYTES
            } else {
                ENTRY_BYTES
            })?;
            map.next_key_seed(self)?
        } {
            match mapping.entry(key) {
                Entry::Occupied(entry) => {
                    use serde_norway::Value as V;
                    let which = match entry.key() {
                        V::Null => "with null key".to_string(),
                        V::Bool(b) => format!("with key `{b}`"),
                        V::Number(n) => format!("with key {n}"),
                        V::String(s) => format!("with key {s:?}"),
                        _ => "in YAML map".to_string(),
                    };
                    return Err(serde::de::Error::custom(format_args!(
                        "duplicate entry {which}"
                    )));
                }
                Entry::Vacant(entry) => {
                    entry.insert(map.next_value_seed(self)?);
                }
            }
        }
        Ok(serde_norway::Value::Mapping(mapping))
    }
    fn visit_enum<A: serde::de::EnumAccess<'de>>(
        self,
        data: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        use serde::de::VariantAccess;
        let (tag, contents): (String, _) = data.variant()?;
        if tag.is_empty() {
            return Err(serde::de::Error::custom("empty YAML tag is not allowed"));
        }
        self.take(heap(tag.len()) + heap(std::mem::size_of::<serde_norway::value::TaggedValue>()))?;
        let value = contents.newtype_variant_seed(self)?;
        Ok(serde_norway::Value::Tagged(Box::new(
            serde_norway::value::TaggedValue {
                tag: serde_norway::value::Tag::new(tag),
                value,
            },
        )))
    }
}

/// Outside TOML strings and comments: the dots (each one in a dotted key makes a table), and
/// the most items in one array or inline table.
fn toml_structure(text: &[u8]) -> (usize, usize, usize) {
    let run = |at: usize, quote: u8| text[at..].iter().take_while(|&&c| c == quote).count();
    let (mut dots, mut i) = (0, 0);
    // Items so far in each open collection; nesting past the limit shares the innermost.
    let (mut open, mut past, mut most, mut deepest) = (vec![], 0usize, 0usize, 0usize);
    while i < text.len() {
        match text[i] {
            b'#' => {
                i += text[i..].iter().take_while(|&&c| c != b'\n').count();
                continue;
            }
            quote @ (b'"' | b'\'') => {
                let open = run(i, quote).min(3);
                i += open;
                if open == 2 {
                    continue; // an empty string
                }
                // Skip to the closing quote(s); a basic string's backslash escapes one byte.
                while i < text.len() {
                    let c = text[i];
                    if quote == b'"' && c == b'\\' {
                        i += 2;
                    } else if c == quote {
                        let close = run(i, quote);
                        i += if open == 3 { close } else { 1 };
                        if open == 1 || close >= 3 {
                            break;
                        }
                    } else if c == b'\n' && open == 1 {
                        break;
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            b'.' => dots += 1,
            b'[' | b'{' => {
                if open.len() < MAX_LOCK_DEPTH {
                    open.push(1);
                } else {
                    past += 1;
                }
                deepest = deepest.max(open.len() + past);
            }
            b']' | b'}' if past > 0 => past -= 1,
            b']' | b'}' => {
                open.pop();
            }
            b',' => {
                if let Some(items) = open.last_mut() {
                    *items += 1;
                    most = most.max(*items);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (dots, most, deepest)
}

/// A Cargo, uv, Poetry or PEP 751 lockfile read by a TOML parser, with its format marker checked.
/// Markers come from the root table (Poetry: `[metadata]`), never from a nested table.
pub(super) fn toml_lock(name: &str, text: &str) -> Result<toml::Table> {
    toml_bounded(text)?;
    let data: toml::Table = text.parse().map_err(|e: toml::de::Error| {
        let line = e
            .span()
            .map_or(0, |s| text[..s.start.min(text.len())].matches('\n').count());
        error(format!(
            "File-level: invalid TOML at line {}: {} (line {}); regenerate the lockfile with a supported tool version",
            line + 1,
            e.message().lines().next().unwrap_or(""),
            display(text.lines().nth(line).unwrap_or(""))
        ))
    })?;
    // An integer marker written as a string (or the reverse) is not the format version.
    let require_toml = |value: Option<&toml::Value>, supported: &[&str], marker: &str| match value {
        None => require(None, supported, marker),
        Some(toml::Value::Integer(n)) if name != "poetry.lock" => {
            require(Some(&n.to_string()), supported, marker)
        }
        Some(toml::Value::String(s)) if name == "poetry.lock" || super::pylock(name) => {
            require(Some(s), supported, marker)
        }
        Some(other) => Err(version_error(
            Some(display(&other.to_string())),
            supported,
            marker,
        )),
    };
    match name {
        // Cargo formats 1 and 2 have no root format marker.
        "Cargo.lock" if data.get("version").is_none() => {}
        "Cargo.lock" => require_toml(data.get("version"), &["1", "2", "3", "4"], "version")?,
        _ if super::pylock(name) => {
            require_toml(data.get("lock-version"), &["1.0"], "lock-version")?
        }
        "uv.lock" => {
            require_toml(data.get("version"), &["1"], "version")?;
            if let Some(revision) = data.get("revision") {
                require_toml(Some(revision), &["1", "2", "3", "4", "5"], "revision")?;
            }
        }
        _ => require_toml(
            data.get("metadata").and_then(|m| m.get("lock-version")),
            &["1.0", "1.1", "2.0", "2.1"],
            "lock-version",
        )?,
    }
    Ok(data)
}

/// A pnpm lockfile read by a YAML parser, one value per document: pnpm 11 and later write
/// the package manager's own lock as a first document before the project's. `format`
/// already checked the first marker line; every parsed root must carry a supported version.
pub(super) fn pnpm_lock(text: &str) -> Result<Vec<serde_norway::Value>> {
    byte_cap(text)?;
    // A directive starts a line; libyaml also breaks lines at CR, NEL, LS and PS.
    let (mut directives, mut line_start) = (0, true);
    for c in text.chars() {
        directives += usize::from(line_start && c == '%');
        line_start = matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
            || (line_start && c == '\u{feff}');
    }
    if directives > MAX_YAML_DIRECTIVES {
        return Err(error(format!("File-level: holds {directives} directive lines (`%`), over the limit of {MAX_YAML_DIRECTIVES}; pnpm writes none, and they are slow to parse; none of its packages were checked; coverage is unknown")));
    }
    // One budget for the file text and both stages: the events serde_norway buffers, then
    // the value built. The event walk must finish in half the time.
    let (started, limit) = (
        std::time::Instant::now(),
        std::time::Duration::from_secs(MAX_YAML_SECONDS),
    );
    let budget = Budget {
        left: std::cell::Cell::new(MAX_YAML_MEMORY.checked_sub(text.len())),
        deadline: std::cell::Cell::new(started + limit / 2),
        slow: std::cell::Cell::new(false),
    };
    yaml_events(text, &budget)?;
    budget.deadline.set(started + limit);
    let mut documents = Vec::new();
    // After a parse error the iterator yields the same error forever, so stop at the first.
    for document in serde_norway::Deserializer::from_str(text) {
        let data = serde::de::DeserializeSeed::deserialize(Budgeted(&budget), document)
            .map_err(|e| {
                if budget.left.get().is_none() {
                    return budget.exceeded();
                }
                error(format!(
                "File-level: invalid YAML: {}; regenerate the lockfile with a supported tool version",
                display(&e.to_string())
            ))
            })?;
        let version = match data.get("lockfileVersion") {
            Some(serde_norway::Value::String(s)) => Some(s.clone()),
            Some(serde_norway::Value::Number(n)) => Some(n.to_string()),
            _ => None,
        };
        require(version.as_deref(), &["6.0", "9.0"], "lockfileVersion")?;
        documents.push(data);
    }
    if documents.is_empty() {
        require(None, &["6.0", "9.0"], "lockfileVersion")?;
    }
    Ok(documents)
}

fn require(found: Option<&str>, supported: &[&str], marker: &str) -> Result<()> {
    if found.is_some_and(|v| supported.contains(&v)) {
        return Ok(());
    }
    Err(version_error(found.map(display), supported, marker))
}

fn version_error(found: Option<String>, supported: &[&str], marker: &str) -> Error {
    let problem = found
        .map(|v| format!("unsupported {marker} {v}"))
        .unwrap_or_else(|| format!("missing {marker}"));
    error(format!("File-level: {problem}; supported versions: {}; regenerate the lockfile with a supported tool version", supported.join(", ")))
}

fn require_json(value: Option<&Value>, supported: &[&str], marker: &str) -> Result<()> {
    match value {
        Some(Value::Number(n)) => require(Some(&n.to_string()), supported, marker),
        None => require(None, supported, marker),
        Some(Value::String(s)) => Err(version_error(
            Some(format!("string {}", display(s))),
            supported,
            marker,
        )),
        Some(other) => Err(version_error(
            Some(display(&other.to_string())),
            supported,
            marker,
        )),
    }
}

fn scalar<'a>(text: &'a str, pattern: &str) -> Option<&'a str> {
    rx(pattern)
        .captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
}

fn yaml_marker<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let pattern = format!(
        r#"(?m)^{prefix}[ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^#\r\n'"]*?))(?:[ \t]+#.*)?[ \t\r]*$"#
    );
    let captures = rx(&pattern).captures(text)?;
    if let Some(value) = captures.get(1).or_else(|| captures.get(2)) {
        Some(value.as_str())
    } else {
        captures.get(3).map(|value| value.as_str().trim())
    }
}

pub(super) fn format(name: &str, text: &str) -> Result<()> {
    match name {
        "package-lock.json" | "Pipfile.lock" | "packages.lock.json" => {
            let data: Value = serde_json::from_str(text)?;
            let (marker, supported): (&str, &[&str]) = match name {
                "package-lock.json" => ("lockfileVersion", &["1", "2", "3"]),
                "Pipfile.lock" => ("/_meta/pipfile-spec", &["6"]),
                _ => ("version", &["1", "2"]),
            };
            let value = if marker.starts_with('/') {
                data.pointer(marker)
            } else {
                data.get(marker)
            };
            require_json(
                value,
                supported,
                &marker.trim_start_matches('/').replace('/', "."),
            )
        }
        "bun.lock" => {
            let data = crate::scanner::agentbom::discover::jsonc(text)?;
            require_json(
                data.get("lockfileVersion"),
                &["0", "1", "2"],
                "lockfileVersion",
            )?;
            if let Some(version) = data.get("configVersion") {
                require_json(Some(version), &["1"], "configVersion")?;
            }
            Ok(())
        }
        "pnpm-lock.yaml" => require(
            yaml_marker(
                text,
                r#"(?:lockfileVersion|"lockfileVersion"|'lockfileVersion'):"#,
            ),
            &["6.0", "9.0"],
            "lockfileVersion",
        ),
        "yarn.lock" => {
            if let Some(metadata) = rx(r#"(?m)^['"]?__metadata['"]?:[ \t]*"#).find(text) {
                let meta = &text[metadata.end()..];
                let block: String = meta
                    .lines()
                    .skip(1)
                    .take_while(|l| l.is_empty() || l.starts_with(char::is_whitespace))
                    .map(|l| format!("{l}\n"))
                    .collect();
                require(
                    yaml_marker(&block, r#"  (?:version|"version"|'version'):"#),
                    &["8", "10"],
                    "Yarn __metadata",
                )
            } else if let Some(version) = scalar(text, r"(?m)^# yarn lockfile v([^\s]+)") {
                require(Some(version), &["1"], "Yarn classic")
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

pub(super) fn empty_text(name: &str, text: &str) -> bool {
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    match name {
        "bun.lock" => crate::scanner::agentbom::discover::jsonc(text)
            .ok()
            .is_some_and(|data| {
                data.get("packages")
                    .and_then(Value::as_object)
                    .is_some_and(|p| p.is_empty())
            }),
        "yarn.lock" => {
            lines.is_empty()
                || lines.iter().all(|l| {
                    *l == "__metadata:" || l.starts_with("version:") || l.starts_with("cacheKey:")
                })
        }
        "Gemfile.lock" => {
            text.contains("specs:")
                && !text
                    .lines()
                    .any(|l| l.starts_with("    ") && !l.trim().is_empty())
                && text.split("DEPENDENCIES").nth(1).is_some_and(|tail| {
                    tail.lines()
                        .skip(1)
                        .take_while(|l| l.is_empty() || l.starts_with(' '))
                        .all(|l| l.trim().is_empty())
                })
        }
        _ => false,
    }
}
