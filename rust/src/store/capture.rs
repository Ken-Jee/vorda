use super::{atomic, Store};
use crate::{
    domain::Package,
    scanner::{input, inventory},
    Error, Result,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Component, Path},
};

const LIMIT: usize = 4 * 1024 * 1024;
/// Most package records one authority may currently hold across all of its selected lockfiles.
/// Over it the capture is refused as a whole, never truncated (docs/native-capture.md). The hub
/// admits as many records in one assessment and holds as many current ones per authority.
pub const PACKAGE_LIMIT: usize = 1500;
/// Most inputs one capture selects; the hub admits as many in one assessment.
pub const INPUT_LIMIT: usize = 256;
/// Longest input path, in bytes; the hub accepts the same.
pub const PATH_LIMIT: usize = 256;
/// The saved-view reader refuses a view larger than this, so a capture whose view is larger is refused
/// up front with a named error. The hub keeps the same view of what it admits and refuses one larger
/// than this too.
pub const VIEW_LIMIT: usize = 4 * 1024 * 1024;
/// What the hub adds to a view: it records the receipt time that the device leaves empty, a few bytes
/// a record. A capture is refused when its view leaves less than this, so the hub never refuses
/// what the device committed.
const VIEW_RECEIPT_MARGIN: usize = 64 * 1024;
/// Separates the input path from the package location in a `capture_current` row key. Input paths may
/// not contain control characters, so the key splits unambiguously.
const KEY_SEP: char = '\u{1f}';
const AXES: [&str; 6] = ["tenant", "site", "device", "generation", "scope", "source"];
fn err(s: &str) -> Error {
    Error::new(s)
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn id(parts: &Value) -> String {
    hash(parts.to_string().as_bytes())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or_else(|| err("invalid_capture_envelope"))
}
fn keys(v: &Value, allowed: &[&str]) -> Result<()> {
    if v.as_object()
        .is_none_or(|m| m.keys().any(|k| !allowed.contains(&k.as_str())))
    {
        return Err(err("unsupported_input_field"));
    }
    Ok(())
}
/// The key serde_json's `arbitrary_precision` feature uses to pass a number through a map visitor.
const NUMBER_KEY: &str = "$serde_json::private::Number";
/// Refuses a number anywhere in the request: no capture request field is numeric, and a lockfile's
/// numbers are read by the scanner, not here.
fn no_numbers(v: &Value) -> Result<()> {
    match v {
        Value::Number(_) => Err(err("invalid_number")),
        Value::Array(a) => a.iter().try_for_each(no_numbers),
        Value::Object(m) => m.values().try_for_each(no_numbers),
        _ => Ok(()),
    }
}
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "bounded JSON")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut m: M,
            ) -> std::result::Result<Strict, M::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = m.next_key::<String>()? {
                    // With arbitrary precision serde_json hands every float, exponent and integer
                    // outside the i64/u64 range over as a one-key map; read it back as the number
                    // it is. Other integers (`-0` included) arrive through the integer visitors.
                    if k == NUMBER_KEY && out.is_empty() {
                        let text = m.next_value::<String>()?;
                        let n = text
                            .parse::<serde_json::Number>()
                            .map_err(|_| serde::de::Error::custom("invalid_number"))?;
                        return Ok(Strict(Value::Number(n)));
                    }
                    if out.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate_input_key"));
                    }
                    out.insert(k, m.next_value::<Strict>()?.0);
                }
                Ok(Strict(Value::Object(out)))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut s: S,
            ) -> std::result::Result<Strict, S::Error> {
                let mut out = vec![];
                while let Some(v) = s.next_element::<Strict>()? {
                    out.push(v.0);
                }
                Ok(Strict(json!(out)))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(s)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                s: String,
            ) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(s)))
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(n)))
            }
            fn visit_i64<E: serde::de::Error>(self, n: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(n)))
            }
            fn visit_bool<E: serde::de::Error>(self, b: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(b)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
        }
        d.deserialize_any(Visitor)
    }
}
fn parse(b: &[u8]) -> Result<Value> {
    if b.len() > LIMIT {
        return Err(err("input_size_limit"));
    }
    Ok(serde_json::from_slice::<Strict>(b)?.0)
}
/// (ecosystem, name, version) of one package in a lockfile.
pub(crate) type Found = (String, String, String);
/// The `error` and optional `detail` recorded for an input the capture cannot take.
pub(crate) type Refusal = (String, Option<String>);
/// Lockfile kinds whose text is JSON, where a repeated key would make two readers disagree.
const JSON_LOCKS: [&str; 4] = [
    "package-lock.json",
    "Pipfile.lock",
    "composer.lock",
    "packages.lock.json",
];
/// Whether `name` is a lockfile the scanner reads and capture can take (not the binary `bun.lockb`).
fn lockfile_name(name: &str) -> bool {
    name != "bun.lockb" && inventory::supported(name)
}
/// The distinct packages the scanner's own reader finds in one lockfile, sorted. Repeated keys in a
/// JSON lockfile are refused first: the scanner would silently keep the last one.
pub(crate) fn lock_packages(file: &str, bytes: &[u8]) -> std::result::Result<Vec<Found>, Refusal> {
    let refuse = |e: Error| ("unsupported_input".to_string(), Some(e.to_string()));
    let text = std::str::from_utf8(bytes).map_err(|e| refuse(Error::new(e.to_string())))?;
    if JSON_LOCKS.contains(&file) {
        parse(bytes).map_err(|e| (e.to_string(), None))?;
    }
    let found: BTreeSet<Found> = inventory::parse_lockfile(file, text, "")
        .map_err(refuse)?
        .into_iter()
        .map(|p| (p.ecosystem, p.name, p.version))
        .collect();
    if found.is_empty() {
        return Err(("unsupported_empty_input".into(), None));
    }
    Ok(found.into_iter().collect())
}
/// The producer both kinds of artifact name: this capture code, pinned by the hash of its sources.
fn producer() -> Value {
    json!({"name":"vorda-native-restricted-capture","source_pin":hash(&[include_bytes!("capture.rs").as_slice(),include_bytes!("../cli.rs").as_slice(),include_bytes!("mod.rs").as_slice(),include_bytes!("../assets/mod.rs").as_slice()].concat())})
}
fn schema(s: &Store) -> Result<()> {
    s.db.execute_batch("CREATE TABLE IF NOT EXISTS capture_attempts(token TEXT PRIMARY KEY,envelope TEXT NOT NULL,outcome TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS capture_authorities(authority TEXT PRIMARY KEY,config TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS capture_artifacts(evidence TEXT PRIMARY KEY,payload TEXT NOT NULL,records TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS capture_current(authority TEXT,path TEXT,record TEXT NOT NULL,PRIMARY KEY(authority,path));
CREATE TABLE IF NOT EXISTS capture_views(snapshot TEXT PRIMARY KEY,authority TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL);")?;
    Ok(())
}
fn decimal(s: &str) -> bool {
    let mut parts = s.split('.');
    let w = parts.next().unwrap();
    let f = parts.next();
    !w.is_empty()
        && w.len() <= 18
        && w.bytes().all(|b| b.is_ascii_digit())
        && f.is_none_or(|f| !f.is_empty() && f.len() <= 18 && f.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}
fn time(v: Option<&str>, reason: &str) -> Value {
    match v {
        Some(s) => json!({"value":s,"null_reason":null}),
        None => json!({"value":null,"null_reason":reason}),
    }
}
fn rows(s: &Store, authority: &str) -> Result<Vec<Value>> {
    let raw =
        s.db.prepare("SELECT record FROM capture_current WHERE authority=? ORDER BY path")?
            .query_map([authority], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
    raw.iter().map(|v| Ok(serde_json::from_str(v)?)).collect()
}
/// One saved artifact and its frozen records, loaded once per evidence id.
struct Frozen {
    payload: String,
    producer: Value,
    records: BTreeMap<String, Value>,
}
/// Checks `r` against the record frozen with its artifact. `cache` holds each artifact once, so a
/// large capture reads and parses it once rather than once per record.
fn check_frozen<'a>(
    s: &Store,
    cache: &'a mut BTreeMap<String, Frozen>,
    r: &Value,
) -> Result<(&'a str, &'a Frozen)> {
    let e = text(&r["dimensions"], "evidence")?;
    if !cache.contains_key(e) {
        let (payload, frozen): (String, String) = s.db.query_row(
            "SELECT payload,records FROM capture_artifacts WHERE evidence=?",
            [e],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let artifact: Value = serde_json::from_str(&payload)?;
        let mut records = BTreeMap::new();
        for v in serde_json::from_str::<Vec<Value>>(&frozen)? {
            let id = text(&v, "record_id")?.to_string();
            records.insert(id, v);
        }
        let producer = artifact["producer"].clone();
        cache.insert(
            e.into(),
            Frozen {
                payload,
                producer,
                records,
            },
        );
    }
    let (key, frozen) = cache.get_key_value(e).unwrap();
    let Some(original) = r["record_id"].as_str().and_then(|i| frozen.records.get(i)) else {
        return Err(err("captured_member_mismatch"));
    };
    if original != r {
        return Err(err("captured_observation_mismatch"));
    }
    Ok((key, frozen))
}
fn view(s: &Store, authority: &str, snapshot: &str, revision: u64) -> Result<Value> {
    let records = rows(s, authority)?;
    let mut evidence = BTreeMap::<String, Value>::new();
    let mut bindings = BTreeMap::new();
    let mut payloads = BTreeMap::new();
    let mut tuples = BTreeMap::new();
    let mut cache = BTreeMap::new();
    for r in &records {
        let (e, frozen) = check_frozen(s, &mut cache, r)?;
        let item=evidence.entry(e.into()).or_insert_with(||json!({"evidence_id":e,"class":"inventory_projection","source_sha256":hash(frozen.payload.as_bytes()),"source_byte_length":frozen.payload.len(),"producer":frozen.producer,"record_ids":[]}));
        item["record_ids"]
            .as_array_mut()
            .unwrap()
            .push(r["record_id"].clone());
        bindings.insert(text(r,"assessment_id")?.to_string(),json!({"assessment_id":r["assessment_id"],"revision":r["revision"],"input_sha256":r["source_sha256"]}));
        payloads
            .entry(e.to_string())
            .or_insert_with(|| frozen.payload.clone());
        tuples.insert(e.to_string(), r["dimensions"].clone());
    }
    Ok(
        json!({"contract_version":"m0b-derived-1","header":{"snapshot_id":snapshot,"snapshot_revision":revision,"catalog_id":format!("catalog-{snapshot}"),"catalog_revision":revision},"catalog_tuples":tuples.into_values().collect::<Vec<_>>(),"assessment_bindings":bindings.into_values().collect::<Vec<_>>(),"records":records,"evidence":evidence.into_values().collect::<Vec<_>>(),"retained_payload_utf8":payloads}),
    )
}
pub fn capture(s: &mut Store, request: &[u8]) -> Result<Value> {
    if !s.db.is_autocommit() {
        return Err(err("capture_requires_outer_transaction"));
    }
    let envelope = parse(request)?;
    no_numbers(&envelope)?;
    keys(
        &envelope,
        &[
            "token",
            "binding",
            "root",
            "inputs",
            "observed_at",
            "completed_at",
            "provider",
            "legacy_import",
        ],
    )?;
    let token = text(&envelope, "token")?.to_string();
    let binding = &envelope["binding"];
    keys(binding, &AXES)?;
    for k in AXES {
        text(binding, k)?;
    }
    let authority = id(&json!(AXES[..5]
        .iter()
        .map(|k| binding[*k].clone())
        .collect::<Vec<_>>()));
    let root = Path::new(text(&envelope, "root")?);
    if !root.is_absolute() || {
        root.canonicalize()?;
        !crate::cli::resolved(root).is_ok_and(|r| r == root)
    } {
        return Err(err("invalid_capture_root"));
    }
    input::refuse_links(root)?;
    let config = json!({"root":root,"binding":binding}).to_string();
    let selected = envelope["inputs"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= INPUT_LIMIT)
        .ok_or_else(|| err("invalid_capture_selection"))?;
    let mut unique = BTreeSet::new();
    for v in selected {
        let path = v.as_str().ok_or_else(|| err("invalid_capture_path"))?;
        if !unique.insert(path)
            || path.len() > PATH_LIMIT
            || Path::new(path)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || !Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(lockfile_name)
            || Path::new(path).to_str() != Some(path)
            || path.contains('\\')
            || path.chars().any(char::is_control)
            || path
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
        {
            return Err(err("invalid_capture_path"));
        }
    }
    let legacy = envelope
        .get("legacy_import")
        .map(|v| v.as_bool().ok_or_else(|| err("invalid_capture_envelope")))
        .transpose()?
        .unwrap_or(false);
    for k in ["observed_at", "completed_at"] {
        if legacy {
            if !envelope[k].is_null() {
                return Err(err("legacy_time_assertion_refused"));
            }
        } else if !decimal(text(&envelope, k)?) {
            return Err(err("invalid_capture_time"));
        }
    }
    let provider = envelope.get("provider");
    if let Some(p) = provider {
        keys(
            p,
            &["name", "request", "status", "checked_at", "response_utf8"],
        )?;
        if text(p, "name")? != "osv"
            || text(p, "status")? != "unavailable"
            || !decimal(text(p, "checked_at")?)
        {
            return Err(err("unsupported_provider"));
        }
        text(p, "request")?;
        if !p["response_utf8"].is_null() {
            text(p, "response_utf8")?;
        }
    }
    if legacy && provider.is_some() {
        return Err(err("unsupported_provider"));
    }
    let _lock = s.locked()?;
    schema(s)?;
    let prior: Option<(String, u64)> =
        s.db.query_row(
            "SELECT config,revision FROM capture_authorities WHERE authority=?",
            [&authority],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if prior.as_ref().is_some_and(|v| v.0 != config) {
        return Err(err("capture_binding_conflict"));
    }
    let revision = prior.map(|v| v.1 + 1).unwrap_or(1);
    let assessment = id(&json!(["assessment", authority, token]));
    let e = id(&json!(["evidence", authority, token]));
    let snapshot = id(&json!(["view", authority, token]));
    let mut inputs: Vec<Value> = vec![];
    // (index in `inputs`, path, packages) for each input that read and parsed.
    let mut parsed = vec![];
    let mut unsupported = false;
    // Bytes of input text that will appear in the retained envelope.
    let mut kept = 0usize;
    for v in selected {
        let path = v.as_str().unwrap();
        let full = root.join(path);
        let mut bytes = vec![];
        let read = input::open_regular(&full, Some(root), LIMIT as u64).and_then(|f| {
            f.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
            Ok(())
        });
        match read {
            Err(error) => {
                let unsupported_path = input::linked(&full)
                    || full.ancestors().any(input::linked)
                    || full.metadata().is_ok_and(|m| m.len() > LIMIT as u64);
                unsupported |= unsupported_path;
                inputs.push(json!({"path":path,"sha256":null,"bytes_utf8":null,"error":if unsupported_path {"unsupported_input_field"} else {"input_read_failed"},"detail":error.to_string()}));
            }
            Ok(()) => {
                // Every readable input's text is kept in the envelope, so the envelope is at least
                // this long: stop before parsing more once it can no longer fit.
                if std::str::from_utf8(&bytes).is_ok() {
                    kept += bytes.len();
                    if kept > LIMIT {
                        return Err(err("capture_size_limit"));
                    }
                }
                let file = Path::new(path).file_name().and_then(|s| s.to_str());
                match lock_packages(file.unwrap_or_default(), &bytes) {
                    Err((error, detail)) => {
                        unsupported = true;
                        let mut item = json!({"path":path,"sha256":hash(&bytes),"bytes_utf8":String::from_utf8(bytes).ok(),"error":error});
                        if let Some(detail) = detail {
                            item["detail"] = json!(detail);
                        }
                        inputs.push(item);
                    }
                    Ok(found) => {
                        parsed.push((inputs.len(), path, found));
                        inputs.push(json!({"path":path,"sha256":hash(&bytes),"bytes_utf8":String::from_utf8(bytes).map_err(|_|err("unsupported_input_field"))?,"error":null}));
                    }
                }
            }
        }
    }
    let encoded = json!({"request":envelope,"inputs":inputs}).to_string();
    if encoded.len() > LIMIT {
        return Err(err("capture_size_limit"));
    }
    // At most one package past the cap is ever stored, so a far larger lockfile must not reserve more:
    // it gets the saved `capture_package_limit` outcome below, not a storage-budget error.
    let found_total: usize = parsed
        .iter()
        .map(|p| p.2.len())
        .sum::<usize>()
        .min(PACKAGE_LIMIT + 1);
    super::storage_admit(
        &s.root,
        (encoded.len() * 4 + found_total * 4096 + 65536) as u64,
    )?;
    if let Some((old, outcome)) =
        s.db.query_row(
            "SELECT envelope,outcome FROM capture_attempts WHERE token=?",
            [&token],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?
    {
        if old != encoded {
            return Err(err("capture_token_conflict"));
        }
        return Ok(serde_json::from_str(&outcome)?);
    }
    // The cap is on everything the authority will currently hold: rows of inputs not re-read here
    // stay, rows of re-read inputs are replaced. Checked after the replay lookup so a saved outcome
    // does not depend on what the authority holds now.
    let reread: BTreeSet<&str> = parsed.iter().map(|p| p.1).collect();
    let mut held =
        s.db.prepare("SELECT path FROM capture_current WHERE authority=?")?
            .query_map([&authority], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .filter(|k| !reread.contains(k.split(KEY_SEP).next().unwrap_or_default()))
            .count();
    for (index, _, found) in &parsed {
        held += found.len();
        if held > PACKAGE_LIMIT {
            inputs[*index]["error"] = json!("capture_package_limit");
            inputs[*index]["detail"] = json!(format!(
                "{held} packages would be held; the limit is {PACKAGE_LIMIT}"
            ));
            unsupported = true;
            break;
        }
    }
    let mut fresh = vec![];
    let mut packages = vec![];
    for (_, path, found) in parsed.iter().filter(|_| !unsupported) {
        let mut versions = BTreeMap::<(&str, &str), usize>::new();
        for (ecosystem, name, _) in found {
            *versions
                .entry((ecosystem.as_str(), name.as_str()))
                .or_default() += 1;
        }
        for (ecosystem, name, version) in found {
            // One location per package. A name found at several versions in one lockfile cannot be
            // told apart by name, so those locations include the version.
            let mut key = if ecosystem == "npm" {
                format!("node_modules/{name}")
            } else {
                format!("{ecosystem}:{name}")
            };
            if versions[&(ecosystem.as_str(), name.as_str())] > 1 {
                key = format!("{key}@{version}");
            }
            let location = id(&json!([authority, binding["source"], path, key]));
            let record_id = id(&json!([assessment, path, location]));
            let package = Package {
                name: name.clone(),
                version: version.clone(),
                ecosystem: ecosystem.clone(),
                path: root.join(path).to_string_lossy().into(),
                scope: "project".into(),
                extra: serde_json::Map::new(),
            };
            let alias = super::asset(&package)?;
            packages.push(package);
            fresh.push(json!({"record_id":record_id,"component_id":format!("component-{location}"),"location_ref":location,"package":{"ecosystem":ecosystem,"namespace":null,"name":name,"version":version,"qualifiers":{}},"legacy_aliases":[{"namespace":"native_asset","value":alias}],"input_path":path}));
        }
    }
    let partial = inputs.iter().any(|v| !v["error"].is_null());
    s.db.execute_batch("SAVEPOINT capture")?;
    let result = (|| -> Result<Value> {
        if unsupported || fresh.is_empty() {
            let current:Option<String>=s.db.query_row("SELECT snapshot FROM capture_views WHERE authority=? ORDER BY revision DESC LIMIT 1",[&authority],|r|r.get(0)).optional()?;
            let outcome = json!({"status":"unsuccessful","token":token,"inputs":inputs,"coverage":if unsupported {"unsupported"} else {"partial"},"current_retained":current,"revision":null});
            s.db.execute(
                "INSERT INTO capture_attempts VALUES(?,?,?)",
                params![token, encoded, outcome.to_string()],
            )?;
            return Ok(outcome);
        }
        let unknown = json!({"state":"unknown","reason":"producer_coverage_unavailable"});
        let coverage = json!({"inventory":if legacy {unknown.clone()} else if partial {json!({"state":"partial","reason":"input_read_failed"})} else {json!({"state":"complete","reason":null})},"advisories":if legacy {unknown} else if provider.is_some() {json!({"state":"unavailable","reason":"provider_unavailable"})} else {json!({"state":"not_requested","reason":"provider_disabled"})},"osv":if legacy {"unknown"} else if provider.is_some() {"unavailable"} else {"not_requested"},"kev":"unknown","epss":null,"global_clean":false,"fix_verified":false});
        let times = json!({"observed_at":time(envelope["observed_at"].as_str(),"legacy_observation_time_unavailable"),"assessment_completed_at":time(envelope["completed_at"].as_str(),"producer_time_unavailable"),"advisory_checked_at":time(provider.and_then(|p|p["checked_at"].as_str()),if legacy {"producer_time_unavailable"} else {"not_requested"}),"received_at":time(None,if legacy {"producer_time_unavailable"} else {"not_received"})});
        let provider=provider.map(|p|json!({"name":p["name"],"request":p["request"],"status":p["status"],"checked_at":p["checked_at"],"response_utf8":p["response_utf8"],"sha256":p["response_utf8"].as_str().map(|b|hash(b.as_bytes())),"null_reason":if p["response_utf8"].is_null(){json!("no_response")}else{Value::Null}}));
        let artifact = json!({"assessment_id":assessment,"revision":revision,"binding":binding,"capture_token":token,"inputs":inputs,"provider":provider,"producer":producer(),"records":fresh,"times":times,"coverage":coverage,"legacy_import":legacy});
        let payload = artifact.to_string();
        let digest = hash(payload.as_bytes());
        // A re-read input replaces all of its rows (also the one-row-per-input rows of older captures).
        for (_, path, _) in &parsed {
            let prefix = format!("{path}{KEY_SEP}");
            s.db.execute(
                "DELETE FROM capture_current WHERE authority=?1 AND (path=?2 OR substr(path,1,length(?3))=?3)",
                params![authority, path, prefix],
            )?;
        }
        let mut records = vec![];
        for mut r in fresh {
            let path = r.as_object_mut().unwrap().remove("input_path").unwrap();
            let mut dimensions = binding.clone();
            dimensions["evidence"] = json!(e);
            dimensions["evidence_class"] = json!("inventory_projection");
            r["assessment_id"] = json!(assessment);
            r["revision"] = json!(revision);
            r["dimensions"] = dimensions;
            r["times"] = times.clone();
            r["coverage"] = coverage.clone();
            r["source_sha256"] = json!(digest);
            let key = format!(
                "{}{KEY_SEP}{}",
                path.as_str().unwrap(),
                r["location_ref"].as_str().unwrap()
            );
            s.db.execute(
                "INSERT OR REPLACE INTO capture_current VALUES(?,?,?)",
                params![authority, key, r.to_string()],
            )?;
            records.push(r);
        }
        s.db.execute(
            "INSERT INTO capture_artifacts VALUES(?,?,?)",
            params![e, payload, json!(records).to_string()],
        )?;
        let snapshot_value = view(s, &authority, &snapshot, revision)?;
        let view_text = snapshot_value.to_string();
        if view_text.len() > VIEW_LIMIT - VIEW_RECEIPT_MARGIN {
            return Err(err("capture_view_size_limit"));
        }
        let grant = full_grant(&snapshot_value);
        crate::snapshot::read(
            view_text.as_bytes(),
            grant.to_string().as_bytes(),
            br#"{"op":"list"}"#,
            "1793898330",
        )
        .map_err(|_| err("capture_reader_integrity_failure"))?;
        crate::cli::commit_capture_native(s, packages, format!("capture-{authority}"))?;
        s.db.execute(
            "INSERT OR REPLACE INTO capture_authorities VALUES(?,?,?)",
            params![authority, config, revision],
        )?;
        s.db.execute(
            "INSERT INTO capture_views VALUES(?,?,?,?)",
            params![snapshot, authority, revision, view_text],
        )?;
        let outcome = json!({"status":"committed","token":token,"assessment_id":assessment,"revision":revision,"snapshot_id":snapshot,"coverage":coverage});
        s.db.execute(
            "INSERT INTO capture_attempts VALUES(?,?,?)",
            params![token, encoded, outcome.to_string()],
        )?;
        super::storage_admit(&s.root, 0)?;
        Ok(outcome)
    })();
    match result {
        Ok(v) => {
            s.db.execute_batch("RELEASE capture")?;
            s.recover_exports()?;
            Ok(v)
        }
        Err(e) => {
            s.db.execute_batch("ROLLBACK TO capture; RELEASE capture")?;
            Err(e)
        }
    }
}
/// Retires the source this device captured for `scope`: a new revision with no inputs and no
/// records, whose inventory coverage says `retired`. The authority's current rows are dropped, so
/// the saved view holds no records; it keeps the retirement artifact as its one piece of evidence,
/// which `queue-native` sends like any other. A later `capture` reopens the source.
pub fn retire(s: &mut Store, scope: &str, source: &str) -> Result<Value> {
    if !s.db.is_autocommit() {
        return Err(err("capture_requires_outer_transaction"));
    }
    let _lock = s.locked()?;
    schema(s)?;
    let mut held = vec![];
    for row in s
        .db
        .prepare("SELECT authority,config,revision FROM capture_authorities ORDER BY authority")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
            ))
        })?
    {
        let (authority, config, revision) = row?;
        let config: Value = serde_json::from_str(&config)?;
        if config["binding"]["scope"] == scope && config["binding"]["source"] == source {
            held.push((authority, config["binding"].clone(), revision));
        }
    }
    let (authority, binding, prior) = match held.len() {
        0 => return Err(err("unknown_capture_source")),
        1 => held.remove(0),
        _ => return Err(err("ambiguous_capture_source")),
    };
    let revision = prior + 1;
    let token = id(&json!(["retire", authority, revision]));
    let assessment = id(&json!(["assessment", authority, token]));
    let e = id(&json!(["evidence", authority, token]));
    let snapshot = id(&json!(["view", authority, token]));
    let at = format!("{:.4}", super::now());
    let artifact = json!({"assessment_id":assessment,"revision":revision,"binding":binding,"capture_token":token,"inputs":[],"provider":null,"producer":producer(),"records":[],
        "times":{"observed_at":time(Some(&at),""),"assessment_completed_at":time(Some(&at),""),"advisory_checked_at":time(None,"not_requested"),"received_at":time(None,"not_received")},
        "coverage":{"inventory":{"state":"retired","reason":"source_retired_by_device"},"advisories":{"state":"not_requested","reason":"provider_disabled"},"osv":"not_requested","kev":"unknown","epss":null,"global_clean":false,"fix_verified":false},
        "legacy_import":false});
    let payload = artifact.to_string();
    let digest = hash(payload.as_bytes());
    super::storage_admit(&s.root, (payload.len() * 4 + 65536) as u64)?;
    s.db.execute_batch("SAVEPOINT retire")?;
    let result = (|| -> Result<Value> {
        s.db.execute(
            "DELETE FROM capture_current WHERE authority=?",
            [&authority],
        )?;
        s.db.execute(
            "INSERT INTO capture_artifacts VALUES(?,?,?)",
            params![e, payload, "[]"],
        )?;
        let view = json!({"contract_version":"m0b-derived-1","header":{"snapshot_id":snapshot,"snapshot_revision":revision,"catalog_id":format!("catalog-{snapshot}"),"catalog_revision":revision},
            "catalog_tuples":[],"assessment_bindings":[{"assessment_id":assessment,"revision":revision,"input_sha256":digest}],"records":[],
            "evidence":[{"evidence_id":e,"class":"inventory_projection","source_sha256":digest,"source_byte_length":payload.len(),"producer":producer(),"record_ids":[]}],
            "retained_payload_utf8":BTreeMap::from([(e.clone(), payload.clone())])});
        s.db.execute(
            "UPDATE capture_authorities SET revision=? WHERE authority=?",
            params![revision, authority],
        )?;
        s.db.execute(
            "INSERT INTO capture_views VALUES(?,?,?,?)",
            params![snapshot, authority, revision, view.to_string()],
        )?;
        let outcome = json!({"status":"committed","token":token,"assessment_id":assessment,"revision":revision,"snapshot_id":snapshot,"coverage":artifact["coverage"]});
        s.db.execute(
            "INSERT INTO capture_attempts VALUES(?,?,?)",
            params![token, artifact.to_string(), outcome.to_string()],
        )?;
        super::storage_admit(&s.root, 0)?;
        Ok(outcome)
    })();
    match result {
        Ok(v) => {
            s.db.execute_batch("RELEASE retire")?;
            Ok(v)
        }
        Err(e) => {
            s.db.execute_batch("ROLLBACK TO retire; RELEASE retire")?;
            Err(e)
        }
    }
}
pub fn full_grant(v: &Value) -> Value {
    let mut g = v["header"].clone();
    g["grant_revision"] = json!(1);
    g["clauses"] = json!(v["catalog_tuples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), json!([v])))
            .collect::<serde_json::Map<_, _>>())
        .collect::<Vec<_>>());
    g
}
pub fn export(s: &mut Store, snapshot: &str, path: &Path) -> Result<()> {
    if !s.db.is_autocommit() {
        return Err(err("capture_requires_outer_transaction"));
    }
    let _lock = s.locked()?;
    schema(s)?;
    let raw: String = s.db.query_row(
        "SELECT payload FROM capture_views WHERE snapshot=?",
        [snapshot],
        |r| r.get(0),
    )?;
    let v: Value = serde_json::from_str(&raw)?;
    let mut cache = BTreeMap::new();
    for r in v["records"]
        .as_array()
        .ok_or_else(|| err("captured_member_mismatch"))?
    {
        check_frozen(s, &mut cache, r)?;
    }
    atomic(path, &raw)
}
const HELP: &str = "Usage: vorda capture REQUEST.json\n       vorda capture-export SNAPSHOT FILE | capture-attempt TOKEN | capture-retire --scope SCOPE --source SOURCE\n\nLow-level native capture of package inventories into local state; inputs are trusted local files.";

pub fn command(root: &Path, cmd: &str, args: &[String]) -> Result<i32> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        crate::cli::outln(format_args!("{HELP}"))?;
        return Ok(0);
    }
    let mut s = Store::open(root)?;
    match (cmd, args) {
        ("capture", [request]) => println!(
            "{}",
            capture(
                &mut s,
                &input::read_regular(Path::new(request), None, LIMIT as u64, false)?
            )?
        ),
        ("capture-export", [snapshot, path]) => export(&mut s, snapshot, Path::new(path))?,
        ("capture-retire", [a, scope, b, source]) if a == "--scope" && b == "--source" => {
            println!("{}", retire(&mut s, scope, source)?)
        }
        ("capture-attempt", [token]) => {
            let _lock = s.locked()?;
            schema(&s)?;
            let outcome: String = s.db.query_row(
                "SELECT outcome FROM capture_attempts WHERE token=?",
                [token],
                |r| r.get(0),
            )?;
            println!("{outcome}");
        }
        _ => {
            return Err(Error::usage(
                "invalid arguments for capture command (see vorda capture --help)",
            ))
        }
    }
    Ok(0)
}
