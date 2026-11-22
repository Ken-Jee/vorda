//! The read routes of `link serve`: `POST /v2/read/{devices,device,findings,status,sources,
//! inventory,changes,evidence,finding}` with a bearer reader credential and a small JSON object body.
//!
//! The clock is always the server's: every handler passes `store::now()` to the query, and a
//! request field that is not listed for its route, such as `now` or `as_of`, is refused. A reader
//! that cannot be authorized gets one answer whatever the reason, before the body is looked at.
use super::auth::{unauthorized, AuthorizedScope, ReaderStore};
use super::coverage::{
    fleet_status, visible_devices, visible_inventory, visible_sources, FreshnessPolicy,
    InventoryFilter, SourceFilter,
};
use super::finding::fleet_finding;
use super::history::{fleet_changes, fleet_evidence, ChangeFilter, Since};
use super::query::{device_detail, visible_findings, DeviceFilter, FindingFilter, PageRequest};
use crate::link::encode;
use crate::link::storage::Hub;
use crate::{Error, Result};
use serde::{de, Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// A request body this size is already far beyond any filter or cursor.
pub const MAX_BODY: usize = 16 * 1024;
/// No answer is longer than this. Pages are cut at their own, smaller byte budget, so this is a
/// backstop: an answer over it is a 500 with a fixed body rather than a very large response.
pub const MAX_RESPONSE: usize = 256 * 1024;
/// The routes, in the order they are documented.
pub const ROUTES: [&str; 9] = [
    "devices",
    "device",
    "findings",
    "status",
    "sources",
    "inventory",
    "changes",
    "evidence",
    "finding",
];

fn bad(field: &str) -> Error {
    Error::rejected(400, format!("invalid field: {field}"))
}
/// Failures with no HTTP meaning of their own are the service being unavailable, never details.
fn service(error: Error) -> Error {
    if error.http_status.is_some() {
        error
    } else {
        Error::rejected(503, "storage unavailable; retry later")
    }
}

/// Succeeds for JSON in which no object repeats a key, at any depth. Ingest refuses repeated keys;
/// here the last value would otherwise win while a proxy or log in front of the hub may have kept
/// the first.
struct DistinctKeys;
impl<'de> Deserialize<'de> for DistinctKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = DistinctKeys;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "JSON")
            }
            fn visit_map<M: de::MapAccess<'de>>(
                self,
                mut m: M,
            ) -> std::result::Result<DistinctKeys, M::Error> {
                let mut seen = BTreeSet::new();
                while let Some(key) = m.next_key::<String>()? {
                    if !seen.insert(key) {
                        return Err(de::Error::custom("repeated key"));
                    }
                    m.next_value::<DistinctKeys>()?;
                }
                Ok(DistinctKeys)
            }
            fn visit_seq<S: de::SeqAccess<'de>>(
                self,
                mut s: S,
            ) -> std::result::Result<DistinctKeys, S::Error> {
                while s.next_element::<DistinctKeys>()?.is_some() {}
                Ok(DistinctKeys)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<DistinctKeys, E> {
                Ok(DistinctKeys)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<DistinctKeys, E> {
                Ok(DistinctKeys)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<DistinctKeys, E> {
                Ok(DistinctKeys)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<DistinctKeys, E> {
                Ok(DistinctKeys)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<DistinctKeys, E> {
                Ok(DistinctKeys)
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<DistinctKeys, E> {
                Ok(DistinctKeys)
            }
        }
        d.deserialize_any(Visitor)
    }
}

/// A request body whose fields are checked against the list the route allows.
struct Fields(Map<String, Value>);
impl Fields {
    fn parse(body: &[u8], allowed: &[&str]) -> Result<Self> {
        let not_an_object = || Error::rejected(400, "request body must be a JSON object");
        serde_json::from_slice::<DistinctKeys>(body).map_err(|_| not_an_object())?;
        let value: Value = serde_json::from_slice(body).map_err(|_| not_an_object())?;
        let Value::Object(map) = value else {
            return Err(not_an_object());
        };
        // The name is not echoed: every refusal here is a fixed body.
        if map.keys().any(|k| !allowed.contains(&k.as_str())) {
            return Err(Error::rejected(400, "unknown field"));
        }
        Ok(Self(map))
    }
    fn strings(&self, name: &str) -> Result<Vec<String>> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(vec![]),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string).ok_or_else(|| bad(name)))
                .collect(),
            Some(_) => Err(bad(name)),
        }
    }
    fn string(&self, name: &str) -> Result<Option<String>> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(bad(name)),
        }
    }
    fn required(&self, name: &str) -> Result<String> {
        self.string(name)?.ok_or_else(|| bad(name))
    }
    fn number(&self, name: &str) -> Result<Option<u64>> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v.as_u64().map(Some).ok_or_else(|| bad(name)),
        }
    }
    fn limit(&self) -> Result<Option<usize>> {
        Ok(self
            .number("limit")?
            .map(|n| n.min(usize::MAX as u64) as usize))
    }
    fn policy(&self) -> Result<FreshnessPolicy> {
        Ok(match self.number("fresh_for_seconds")? {
            Some(secs) => FreshnessPolicy {
                fresh_for_secs: secs,
            },
            None => FreshnessPolicy::default(),
        })
    }
}

fn authenticate(hub: &Hub, credential: &str) -> Result<AuthorizedScope> {
    ReaderStore::open(&hub.database.path)
        .and_then(|store| store.authorize(credential))
        .map_err(refuse)
}

fn refuse(e: Error) -> Error {
    if e.http_status == Some(401) {
        e
    } else if e.busy {
        // An owner command is writing the store: a good credential should retry, not
        // be thrown away. This says nothing about the credential.
        Error::rejected(503, "storage unavailable; retry later")
    } else {
        // An unreadable store is not a reason the reader can act on.
        unauthorized()
    }
}

/// Serve one read request. `route` is one of `ROUTES`; the credential has been taken from the
/// `Authorization` header and nowhere else.
pub fn handle(hub: &Hub, route: &str, credential: &str, body: &[u8]) -> Result<Vec<u8>> {
    handle_capped(hub, route, credential, body, MAX_RESPONSE)
}

/// `handle` with the answer length limit given, so the cap can be exercised without an answer of
/// the real limit's size. Not part of the API: only tests call it with another limit.
#[doc(hidden)]
pub fn handle_capped(
    hub: &Hub,
    route: &str,
    credential: &str,
    body: &[u8],
    max_response: usize,
) -> Result<Vec<u8>> {
    let scope = authenticate(hub, credential)?;
    let answer = respond(hub, &scope, route, body, crate::store::now()).map_err(service)?;
    let encoded = encode(&answer)?;
    if encoded.len() > max_response {
        return Err(Error::rejected(500, "response_limit"));
    }
    Ok(encoded)
}

fn respond(
    hub: &Hub,
    scope: &AuthorizedScope,
    route: &str,
    body: &[u8],
    now: f64,
) -> Result<Value> {
    // Every list may be narrowed by site and device; the rest is per route.
    let parse = |extra: &[&str]| -> Result<Fields> {
        let mut allowed = vec!["sites", "devices"];
        allowed.extend_from_slice(extra);
        Fields::parse(body, &allowed)
    };
    match route {
        "devices" => {
            let f = parse(&["limit", "cursor"])?;
            let cursor = f.string("cursor")?;
            visible_devices(
                hub,
                scope,
                &DeviceFilter {
                    sites: f.strings("sites")?,
                    devices: f.strings("devices")?,
                },
                &PageRequest {
                    limit: f.limit()?,
                    cursor: cursor.as_deref(),
                },
                now,
            )
        }
        "device" => {
            let f = Fields::parse(body, &["device"])?;
            device_detail(hub, scope, &f.required("device")?)
        }
        "findings" => {
            let f = parse(&["advisory", "name", "limit", "cursor"])?;
            let cursor = f.string("cursor")?;
            visible_findings(
                hub,
                scope,
                &FindingFilter {
                    sites: f.strings("sites")?,
                    devices: f.strings("devices")?,
                    advisory: f.string("advisory")?,
                    name: f.string("name")?,
                },
                &PageRequest {
                    limit: f.limit()?,
                    cursor: cursor.as_deref(),
                },
                now,
            )
        }
        "status" => {
            let f = parse(&["fresh_for_seconds"])?;
            fleet_status(
                hub,
                scope,
                &DeviceFilter {
                    sites: f.strings("sites")?,
                    devices: f.strings("devices")?,
                },
                &f.policy()?,
                now,
            )
        }
        "sources" => {
            let f = parse(&[
                "sources",
                "freshness",
                "inventory_state",
                "fresh_for_seconds",
                "limit",
                "cursor",
            ])?;
            let cursor = f.string("cursor")?;
            visible_sources(
                hub,
                scope,
                &SourceFilter {
                    sites: f.strings("sites")?,
                    devices: f.strings("devices")?,
                    sources: f.strings("sources")?,
                    freshness: f.string("freshness")?,
                    inventory_state: f.string("inventory_state")?,
                },
                &f.policy()?,
                &PageRequest {
                    limit: f.limit()?,
                    cursor: cursor.as_deref(),
                },
                now,
            )
        }
        "inventory" => {
            let f = parse(&[
                "sources",
                "ecosystem",
                "name",
                "version",
                "fresh_for_seconds",
                "limit",
                "cursor",
            ])?;
            let cursor = f.string("cursor")?;
            visible_inventory(
                hub,
                scope,
                &InventoryFilter {
                    sites: f.strings("sites")?,
                    devices: f.strings("devices")?,
                    sources: f.strings("sources")?,
                    ecosystem: f.string("ecosystem")?,
                    name: f.string("name")?,
                    version: f.string("version")?,
                },
                &f.policy()?,
                &PageRequest {
                    limit: f.limit()?,
                    cursor: cursor.as_deref(),
                },
                now,
            )
        }
        "changes" => {
            let f = parse(&["sources", "since", "limit", "cursor"])?;
            let cursor = f.string("cursor")?;
            // The window start is data, not a clock: the server still decides what "now" is and
            // refuses a start in its future.
            let since = match f.0.get("since") {
                Some(Value::String(s)) if s == "start" => Since::Start,
                Some(Value::Object(o)) if o.len() == 1 => {
                    match o.get("time").and_then(Value::as_f64) {
                        Some(t) => Since::Time(t),
                        None => return Err(bad("since")),
                    }
                }
                _ => return Err(bad("since")),
            };
            fleet_changes(
                hub,
                scope,
                &ChangeFilter {
                    sites: f.strings("sites")?,
                    devices: f.strings("devices")?,
                    sources: f.strings("sources")?,
                },
                &since,
                &PageRequest {
                    limit: f.limit()?,
                    cursor: cursor.as_deref(),
                },
                now,
            )
        }
        "evidence" => {
            let f = Fields::parse(body, &["reference"])?;
            fleet_evidence(hub, scope, &f.required("reference")?)
        }
        "finding" => {
            let f = Fields::parse(body, &["key"])?;
            fleet_finding(
                hub,
                scope,
                &f.required("key")?,
                &FreshnessPolicy::default(),
                now,
            )
        }
        _ => Err(Error::rejected(404, "route")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sqlite_interrupt_is_the_fixed_503_and_leaks_nothing() {
        let interrupt = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),
            None,
        );
        let answer = service(interrupt.into());
        assert_eq!(answer.http_status, Some(503));
        assert_eq!(answer.message, "storage unavailable; retry later");
    }

    fn sqlite(code: i32) -> Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None).into()
    }

    #[test]
    fn a_busy_or_locked_store_is_told_to_retry() {
        for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
            let answer = refuse(sqlite(code));
            assert_eq!(answer.http_status, Some(503));
            assert_eq!(answer.message, "storage unavailable; retry later");
        }
    }

    #[test]
    fn error_text_saying_locked_is_not_a_retry() {
        let answer = refuse(Error::new("the account is locked"));
        assert_eq!(answer.http_status, Some(401));
    }

    #[test]
    fn a_sqlite_interrupt_is_not_flagged_busy() {
        assert!(!sqlite(rusqlite::ffi::SQLITE_INTERRUPT).busy);
    }
}
