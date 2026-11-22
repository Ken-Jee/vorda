use super::storage::Database;
use super::{digest, encode, exact_fields, validate, MAX_BATCH};
use crate::store::now;
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{io::Read, path::Path, time::Duration};

/// Failed attempts after which an entry is reported as needing the operator (it stays queued).
const ATTENTION_ATTEMPTS: i64 = 5;

fn transport_error(error: reqwest::Error) -> Error {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    Error::new(message)
}

/// Posts `body` and returns the answer bytes; a refusal carries the hub's `Retry-After` seconds.
fn post_bytes(
    url: &str,
    route: &str,
    credential: &str,
    body: Vec<u8>,
    ca_file: Option<&Path>,
) -> std::result::Result<Vec<u8>, (Error, f64)> {
    let perform = || -> Result<std::result::Result<Vec<u8>, (u16, f64)>> {
        let parsed = url::Url::parse(url)
            .map_err(|_| Error::new("hub URL must be an origin without credentials"))?;
        let raw_origin = url.split_once("://").map(|(_, s)| s).unwrap_or("");
        let suffix = raw_origin.find('/').map(|n| &raw_origin[n..]).unwrap_or("");
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !["", "/"].contains(&suffix)
            || parsed.host_str().is_none()
        {
            return Err(Error::new("hub URL must be an origin without credentials"));
        }
        if parsed.scheme() != "https"
            && !(parsed.scheme() == "http"
                && ["127.0.0.1", "[::1]", "::1", "localhost"].contains(&parsed.host_str().unwrap()))
        {
            return Err(Error::new("HTTPS is required except on loopback"));
        }
        let mut builder = reqwest::blocking::Client::builder()
            .use_native_tls()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .min_tls_version(reqwest::tls::Version::TLS_1_2);
        if let Some(path) = ca_file {
            let bytes = std::fs::read(path)?;
            for cert in reqwest::Certificate::from_pem_bundle(&bytes)
                .map_err(|e| Error::new(e.to_string()))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder.build().map_err(|e| Error::new(e.to_string()))?;
        let response = client
            .post(format!("{}{route}", url.trim_end_matches('/')))
            .header("Authorization", format!("Bearer {credential}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(transport_error)?;
        let retry = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|n| n.is_finite())
            .unwrap_or(0.0)
            .clamp(0.0, 3600.0);
        if !response.status().is_success() {
            return Ok(Err((response.status().as_u16(), retry)));
        }
        let mut raw = Vec::new();
        response
            .take((MAX_BATCH + 1) as u64)
            .read_to_end(&mut raw)?;
        if raw.len() > MAX_BATCH {
            return Err(Error::new("hub response too large"));
        }
        Ok(Ok(raw))
    };
    match perform() {
        Ok(Ok(raw)) => Ok(raw),
        Ok(Err((status, retry))) => Err((Error::rejected(status, "hub request failed"), retry)),
        Err(e) => Err((e, 0.0)),
    }
}
fn request_retry(
    url: &str,
    route: &str,
    credential: &str,
    body: &Value,
    ca_file: Option<&Path>,
) -> std::result::Result<Value, (Error, f64)> {
    let raw = post_bytes(
        url,
        route,
        credential,
        encode(body).map_err(|e| (e, 0.0))?,
        ca_file,
    )?;
    serde_json::from_slice(&raw).map_err(|e| (e.into(), 0.0))
}
pub fn request(
    url: &str,
    route: &str,
    credential: &str,
    body: &Value,
    ca_file: Option<&Path>,
) -> Result<Value> {
    request_retry(url, route, credential, body, ca_file).map_err(|e| e.0)
}
pub fn validate_ack(batch: &Value, ack: &Value) -> Result<()> {
    if !ack.is_object()
        || ["device", "generation", "sequence"]
            .iter()
            .any(|k| ack.get(*k) != batch.get(*k))
        || ack["digest"] != digest(batch)?
    {
        return Err(Error::new("invalid durable acknowledgement"));
    }
    Ok(())
}
fn receipt_mac(ack: &Value, credential: &str) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(credential.as_bytes())
        .map_err(|_| Error::new("invalid credential"))?;
    mac.update(&encode(ack)?);
    Ok(mac)
}
pub fn sign_receipt(ack: &Value, credential: &str) -> Result<String> {
    Ok(receipt_mac(ack, credential)?
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
pub struct Outbox {
    pub database: Database,
    pub max_pending: usize,
}
impl Outbox {
    pub fn open(path: &Path) -> Result<Self> {
        Self::with_limits(path, 64 * 1024 * 1024, 1000)
    }
    pub fn with_limits(path: &Path, max_bytes: u64, max_pending: usize) -> Result<Self> {
        let database = Database::open(path, max_bytes)?;
        let db = database.connect()?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS identity(device TEXT,generation TEXT,sequence INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS pending(sequence INTEGER PRIMARY KEY,payload BLOB,attempts INTEGER DEFAULT 0,due REAL DEFAULT 0);")?;
        // An outbox made before native sending lacks the columns that order and describe entries.
        for column in ["queued REAL DEFAULT 0", "status INTEGER DEFAULT 0"] {
            let name = column.split(' ').next().unwrap();
            let present = db
                .prepare("SELECT 1 FROM pragma_table_info('pending') WHERE name=?")?
                .exists([name])?;
            if !present {
                db.execute_batch(&format!("ALTER TABLE pending ADD COLUMN {column}"))?;
            }
        }
        db.execute_batch("CREATE TABLE IF NOT EXISTS native_pending(entry INTEGER PRIMARY KEY AUTOINCREMENT,authority TEXT NOT NULL,sequence INTEGER NOT NULL,payload BLOB NOT NULL,attempts INTEGER DEFAULT 0,due REAL DEFAULT 0,queued REAL NOT NULL,status INTEGER DEFAULT 0,UNIQUE(authority,sequence)); CREATE TABLE IF NOT EXISTS native_sequence(authority TEXT PRIMARY KEY,sequence INTEGER NOT NULL);")?;
        Ok(Self {
            database,
            max_pending,
        })
    }
    pub fn identity(&self) -> Result<Option<Value>> {
        Ok(self.database.connect()?.query_row("SELECT device,generation,sequence FROM identity",[],|r| Ok(json!({"device":r.get::<_,String>(0)?,"generation":r.get::<_,String>(1)?,"sequence":r.get::<_,i64>(2)?}))).optional()?)
    }
    pub fn bind(&self, device: &str, generation: &str) -> Result<()> {
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(String, String)> = tx
            .query_row("SELECT device,generation FROM identity", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        if let Some((d, g)) = prior {
            if d != device || g != generation {
                return Err(Error::new(
                    "outbox already bound; use a new outbox for re-enrollment",
                ));
            }
        } else {
            tx.execute(
                "INSERT INTO identity(device,generation) VALUES(?,?)",
                params![device, generation],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn enqueue(&self, batch: &Value) -> Result<Value> {
        let mut batch = batch.clone();
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(String, String, i64)> = tx
            .query_row("SELECT device,generation,sequence FROM identity", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        let (device, generation, sequence) =
            row.ok_or_else(|| Error::new("outbox identity mismatch"))?;
        if batch["device"] != device || batch["generation"] != generation {
            return Err(Error::new("outbox identity mismatch"));
        }
        let sequence = sequence
            .checked_add(1)
            .ok_or_else(|| Error::rejected(400, "invalid sequence"))?;
        batch["sequence"] = json!(sequence);
        validate(&batch)?;
        let count: usize = tx.query_row("SELECT count(*) FROM pending", [], |r| r.get(0))?;
        if count + queued_native(&tx)? >= self.max_pending {
            return Err(Error::new("outbox full; batch was not queued"));
        }
        tx.execute(
            "INSERT INTO pending(sequence,payload,queued) VALUES(?,?,?)",
            params![sequence, encode(&batch)?, now()],
        )?;
        tx.execute("UPDATE identity SET sequence=?", [sequence])?;
        tx.commit()?;
        Ok(batch)
    }
    /// Queues the newest assessment of a saved capture view as a v2 request. The request is
    /// built from the artifact the capture kept, so the binding it names is the capture's own;
    /// the sequence is the next one of that binding's authority and never reused.
    pub fn enqueue_native(&self, view: &Value) -> Result<Value> {
        let (evidence, raw) = newest_artifact(view)?;
        let artifact: Value = serde_json::from_str(&raw).map_err(|_| {
            Error::instruction("capture artifact is not valid JSON; nothing was queued")
        })?;
        let binding = artifact["binding"].clone();
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (device, generation): (String, String) = tx
            .query_row("SELECT device,generation FROM identity", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .ok_or_else(|| Error::instruction("enrollment required for queue-native"))?;
        if binding["device"] != device || binding["generation"] != generation {
            return Err(Error::instruction("outbox identity mismatch"));
        }
        let authority = String::from_utf8(super::native::canonical(&json!([
            binding["tenant"],
            binding["site"],
            binding["device"],
            binding["generation"],
            binding["scope"]
        ])))
        .map_err(|_| Error::instruction("invalid binding"))?;
        let sequence: i64 = tx
            .query_row(
                "SELECT sequence FROM native_sequence WHERE authority=?",
                [&authority],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0_i64)
            .checked_add(1)
            .ok_or_else(|| Error::instruction("invalid sequence"))?;
        let request = super::native::canonical(
            &json!({"schema":2,"binding":binding,"sequence":sequence,"evidence_id":evidence,"artifact_sha256":format!("{:x}",<Sha256 as sha2::Digest>::digest(raw.as_bytes())),"artifact_byte_length":raw.len(),"artifact_utf8":raw}),
        );
        if request.len() > super::native::REQUEST_LIMIT {
            return Err(Error::instruction(
                "capture is larger than the hub accepts; nothing was queued",
            ));
        }
        let count: usize = tx.query_row("SELECT count(*) FROM pending", [], |r| r.get(0))?;
        if count + queued_native(&tx)? >= self.max_pending {
            return Err(Error::instruction("outbox full; capture was not queued"));
        }
        tx.execute(
            "INSERT INTO native_pending(authority,sequence,payload,queued) VALUES(?,?,?,?)",
            params![authority, sequence, request, now()],
        )?;
        tx.execute(
            "INSERT INTO native_sequence(authority,sequence) VALUES(?,?) ON CONFLICT(authority) DO UPDATE SET sequence=excluded.sequence",
            params![authority, sequence],
        )?;
        tx.commit()?;
        Ok(json!({"queued":"native","sequence":sequence,"evidence_id":evidence}))
    }
    pub fn health(&self) -> Result<Value> {
        let db = self.database.connect()?;
        let totals = |table: &str| -> Result<(i64, i64, i64, Option<f64>)> {
            Ok(db.query_row(
                &format!("SELECT count(*),COALESCE(sum(length(payload)),0),COALESCE(max(attempts),0),min(due) FROM {table}"),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        };
        let (v1, native) = (totals("pending")?, totals("native_pending")?);
        let next_attempt = [v1.3, native.3]
            .into_iter()
            .flatten()
            .fold(f64::INFINITY, f64::min);
        let next_attempt = if next_attempt.is_finite() {
            next_attempt
        } else {
            0.0
        };
        let mut result = json!({"queued":v1.0 + native.0,"bytes":v1.1 + native.1,"attempts":v1.2.max(native.2),"next_attempt":next_attempt});
        // An entry the sender gave up retrying by itself, or the hub refused for good, waits for
        // the operator; it stays queued and is named here.
        let mut attention = vec![];
        for (kind, table, key) in [
            ("v1", "pending", "sequence"),
            ("native", "native_pending", "sequence"),
        ] {
            let mut query = db.prepare(&format!("SELECT {key},attempts,status FROM {table} WHERE attempts>=? OR status IN (400,401,403,409,413,422) ORDER BY queued,{key}"))?;
            let rows = query.query_map([ATTENTION_ATTEMPTS], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (sequence, attempts, status) = row?;
                attention.push(json!({"kind":kind,"sequence":sequence,"attempts":attempts,"last_status":status}));
            }
        }
        result["needs_attention"] = json!(!attention.is_empty());
        result["attention"] = json!(attention);
        let queued_native: Option<f64> =
            db.query_row("SELECT min(queued) FROM native_pending", [], |r| r.get(0))?;
        let first: Option<Vec<u8>> = db
            .query_row(
                "SELECT payload FROM pending ORDER BY sequence LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let v1_age = match first {
            Some(raw) => Some(
                (now()
                    - serde_json::from_slice::<Value>(&raw)?["observed"]
                        .as_f64()
                        .ok_or_else(|| Error::new("invalid observation"))?)
                .max(0.0),
            ),
            None => None,
        };
        let native_age = queued_native.map(|t| (now() - t).max(0.0));
        result["oldest_age"] = json!([v1_age, native_age]
            .into_iter()
            .flatten()
            .fold(0.0, f64::max));
        Ok(result)
    }
    pub fn bundle(&self) -> Result<Value> {
        let raw: Vec<u8> = self
            .database
            .connect()?
            .query_row(
                "SELECT payload FROM pending ORDER BY sequence LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::new("outbox empty"))?;
        Ok(serde_json::from_slice(&raw)?)
    }
    pub fn confirm(&self, receipt: &Value, credential: &str) -> Result<()> {
        if !exact_fields(receipt, &["ack", "signature"]) || !receipt["signature"].is_string() {
            return Err(Error::new("invalid receipt"));
        }
        let signature = receipt["signature"].as_str().unwrap();
        let bytes = if signature.len() == 64
            && signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&signature[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        } else {
            return Err(Error::new("unauthenticated receipt"));
        };
        receipt_mac(&receipt["ack"], credential)?
            .verify_slice(&bytes)
            .map_err(|_| Error::new("unauthenticated receipt"))?;
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (sequence, raw): (i64, Vec<u8>) = tx
            .query_row(
                "SELECT sequence,payload FROM pending ORDER BY sequence LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| Error::new("outbox empty"))?;
        validate_ack(&serde_json::from_slice(&raw)?, &receipt["ack"])?;
        tx.execute("DELETE FROM pending WHERE sequence=?", [sequence])?;
        tx.commit()?;
        Ok(())
    }
    pub fn drain(&self, url: &str, credential: &str, ca_file: Option<&Path>) -> Result<bool> {
        Ok(self.deliver(url, credential, ca_file)?.is_some())
    }
    /// Sends the oldest entry that is due, of either kind, and returns the hub's acknowledgement.
    /// An entry that is not due, or was refused, holds back only the later entries of its own
    /// lane (the v1 stream, or one native authority): sequences of a lane must arrive in order,
    /// but one stuck entry never stops the rest of the outbox. A failed entry stays queued.
    pub fn deliver(
        &self,
        url: &str,
        credential: &str,
        ca_file: Option<&Path>,
    ) -> Result<Option<Value>> {
        self.deliver_with_clock(url, credential, ca_file, now)
    }
    /// Exercise the sender's real scheduling path with a controlled clock.
    #[doc(hidden)]
    pub fn deliver_with_clock(
        &self,
        url: &str,
        credential: &str,
        ca_file: Option<&Path>,
        clock: impl Fn() -> f64,
    ) -> Result<Option<Value>> {
        let mut db = self.database.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows: Vec<(bool, i64, String, i64, f64)> = {
            let mut ordered = tx.prepare("SELECT kind,key,lane,attempts,due FROM (SELECT 0 AS kind,sequence AS key,'v1' AS lane,attempts,due,queued FROM pending WHERE sequence=(SELECT min(sequence) FROM pending) UNION ALL SELECT 1,entry,authority,attempts,due,queued FROM native_pending n WHERE sequence=(SELECT min(sequence) FROM native_pending WHERE authority=n.authority)) ORDER BY queued,kind,key")?;
            let mapped = ordered.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? == 1,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            })?;
            mapped.collect::<std::result::Result<_, _>>()?
        };
        // Only each lane's lowest sequence is a candidate, so a later entry never overtakes it.
        let chosen = rows
            .into_iter()
            .find(|row| row.4 <= clock())
            .map(|(native, key, _, attempts, _)| (native, key, attempts));
        let Some((native, key, attempts)) = chosen else {
            return Ok(None);
        };
        let (table, column) = if native {
            ("native_pending", "entry")
        } else {
            ("pending", "sequence")
        };
        let raw: Vec<u8> = tx.query_row(
            &format!("SELECT payload FROM {table} WHERE {column}=?"),
            [key],
            |r| r.get(0),
        )?;
        tx.commit()?;
        let answer = if native {
            post_bytes(url, "/v2/batches", credential, raw.clone(), ca_file).and_then(|ack| {
                // The hub answered 200: a mismatch is a bad answer, not an HTTP refusal.
                super::native::validate_ack(&raw, &ack)
                    .map_err(|_| (Error::new("invalid durable acknowledgement"), 0.0))?;
                serde_json::from_slice(&ack).map_err(|e| (e.into(), 0.0))
            })
        } else {
            let batch: Value = serde_json::from_slice(&raw)?;
            request_retry(url, "/v1/batches", credential, &batch, ca_file).and_then(|ack| {
                validate_ack(&batch, &ack)
                    .map(|_| ack)
                    .map_err(|e| (e, 0.0))
            })
        };
        match answer {
            Ok(ack) => {
                db.execute(
                    &format!("DELETE FROM {table} WHERE {column}=? AND payload=?"),
                    params![key, raw],
                )?;
                Ok(Some(ack))
            }
            Err((error, retry)) => {
                let maximum = 2_f64
                    .powi((attempts.saturating_add(1)).min(12) as i32)
                    .min(3600.0);
                let random =
                    u64::from_le_bytes(uuid::Uuid::new_v4().as_bytes()[..8].try_into().unwrap())
                        as f64
                        / u64::MAX as f64;
                let delay = (1.0 + random * (maximum - 1.0)).max(retry);
                db.execute(
                    &format!("UPDATE {table} SET attempts=attempts+1,due=MAX(due,?),status=? WHERE {column}=? AND payload=?"),
                    params![clock() + delay, error.http_status.unwrap_or(0), key, raw],
                )?;
                Ok(None)
            }
        }
    }
}
/// Entries of the native kind waiting in the outbox.
fn queued_native(db: &rusqlite::Connection) -> Result<usize> {
    Ok(db.query_row("SELECT count(*) FROM native_pending", [], |r| r.get(0))?)
}
/// The evidence id and artifact text of the newest assessment in a saved capture view.
fn newest_artifact(view: &Value) -> Result<(String, String)> {
    let refusal = || Error::instruction("not a saved capture view; nothing was queued");
    let newest = view["assessment_bindings"]
        .as_array()
        .and_then(|bindings| bindings.iter().max_by_key(|b| b["revision"].as_u64()))
        .ok_or_else(refusal)?;
    // A view of a retired source holds no records: its one piece of evidence is the retirement.
    let from_records = view["records"]
        .as_array()
        .and_then(|records| {
            records
                .iter()
                .find(|r| r["assessment_id"] == newest["assessment_id"])
        })
        .and_then(|r| r["dimensions"]["evidence"].as_str());
    let from_evidence = || {
        let kept = view["evidence"].as_array()?;
        let mut named = kept
            .iter()
            .filter_map(|e| e["evidence_id"].as_str())
            .filter(|e| {
                view["retained_payload_utf8"][*e]
                    .as_str()
                    .and_then(|p| serde_json::from_str::<Value>(p).ok())
                    .is_some_and(|a| a["assessment_id"] == newest["assessment_id"])
            });
        let only = named.next()?;
        named.next().is_none().then_some(only)
    };
    let evidence = from_records.or_else(from_evidence).ok_or_else(refusal)?;
    let artifact = view["retained_payload_utf8"][evidence]
        .as_str()
        .ok_or_else(refusal)?;
    Ok((evidence.to_string(), artifact.to_string()))
}
