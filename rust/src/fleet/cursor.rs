//! Opaque, authenticated page cursors. A cursor is `base64url(offset).hex(mac)` and carries nothing
//! else: the MAC covers the reader, the grant, the query, the snapshot revision and the policy
//! version, which the server recomputes on every request. A cursor presented under any other
//! binding fails the same way as an invented one, so a failure says nothing about which part
//! differed or whether the cursor was ever real.
use crate::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Bumped when what a cursor means changes, which invalidates every outstanding cursor.
pub const POLICY_VERSION: u32 = 1;

/// What a cursor is bound to. All of it is recomputed from live state per request.
pub struct Binding<'a> {
    pub reader: &'a str,
    pub grant: &'a str,
    pub query: &'a str,
    pub revision: &'a str,
}

pub fn invalid() -> Error {
    Error::rejected(400, "invalid or expired cursor: restart the query")
}
/// A cursor continues a walk only for an hour, so a snapshot cannot be resumed days later.
pub const MAX_AGE_SECS: u64 = 3600;
fn mac(key: &[u8; 32], b: &Binding, offset: u64, issued: u64) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    for part in [
        "vorda-cursor-v1",
        b.reader,
        b.grant,
        b.query,
        b.revision,
        &POLICY_VERSION.to_string(),
        &offset.to_string(),
        &issued.to_string(),
    ] {
        m.update(part.as_bytes());
        m.update(&[0]);
    }
    m
}
/// `issued` is the whole second the walk started; later pages keep it, so a walk has one age.
pub fn issue(key: &[u8; 32], b: &Binding, offset: u64, issued: u64) -> String {
    let tag = mac(key, b, offset, issued).finalize().into_bytes();
    let hex: String = tag.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}.{hex}",
        URL_SAFE_NO_PAD.encode(format!("{offset}:{issued}"))
    )
}
/// The `(offset, issued)` a valid, unexpired cursor carries; every defect, including age, is the
/// same `invalid()`. Only the canonical spelling of a cursor is accepted.
pub fn open(key: &[u8; 32], b: &Binding, cursor: &str, now: f64) -> Result<(u64, u64)> {
    let (encoded, tag) = cursor.split_once('.').ok_or_else(invalid)?;
    let text = String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let (offset, issued) = text.split_once(':').ok_or_else(invalid)?;
    let (offset, issued): (u64, u64) = (
        offset.parse().map_err(|_| invalid())?,
        issued.parse().map_err(|_| invalid())?,
    );
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if URL_SAFE_NO_PAD.encode(format!("{offset}:{issued}")) != encoded
        || tag.len() != 64
        || !tag.bytes().all(lower_hex)
    {
        return Err(invalid());
    }
    let raw: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&tag[2 * i..2 * i + 2], 16).map_err(|_| invalid()))
        .collect::<Result<_>>()?;
    mac(key, b, offset, issued)
        .verify_slice(&raw)
        .map_err(|_| invalid())?;
    let age = now - issued as f64;
    if !(-60.0..=MAX_AGE_SECS as f64).contains(&age) {
        return Err(invalid());
    }
    Ok((offset, issued))
}
