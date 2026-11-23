pub mod action;
pub mod manifests;
use crate::{Error, Result};
use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn invalid(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
        class: "ValueError".into(),
        http_status: None,
        usage: false,
        busy: false,
    }
}

/// The release public key built into the binary (minisign key ID 57E5204A70E3811B). A build
/// whose key file is a placeholder has no release key and reports itself unsigned.
const RELEASE_KEY: &str = include_str!("../../release/vorda-release.pub");

pub(crate) fn built_in_key() -> Option<&'static str> {
    (!RELEASE_KEY.contains("PLACEHOLDER")).then_some(RELEASE_KEY)
}

fn verify_file(
    file: &Path,
    signature: &Path,
    key_text: &str,
) -> std::result::Result<(String, String), String> {
    let key = PublicKey::decode(key_text).map_err(|e| e.to_string())?;
    let signature = Signature::from_file(signature).map_err(|e| e.to_string())?;
    let content = fs::read(file).map_err(|e| e.to_string())?;
    key.verify(&content, &signature, true)
        .map_err(|e| e.to_string())?;
    let encoded = key_text
        .lines()
        .find(|line| !line.trim().is_empty() && !line.starts_with("untrusted comment:"))
        .ok_or("missing public key")?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| e.to_string())?;
    let bytes: [u8; 8] = raw
        .get(2..10)
        .ok_or("invalid public key identifier")?
        .try_into()
        .map_err(|_| "invalid public key identifier")?;
    Ok((
        format!("{:X}", u64::from_le_bytes(bytes)),
        signature.trusted_comment().to_owned(),
    ))
}

/// Verify a downloaded artifact or the running native executable.
pub fn verify_self(args: &[String]) -> Result<i32> {
    let mut file = None;
    let mut signature = None;
    let mut public_key = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--help" || arg == "-h" {
            println!(
                "Usage: vorda verify-self [--file FILE] [--sig SIGNATURE] [--pubkey PUBLIC_KEY]"
            );
            return Ok(0);
        }
        let slot = match arg.as_str() {
            "--file" => &mut file,
            "--sig" => &mut signature,
            "--pubkey" => &mut public_key,
            _ => {
                return Err(Error::usage(format!(
                    "unrecognized verify-self argument: {arg}"
                )))
            }
        };
        *slot = Some(PathBuf::from(
            iter.next()
                .filter(|value| !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V"))
                .ok_or_else(|| Error::usage(format!("{arg} requires a value")))?,
        ));
    }
    if file.is_some() && public_key.is_none() && built_in_key().is_none() {
        return Err(Error::usage(
            "--file needs --pubkey: this build has no release key built in",
        ));
    }
    if signature.is_some() && file.is_none() {
        return Err(Error::usage("--sig needs --file"));
    }
    let explicit_file = file.is_some();
    let file = match file {
        Some(path) => path,
        None => std::env::current_exe().map_err(|e| invalid(e.to_string()))?,
    };
    let signature = signature.unwrap_or_else(|| {
        let mut name = file.as_os_str().to_owned();
        name.push(".minisig");
        PathBuf::from(name)
    });
    // A key file beside the executable is never trusted: whoever replaced the binary could
    // replace it too. Only --pubkey or the key compiled into this build count.
    let required = public_key.is_some();
    // A key or file that cannot be read was never checked: that is not evidence of tampering.
    let unreadable = |what: &str, path: &Path, e: std::io::Error| json!({"status":"unverified", "file":file, "detail":format!("cannot read the {what} {}: {e}", path.display())});
    let key = match public_key {
        Some(path) => Some(fs::read_to_string(&path).map_err(|e| unreadable("key file", &path, e))),
        None => built_in_key().map(|key| Ok(key.to_owned())),
    };
    let key = key.map(|key| {
        // Open and read one byte: a missing file, no read permission and a folder all fail here.
        let readable =
            fs::File::open(&file).and_then(|mut f| std::io::Read::read(&mut f, &mut [0u8; 1]));
        key.and_then(|key| match readable {
            Err(e) => Err(unreadable("file", &file, e)),
            Ok(_) => Ok(key),
        })
    });
    let result: Value = match key {
        None => {
            json!({"status":"unsigned", "detail":"This binary has no release key built in because it was built with a placeholder release key file (every standard Vorda build, including official releases and builds compiled from source, has the release key built in). Pass --pubkey FILE to check against a key you trust."})
        }
        Some(_) if !explicit_file && !required && !signature.exists() => {
            json!({"status":"unsigned", "detail":"No signature beside this executable. Pass --pubkey to require one."})
        }
        Some(Err(report)) => report,
        Some(Ok(key)) => match verify_file(&file, &signature, &key) {
            Ok((key_id, trusted_comment)) => {
                json!({"status":"verified", "file":file, "key_id":key_id, "trusted_comment":trusted_comment, "key_source":if required {"--pubkey"} else {"built-in release key"}})
            }
            Err(detail) => json!({"status":"tampered", "file":file, "detail":detail}),
        },
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|e| invalid(e.to_string()))?
    );
    Ok(match result["status"].as_str() {
        Some("verified") => 0,
        Some("tampered") => 1,
        _ => 2,
    })
}

/// License and attribution text travels with the native executable.
pub fn licenses() -> &'static str {
    include_str!("../../THIRD_PARTY_LICENSES.txt")
}
