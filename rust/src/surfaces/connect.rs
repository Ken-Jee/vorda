use crate::repair::commands::read_json;
use crate::{
    store::{atomic, private_dir},
    Error, Result,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn refuse_link(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::new(
            "configuration file is a symlink; connect the resolved file instead",
        ));
    }
    Ok(())
}
pub fn plan(client: &str, home: &Path, state: &Path, config: Option<&Path>) -> Result<Value> {
    let state = if state.exists() {
        fs::canonicalize(state)?
    } else {
        std::path::absolute(state)?
    };
    let command = json!({"command":std::env::current_exe()?,"args":["--state",state,"mcp"]});
    plan_entry(client, home, config, "vorda", command, &[])
}
/// The `vorda hub-mcp` bridge as a second MCP entry (`name`, default `vorda-fleet`) for the two
/// clients with acceptance work planned. Only the environment variable's name is recorded.
pub fn plan_hub(
    client: &str,
    home: &Path,
    config: Option<&Path>,
    hub: &str,
    reader_env: &str,
    ca_file: Option<&Path>,
    name: &str,
) -> Result<Value> {
    if !["claude-code", "codex"].contains(&client) {
        return Err(Error::usage("hub mode supports claude-code and codex only"));
    }
    if !super::hub_mcp::hub_is_usable(hub) {
        return Err(Error::usage(
            "--hub must be an https origin (http only on loopback) with no path, query or credentials",
        ));
    }
    if !super::hub_mcp::is_env_name(reader_env) {
        return Err(Error::usage(
            "--reader-env must name an environment variable",
        ));
    }
    if name.is_empty()
        || name.len() > 32
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
    {
        return Err(Error::usage("--name must be 1-32 letters, digits, - or _"));
    }
    let mut args = vec![
        json!("hub-mcp"),
        json!("--hub"),
        json!(hub),
        json!("--reader-env"),
        json!(reader_env),
    ];
    if let Some(ca) = ca_file {
        if !super::hub_mcp::readable_ca_file(ca) {
            return Err(Error::new("--ca-file must name a readable file"));
        }
        args.extend([json!("--ca-file"), json!(std::path::absolute(ca)?)]);
    }
    let command = json!({"command":std::env::current_exe()?,"args":args});
    // Codex starts a server with a minimal environment and passes only the variables listed here.
    plan_entry(client, home, config, name, command, &[reader_env])
}
fn plan_entry(
    client: &str,
    home: &Path,
    config: Option<&Path>,
    name: &str,
    command: Value,
    env_vars: &[&str],
) -> Result<Value> {
    let path = if let Some(config) = config {
        config.to_path_buf()
    } else {
        match client {
            "claude-code" => home.join(".claude.json"),
            "cursor" => home.join(".cursor/mcp.json"),
            "codex" => home.join(".codex/config.toml"),
            "claude-desktop" => {
                if cfg!(windows) {
                    std::env::var_os("APPDATA")
                        .map(Into::into)
                        .unwrap_or_else(|| home.join("AppData/Roaming"))
                        .join("Claude/claude_desktop_config.json")
                } else {
                    home.join("Library/Application Support/Claude/claude_desktop_config.json")
                }
            }
            _ => return Err(Error::usage("unrecognized MCP client")),
        }
    };
    refuse_link(&path)?;
    let before = if path.exists() {
        Some(fs::read_to_string(&path)?)
    } else {
        None
    };
    let after = if client == "codex" {
        let text = before.as_deref().unwrap_or("");
        let parsed: toml::Value = toml::from_str(text).map_err(|e| Error::new(e.to_string()))?;
        if parsed
            .get("mcp_servers")
            .and_then(|s| s.get(name))
            .is_some()
        {
            return Err(Error::new(format!(
                "{name} entry already exists; remove or undo before connecting"
            )));
        }
        if text
            .lines()
            .any(|line| line.trim_start().starts_with("mcp_servers") && line.contains('='))
        {
            return Err(Error::new("cannot extend inline mcp_servers table"));
        }
        let mut block = format!(
            "\n[mcp_servers.{name}]\ncommand = {}\nargs = {}\n",
            command["command"], command["args"]
        );
        if !env_vars.is_empty() {
            block += &format!("env_vars = {}\n", json!(env_vars));
        }
        let after = format!("{text}{block}");
        toml::from_str::<toml::Value>(&after)
            .map_err(|_| Error::new("generated Codex entry is not valid TOML; refusing"))?;
        after
    } else {
        let mut document: Value = serde_json::from_str(before.as_deref().unwrap_or("{}"))?;
        if !document.is_object() {
            return Err(Error::new("client configuration must be an object"));
        }
        if document.get("mcpServers").is_none() {
            document["mcpServers"] = json!({});
        }
        if !document["mcpServers"].is_object() || document["mcpServers"].get(name).is_some() {
            return Err(Error::new(format!("invalid or existing {name} entry")));
        }
        document["mcpServers"][name] = command.clone();
        format!("{}\n", serde_json::to_string_pretty(&document)?)
    };
    Ok(
        json!({"path":path,"client":client,"name":name,"before":before,"after":after,"diff":format!("--- {}\n+++ {}\n+ Add mcp server {name}: {}\n",path.display(),path.display(),command)}),
    )
}
pub fn apply(change: &Value) -> Result<Value> {
    let path = Path::new(super::text(change, "path")?);
    refuse_link(path)?;
    let before = if path.exists() {
        Some(fs::read_to_string(path)?)
    } else {
        None
    };
    if json!(before) != change["before"] {
        return Err(Error::new("configuration changed since preview"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("configuration path needs a parent"))?;
    fs::create_dir_all(parent)?;
    let private = parent.join(format!(".vorda-backup-{}", uuid::Uuid::new_v4().simple()));
    private_dir(&private)?;
    let old = if before.is_some() {
        fs::read(path)?
    } else {
        vec![]
    };
    let backup = private.join("original");
    fs::write(&backup, &old)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))?;
    }
    let after = super::text(change, "after")?;
    let name = super::text(change, "name")?;
    let mut metadata = json!({"client":change["client"],"name":name,"existed":before.is_some(),"installed_hash":hash(after.as_bytes())});
    if change["client"] == "codex" {
        metadata["block"] = json!(&after[before.as_deref().unwrap_or("").len()..]);
    } else {
        let document: Value = serde_json::from_str(after)?;
        metadata["entry"] = document["mcpServers"][name].clone();
    }
    atomic(&private.join("metadata.json"), &metadata.to_string())?;
    atomic(path, after)?;
    Ok(json!({"path":path,"sha256":hash(&old),"backup":backup}))
}
pub fn undo(receipt: &Value) -> Result<()> {
    let path = Path::new(super::text(receipt, "path")?);
    refuse_link(path)?;
    let backup = Path::new(super::text(receipt, "backup")?);
    let old = fs::read(backup)?;
    if hash(&old) != super::text(receipt, "sha256")? {
        return Err(Error::new("backup content changed; refusing undo"));
    }
    let metadata_path = backup.parent().unwrap().join("metadata.json");
    let metadata = read_json(&metadata_path)?;
    // Receipts written before hub mode carry no name.
    let name = metadata["name"].as_str().unwrap_or("vorda");
    let current = fs::read_to_string(path)?;
    if hash(current.as_bytes()) != metadata["installed_hash"] {
        if metadata["client"] == "codex" {
            let block = super::text(&metadata, "block")?;
            if current.matches(block).count() != 1 {
                return Err(Error::new("installed entry changed; refusing overwrite"));
            }
            atomic(path, &current.replacen(block, "", 1))?;
        } else {
            let mut document: Value = serde_json::from_str(&current)?;
            if document["mcpServers"][name] != metadata["entry"] {
                return Err(Error::new("installed entry changed; refusing overwrite"));
            }
            document["mcpServers"]
                .as_object_mut()
                .ok_or_else(|| Error::new("MCP mapping is required"))?
                .remove(name);
            atomic(
                path,
                &format!("{}\n", serde_json::to_string_pretty(&document)?),
            )?;
        }
    } else if metadata["existed"] == true {
        atomic(
            path,
            std::str::from_utf8(&old).map_err(|e| Error::new(e.to_string()))?,
        )?;
    } else {
        fs::remove_file(path)?;
    }
    fs::remove_file(backup)?;
    fs::remove_file(metadata_path)?;
    fs::remove_dir(backup.parent().unwrap())?;
    Ok(())
}
