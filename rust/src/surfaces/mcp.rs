use super::*;
use crate::domain::{InventoryOptions, ScanOptions};
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
pub fn schemas(repair: bool) -> Value {
    if !repair {
        let mut result = json!({"agent_check":{"type":"object","properties":{"roots":{"type":"array","items":{"type":"string"}},"offline":{"type":"boolean"}},"additionalProperties":false},"agent_inventory":{"type":"object","properties":{"roots":{"type":"array","items":{"type":"string"}}},"additionalProperties":false},"inventory":{"type":"object","properties":{"roots":{"type":"array","items":{"type":"string"}}},"additionalProperties":false},"check":{"type":"object","properties":{"offline":{"type":"boolean"},"roots":{"type":"array","items":{"type":"string"}}},"additionalProperties":false},"list":{"type":"object","properties":{"reader":{"type":"string"},"after":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["reader"]},"read":{"type":"object","properties":{"reader":{"type":"string"},"message":{"type":"integer"}},"required":["reader"]},"ack":{"type":"object","properties":{"reader":{"type":"string"},"message":{"type":"integer"}},"required":["reader","message"]}});
        result["storage"] = json!({"type":"object","properties":{},"additionalProperties":false});
        for key in ["online", "offline_db"] {
            result["check"]["properties"][key] = json!({"type":"boolean"});
        }
        result["attention"] = json!({"type":"object","properties":{"reader":{"type":"string"},"mode":{"type":"string","enum":["current","pending"]},"scope":{"type":"string"},"after":{"type":"integer"},"limit":{"type":"integer","minimum":1,"maximum":100}},"required":["reader"],"additionalProperties":false});
        return result;
    }
    let mut result = json!({});
    for name in [
        "claim", "plan", "apply", "verify", "release", "draft", "dismiss", "can", "drafts",
    ] {
        let mut properties = json!({});
        let mut required = vec![];
        if name != "drafts" {
            properties["agent"] = json!({"type":"string"});
            required.push("agent");
            if name == "can" {
                properties["action"] = json!({"type":"string"});
                required.push("action");
            } else {
                properties["item"] = json!({"type":"string"});
                required.push("item");
            }
        }
        if name == "plan" {
            properties["plan"] = json!({"type":"object"});
            required.push("plan");
        }
        if name == "apply" {
            properties["dry_run"] = json!({"type":"boolean","default":true});
        }
        result[name] = json!({"type":"object","properties":properties,"required":required,"additionalProperties":false});
    }
    result
}
fn configured_inventory_flag(config: &Value, name: &str) -> Result<bool> {
    match config.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(Error::new(format!(
            "local configuration {name} must be a boolean"
        ))),
    }
}
fn argument_flag(args: &Value, name: &str) -> Result<bool> {
    match args.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(Error::usage(format!("argument {name} must be a boolean"))),
    }
}

fn description(name: &str) -> &'static str {
    match name {
        "agent_check" => "Assess AI-agent components found in configured project roots using existing posture checks and npm/PyPI advisory matching; save findings to the mailbox. Uses advisory feeds unless offline is true. Home and model scans are excluded. Unsupported and incomplete coverage is explicit. Does not execute discovered commands or apply repairs.",
        "agent_inventory" => "Inspect AI agent configuration, MCP servers, skills and hooks found in configured project roots. Local read-only discovery and posture checks only: no commands executed, no advisory requests, no home-wide or model-file scan. Missing or skipped coverage is reported; this is not a vulnerability clearance.",
        "inventory" => "Discover supported packages in locally configured project roots without advisory requests or mailbox changes. Omit roots to use configured roots (working directory if unconfigured). Inspect errors and input_evidence: inventory alone does not establish safety. Unconfigured roots are refused.",
        "check" => "Scan supported lockfiles and pinned requirements*.txt in configured project roots (omit roots for the configured scope) and update the vulnerability mailbox. Pass offline_db: true to query the local advisory database, online: true to query OSV.dev, or offline: true for inventory-only scans (always unknown); conflicting booleans are rejected, and omitting them follows the CLI config/environment default. Missing or stale local databases and unavailable coverage save unknown health findings, never clean. Does not apply repairs.",
        "storage" => "Report selected local state storage accounting and admission policy without deleting or archiving evidence.",
        "attention" => "Read bounded saved current findings or pending unacknowledged messages, including already seen deliveries. No scan, network or receipt mutation. ACK affects delivery only.",
        "list" => "List unread vulnerability messages for a stable reader identity, oldest first, 20 per call unless limit (at most 100) says otherwise. When more remain, a second content item reports truncated, remaining and next_after; pass after: next_after for the next page. Use the same reader across sessions, read each message, then acknowledge after the intended recipient reviews the delivery. This does not run a scan.",
        "read" => "Read a vulnerability message for your reader identity; omit message to read all available messages and mark them seen. Reading does not repair the affected software.",
        "ack" => "Acknowledge delivery reviewed by the intended recipient for your reader identity. This advances mailbox delivery only; it does not fix or resolve the vulnerability.",
        _ => "Vulnerability mailbox",
    }
}
pub fn call(
    state: &Path,
    request: &Value,
    bound: Option<&str>,
    repairs: Option<&mut Repairs>,
) -> Result<Value> {
    call_with_store(state, request, bound, repairs, &mut None)
}
fn call_with_store(
    state: &Path,
    request: &Value,
    bound: Option<&str>,
    repairs: Option<&mut Repairs>,
    session: &mut Option<Store>,
) -> Result<Value> {
    let repair = repairs.is_some();
    let schemas = schemas(repair);
    match field(request, "method")? {
        "initialize" => Ok(
            json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":if repair{"vorda-fix"}else{"vorda"},"version":"0.1.0"}}),
        ),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(
            json!({"tools":schemas.as_object().unwrap().iter().map(|(name,schema)|json!({"name":name,"description":if repair{format!("Policy checked repair {name}")}else{description(name).to_owned()},"inputSchema":schema})).collect::<Vec<_>>()}),
        ),
        "tools/call" => {
            let name = field(&request["params"], "name")?;
            let args = request["params"]
                .get("arguments")
                .cloned()
                .unwrap_or(json!({}));
            let schema = schemas
                .get(name)
                .ok_or_else(|| Error::new("unknown tool"))?;
            if !args.is_object() {
                return Err(Error::new("arguments must be object"));
            }
            if args
                .as_object()
                .unwrap()
                .keys()
                .any(|k| schema["properties"].get(k).is_none())
                || schema["required"].as_array().is_some_and(|required| {
                    required
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|k| args.get(k).is_none())
                })
            {
                return Err(Error::new("unknown or missing required tool arguments"));
            }
            if repair {
                if args
                    .as_object()
                    .unwrap()
                    .keys()
                    .any(|k| schema["properties"].get(k).is_none())
                    || schema["required"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|k| {
                            if k == "plan" {
                                !args[k].is_object()
                            } else {
                                args[k].as_str().is_none_or(|s| s.is_empty())
                            }
                        })
                {
                    return Err(Error::new("unknown or invalid tool arguments"));
                }
                if args.get("agent").is_some_and(|v| v.as_str() != bound) {
                    return Err(Error::rejected(
                        403,
                        "MCP agent differs from host-bound identity",
                    ));
                }
                let data = repairs.unwrap().dispatch(name, &args)?;
                return Ok(json!({"content":[{"type":"text","text":data.to_string()}]}));
            }
            let data = if name == "storage" {
                crate::store::storage_report(state)?
            } else if ["check", "inventory", "agent_inventory", "agent_check"].contains(&name) {
                if args
                    .as_object()
                    .unwrap()
                    .keys()
                    .any(|k| schema["properties"].get(k).is_none())
                    || args.get("offline").is_some_and(|v| !v.is_boolean())
                {
                    return Err(Error::new("unknown arguments or invalid offline flag"));
                }
                let config_path = state.join("config.json");
                let config = if config_path.exists() {
                    read_json(&config_path)?
                } else {
                    json!({"roots":[crate::cli::resolved(&std::env::current_dir()?)?]})
                };
                let roots = args.get("roots").unwrap_or(&config["roots"]);
                let roots = roots
                    .as_array()
                    .filter(|a| !a.is_empty())
                    .ok_or_else(|| Error::new("configured roots are required"))?
                    .iter()
                    .map(|v| {
                        let root = v
                            .as_str()
                            .ok_or_else(|| Error::new("roots must be strings"))?;
                        let path = crate::cli::resolved(Path::new(root))?;
                        if !config["roots"]
                            .as_array()
                            .is_some_and(|r| r.contains(&json!(path)))
                        {
                            return Err(Error::rejected(
                                403,
                                "check roots must be configured locally",
                            ));
                        }
                        Ok(Path::new(root).to_path_buf())
                    })
                    .collect::<Result<Vec<_>>>()?;
                let inventory = InventoryOptions {
                    roots,
                    os_packages: configured_inventory_flag(&config, "os_packages")?,
                    tools: configured_inventory_flag(&config, "tools")?,
                    browsers: configured_inventory_flag(&config, "browsers")?,
                    installed_apps: configured_inventory_flag(&config, "installed_apps")?,
                    installed_roots: match config.get("installed_roots") {
                        None => vec![],
                        Some(Value::Array(paths)) => paths
                            .iter()
                            .map(|v| {
                                v.as_str()
                                    .map(PathBuf::from)
                                    .ok_or_else(|| Error::new("installed_roots must contain paths"))
                            })
                            .collect::<Result<Vec<_>>>()?,
                        Some(_) => return Err(Error::new("installed_roots must be an array")),
                    },
                    ..Default::default()
                };
                if name == "agent_inventory" || name == "agent_check" {
                    let bom = crate::scanner::agentbom::collect_scoped(
                        &crate::repair::commands::home(),
                        &inventory.roots,
                        &crate::store::hostname()?,
                    )?;
                    if name == "agent_check" {
                        crate::cli::assess_agentbom(
                            state,
                            bom,
                            args["offline"].as_bool().unwrap_or(false),
                            false,
                        )?
                    } else {
                        json!({"status":"inventory-only","items":bom.items,"packages":bom.packages,
                        "findings":bom.findings,"posture":bom.posture,"errors":bom.errors,
                        "coverage":{"incomplete":bom.incomplete,"skipped_kinds":bom.skip_kinds,
                            "uncertain_sources":bom.unsure_sources,"uncertain_assets":bom.unsure_assets,
                            "advisories_checked":false,"home_scanned":false,"models_scanned":false}})
                    }
                } else if name == "inventory" {
                    Value::Object(crate::scanner::inventory(&inventory)?)
                } else {
                    let mut options = ScanOptions {
                        inventory,
                        offline: argument_flag(&args, "offline")?,
                        mcp_scope: true,
                        ..Default::default()
                    };
                    let online = argument_flag(&args, "online")?;
                    let offline_db = argument_flag(&args, "offline_db")?;
                    if [online, offline_db, options.offline]
                        .iter()
                        .filter(|b| **b)
                        .count()
                        > 1
                    {
                        return Err(Error::usage("online, offline_db, and offline cannot be combined; set at most one to true"));
                    }
                    options.offline_db = if online {
                        Some(false)
                    } else if offline_db {
                        Some(true)
                    } else if options.offline {
                        Some(false)
                    } else {
                        Some(crate::scanner::osvdb::configured_scan(state)?)
                    };
                    Value::Object(crate::cli::check(&options, &mut Store::open(state)?)?)
                }
            } else {
                let reader = field(&args, "reader")?;
                let id = args.get("message").cloned().unwrap_or(json!(0));
                if !id.is_number()
                    || !id
                        .to_string()
                        .trim_start_matches('-')
                        .bytes()
                        .all(|b| b.is_ascii_digit())
                {
                    return Err(Error::new("message must be integer"));
                }
                if name == "attention" {
                    let mode = args
                        .get("mode")
                        .map(|v| v.as_str().ok_or_else(|| Error::new("mode must be string")))
                        .transpose()?
                        .unwrap_or("current");
                    let scope = args
                        .get("scope")
                        .map(|v| v.as_str().ok_or_else(|| Error::new("scope must be string")))
                        .transpose()?;
                    let after = args
                        .get("after")
                        .map(|v| {
                            v.as_i64()
                                .ok_or_else(|| Error::new("after must be integer"))
                        })
                        .transpose()?
                        .unwrap_or(0);
                    let limit = args
                        .get("limit")
                        .map(|v| {
                            v.as_u64()
                                .ok_or_else(|| Error::new("limit must be integer"))
                        })
                        .transpose()?
                        .unwrap_or(50);
                    if !["current", "pending"].contains(&mode)
                        || after < 0
                        || !(1..=100).contains(&limit)
                    {
                        return Err(Error::new("invalid attention selection"));
                    }
                    if session.is_none() {
                        *session = Some(Store::open(state)?);
                    }
                    session.as_ref().unwrap().attention(
                        reader,
                        mode,
                        scope,
                        after,
                        limit as usize,
                    )?
                } else {
                    let bound = |key: &str, min: u64, max: u64, default: u64| {
                        args.get(key)
                            .map(|v| v.as_u64().filter(|n| (min..=max).contains(n)))
                            .unwrap_or(Some(default))
                            .ok_or_else(|| Error::new(format!("invalid {key}")))
                    };
                    let (after, limit) = if name == "list" {
                        (
                            bound("after", 0, i64::MAX as u64, 0)? as i64,
                            bound("limit", 1, 100, crate::store::MAIL_PAGE as u64)? as usize,
                        )
                    } else {
                        (0, 0)
                    };
                    if session.is_none() {
                        *session = Some(Store::open(state)?);
                    }
                    let mail = session.as_mut().unwrap().mail(
                        reader,
                        name,
                        id.as_number().unwrap(),
                        &3600.into(),
                    )?;
                    if name == "list" {
                        let (page, remaining) = crate::store::page(mail, after, limit);
                        let marker = json!({"truncated":true,"returned":page.len(),"remaining":remaining,"next_after":page.last().map(|m| m["id"].clone())});
                        let mut content =
                            vec![json!({"type":"text","text":Value::Array(page).to_string()})];
                        if remaining > 0 {
                            content.push(json!({"type":"text","text":marker.to_string()}));
                        }
                        return Ok(json!({"content":content}));
                    }
                    mail
                }
            };
            Ok(json!({"content":[{"type":"text","text":data.to_string()}]}))
        }
        _ => Err(Error::new("unknown method")),
    }
}
pub fn serve(state: &Path, config: Option<(&Path, &str)>) -> Result<()> {
    let mut session = None;
    let mut repairs = config.map(|(p, _)| Repairs::open(state, p)).transpose()?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let mut input = stdin.lock();
    loop {
        let mut bytes = Vec::new();
        let n = input
            .by_ref()
            .take(4_000_001)
            .read_until(b'\n', &mut bytes)?;
        if n == 0 {
            break;
        }
        if bytes.len() > 4_000_000 {
            return Err(Error::new("MCP request exceeds limit"));
        }
        let request = serde_json::from_slice::<Value>(&bytes);
        if request
            .as_ref()
            .is_ok_and(|r| r.is_object() && r.get("id").is_none())
        {
            continue;
        }
        let id = request
            .as_ref()
            .ok()
            .and_then(|r| r.get("id"))
            .cloned()
            .unwrap_or(Value::Null);
        let result = request.map_err(Error::from).and_then(|r| {
            call_with_store(
                state,
                &r,
                config.map(|(_, a)| a),
                repairs.as_mut(),
                &mut session,
            )
        });
        let response = match result {
            Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err(e) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":if e.message=="unknown method" && config.is_none(){-32601}else{-32602},"message":e.to_string()}})
            }
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}
