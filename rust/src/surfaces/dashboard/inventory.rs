//! The Inventory page: what the saved scans found, by machine, project, browser and agent tool.
use super::english::{a, browser_name, number, s};
use super::views::{
    attention, cmdline, encoded, grouped, head, icon, no_scans_label, project_href, scan_problem,
    scope_row, state,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const TABS: [(&str, &str); 4] = [
    ("machines", "Machines"),
    ("projects", "Projects"),
    ("browsers", "Browsers"),
    ("agents", "Agent tools"),
];
/// The agent command-line tools a machine scan looks for (`scanner::inventory`, `tool:` paths).
const AGENT_CLIS: [&str; 4] = ["tool:claude", "tool:codex", "tool:gemini", "tool:opencode"];

/// An agent tool: an agentbom row, or one of the agent CLIs a machine scan found.
pub fn is_agent_tool(item: &Value) -> bool {
    item["category"] == "Developer Tools"
        && (item["subtype"] != "tool" || AGENT_CLIS.contains(&s(&item["record"], "path")))
}

/// The lockfiles project scans read, one per path.
pub fn lockfiles(items: &[Value]) -> BTreeSet<(&str, &str)> {
    items
        .iter()
        .filter(|i| i["subtype"] == "project")
        .map(|i| (s(i, "host"), s(&i["record"], "path")))
        .filter(|(_, path)| !path.is_empty())
        .collect()
}

fn item_side(item: &Value) -> String {
    match number(item, "finding_count") as usize {
        0 if item["checked"] == true => "Checked".into(),
        0 => "Not checked".into(),
        n => attention(n, &Value::Null),
    }
}

fn legend() -> String {
    let facts: String = [
        ("Completed", "Show sources scanned successfully and the assets discovered."),
        ("Partial", "Show paths or advisory sources that could not be checked."),
        ("Unknown", "Make unsupported inventories explicit, particularly agent tools and unrecognized platforms."),
    ]
    .iter()
    .map(|(title, line)| format!("<div class=\"fact\"><b>{title}</b><p>{line}</p></div>"))
    .collect();
    format!("<section class=\"panel sidecard\"><h2>Coverage is part of the result</h2><p class=\"lead\">A missing finding does not always mean a machine is secure.</p>{facts}</section>")
}

fn subnav(current: &str, counts: Option<[usize; 4]>) -> String {
    let links: String = TABS
        .iter()
        .enumerate()
        .map(|(n, (key, label))| {
            let on = if *key == current {
                " class=\"on\" aria-current=\"page\""
            } else {
                ""
            };
            let count = counts.map_or(String::new(), |c| {
                format!("<span class=\"n\">{}</span>", grouped(c[n]))
            });
            format!("<a href=\"/inventory?tab={key}\"{on}>{label}{count}</a>")
        })
        .collect();
    format!("<nav class=\"subnav\" aria-label=\"Inventory\">{links}</nav>")
}

fn layout(current: &str, counts: Option<[usize; 4]>, main: &str, right: &str) -> String {
    head(
        "Inventory",
        "What Vorda can discover, where each item lives, and where visibility remains uncertain.",
        right,
    ) + &subnav(current, counts)
        + &format!("<div class=\"grid page-grid\">{main}{}</div>", legend())
}

pub fn inventory_screen(snapshot: &Value, tab: &str) -> String {
    let tab = TABS
        .iter()
        .map(|(key, _)| *key)
        .find(|key| *key == tab)
        .unwrap_or("machines");
    let (hosts, projects) = (a(snapshot, "hosts"), a(snapshot, "projects"));
    if hosts.is_empty() && projects.is_empty() {
        let title = if snapshot["has_scans"] == true {
            no_scans_label(snapshot)
        } else {
            "No inventory yet"
        };
        let first = state(
            "findings",
            title,
            "Vorda shows findings, coverage and inventory after the first scan.",
            &cmdline("vorda scan"),
            "",
        );
        return layout(
            tab,
            None,
            &format!("<section class=\"panel\">{first}</section>"),
            "",
        );
    }
    let now = number(snapshot, "now");
    let items = a(&snapshot["assets"], "items");
    let browsers: Vec<_> = items.iter().filter(|i| i["subtype"] == "browser").collect();
    let tools: Vec<_> = items
        .iter()
        .filter(|i| i["category"] == "Developer Tools")
        .collect();
    let agents = tools.iter().filter(|i| is_agent_tool(i)).count();
    let counts = [hosts.len(), projects.len(), browsers.len(), agents];
    let empty = |title: &str, line: &str| state("inventory", title, line, "", "small");
    let body = match tab {
        "projects" if projects.is_empty() => empty(
            "No projects found",
            "Vorda finds projects from lockfiles such as package-lock.json and Cargo.lock under scanned folders, or you can scan a folder directly with vorda scan PATH.",
        ),
        "projects" => {
            let lockfiles = lockfiles(items);
            let rows: String = projects
                .iter()
                .map(|p| {
                    let root = s(p, "root");
                    let mine: Vec<&str> = lockfiles
                        .iter()
                        .filter(|(host, path)| {
                            *host == s(p, "host") && !root.is_empty() && Path::new(path).starts_with(root)
                        })
                        .map(|(_, path)| *path)
                        .collect();
                    let ecosystems: BTreeSet<&str> = items
                        .iter()
                        .filter(|i| i["subtype"] == "project" && i["host"] == p["host"])
                        .filter(|i| mine.contains(&s(&i["record"], "path")))
                        .map(|i| s(&i["record"], "ecosystem"))
                        .collect();
                    let place = match mine.as_slice() {
                        [one] => one.to_string(),
                        [] if p["imported"] == true => s(p, "source").to_string(),
                        [] if root.is_empty() => "Location not recorded".into(),
                        [] => root.to_string(),
                        many => format!("{root} · {} lockfiles", many.len()),
                    };
                    let desc = ecosystems
                        .into_iter()
                        .chain([place.as_str()])
                        .collect::<Vec<_>>()
                        .join(" · ");
                    let side = if p["scan"] != "ok" {
                        "Can't confirm".to_string()
                    } else {
                        attention(number(p, "open") as usize, &p["scan"])
                    };
                    scope_row(&project_href(p), "pkg", s(p, "name"), &desc, &side)
                })
                .collect();
            format!("<div class=\"entity list-heavy\">{rows}</div>")
        }
        "browsers" if browsers.is_empty() => empty("No browsers found", ""),
        "browsers" => {
            let rows: String = browsers
                .iter()
                .map(|b| {
                    let path = s(&b["record"], "path");
                    let name = format!("{} {}", browser_name(path), s(&b["record"], "version"));
                    scope_row(&host_href(b), "globe", name.trim(), path, &item_side(b))
                })
                .collect();
            format!("<div class=\"entity\">{rows}</div>")
        }
        "agents" => {
            let mut body = if agents == 0 {
                state(
                    "bot",
                    "No agent tools found",
                    "A machine scan looks for the Claude Code, Codex, Gemini, and OpenCode command-line tools, and vorda agentbom lists MCP servers, skills, and models in a project.",
                    "",
                    "small",
                )
            } else {
                String::new()
            };
            let rows: String = tools
                .iter()
                .map(|t| {
                    let record = &t["record"];
                    let name = format!("{} {}", s(record, "name"), s(record, "version"));
                    let (ic, kind) = match s(t, "subtype") {
                        "tool" if is_agent_tool(t) => ("bot", "Agent CLI"),
                        "tool" => ("terminal", "Tool"),
                        "mcp" | "mcp-config" | "mcp-package" => ("bot", "MCP"),
                        "skill" => ("box", "Skill"),
                        "cli" => ("terminal", "CLI"),
                        other => ("box", other),
                    };
                    let feed = s(record, "ecosystem");
                    let desc = if feed.is_empty() {
                        kind.to_string()
                    } else {
                        format!("{kind} · {feed} advisories")
                    };
                    scope_row(&host_href(t), ic, name.trim(), &desc, &item_side(t))
                })
                .collect();
            if !rows.is_empty() {
                body.push_str(&format!("<div class=\"entity\">{rows}</div>"));
            }
            body
        }
        _ if hosts.is_empty() => empty("No machines in this view", ""),
        _ => {
            let rows: String = hosts
                .iter()
                .map(|h| {
                    let host = s(h, "host");
                    let packages = items.iter().filter(|i| i["host"] == h["host"]).count();
                    let side = match s(h, "scan") {
                        "ok" => "Coverage complete".to_string(),
                        "never" => "Coverage unknown".to_string(),
                        "stale" => scan_problem(h, now),
                        _ => "Coverage partial".to_string(),
                    };
                    let mut desc = format!(
                        "System packages, browsers, tools · {} package{}",
                        grouped(packages),
                        if packages == 1 { "" } else { "s" }
                    );
                    let not_assessed = h["last"]["not_assessed"]
                        .as_str()
                        .and_then(|text| serde_json::from_str::<Value>(text).ok())
                        .map_or(0, |v| v.as_array().map_or(0, Vec::len));
                    if not_assessed > 0 {
                        desc.push_str(&format!(" · Not assessed ({not_assessed})"));
                    }
                    scope_row(
                        &format!("/findings?host={}", encoded(host)),
                        "inventory",
                        host,
                        &desc,
                        &side,
                    )
                })
                .collect();
            format!("<div class=\"entity list-heavy\">{rows}</div>")
        }
    };
    let label = TABS
        .iter()
        .find(|(key, _)| *key == tab)
        .map_or("", |(_, l)| l);
    let main = format!(
        "<section class=\"panel\"><div class=\"panel-header\"><h2>{label}</h2><a class=\"text-link\" href=\"/findings\">Inspect findings →</a></div>{body}</section>"
    );
    let export = format!(
        "<div><button class=\"btn\" type=\"button\" data-copy=\"vorda inventory --format cyclonedx\">{}<span>Copy inventory command</span></button></div>",
        icon("copy")
    );
    layout(tab, Some(counts), &main, &export)
}

fn host_href(item: &Value) -> String {
    format!("/findings?host={}", encoded(s(item, "host")))
}
