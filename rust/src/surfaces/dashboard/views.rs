use super::{
    english::*,
    inventory::{inventory_screen, is_agent_tool, lockfiles},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
const NAV: [(&str, &str, &str, &str); 6] = [
    ("overview", "/", "Overview", "overview"),
    ("findings", "/findings", "Findings", "findings"),
    ("inventory", "/inventory", "Inventory", "inventory"),
    ("inbox", "/inbox", "Inbox", "inbox"),
    ("repairs", "/repairs", "Repairs", "repairs"),
    ("policy", "/policy", "Policy", "policy"),
];
pub fn e(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
pub fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|first| first.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}
pub(super) fn icon(name: &str) -> String {
    static ICONS: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let icons = ICONS.get_or_init(|| serde_json::from_str(include_str!("icons.json")).unwrap());
    format!(
        "<svg class=\"i\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">{}</svg>",
        icons.get(name).and_then(Value::as_str).unwrap_or("")
    )
}
pub fn ago(ts: f64, now: f64) -> String {
    if ts == 0. {
        return "never".into();
    }
    let d = (now - ts).max(0.);
    if d < 90. {
        "just now".into()
    } else if d < 3600. {
        format!("{} min ago", (d / 60.) as u64)
    } else if d < 86400. {
        format!("{} h ago", (d / 3600.) as u64)
    } else {
        format!("{} d ago", (d / 86400.) as u64)
    }
}
pub fn page(active: &str, title: &str, body: &str, nonce: &str, foot: &str) -> String {
    let nav: String = NAV
        .iter()
        .map(|(key, href, label, ic)| {
            let current = if *key == active {
                " aria-current=\"page\""
            } else {
                ""
            };
            format!(
                "<a href=\"{href}\"{current}>{}<span>{label}</span></a>",
                icon(ic)
            )
        })
        .collect();
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><meta name=\"color-scheme\" content=\"light\"><meta name=\"referrer\" content=\"no-referrer\"><title>{} · vorda</title><link rel=\"icon\" href=\"{}\"><style nonce=\"{}\">{}</style><script nonce=\"{}\">{}</script></head><body><div class=\"shell\"><nav class=\"side\" aria-label=\"Main\"><div class=\"logo\">vorda<span>.</span></div><div class=\"nav\">{nav}</div>{foot}</nav><main><div class=\"in\">{body}</div></main></div><div id=\"tip\" role=\"tooltip\"></div></body></html>",e(title),include_str!("favicon.txt"),e(nonce),include_str!("style.css"),e(nonce),include_str!("script.js"))
}
pub fn copy_cmd(cmd: &str) -> String {
    format!("<code class=\"cmd\">{0}</code><button class=\"b copy\" type=\"button\" data-copy=\"{0}\">Copy</button>",e(cmd))
}
pub fn empty(line: &str, action: &str) -> String {
    format!("<div class=\"card empty\"><div class=\"title\">{}</div><div class=\"meta\">{action}</div></div>",e(line))
}
fn host(name: &str) -> String {
    format!("<span class=\"nw\">{}</span>", e(name))
}
fn type_icon(t: &str) -> &str {
    match t {
        "browser" => "globe",
        "os" => "server",
        "library" => "box",
        "mcp" | "skill" => "bot",
        "cli" => "terminal",
        "health" => "pulse",
        _ => "list",
    }
}
fn advice(i: &Value) -> String {
    if i["draft"].is_object() {
        return format!("Needs your OK: {}", s(&i["draft"], "title"));
    }
    let fix = s(i, "fix");
    if i["mode"] == "watch" || i["type"] == "health" || fix.is_empty() {
        return if i["type"] == "health" {
            fix.into()
        } else {
            "Alert only".into()
        };
    }
    let mut chars = fix.chars();
    let first = chars.next().unwrap_or_default();
    let rest = chars.as_str();
    format!(
        "Advice: {}",
        if let Some(command) = fix.strip_prefix("Run: ") {
            format!("run {command}")
        } else if rest.chars().next().is_some_and(char::is_lowercase) {
            first.to_lowercase().collect::<String>() + rest
        } else {
            fix.into()
        }
    )
}
fn versions(d: &Value) -> String {
    format!(
        "<span class=\"nw m\">{}</span> → <span class=\"nw m\">{}</span>",
        e(s(d, "old")),
        e(s(d, "new"))
    )
}
pub(super) fn scan_problem(h: &Value, now: f64) -> String {
    let problems = a(h, "problems");
    let count = (number(h, "problem_count") as usize).max(problems.len());
    if h["scan"] == "failed" && !problems.is_empty() {
        return format!(
            "{}{}",
            problems[0].as_str().unwrap_or("Scan failed"),
            if count > 1 {
                format!(" and {} more", count - 1)
            } else {
                String::new()
            }
        );
    }
    if h["missing"] == true {
        return "Folder missing: restore it, or run vorda check in its new location".into();
    }
    if h["nothing_checked"] == true {
        return "Nothing checked: no supported lockfile found; add one and run vorda check in that folder".into();
    }
    match s(h, "scan") {
        "unconfirmed" => "Some projects can't be confirmed: see the project list".into(),
        "failed" if h["inferred"].is_boolean() => {
            "Last scan could not confirm everything: run vorda check again".into()
        }
        "failed" => "Scan failed".into(),
        "never" => "Never scanned".into(),
        "stale" => format!("Last scan {}", ago(number(&h["last"], "finished"), now)),
        _ => String::new(),
    }
}
fn coverage(hosts: &[Value], now: f64) -> String {
    let mut groups: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for h in hosts {
        let why = scan_problem(h, now);
        if !why.is_empty() {
            groups.entry(why).or_default().push(s(h, "host"));
        }
    }
    groups
        .iter()
        .map(|(why, hosts)| format!("{why} on {}", hosts.join(", ")))
        .collect::<Vec<_>>()
        .join(" · ")
}
pub(super) fn encoded(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
fn open_count(issue: &Value) -> usize {
    if issue["type"] == "health" {
        0
    } else {
        number(issue, "count") as usize
    }
}
pub(super) fn no_scans_label(snapshot: &Value) -> &str {
    if snapshot["has_scans"] == true {
        "No scans in this view"
    } else {
        "No scans yet"
    }
}
pub(super) fn project_href(p: &Value) -> String {
    if p["inferred"] == true {
        format!("/findings?scope={}", encoded(s(p, "scope")))
    } else if p["imported"] == true {
        // The card's own rule picks the findings, inside its scope's view.
        let scope = encoded(s(p, "scope"));
        format!(
            "/findings?scope={scope}&host={}&project={scope}",
            encoded(s(p, "host"))
        )
    } else {
        format!(
            "/findings?host={}&project={}",
            encoded(s(p, "host")),
            encoded(s(p, "root"))
        )
    }
}
pub fn head(title: &str, sub: &str, right: &str) -> String {
    format!(
        "<div class=\"header-row\"><div class=\"hgroup\"><h1>{}</h1><p>{}</p></div>{right}</div>",
        e(title),
        e(sub)
    )
}
pub fn panel(title: &str, link: Option<(&str, &str)>, body: &str) -> String {
    let link = link
        .map(|(href, label)| format!("<a class=\"text-link\" href=\"{href}\">{label} →</a>"))
        .unwrap_or_default();
    format!(
        "<section class=\"panel\"><div class=\"panel-header\"><h2>{}</h2>{link}</div>{body}</section>",
        e(title)
    )
}
pub fn state(ic: &str, title: &str, line: &str, extra: &str, class: &str) -> String {
    let line = if line.is_empty() {
        String::new()
    } else {
        format!("<p>{}</p>", e(line))
    };
    format!(
        "<div class=\"state {class}\"><div class=\"badge\">{}</div><h3>{}</h3>{line}{extra}</div>",
        icon(ic),
        e(title)
    )
}
pub fn cmdline(cmd: &str) -> String {
    format!(
        "<div class=\"cmdline\"><code>{0}</code><button class=\"btn\" type=\"button\" data-copy=\"{0}\"><span>Copy</span></button></div>",
        e(cmd)
    )
}
fn copy_scan() -> String {
    format!(
        "<div><button class=\"btn primary\" type=\"button\" data-copy=\"vorda scan\">{}<span>Copy scan command</span></button></div>",
        icon("copy")
    )
}
pub fn error_page(title: &str, path: &str) -> String {
    head(title, "This page needs Vorda's saved results.", &copy_scan())
        + &format!(
            "<div class=\"grid\"><section class=\"panel wide\">{}</section></div>",
            state(
                "warn",
                "Cannot read saved results",
                "Could not open the mailbox file. Check that this path exists and is readable, then reload.",
                &format!("<div class=\"errbox\">{}</div>", e(path)),
                "err"
            )
        )
}
pub fn last_scan(snapshot: &Value) -> String {
    let last = a(snapshot, "hosts")
        .iter()
        .max_by(|x, y| number(&x["last"], "finished").total_cmp(&number(&y["last"], "finished")));
    let when = last.map_or(0., |h| number(&h["last"], "finished"));
    let mut text = e(&ago(when, number(snapshot, "now")));
    if let Some(h) = last.filter(|_| when > 0.) {
        text.push_str(&format!(" · {}", e(s(h, "host"))));
    }
    format!("<div class=\"nav-end\"><b>Last scan</b>{text}</div>")
}
pub(super) fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
fn action_row(href: &str, signal: &str, title: &str, sub: &str, foot: &str) -> String {
    format!(
        "<a class=\"action-row\" href=\"{href}\"><span class=\"signal {signal}\"></span><div class=\"row-text\"><div class=\"row-title\">{}</div><div class=\"row-sub\">{}</div><div class=\"row-foot\">{}</div></div>{}</a>",
        e(title),
        e(sub),
        e(foot),
        icon("chev")
    )
}
pub(super) fn scope_row(href: &str, ic: &str, name: &str, desc: &str, side: &str) -> String {
    format!(
        "<a class=\"listrow\" href=\"{href}\"><div class=\"badge\">{}</div><div class=\"row-text\"><div class=\"name\">{}</div><div class=\"desc\">{}</div></div><div class=\"side\">{}</div>{}</a>",
        icon(ic),
        e(name),
        e(desc),
        e(side),
        icon("chev")
    )
}
fn entry(title: &str, line: &str) -> String {
    format!(
        "<div class=\"entry\"><div class=\"row-title\">{}</div><div class=\"row-sub\">{}</div></div>",
        e(title),
        e(line)
    )
}
const COVERAGE: [&str; 4] = [
    "System packages",
    "Project lockfiles",
    "Browsers",
    "Agent tools",
];
/// The right-side label of a machine or project row: how many open findings need attention.
pub(super) fn attention(open: usize, scan: &Value) -> String {
    match open {
        0 if !scan.is_null() && scan != "ok" => "Partial coverage".to_string(),
        0 => String::new(),
        1 => "1 needs attention".to_string(),
        n => format!("{n} need attention"),
    }
}
pub fn overview_screen(snapshot: &Value) -> String {
    let (hosts, issues, projects) = (
        a(snapshot, "hosts"),
        a(snapshot, "issues"),
        a(snapshot, "projects"),
    );
    let copy = copy_scan();
    if hosts.is_empty() && issues.is_empty() {
        let title = if snapshot["has_scans"] == true {
            no_scans_label(snapshot)
        } else {
            "Welcome to Vorda"
        };
        let ghost: String = COVERAGE
            .iter()
            .map(|name| {
                format!("<div class=\"cov-row\"><span>{name}</span><span>Not scanned</span></div>")
            })
            .collect();
        return head(
            title,
            "Run a scan to see what needs attention on this machine.",
            &copy,
        ) + &format!(
            "<div class=\"grid\">{}{}</div><div class=\"grid\">{}{}</div>",
            panel(
                "Next actions",
                None,
                &state(
                    "findings",
                    no_scans_label(snapshot),
                    "Vorda shows findings, coverage and inventory after the first scan.",
                    &cmdline("vorda scan"),
                    ""
                )
            ),
            panel(
                "Scan coverage",
                None,
                &format!("<div class=\"coverage ghost\">{ghost}</div>")
            ),
            panel(
                "In scope",
                None,
                &state("inventory", "No inventory yet", "", "", "small")
            ),
            panel(
                "Inbox",
                None,
                &format!(
                    "<div class=\"mini\">{}</div>",
                    entry(
                        "No messages yet",
                        "Each scan adds new findings and changes here for every reader."
                    )
                )
            ),
        );
    }
    let now = number(snapshot, "now");
    let found: Vec<_> = issues.iter().filter(|i| i["type"] != "health").collect();
    let open: usize = found.iter().map(|i| open_count(i)).sum();
    let unsure_hosts: Vec<_> = hosts.iter().filter(|h| h["scan"] != "ok").collect();
    let unsure_projects: Vec<_> = projects.iter().filter(|p| p["scan"] != "ok").collect();
    let unsure = !unsure_hosts.is_empty() || !unsure_projects.is_empty();
    let title = match open {
        0 if unsure => "Scan coverage is incomplete".to_string(),
        0 => "Nothing needs attention".to_string(),
        1 => "1 item needs attention".to_string(),
        n => format!("{n} items need attention"),
    };
    let dev: usize = found
        .iter()
        .filter(|i| i["dev_only"] == true)
        .map(|i| open_count(i))
        .sum();
    let sub = match dev {
        0 => "Start with what matters. Everything else is available when you need it.".to_string(),
        1 => {
            "1 is likely dev only, based on lockfile flags or test and fixture folders.".to_string()
        }
        n => {
            format!("{n} are likely dev only, based on lockfile flags or test and fixture folders.")
        }
    };
    let mut actions: String = found
        .iter()
        .take(4)
        .map(|i| {
            let path = s(i, "path");
            let place = if path.is_empty() {
                s(i, "eyebrow").to_string()
            } else {
                basename(path)
            };
            let advice = advice(i);
            action_row(
                &format!("/finding/{}", s(i, "id")),
                if i["kev"] == true { "red" } else { "" },
                s(i, "title"),
                &format!("{} · {place}", s(i, "host")),
                &capitalize(advice.strip_prefix("Advice: ").unwrap_or(&advice)),
            )
        })
        .collect();
    for h in &unsure_hosts {
        let problems = a(h, "problems");
        if problems.is_empty() {
            actions.push_str(&action_row(
                &format!("/findings?host={}", encoded(s(h, "host"))),
                "amber",
                &scan_problem(h, now),
                s(h, "host"),
                "",
            ));
            continue;
        }
        let count = (number(h, "problem_count") as usize).max(problems.len());
        actions.push_str(&action_row(
            "/findings?f=coverage",
            "amber",
            &format!("Coverage is partial on {}", s(h, "host")),
            &format!(
                "{} · {}",
                s(h, "host"),
                problems
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            &format!(
                "{} · Check coverage",
                if count == 1 {
                    "1 source could not be checked".to_string()
                } else {
                    format!("{count} sources could not be checked")
                }
            ),
        ));
    }
    for p in &unsure_projects {
        actions.push_str(&action_row(
            &project_href(p),
            "amber",
            &scan_problem(p, now),
            s(p, "name"),
            "",
        ));
    }
    let actions = if actions.is_empty() {
        state("findings", &title, "", "", "small")
    } else {
        format!("<div class=\"list\">{actions}</div>")
    };
    let items = a(&snapshot["assets"], "items");
    let kind = |t: &str| items.iter().filter(|i| i["subtype"] == t).count();
    let agent_tools = items.iter().filter(|i| is_agent_tool(i)).count();
    let coverage: String = COVERAGE
        .iter()
        .zip([
            kind("os-package"),
            lockfiles(items).len(),
            kind("browser"),
            agent_tools,
        ])
        .map(|(name, n)| {
            let value = if n == 0 {
                "None found".to_string()
            } else {
                format!("{} found", grouped(n))
            };
            format!("<div class=\"cov-row\"><span>{name}</span><span>{value}</span></div>")
        })
        .collect();
    let note = if unsure {
        "<div class=\"panel-note\">A clean result cannot be confirmed where discovery is incomplete.</div>"
    } else {
        ""
    };
    let mut scope: String = hosts
        .iter()
        .map(|h| {
            scope_row(
                &format!("/findings?host={}", encoded(s(h, "host"))),
                "inventory",
                s(h, "host"),
                "System packages, browsers, tools",
                &attention(
                    found
                        .iter()
                        .filter(|i| i["host"] == h["host"])
                        .map(|i| open_count(i))
                        .sum(),
                    &h["scan"],
                ),
            )
        })
        .collect();
    for p in projects {
        let place = if p["imported"] == true {
            s(p, "source")
        } else if s(p, "root").is_empty() {
            "Location not recorded"
        } else {
            s(p, "root")
        };
        let mut desc = format!(
            "{place} · scanned {} · {} urgent, {} open",
            ago(number(&p["last"], "finished"), now),
            number(p, "urgent"),
            number(p, "open")
        );
        if p["missing"] == true || p["nothing_checked"] == true || !a(p, "problems").is_empty() {
            desc.push_str(&format!(" · {}", scan_problem(p, now)));
        }
        if p["inferred"] == true {
            desc.push_str(" · Saved historical scope · Original scan root not recorded");
        }
        let side = if p["scan"] != "ok" {
            "Can't confirm".to_string()
        } else {
            attention(number(p, "open") as usize, &p["scan"])
        };
        scope.push_str(&scope_row(
            &project_href(p),
            "pkg",
            s(p, "name"),
            &desc,
            &side,
        ));
    }
    let readers = a(snapshot, "readers");
    let mut inbox: String = readers
        .iter()
        .map(|r| {
            entry(
                &format!("Unread for {}", s(r, "name")),
                &format!(
                    "{} messages not yet acknowledged by this reader.",
                    number(r, "unread")
                ),
            )
        })
        .collect();
    if readers.is_empty() {
        inbox = entry(
            "No messages yet",
            "Each scan adds new findings and changes here for every reader.",
        );
    }
    let waiting = a(snapshot, "drafts")
        .iter()
        .filter(|d| d["state"] == "waiting")
        .count();
    inbox.push_str(&match waiting {
        0 if snapshot["repairs_on"] == true => {
            entry("No repair drafts", "No drafts are waiting for approval.")
        }
        0 => entry(
            "No repair drafts",
            "Vorda drafts repairs only when started with --fix-config.",
        ),
        1 => entry(
            "1 repair draft waiting",
            "Each draft needs review and approval before Vorda applies it.",
        ),
        n => entry(
            &format!("{n} repair drafts waiting"),
            "Each draft needs review and approval before Vorda applies it.",
        ),
    });
    let mut inbox = format!("<div class=\"mini\">{inbox}</div>");
    if let Some(fleet) = a(snapshot, "modes").first() {
        let mode = s(fleet, "mode");
        let line = match mode {
            "watch" => "Report findings without proposing changes.",
            "fix" => "Permit explicitly allowed, approved remediation.",
            _ => "Vorda prepares changes; approval is required.",
        };
        inbox.push_str(&format!(
            "<div class=\"policy-inline\"><div><div class=\"t\">Policy: {}</div><div class=\"s\">{line}</div></div><a class=\"text-link\" href=\"/policy\">Manage →</a></div>",
            e(&capitalize(mode))
        ));
    }
    head(&title, &sub, &copy)
        + &format!(
            "<div class=\"grid\">{}{}</div><div class=\"grid\">{}{}</div>",
            panel(
                "Next actions",
                Some(("/findings", "All findings")),
                &actions
            ),
            panel(
                "Scan coverage",
                Some(("/inventory", "Explore inventory")),
                &format!("<div class=\"coverage\">{coverage}</div>{note}")
            ),
            panel(
                "In scope",
                Some(("/inventory", "All assets")),
                &format!("<div class=\"entity\">{scope}</div>")
            ),
            panel("Inbox", Some(("/inbox", "Open inbox")), &inbox),
        )
}
const TABS: [(&str, &str); 4] = [
    ("all", "All findings"),
    ("kev", "Known exploited"),
    ("review", "Needs review"),
    ("coverage", "Uncertain coverage"),
];
fn fact(title: &str, body: &str) -> String {
    format!("<div class=\"fact\"><b>{}</b>{body}</div>", e(title))
}
fn para(text: &str) -> String {
    format!("<p>{}</p>", e(text))
}
// A path a shell reads as one word, so the copied scan command runs as shown.
fn shell_word(path: &str) -> String {
    if path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+~".contains(c))
    {
        path.into()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
    }
}
fn finding_detail(i: &Value) -> String {
    let fix = s(i, "fix");
    let mut kv = String::new();
    let mut item = |label: &str, value: String| {
        kv.push_str(&format!("<dt>{}</dt><dd>{value}</dd>", e(label)));
    };
    let advisories = a(i, "advisories");
    if !advisories.is_empty() {
        let mut lines: Vec<String> = advisories
            .iter()
            .take(8)
            .map(|adv| {
                let basis = s(adv, "basis");
                let confidence = s(adv, "confidence");
                format!(
                    "<span class=\"m\">{}</span> · {}{}{}",
                    e(s(adv, "id")),
                    capitalize(s(adv, "severity")),
                    if basis.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", e(basis))
                    },
                    if confidence.is_empty() {
                        String::new()
                    } else {
                        format!(" · Match: {}", e(confidence))
                    }
                )
            })
            .collect();
        if advisories.len() > 8 {
            lines.push(format!("and {} more", advisories.len() - 8));
        }
        item("Advisory", lines.join("<br>"));
        let mut aliases: BTreeSet<&str> = advisories
            .iter()
            .flat_map(|adv| a(adv, "aliases").iter().filter_map(Value::as_str))
            .collect();
        for adv in advisories {
            aliases.remove(s(adv, "id"));
        }
        if !aliases.is_empty() {
            item(
                "Also known as",
                e(&aliases.into_iter().take(30).collect::<Vec<_>>().join(", ")),
            );
        }
    }
    let (installed, target, path) = (s(i, "installed"), s(i, "target"), s(i, "path"));
    if !installed.is_empty() || !path.is_empty() {
        let mut value = e(installed);
        if !target.is_empty() {
            value.push_str(&format!(" → {}", e(target)));
        }
        if !path.is_empty() {
            value.push_str(&format!(
                "{}<span class=\"m\">{}</span>",
                if installed.is_empty() { "" } else { " in " },
                e(path)
            ));
        }
        item("Installed", value);
    }
    if i["dev_only"] == true {
        item(
            "Scope",
            e("Likely dev only (lockfile flags or test and fixture folders)"),
        );
    }
    item(
        "Exploit signal",
        e(if i["kev"] == true {
            "On the CISA known exploited list"
        } else {
            "Not on the CISA known exploited list"
        }),
    );
    let epss = number(i, "epss");
    if epss > 0. {
        item("EPSS", format!("{:.1}%", epss * 100.));
    }
    let sources: BTreeSet<&str> = advisories
        .iter()
        .flat_map(|adv| a(adv, "sources").iter().filter_map(Value::as_str))
        .collect();
    if !sources.is_empty() {
        item(
            "Source",
            sources
                .iter()
                .take(2)
                .map(|url| {
                    format!(
                        "<a class=\"text-link\" href=\"{0}\" rel=\"noreferrer noopener\" target=\"_blank\">{0}</a>",
                        e(url)
                    )
                })
                .collect::<Vec<_>>()
                .join("<br>"),
        );
    }
    let draft = &i["draft"];
    let action = if draft.is_object() {
        format!(
            "<p><a class=\"text-link\" href=\"/review/{}\">Needs your OK: {} →</a></p>",
            e(s(draft, "id")),
            e(s(draft, "title"))
        )
    } else if i["mode"] == "watch" {
        para("Alert only on this machine")
    } else if let Some(cmd) = fix.strip_prefix("Run: ") {
        cmdline(cmd)
    } else if fix.is_empty() {
        String::new()
    } else {
        para(fix)
    };
    let library = i["type"] == "library" && !path.is_empty();
    let scan = if library {
        let dir = std::path::Path::new(path)
            .parent()
            .map_or(String::new(), |d| d.to_string_lossy().into_owned());
        if dir.is_empty() {
            "vorda scan".to_string()
        } else {
            format!("vorda scan {}", shell_word(&dir))
        }
    } else {
        "vorda scan".to_string()
    };
    format!(
        "<section class=\"panel sidecard\"><h2>{}</h2>{}{}{}{}<button class=\"btn primary\" type=\"button\" data-copy=\"{}\">{}<span>Copy scan command</span></button></section>",
        e(s(i, "title")),
        fact(
            "Why it matters",
            &para(if s(i, "why").is_empty() { fix } else { s(i, "why") })
        ),
        fact("Evidence", &format!("<dl class=\"kv\">{kv}</dl>")),
        if action.is_empty() {
            String::new()
        } else {
            fact("Recommended action", &action)
        },
        fact(
            "After a change",
            &para(if library {
                "Rescan the project to confirm the finding is resolved."
            } else {
                "Rescan the machine to confirm the finding is resolved."
            })
        ),
        e(&scan),
        icon("copy")
    )
}
fn finding_row(href: &str, i: &Value, selected: bool) -> String {
    let ids: Vec<&str> = a(i, "advisories").iter().map(|adv| s(adv, "id")).collect();
    let mut desc = format!("{} · {}", s(i, "host"), s(i, "eyebrow"));
    if !ids.is_empty() {
        desc.push_str(&format!(" · {}", ids[..ids.len().min(3)].join(", ")));
        if ids.len() > 3 {
            desc.push_str(&format!(" and {} more", ids.len() - 3));
        }
    }
    let side = if i["kev"] == true {
        "<span class=\"crit\">On the CISA known exploited list</span>".to_string()
    } else {
        e(&capitalize(s(i, "severity")))
    };
    format!(
        "<a class=\"listrow{}\" href=\"{href}\"><div class=\"badge\">{}</div><div class=\"row-text\"><div class=\"name\">{}</div><div class=\"desc\">{}</div></div><div class=\"side\">{side}</div>{}</a>",
        if selected { " sel" } else { "" },
        icon(type_icon(s(i, "type"))),
        e(s(i, "title")),
        e(&desc),
        icon("chev")
    )
}
fn coverage_row(name: &str, desc: &str, side: &str) -> String {
    format!(
        "<div class=\"listrow\"><div class=\"badge\">{}</div><div class=\"row-text\"><div class=\"name\">{}</div><div class=\"desc\">{}</div></div><div class=\"side\">{}</div></div>",
        icon("warn"),
        e(name),
        e(desc),
        e(side)
    )
}
pub(super) fn findings_screen(
    snapshot: &Value,
    filter: &str,
    host: &str,
    project: &str,
    id: &str,
) -> String {
    let projects: Vec<_> = a(snapshot, "projects")
        .iter()
        .filter(|p| {
            (project.is_empty()
                || p["root"] == project
                || p["imported"] == true && p["scope"] == project)
                && (host.is_empty() || p["host"] == host)
        })
        .cloned()
        .collect();
    let issues: Vec<_> = a(snapshot, "issues")
        .iter()
        .filter(|i| host.is_empty() || i["host"] == host)
        .filter(|i| {
            project.is_empty()
                || projects
                    .iter()
                    .any(|p| super::data::belongs_to_project(i, p))
        })
        .collect();
    // A scan of several folders saves one scan-health finding for all of them; on a folder's
    // page that row gives the folder's own reason, never another folder's.
    let folder = projects
        .iter()
        .find(|p| !project.is_empty() && p["imported"] != true && !s(p, "root").is_empty());
    let own: Vec<Value> = issues
        .iter()
        .map(|i| {
            let mut i = (*i).clone();
            let inventory = a(&i, "keys")
                .iter()
                .any(|k| k.as_str().is_some_and(|k| k.ends_with(":inventory")));
            if let Some(p) = folder.filter(|_| i["type"] == "health" && inventory) {
                i["fix"] = Value::from(a(p, "problems").first().and_then(Value::as_str).unwrap_or(
                    "Another part of this scan could not be read; run vorda check --json for the reason",
                ));
            }
            i
        })
        .collect();
    let found: Vec<&Value> = own.iter().filter(|i| i["type"] != "health").collect();
    let title = if host.is_empty() {
        "Findings".to_string()
    } else {
        format!("Findings on {host}")
    };
    let sub = if project.is_empty() {
        "Understand the risk, the affected asset, and the available remedy before taking action."
            .to_string()
    } else {
        let label = projects
            .iter()
            .find(|p| p["imported"] == true)
            .map_or(project, |p| s(p, "name"));
        format!("Project: {label}")
    };
    let head = head(
        &title,
        &sub,
        "<a class=\"btn\" href=\"/repairs\">Review repairs →</a>",
    );
    let query = format!(
        "{}{}",
        if host.is_empty() {
            String::new()
        } else {
            format!("&amp;host={}", encoded(host))
        },
        if project.is_empty() {
            String::new()
        } else {
            format!("&amp;project={}", encoded(project))
        }
    );
    let tabs = |counts: [Option<usize>; 4]| {
        let links: String = TABS
            .iter()
            .zip(counts)
            .map(|((key, label), n)| {
                format!(
                    "<a href=\"/findings?f={key}{query}\"{}>{label}{}</a>",
                    if *key == filter {
                        " class=\"on\" aria-current=\"page\""
                    } else {
                        ""
                    },
                    n.map_or(String::new(), |n| format!("<span class=\"n\">{n}</span>"))
                )
            })
            .collect();
        format!("<nav class=\"subnav\">{links}</nav>")
    };
    let whole = |body: String| {
        format!("<div class=\"grid\"><section class=\"panel wide\">{body}</section></div>")
    };
    if a(snapshot, "hosts").is_empty() {
        let title = if snapshot["has_scans"] == true {
            no_scans_label(snapshot)
        } else {
            "No findings yet"
        };
        return head
            + &tabs([None; 4])
            + &whole(state(
                "findings",
                title,
                "Vorda shows findings, coverage and inventory after the first scan.",
                &cmdline("vorda scan"),
                "",
            ));
    }
    let now = number(snapshot, "now");
    let hosts: Vec<_> = a(snapshot, "hosts")
        .iter()
        .filter(|h| host.is_empty() || h["host"] == host)
        .cloned()
        .collect();
    let mut uncertain: Vec<String> = own
        .iter()
        .filter(|i| i["type"] == "health")
        .map(|i| {
            let n = number(i, "count") as usize;
            coverage_row(
                s(i, "title"),
                s(i, "fix"),
                &if n > 1 {
                    format!("{n} scan entries")
                } else {
                    String::new()
                },
            )
        })
        .collect();
    if project.is_empty() {
        for h in hosts.iter().filter(|h| a(h, "problems").is_empty()) {
            let why = scan_problem(h, now);
            if !why.is_empty() {
                uncertain.push(coverage_row(&why, s(h, "host"), ""));
            }
        }
    }
    for p in projects.iter().filter(|p| a(p, "problems").is_empty()) {
        let why = scan_problem(p, now);
        if p["scan"] != "ok" && !why.is_empty() {
            uncertain.push(coverage_row(&why, s(p, "name"), ""));
        }
    }
    let sum = |list: &[&Value]| list.iter().map(|i| open_count(i)).sum::<usize>();
    let kev: Vec<&Value> = found.iter().copied().filter(|i| i["kev"] == true).collect();
    let review: Vec<&Value> = found
        .iter()
        .copied()
        .filter(|i| i["needs"] == true)
        .collect();
    let head = head
        + &tabs([
            Some(sum(&found)),
            Some(sum(&kev)),
            Some(sum(&review)),
            Some(uncertain.len()),
        ]);
    let coverage_view = if uncertain.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"grid page-grid\">{}<section class=\"panel sidecard\"><h2>Coverage is part of the result</h2><p class=\"lead\">Sources Vorda could not check in the last scan. These are not vulnerabilities.</p>{}<div class=\"panel-note\">A clean result cannot be confirmed where discovery is incomplete.</div></section></div>",
            panel(
                "Uncertain coverage",
                None,
                &format!("<div class=\"entity list-heavy\">{}</div>", uncertain.concat())
            ),
            fact("Partial", &para("Show paths or advisory sources that could not be checked."))
        )
    };
    if filter == "coverage" {
        return head
            + &if uncertain.is_empty() {
                whole(state("check", "Coverage is complete", "", "", ""))
            } else {
                coverage_view
            };
    }
    let list = match filter {
        "kev" => kev,
        "review" => review,
        _ => found,
    };
    if list.is_empty() {
        let why = coverage(
            if project.is_empty() {
                &hosts
            } else {
                &projects
            },
            now,
        );
        return head
            + &whole(match filter {
                "kev" => state(
                    "findings",
                    "No known-exploited findings",
                    "No open findings are on the CISA known exploited list.",
                    "",
                    "",
                ),
                "review" => state("findings", "Nothing needs review", "", "", ""),
                _ if why.is_empty() && uncertain.is_empty() => {
                    state("findings", "Nothing found", "", "", "")
                }
                _ => state(
                    "findings",
                    "Can't confirm",
                    &why,
                    &cmdline("vorda scan"),
                    "",
                ),
            })
            + if filter == "all" {
                coverage_view.as_str()
            } else {
                ""
            };
    }
    let selected = list
        .iter()
        .copied()
        .find(|i| i["id"] == id)
        .unwrap_or(list[0]);
    let rows: String = list
        .iter()
        .map(|i| {
            finding_row(
                &format!("/findings?f={filter}&amp;id={}{query}", encoded(s(i, "id"))),
                i,
                std::ptr::eq(*i, selected),
            )
        })
        .collect();
    head + &format!(
        "<div class=\"grid page-grid\">{}{}</div>",
        panel(
            "Prioritized findings",
            None,
            &format!("<div class=\"entity list-heavy\">{rows}</div>")
        ),
        finding_detail(selected)
    )
}
fn back(href: &str, label: &str) -> String {
    format!(
        "<a class=\"back\" href=\"{href}\">{}{label}</a>",
        icon("chev")
    )
}
pub fn missing(screen: &str) -> String {
    if screen == "finding" {
        back("/findings", "Findings")
            + "<h1>Not found</h1>"
            + &empty(
                "This issue is closed or gone",
                "<a href=\"/repairs\">See repairs</a>",
            )
    } else {
        back("/repairs", "Repairs")
            + "<h1>Not found</h1>"
            + &empty(
                "This draft was applied, dismissed or replaced",
                "<a href=\"/repairs\">See repairs</a>",
            )
    }
}
fn draft_state(d: &Value) -> &str {
    match s(d, "state") {
        "waiting" => "Needs your OK",
        "approved" => "Approved",
        "applying" => "Applying",
        "fixed" => "Fixed",
        "denied" => "Denied",
        "failed" => "Failed",
        "rolled-back" => "Failed, rolled back",
        "rollback-failed" => "Failed, rollback failed",
        "published" => "PR opened",
        "pr-pushed" => "Branch pushed; PR needs recovery",
        _ => "Changed since drafted",
    }
}
fn draft_meta(d: &Value) -> String {
    let who = if s(d, "agent").is_empty() {
        "Drafted".into()
    } else {
        format!("Drafted by {}", s(d, "agent"))
    };
    let state = match s(d, "state") {
        "waiting" => format!(
            "draft {}{}",
            s(d, "digest").chars().take(12).collect::<String>(),
            if number(d, "needed") > 1. {
                format!(
                    " · {} of {} approvals",
                    number(d, "votes"),
                    number(d, "needed")
                )
            } else {
                String::new()
            }
        ),
        "approved" => format!(
            "{} applies it next",
            if s(d, "agent").is_empty() {
                "the agent"
            } else {
                s(d, "agent")
            }
        ),
        "fixed" => "applied and re-scanned".into(),
        "rollback-failed" => "check the machine".into(),
        "stale" => "not shown; re-draft it".into(),
        _ => String::new(),
    };
    if state.is_empty() {
        who
    } else {
        format!("{who} · {state}")
    }
}
fn hidden(csrf: &str, fields: &[(&str, &str)]) -> String {
    let mut result = format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        e(csrf)
    );
    for (k, v) in fields {
        result.push_str(&format!(
            "<input type=\"hidden\" name=\"{k}\" value=\"{}\">",
            e(v)
        ));
    }
    result
}
fn review_screen(snapshot: &Value, id: &str, csrf: &str) -> Option<String> {
    let d = a(snapshot, "drafts").iter().find(|d| d["id"] == id)?;
    let change = if d["state"] == "stale" {
        format!("<div class=\"quiet\">The plan changed after this draft. Ask {} to draft it again.</div>",e(s(d,"agent")))
    } else if !s(d, "commands").is_empty() {
        copy_cmd(s(d, "commands"))
    } else {
        format!("<div class=\"quiet\">Branch {} · commit {}</div><pre class=\"diff\"><code>{}</code></pre>",e(s(d,"branch")),e(&s(d,"commit").chars().take(12).collect::<String>()),e(s(d,"diff")))
    };
    let f = hidden(csrf, &[("item", s(d, "item")), ("digest", s(d, "digest"))]);
    let acts = if d["state"] == "waiting" && snapshot["can_decide"] == true {
        format!("<form class=\"acts\" method=\"post\" action=\"/review\">{f}<button class=\"b go\" name=\"decision\" value=\"approve\">Approve</button></form><form class=\"acts\" method=\"post\" action=\"/review\">{f}<input class=\"reason\" name=\"reason\" maxlength=\"200\" placeholder=\"Why dismiss (optional)\" aria-label=\"Why dismiss\"><button class=\"b no\" name=\"decision\" value=\"dismiss\">Dismiss</button></form>")
    } else if d["state"] == "waiting" {
        format!(
            "<details class=\"toggle\"><summary>{}Approve from a shell</summary>{}</details>",
            icon("chev"),
            copy_cmd(&format!(
                "{} approve --item {} --digest {}",
                s(snapshot, "fix_cli"),
                crate::surfaces::advice::quote(s(d, "item")),
                crate::surfaces::advice::quote(s(d, "digest"))
            ))
        )
    } else if d["state"] == "approved" {
        let reason = s(d, "action_reason");
        let mut acts = if reason.is_empty() {
            format!("<form class=\"acts\" method=\"post\" action=\"/repair\">{f}<button class=\"b go\" name=\"decision\" value=\"apply\">Apply</button></form>")
        } else {
            format!("<div class=\"quiet\">{}</div>", e(reason))
        };
        let reason = s(d, "publish_reason");
        if reason.is_empty() {
            acts.push_str(&format!("<form class=\"acts\" method=\"post\" action=\"/repair\">{f}<label>GitHub repository <input name=\"repository\" required placeholder=\"owner/repository\"></label><label>Base branch <input name=\"base\" required placeholder=\"main\"></label><label>New branch <input name=\"branch\" required placeholder=\"vorda/fix\"></label><button class=\"b\" name=\"decision\" value=\"publish\">Open PR</button></form>"));
        } else {
            acts.push_str(&format!("<div class=\"quiet\">{}</div>", e(reason)));
        }
        acts
    } else {
        format!("<div class=\"quiet\">{}</div>", e(&draft_meta(d)))
    };
    let mut receipt=format!("<dt>Changes</dt><dd><span class=\"m\">{}</span> {}</dd><dt>Where</dt><dd>{}</dd><dt>Why</dt><dd>{}{}</dd><dt>Risk</dt><dd>{}</dd>",e(s(d,"package")),versions(d),if !s(d,"where").is_empty(){format!("<span class=\"m\">{}</span>{}",e(s(d,"where")),if s(d,"host").is_empty(){String::new()}else{format!(" on {}",host(s(d,"host")))})}else if s(d,"host").is_empty(){"-".into()}else{host(s(d,"host"))},e(s(d,"why")),if s(d,"finding").is_empty(){String::new()}else{format!(" <a class=\"lnk\" href=\"/finding/{}\">See the finding</a>",e(s(d,"finding")))},e(if s(d,"risk").is_empty(){"not stated"}else{s(d,"risk")}));
    if d["state"] != "stale" {
        receipt.push_str(&format!(
            "<dt>Undo</dt><dd>{}</dd>",
            if s(d, "undo").is_empty() {
                "No undo recorded".into()
            } else {
                copy_cmd(s(d, "undo"))
            }
        ));
    }
    if d["publication"].as_object().is_some_and(|o| !o.is_empty()) {
        receipt.push_str(&format!(
            "<dt>Pull request</dt><dd>{}</dd>",
            e(s(&d["publication"], "url"))
        ));
    }
    let test = if s(d, "test").is_empty() || d["state"] == "stale" {
        String::new()
    } else {
        format!("<details class=\"toggle\"><summary>{}Test result</summary><pre class=\"diff wrap\"><code>{}</code></pre></details>",icon("chev"),e(s(d,"test")))
    };
    let sha = format!(
        "<details class=\"toggle\"><summary>{}Draft sha256</summary><code>{}</code></details>",
        icon("chev"),
        e(s(d, "digest"))
    );
    Some(format!("{}<h1>{}</h1><div class=\"sub\">{} · drafted by {}</div><div class=\"card receipt-card\"><dl class=\"receipt\">{receipt}</dl><div class=\"summary\"><div class=\"label\">Exact change</div>{change}{test}</div><div class=\"foot\">{acts}{sha}</div></div>",back("/repairs","Repairs"),e(s(d,"title")),draft_state(d),e(s(d,"agent"))))
}
fn segmented(m: &Value, csrf: &str, writable: bool) -> String {
    let label = format!(
        "Mode for {}",
        if s(m, "name").is_empty() {
            "the fleet"
        } else {
            s(m, "name")
        }
    );
    let mut buttons = String::new();
    for mode in crate::policy::MODES {
        if writable {
            buttons.push_str(&format!(
                "<button name=\"mode\" value=\"{mode}\" aria-pressed=\"{}\">{}</button>",
                m["mode"] == mode,
                capitalize(mode)
            ));
        } else {
            buttons.push_str(&format!(
                "<span{}>{}</span>",
                if m["mode"] == mode {
                    " aria-current=\"true\""
                } else {
                    ""
                },
                capitalize(mode)
            ));
        }
    }
    if writable {
        format!("<form class=\"segc\" method=\"post\" action=\"/mode\" role=\"group\" aria-label=\"{}\">{}{buttons}</form>",e(&label),hidden(csrf,&[("scope",s(m,"scope")),("name",s(m,"name"))]))
    } else {
        format!(
            "<div class=\"segc\" role=\"group\" aria-label=\"{}\">{buttons}</div>",
            e(&label)
        )
    }
}
fn sidecard(title: &str, body: &str) -> String {
    format!(
        "<section class=\"panel sidecard\"><h2>{}</h2>{body}</section>",
        e(title)
    )
}
fn page_grid(main: &str, side: &str) -> String {
    format!("<div class=\"grid page-grid\">{main}{side}</div>")
}
fn inbox_screen(snapshot: &Value) -> String {
    let h = head(
        "Inbox",
        "One private record of findings, with independent read and acknowledgement state for each reader.",
        "",
    );
    let readers = a(snapshot, "readers");
    let side = if readers.is_empty() {
        sidecard(
            "Readers",
            &(fact(
                "No readers yet",
                &para("A reader appears the first time an agent or person reads the mailbox, and the command below sets up the MCP tools for an agent."),
            ) + &cmdline("vorda snippet mcp")),
        )
    } else {
        let facts: String = readers
            .iter()
            .map(|r| {
                fact(
                    s(r, "name"),
                    &para(&format!(
                        "{} unread · {} acknowledged",
                        number(r, "unread"),
                        number(r, "acked")
                    )),
                )
            })
            .collect();
        sidecard(
            "Readers",
            &format!("{facts}<div class=\"note\">A finding can remain open while individual readers acknowledge the message.</div>"),
        )
    };
    let inbox = &snapshot["inbox"];
    let messages = a(inbox, "messages");
    let main = if snapshot["has_scans"] != true && messages.is_empty() {
        format!(
            "<section class=\"panel\">{}</section>",
            state(
                "inbox",
                "No messages yet",
                "Each scan adds new findings and changes here for every reader.",
                &cmdline("vorda scan"),
                ""
            )
        )
    } else if messages.is_empty() {
        format!(
            "<section class=\"panel\">{}</section>",
            state(
                "inbox",
                "Inbox is clear",
                "No messages about open findings are waiting.",
                "",
                ""
            )
        )
    } else {
        let open = number(inbox, "open") as usize;
        let reader = s(inbox, "reader");
        let meta = if reader.is_empty() {
            if open == 1 {
                "1 open message".into()
            } else {
                format!("{} open messages", grouped(open))
            }
        } else {
            format!("Reader: {reader} · {} open", grouped(open))
        };
        let rows: String = messages
            .iter()
            .map(|m| {
                let issue = a(snapshot, "issues")
                    .iter()
                    .find(|i| a(i, "keys").contains(&m["key"]));
                let href = issue.map_or(String::new(), |i| format!("/finding/{}", s(i, "id")));
                let sub = [
                    s(m, "host"),
                    if m["kind"] == "health" { "Health" } else { s(m, "title") },
                ]
                .into_iter()
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
                let side = match m["unread"].as_i64() {
                    Some(1) => "Unread",
                    Some(_) => "Read",
                    None => "",
                };
                let ic = if m["kind"] == "health" { "warn" } else { "pkg" };
                if href.is_empty() {
                    format!(
                        "<div class=\"listrow\"><div class=\"badge\">{}</div><div class=\"row-text\"><div class=\"name\">{}</div><div class=\"desc\">{}</div></div><div class=\"side\">{}</div></div>",
                        icon(ic),
                        e(s(m, "headline")),
                        e(&sub),
                        side
                    )
                } else {
                    scope_row(&href, ic, s(m, "headline"), &sub, side)
                }
            })
            .collect();
        let more = if open > messages.len() {
            format!(
                "<div class=\"pad\"><p class=\"row-sub\">{} more</p></div>",
                grouped(open - messages.len())
            )
        } else {
            String::new()
        };
        format!(
            "<section class=\"panel\"><div class=\"panel-header\"><h2>Messages</h2><span class=\"meta\">{}</span></div><div class=\"entity\">{rows}</div>{more}</section>",
            e(&meta)
        )
    };
    h + &page_grid(&main, &side)
}
const REPAIR_TABS: [(&str, &str); 4] = [
    ("needs", "Needs review"),
    ("approved", "Approved"),
    ("verified", "Verified"),
    ("history", "History"),
];
fn draft_tab(d: &Value) -> &str {
    match s(d, "state") {
        "waiting" => "needs",
        "approved" | "applying" | "published" | "pr-pushed" => "approved",
        _ => "history",
    }
}
fn proposed(d: &Value) -> String {
    let place = if s(d, "where").is_empty() {
        s(d, "host")
    } else {
        s(d, "where")
    };
    let meta = [place, s(d, "package")]
        .into_iter()
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    let steps = [
        ("1. Draft", "Review exact changes"),
        ("2. Approve", "Owner-authorized decision"),
        ("3. Apply", "Checks and rollback"),
        ("4. Verify", "Rescan and close"),
    ]
    .iter()
    .enumerate()
    .map(|(k, (b, p))| {
        format!(
            "<div{}><b>{b}</b>{p}</div>",
            if k == 0 { " class=\"now\"" } else { "" }
        )
    })
    .collect::<String>();
    let mut code = String::new();
    for (k, v) in [
        ("item", s(d, "item").to_string()),
        (
            "change",
            if s(d, "old").is_empty() && s(d, "new").is_empty() {
                String::new()
            } else {
                format!("{} → {}", s(d, "old"), s(d, "new"))
            },
        ),
        ("scope", place.to_string()),
        ("risk", s(d, "risk").to_string()),
        ("undo", s(d, "undo").to_string()),
    ] {
        if !v.is_empty() {
            code.push_str(&format!("<span class=\"k\">{k:<8}</span>{}\n", e(&v)));
        }
    }
    format!(
        "<section class=\"panel\"><div class=\"panel-header\"><h2>Proposed change</h2><span class=\"meta\">{}</span></div><div class=\"pad\"><div class=\"proposal\">{}</div><div class=\"row-sub\">{}</div><div class=\"workflow\">{steps}</div><div class=\"code\">{}</div><a class=\"btn primary\" href=\"/review/{}\">Inspect review →</a><p class=\"row-sub\">Preview only. No package or file is modified.</p></div></section>",
        e(&meta),
        e(s(d, "title")),
        e(&draft_meta(d)),
        code.trim_end(),
        e(s(d, "id"))
    )
}
fn repairs_screen(snapshot: &Value, tab: &str) -> String {
    let tab = REPAIR_TABS
        .iter()
        .find(|(k, _)| *k == tab)
        .map_or("needs", |(k, _)| *k);
    let mut out = head(
        "Repairs",
        "Proposed changes, decisions, rollback information, and proof that a fix worked.",
        "",
    );
    out.push_str("<nav class=\"subnav\">");
    for (k, label) in REPAIR_TABS {
        out.push_str(&format!(
            "<a href=\"/repairs?tab={k}\"{}>{label}</a>",
            if k == tab {
                " aria-current=\"page\""
            } else {
                ""
            }
        ));
    }
    out.push_str("</nav>");
    let safety: String = [
        (
            "Exact change",
            "Review the patch, package versions, and resolved dependency state.",
        ),
        (
            "Policy",
            "Watch and Advise modes cannot silently apply changes.",
        ),
        (
            "Rollback",
            "Checks or incomplete rescans trigger rollback in supported repair flows.",
        ),
        (
            "Proof",
            "A completed rescan establishes whether the finding can be closed.",
        ),
    ]
    .iter()
    .map(|(t, p)| fact(t, &para(p)))
    .collect();
    let side = sidecard("Safety conditions", &safety);
    let lone = |body: String| format!("<section class=\"panel\">{body}</section>");
    let main = if snapshot["has_scans"] != true
        && a(snapshot, "drafts").is_empty()
        && a(snapshot, "fixes").is_empty()
    {
        lone(state(
            "findings",
            "No repairs yet",
            "Vorda shows findings, coverage and inventory after the first scan.",
            &cmdline("vorda scan"),
            "",
        ))
    } else if tab == "verified" {
        let fixes = a(snapshot, "fixes");
        if fixes.is_empty() {
            lone(state("check", "No verified repairs", "", "", "small"))
        } else {
            let now = number(snapshot, "now");
            let rows: String = fixes
                .iter()
                .map(|f| {
                    let who = if s(f, "actor_kind").is_empty() {
                        s(f, "actor").to_string()
                    } else {
                        format!("{} ({})", s(f, "actor"), s(f, "actor_kind"))
                    };
                    let proof = if f["proof"].is_null() {
                        "gone on re-scan".into()
                    } else {
                        format!("proof scan #{}", f["proof"])
                    };
                    let mut line = entry(
                        &format!("Fixed: {}", s(f, "what")),
                        &format!(
                            "{} · {} by {who} · {proof}",
                            s(f, "host"),
                            ago(number(f, "at"), now)
                        ),
                    );
                    if !s(f, "undo").is_empty() {
                        line.push_str(&cmdline(s(f, "undo")));
                    }
                    line
                })
                .collect();
            panel(
                "Verified",
                None,
                &format!("<div class=\"mini\">{rows}</div>"),
            )
        }
    } else if snapshot["repairs_on"] != true {
        lone(state(
            "repairs",
            "Repairs are off",
            "Start the dashboard with --fix-config to draft repairs. Findings still show fixes to apply by hand.",
            &cmdline("vorda dashboard --fix-config repair.json"),
            "",
        ))
    } else {
        let drafts: Vec<_> = a(snapshot, "drafts")
            .iter()
            .filter(|d| draft_tab(d) == tab)
            .collect();
        if drafts.is_empty() {
            let title = match tab {
                "needs" => "No repairs to review",
                "approved" => "No approved repairs",
                _ => "No repair history",
            };
            lone(state("repairs", title, "", "", "small"))
        } else if tab == "needs" {
            format!(
                "<div class=\"stack\">{}</div>",
                drafts.into_iter().map(proposed).collect::<String>()
            )
        } else {
            let rows: String = drafts
                .iter()
                .map(|d| {
                    action_row(
                        &format!("/review/{}", s(d, "id")),
                        "",
                        s(d, "title"),
                        draft_state(d),
                        &draft_meta(d),
                    )
                })
                .collect();
            panel(
                REPAIR_TABS
                    .iter()
                    .find(|(k, _)| *k == tab)
                    .map_or("", |(_, l)| *l),
                None,
                &format!("<div class=\"list\">{rows}</div>"),
            )
        }
    };
    out + &page_grid(&main, &side)
}
fn mode_line(mode: &str) -> &'static str {
    match mode {
        "watch" => "Report findings without proposing changes.",
        "fix" => "Permit explicitly allowed, approved remediation.",
        _ => "Prepare guidance and changes for owner review.",
    }
}
fn policy_screen(snapshot: &Value, csrf: &str, writable: bool) -> String {
    let h = head(
        "Policy",
        "Decide what Vorda can inspect, suggest, and change for each machine and agent.",
        "",
    );
    let modes = a(snapshot, "modes");
    let Some(fleet) = modes
        .first()
        .filter(|_| s(snapshot, "control_error").is_empty())
    else {
        return h + &format!(
            "<div class=\"grid\"><section class=\"panel wide\">{}</section></div>",
            state(
                "warn",
                "Can't read the fleet file",
                s(snapshot, "control_error"),
                "",
                "err"
            )
        );
    };
    let can_write = writable && s(snapshot, "fleet_note").is_empty();
    let mode = s(fleet, "mode");
    let boxes: String = crate::policy::MODES
        .iter()
        .map(|m| {
            let on = if *m == mode { " on" } else { "" };
            let inner = format!(
                "<b>{}</b><span>{}</span>",
                capitalize(m),
                mode_line(m)
            );
            if can_write {
                format!(
                    "<button class=\"modebox{on}\" name=\"mode\" value=\"{m}\" aria-pressed=\"{}\">{inner}</button>",
                    *m == mode
                )
            } else {
                format!("<div class=\"modebox{on}\">{inner}</div>")
            }
        })
        .collect();
    let boxes = if can_write {
        format!(
            "<form class=\"modegrid\" method=\"post\" action=\"/mode\" aria-label=\"Mode for the fleet\">{}{boxes}</form>",
            hidden(csrf, &[("scope", "fleet"), ("name", "")])
        )
    } else {
        format!("<div class=\"modegrid\">{boxes}</div>")
    };
    let note = if !writable {
        "Read-only. Start the dashboard with --allow-writes to change the mode."
    } else {
        s(snapshot, "fleet_note")
    };
    let note = if note.is_empty() {
        String::new()
    } else {
        format!("<div class=\"note\">{}</div>", e(note))
    };
    let top = format!(
        "<section class=\"panel\"><div class=\"pad top\"><h2>Default mode</h2><p class=\"row-sub\">Current policy is {}. Changes still need a reviewed draft and required approval.</p>{boxes}{note}</div></section>",
        e(&capitalize(mode))
    );
    let rules = |scope: &str| -> String {
        modes
            .iter()
            .filter(|m| m["scope"] == scope)
            .map(|m| {
                format!(
                    "<div class=\"data-row\"><div><strong>{}</strong><small>{}</small></div><div>{}</div></div>",
                    e(s(m, "name")),
                    e(s(m, "why")),
                    if can_write {
                        segmented(m, csrf, true)
                    } else {
                        e(&capitalize(s(m, "mode")))
                    }
                )
            })
            .collect()
    };
    let machines = rules("machine");
    let machines = if machines.is_empty() {
        state(
            "inventory",
            "No inventory yet",
            "Machines appear here after their first scan. The default mode applies to all of them.",
            "",
            "small",
        )
    } else {
        format!("<div class=\"pad\">{machines}</div>")
    };
    let mut main = panel("Machine rules", None, &machines);
    let agents = rules("agent");
    if !agents.is_empty() {
        main.push_str(&panel(
            "Agent rules",
            None,
            &format!("<div class=\"pad\">{agents}</div>"),
        ));
    }
    let never: String = crate::policy::NEVER
        .iter()
        .map(|n| {
            fact(
                match *n {
                    "kernel" => "Kernel",
                    "bootloader" => "Bootloader",
                    "package-manager" => "Package manager",
                    other => other,
                },
                "",
            )
        })
        .collect();
    let side = sidecard(
        "Protected by default",
        &format!("<p class=\"lead\">Vorda never changes these in any mode.</p>{never}"),
    );
    h + &top + &page_grid(&format!("<div class=\"stack\">{main}</div>"), &side)
}
pub fn render(
    snapshot: &Value,
    screen: &str,
    id: &str,
    filter: &str,
    host: &str,
    csrf: &str,
    writable: bool,
) -> Option<String> {
    Some(match screen {
        "overview" => overview_screen(snapshot),
        "findings" => findings_screen(snapshot, filter, host, "", id),
        "finding" => {
            let i = a(snapshot, "issues").iter().find(|i| i["id"] == id)?;
            let tab = if i["type"] == "health" {
                "coverage"
            } else {
                "all"
            };
            findings_screen(snapshot, tab, "", "", id)
        }
        "inventory" => inventory_screen(snapshot, id),
        "inbox" => inbox_screen(snapshot),
        "review" => return review_screen(snapshot, id, csrf),
        "repairs" => repairs_screen(snapshot, id),
        "policy" => policy_screen(snapshot, csrf, writable),
        _ => return None,
    })
}
