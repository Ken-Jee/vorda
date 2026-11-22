use super::{data::scan_state, english::*};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
const NAV: [(&str, &str, &str, &str); 9] = [
    ("now", "/", "Now", "shield"),
    ("hosts", "/hosts", "Hosts", "server"),
    ("findings", "/findings", "Findings", "list"),
    ("fixes", "/fixes", "Fixes", "check"),
    ("agents", "/agents", "Agent tools", "bot"),
    ("speed", "/speed", "Speed", "gauge"),
    ("news", "/news", "News", "news"),
    ("mailbox", "/mailbox", "Mailbox", "inbox"),
    ("modes", "/modes", "Modes", "sliders"),
];
const FILTERS: [(&str, &str); 6] = [
    ("all", "All"),
    ("kev", "Exploited"),
    ("browser", "Browsers"),
    ("os", "System"),
    ("library", "Projects"),
    ("agent", "Agents"),
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
fn icon(name: &str) -> String {
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
fn span(seconds: Option<f64>) -> String {
    let Some(s) = seconds else {
        return "-".into();
    };
    if s < 3600. {
        format!("{} min", (s / 60.).round().max(1.))
    } else if s < 86400. {
        format!("{:.1} h", s / 3600.)
    } else {
        format!("{:.1} d", s / 86400.)
    }
}
pub fn page(active: &str, title: &str, body: &str, nonce: &str) -> String {
    let mut side = String::new();
    let mut tabs = String::new();
    for (key, href, label, ic) in NAV {
        let current = if key == active {
            " aria-current=\"page\""
        } else {
            ""
        };
        side.push_str(&format!(
            "<a href=\"{href}\"{current}>{}{label}</a>",
            icon(ic)
        ));
        if ["now", "hosts", "findings", "fixes"].contains(&key) {
            tabs.push_str(&format!(
                "<a href=\"{href}\"{current}>{}<span class=\"vh\">{label}</span></a>",
                icon(ic)
            ));
        }
    }
    let more = if ["now", "hosts", "findings", "fixes"].contains(&active) {
        ""
    } else {
        " aria-current=\"page\""
    };
    format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><meta name=\"color-scheme\" content=\"light dark\"><meta name=\"referrer\" content=\"no-referrer\"><title>{} · vorda</title><link rel=\"icon\" href=\"{}\"><style nonce=\"{}\">{}</style><script nonce=\"{}\">{}</script></head><body><div class=\"shell\"><nav class=\"side\" aria-label=\"Main\"><div class=\"brand\">{}vorda</div>{side}<button class=\"theme\" type=\"button\">{}Theme</button></nav><main><div class=\"in\">{body}</div></main></div><nav class=\"tabs\" aria-label=\"Main\"><div class=\"pill\">{tabs}</div><a class=\"round\" href=\"/more\"{more}>{}<span class=\"vh\">More</span></a></nav><div id=\"tip\" role=\"tooltip\"></div></body></html>",e(title),include_str!("favicon.txt"),e(nonce),include_str!("style.css"),e(nonce),include_str!("script.js"),icon("logo"),icon("moon"),icon("more"))
}
pub fn copy_cmd(cmd: &str) -> String {
    format!("<code class=\"cmd\">{0}</code><button class=\"b copy\" type=\"button\" data-copy=\"{0}\">Copy</button>",e(cmd))
}
pub fn empty(line: &str, action: &str) -> String {
    format!("<div class=\"card empty\"><div class=\"title\">{}</div><div class=\"meta\">{action}</div></div>",e(line))
}
#[allow(clippy::too_many_arguments)] // argument list mirrors the report fields; a params struct would only move them
fn row(
    href: &str,
    ic: &str,
    state: &str,
    title: &str,
    meta: &str,
    tone: &str,
    end: &str,
    tag: &str,
) -> String {
    let attrs = if tag == "a" {
        format!(" href=\"{}\"", e(href))
    } else {
        String::new()
    };
    let line = [state, meta]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    let mt = if line.is_empty() {
        String::new()
    } else {
        format!("<span class=\"meta\">{line}</span>")
    };
    let chev = if tag == "div" {
        String::new()
    } else {
        format!("<span class=\"chev\">{}</span>", icon("chev"))
    };
    format!("<{tag} class=\"row\"{attrs}><span class=\"ico {tone}\">{}</span><span class=\"body\"><span class=\"title\">{}</span>{mt}</span>{end}{chev}</{tag}>",icon(ic),e(title))
}
fn capped(items: Vec<String>) -> String {
    if items.len() <= 7 {
        format!("<div class=\"rows\">{}</div>", items.join(""))
    } else {
        format!(
            "<div class=\"rows\">{}<details>{}{}</details></div>",
            items[..7].join(""),
            row(
                "",
                "more",
                "",
                &format!("{} more", items.len() - 7),
                "",
                "",
                "",
                "summary"
            ),
            items[7..].join("")
        )
    }
}
fn plural(n: usize, one: &str) -> String {
    format!("{n} {one}{}", if n == 1 { "" } else { "s" })
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
fn issue_state(i: &Value) -> String {
    format!(
        "{} · {}",
        host(s(i, "host")),
        if i["kev"] == true {
            "<span class=\"crit\">Exploited</span>".into()
        } else {
            e(s(i, "eyebrow"))
        }
    )
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
fn issue_row(i: &Value, action: bool) -> String {
    let draft = &i["draft"];
    let href = if draft.is_object() {
        format!("/review/{}", s(draft, "id"))
    } else {
        format!("/finding/{}", s(i, "id"))
    };
    if draft.is_object() && action {
        return row(
            &href,
            "key",
            &format!("{} · Ready to approve", host(s(i, "host"))),
            s(draft, "title"),
            &versions(draft),
            "",
            "<span class=\"go\">Review</span>",
            "a",
        )
        .replacen("class=\"row\"", "class=\"row act\"", 1);
    }
    let advice = advice(i);
    let meta = if action {
        capitalize(advice.strip_prefix("Advice: ").unwrap_or(&advice))
    } else {
        advice
    };
    let effort = if s(i, "fix").starts_with("No fixed version") {
        "No fix yet"
    } else {
        match s(i, "type") {
            "browser" => "About a minute",
            "os" => "One command",
            "mcp" | "cli" => "One update",
            "skill" => "One switch",
            _ => "",
        }
    };
    let end = if action && !effort.is_empty() {
        format!("<span class=\"fig\">{}</span>", e(effort))
    } else {
        String::new()
    };
    if action && i["mode"] == "watch" {
        return row(
            &href,
            type_icon(s(i, "type")),
            &format!("{} · Alert only", host(s(i, "host"))),
            s(i, "title"),
            &e(s(i, "why")),
            "",
            "",
            "a",
        )
        .replacen("class=\"row\"", "class=\"row act\"", 1);
    }
    let state = if action && i["kev"] != true {
        format!("{} · Advice", host(s(i, "host")))
    } else {
        issue_state(i)
    };
    let rendered = row(
        &href,
        type_icon(s(i, "type")),
        &state,
        s(i, "title"),
        &e(&meta),
        if i["kev"] == true { "crit" } else { "" },
        &end,
        "a",
    );
    if action {
        rendered.replacen("class=\"row\"", "class=\"row act\"", 1)
    } else {
        rendered
    }
}
fn versions(d: &Value) -> String {
    format!(
        "<span class=\"nw m\">{}</span> → <span class=\"nw m\">{}</span>",
        e(s(d, "old")),
        e(s(d, "new"))
    )
}
fn scan_problem(h: &Value, now: f64) -> String {
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
fn coverage_note(why: &str) -> String {
    if why.is_empty() {
        String::new()
    } else {
        format!("<div class=\"quiet\">{} {}</div>", icon("alert"), e(why))
    }
}
fn spark(counts: &[f64]) -> String {
    if counts.len() < 2 {
        return String::new();
    }
    let top = counts.iter().copied().fold(1., f64::max);
    let path = counts
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "{:.1} {:.1}",
                i as f64 * 144. / (counts.len() - 1) as f64,
                36. - c * 32. / top
            )
        })
        .collect::<Vec<_>>()
        .join(" L");
    format!("<svg class=\"spark\" viewBox=\"0 0 144 40\" preserveAspectRatio=\"none\" aria-hidden=\"true\"><path class=\"ln\" d=\"M{path}\" vector-effect=\"non-scaling-stroke\"/></svg>")
}
fn machine_cards(snapshot: &Value) -> String {
    let mut cards = String::new();
    let now = number(snapshot, "now");
    for h in a(snapshot, "hosts") {
        let mine: Vec<_> = a(snapshot, "issues")
            .iter()
            .filter(|i| i["host"] == h["host"] && i["type"] != "health")
            .collect();
        let problem = scan_problem(h, now);
        let kev = mine.iter().any(|i| i["kev"] == true);
        let exploited = mine.iter().filter(|i| i["kev"] == true).count();
        let ready = mine.iter().any(|i| i["draft"].is_object());
        let need = mine.iter().filter(|i| i["needs"] == true).count();
        let word = if kev {
            "<span class=\"word crit\">Exploited</span>".into()
        } else if !problem.is_empty() {
            format!("<span class=\"word crit\">{}</span>", e(&problem))
        } else if need > 0 {
            "<span class=\"word\">Behind</span>".into()
        } else if !mine.is_empty() {
            "<span class=\"word\">Open findings</span>".into()
        } else {
            "<span class=\"word ok\">Fine</span>".into()
        };
        let counts: Vec<_> = a(h, "runs")
            .iter()
            .filter_map(|r| r["findings"].as_f64())
            .collect();
        cards.push_str(&format!("<a href=\"/findings?host={}\" aria-label=\"{}\" class=\"mc\"><span class=\"hd\">{}<span class=\"nm\">{}</span><span class=\"t\">{}{}</span></span><span class=\"fig\"><span class=\"cap\">{need}</span><span class=\"unit\">need you</span></span>{word}{}</a>",encoded(s(h,"host")),e(&format!("{}: {need} need you, {}{}{}{}",s(h,"host"),plural(mine.len(),"open issue"),if exploited > 0 { format!(", {exploited} exploited") } else { String::new() },if ready { ", a fix is ready" } else { "" },if problem.is_empty() { String::new() } else { format!(", {}",problem.to_lowercase()) })),icon("server"),e(s(h,"host")),e(&ago(number(&h["last"],"finished"),now)),icon("chev"),spark(&counts)));
    }
    if cards.is_empty() {
        cards
    } else {
        format!("<div class=\"mcs\">{cards}</div>")
    }
}
fn chart(ex: &Value, soft: bool, now: f64) -> String {
    let counts: Vec<_> = a(ex, "counts").iter().filter_map(Value::as_f64).collect();
    if counts.len() < 2 {
        return String::new();
    }
    let top = counts.iter().copied().fold(1., f64::max);
    let mut path = format!(
        "M0 {:.1}",
        if soft { 112. } else { 108. } - counts[0] * 96. / top
    );
    for (i, c) in counts.iter().enumerate().skip(1) {
        let x = i as f64 * 700. / (counts.len() - 1) as f64;
        let y = if soft { 112. } else { 108. } - c * 96. / top;
        if soft {
            path.push_str(&format!(" L{x:.1} {y:.1}"));
        } else {
            path.push_str(&format!(" H{x:.1} V{y:.1}"));
        }
    }
    let n = counts.last().unwrap();
    if soft {
        return format!("<svg class=\"soft\" viewBox=\"0 0 700 120\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"Open issues per day for 14 days, {n} today\"><defs><linearGradient id=\"soft-fill\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\"><stop offset=\"0\" class=\"top\"/><stop offset=\"1\" class=\"bot\"/></linearGradient></defs><path d=\"{path} V120 H0 Z\" fill=\"url(#soft-fill)\"/><path class=\"ln\" d=\"{path}\" vector-effect=\"non-scaling-stroke\"/></svg><div class=\"axis\"><span>14 days ago</span><span>Today, {n} open</span></div>");
    }
    let mut ticks = String::new();
    for f in a(ex, "fixes") {
        let x =
            (number(f, "at") - number(ex, "start")) / (now - number(ex, "start")).max(1.) * 700.;
        let tip = e(&format!(
            "Fixed {} · {}",
            s(f, "what"),
            ago(number(f, "at"), now)
        ));
        ticks.push_str(&format!("<line class=\"tick\" x1=\"{x:.1}\" x2=\"{x:.1}\" y1=\"108\" y2=\"118\" vector-effect=\"non-scaling-stroke\"/><rect class=\"hit\" x=\"{:.1}\" y=\"96\" width=\"16\" height=\"24\" data-tip=\"{tip}\"><title>{tip}</title></rect>",x-8.));
    }
    format!("<div class=\"card\"><div class=\"label\">Open, 14 days</div><div class=\"endlabel\"><b>{n}</b>today</div><svg class=\"area\" viewBox=\"0 0 700 120\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"Open findings per day for 14 days, {n} today\"><path class=\"wash\" d=\"{path} V108 H0 Z\"/><path class=\"ln\" d=\"{path}\" vector-effect=\"non-scaling-stroke\"/><line class=\"base\" x1=\"0\" x2=\"700\" y1=\"108\" y2=\"108\" vector-effect=\"non-scaling-stroke\"/>{ticks}</svg><div class=\"axis\"><span>14 d ago</span><span>Ticks are fixes</span><span>Today</span></div></div>")
}
fn encoded(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
fn finding_advisories(issue: &Value) -> &[Value] {
    if issue["type"] == "health" {
        &[]
    } else {
        a(issue, "advisories")
    }
}
fn open_count(issue: &Value) -> usize {
    if issue["type"] == "health" {
        0
    } else {
        number(issue, "count") as usize
    }
}
fn no_scans_label(snapshot: &Value) -> &str {
    if snapshot["has_scans"] == true {
        "No scans in this view"
    } else {
        "No scans yet"
    }
}
fn project_cards(snapshot: &Value) -> String {
    let projects = a(snapshot, "projects");
    if projects.is_empty() {
        return String::new();
    }
    let mut body = "<h2>Projects</h2><div class=\"rows\">".to_string();
    for p in projects {
        let unknown = p["scan"] != "ok";
        let word = if unknown {
            "Can't confirm"
        } else if number(p, "urgent") > 0. {
            "Urgent"
        } else if number(p, "open") > 0. {
            "Open findings"
        } else if p["inferred"] == true {
            "Saved historical scope"
        } else {
            "Clear"
        };
        let place = if p["imported"] == true {
            s(p, "source")
        } else if s(p, "root").is_empty() {
            "Location not recorded"
        } else {
            s(p, "root")
        };
        let mut meta = format!(
            "{} · scanned {} · {} urgent, {} open",
            place,
            ago(number(&p["last"], "finished"), number(snapshot, "now")),
            number(p, "urgent"),
            number(p, "open")
        );
        if p["missing"] == true || p["nothing_checked"] == true || !a(p, "problems").is_empty() {
            meta.push_str(&format!(" · {}", scan_problem(p, number(snapshot, "now"))));
        }
        if p["inferred"] == true {
            meta.push_str(" · Saved historical scope · Original scan root not recorded");
        }
        body.push_str(&row(
            &if p["inferred"] == true {
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
            },
            "list",
            word,
            s(p, "name"),
            &e(&meta),
            if unknown || number(p, "urgent") > 0. {
                "crit"
            } else {
                ""
            },
            "",
            "a",
        ));
    }
    body + "</div>"
}
pub fn now_screen(snapshot: &Value) -> String {
    let (hosts, issues) = (a(snapshot, "hosts"), a(snapshot, "issues"));
    if hosts.is_empty() && issues.is_empty() {
        return format!(
            "<div class=\"card\"><div class=\"hero\">{}</div>{}</div>",
            no_scans_label(snapshot),
            copy_cmd("vorda check")
        );
    }
    let needs: Vec<_> = issues.iter().filter(|i| i["needs"] == true).collect();
    let now = number(snapshot, "now");
    let last = hosts
        .iter()
        .map(|h| number(&h["last"], "finished"))
        .fold(0., f64::max);
    let month = a(snapshot, "fixes")
        .iter()
        .filter(|f| now - number(f, "at") < 2592000.)
        .count();
    let mut quiet = format!(
        "<div class=\"quiet\">{} new today · {month} fixed in 30 days · scanned {}</div>",
        number(snapshot, "new_today"),
        e(&ago(last, now))
    );
    let mut why = coverage(hosts, now);
    let unknown: Vec<_> = a(snapshot, "projects")
        .iter()
        .filter(|p| p["scan"] != "ok")
        .collect();
    if !unknown.is_empty() {
        if !why.is_empty() {
            why.push_str(" · ");
        }
        why.push_str(&format!(
            "Can't confirm: {}",
            unknown
                .iter()
                .map(|p| s(p, "name"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let open: usize = issues.iter().map(open_count).sum();
    quiet.push_str(&format!(
        "<div class=\"quiet\">{} urgent, {open} open · {} unknown · <a class=\"lnk\" href=\"/findings\">View findings</a></div>",
        needs.len(), plural(unknown.len(), "project")
    ));
    let hero = if !why.is_empty() {
        let urgent = if needs.is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"hero\">{}<span class=\"label\">need you</span></div>",
                needs.len()
            )
        };
        format!(
            "{urgent}<div class=\"hero\">{}<span>Can't confirm</span></div><div class=\"quiet\">{}</div>{}",
            icon("alert"),
            e(&why),
            copy_cmd("vorda check")
        )
    } else if !needs.is_empty() {
        format!(
            "<div class=\"hero\">{}<span class=\"label\">need you</span></div>",
            needs.len()
        )
    } else if !issues.is_empty() {
        let dev: usize = issues
            .iter()
            .filter(|i| i["dev_only"] == true)
            .map(open_count)
            .sum();
        if dev > 0 {
            quiet.push_str(&format!("<div class=\"quiet\">{dev} marked likely dev only by lockfile flags or test or fixture folders</div>"));
        }
        format!("<div class=\"hero\">0 urgent, {open} open</div><a class=\"lnk\" href=\"/findings\">View findings</a>")
    } else {
        format!(
            "<div class=\"hero\">{}<span>All clear</span></div>",
            icon("check")
        )
    };
    let mut body = format!(
        "<div class=\"card\">{hero}{quiet}{}</div>{}",
        if !issues.is_empty() || !a(snapshot, "fixes").is_empty() {
            chart(&snapshot["exposure"], true, now)
        } else {
            String::new()
        },
        machine_cards(snapshot) + &project_cards(snapshot)
    );
    if !needs.is_empty() {
        body.push_str(&format!(
            "<h2>Do these next</h2><div class=\"rows\">{}</div>",
            needs
                .iter()
                .take(4)
                .map(|i| issue_row(i, true))
                .collect::<String>()
        ));
    }
    if needs.len() > 4 {
        body.push_str(&format!(
            "<div class=\"rows\" id=\"later\">{}</div>",
            row(
                "/findings",
                "list",
                "",
                &format!("{} more need you", needs.len() - 4),
                "",
                "",
                "",
                "a"
            )
        ));
    }
    if issues.len() > needs.len() {
        body.push_str(&format!(
            "<a class=\"lnk quiet\" href=\"/findings\">All {}</a>",
            plural(issues.len(), "issue")
        ));
    }
    if !a(snapshot, "news").is_empty() {
        body.push_str(&format!(
            "<h2>Latest</h2><div class=\"rows\">{}{}</div>",
            {
                let mut latest = a(snapshot, "news").to_vec();
                latest.sort_by_key(|n| !(n["kev"] == true && !a(n, "hosts").is_empty()));
                news_rows(&latest.iter().collect::<Vec<_>>(), now)
                    .into_iter()
                    .take(2)
                    .collect::<String>()
            },
            row("/news", "news", "", "All news", "", "", "", "a")
        ));
    }
    body
}
fn news_where(n: &Value) -> String {
    let hosts = a(n, "hosts");
    if !hosts.is_empty() {
        format!(
            "Saved match on {}",
            if hosts.len() < 3 {
                hosts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                plural(hosts.len(), "machine")
            }
        )
    } else if n["type"] == "public-update" {
        "No saved local match".into()
    } else if n["fixed"] == true {
        "Fixed here".into()
    } else {
        "No longer found".into()
    }
}
fn news_row(n: &Value, now: f64) -> String {
    let meta = format!(
        "{} · <span class=\"nw m\">{}</span> · <span class=\"nw\">{}</span>",
        e(&news_where(n)),
        e(s(n, "advisory")),
        e(&if s(n, "published").is_empty() {
            ago(number(n, "at"), now)
        } else {
            s(n, "published").into()
        })
    );
    let urgent = n["kev"] == true && !a(n, "hosts").is_empty();
    let url = s(n, "url");
    let html = row(
        url,
        if urgent {
            "alert"
        } else {
            type_icon(s(n, "type"))
        },
        "",
        s(n, "text"),
        &meta,
        if urgent { "crit" } else { "" },
        "",
        if url.is_empty() { "div" } else { "a" },
    );
    if url.is_empty() {
        html
    } else {
        html.replacen('>', " rel=\"noreferrer noopener\" target=\"_blank\">", 1)
    }
}
fn hosts_screen(snapshot: &Value) -> String {
    let hosts = a(snapshot, "hosts");
    if hosts.is_empty() {
        return "<h1>Hosts</h1>".to_string()
            + &empty(no_scans_label(snapshot), &copy_cmd("vorda check"));
    }
    let good = hosts.iter().filter(|h| h["health"] == "good").count();
    let mut body=format!("<h1>Hosts</h1><div class=\"tiles\"><div class=\"card tile\"><div class=\"label\">Healthy</div><div class=\"num\">{good}</div></div><div class=\"card tile\"><div class=\"label\">Needs a look</div><div class=\"num\">{}</div></div></div><h2>All hosts</h2><div class=\"rows\">",hosts.len()-good);
    let now = number(snapshot, "now");
    for h in hosts {
        let (word, tone) = match s(h, "health") {
            "good" => ("Healthy", "ok"),
            "critical" => ("Exploited flaw", "crit"),
            _ => ("Needs a look", "warn"),
        };
        let problem = scan_problem(h, now);
        let word = if problem.is_empty() {
            word.into()
        } else if tone == "crit" {
            format!("{word} · {problem}")
        } else {
            problem
        };
        let mut meta = format!(
            "Scanned {} · {}",
            ago(number(&h["last"], "finished"), now),
            plural(number(h, "open") as usize, "issue")
        );
        let bad = a(h, "runs")
            .iter()
            .filter(|r| scan_state(r, now, false) == "failed")
            .count();
        if bad > 0 {
            meta.push_str(&format!(
                " · {bad} of {} scans incomplete",
                a(h, "runs").len()
            ));
        }
        let state = if ["crit", "ok"].contains(&tone) {
            format!("<span class=\"{tone}\">{}</span>", e(&word))
        } else {
            e(&word)
        };
        body.push_str(&row(
            &format!("/findings?host={}", encoded(s(h, "host"))),
            "server",
            &state,
            s(h, "host"),
            &e(&meta),
            tone,
            "",
            "a",
        ));
    }
    body + "</div>"
}
fn sev_card(issues: &[&Value]) -> String {
    let mut counts = [0usize; 5];
    for i in issues {
        for adv in finding_advisories(i) {
            counts[SEVERITIES
                .iter()
                .position(|s| *s == super::english::s(adv, "severity"))
                .unwrap_or(4)] += 1;
        }
        let observations = open_count(i).saturating_sub(finding_advisories(i).len());
        counts[SEVERITIES
            .iter()
            .position(|sev| *sev == s(i, "severity"))
            .unwrap_or(4)] += observations;
    }
    let total: usize = counts.iter().sum();
    let (mut x, mut segments, mut legend) = (0., String::new(), String::new());
    for (sev, count) in SEVERITIES.iter().zip(counts) {
        if count > 0 {
            let w = count as f64 * 100. / total as f64;
            let tip = format!("{}: {count}", capitalize(sev));
            segments.push_str(&format!("<rect class=\"seg sev-{sev}\" x=\"{x:.3}%\" y=\"0\" width=\"{w:.3}%\" height=\"14\" rx=\"2\" data-tip=\"{tip}\"><title>{tip}</title></rect>"));
            x += w;
        }
        legend.push_str(&format!("<div><span class=\"dot sev-{sev}\"></span><span>{}</span><span class=\"lead\"></span><span>{count}</span></div>",capitalize(sev)));
    }
    format!("<div class=\"card\" id=\"sev\"><div class=\"label\">Open findings</div><div class=\"hero\">{total}</div><svg class=\"bar\" role=\"img\" aria-label=\"Findings by severity\">{segments}</svg><div class=\"legend\">{legend}</div></div>")
}
pub(super) fn findings_screen(snapshot: &Value, filter: &str, host: &str, project: &str) -> String {
    let projects: Vec<_> = a(snapshot, "projects")
        .iter()
        .filter(|p| {
            (p["root"] == project || p["imported"] == true && p["scope"] == project)
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
    let issues: Vec<&Value> = own.iter().collect();
    let shown: Vec<_> = issues
        .iter()
        .copied()
        .filter(|i| {
            filter == "all"
                || filter == "kev" && i["kev"] == true
                || i["type"] == filter
                || filter == "agent" && ["mcp", "skill", "cli"].contains(&s(i, "type"))
        })
        .collect();
    let mut title = format!(
        "<h1>Findings{}</h1>",
        if host.is_empty() {
            String::new()
        } else {
            format!(" on {}", e(host))
        }
    );
    if !project.is_empty() {
        let label = projects
            .iter()
            .find(|p| p["imported"] == true)
            .map_or(project, |p| s(p, "name"));
        title.push_str(&format!("<div class=\"sub\">Project: {}</div>", e(label)));
    }
    if a(snapshot, "hosts").is_empty() {
        return title + &empty(no_scans_label(snapshot), &copy_cmd("vorda check"));
    }
    let hosts: Vec<_> = a(snapshot, "hosts")
        .iter()
        .filter(|h| host.is_empty() || h["host"] == host)
        .cloned()
        .collect();
    let why = coverage(
        if project.is_empty() {
            &hosts
        } else {
            &projects
        },
        number(snapshot, "now"),
    );
    if issues.is_empty() {
        return title
            + &if why.is_empty() {
                empty("Nothing found", "<a href=\"/hosts\">See hosts</a>")
            } else {
                empty("Can't confirm", &(e(&why) + &copy_cmd("vorda check")))
            };
    }
    let tabs = FILTERS
        .iter()
        .map(|(key, label)| {
            format!(
                "<a href=\"/findings?f={key}{}{}\"{}>{label}</a>",
                if host.is_empty() {
                    String::new()
                } else {
                    format!("&amp;host={}", encoded(host))
                },
                if project.is_empty() {
                    String::new()
                } else {
                    format!("&amp;project={}", encoded(project))
                },
                if *key == filter {
                    " aria-current=\"page\""
                } else {
                    ""
                }
            )
        })
        .collect::<String>();
    let mut body = title + &coverage_note(&why) + &format!("<div class=\"filters\">{tabs}</div>");
    if shown.is_empty() {
        return body + &empty("None in this view", "<a href=\"/findings\">Show all</a>");
    }
    body.push_str(&format!(
        "<div class=\"stack\">{}{}</div><h2>{}</h2>{}",
        sev_card(&shown),
        if filter == "all" && host.is_empty() && project.is_empty() {
            chart(&snapshot["exposure"], false, number(snapshot, "now"))
        } else {
            String::new()
        },
        plural(shown.len(), "issue"),
        capped(shown.iter().map(|i| issue_row(i, false)).collect())
    ));
    body
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
                "<a href=\"/fixes\">See fixes</a>",
            )
    } else {
        back("/mailbox", "Mailbox")
            + "<h1>Not found</h1>"
            + &empty(
                "This draft was applied, dismissed or replaced",
                "<a href=\"/fixes\">See fixes</a>",
            )
    }
}
fn finding_screen(snapshot: &Value, id: &str) -> Option<String> {
    let i = a(snapshot, "issues").iter().find(|i| i["id"] == id)?;
    let fix = s(i, "fix");
    let fix_card = if i["mode"] == "watch" && i["type"] != "health" {
        "<div class=\"card\"><div class=\"title step\">Alert only on this machine</div></div>"
            .into()
    } else {
        format!(
            "<div class=\"card\"><div class=\"label\">Fix</div>{}{}{}</div>",
            if let Some(cmd) = fix.strip_prefix("Run: ") {
                copy_cmd(cmd)
            } else {
                format!("<div class=\"title step\">{}</div>", e(fix))
            },
            if s(i, "installed").is_empty() {
                String::new()
            } else {
                format!(
                    "<div class=\"quiet\">Installed {}{}</div>",
                    e(s(i, "installed")),
                    if s(i, "target").is_empty() {
                        String::new()
                    } else {
                        format!(" → needs {}", e(s(i, "target")))
                    }
                )
            },
            if s(i, "path").is_empty() {
                String::new()
            } else {
                format!("<div class=\"quiet\">At {}</div>", e(s(i, "path")))
            }
        )
    };
    let mut advs = String::new();
    let mut aliases = BTreeSet::new();
    for adv in a(i, "advisories") {
        let basis = if s(adv, "basis").is_empty() {
            String::new()
        } else {
            format!(" ({})", e(s(adv, "basis")))
        };
        let confidence = if s(adv, "confidence").is_empty() {
            String::new()
        } else {
            format!(" · Match: {}", e(s(adv, "confidence")))
        };
        advs.push_str(&format!("<div><div class=\"title\">{}</div><div class=\"meta\">{} · {}{basis}{}{confidence}</div>{}</div>",e(s(adv,"id")),e(s(adv,"package")),capitalize(s(adv,"severity")),if adv["kev"]==true{" · Exploited in the wild"}else{""},a(adv,"sources").iter().filter_map(Value::as_str).take(2).map(|url|format!("<div class=\"meta\"><a href=\"{0}\" rel=\"noreferrer noopener\" target=\"_blank\">{0}</a></div>",e(url))).collect::<String>()));
        aliases.extend(a(adv, "aliases").iter().filter_map(Value::as_str));
    }
    for adv in a(i, "advisories") {
        aliases.remove(s(adv, "id"));
    }
    if !aliases.is_empty() {
        advs.push_str(&format!(
            "<div><div class=\"meta\">Also known as {}</div></div>",
            e(&aliases.into_iter().take(30).collect::<Vec<_>>().join(", "))
        ));
    }
    let details = if a(i, "advisories").is_empty() {
        String::new()
    } else {
        format!("<details class=\"toggle\"><summary>{}Details · {}</summary><div class=\"card adv\">{advs}</div></details>",icon("chev"),plural(a(i,"advisories").len(),"finding"))
    };
    Some(format!("{}<h1>{}</h1><div class=\"sub\">{}</div><div class=\"stack\"><div class=\"card\"><div class=\"label\">Why it matters</div><div class=\"title step\">{}</div></div>{fix_card}</div>{details}",back("/findings","Findings"),e(s(i,"title")),issue_state(i),e(if s(i,"why").is_empty(){fix}else{s(i,"why")})))
}
fn bars(values: &[Value]) -> String {
    let top = values.iter().filter_map(Value::as_f64).fold(1., f64::max);
    let mut out = String::new();
    for (k, v) in values.iter().enumerate() {
        let v = v.as_f64().unwrap_or(0.);
        let h = if v == 0. {
            0.
        } else {
            (v * 120. / top).max(4.)
        };
        let x = k as f64 * 100. / values.len().max(1) as f64;
        let label = if k < 7 {
            format!("{}w", 7 - k)
        } else {
            "Now".into()
        };
        let tip = format!("{label}: {v} fixed");
        out.push_str(&format!("<rect class=\"b\" x=\"{:.3}%\" y=\"{:.1}\" width=\"7.5%\" height=\"{h:.1}\" rx=\"2\" data-tip=\"{tip}\"><title>{tip}</title></rect><text class=\"v\" x=\"{:.3}%\" y=\"{:.1}\" text-anchor=\"middle\">{v}</text><text x=\"{:.3}%\" y=\"172\" text-anchor=\"middle\">{label}</text>",x+2.5,150.-h,x+6.25,142.-h,x+6.25));
    }
    format!("<svg class=\"chart\" role=\"img\" aria-label=\"Fixes per week\"><line class=\"base\" x1=\"0\" x2=\"100%\" y1=\"150.5\" y2=\"150.5\"/>{out}</svg>")
}
fn fixes_screen(snapshot: &Value) -> String {
    let fixes = a(snapshot, "fixes");
    if fixes.is_empty() {
        return "<h1>Fixes</h1>".to_string()
            + &empty(
                "Nothing fixed yet",
                "<a href=\"/findings\">See findings</a>",
            );
    }
    let values = a(snapshot, "fixes_weekly");
    let total: f64 = values.iter().filter_map(Value::as_f64).sum();
    let mut items = Vec::new();
    for f in fixes {
        let who = format!(
            "by {}{}",
            s(f, "actor"),
            if s(f, "actor_kind").is_empty() {
                String::new()
            } else {
                format!(" ({})", s(f, "actor_kind"))
            }
        );
        let proof = if f["proof"].is_null() {
            "gone on re-scan".into()
        } else {
            format!("proof scan #{}", f["proof"])
        };
        let meta = format!(
            "{} · {} {who} · {proof}",
            s(f, "host"),
            ago(number(f, "at"), number(snapshot, "now"))
        );
        let inner = row(
            "",
            "check",
            "",
            &format!("Fixed: {}", s(f, "what")),
            &e(&meta),
            "ok",
            "",
            "summary",
        );
        let mut more = String::new();
        if !s(f, "command").is_empty() {
            more.push_str(&format!(
                "<p class=\"meta\">Ran</p><code class=\"cmd\">{}</code>",
                e(s(f, "command"))
            ));
        }
        if !s(f, "undo").is_empty() {
            more.push_str(&format!(
                "<p class=\"meta\">Undo</p>{}",
                copy_cmd(s(f, "undo"))
            ));
        }
        if more.is_empty() {
            more = "<p class=\"meta\">Closed by a clean re-scan</p>".into();
        }
        items.push(format!(
            "<details>{inner}<div class=\"more\">{more}</div></details>"
        ));
    }
    format!("<h1>Fixes</h1><div class=\"card\"><div class=\"label\">Fixed, 8 weeks</div><div class=\"hero\">{total}</div>{}</div><h2>History</h2>{}",bars(values),capped(items))
}
fn agents_screen(snapshot: &Value) -> String {
    let bom = a(snapshot, "bom");
    if bom.is_empty() {
        return "<h1>Agent tools</h1>".to_string()
            + &empty(
                "No agent tools listed yet",
                "<a href=\"/hosts\">See hosts</a>",
            );
    }
    let count = |kind: &str| bom.iter().filter(|b| b["kind"] == kind).count();
    let mut body=format!("<h1>Agent tools</h1><div class=\"tiles\"><div class=\"card tile\"><div class=\"label\">MCP servers</div><div class=\"num\">{}</div></div><div class=\"card tile\"><div class=\"label\">Skills and CLIs</div><div class=\"num\">{}</div></div></div>",count("mcp"),count("skill")+count("cli"));
    let hosts: BTreeSet<_> = bom.iter().map(|b| s(b, "host")).collect();
    for h in hosts {
        body.push_str(&format!("<h2>{}</h2><div class=\"rows\">", e(h)));
        for b in bom.iter().filter(|b| b["host"] == h) {
            let (word, ic) = match s(b, "kind") {
                "mcp" => ("MCP", "bot"),
                "skill" => ("Skill", "box"),
                "cli" => ("CLI", "terminal"),
                k => (k, "box"),
            };
            let bad = a(snapshot, "issues").iter().any(|i| {
                i["host"] == h
                    && i["type"] == b["kind"]
                    && a(i, "advisories")
                        .first()
                        .is_some_and(|a| s(a, "package").split(' ').next() == Some(s(b, "name")))
            });
            let mut meta = format!(
                "{} · {}",
                if s(b, "version").is_empty() {
                    "?"
                } else {
                    s(b, "version")
                },
                s(b, "source")
            );
            if ["unknown", "stale"].contains(&s(b, "confidence")) {
                meta.push_str(&format!(" · {}", capitalize(s(b, "confidence"))));
            }
            let state = if bad {
                format!("{word} · Known flaw")
            } else {
                word.into()
            };
            body.push_str(&row(
                if bad { "/findings?f=agent" } else { "" },
                ic,
                &e(&state),
                s(b, "name"),
                &e(&meta),
                if bad { "crit" } else { "" },
                "",
                if bad { "a" } else { "div" },
            ));
        }
        body.push_str("</div>");
    }
    body
}
fn dot_plot(delays: &[Value], median: f64) -> String {
    let pos = |d: f64| (d.clamp(60., 604800.) / 60.).ln() / (604800f64 / 60.).ln() * 100.;
    let mut values: Vec<_> = delays.iter().filter_map(Value::as_f64).collect();
    values.sort_by(f64::total_cmp);
    let mut levels: BTreeMap<i64, usize> = BTreeMap::new();
    let mut dots = String::new();
    for d in values.into_iter().take(400) {
        let key = (pos(d) / 2.).round() as i64;
        let level = levels.entry(key).or_default();
        let tip = e(&span(Some(d)));
        dots.push_str(&format!("<circle cx=\"{:.2}%\" cy=\"{}\" r=\"5\" data-tip=\"{tip}\"><title>{tip}</title></circle>",pos(d),109-(*level).min(8)*11));
        *level += 1;
    }
    let mut ticks = String::new();
    for (t, label, anchor) in [
        (60., "1 min", "start"),
        (600., "10 min", "middle"),
        (3600., "1 h", "middle"),
        (21600., "6 h", "middle"),
        (86400., "1 d", "middle"),
        (604800., "7 d", "end"),
    ] {
        ticks.push_str(&format!(
            "<text x=\"{:.2}%\" y=\"140\" text-anchor=\"{anchor}\">{label}</text>",
            pos(t)
        ));
    }
    let m = pos(median);
    let label = e(&span(Some(median)));
    format!("<svg class=\"dots\" role=\"img\" aria-label=\"Time to warn for each alert, median {label}\"><line class=\"base\" x1=\"0\" x2=\"100%\" y1=\"118\" y2=\"118\"/>{dots}<line class=\"med\" x1=\"{m:.2}%\" x2=\"{m:.2}%\" y1=\"22\" y2=\"118\"/><text class=\"v\" x=\"{m:.2}%\" y=\"14\" text-anchor=\"{}\">median {label}</text>{ticks}</svg>",if m<50.{"start"}else{"end"})
}
fn speed_screen(snapshot: &Value) -> String {
    let sp = &snapshot["speed"];
    if number(sp, "count") == 0. {
        return "<h1>Speed</h1>".to_string()
            + &empty("No timing yet", "<a href=\"/findings\">See findings</a>");
    }
    let mut body=format!("<h1>Speed</h1><div class=\"card\"><div class=\"label\">Time to warn you, median</div><div class=\"hero\">{}</div><div class=\"quiet\">Published to alert · {}</div>{}</div><h2>By kind</h2><div class=\"rows\">",span(sp["median"].as_f64()),plural(number(sp,"count")as usize,"alert"),dot_plot(a(sp,"delays"),number(sp,"median")));
    for r in a(sp, "by_type") {
        let t = r[0].as_str().unwrap_or("");
        let name = match t {
            "browser" => "Browsers",
            "os" => "System packages",
            "library" => "Projects",
            "mcp" => "MCP servers",
            "skill" => "Skills",
            "cli" => "Agent tools",
            _ => "Other",
        };
        body.push_str(&row(
            "",
            type_icon(t),
            "",
            name,
            &plural(r[2].as_u64().unwrap_or(0) as usize, "alert"),
            "",
            &format!("<span class=\"end\">{}</span>", span(r[1].as_f64())),
            "div",
        ));
    }
    body + "</div>"
}
fn news_screen(snapshot: &Value) -> String {
    let news = a(snapshot, "news");
    if news.is_empty() {
        return "<h1>News</h1>".to_string()
            + &empty(
                "Public updates unavailable",
                "No usable public catalog is saved. An online assessment can refresh it.",
            );
    }
    let now = number(snapshot, "now");
    let mine = news.iter().filter(|n| !a(n, "hosts").is_empty()).count();
    let mut body=format!("<h1>News</h1><div class=\"card\"><div class=\"label\">Saved local matches</div><div class=\"hero\">{mine}<span class=\"label\"> of {}</span></div>{}</div>",news.len(),coverage_note(&coverage(a(snapshot,"hosts"),now)));
    if snapshot["feed"]["status"] == "stale" {
        body.push_str("<p class=\"meta\">Saved CISA KEV data is stale. These updates may be incomplete; an online assessment can refresh them.</p>");
    }
    let kev: Vec<_> = news
        .iter()
        .filter(|n| n["kev"] == true && !a(n, "hosts").is_empty())
        .map(|n| news_row(n, now))
        .collect();
    if !kev.is_empty() {
        body.push_str(&format!(
            "<h2>Exploited</h2><div class=\"rows\">{}</div>",
            kev.join("")
        ));
    }
    let mut groups: Vec<(String, Vec<&Value>)> = Vec::new();
    for n in news {
        let label = day(number(n, "at"), now);
        if let Some((_, items)) = groups.iter_mut().find(|(name, _)| name == &label) {
            items.push(n);
        } else {
            groups.push((label, vec![n]));
        }
    }
    body.push_str("<div class=\"tl\">");
    for (label, items) in groups {
        body.push_str(&format!(
            "<h2>{}</h2>{}",
            e(&label),
            capped(news_rows(&items, now))
        ));
    }
    body + "</div>"
}
fn local_time(timestamp: f64) -> Option<libc::tm> {
    if !timestamp.is_finite() || timestamp < 0. || timestamp > 253402300799. {
        return None;
    }
    let time = timestamp as libc::time_t;
    let mut out = std::mem::MaybeUninit::<libc::tm>::uninit();
    #[cfg(unix)]
    {
        if unsafe { libc::localtime_r(&time, out.as_mut_ptr()) }.is_null() {
            return None;
        }
    }
    #[cfg(windows)]
    {
        if unsafe { libc::localtime_s(out.as_mut_ptr(), &time) } != 0 {
            return None;
        }
    }
    Some(unsafe { out.assume_init() })
}
fn day(timestamp: f64, now: f64) -> String {
    let Some(date) = local_time(timestamp) else {
        return "Unknown date".into();
    };
    let same = |other: libc::tm| other.tm_year == date.tm_year && other.tm_yday == date.tm_yday;
    if local_time(now).is_some_and(same) {
        return "Today".into();
    }
    if local_time(now - 86400.).is_some_and(same) {
        return "Yesterday".into();
    }
    let weekdays = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    let months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    format!(
        "{} {} {}",
        weekdays.get(date.tm_wday as usize).unwrap_or(&""),
        date.tm_mday,
        months.get(date.tm_mon as usize).unwrap_or(&"")
    )
}
fn news_rows(items: &[&Value], now: f64) -> Vec<String> {
    let mut groups: Vec<Vec<&Value>> = Vec::new();
    for n in items.iter().copied().filter(|n| n["mine"] == true) {
        if let Some(group) = groups.iter_mut().find(|g| {
            g[0]["name"] == n["name"] && g[0]["hosts"] == n["hosts"] && g[0]["fixed"] == n["fixed"]
        }) {
            group.push(n);
        } else {
            groups.push(vec![n]);
        }
    }
    let mut out = Vec::new();
    for group in groups {
        if group.len() == 1 {
            out.push(news_row(group[0], now));
            continue;
        }
        let first = group[0];
        let kev = group.iter().filter(|n| n["kev"] == true).count();
        let meta = format!(
            "{}{} · <span class=\"nw\">{}</span>",
            e(&news_where(first)),
            if kev > 0 {
                format!(" · {kev} exploited")
            } else {
                String::new()
            },
            e(&ago(number(first, "at"), now))
        );
        let ids=group.iter().map(|n|{let id=e(s(n,"advisory"));let url=s(n,"url");if url.is_empty(){format!("<span class=\"nw m\">{id}</span>")}else{format!("<a class=\"lnk nw m\" href=\"{}\" rel=\"noreferrer noopener\" target=\"_blank\">{id}</a>",e(url))}}).collect::<String>();
        let urgent = kev > 0 && !a(first, "hosts").is_empty();
        let summary = row(
            "",
            if urgent {
                "alert"
            } else {
                type_icon(s(first, "type"))
            },
            "",
            &format!(
                "{}: {} {}flaws",
                s(first, "name"),
                group.len(),
                if a(first, "hosts").is_empty() {
                    ""
                } else {
                    "new "
                }
            ),
            &meta,
            if urgent { "crit" } else { "" },
            "",
            "summary",
        );
        out.push(format!(
            "<details>{summary}<div class=\"more ids\">{ids}</div></details>"
        ));
    }
    let others: Vec<_> = items
        .iter()
        .copied()
        .filter(|n| n["mine"] != true)
        .collect();
    if !others.is_empty() {
        let title = if others.len() == 1 {
            "1 advisory doesn't affect you".into()
        } else {
            format!("{} advisories don't affect you", others.len())
        };
        let inner = others
            .iter()
            .map(|n| {
                row(
                    s(n, "url"),
                    "news",
                    "",
                    s(n, "advisory"),
                    &e(&format!(
                        "{} · {}",
                        s(n, "source"),
                        ago(number(n, "at"), now)
                    )),
                    "",
                    "",
                    "a",
                )
                .replacen(
                    '>',
                    " rel=\"noreferrer noopener\" target=\"_blank\">",
                    1,
                )
            })
            .collect::<String>();
        out.push(format!(
            "<details>{}{inner}</details>",
            row("", "news", "", &title, "", "", "", "summary")
        ));
    }
    out
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
fn mailbox_screen(snapshot: &Value) -> String {
    let mut body = "<h1>Mailbox</h1>".to_string();
    let waiting: Vec<_> = a(snapshot, "drafts")
        .iter()
        .filter(|d| d["state"] == "waiting")
        .collect();
    if !waiting.is_empty() {
        body.push_str("<h2>Needs your OK</h2>");
        body.push_str(&capped(
            waiting
                .iter()
                .map(|d| {
                    row(
                        &format!("/review/{}", s(d, "id")),
                        "key",
                        "",
                        s(d, "title"),
                        &e(&draft_meta(d)),
                        "",
                        "",
                        "a",
                    )
                })
                .collect(),
        ));
    }
    if a(snapshot, "readers").is_empty() && waiting.is_empty() {
        return body
            + &empty(
                "No agents read the mailbox yet",
                &copy_cmd("vorda snippet mcp"),
            );
    }
    body.push_str("<h2>Readers</h2><div class=\"rows\">");
    for r in a(snapshot, "readers") {
        let meta = format!(
            "{} done · read {}",
            number(r, "acked"),
            ago(number(r, "last_read"), number(snapshot, "now"))
        );
        body.push_str(&format!("<div class=\"row\"><span class=\"ico av\">{}</span><span class=\"body\"><span class=\"title\">{}</span><span class=\"meta\">{}</span></span><span class=\"end\">{}<small>unread</small></span></div>",e(&s(r,"name").chars().take(2).collect::<String>().to_uppercase()),e(s(r,"name")),e(&meta),number(r,"unread")));
    }
    body.push_str("</div>");
    let decided: Vec<_> = a(snapshot, "drafts")
        .iter()
        .filter(|d| d["state"] != "waiting")
        .collect();
    if !decided.is_empty() {
        body.push_str("<h2>Decided</h2>");
        body.push_str(&capped(
            decided
                .iter()
                .map(|d| {
                    row(
                        &format!("/review/{}", s(d, "id")),
                        if ["approved", "fixed", "applying"].contains(&s(d, "state")) {
                            "check"
                        } else {
                            "alert"
                        },
                        draft_state(d),
                        s(d, "title"),
                        &e(&draft_meta(d)),
                        "",
                        "",
                        "a",
                    )
                })
                .collect(),
        ));
    }
    body
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
    Some(format!("{}<h1>{}</h1><div class=\"sub\">{} · drafted by {}</div><div class=\"card receipt-card\"><dl class=\"receipt\">{receipt}</dl><div class=\"summary\"><div class=\"label\">Exact change</div>{change}{test}</div><div class=\"foot\">{acts}{sha}</div></div>",back("/mailbox","Mailbox"),e(s(d,"title")),draft_state(d),e(s(d,"agent"))))
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
fn modes_screen(snapshot: &Value, csrf: &str, writable: bool) -> String {
    let mut body = "<h1>Modes</h1>".to_string();
    if !s(snapshot, "control_error").is_empty() {
        return body
            + &empty(
                "Can't read the fleet file",
                &e(s(snapshot, "control_error")),
            );
    }
    let modes = a(snapshot, "modes");
    if modes.is_empty() {
        return body
            + &empty(
                "Add a fix config to manage modes",
                "Restart the dashboard with --fix-config pointing to your repair config.",
            );
    }
    let can_write = writable && s(snapshot, "fleet_note").is_empty();
    if writable && !s(snapshot, "fleet_note").is_empty() {
        body.push_str(&format!(
            "<div class=\"quiet\">{}</div>",
            e(s(snapshot, "fleet_note"))
        ));
    }
    let fleet = &modes[0];
    body.push_str(&format!("<div class=\"card\"><div class=\"label\">Fleet default</div><div class=\"hero\">{}</div><div class=\"quiet\">{}</div><div class=\"acts\">{}</div></div>",capitalize(s(fleet,"mode")),e(s(fleet,"why")),segmented(fleet,csrf,can_write)));
    for (scope, heading, ic) in [
        ("machine", "Machines", "server"),
        ("agent", "Agents", "bot"),
    ] {
        let rows: Vec<_> = modes.iter().filter(|m| m["scope"] == scope).collect();
        if !rows.is_empty() {
            body.push_str(&format!("<h2>{heading}</h2><div class=\"rows\">"));
            for m in rows {
                body.push_str(&format!("<div class=\"row wrap\"><span class=\"ico\">{}</span><span class=\"body\"><span class=\"title\">{}</span><span class=\"meta\">{}</span></span>{}</div>",icon(ic),e(s(m,"name")),e(s(m,"why")),segmented(m,csrf,can_write)));
            }
            body.push_str("</div>");
        }
    }
    if !a(snapshot, "matrix").is_empty() {
        body.push_str("<h2>Who can change what</h2><div class=\"card\"><div class=\"quiet\">The most an agent may do on each machine</div><div class=\"scroll\"><table class=\"mx\"><tr><th></th>");
        for host in snapshot["known"][0].as_array().into_iter().flatten() {
            body.push_str(&format!(
                "<th scope=\"col\">{}</th>",
                e(host.as_str().unwrap_or(""))
            ));
        }
        body.push_str("</tr>");
        for r in a(snapshot, "matrix") {
            let agent = r[0].as_str().unwrap_or("");
            body.push_str(&format!(
                "<tr><th scope=\"row\">{}</th>",
                e(if agent == "*" { "any other" } else { agent })
            ));
            for cell in r[1].as_array().into_iter().flatten() {
                let word = cell[0].as_str().unwrap_or("");
                let rule = e(cell[1].as_str().unwrap_or(""));
                body.push_str(&format!(
                    "<td class=\"w-{}\" data-tip=\"{rule}\" title=\"{rule}\">{}</td>",
                    word.to_lowercase(),
                    e(word)
                ));
            }
            body.push_str("</tr>");
        }
        body.push_str("</table></div></div>");
    }
    body
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
        "now" => now_screen(snapshot),
        "hosts" => hosts_screen(snapshot),
        "findings" => findings_screen(snapshot, filter, host, ""),
        "finding" => return finding_screen(snapshot, id),
        "fixes" => fixes_screen(snapshot),
        "agents" => agents_screen(snapshot),
        "speed" => speed_screen(snapshot),
        "news" => news_screen(snapshot),
        "mailbox" => mailbox_screen(snapshot),
        "review" => return review_screen(snapshot, id, csrf),
        "modes" => modes_screen(snapshot, csrf, writable),
        "more" => format!(
            "<h1>More</h1><div class=\"rows\">{}</div>",
            NAV.iter()
                .filter(|(k, _, _, _)| !["now", "hosts", "findings", "fixes"].contains(k))
                .map(|(_, href, label, ic)| row(href, ic, "", label, "", "", "", "a"))
                .collect::<String>()
        ),
        _ => return None,
    })
}
