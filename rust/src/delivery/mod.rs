pub mod schedule;
use crate::repair::commands::{execute, strings};
use crate::{store::Store, Error, Result};
use rusqlite::params;
use serde_json::{json, Value};
use std::{io::Read, time::Duration};
#[derive(Default, Clone)]
pub struct Options {
    pub webhook: Option<String>,
    pub ntfy: Option<String>,
    pub desktop: bool,
}
/// A delivery endpoint: an http(s) URL with a host.
pub fn endpoint_url(endpoint: &str) -> Option<url::Url> {
    url::Url::parse(endpoint)
        .ok()
        .filter(|url| ["http", "https"].contains(&url.scheme()) && url.host_str().is_some())
}
pub fn deliver(messages: &[Value], options: &Options) -> Result<()> {
    if messages.is_empty() {
        return Ok(());
    }
    let text = messages
        .iter()
        .filter_map(|m| m["title"].as_str())
        .map(|t| {
            t.replace(
                |c: char| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'),
                " ",
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| Error::new(e.to_string()))?;
    for (endpoint, plain) in [(&options.webhook, false), (&options.ntfy, true)] {
        let Some(endpoint) = endpoint else {
            continue;
        };
        let url = endpoint_url(endpoint)
            .ok_or_else(|| Error::new("delivery requires an explicit owned http(s) endpoint"))?;
        let (body, content) = if plain {
            let mut end = text.len().min(4000);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            (text[..end].to_string(), "text/plain")
        } else {
            (json!({"messages":messages}).to_string(), "application/json")
        };
        let response = client
            .post(url)
            .header("Content-Type", content)
            .body(body)
            .send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| Error::new(e.to_string()))?;
        let mut sink = Vec::new();
        response.take(1024).read_to_end(&mut sink)?;
    }
    if options.desktop {
        let brief = text.chars().take(1000).collect::<String>();
        let notifier = if cfg!(target_os = "macos") {
            Notifier::AppleScript
        } else if cfg!(windows) {
            Notifier::PowerShell("powershell.exe")
        } else if std::path::Path::new(WSL_POWERSHELL).exists() {
            Notifier::PowerShell(WSL_POWERSHELL)
        } else if std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|p| p.join("notify-send").is_file())
        {
            Notifier::NotifySend
        } else {
            Notifier::Gdbus
        };
        let (argv, input) = desktop_command(notifier, &brief);
        execute(&argv, None, input.as_deref(), true)?;
    }
    Ok(())
}
const WSL_POWERSHELL: &str = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";
/// A desktop notifier this machine offers.
#[derive(Clone, Copy)]
enum Notifier {
    AppleScript,
    PowerShell(&'static str),
    NotifySend,
    Gdbus,
}
/// Shows the alert it reads as UTF-8 on stdin. The alert never appears in the script text, so no
/// quote or substitution in it can reach the PowerShell parser.
const POWERSHELL_ALERT: &str = "$m=New-Object System.IO.MemoryStream; [Console]::OpenStandardInput().CopyTo($m); $t=[System.Text.Encoding]::UTF8.GetString($m.ToArray()); Add-Type -AssemblyName System.Windows.Forms; $n=New-Object System.Windows.Forms.NotifyIcon; $n.Icon=[System.Drawing.SystemIcons]::Warning; $n.Visible=$true; $n.ShowBalloonTip(10000,'vorda',$t,[System.Windows.Forms.ToolTipIcon]::Warning)";
/// The process that shows `brief`: its argument vector and the text it reads on stdin.
/// No shell runs it. Control characters other than the line break between alerts become
/// spaces, and the text never starts with `-`, so no notifier reads it as an option.
fn desktop_command(notifier: Notifier, brief: &str) -> (Vec<String>, Option<String>) {
    let mut text: String = brief
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    if text.starts_with('-') {
        text.insert(0, ' ');
    }
    match notifier {
        Notifier::AppleScript => (
            strings(&[
                "osascript",
                "-e",
                "on run argv",
                "-e",
                "display notification (item 1 of argv) with title \"vorda\"",
                "-e",
                "end run",
                &text,
            ]),
            None,
        ),
        Notifier::PowerShell(exe) => (
            strings(&[
                exe,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                POWERSHELL_ALERT,
            ]),
            Some(text),
        ),
        Notifier::NotifySend => (strings(&["notify-send", "--", "vorda", &text]), None),
        Notifier::Gdbus => (
            strings(&[
                "gdbus",
                "call",
                "--session",
                "--dest",
                "org.freedesktop.Notifications",
                "--object-path",
                "/org/freedesktop/Notifications",
                "--method",
                "org.freedesktop.Notifications.Notify",
                "vorda",
                "0",
                "",
                "vorda",
                &text,
                "[]",
                "{}",
                "10000",
            ]),
            None,
        ),
    }
}
/// `outbox.delivered` value for a row that will not be retried; attempts and
/// last_error stay for inspection.
const ABANDONED: i64 = -1;
/// A row stops retrying after this many failed attempts.
const GIVE_UP_ATTEMPTS: i64 = 24;
/// A channel this run does not use is quiet after a week without an attempt.
const IDLE_SECONDS: f64 = 7.0 * 86400.0;
fn endpoints(options: &Options) -> [(&'static str, Option<Value>); 3] {
    [
        ("webhook", options.webhook.as_ref().map(|s| json!(s))),
        ("ntfy", options.ntfy.as_ref().map(|s| json!(s))),
        ("desktop", options.desktop.then(|| json!(true))),
    ]
}
pub fn channel_keys(options: &Options) -> Result<Vec<String>> {
    endpoints(options)
        .into_iter()
        .filter_map(|(channel, endpoint)| {
            endpoint.map(|e| crate::store::identity(&json!([channel, e])))
        })
        .collect()
}
/// Closes the delivery-health finding of every channel with nothing left to retry,
/// and of every channel outside `current` (the channels this run delivers to) that
/// has had no attempt for a week. Queued rows are never changed: they send the next
/// time the channel is used, and a new failure raises the finding again. The caller
/// holds the scan lock.
pub fn expire(store: &mut Store, current: &[String]) -> Result<()> {
    let active = store.active()?;
    let mut settled = std::collections::BTreeSet::new();
    for finding in &active {
        let Some(key) = finding.get("key").and_then(Value::as_str) else {
            continue;
        };
        let Some(channel) = key.strip_prefix("health:delivery:") else {
            continue;
        };
        let in_use = current.iter().any(|c| c == channel);
        let live: i64 = store.db.query_row(
            "SELECT COUNT(*) FROM outbox o JOIN messages m ON m.id=o.message WHERE o.channel=?1 AND o.delivered=0 AND (?2 OR MAX(o.next_attempt,m.created)>=?3)",
            params![channel, in_use, crate::store::now() - IDLE_SECONDS],
            |r| r.get(0),
        )?;
        if live == 0 {
            settled.insert(key.to_string());
        }
    }
    if settled.is_empty() {
        return Ok(());
    }
    let remaining: Vec<_> = active
        .into_iter()
        .filter(|f| {
            !f.get("key")
                .and_then(Value::as_str)
                .is_some_and(|k| settled.contains(k))
        })
        .collect();
    store.reconcile(&remaining, &settled, &[])?;
    Ok(())
}
pub fn drain(store: &mut Store, options: &Options) -> Result<Value> {
    let _lock = store.locked()?;
    let mut errors = Vec::new();
    for (channel, endpoint) in endpoints(options) {
        let Some(endpoint) = endpoint else {
            continue;
        };
        let key = crate::store::identity(&json!([channel, endpoint]))?;
        let rows:Vec<(i64,i64,String,String)>=store.db.prepare("SELECT o.message,o.attempts,m.payload,m.kind FROM outbox o JOIN messages m ON m.id=o.message WHERE o.channel=? AND delivered=0 AND next_attempt<=? ORDER BY message LIMIT 50")?.query_map(params![key,crate::store::now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?.collect::<std::result::Result<_,_>>()?;
        let mut size = 0;
        let mut selected = Vec::new();
        let mut messages = Vec::new();
        for row in rows {
            let mut message: Value = serde_json::from_str(&row.2)?;
            let n = message["title"].as_str().unwrap_or("").len() + 1;
            if channel == "ntfy" && !messages.is_empty() && size + n > 4000 {
                break;
            }
            size += n;
            message["id"] = json!(row.0);
            message["kind"] = json!(row.3);
            messages.push(message);
            selected.push(row);
        }
        if messages.is_empty() {
            continue;
        }
        let mut opt = Options::default();
        match channel {
            "webhook" => opt.webhook = options.webhook.clone(),
            "ntfy" => opt.ntfy = options.ntfy.clone(),
            _ => opt.desktop = true,
        };
        let health_key = format!("health:delivery:{key}");
        let mut active: Vec<crate::domain::Record> = store
            .db
            .prepare("SELECT payload FROM findings WHERE active=1")?
            .query_map([], |r| r.get::<_, String>(0))?
            .map(|r| -> Result<crate::domain::Record> { Ok(serde_json::from_str(&r?)?) })
            .collect::<Result<_>>()?;
        active.retain(|r| r.get("key").and_then(Value::as_str) != Some(&health_key));
        match deliver(&messages, &opt) {
            Ok(()) => {
                for row in selected {
                    store.db.execute("UPDATE outbox SET delivered=1,last_error=NULL WHERE channel=? AND message=?",params![key,row.0])?;
                }
                store.reconcile(&active, &[health_key].into_iter().collect(), &[])?;
            }
            Err(e) => {
                errors.push(json!({"channel":channel,"error":e.to_string()}));
                for row in selected {
                    let attempts = row.1.saturating_add(1);
                    let delivered = if attempts >= GIVE_UP_ATTEMPTS {
                        ABANDONED
                    } else {
                        0
                    };
                    store.db.execute("UPDATE outbox SET attempts=?,last_error=?,next_attempt=?,delivered=? WHERE channel=? AND message=?",params![attempts,e.to_string(),crate::store::now()+(1u64<<attempts.min(10)) as f64,delivered,key,row.0])?;
                }
                active.push(json!({"key":health_key,"asset":health_key,"kind":"health","title":format!("Delivery unavailable: {channel}"),"error":e.to_string()}).as_object().unwrap().clone());
                store.reconcile(&active, &Default::default(), &[])?;
            }
        }
    }
    Ok(json!(errors))
}
#[cfg(test)]
mod tests {
    use super::{desktop_command, Notifier};

    /// Alert titles a scanned lockfile can make Vorda show: quotes of both kinds, PowerShell and
    /// shell substitutions, separators, line breaks, control characters and a leading dash.
    const HOSTILE: [&str; 8] = [
        "minimist 0\u{2019}+$(exit 77)+\u{2019}: advisory",
        "it's \"quoted\" `whoami` $(id) ; echo done",
        "'); Start-Process calc; ('",
        "-v leading dash",
        "--help",
        "first alert\nsecond alert",
        "tab\there\u{7}bell\r\nend\u{1b}[0m",
        "\u{201c}curly\u{201d} \u{2018}single\u{2019} & | > < %TEMP% ${env:PATH}",
    ];

    /// The text the notifier is given: control characters other than the line break between
    /// alerts become spaces, and it never starts with `-`, so no notifier reads it as an option.
    fn shown(text: &str) -> String {
        let clean: String = text
            .chars()
            .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
            .collect();
        if clean.starts_with('-') {
            format!(" {clean}")
        } else {
            clean
        }
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn powershell_reads_the_alert_on_stdin_and_never_in_its_script() {
        for exe in [
            "powershell.exe",
            "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
        ] {
            let (benign, _) = desktop_command(Notifier::PowerShell(exe), "plain alert");
            assert_eq!(
                benign[..4],
                argv(&[exe, "-NoProfile", "-NonInteractive", "-Command"])
            );
            assert_eq!(benign.len(), 5);
            for text in HOSTILE {
                let (command, input) = desktop_command(Notifier::PowerShell(exe), text);
                assert_eq!(command, benign, "script changed with alert {text:?}");
                assert_eq!(input, Some(shown(text)));
            }
        }
    }

    #[test]
    fn osascript_takes_the_alert_as_a_run_argument() {
        for text in HOSTILE {
            assert_eq!(
                desktop_command(Notifier::AppleScript, text),
                (
                    argv(&[
                        "osascript",
                        "-e",
                        "on run argv",
                        "-e",
                        "display notification (item 1 of argv) with title \"vorda\"",
                        "-e",
                        "end run",
                        &shown(text),
                    ]),
                    None
                )
            );
        }
    }

    #[test]
    fn notify_send_takes_the_alert_after_the_end_of_options() {
        for text in HOSTILE {
            assert_eq!(
                desktop_command(Notifier::NotifySend, text),
                (argv(&["notify-send", "--", "vorda", &shown(text)]), None)
            );
        }
    }

    #[test]
    fn gdbus_takes_the_alert_as_one_argument() {
        for text in HOSTILE {
            assert_eq!(
                desktop_command(Notifier::Gdbus, text),
                (
                    argv(&[
                        "gdbus",
                        "call",
                        "--session",
                        "--dest",
                        "org.freedesktop.Notifications",
                        "--object-path",
                        "/org/freedesktop/Notifications",
                        "--method",
                        "org.freedesktop.Notifications.Notify",
                        "vorda",
                        "0",
                        "",
                        "vorda",
                        &shown(text),
                        "[]",
                        "{}",
                        "10000",
                    ]),
                    None
                )
            );
        }
    }
}
