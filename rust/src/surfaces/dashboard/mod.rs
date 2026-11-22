pub mod control;
pub mod data;
pub mod english;
pub mod feed;
pub mod views;
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{IpAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().to_vec()
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn equal(a: &str, b: &str) -> bool {
    let mut m = Hmac::<Sha256>::new_from_slice(b"vorda-constant-comparison").unwrap();
    m.update(a.as_bytes());
    m.verify_slice(&mac(b"vorda-constant-comparison", b.as_bytes()))
        .is_ok()
}
fn random() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}
pub struct App {
    pub state: PathBuf,
    pub bind: String,
    pub port: u16,
    pub token: String,
    pub writable: bool,
    pub fix_config: Option<PathBuf>,
    secret: String,
}
pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
impl Response {
    fn new(status: u16, body: impl Into<Vec<u8>>, nonce: &str) -> Self {
        let body = body.into();
        Self{status,headers:BTreeMap::from([("Content-Type".into(),"text/html; charset=utf-8".into()),("Content-Length".into(),body.len().to_string()),("Cache-Control".into(),"no-store".into()),("Content-Security-Policy".into(),format!("default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; img-src data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")),("X-Content-Type-Options".into(),"nosniff".into()),("Referrer-Policy".into(),"no-referrer".into()),("X-Frame-Options".into(),"DENY".into()),("Cross-Origin-Resource-Policy".into(),"same-origin".into())]),body}
    }
    fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.insert(k.into(), v.into());
        self
    }
}
impl App {
    pub fn new(
        state: &Path,
        bind: &str,
        port: u16,
        token: String,
        writable: bool,
        fix_config: Option<&Path>,
    ) -> Result<Self> {
        let address = bind.parse::<IpAddr>().ok();
        if bind != "localhost" && address.is_none() {
            return Err(Error::usage(format!(
                "--bind must be an IP address or localhost, not {bind:?}"
            )));
        }
        let loopback = bind == "localhost" || address.is_some_and(|a| a.is_loopback());
        if !loopback && token.is_empty() {
            return Err(Error::usage("--bind beyond loopback needs --token"));
        }
        if writable && token.is_empty() {
            return Err(Error::usage("--allow-writes needs --token"));
        }
        Ok(Self {
            state: state.into(),
            bind: bind.into(),
            port,
            token,
            writable,
            fix_config: fix_config.map(Into::into),
            secret: random(),
        })
    }
    pub fn session(&self) -> String {
        hex(&mac(self.token.as_bytes(), b"vorda-dashboard-session"))
    }
    pub fn csrf(&self, session: &str) -> String {
        hex(&mac(
            self.secret.as_bytes(),
            format!("csrf:{session}").as_bytes(),
        ))
    }
    fn hosts(&self) -> BTreeSet<String> {
        let bind = if self.bind.contains(':') {
            format!("[{}]", self.bind)
        } else {
            self.bind.clone()
        };
        [bind, "localhost".into(), "127.0.0.1".into(), "[::1]".into()]
            .into_iter()
            .flat_map(|h| [h.clone(), format!("{h}:{}", self.port)])
            .collect()
    }
    fn authenticated(&self, request: &Request) -> Option<String> {
        if self.token.is_empty() {
            return self
                .hosts()
                .contains(
                    request
                        .headers
                        .get("host")
                        .map(String::as_str)
                        .unwrap_or(""),
                )
                .then(|| "local".into());
        }
        let cookie = request
            .headers
            .get("cookie")
            .map(String::as_str)
            .unwrap_or("")
            .split(';')
            .filter_map(|s| s.trim().split_once('='))
            .find(|(k, _)| *k == "vorda")
            .map(|(_, v)| v)
            .unwrap_or("");
        equal(cookie, &self.session()).then(|| cookie.into())
    }
    pub fn read(&self, scopes: Option<&BTreeSet<String>>) -> Result<Value> {
        let mut snapshot = data::snapshot(&self.state, crate::store::now(), scopes)?;
        control::augment(
            &mut snapshot,
            &self.state,
            self.fix_config.as_deref(),
            self.writable,
        )?;
        Ok(snapshot)
    }
    pub fn handle(&self, request: &Request) -> Response {
        let nonce = random();
        let parsed = url::Url::parse(&format!("http://local{}", request.target));
        let Ok(url) = parsed else {
            return Response::new(400, "Bad request", &nonce);
        };
        // The parsed path is checked too: the URL parser reads `\` as `/` and drops tabs,
        // so `/\host` becomes `//host`, which the token login would echo as a redirect.
        if !request.target.starts_with('/')
            || request.target.starts_with("//")
            || url.path().starts_with("//")
        {
            return Response::new(400, "Bad request", &nonce);
        }
        let mut query: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in url.query_pairs() {
            query
                .entry(k.into_owned())
                .or_default()
                .push(v.into_owned());
        }
        let path = url.path().trim_end_matches('/');
        let path = if path.is_empty() { "/" } else { path };
        let get = |k: &str| {
            query
                .get(k)
                .and_then(|v| v.first())
                .map(String::as_str)
                .unwrap_or("")
        };
        if ["GET", "HEAD"].contains(&request.method.as_str())
            && !self.token.is_empty()
            && query.contains_key("token")
            && equal(get("token"), &self.token)
        {
            let rest = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(
                    query
                        .iter()
                        .filter(|(k, _)| k.as_str() != "token")
                        .flat_map(|(k, values)| values.iter().map(move |v| (k, v))),
                )
                .finish();
            return Response::new(303, Vec::new(), &nonce)
                .header(
                    "Location",
                    format!(
                        "{}{}",
                        url.path(),
                        if rest.is_empty() {
                            String::new()
                        } else {
                            format!("?{rest}")
                        }
                    ),
                )
                .header(
                    "Set-Cookie",
                    format!(
                        "vorda={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000",
                        self.session()
                    ),
                );
        }
        let Some(session) = self.authenticated(request) else {
            return Response::new(403, "Forbidden", &nonce);
        };
        if request.method == "POST" {
            if !self.writable || !["/review", "/mode", "/repair"].contains(&path) {
                return Response::new(403, "Read-only", &nonce);
            }
            if let Some(origin) = request.headers.get("origin") {
                let valid = url::Url::parse(origin).is_ok_and(|o| {
                    let authority = &o[url::Position::BeforeHost..url::Position::AfterPort];
                    Some(authority) == request.headers.get("host").map(String::as_str)
                });
                if !valid {
                    return Response::new(403, "Bad origin", &nonce);
                }
            }
            if request.body.len() > 4096 {
                return Response::new(400, "Bad request", &nonce);
            }
            let mut form = json!({});
            for (k, v) in url::form_urlencoded::parse(&request.body) {
                if form.get(k.as_ref()).is_none() {
                    form[k.as_ref()] = json!(v);
                }
            }
            if !equal(form["csrf"].as_str().unwrap_or(""), &self.csrf(&session)) {
                return Response::new(403, "Bad CSRF token", &nonce);
            }
            return match control::write(&self.state, self.fix_config.as_deref(), path, &form) {
                Ok(location) => Response::new(303, Vec::new(), &nonce).header("Location", location),
                Err(e) => {
                    let screen = if path == "/mode" { "modes" } else { "mailbox" };
                    let body = format!(
                        "<h1>Not done</h1>{}",
                        views::empty(
                            &e.to_string(),
                            &format!("<a href=\"/{screen}\">Go back</a>")
                        )
                    );
                    Response::new(409, views::page(screen, "Not done", &body, &nonce), &nonce)
                }
            };
        }
        if !["GET", "HEAD"].contains(&request.method.as_str()) {
            return Response::new(405, "Method not allowed", &nonce);
        }
        if path.starts_with("/fonts/") {
            let data: Option<&[u8]> = match path {
                "/fonts/vorda-sans.woff2" => Some(include_bytes!("vorda-sans.woff2")),
                "/fonts/geist-mono.woff2" => Some(include_bytes!("geist-mono.woff2")),
                _ => None,
            };
            return if let Some(data) = data {
                Response::new(200, data.to_vec(), &nonce)
                    .header("Content-Type", "font/woff2")
                    .header("Cache-Control", "public, max-age=31536000, immutable")
            } else {
                Response::new(404, "Not found", &nonce)
            };
        }
        let scopes = query
            .get("scope")
            .map(|v| v.iter().cloned().collect::<BTreeSet<_>>());
        let snapshot = match self.read(scopes.as_ref()) {
            Ok(s) => s,
            Err(_) => {
                let exists = self.state.join("mail.db").exists();
                let body = format!(
                    "<h1>Now</h1>{}",
                    views::empty(
                        if exists {
                            "Can't read the mailbox"
                        } else {
                            "No mailbox yet"
                        },
                        &if exists {
                            views::e(&self.state.to_string_lossy())
                        } else {
                            views::copy_cmd("vorda check")
                        }
                    )
                );
                return Response::new(200, views::page("now", "Now", &body, &nonce), &nonce);
            }
        };
        if path == "/api/assets" {
            return Response::new(200, snapshot["assets"].to_string(), &nonce)
                .header("Content-Type", "application/json");
        }
        let (screen, title, id) = match path {
            "/" => ("now", "Now", ""),
            "/hosts" => ("hosts", "Hosts", ""),
            "/findings" => ("findings", "Findings", ""),
            "/fixes" => ("fixes", "Fixes", ""),
            "/agents" => ("agents", "Agent tools", ""),
            "/speed" => ("speed", "Speed", ""),
            "/news" => ("news", "News", ""),
            "/mailbox" => ("mailbox", "Mailbox", ""),
            "/modes" => ("modes", "Modes", ""),
            "/more" => ("more", "More", ""),
            p if p.starts_with("/finding/") => ("finding", "Finding", &p[9..]),
            p if p.starts_with("/review/") => ("review", "Review", &p[8..]),
            _ => return Response::new(404, "Not found", &nonce),
        };
        let filter = if ["all", "kev", "browser", "os", "library", "agent"].contains(&get("f")) {
            get("f")
        } else {
            "all"
        };
        let body = if screen == "findings" && !get("project").is_empty() {
            Some(views::findings_screen(
                &snapshot,
                filter,
                get("host"),
                get("project"),
            ))
        } else {
            views::render(
                &snapshot,
                screen,
                id,
                filter,
                get("host"),
                &self.csrf(&session),
                self.writable,
            )
        };
        let status = if body.is_some() { 200 } else { 404 };
        let body = body.unwrap_or_else(|| views::missing(screen));
        let active = match screen {
            "finding" => "findings",
            "review" => "mailbox",
            s => s,
        };
        let mut html = views::page(active, title, &body, &nonce);
        if let Some(scopes) = scopes {
            let selection = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(scopes.iter().map(|v| ("scope", v)))
                .finish();
            let re = regex::Regex::new(r#"(<a[^>]* href=")(/[^"]*)"#).unwrap();
            html = re
                .replace_all(&html, |c: &regex::Captures| {
                    if c[2].starts_with("//") {
                        return c[0].to_string();
                    }
                    format!(
                        "{}{}{}{}",
                        &c[1],
                        &c[2],
                        if c[2].contains('?') { "&amp;" } else { "?" },
                        views::e(&selection)
                    )
                })
                .into_owned();
        }
        Response::new(status, html, &nonce)
    }
}
fn request(stream: &mut TcpStream) -> Result<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            return Err(Error::new("incomplete request"));
        }
        bytes.push(byte[0]);
        if bytes.len() > 32768 {
            return Err(Error::new("headers are too large"));
        }
    }
    let header = std::str::from_utf8(&bytes).map_err(|_| Error::new("invalid headers"))?;
    let mut lines = header.split("\r\n");
    let line = lines.next().unwrap();
    let words: Vec<_> = line.split(' ').collect();
    if words.len() != 3 || !["HTTP/1.0", "HTTP/1.1"].contains(&words[2]) {
        return Err(Error::new("invalid request line"));
    }
    let mut headers = BTreeMap::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| Error::new("invalid header"))?;
        if k.is_empty()
            || !k
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
            || v.bytes().any(|c| c < 32 && c != b'\t')
        {
            return Err(Error::new("invalid header"));
        }
        if headers
            .insert(k.to_ascii_lowercase(), v.trim().to_string())
            .is_some()
        {
            return Err(Error::new("duplicate header"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(Error::new("transfer encoding is unsupported"));
    }
    let size = headers
        .get("content-length")
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|_| Error::new("invalid Content-Length"))?
        .unwrap_or(0);
    if size > 4096 {
        return Err(Error::new("body is too large"));
    }
    let mut body = vec![0; size];
    stream.read_exact(&mut body)?;
    Ok(Request {
        method: words[0].into(),
        target: words[1].into(),
        headers,
        body,
    })
}
fn respond(stream: &mut TcpStream, response: Response, head: bool) -> Result<()> {
    let reason = match response.status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        _ => "Service Unavailable",
    };
    write!(
        stream,
        "HTTP/1.1 {} {reason}\r\nConnection: close\r\n",
        response.status
    )?;
    for (k, v) in response.headers {
        write!(stream, "{k}: {v}\r\n")?;
    }
    write!(stream, "\r\n")?;
    if !head {
        stream.write_all(&response.body)?;
    }
    Ok(())
}
pub fn serve(
    state: &Path,
    bind: &str,
    port: u16,
    token: bool,
    writable: bool,
    config: Option<&Path>,
) -> Result<()> {
    let secret = if token || writable {
        std::env::var("VORDA_DASHBOARD_TOKEN")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(random)
    } else {
        String::new()
    };
    let mut app = App::new(state, bind, port, secret, writable, config)?;
    let listener = TcpListener::bind((bind, port)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            Error::new(format!(
                "port {port} is busy; run vorda dashboard --port 0 to use a free port"
            ))
        } else {
            e.into()
        }
    })?;
    app.port = listener.local_addr()?.port();
    let host = if bind.contains(':') {
        format!("[{bind}]")
    } else {
        bind.into()
    };
    println!(
        "http://{host}:{}/{}",
        app.port,
        if app.token.is_empty() {
            String::new()
        } else {
            format!("?token={}", app.token)
        }
    );
    std::io::stdout().flush()?;
    let app = Arc::new(app);
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut stream = stream?;
        if active.fetch_add(1, Ordering::SeqCst) >= 32 {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = respond(&mut stream, Response::new(503, "Busy", "x"), false);
            continue;
        }
        let (app, active) = (Arc::clone(&app), Arc::clone(&active));
        std::thread::spawn(move || {
            let response = request(&mut stream);
            match response {
                Ok(request) => {
                    let head = request.method == "HEAD";
                    let response = app.handle(&request);
                    let _ = respond(&mut stream, response, head);
                }
                Err(_) => {
                    let _ = respond(&mut stream, Response::new(400, "Bad request", "x"), false);
                }
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}
