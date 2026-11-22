use super::storage::Hub;
use super::{encode, exact_fields, MAX_BATCH};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

struct DeadlineStream {
    stream: std::net::TcpStream,
    deadline: Instant,
    read_failed: bool,
}
impl DeadlineStream {
    fn allow_reply(&mut self) {
        // Processing may consume the receive deadline. A completed answer still gets the
        // same bounded 225 ms available to a busy refusal; writes cannot renew this grace.
        // A timed-out/incomplete request must not gain a new write budget.
        if !self.read_failed {
            self.deadline = self
                .deadline
                .max(Instant::now() + Duration::from_millis(225));
        }
    }
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline exceeded")
            })
    }
}
impl Drop for DeadlineStream {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let result = (|| {
            self.stream.set_read_timeout(Some(self.remaining()?))?;
            self.stream.read(bytes)
        })();
        self.read_failed |= result.is_err();
        result
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

pub struct Server {
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    hub: Hub,
}
impl Server {
    pub fn bind(
        hub: Hub,
        bind: &str,
        port: u16,
        certificate: Option<&Path>,
        key: Option<&Path>,
    ) -> Result<Self> {
        if certificate.is_some() != key.is_some() {
            return Err(Error::new("certificate and key must be supplied together"));
        }
        if certificate.is_none() && !["127.0.0.1", "localhost"].contains(&bind) {
            return Err(Error::new("non-loopback listeners require TLS"));
        }
        let tls = match (certificate, key) {
            (Some(cert), Some(key)) => {
                use rustls::pki_types::{pem, pem::PemObject, CertificateDer, PrivateKeyDer};
                let certs = CertificateDer::pem_reader_iter(std::fs::File::open(cert)?)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| Error::new(e.to_string()))?;
                let key = PrivateKeyDer::from_pem_reader(std::fs::File::open(key)?).map_err(
                    |e| match e {
                        pem::Error::NoItemsFound => Error::new("private key missing"),
                        e => Error::new(e.to_string()),
                    },
                )?;
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|e| Error::new(e.to_string()))?
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| Error::new(e.to_string()))?;
                Some(Arc::new(config))
            }
            _ => None,
        };
        Ok(Self {
            listener: TcpListener::bind((bind, port))?,
            tls,
            hub,
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    pub fn serve_bounded(
        &self,
        admission: &super::native::Admission,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        self.same_hub(admission)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::listen(self.listener.as_raw_fd(), 8) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        self.listener.set_nonblocking(true)?;
        let result = std::thread::scope(|scope| -> Result<()> {
            let mut active: Option<std::thread::ScopedJoinHandle<'_, ()>> = None;
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                if active.as_ref().is_some_and(|h| h.is_finished()) {
                    active
                        .take()
                        .unwrap()
                        .join()
                        .map_err(|_| Error::new("worker failed"))?;
                }
                let stream = match self.listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                let accepted = Instant::now();
                if active.is_some() {
                    let _ = self.bounded_connection(stream, accepted, true, admission);
                } else {
                    active = Some(scope.spawn(move || {
                        let _ = self.bounded_connection(stream, accepted, false, admission);
                    }));
                }
            }
            if let Some(h) = active {
                h.join().map_err(|_| Error::new("worker failed"))?;
            }
            Ok(())
        });
        self.listener.set_nonblocking(false)?;
        result
    }
    fn same_hub(&self, admission: &super::native::Admission) -> Result<()> {
        if self.hub.database.path.canonicalize()? != admission.path().canonicalize()? {
            return Err(Error::new("admission must address the same hub"));
        }
        Ok(())
    }
    fn bounded_connection(
        &self,
        stream: std::net::TcpStream,
        accepted: Instant,
        busy: bool,
        admission: &super::native::Admission,
    ) -> Result<()> {
        stream.set_nonblocking(false)?;
        let deadline = accepted + Duration::from_millis(if busy { 225 } else { 4975 });
        let mut stream = DeadlineStream {
            stream,
            deadline,
            read_failed: false,
        };
        if let Some(config) = &self.tls {
            let handshake_deadline = accepted + Duration::from_millis(950);
            stream.deadline = deadline.min(handshake_deadline);
            let mut connection = rustls::ServerConnection::new(config.clone())
                .map_err(|e| Error::new(e.to_string()))?;
            while connection.is_handshaking() {
                connection.complete_io(&mut stream)?;
            }
            if Instant::now() >= handshake_deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "request deadline exceeded",
                )
                .into());
            }
            stream.deadline = deadline;
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let result = self.bounded_respond(&mut stream, busy, admission, deadline);
            stream.conn.send_close_notify();
            let _ = stream.flush();
            let _ = stream.sock.stream.shutdown(std::net::Shutdown::Write);
            result
        } else {
            let result = self.bounded_respond(&mut stream, busy, admission, deadline);
            let _ = stream.stream.shutdown(std::net::Shutdown::Write);
            result
        }
    }
    fn bounded_respond<S: Read + Write>(
        &self,
        stream: S,
        busy: bool,
        admission: &super::native::Admission,
        deadline: Instant,
    ) -> Result<()> {
        let mut stream = BufReader::new(stream);
        let mut v2 = false;
        let result = if busy {
            Err(Error::rejected(503, "busy"))
        } else {
            self.handle_with_admission(&mut stream, admission, deadline, &mut v2)
        };
        self.write_response(&mut stream, result, v2)
    }
    fn handle_with_admission<S: Read + Write>(
        &self,
        stream: &mut BufReader<S>,
        admission: &super::native::Admission,
        deadline: Instant,
        v2_target: &mut bool,
    ) -> Result<Vec<u8>> {
        let mut first = [0; 1026];
        let mut bytes = 0;
        let mut previous = 0;
        let mut utf8 = [0; 4];
        let mut utf8_len = 0;
        let mut tokens = 0usize;
        let mut in_token = false;
        let mut token_len = 0usize;
        let mut method = [0; 4];
        let mut route = [0; 11];
        let mut route_len = 0;
        let mut v2 = false;
        loop {
            let mut byte = [0];
            stream
                .read_exact(&mut byte)
                .map_err(|_| Error::rejected(400, "invalid HTTP headers"))?;
            let byte = byte[0];
            bytes += 1;
            if bytes <= first.len() {
                first[bytes - 1] = byte;
            }
            utf8[utf8_len] = byte;
            utf8_len += 1;
            match std::str::from_utf8(&utf8[..utf8_len]) {
                Ok(text) => {
                    let c = text.chars().next().unwrap();
                    if c.is_whitespace() {
                        in_token = false;
                    } else {
                        if !in_token {
                            tokens = (tokens + 1).min(4);
                            token_len = 0;
                            in_token = true;
                        }
                        for &b in &utf8[..utf8_len] {
                            if tokens == 1 && token_len < method.len() {
                                method[token_len] = b;
                            }
                            if tokens == 2 && token_len < route.len() {
                                route[token_len] = b;
                            }
                            token_len = (token_len + 1).min(12);
                        }
                        if tokens == 1 && token_len > 4 {
                            method[0] = 0;
                        }
                        if tokens == 2 {
                            route_len = token_len;
                            v2 |= route_len >= 4 && route[..4] == *b"/v2/";
                            *v2_target = v2;
                        }
                    }
                    utf8_len = 0;
                }
                Err(e) if e.error_len().is_none() && utf8_len < 4 => {}
                Err(_) => return Err(Error::rejected(400, "invalid HTTP headers")),
            }
            let content_len = bytes
                - if byte == b'\n' {
                    if previous == b'\r' {
                        2
                    } else {
                        1
                    }
                } else if byte == b'\r' {
                    1
                } else {
                    0
                };
            if v2 && content_len > 1024 {
                return Err(Error::rejected(413, "request_line_limit"));
            }
            if byte == b'\n' {
                break;
            }
            if bytes >= 65536 {
                return Err(Error::rejected(400, "invalid HTTP headers"));
            }
            previous = byte;
        }
        if !v2 {
            if tokens != 3 || method != *b"POST" {
                return Err(Error::rejected(501, "unsupported method"));
            }
            let route = match &route[..route_len.min(route.len())] {
                b"/v1/enroll" if route_len == 10 => "/v1/enroll",
                b"/v1/batches" if route_len == 11 => "/v1/batches",
                _ => return Err(Error::rejected(404, "unknown route")),
            };
            return self.handle_v1(stream, route);
        }
        if !first[..bytes].ends_with(b"\r\n") {
            return Err(Error::rejected(400, "invalid_request_line"));
        }
        let mut headers = [0; 8192];
        headers[..bytes].copy_from_slice(&first[..bytes]);
        let mut used = bytes;
        let mut line_start = used;
        let mut count = 0;
        loop {
            let mut byte = [0];
            stream
                .read_exact(&mut byte)
                .map_err(|_| Error::rejected(400, "headers_incomplete"))?;
            let byte = byte[0];
            let line_len = used - line_start;
            if used == headers.len()
                || (count == 32 && line_len == 0 && byte != b'\r')
                || (line_len >= 2048 && byte != b'\r' && byte != b'\n')
                || line_len >= 2050
            {
                return Err(Error::rejected(413, "header_limit"));
            }
            headers[used] = byte;
            used += 1;
            if byte == b'\n' {
                if used < 2 || headers[used - 2] != b'\r' {
                    return Err(Error::rejected(400, "invalid_header"));
                }
                if used - line_start == 2 {
                    break;
                }
                count += 1;
                if count > 32 {
                    return Err(Error::rejected(413, "header_limit"));
                }
                line_start = used;
            }
        }
        let (route, size, credential) = super::native_http::header_route(&headers[..used - 4])?;
        let mut body = vec![0; size];
        stream
            .read_exact(&mut body)
            .map_err(|_| Error::rejected(400, "truncated_request"))?;
        let complete = Instant::now().min(deadline - Duration::from_millis(1000));
        if !stream.buffer().is_empty() {
            return Err(Error::rejected(400, "body_length"));
        }
        match route {
            super::native_http::Route::Batches => {
                admission.admit_authenticated(&body, credential, complete)
            }
            super::native_http::Route::Read(name) => {
                crate::fleet::http::handle(&self.hub, name, credential, &body)
            }
        }
    }
    pub fn serve_once(&self) -> Result<()> {
        self.serve_connection(None)
    }
    pub fn serve(&self) -> Result<()> {
        loop {
            let _ = self.serve_once();
        }
    }
    pub fn serve_once_with_admission(&self, admission: &super::native::Admission) -> Result<()> {
        self.same_hub(admission)?;
        self.serve_connection(Some(admission))
    }
    pub fn serve_with_admission(&self, admission: &super::native::Admission) -> Result<()> {
        self.same_hub(admission)?;
        loop {
            let _ = self.serve_connection(Some(admission));
        }
    }
    fn serve_connection(&self, admission: Option<&super::native::Admission>) -> Result<()> {
        let (stream, _) = self.listener.accept()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = DeadlineStream {
            stream,
            deadline,
            read_failed: false,
        };
        if let Some(config) = &self.tls {
            let connection = rustls::ServerConnection::new(config.clone())
                .map_err(|e| Error::new(e.to_string()))?;
            self.respond(
                rustls::StreamOwned::new(connection, stream),
                admission,
                deadline,
                |stream| stream.sock.allow_reply(),
            )
        } else {
            self.respond(stream, admission, deadline, DeadlineStream::allow_reply)
        }
    }
    fn respond<S: Read + Write>(
        &self,
        stream: S,
        admission: Option<&super::native::Admission>,
        deadline: Instant,
        prepare_reply: impl FnOnce(&mut S),
    ) -> Result<()> {
        let mut stream = BufReader::new(stream);
        let mut v2 = false;
        let response = match admission {
            Some(admission) => {
                self.handle_with_admission(&mut stream, admission, deadline, &mut v2)
            }
            None => self.handle(&mut stream),
        };
        prepare_reply(stream.get_mut());
        self.write_response(&mut stream, response, v2)
    }
    fn write_response<S: Read + Write>(
        &self,
        stream: &mut BufReader<S>,
        response: Result<Vec<u8>>,
        v2: bool,
    ) -> Result<()> {
        let (status, body) = match response {
            Ok(raw) => (200, raw),
            Err(error) => {
                let status =
                    error
                        .http_status
                        .unwrap_or(if error.class == "Error" { 503 } else { 400 });
                let message = if status == 503 {
                    "storage unavailable; retry later"
                } else if error.http_status.is_none() {
                    "invalid JSON request"
                } else {
                    &error.message
                };
                (status, encode(&json!({"error":message}))?)
            }
        };
        let retry = if status == 503 {
            "Retry-After: 5\r\n"
        } else {
            ""
        };
        // Answers to /v2/ requests are for one reader: no cache keeps them, no sniffing retypes them.
        let hardening = if v2 {
            "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
        } else {
            ""
        };
        if status != 200 && body.len() > 4096 {
            return Err(Error::new("error response too large"));
        }
        let mut response = format!("HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{retry}{hardening}\r\n",if status == 200 {"OK"} else {"Error"},body.len()).into_bytes();
        if body.len() <= 4096 {
            response.extend_from_slice(&body);
            stream.get_mut().write_all(&response)?;
        } else {
            stream.get_mut().write_all(&response)?;
            stream.get_mut().write_all(&body)?;
        }
        stream.get_mut().flush()?;
        Ok(())
    }
    fn handle<S: Read + Write>(&self, stream: &mut BufReader<S>) -> Result<Vec<u8>> {
        let request = legacy_line(stream)?;
        let words: Vec<_> = request.split_whitespace().collect();
        if words.len() != 3 || words[0] != "POST" {
            return Err(Error::rejected(501, "unsupported method"));
        }
        let route = words[1];
        if !["/v1/enroll", "/v1/batches"].contains(&route) {
            return Err(Error::rejected(404, "unknown route"));
        }
        self.handle_v1(stream, route)
    }
    fn handle_v1<S: Read + Write>(
        &self,
        stream: &mut BufReader<S>,
        route: &str,
    ) -> Result<Vec<u8>> {
        let mut headers = Vec::<(String, String)>::new();
        loop {
            if headers.len() >= 100 {
                return Err(Error::rejected(400, "too many headers"));
            }
            let raw = legacy_line(stream)?;
            if raw == "\r\n" || raw == "\n" {
                break;
            }
            let (name, value) = raw
                .split_once(':')
                .ok_or_else(|| Error::rejected(400, "invalid HTTP headers"))?;
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
        let values = |name: &str| {
            headers
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
        };
        if !values("transfer-encoding").is_empty()
            || values("content-encoding").iter().any(|v| *v != "identity")
        {
            return Err(Error::rejected(415, "encoded requests are not supported"));
        }
        let lengths = values("content-length");
        if lengths.len() != 1
            || lengths[0].is_empty()
            || !lengths[0].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::rejected(400, "one content length required"));
        }
        let size = lengths[0]
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0 && *n <= MAX_BATCH)
            .ok_or_else(|| Error::rejected(413, "request too large"))?;
        let auth = values("authorization");
        if auth.len() != 1 || !auth[0].starts_with("Bearer ") {
            return Err(Error::rejected(401, "bearer credential required"));
        }
        let mut raw = vec![0; size];
        stream
            .read_exact(&mut raw)
            .map_err(|_| Error::rejected(400, "truncated request"))?;
        let body: Value = serde_json::from_slice(&raw)?;
        if route == "/v1/enroll" {
            if !exact_fields(&body, &["credential"]) {
                return Err(Error::rejected(400, "invalid enrollment"));
            }
            let credential = body["credential"].as_str().ok_or_else(|| {
                Error::rejected(400, "credential must contain 32 to 256 characters")
            })?;
            encode(&self.hub.enroll(&auth[0][7..], credential)?)
        } else {
            self.hub.ingest(&auth[0][7..], &body)
        }
    }
}

fn legacy_line<S: Read>(stream: &mut BufReader<S>) -> Result<String> {
    let mut raw = Vec::new();
    stream.take(65537).read_until(b'\n', &mut raw)?;
    if raw.len() > 65536 || !raw.ends_with(b"\n") {
        return Err(Error::rejected(400, "invalid HTTP headers"));
    }
    String::from_utf8(raw).map_err(|_| Error::rejected(400, "invalid HTTP headers"))
}
