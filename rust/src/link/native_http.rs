use super::native::Admission;
use crate::{Error, Result};
impl Admission {
    pub fn http_trial(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let end = raw
            .windows(4)
            .position(|s| s == b"\r\n\r\n")
            .ok_or_else(|| Error::rejected(400, "headers_incomplete"))?;
        let (n, _) = header(&raw[..end])?;
        if raw.len() - end - 4 != n {
            return Err(Error::rejected(400, "body_length"));
        }
        self.admit(&raw[end + 4..])
    }
}

/// Where an authenticated request goes.
pub(crate) enum Route {
    /// `POST /v2/batches`, the ingest route.
    Batches,
    /// `POST /v2/read/<name>`, a reader route (a name in `fleet::http::ROUTES`).
    Read(&'static str),
}
pub(crate) fn header(raw: &[u8]) -> Result<(usize, &str)> {
    match header_route(raw)? {
        (Route::Batches, n, credential) => Ok((n, credential)),
        _ => Err(Error::rejected(404, "route")),
    }
}
pub(crate) fn header_route(raw: &[u8]) -> Result<(Route, usize, &str)> {
    let end = raw.len();
    if end > 8192 {
        return Err(Error::rejected(413, "header_limit"));
    }
    let text =
        std::str::from_utf8(&raw[..end]).map_err(|_| Error::rejected(400, "invalid_headers"))?;
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap();
    if first.len() > 1024 {
        return Err(Error::rejected(413, "request_line_limit"));
    }
    let parts: Vec<_> = first.split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err(Error::rejected(400, "invalid_request_line"));
    }
    if parts[0] != "POST" {
        return Err(Error::rejected(405, "method"));
    }
    let route = if parts[1] == "/v2/batches" {
        Route::Batches
    } else if let Some(name) = parts[1]
        .strip_prefix("/v2/read/")
        .and_then(|n| crate::fleet::http::ROUTES.iter().copied().find(|r| *r == n))
    {
        Route::Read(name)
    } else {
        return Err(Error::rejected(404, "route"));
    };
    let mut headers = std::collections::BTreeMap::new();
    let mut count = 0;
    for line in lines {
        count += 1;
        if count > 32 || line.len() > 2048 {
            return Err(Error::rejected(413, "header_limit"));
        }
        if line.starts_with([' ', '\t']) || line.bytes().any(|b| b < 32 || b == 127) {
            return Err(Error::rejected(400, "invalid_header"));
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| Error::rejected(400, "invalid_header"))?;
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(Error::rejected(400, "invalid_header"));
        }
        if headers.insert(k.to_ascii_lowercase(), v.trim()).is_some() {
            return Err(Error::rejected(400, "duplicate_header"));
        }
    }
    if headers.contains_key("transfer-encoding") || headers.contains_key("content-encoding") {
        return Err(Error::rejected(415, "unsupported_encoding"));
    }
    if headers.contains_key("expect") {
        return Err(Error::rejected(417, "expect"));
    }
    if headers.get("content-type") != Some(&"application/json") || !headers.contains_key("host") {
        return Err(Error::rejected(400, "required_header"));
    }
    let n = headers
        .get("content-length")
        .ok_or_else(|| Error::rejected(400, "content_length"))?;
    if n.starts_with('0') || n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::rejected(400, "content_length"));
    }
    let n = n
        .parse::<usize>()
        .map_err(|_| Error::rejected(413, "byte_limit"))?;
    let limit = match route {
        Route::Batches => super::native::REQUEST_LIMIT,
        Route::Read(_) => crate::fleet::http::MAX_BODY,
    };
    if n > limit {
        return Err(Error::rejected(413, "byte_limit"));
    }
    if !headers
        .get("authorization")
        .is_some_and(|v| v.starts_with("Bearer ") && v.len() > 7)
    {
        return Err(match route {
            // A reader gets the one answer every credential failure gets.
            Route::Read(_) => crate::fleet::auth::unauthorized(),
            Route::Batches => Error::rejected(401, "identity_unbound"),
        });
    }
    Ok((route, n, &headers["authorization"][7..]))
}
