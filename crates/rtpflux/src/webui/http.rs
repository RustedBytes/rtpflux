//! A small HTTP/1.1 server for the web UI: GET and HEAD only, a bounded
//! number of connections (one thread each), request heads capped at 8 KiB,
//! keep-alive with an idle timeout, Basic auth on every request, and
//! security headers on every response.

use super::api::{Api, Query};
use super::assets::{self, Asset};
use super::auth::{Credentials, Throttle};
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const MAX_HEAD: usize = 8 * 1024;
/// How long a connection may wait between requests.
const IDLE: Duration = Duration::from_secs(15);
/// How long a request head may take once it started: a client trickling
/// a byte at a time cannot hold a connection for long.
const HEAD_DEADLINE: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(10)
};

/// The UI's server: its API, login and limits.
pub struct Server {
    pub api: Api,
    pub creds: Credentials,
    pub realm: String,
    pub max_connections: usize,
    pub throttle: Throttle,
    active: AtomicUsize,
}

/// One parsed request.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Query,
    pub headers: Vec<(String, String)>,
}

impl Request {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A response before it is written.
#[derive(Debug)]
pub struct Response {
    pub code: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
    pub extra: Vec<(&'static str, String)>,
}

impl Response {
    fn json(code: u16, v: &Value) -> Self {
        Response {
            code,
            ctype: "application/json",
            body: v.to_string().into_bytes(),
            extra: vec![("Cache-Control", "no-store".into())],
        }
    }

    fn error(code: u16, msg: &str) -> Self {
        Self::json(code, &json!({ "error": msg }))
    }
}

impl Server {
    #[must_use]
    pub fn new(api: Api, creds: Credentials, realm: String, max_connections: usize) -> Self {
        Server {
            api,
            creds,
            realm,
            max_connections,
            throttle: Throttle::default(),
            active: AtomicUsize::new(0),
        }
    }

    /// Accept connections on `listener` until `stop` is set. Open
    /// connections end by themselves (idle timeout).
    pub fn serve(self: &Arc<Self>, listener: &TcpListener, stop: &AtomicBool) {
        if listener.set_nonblocking(true).is_err() {
            return;
        }
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer)) => self.accepted(stream, peer),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    log::warn!("webui: accept: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    fn accepted(self: &Arc<Self>, mut stream: TcpStream, peer: SocketAddr) {
        let _ = stream.set_nonblocking(false);
        if self.active.fetch_add(1, Ordering::AcqRel) >= self.max_connections {
            self.active.fetch_sub(1, Ordering::AcqRel);
            let _ = write_response(
                &mut stream,
                &Response::error(503, "too many connections"),
                false,
                false,
            );
            return;
        }
        let me = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("rtpflux-webui-conn".into())
            .spawn(move || {
                let _ = me.connection(&mut stream, Some(peer));
                me.active.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn connection(&self, s: &mut TcpStream, peer: Option<SocketAddr>) -> io::Result<()> {
        s.set_read_timeout(Some(IDLE))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let _ = s.set_nodelay(true);
        let mut buf = Vec::with_capacity(1024);
        loop {
            let Some(head_len) = read_head(s, &mut buf)? else {
                if buf.len() >= MAX_HEAD {
                    write_response(
                        s,
                        &Response::error(431, "request head too large"),
                        false,
                        false,
                    )?;
                }
                return Ok(());
            };
            let head = String::from_utf8_lossy(&buf[..head_len]).into_owned();
            buf.drain(..head_len);
            let Some(req) = parse_head(&head) else {
                return write_response(s, &Response::error(400, "bad request"), false, false);
            };
            let keep = !req
                .header("connection")
                .is_some_and(|c| c.eq_ignore_ascii_case("close"));
            // A request body is never expected: refuse it, not skip it,
            // and close (the body is not read). A method other than GET or
            // HEAD is answered as such (405), body or not.
            if req
                .header("content-length")
                .is_some_and(|l| l.trim() != "0")
                || req.header("transfer-encoding").is_some()
            {
                let resp = if req.method == "GET" || req.method == "HEAD" {
                    Response::error(400, "request bodies are not accepted")
                } else {
                    self.respond(&req, peer)
                };
                return write_response(s, &resp, false, false);
            }
            let head_only = req.method == "HEAD";
            let resp = self.respond(&req, peer);
            write_response(s, &resp, keep, head_only)?;
            if !keep {
                return Ok(());
            }
        }
    }

    /// Authentication, then routing.
    #[must_use]
    pub fn respond(&self, req: &Request, peer: Option<SocketAddr>) -> Response {
        if req.method != "GET" && req.method != "HEAD" {
            let mut r = Response::error(405, "read-only: only GET and HEAD");
            r.extra.push(("Allow", "GET, HEAD".into()));
            return r;
        }
        let ip = peer.map(|p| p.ip());
        if ip.is_some_and(|ip| self.throttle.blocked(ip)) {
            let mut r = Response::error(429, "too many failed logins, try again later");
            r.extra.push(("Retry-After", "60".into()));
            return r;
        }
        let auth = req.header("authorization");
        if !self.creds.check(auth) {
            if auth.is_some()
                && let Some(ip) = ip
            {
                self.throttle.failed(ip);
            }
            let mut r = Response::error(401, "authentication required");
            r.extra.push((
                "WWW-Authenticate",
                format!("Basic realm=\"{}\", charset=\"UTF-8\"", self.realm),
            ));
            return r;
        }
        if let Some(ip) = ip {
            self.throttle.succeeded(ip);
        }
        if req.path == "/api/v1/recordings/download" {
            return match self.api.recordings.download(&req.query) {
                Ok((name, bytes)) => Response {
                    code: 200,
                    ctype: "application/vnd.tcpdump.pcap",
                    body: bytes,
                    extra: vec![
                        // The name was checked: a plain base name, no quotes.
                        (
                            "Content-Disposition",
                            format!("attachment; filename=\"{name}\""),
                        ),
                        ("Cache-Control", "no-store".into()),
                    ],
                },
                Err((code, v)) => Response::json(code, &v),
            };
        }
        if let Some(api_path) = req.path.strip_prefix("/api/v1/") {
            let (code, v) = self.api.handle(api_path, &req.query);
            return Response::json(code, &v);
        }
        match assets::find(&req.path) {
            Some(a) => asset_response(a, req),
            None => Response::error(404, "not found"),
        }
    }
}

fn asset_response(a: &Asset, req: &Request) -> Response {
    let mut extra = vec![
        ("ETag", a.etag.clone()),
        ("Cache-Control", "no-cache".into()),
        ("Vary", "Accept-Encoding".into()),
    ];
    if req.header("if-none-match") == Some(a.etag.as_str()) {
        return Response {
            code: 304,
            ctype: a.ctype,
            body: Vec::new(),
            extra,
        };
    }
    let gzip_ok = req
        .header("accept-encoding")
        .is_some_and(|e| e.split(',').any(|x| x.trim().starts_with("gzip")));
    let body = match a.gzipped {
        Some(gz) if gzip_ok => {
            extra.push(("Content-Encoding", "gzip".into()));
            gz
        }
        _ => a.bytes,
    };
    Response {
        code: 200,
        ctype: a.ctype,
        body: body.to_vec(),
        extra,
    }
}

/// Read until the end of a request head: `Some(len)` (octets including
/// the blank line), or `None` on EOF, an idle connection, a head that
/// takes longer than [`HEAD_DEADLINE`] once started, or one over the limit.
fn read_head(s: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Option<usize>> {
    let mut deadline = (!buf.is_empty()).then(|| std::time::Instant::now() + HEAD_DEADLINE);
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(Some(p + 4));
        }
        if buf.len() >= MAX_HEAD {
            return Ok(None);
        }
        let wait = match deadline {
            None => IDLE,
            Some(d) => match d.checked_duration_since(std::time::Instant::now()) {
                Some(left) if !left.is_zero() => left,
                _ => return Ok(None),
            },
        };
        s.set_read_timeout(Some(wait))?;
        let mut chunk = [0u8; 2048];
        match s.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                deadline.get_or_insert_with(|| std::time::Instant::now() + HEAD_DEADLINE);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
}

/// A request head, or `None` when it is malformed or names a path with
/// `..`.
#[must_use]
pub fn parse_head(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut rl = lines.next()?.split(' ');
    let (method, target, version) = (rl.next()?, rl.next()?, rl.next()?);
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    let (path, qs) = target.split_once('?').unwrap_or((target, ""));
    let path = percent_decode(path)?;
    if path.contains("..") {
        return None;
    }
    let mut query = Query::new();
    for p in qs.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        query.insert(
            percent_decode(&k.replace('+', " "))?,
            percent_decode(&v.replace('+', " "))?,
        );
    }
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Some(Request {
        method: method.to_owned(),
        path,
        query,
        headers,
    })
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

const fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

fn write_response(s: &mut TcpStream, r: &Response, keep: bool, head_only: bool) -> io::Result<()> {
    let mut h = format!(
        "HTTP/1.1 {} {}\r\nServer: rtpflux-webui\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n\
         Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n",
        r.code,
        reason(r.code),
        r.ctype,
        r.body.len(),
        if keep { "keep-alive" } else { "close" }
    );
    for (n, v) in &r.extra {
        let _ = write!(h, "{n}: {v}\r\n");
    }
    h.push_str("\r\n");
    s.write_all(h.as_bytes())?;
    if !head_only && r.code != 304 {
        s.write_all(&r.body)?;
    }
    s.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trickled_head_is_cut_off() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            // One byte every 100 ms: never a whole head.
            for b in b"GET / HTTP/1.1\r\nHost: x\r\n" {
                if c.write_all(&[*b]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let (mut s, _) = listener.accept().unwrap();
        let start = std::time::Instant::now();
        let mut buf = Vec::new();
        assert_eq!(read_head(&mut s, &mut buf).unwrap(), None);
        let took = start.elapsed();
        assert!(took < Duration::from_secs(2), "cut off after {took:?}");
        drop(s);
        client.join().unwrap();
    }

    #[test]
    fn heads() {
        let r = parse_head(
            "GET /api/v1/calls?q=alice%40x&sort=-age&limit=5 HTTP/1.1\r\nHost: x\r\nAuthorization: Basic abc\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (r.method.as_str(), r.path.as_str()),
            ("GET", "/api/v1/calls")
        );
        assert_eq!(r.query["q"], "alice@x");
        assert_eq!(r.query["sort"], "-age");
        assert_eq!(r.header("authorization"), Some("Basic abc"));
        assert!(parse_head("GET /../etc/passwd HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_head("GET /%2e%2e/x HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_head("GET x HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_head("GET /%zz HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_head("GARBAGE\r\n\r\n").is_none());
    }
}
