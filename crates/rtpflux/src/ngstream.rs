//! The `ng` control protocol over streams, as rtpengine serves it besides
//! UDP:
//!
//! * TCP (`control.listen_tcp`): messages `cookie SP bencode` back to back,
//!   each ending where its bencoded dictionary does (no length prefix);
//!   replies the same way.
//! * HTTP (`control.listen_http`): `POST /ng` with `Content-Type:
//!   application/x-rtpengine-ng`, the body a message (`cookie SP` then
//!   bencode or JSON), the reply in the same form; `POST /ng-plain` without
//!   the cookie (bencode, or JSON with `application/json`); `GET /ping`.
//! * WebSocket on the HTTP endpoints, subprotocol `ng.rtpengine.com` (one
//!   message per WebSocket message, with the cookie) or
//!   `ng-plain.rtpengine.com` (without); replies in binary frames.
//!
//! JSON requests (a body starting with `{`) get JSON replies. Each
//! connection has its thread; the messages themselves are handled by the
//! control thread ([`NgLink`]), with the same reply cache as for UDP (by
//! connection and cookie). No TLS: for HTTPS / WSS, terminate TLS in front.

use crate::control::NgLink;
use rtpflux_ng::bencode::{Value, item_len};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Largest message or HTTP body accepted.
const MAX_MESSAGE: usize = 65_535;
/// Largest HTTP request head.
const MAX_HEAD: usize = 16 * 1024;
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Accept connections on `listener` until `stop`, serving each with
/// `serve` on its own thread.
fn accept_loop(
    listener: &TcpListener,
    stop: &Arc<AtomicBool>,
    link: &NgLink,
    serve: fn(TcpStream, SocketAddr, &NgLink, &AtomicBool),
) {
    if let Err(e) = listener.set_nonblocking(true) {
        log::warn!("ng: {e}");
        return;
    }
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let (link, stop) = (link.clone(), Arc::clone(stop));
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let spawned = std::thread::Builder::new()
                    .name("rtpflux-ng-conn".to_owned())
                    .spawn(move || serve(stream, peer, &link, &stop));
                if let Err(e) = spawned {
                    log::warn!("ng: connection from {peer}: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                log::warn!("ng: accept: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// Serve `ng` over TCP on `listener` until `stop`.
pub fn serve_tcp(listener: &TcpListener, link: &NgLink, stop: &Arc<AtomicBool>) {
    accept_loop(listener, stop, link, tcp_connection);
}

/// Serve `ng` over HTTP and WebSocket on `listener` until `stop`.
pub fn serve_http(listener: &TcpListener, link: &NgLink, stop: &Arc<AtomicBool>) {
    accept_loop(listener, stop, link, http_connection);
}

/// Read into `buf` (more bytes appended); false at the end of the stream,
/// on an error or when stopping.
fn fill(stream: &mut TcpStream, buf: &mut Vec<u8>, stop: &AtomicBool) -> bool {
    let mut chunk = [0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return false,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                return true;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

/// The length of the first complete message (`cookie SP value`) in `buf`:
/// `Ok(None)` when it is not complete yet, `Err` when it cannot be one.
/// The length of the first `ng` message in `buf` (`cookie SP bencode`):
/// `Ok(None)` while it has not arrived whole, `Err` when `buf` is not `ng`
/// (no space within the first 256 bytes, an empty cookie, a value that
/// cannot be bencode).
///
/// # Errors
///
/// [`NotNg`] when `buf` cannot start an `ng` message.
pub fn message_len(buf: &[u8]) -> Result<Option<usize>, NotNg> {
    let Some(space) = buf.iter().position(|&b| b == b' ') else {
        return if buf.len() > 256 {
            Err(NotNg)
        } else {
            Ok(None)
        };
    };
    if space == 0 {
        return Err(NotNg);
    }
    match item_len(&buf[space + 1..]) {
        Ok(Some(n)) => Ok(Some(space + 1 + n)),
        Ok(None) => Ok(None),
        Err(_) => Err(NotNg),
    }
}

/// Bytes that cannot start an `ng` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotNg;

/// Messages arriving on a stream, cut where each ends (`message_len`).
#[derive(Debug, Default)]
pub struct NgFramer {
    buf: Vec<u8>,
    closed: bool,
}

impl NgFramer {
    #[must_use]
    pub fn new() -> Self {
        NgFramer::default()
    }

    /// Bytes received: the messages they complete. The stream is given up
    /// (`is_closed`) when it is not `ng`, or when what is left of a message
    /// exceeds `MAX_MESSAGE` bytes; the messages before that are returned.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        self.buf.extend_from_slice(chunk);
        loop {
            match message_len(&self.buf) {
                Ok(Some(n)) => out.push(self.buf.drain(..n).collect()),
                Ok(None) => break,
                Err(NotNg) => {
                    self.closed = true;
                    return out;
                }
            }
        }
        if self.buf.len() > MAX_MESSAGE {
            self.closed = true;
        }
        out
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// What the front of the bytes a WebSocket server received holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Not a whole frame yet.
    More,
    /// The connection must be failed.
    Close,
    /// A frame (unmasked payload) of `used` bytes.
    Frame {
        fin: bool,
        op: u8,
        payload: Vec<u8>,
        used: usize,
    },
}

/// Read a client frame (RFC 6455 §5.2) from the front of `buf`, as a server
/// with no extension. The connection fails on a reserved bit, a reserved
/// opcode, an unmasked frame (§5.1), a fragmented or long control frame
/// (§5.5), a length not in its minimal form or with the top bit set, or a
/// payload over `MAX_MESSAGE` bytes. Decided from the header first, then the
/// extended length, then the size.
#[must_use]
pub fn parse_frame(buf: &[u8]) -> Parsed {
    let [b0, b1, ..] = *buf else {
        return Parsed::More;
    };
    let op = b0 & 0x0f;
    let control = op >= 8;
    let header_ok = b0 & 0x70 == 0
        && matches!(op, 0..=2 | 8..=10)
        && b1 & 0x80 != 0
        && (!control || (b0 & 0x80 != 0 && b1 & 0x7f <= 125));
    if !header_ok {
        return Parsed::Close;
    }
    let l7 = b1 & 0x7f;
    let ext = match l7 {
        0..=125 => 0,
        126 => 2,
        _ => 8,
    };
    if buf.len() - 2 < ext {
        return Parsed::More;
    }
    let len: u64 = match l7 {
        0..=125 => u64::from(l7),
        126 => {
            let n = u64::from(u16::from_be_bytes([buf[2], buf[3]]));
            if n < 126 {
                return Parsed::Close;
            }
            n
        }
        _ => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[2..10]);
            let n = u64::from_be_bytes(b);
            if !(65_536..1 << 63).contains(&n) {
                return Parsed::Close;
            }
            n
        }
    };
    let Ok(len) = usize::try_from(len) else {
        return Parsed::Close;
    };
    if len > MAX_MESSAGE {
        return Parsed::Close;
    }
    let need = 2 + ext + 4 + len;
    if buf.len() < need {
        return Parsed::More;
    }
    let mask = [buf[2 + ext], buf[3 + ext], buf[4 + ext], buf[5 + ext]];
    let payload = buf[6 + ext..need]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 4])
        .collect();
    Parsed::Frame {
        fin: b0 & 0x80 != 0,
        op,
        payload,
        used: need,
    }
}

fn tcp_connection(mut stream: TcpStream, peer: SocketAddr, link: &NgLink, stop: &AtomicBool) {
    let mut framer = NgFramer::new();
    let mut chunk = Vec::new();
    loop {
        for message in framer.push(&chunk) {
            if let Some(reply) = link.ask(message, Some(peer))
                && stream.write_all(&reply).is_err()
            {
                return;
            }
        }
        if framer.is_closed() {
            log::debug!("ng: {peer}: not an ng message; closing");
            return;
        }
        chunk.clear();
        if !fill(&mut stream, &mut chunk, stop) {
            return;
        }
    }
}

/// A request's head: method, path, and headers (names lower-case).
struct Head {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn content_type(&self) -> String {
        self.header("content-type")
            .and_then(|v| v.split(';').next())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    }
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            let (n, v) = l.split_once(':')?;
            Some((n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect();
    Some(Head {
        method,
        path,
        headers,
    })
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) -> bool {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).is_ok() && stream.write_all(body).is_ok()
}

/// A cookie for a request that came without one (`ng-plain`).
fn fresh_cookie() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "plain-{:x}-{}",
        rand::random::<u64>(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Handle a message whose body is bencode or JSON (`plain`: no cookie in
/// it or in the reply). The reply in the request's encoding.
fn handle(link: &NgLink, peer: SocketAddr, data: &[u8], plain: bool) -> Option<Vec<u8>> {
    let (cookie, body) = if plain {
        (fresh_cookie().into_bytes(), data)
    } else {
        let space = data.iter().position(|&b| b == b' ')?;
        (data[..space].to_vec(), &data[space + 1..])
    };
    let json = body.first() == Some(&b'{');
    let mut message = cookie.clone();
    message.push(b' ');
    if json {
        let v: serde_json::Value = serde_json::from_slice(body).ok()?;
        json_to_bencode(&v, &mut message);
    } else {
        message.extend_from_slice(body);
    }
    let reply = link.ask(message, Some(peer))?;
    let reply_body = reply.get(cookie.len() + 1..)?;
    let reply_body = if json {
        let v = rtpflux_ng::bencode::decode(reply_body).ok()?;
        serde_json::to_vec(&bencode_to_json(v)).ok()?
    } else {
        reply_body.to_vec()
    };
    if plain {
        Some(reply_body)
    } else {
        let mut out = cookie;
        out.push(b' ');
        out.extend_from_slice(&reply_body);
        Some(out)
    }
}

fn http_connection(mut stream: TcpStream, peer: SocketAddr, link: &NgLink, stop: &AtomicBool) {
    let mut buf = Vec::new();
    loop {
        // The head.
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            if buf.len() > MAX_HEAD || !fill(&mut stream, &mut buf, stop) {
                return;
            }
        };
        let Some(head) = parse_head(&buf[..end]) else {
            let _ = respond(&mut stream, "400 Bad Request", "text/plain", b"bad request");
            return;
        };
        buf.drain(..end + 4);
        let length: usize = head
            .header("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if length > MAX_MESSAGE {
            let _ = respond(
                &mut stream,
                "413 Payload Too Large",
                "text/plain",
                b"too large",
            );
            return;
        }
        while buf.len() < length {
            if !fill(&mut stream, &mut buf, stop) {
                return;
            }
        }
        let body: Vec<u8> = buf.drain(..length).collect();
        if head
            .header("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        {
            websocket(stream, peer, &head, buf, link, stop);
            return;
        }
        let ct = head.content_type();
        let ok = match (head.method.as_str(), head.path.as_str()) {
            ("GET", "/ping") => respond(&mut stream, "200 OK", "text/plain", b"pong"),
            ("POST", "/ng") if ct == "application/x-rtpengine-ng" => {
                match handle(link, peer, &body, false) {
                    Some(r) => respond(&mut stream, "200 OK", "application/x-rtpengine-ng", &r),
                    None => respond(&mut stream, "400 Bad Request", "text/plain", b"error"),
                }
            }
            ("POST", "/ng-plain")
                if ct == "application/x-rtpengine-ng" || ct == "application/json" =>
            {
                match handle(link, peer, &body, true) {
                    Some(r) => respond(&mut stream, "200 OK", &ct, &r),
                    None => respond(&mut stream, "400 Bad Request", "text/plain", b"error"),
                }
            }
            _ => respond(&mut stream, "404 Not Found", "text/plain", b"not found"),
        };
        let close = head
            .header("connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"));
        if !ok || close {
            return;
        }
    }
}

/// Standard base64 with padding.
#[must_use]
pub fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                out.push(char::from(T[((n >> (18 - 6 * k)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `Sec-WebSocket-Accept` for a key (RFC 6455 §4.2.2).
fn accept_key(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64(&h.finalize())
}

/// A frame from the client: opcode, FIN, unmasked payload.
fn read_frame(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    stop: &AtomicBool,
) -> Option<(u8, bool, Vec<u8>)> {
    loop {
        match parse_frame(buf) {
            Parsed::Frame {
                fin,
                op,
                payload,
                used,
            } => {
                buf.drain(..used);
                return Some((op, fin, payload));
            }
            Parsed::Close => {
                // Fail the connection (RFC 6455 §7.1.7): a Close frame
                // with 1002 (protocol error) first.
                let _ = write_frame(stream, 8, &1002u16.to_be_bytes());
                return None;
            }
            Parsed::More => {
                if !fill(stream, buf, stop) {
                    return None;
                }
            }
        }
    }
}

fn write_frame(stream: &mut TcpStream, op: u8, payload: &[u8]) -> bool {
    let mut f = vec![0x80 | op];
    match payload.len() {
        n if n < 126 => f.push(u8::try_from(n).unwrap_or(0)),
        n if n <= 0xffff => {
            f.push(126);
            f.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
        }
        n => {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(payload);
    stream.write_all(&f).is_ok()
}

fn websocket(
    mut stream: TcpStream,
    peer: SocketAddr,
    head: &Head,
    mut buf: Vec<u8>,
    link: &NgLink,
    stop: &AtomicBool,
) {
    let Some(key) = head.header("sec-websocket-key") else {
        let _ = respond(&mut stream, "400 Bad Request", "text/plain", b"no key");
        return;
    };
    let offered = head.header("sec-websocket-protocol").unwrap_or("");
    let Some(protocol) = offered
        .split(',')
        .map(str::trim)
        .find(|p| *p == "ng.rtpengine.com" || *p == "ng-plain.rtpengine.com")
        .map(str::to_owned)
    else {
        let _ = respond(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            b"unsupported subprotocol",
        );
        return;
    };
    let plain = protocol == "ng-plain.rtpengine.com";
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n",
        accept_key(key)
    );
    if stream.write_all(answer.as_bytes()).is_err() {
        return;
    }
    let mut message: Vec<u8> = Vec::new();
    // A fragmented message is in progress (RFC 6455 §5.4): it goes on with
    // continuation frames only, and only it does.
    let mut fragmented = false;
    while let Some((op, fin, payload)) = read_frame(&mut stream, &mut buf, stop) {
        match op {
            0..=2 => {
                if (op == 0) != fragmented {
                    let _ = write_frame(&mut stream, 8, &1002u16.to_be_bytes());
                    return;
                }
                fragmented = !fin;
                message.extend_from_slice(&payload);
                if message.len() > MAX_MESSAGE {
                    // 1009: message too big (RFC 6455 §7.4.1).
                    let _ = write_frame(&mut stream, 8, &1009u16.to_be_bytes());
                    return;
                }
                if fin {
                    let m = core::mem::take(&mut message);
                    if let Some(r) = handle(link, peer, &m, plain)
                        && !write_frame(&mut stream, 2, &r)
                    {
                        return;
                    }
                }
            }
            8 => {
                let _ = write_frame(&mut stream, 8, &payload);
                return;
            }
            9 if !write_frame(&mut stream, 10, &payload) => return,
            _ => {}
        }
    }
}

/// A JSON request as bencode: objects as dictionaries, arrays as lists,
/// strings as byte strings, integers as integers, other numbers and
/// booleans as strings; `null` members are left out.
pub fn json_to_bencode(v: &serde_json::Value, out: &mut Vec<u8>) {
    use serde_json::Value as J;
    let string = |s: &str, out: &mut Vec<u8>| {
        out.extend_from_slice(s.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(s.as_bytes());
    };
    match v {
        J::Object(m) => {
            out.push(b'd');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for k in keys {
                if m[k].is_null() {
                    continue;
                }
                string(k, out);
                json_to_bencode(&m[k], out);
            }
            out.push(b'e');
        }
        J::Array(a) => {
            out.push(b'l');
            for x in a {
                json_to_bencode(x, out);
            }
            out.push(b'e');
        }
        J::String(s) => string(s, out),
        J::Number(n) => match n.as_i64() {
            Some(i) => out.extend_from_slice(format!("i{i}e").as_bytes()),
            None => string(&n.to_string(), out),
        },
        J::Bool(b) => string(if *b { "true" } else { "false" }, out),
        J::Null => string("", out),
    }
}

/// A reply as JSON: byte strings as strings (lossy UTF-8).
#[must_use]
pub fn bencode_to_json(v: Value<'_>) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Int(i) => J::from(i),
        Value::Bytes(b) => J::String(String::from_utf8_lossy(b).into_owned()),
        Value::List(l) => J::Array(l.iter().map(bencode_to_json).collect()),
        Value::Dict(d) => J::Object(
            d.iter()
                .map(|(k, v)| (String::from_utf8_lossy(k).into_owned(), bencode_to_json(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing() {
        assert_eq!(message_len(b"abc d7:command4:pinge"), Ok(Some(21)));
        assert_eq!(message_len(b"abc d7:command4:pinge1 d"), Ok(Some(21)));
        assert_eq!(message_len(b"abc d7:comm"), Ok(None));
        assert_eq!(message_len(b"abc"), Ok(None));
        assert_eq!(message_len(b" d7:command4:pinge"), Err(NotNg));
        assert_eq!(message_len(b"abc {\"command\"}"), Err(NotNg));
    }

    #[test]
    fn websocket_accept() {
        // RFC 6455 §1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn json() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"command":"ping","flags":["a","b"],"n":3,"skip":null}"#)
                .unwrap();
        let mut b = Vec::new();
        json_to_bencode(&v, &mut b);
        assert_eq!(b, b"d7:command4:ping5:flagsl1:a1:be1:ni3ee");
        let back = bencode_to_json(rtpflux_ng::bencode::decode(&b).unwrap());
        assert_eq!(back["flags"][1], "b");
        assert_eq!(back["n"], 3);
    }
}
