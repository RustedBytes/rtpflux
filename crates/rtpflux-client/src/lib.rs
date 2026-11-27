//! A client of rtpflux's native control API: what a B2BUA or softswitch
//! links to manage media endpoints, without any of the relay's internals.
//!
//! The protocol (see `docs/native-api.md`): over a Unix stream socket (or
//! TCP, authenticated with a tenant's token: [`Client::connect_tcp`]),
//! each message is a 4-octet big-endian length and that many octets of
//! JSON. A request is `{"v": 1, "op": …, "operation_id": …, …}`; its reply
//! carries the same `operation_id` and either `"ok": true` with `result`,
//! or `"ok": false` with `error: {code, message}`. Once the connection has
//! subscribed (`events.subscribe`), events (`{"event": …}`) arrive between
//! replies; [`Client::call`] keeps them for [`Client::next_event`].
//!
//! ```no_run
//! use rtpflux_client::Client;
//! use serde_json::json;
//!
//! let mut c = Client::connect("/run/rtpflux/native.sock")?;
//! let ep = c.call("endpoint.create", json!({"remote_sdp": "v=0\r\n…"}))?;
//! println!("answer: {}", ep["sdp"]);
//! # Ok::<(), rtpflux_client::ClientError>(())
//! ```

#![forbid(unsafe_code)]

use serde_json::{Map, Value, json};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// The protocol version this client speaks.
pub const VERSION: u64 = 1;
/// How long a request waits for its reply, unless set otherwise.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest message, either way.
pub const MAX_MESSAGE: usize = 1 << 20;

/// Why a call failed.
#[derive(Debug)]
pub enum ClientError {
    /// The connection failed.
    Io(std::io::Error),
    /// The relay answered something that is not the protocol.
    Protocol(String),
    /// The relay refused: its error code (`not_found`, `conflict`,
    /// `unsupported`, `exhausted`, `timeout`, `unauthorized`, `invalid`,
    /// `internal`) and message.
    Refused { code: String, message: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "{e}"),
            ClientError::Protocol(why) => write!(f, "protocol: {why}"),
            ClientError::Refused { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl ClientError {
    /// The relay's error code, if it refused.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            ClientError::Refused { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// A connection to the native API.
#[derive(Debug)]
pub struct Client {
    stream: Conn,
    next_operation: u64,
    /// Events that arrived while waiting for replies.
    events: VecDeque<Value>,
    /// The tenant named in every request, if set.
    tenant: Option<String>,
    /// How long a request waits for its reply (`None`: no limit).
    request_timeout: Option<Duration>,
    /// A request timed out: its reply may still come and be taken for the
    /// next one's, so the connection is not used again.
    poisoned: bool,
}

/// The connection: a Unix socket or TCP.
#[derive(Debug)]
enum Conn {
    Unix(UnixStream),
    Tcp(std::net::TcpStream),
}

impl Conn {
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        match self {
            Conn::Unix(s) => s.set_read_timeout(t),
            Conn::Tcp(s) => s.set_read_timeout(t),
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Unix(s) => s.read(buf),
            Conn::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Unix(s) => s.write(buf),
            Conn::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Unix(s) => s.flush(),
            Conn::Tcp(s) => s.flush(),
        }
    }
}

/// One message, framed.
fn frame(v: &Value) -> Result<Vec<u8>, ClientError> {
    let body = serde_json::to_vec(v).map_err(|e| ClientError::Protocol(e.to_string()))?;
    let len = u32::try_from(body.len()).map_err(|_| ClientError::Protocol("too large".into()))?;
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

impl Client {
    /// Connect to the socket at `path`.
    ///
    /// # Errors
    ///
    /// When the socket cannot be connected to.
    pub fn connect(path: impl AsRef<Path>) -> Result<Client, ClientError> {
        let stream = Conn::Unix(UnixStream::connect(path)?);
        Ok(Client {
            stream,
            next_operation: 0,
            events: VecDeque::new(),
            tenant: None,
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
            poisoned: false,
        })
    }

    /// Connect over TCP to `addr` and authenticate with `token`: the
    /// connection is then the token's tenant's.
    ///
    /// # Errors
    ///
    /// When the connection fails, or the relay refuses the token.
    pub fn connect_tcp(
        addr: impl std::net::ToSocketAddrs,
        token: &str,
    ) -> Result<Client, ClientError> {
        let s = std::net::TcpStream::connect(addr)?;
        let _ = s.set_nodelay(true);
        let mut c = Client {
            stream: Conn::Tcp(s),
            next_operation: 0,
            events: VecDeque::new(),
            tenant: None,
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
            poisoned: false,
        };
        c.call("auth", json!({ "token": token }))?;
        Ok(c)
    }

    /// How long each request waits for its reply ([`DEFAULT_REQUEST_TIMEOUT`]
    /// unless set; `None`: no limit). A request that times out leaves the
    /// connection unusable (its late reply would be taken for the next
    /// request's): connect again.
    pub fn set_request_timeout(&mut self, timeout: Option<Duration>) {
        self.request_timeout = timeout;
    }

    /// Name `tenant` in every request from now on.
    pub fn set_tenant(&mut self, tenant: impl Into<String>) {
        self.tenant = Some(tenant.into());
    }

    /// Send `request` as it is (it should have `op`), and wait for its
    /// reply, keeping events that arrive meanwhile. The whole reply.
    ///
    /// # Errors
    ///
    /// When the connection fails or the reply is not the protocol.
    pub fn raw(&mut self, request: &Value) -> Result<Value, ClientError> {
        if self.poisoned {
            return Err(ClientError::Protocol(
                "an earlier request timed out: connect again".into(),
            ));
        }
        self.stream.set_read_timeout(self.request_timeout)?;
        self.stream.write_all(&frame(request)?)?;
        loop {
            let m = match self.read_message() {
                Ok(m) => m,
                Err(ClientError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    self.poisoned = true;
                    return Err(ClientError::Io(std::io::ErrorKind::TimedOut.into()));
                }
                Err(e) => return Err(e),
            };
            if m.get("event").is_some() {
                self.events.push_back(m);
            } else {
                return Ok(m);
            }
        }
    }

    /// Run operation `op` with the fields of `args` (an object); its
    /// `result`.
    ///
    /// # Errors
    ///
    /// When the relay refuses ([`ClientError::Refused`]), or the connection
    /// fails.
    pub fn call(&mut self, op: &str, args: Value) -> Result<Value, ClientError> {
        let mut req = match args {
            Value::Object(m) => m,
            Value::Null => Map::new(),
            _ => return Err(ClientError::Protocol("args: not an object".into())),
        };
        self.next_operation += 1;
        let id = req
            .get("operation_id")
            .and_then(Value::as_str)
            .map_or_else(|| format!("op-{}", self.next_operation), str::to_owned);
        req.insert("v".into(), json!(VERSION));
        req.insert("op".into(), json!(op));
        req.insert("operation_id".into(), json!(id));
        if let Some(t) = &self.tenant {
            req.entry("tenant").or_insert_with(|| json!(t));
        }
        let reply = self.raw(&Value::Object(req))?;
        if reply.get("operation_id").and_then(Value::as_str) != Some(id.as_str()) {
            return Err(ClientError::Protocol(format!(
                "a reply to another operation: {reply}"
            )));
        }
        if reply.get("ok").and_then(Value::as_bool) == Some(true) {
            return Ok(reply.get("result").cloned().unwrap_or(Value::Null));
        }
        let e = reply.get("error").cloned().unwrap_or(Value::Null);
        Err(ClientError::Refused {
            code: e
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("internal")
                .to_owned(),
            message: e
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        })
    }

    /// The next event, waiting up to `timeout` for one.
    ///
    /// # Errors
    ///
    /// When the connection fails.
    pub fn next_event(&mut self, timeout: Duration) -> Result<Option<Value>, ClientError> {
        if let Some(e) = self.events.pop_front() {
            return Ok(Some(e));
        }
        if timeout.is_zero() {
            return Ok(None);
        }
        self.stream.set_read_timeout(Some(timeout))?;
        match self.read_message() {
            Ok(m) if m.get("event").is_some() => Ok(Some(m)),
            Ok(m) => Err(ClientError::Protocol(format!("an unasked-for reply: {m}"))),
            Err(ClientError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// The next event of type `ty` within `timeout`; other events before
    /// it are dropped.
    ///
    /// # Errors
    ///
    /// When the connection fails.
    pub fn wait_event(
        &mut self,
        ty: &str,
        timeout: Duration,
    ) -> Result<Option<Value>, ClientError> {
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.next_event(left)? {
                Some(e) if e.get("event").and_then(Value::as_str) == Some(ty) => {
                    return Ok(Some(e));
                }
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    fn read_message(&mut self) -> Result<Value, ClientError> {
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_MESSAGE {
            return Err(ClientError::Protocol(format!("a {n}-octet message")));
        }
        let mut body = vec![0u8; n];
        self.stream.read_exact(&mut body)?;
        serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixtures (`fixtures/*.json`) are valid messages of the protocol:
    /// each request has `op` and `v`, each reply `ok`, each event `event`.
    #[test]
    fn the_fixtures_are_messages() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
        let mut n = 0;
        for f in std::fs::read_dir(dir).unwrap() {
            let path = f.unwrap().path();
            let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            for m in v.as_array().unwrap() {
                let ok = m.get("op").is_some() && m.get("v") == Some(&json!(1))
                    || m.get("ok").is_some()
                    || m.get("event").is_some();
                assert!(ok, "{name}: {m}");
                n += 1;
            }
        }
        assert!(n > 10);
    }

    /// A relay that never answers: the request times out, and the
    /// connection is not used again (a late reply would be misread).
    #[test]
    fn a_request_times_out_and_the_connection_is_retired() {
        let dir = std::env::temp_dir().join(format!("rtpflux-client-to-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mute.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut c = Client::connect(&path).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        c.set_request_timeout(Some(Duration::from_millis(100)));
        let started = Instant::now();
        let e = c.call("hello", Value::Null).unwrap_err();
        assert!(
            matches!(&e, ClientError::Io(io) if io.kind() == std::io::ErrorKind::TimedOut),
            "{e}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(
            c.call("hello", Value::Null),
            Err(ClientError::Protocol(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_message_is_framed() {
        let f = frame(&json!({"op": "hello"})).unwrap();
        assert_eq!(&f[..4], &14u32.to_be_bytes());
        assert_eq!(&f[4..], br#"{"op":"hello"}"#);
    }
}
