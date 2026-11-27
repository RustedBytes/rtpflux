//! The native control API's server: a Unix socket whose connections carry
//! requests and replies, and events once subscribed (see
//! `docs/native-api.md`).
//!
//! Each message is a 4-octet big-endian length, then that many octets of
//! JSON (at most [`MAX_MESSAGE`]). A connection's requests are answered in
//! order; its events are written between replies, never in the middle of
//! one. On the Unix socket only the relay's own user, root and the
//! configured user ids may connect (the peer's credentials,
//! `SO_PEERCRED`). Over TCP ([`serve_tcp`]) a connection's first request
//! must be `{"op": "auth", "token": …}` with a tenant's token: the
//! connection is then that tenant's, and its requests name no other.
//!
//! The connection threads never touch call state: they hand each request
//! to the control thread ([`crate::control::native::NativeLink`]) and wait
//! for its reply. Events reach a connection through a bounded queue the
//! control thread never waits on.

use crate::control::native::{NativeLink, Origin, SUBSCRIBER_QUEUE};
use serde_json::json;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The largest message, either way.
pub const MAX_MESSAGE: usize = 1 << 20;
/// Connections served at once, at most.
pub const MAX_CONNECTIONS: usize = 64;
/// How often a blocked thread looks at the stop flag.
const POLL: Duration = Duration::from_millis(200);

/// Bind the native API's socket at `path`: a stale socket left there is
/// removed (anything else is refused), and the new one is readable and
/// writable by the relay's user only.
///
/// # Errors
///
/// When `path` holds something other than a socket, or binding fails.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                ErrorKind::AlreadyExists,
                "exists and is not a socket",
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// The relay's own user id.
fn own_uid() -> Option<u32> {
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Whether the peer of `stream` may use the API.
fn allowed(stream: &UnixStream, uids: &[u32]) -> bool {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let Ok(cred) = getsockopt(stream, PeerCredentials) else {
        return false;
    };
    let uid = cred.uid();
    uid == 0 || Some(uid) == own_uid() || uids.contains(&uid)
}

/// A connection's stream: a Unix one or a TCP one.
pub trait Stream: Read + Write + Send + Sized + 'static {
    /// Another handle on the same connection.
    ///
    /// # Errors
    ///
    /// When the socket cannot be duplicated.
    fn duplicate(&self) -> std::io::Result<Self>;
    /// Wake a blocked read after `t`.
    ///
    /// # Errors
    ///
    /// When the socket refuses.
    fn read_timeout(&self, t: Duration) -> std::io::Result<()>;
    /// Close both ways.
    fn close(&self);
}

impl Stream for UnixStream {
    fn duplicate(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn read_timeout(&self, t: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(t))
    }
    fn close(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

impl Stream for TcpStream {
    fn duplicate(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn read_timeout(&self, t: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(t))
    }
    fn close(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

/// Tokens over TCP: tenant → token.
pub type Tokens = std::collections::BTreeMap<String, String>;

/// Serve the Unix socket `listener` until `stop` is set.
pub fn serve(listener: &UnixListener, link: &NativeLink, uids: &[u32], stop: &Arc<AtomicBool>) {
    let accept = || {
        let (s, _) = listener.accept()?;
        if allowed(&s, uids) {
            Ok(Some(s))
        } else {
            log::warn!("native: a connection from a user not allowed, closed");
            Ok(None)
        }
    };
    if let Err(e) = listener.set_nonblocking(true) {
        log::error!("native: {e}");
        return;
    }
    accept_loop(accept, link, None, stop);
}

/// Serve the TCP `listener` until `stop` is set: each connection
/// authenticates with one of `tokens` first.
pub fn serve_tcp(
    listener: &TcpListener,
    link: &NativeLink,
    tokens: &Tokens,
    stop: &Arc<AtomicBool>,
) {
    if let Err(e) = listener.set_nonblocking(true) {
        log::error!("native: {e}");
        return;
    }
    let accept = || {
        let (s, _) = listener.accept()?;
        s.set_nonblocking(false)?;
        let _ = s.set_nodelay(true);
        Ok(Some(s))
    };
    accept_loop(accept, link, Some(&Arc::new(tokens.clone())), stop);
}

/// Accept connections from `accept` (`None`: refused) until `stop`.
fn accept_loop<S: Stream>(
    mut accept: impl FnMut() -> std::io::Result<Option<S>>,
    link: &NativeLink,
    tokens: Option<&Arc<Tokens>>,
    stop: &Arc<AtomicBool>,
) {
    let ids = AtomicU64::new(0);
    let open = Arc::new(AtomicUsize::new(0));
    let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        match accept() {
            Ok(None) => {}
            Ok(Some(stream)) => {
                if open.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    log::warn!("native: {MAX_CONNECTIONS} connections already; one refused");
                    continue;
                }
                let id = ids.fetch_add(1, Ordering::Relaxed) + 1;
                let (link, stop, open) = (link.clone(), Arc::clone(stop), Arc::clone(&open));
                let tokens = tokens.cloned();
                open.fetch_add(1, Ordering::Relaxed);
                match std::thread::Builder::new()
                    .name("rtpflux-native".to_owned())
                    .spawn(move || {
                        connection(stream, id, &link, tokens.as_deref(), &stop);
                        open.fetch_sub(1, Ordering::Relaxed);
                    }) {
                    Ok(t) => threads.push(t),
                    Err(e) => log::warn!("native: no thread for a connection: {e}"),
                }
                threads.retain(|t| !t.is_finished());
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL / 4),
            Err(e) => {
                log::warn!("native: accept: {e}");
                std::thread::sleep(POLL);
            }
        }
    }
    for t in threads {
        let _ = t.join();
    }
}

/// Read exactly `buf.len()` octets, waking every [`POLL`] to look at
/// `stop`. `Ok(false)`: the peer closed (before the first octet), or the
/// relay stops.
fn read_full<S: Stream>(
    stream: &mut S,
    buf: &mut [u8],
    stop: &AtomicBool,
) -> std::io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        if stop.load(Ordering::Relaxed) {
            return Ok(false);
        }
        match stream.read(&mut buf[got..]) {
            Ok(0) if got == 0 => return Ok(false),
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Whether `a` and `b` are equal, in time that does not depend on where
/// they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    let diff = a
        .iter()
        .zip(b)
        .fold(u8::from(a.len() != b.len()), |d, (x, y)| d | (x ^ y));
    diff == 0
}

/// The tenant whose token an `auth` request gives, if any.
fn authenticate(body: &[u8], tokens: &Tokens) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    if v.get("op")?.as_str()? != "auth" {
        return None;
    }
    let given = v.get("token")?.as_str()?.as_bytes();
    // Every token is compared, whichever matches.
    tokens.iter().fold(None, |found, (tenant, token)| {
        if same(given, token.as_bytes()) {
            Some(tenant.clone())
        } else {
            found
        }
    })
}

/// A framed reply to an `auth` request.
fn auth_reply(body: &[u8], tenant: Option<&str>) -> Vec<u8> {
    let op = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("operation_id").cloned());
    let r = match tenant {
        Some(t) => json!({"v": 1, "operation_id": op, "ok": true, "result": {"tenant": t}}),
        None => json!({"v": 1, "operation_id": op, "ok": false,
            "error": {"code": "unauthorized", "message": "authenticate first: {\"op\": \"auth\", \"token\": …}"}}),
    };
    serde_json::to_vec(&r).unwrap_or_default()
}

/// One connection: its requests in turn, its events as they come. With
/// `tokens` (TCP), its first request authenticates it.
fn connection<S: Stream>(
    mut stream: S,
    id: u64,
    link: &NativeLink,
    tokens: Option<&Tokens>,
    stop: &Arc<AtomicBool>,
) {
    let _ = stream.read_timeout(POLL);
    let Ok(writer) = stream.duplicate() else {
        return;
    };
    let writer = Arc::new(Mutex::new(writer));
    // Events: written by a thread of their own as they come.
    let (events_tx, events_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(SUBSCRIBER_QUEUE);
    // Not waited for: it ends when the control thread lets go of the
    // queue (the connection's subscriptions end with it), or at its next
    // write once the connection is gone.
    let _events_writer = {
        let writer = Arc::clone(&writer);
        std::thread::Builder::new()
            .name("rtpflux-native-ev".to_owned())
            .spawn(move || {
                for frame in events_rx {
                    let Ok(mut w) = writer.lock() else {
                        return;
                    };
                    if w.write_all(&frame).is_err() {
                        return;
                    }
                }
            })
    };
    let mut origin = Origin {
        connection: id,
        events: Some(events_tx),
        tenant: None,
    };
    let mut failures = 0;
    let mut len = [0u8; 4];
    loop {
        match read_full(&mut stream, &mut len, stop) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => {
                log::debug!("native: connection {id}: {e}");
                break;
            }
        }
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_MESSAGE {
            log::debug!("native: connection {id}: a {n}-octet message; closed");
            break;
        }
        let mut body = vec![0u8; n];
        match read_full(&mut stream, &mut body, stop) {
            Ok(true) => {}
            _ => break,
        }
        let authenticated = tokens.is_none() || origin.tenant.is_some();
        let reply = if authenticated {
            None
        } else {
            let tenant = tokens.and_then(|t| authenticate(&body, t));
            if tenant.is_none() {
                failures += 1;
            }
            let r = auth_reply(&body, tenant.as_deref());
            origin.tenant = tenant;
            Some(r)
        };
        let reply = reply
            .or_else(|| link.ask(body, origin.clone()))
            .unwrap_or_else(|| {
                serde_json::to_vec(&json!({
                    "v": 1,
                    "ok": false,
                    "error": {"code": "exhausted", "message": "the relay is busy"},
                }))
                .unwrap_or_default()
            });
        let framed = {
            let mut f = Vec::with_capacity(reply.len() + 4);
            f.extend_from_slice(&u32::try_from(reply.len()).unwrap_or(u32::MAX).to_be_bytes());
            f.extend_from_slice(&reply);
            f
        };
        let Ok(mut w) = writer.lock() else {
            break;
        };
        if w.write_all(&framed).is_err() || failures >= 3 {
            break;
        }
    }
    stream.close();
    drop(origin);
    link.closed(id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_names_its_tenant() {
        let tokens: Tokens = [("a".to_owned(), "0123456789abcdef".to_owned())].into();
        let auth = |t: &str| {
            authenticate(
                format!(r#"{{"op":"auth","token":"{t}"}}"#).as_bytes(),
                &tokens,
            )
        };
        assert_eq!(auth("0123456789abcdef").as_deref(), Some("a"));
        assert_eq!(auth("0123456789abcdeX"), None);
        assert_eq!(auth("0123456789abcde"), None);
        assert_eq!(auth(""), None);
        assert_eq!(authenticate(br#"{"op":"hello"}"#, &tokens), None);
        assert_eq!(authenticate(b"nonsense", &tokens), None);
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }

    #[test]
    fn only_a_stale_socket_is_replaced() {
        let dir = std::env::temp_dir().join(format!("rtpflux-native-bind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api.sock");
        let first = bind(&path).unwrap();
        drop(first);
        // The socket left behind is replaced.
        let _second = bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // A file is not.
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(bind(&file).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
