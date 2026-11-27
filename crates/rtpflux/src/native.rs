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
//! Tokens rotate through a file re-read when it changes ([`TokenSet`]):
//! a connection whose token is gone is refused at its next request.
//! Refusals and authentication failures go to the audit log
//! (`rtpflux::audit`), never with a token.
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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The largest message, either way.
pub const MAX_MESSAGE: usize = 1 << 20;
/// Connections served at once, at most.
pub const MAX_CONNECTIONS: usize = 64;
/// How often a blocked thread looks at the stop flag.
const POLL: Duration = Duration::from_millis(200);

/// Bind the native API's socket at `path`: a stale socket left there is
/// removed (anything else is refused). The new one is readable and
/// writable by the relay's user only (0600), unless other users are
/// allowed (`uids`): then 0660 with `group`, else 0666, the peer's
/// credentials deciding on each connection.
///
/// # Errors
///
/// When `path` holds something other than a socket, or binding fails.
pub fn bind(path: &Path, uids: &[u32], group: Option<u32>) -> std::io::Result<UnixListener> {
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
    let mode = match (uids.is_empty(), group) {
        (_, Some(gid)) => {
            std::os::unix::fs::chown(path, None, Some(gid))?;
            0o660
        }
        (true, None) => 0o600,
        (false, None) => 0o666,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
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
    /// Who is at the other end, for the audit log (`uid 1000`,
    /// `tcp 192.0.2.7:51234`).
    fn peer(&self) -> String;
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
    fn peer(&self) -> String {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        getsockopt(self, PeerCredentials).map_or_else(
            |_| "unix peer".to_owned(),
            |c| format!("uid {} pid {}", c.uid(), c.pid()),
        )
    }

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
    fn peer(&self) -> String {
        self.peer_addr()
            .map_or_else(|_| "tcp peer".to_owned(), |a| format!("tcp {a}"))
    }

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

/// A token's fingerprint: what a connection keeps of the token it
/// authenticated with, to find it gone after a rotation.
type Fingerprint = [u8; 32];

fn fingerprint(token: &[u8]) -> Fingerprint {
    use sha2::Digest;
    sha2::Sha256::digest(token).into()
}

/// The tokens TCP connections authenticate with: the configuration's,
/// and a file's (`tenant token` lines) re-read when it changes, looked at
/// once a second at most.
#[derive(Debug)]
pub struct TokenSet {
    inline: Tokens,
    file: Option<PathBuf>,
    state: Mutex<FileTokens>,
}

#[derive(Debug, Default)]
struct FileTokens {
    stamp: Option<(std::time::SystemTime, u64)>,
    tokens: Vec<(String, String)>,
    checked: Option<Instant>,
}

/// The `tenant token` lines of a tokens file; a short token is left out.
fn parse_tokens(text: &str, path: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_whitespace();
        match (f.next(), f.next(), f.next()) {
            (Some(tenant), Some(token), None) if token.len() >= 16 => {
                out.push((tenant.to_owned(), token.to_owned()));
            }
            // Never the token itself.
            _ => log::warn!(
                "native: {}: line {}: not `tenant token` with a token of 16 characters or more; left out",
                path.display(),
                n + 1
            ),
        }
    }
    out
}

impl TokenSet {
    /// The configuration's tokens, and the file's.
    ///
    /// # Errors
    ///
    /// When the file cannot be read at the start.
    pub fn new(inline: Tokens, file: Option<PathBuf>) -> std::io::Result<Self> {
        let set = TokenSet {
            inline,
            file,
            state: Mutex::new(FileTokens::default()),
        };
        if let Some(path) = &set.file {
            let text = std::fs::read_to_string(path)?;
            let meta = std::fs::metadata(path)?;
            let mut st = set
                .state
                .lock()
                .map_err(|_| std::io::Error::other("lock"))?;
            st.tokens = parse_tokens(&text, path);
            st.stamp = Some((meta.modified()?, meta.len()));
            st.checked = Some(Instant::now());
        }
        Ok(set)
    }

    /// Every token now: the file re-read if it changed. A file that cannot
    /// be read keeps the tokens it last gave (a rewrite in progress does
    /// not lock everyone out).
    fn current(&self) -> Vec<(String, String)> {
        let mut all: Vec<(String, String)> = self
            .inline
            .iter()
            .map(|(t, k)| (t.clone(), k.clone()))
            .collect();
        let (Some(path), Ok(mut st)) = (&self.file, self.state.lock()) else {
            return all;
        };
        if st
            .checked
            .is_none_or(|c| c.elapsed() >= Duration::from_secs(1))
        {
            st.checked = Some(Instant::now());
            let stamp = std::fs::metadata(path)
                .ok()
                .and_then(|m| Some((m.modified().ok()?, m.len())));
            if stamp.is_some() && stamp != st.stamp {
                match std::fs::read_to_string(path) {
                    Ok(text) => {
                        st.tokens = parse_tokens(&text, path);
                        st.stamp = stamp;
                        log::info!(
                            target: "rtpflux::audit",
                            "native tokens reloaded from {}: {} tokens",
                            path.display(),
                            st.tokens.len()
                        );
                    }
                    Err(e) => log::warn!("native: {}: {e}; the tokens before stay", path.display()),
                }
            }
        }
        all.extend(st.tokens.iter().cloned());
        all
    }

    /// The tenant a request's `auth` names with one of the tokens, and the
    /// token's fingerprint. Every token is compared, in constant time.
    fn authenticate(&self, body: &[u8]) -> Option<(String, Fingerprint)> {
        let v: serde_json::Value = serde_json::from_slice(body).ok()?;
        if v.get("op")?.as_str()? != "auth" {
            return None;
        }
        let given = v.get("token")?.as_str()?.as_bytes();
        self.current().iter().fold(None, |found, (tenant, token)| {
            if same(given, token.as_bytes()) {
                Some((tenant.clone(), fingerprint(given)))
            } else {
                found
            }
        })
    }

    /// Whether `tenant` still has the token of fingerprint `fp`.
    fn holds(&self, tenant: &str, fp: &Fingerprint) -> bool {
        self.current()
            .iter()
            .any(|(t, k)| t == tenant && same(&fingerprint(k.as_bytes()), fp))
    }
}

/// Serve the Unix socket `listener` until `stop` is set.
pub fn serve(listener: &UnixListener, link: &NativeLink, uids: &[u32], stop: &Arc<AtomicBool>) {
    let accept = || {
        let (s, _) = listener.accept()?;
        if allowed(&s, uids) {
            Ok(Some(s))
        } else {
            log::warn!(
                target: "rtpflux::audit",
                "native: refused {}: user not allowed",
                s.peer()
            );
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
    tokens: &Arc<TokenSet>,
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
    accept_loop(accept, link, Some(tokens), stop);
}

/// Accept connections from `accept` (`None`: refused) until `stop`.
fn accept_loop<S: Stream>(
    mut accept: impl FnMut() -> std::io::Result<Option<S>>,
    link: &NativeLink,
    tokens: Option<&Arc<TokenSet>>,
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

/// What a TCP connection's request gets before the control thread sees
/// it: an `auth` answered (the connection then that tenant's, its token's
/// fingerprint kept), or a refusal when its token was rotated away
/// (`failures` set so the connection closes). `None`: on to the control
/// thread.
fn gate(
    tokens: Option<&TokenSet>,
    origin: &mut Origin,
    token: &mut Option<Fingerprint>,
    body: &[u8],
    failures: &mut u32,
) -> Option<Vec<u8>> {
    let tokens = tokens?;
    let peer = &origin.peer;
    if let (Some(tenant), Some(fp)) = (origin.tenant.as_deref(), token.as_ref()) {
        if tokens.holds(tenant, fp) {
            return None;
        }
        log::warn!(
            target: "rtpflux::audit",
            "native: {peer}: tenant {tenant}: token revoked; connection closed"
        );
        *failures = 3;
        let op = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("operation_id").cloned());
        return Some(
            serde_json::to_vec(&json!({"v": 1, "operation_id": op, "ok": false,
                "error": {"code": "unauthorized", "message": "the connection's token was revoked"}}))
            .unwrap_or_default(),
        );
    }
    let found = tokens.authenticate(body);
    if let Some((tenant, _)) = &found {
        log::info!(target: "rtpflux::audit", "native: {peer}: authenticated as tenant {tenant}");
    } else {
        *failures += 1;
        log::warn!(target: "rtpflux::audit", "native: {peer}: authentication failed");
    }
    let r = auth_reply(body, found.as_ref().map(|(t, _)| t.as_str()));
    origin.tenant = found.as_ref().map(|(t, _)| t.clone());
    *token = found.map(|(_, fp)| fp);
    Some(r)
}

/// One connection: its requests in turn, its events as they come. With
/// `tokens` (TCP), its first request authenticates it.
fn connection<S: Stream>(
    mut stream: S,
    id: u64,
    link: &NativeLink,
    tokens: Option<&TokenSet>,
    stop: &Arc<AtomicBool>,
) {
    let _ = stream.read_timeout(POLL);
    let peer = stream.peer();
    let mut token: Option<Fingerprint> = None;
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
        peer: peer.clone(),
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
        let reply = gate(tokens, &mut origin, &mut token, &body, &mut failures);
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
        let tokens = TokenSet::new(
            [("a".to_owned(), "0123456789abcdef".to_owned())].into(),
            None,
        )
        .unwrap();
        let auth = |t: &str| {
            tokens
                .authenticate(format!(r#"{{"op":"auth","token":"{t}"}}"#).as_bytes())
                .map(|(tenant, _)| tenant)
        };
        assert_eq!(auth("0123456789abcdef").as_deref(), Some("a"));
        assert_eq!(auth("0123456789abcdeX"), None);
        assert_eq!(auth("0123456789abcde"), None);
        assert_eq!(auth(""), None);
        assert_eq!(tokens.authenticate(br#"{"op":"hello"}"#), None);
        assert_eq!(tokens.authenticate(b"nonsense"), None);
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }

    #[test]
    fn only_a_stale_socket_is_replaced() {
        let dir = std::env::temp_dir().join(format!("rtpflux-native-bind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api.sock");
        let first = bind(&path, &[], None).unwrap();
        drop(first);
        // The socket left behind is replaced.
        let _second = bind(&path, &[], None).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "the relay's user only");
        // Other users allowed: reachable, the peer's credentials decide.
        let _third = bind(&path, &[54_321], None).unwrap();
        assert_eq!(mode(&path), 0o666);
        // With a group (the relay's own, which needs no privilege).
        let gid = std::fs::metadata("/proc/self").unwrap().gid();
        let _fourth = bind(&path, &[54_321], Some(gid)).unwrap();
        assert_eq!(mode(&path), 0o660);
        assert_eq!(std::fs::metadata(&path).unwrap().gid(), gid);
        // A file is not.
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(bind(&file, &[], None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tokens_rotate_through_their_file() {
        let dir =
            std::env::temp_dir().join(format!("rtpflux-native-tokens-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tokens");
        std::fs::write(&path, "# rotation\na old-token-of-a-0001\nb short\n").unwrap();
        let set = TokenSet::new(Tokens::new(), Some(path.clone())).unwrap();
        let auth =
            |t: &str| set.authenticate(format!(r#"{{"op":"auth","token":"{t}"}}"#).as_bytes());
        let (tenant, old) = auth("old-token-of-a-0001").unwrap();
        assert_eq!(tenant, "a");
        assert!(auth("short").is_none(), "a short token is left out");
        // The new token next to the old (an overlap), then the old one gone.
        std::fs::write(&path, "a old-token-of-a-0001\na new-token-of-a-0002\n").unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        let (_, new) = auth("new-token-of-a-0002").unwrap();
        assert!(set.holds("a", &old) && set.holds("a", &new));
        std::fs::write(&path, "a new-token-of-a-0002\n").unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!set.holds("a", &old), "revoked");
        assert!(set.holds("a", &new) && !set.holds("b", &new));
        assert!(auth("old-token-of-a-0001").is_none());
        // Unreadable for a moment (a rewrite): the tokens stay.
        std::fs::remove_file(&path).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        assert!(set.holds("a", &new));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
