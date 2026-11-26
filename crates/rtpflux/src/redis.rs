//! The dialogs in Redis, alongside or instead of the state file
//! ([`crate::state`]), so another host (or this one with a fresh disk) can
//! take the calls over.
//!
//! A small RESP2 client over TCP: `AUTH`, `SELECT`, `SET` and `GET`, which
//! is all the state needs (no TLS: run it on the host or a private
//! network). Writes go through one thread that keeps only the newest
//! snapshot, so a slow or unreachable server never holds up the control
//! thread; reads happen once, at start.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The default key.
pub const DEFAULT_KEY: &str = "rtpflux:state";
/// Connect, read and write timeout of one operation.
const TIMEOUT: Duration = Duration::from_secs(2);
/// Wait before retrying a failed write.
const RETRY: Duration = Duration::from_secs(1);
/// How long a stopping relay waits for its last snapshot to be written.
const CLOSE_WAIT: Duration = Duration::from_secs(3);
/// A value longer than this is refused when read (a corrupt length).
const MAX_VALUE: usize = 512 << 20;
/// A reply line longer than this is refused.
const MAX_LINE: usize = 4096;

/// Where the state goes: `redis://[[user]:password@]host[:port][/db]`.
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    host: String,
    port: u16,
    db: u32,
    user: Option<String>,
    password: Option<String>,
    key: String,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

/// Why a `redis` URL or key cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// `rediss://`: TLS is not supported.
    Tls,
    /// Not a `redis://` URL.
    NotRedis,
    /// An empty key.
    EmptyKey,
    /// A database that is not a number.
    BadDatabase(String),
    /// An IPv6 host without its `]`.
    UnclosedBracket,
    /// A port that is not a number.
    BadPort(String),
    /// Text after an IPv6 host that is not a port.
    AfterHost(String),
    /// No host, or port 0.
    NoHost,
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetError::Tls => f.write_str("rediss:// (TLS) is not supported"),
            TargetError::NotRedis => {
                f.write_str("expected redis://[[user]:password@]host[:port][/db]")
            }
            TargetError::EmptyKey => f.write_str("the key must not be empty"),
            TargetError::BadDatabase(db) => write!(f, "bad database {db:?}"),
            TargetError::UnclosedBracket => f.write_str("unclosed [ in the host"),
            TargetError::BadPort(p) => write!(f, "bad port {p:?}"),
            TargetError::AfterHost(a) => write!(f, "unexpected {a:?} after the host"),
            TargetError::NoHost => f.write_str("a host and a non-zero port are required"),
        }
    }
}

impl std::error::Error for TargetError {}

impl Target {
    /// Parse a `redis://` URL; the state is kept under `key`.
    ///
    /// # Errors
    ///
    /// A URL that is not `redis://` (`rediss://` is not supported), an
    /// empty host, a bad port or database number, or an empty key.
    pub fn parse(url: &str, key: &str) -> Result<Self, TargetError> {
        let rest = match url.split_once("://") {
            Some(("redis", rest)) => rest,
            Some(("rediss", _)) => return Err(TargetError::Tls),
            _ => return Err(TargetError::NotRedis),
        };
        if key.is_empty() {
            return Err(TargetError::EmptyKey);
        }
        let (auth, rest) = match rest.rsplit_once('@') {
            Some((a, r)) => (Some(a), r),
            None => (None, rest),
        };
        let (user, password) = match auth {
            None => (None, None),
            Some(a) => match a.split_once(':') {
                Some((u, p)) => ((!u.is_empty()).then(|| u.to_owned()), Some(p.to_owned())),
                None => (Some(a.to_owned()), None),
            },
        };
        let (hostport, db) = match rest.split_once('/') {
            Some((hp, "")) => (hp, 0),
            Some((hp, db)) => (
                hp,
                db.parse()
                    .map_err(|_| TargetError::BadDatabase(db.to_owned()))?,
            ),
            None => (rest, 0),
        };
        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or(TargetError::UnclosedBracket)?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| TargetError::BadPort(p.to_owned()))?,
                None if after.is_empty() => 6379,
                None => return Err(TargetError::AfterHost(after.to_owned())),
            };
            (h.to_owned(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_owned(),
                    p.parse().map_err(|_| TargetError::BadPort(p.to_owned()))?,
                ),
                None => (hostport.to_owned(), 6379),
            }
        };
        if host.is_empty() || port == 0 {
            return Err(TargetError::NoHost);
        }
        Ok(Target {
            host,
            port,
            db,
            user,
            password,
            key: key.to_owned(),
        })
    }

    /// Whether the URL carries a password (`AUTH` is sent).
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Whether the server is on this host (`localhost` or a loopback
    /// address), so the state never crosses a network.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_loopback())
    }

    /// The target without its password, for logs and the web UI.
    #[must_use]
    pub fn describe(&self) -> String {
        let auth = match (&self.user, &self.password) {
            (Some(u), Some(_)) => format!("{u}:***@"),
            (None, Some(_)) => ":***@".to_owned(),
            (Some(u), None) => format!("{u}@"),
            (None, None) => String::new(),
        };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!(
            "redis://{auth}{host}:{}/{} key {}",
            self.port, self.db, self.key
        )
    }

    /// Read the state, `Ok(None)` when the key does not exist.
    ///
    /// # Errors
    ///
    /// When the server cannot be reached or refuses.
    pub fn get(&self) -> io::Result<Option<Vec<u8>>> {
        let mut c = Conn::open(self)?;
        match c.command(&[b"GET", self.key.as_bytes()])? {
            Reply::Bulk(v) => Ok(v),
            other => Err(unexpected(&other)),
        }
    }

    /// Write `value` under the key.
    ///
    /// # Errors
    ///
    /// When the server cannot be reached or refuses.
    pub fn set(&self, value: &[u8]) -> io::Result<()> {
        Conn::open(self)?.set(&self.key, value)
    }
}

/// A RESP reply (arrays are not needed here and are refused).
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Simple(String),
    Int(i64),
    Bulk(Option<Vec<u8>>),
}

fn unexpected(r: &Reply) -> io::Error {
    io::Error::other(format!("unexpected reply {r:?}"))
}

/// One connection, authenticated and on its database.
struct Conn {
    stream: BufReader<TcpStream>,
}

impl Conn {
    fn open(t: &Target) -> io::Result<Self> {
        let mut last = io::Error::other(format!("{}: no address", t.host));
        for addr in (t.host.as_str(), t.port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, TIMEOUT) {
                Ok(s) => {
                    s.set_read_timeout(Some(TIMEOUT))?;
                    s.set_write_timeout(Some(TIMEOUT))?;
                    s.set_nodelay(true)?;
                    let mut c = Conn {
                        stream: BufReader::new(s),
                    };
                    if let Some(p) = &t.password {
                        let r = match &t.user {
                            Some(u) => c.command(&[b"AUTH", u.as_bytes(), p.as_bytes()])?,
                            None => c.command(&[b"AUTH", p.as_bytes()])?,
                        };
                        c.ok(&r)?;
                    }
                    if t.db != 0 {
                        let r = c.command(&[b"SELECT", t.db.to_string().as_bytes()])?;
                        c.ok(&r)?;
                    }
                    return Ok(c);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    #[allow(clippy::unused_self)]
    fn ok(&self, r: &Reply) -> io::Result<()> {
        match r {
            Reply::Simple(s) if s == "OK" => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn set(&mut self, key: &str, value: &[u8]) -> io::Result<()> {
        let r = self.command(&[b"SET", key.as_bytes(), value])?;
        self.ok(&r)
    }

    /// Send one command and read its reply; an error reply is an `Err`.
    fn command(&mut self, args: &[&[u8]]) -> io::Result<Reply> {
        let mut out = Vec::with_capacity(32 + args.iter().map(|a| a.len() + 16).sum::<usize>());
        write!(out, "*{}\r\n", args.len())?;
        for a in args {
            write!(out, "${}\r\n", a.len())?;
            out.extend_from_slice(a);
            out.extend_from_slice(b"\r\n");
        }
        self.stream.get_mut().write_all(&out)?;
        self.reply()
    }

    fn line(&mut self) -> io::Result<String> {
        let mut buf = Vec::new();
        io::Read::take(&mut self.stream, MAX_LINE as u64).read_until(b'\n', &mut buf)?;
        if !buf.ends_with(b"\r\n") {
            return Err(io::Error::other("bad or truncated reply line"));
        }
        buf.truncate(buf.len() - 2);
        String::from_utf8(buf).map_err(|_| io::Error::other("reply line not UTF-8"))
    }

    fn reply(&mut self) -> io::Result<Reply> {
        let line = self.line()?;
        let (kind, rest) = line
            .split_at_checked(1)
            .ok_or_else(|| io::Error::other("empty reply"))?;
        match kind {
            "+" => Ok(Reply::Simple(rest.to_owned())),
            "-" => Err(io::Error::other(format!("server error: {rest}"))),
            ":" => rest
                .parse()
                .map(Reply::Int)
                .map_err(|_| io::Error::other("bad integer reply")),
            "$" => {
                let n: i64 = rest
                    .parse()
                    .map_err(|_| io::Error::other("bad bulk length"))?;
                if n < 0 {
                    return Ok(Reply::Bulk(None));
                }
                let n = usize::try_from(n)
                    .ok()
                    .filter(|&n| n <= MAX_VALUE)
                    .ok_or_else(|| io::Error::other("value too long"))?;
                let mut v = vec![0; n + 2];
                io::Read::read_exact(&mut self.stream, &mut v)?;
                if !v.ends_with(b"\r\n") {
                    return Err(io::Error::other("bulk value not terminated"));
                }
                v.truncate(n);
                Ok(Reply::Bulk(Some(v)))
            }
            _ => Err(io::Error::other(format!("unsupported reply type {kind:?}"))),
        }
    }
}

/// What the writer thread is handed.
#[derive(Default)]
struct Pending {
    /// The newest snapshot not yet written.
    latest: Option<Vec<u8>>,
    /// Stop once `latest` is written, or at this time.
    closing: Option<Instant>,
}

type Shared = Arc<(Mutex<Pending>, Condvar)>;

/// Writes snapshots to Redis in the background, the newest one only.
pub struct Writer {
    target: Target,
    shared: Shared,
    thread: Option<JoinHandle<()>>,
    counts: Arc<WriterCounts>,
}

/// What the writer thread did: snapshots written, failed attempts, and
/// whether it is failing now.
#[derive(Debug, Default)]
pub struct WriterCounts {
    pub written: std::sync::atomic::AtomicU64,
    pub failures: std::sync::atomic::AtomicU64,
    pub failing: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Writer({})", self.target.describe())
    }
}

impl Writer {
    /// Start the writer thread for `target`.
    ///
    /// # Errors
    ///
    /// When the thread cannot be started.
    pub fn spawn(target: Target) -> io::Result<Self> {
        let shared: Shared = Arc::default();
        let counts: Arc<WriterCounts> = Arc::default();
        let thread = {
            let (shared, target, counts) =
                (Arc::clone(&shared), target.clone(), Arc::clone(&counts));
            std::thread::Builder::new()
                .name("rtpflux-redis".to_owned())
                .spawn(move || run(&target, &shared, &counts))?
        };
        Ok(Writer {
            target,
            shared,
            thread: Some(thread),
            counts,
        })
    }

    /// Where it writes.
    #[must_use]
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// What it did so far.
    #[must_use]
    pub fn counts(&self) -> &WriterCounts {
        &self.counts
    }

    /// Hand over a snapshot; one not yet written is replaced.
    pub fn put(&self, value: Vec<u8>) {
        let (lock, cv) = &*self.shared;
        lock.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .latest = Some(value);
        cv.notify_one();
    }
}

impl Drop for Writer {
    /// Write the last snapshot handed over, waiting at most a few seconds.
    fn drop(&mut self) {
        {
            let (lock, cv) = &*self.shared;
            lock.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .closing = Some(Instant::now() + CLOSE_WAIT);
            cv.notify_one();
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The writer thread: wait for a snapshot, write it, keep it to retry on
/// failure unless a newer one came.
fn run(target: &Target, shared: &Shared, counts: &WriterCounts) {
    use std::sync::atomic::Ordering::Relaxed;
    let (lock, cv) = &**shared;
    let mut conn: Option<Conn> = None;
    let mut failing = false;
    loop {
        let value = {
            let mut p = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(v) = p.latest.take() {
                    break v;
                }
                if p.closing.is_some() {
                    return;
                }
                p = cv
                    .wait(p)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        let written = match conn.as_mut() {
            Some(c) => c.set(&target.key, &value),
            None => Conn::open(target).and_then(|mut c| {
                let r = c.set(&target.key, &value);
                conn = Some(c);
                r
            }),
        };
        match written {
            Ok(()) => {
                counts.written.fetch_add(1, Relaxed);
                counts.failing.store(false, Relaxed);
                if failing {
                    log::info!("state: writing to {} again", target.describe());
                    failing = false;
                }
            }
            Err(e) => {
                counts.failures.fetch_add(1, Relaxed);
                counts.failing.store(true, Relaxed);
                conn = None;
                if !failing {
                    log::warn!("state: writing to {}: {e}; retrying", target.describe());
                    failing = true;
                }
                let mut p = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if p.latest.is_none() {
                    p.latest = Some(value);
                }
                // Wait to retry, unless the relay is stopping and its time
                // is up.
                match p.closing {
                    Some(deadline) if Instant::now() >= deadline => {
                        log::warn!(
                            "state: the last snapshot did not reach {}",
                            target.describe()
                        );
                        return;
                    }
                    Some(deadline) => {
                        let wait = RETRY.min(deadline.saturating_duration_since(Instant::now()));
                        drop(cv.wait_timeout(p, wait));
                    }
                    None => drop(cv.wait_timeout(p, RETRY)),
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;

    /// A RESP server holding keys in memory: `AUTH pw` (when it has a
    /// password), `SELECT`, `SET`, `GET`; `down` makes it close connections.
    /// Keys by (database, key).
    type Db = Mutex<HashMap<(u32, Vec<u8>), Vec<u8>>>;

    pub(crate) struct Fake {
        pub addr: std::net::SocketAddr,
        pub data: Arc<Db>,
        pub down: Arc<std::sync::atomic::AtomicBool>,
        pub sets: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Fake {
        pub(crate) fn start(password: Option<&str>) -> Fake {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let fake = Fake {
                addr,
                data: Arc::default(),
                down: Arc::default(),
                sets: Arc::default(),
            };
            let (data, down, sets) = (
                Arc::clone(&fake.data),
                Arc::clone(&fake.down),
                Arc::clone(&fake.sets),
            );
            let password = password.map(str::to_owned);
            std::thread::spawn(move || {
                for s in l.incoming().flatten() {
                    let (data, down, sets, password) = (
                        Arc::clone(&data),
                        Arc::clone(&down),
                        Arc::clone(&sets),
                        password.clone(),
                    );
                    std::thread::spawn(move || serve(s, &data, &down, &sets, password.as_deref()));
                }
            });
            fake
        }

        pub(crate) fn url(&self) -> String {
            format!("redis://{}", self.addr)
        }
    }

    fn serve(
        stream: TcpStream,
        data: &Db,
        down: &std::sync::atomic::AtomicBool,
        sets: &std::sync::atomic::AtomicUsize,
        password: Option<&str>,
    ) {
        use std::sync::atomic::Ordering;
        let mut out = stream.try_clone().unwrap();
        let mut input = BufReader::new(stream);
        let mut authed = password.is_none();
        let mut db = 0;
        let mut line = String::new();
        loop {
            line.clear();
            if input.read_line(&mut line).unwrap_or(0) == 0 || down.load(Ordering::SeqCst) {
                return;
            }
            let n: usize = line.trim_end()[1..].parse().unwrap();
            let mut args = Vec::new();
            for _ in 0..n {
                line.clear();
                input.read_line(&mut line).unwrap();
                let len: usize = line.trim_end()[1..].parse().unwrap();
                let mut v = vec![0; len + 2];
                io::Read::read_exact(&mut input, &mut v).unwrap();
                v.truncate(len);
                args.push(v);
            }
            let reply: Vec<u8> = match (args[0].as_slice(), authed) {
                (b"AUTH", _) => {
                    if password.is_some_and(|p| args.last().unwrap() == p.as_bytes()) {
                        authed = true;
                        b"+OK\r\n".to_vec()
                    } else {
                        b"-WRONGPASS invalid password\r\n".to_vec()
                    }
                }
                (_, false) => b"-NOAUTH Authentication required.\r\n".to_vec(),
                (b"SELECT", true) => {
                    db = std::str::from_utf8(&args[1]).unwrap().parse().unwrap();
                    b"+OK\r\n".to_vec()
                }
                (b"SET", true) => {
                    sets.fetch_add(1, Ordering::SeqCst);
                    data.lock()
                        .unwrap()
                        .insert((db, args[1].clone()), args[2].clone());
                    b"+OK\r\n".to_vec()
                }
                (b"GET", true) => match data.lock().unwrap().get(&(db, args[1].clone())) {
                    Some(v) => {
                        let mut out = format!("${}\r\n", v.len()).into_bytes();
                        out.extend_from_slice(v);
                        out.extend_from_slice(b"\r\n");
                        out
                    }
                    None => b"$-1\r\n".to_vec(),
                },
                _ => b"-ERR unknown command\r\n".to_vec(),
            };
            if out.write_all(&reply).is_err() {
                return;
            }
        }
    }

    #[test]
    fn urls() {
        let t = Target::parse("redis://127.0.0.1", DEFAULT_KEY).unwrap();
        assert_eq!((t.host.as_str(), t.port, t.db), ("127.0.0.1", 6379, 0));
        let t = Target::parse("redis://:s3cret@cache.local:6380/2", "k").unwrap();
        assert_eq!((t.host.as_str(), t.port, t.db), ("cache.local", 6380, 2));
        assert_eq!(
            (t.user.as_deref(), t.password.as_deref()),
            (None, Some("s3cret"))
        );
        assert_eq!(t.describe(), "redis://:***@cache.local:6380/2 key k");
        let t = Target::parse("redis://relay:p@ss:w@[::1]:7000/", "k").unwrap();
        assert_eq!(
            (t.user.as_deref(), t.password.as_deref()),
            (Some("relay"), Some("p@ss:w"))
        );
        assert_eq!((t.host.as_str(), t.port), ("::1", 7000));
        assert!(!format!("{t:?}").contains("p@ss"), "no password in Debug");
        for (bad, why) in [
            ("rediss://h", TargetError::Tls),
            ("http://h", TargetError::NotRedis),
            ("redis://", TargetError::NoHost),
            ("redis://h:x", TargetError::BadPort("x".to_owned())),
            ("redis://h:0", TargetError::NoHost),
            ("redis://h/x", TargetError::BadDatabase("x".to_owned())),
            ("redis://[::1", TargetError::UnclosedBracket),
            ("redis://[::1]x", TargetError::AfterHost("x".to_owned())),
        ] {
            assert_eq!(Target::parse(bad, "k").unwrap_err(), why, "{bad}");
        }
        assert_eq!(
            Target::parse("redis://h", "").unwrap_err(),
            TargetError::EmptyKey
        );
        assert_eq!(
            TargetError::BadPort("x".to_owned()).to_string(),
            "bad port \"x\""
        );
    }

    #[test]
    fn set_and_get_with_auth_and_database() {
        let fake = Fake::start(Some("pw"));
        let url = format!("redis://:pw@{}/3", fake.addr);
        let t = Target::parse(&url, "state").unwrap();
        assert_eq!(t.get().unwrap(), None);
        t.set(b"{\"version\":1}").unwrap();
        assert_eq!(t.get().unwrap().as_deref(), Some(&b"{\"version\":1}"[..]));
        assert!(
            fake.data
                .lock()
                .unwrap()
                .contains_key(&(3, b"state".to_vec()))
        );
        // A large value (bulk lengths, partial reads) and binary octets.
        let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        t.set(&big).unwrap();
        assert_eq!(t.get().unwrap(), Some(big));
        // Wrong password: refused.
        let bad = Target::parse(&format!("redis://:nope@{}", fake.addr), "state").unwrap();
        assert!(bad.get().is_err());
    }

    #[test]
    fn the_writer_keeps_the_newest_and_retries() {
        use std::sync::atomic::Ordering;
        let fake = Fake::start(None);
        let t = Target::parse(&fake.url(), "s").unwrap();
        let w = Writer::spawn(t.clone()).unwrap();
        w.put(b"one".to_vec());
        let until = |want: &[u8]| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if fake
                    .data
                    .lock()
                    .unwrap()
                    .get(&(0, b"s".to_vec()))
                    .map(Vec::as_slice)
                    == Some(want)
                {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        };
        assert!(until(b"one"));
        // Down: the newest snapshot is written once it is back.
        fake.down.store(true, Ordering::SeqCst);
        w.put(b"two".to_vec());
        std::thread::sleep(Duration::from_millis(200));
        w.put(b"three".to_vec());
        std::thread::sleep(Duration::from_millis(200));
        fake.down.store(false, Ordering::SeqCst);
        assert!(until(b"three"));
        // The last snapshot is written when the writer is dropped.
        w.put(b"last".to_vec());
        drop(w);
        assert_eq!(
            fake.data
                .lock()
                .unwrap()
                .get(&(0, b"s".to_vec()))
                .map(Vec::as_slice),
            Some(&b"last"[..])
        );
        assert!(fake.sets.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn an_unreachable_server_does_not_hold_the_caller() {
        // Nothing listens on a port just freed.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let t = Target::parse(&format!("redis://127.0.0.1:{port}"), "s").unwrap();
        assert!(t.get().is_err());
        let w = Writer::spawn(t).unwrap();
        let start = Instant::now();
        for i in 0..100u8 {
            w.put(vec![i]);
        }
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "put never blocks"
        );
        let start = Instant::now();
        drop(w);
        assert!(
            start.elapsed() < CLOSE_WAIT + Duration::from_secs(2),
            "gives up at its deadline"
        );
    }
}
