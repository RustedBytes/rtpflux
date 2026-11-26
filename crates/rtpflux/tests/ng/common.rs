//! Helpers shared by the ng tests: a relay with its ng server, requests,
//! endpoints and SDP.

use rtpflux::config::Config;
use rtpflux::control::{Control, serve};
use rtpflux::relay::Relay;
use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
use rtpflux_ng::bencode::{Encoder, Value, decode};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

pub(crate) struct Server {
    pub(crate) addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub(crate) fn server(first_port: u16) -> Server {
    server_with(first_port, "")
}

/// [`server`] with more `[sessions]` settings (e.g. timeouts).
pub(crate) fn server_with(first_port: u16, sessions: &str) -> Server {
    server_on(
        first_port,
        "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
        sessions,
    )
}

/// [`server_with`] on these `[[interface]]`s.
pub(crate) fn server_on(first_port: u16, interfaces: &str, sessions: &str) -> Server {
    server_full(first_port, interfaces, sessions, 1)
}

/// [`server_on`] with this many media workers. They receive as the
/// configuration's default says (`io_uring`), or as `RTPFLUX_TEST_RECEIVE`
/// (`recvmmsg`, `io_uring`) says, so the whole suite can run with either.
pub(crate) fn server_full(
    first_port: u16,
    interfaces: &str,
    sessions: &str,
    workers: usize,
) -> Server {
    let receive = std::env::var("RTPFLUX_TEST_RECEIVE").unwrap_or_else(|_| "io_uring".to_owned());
    server_receiving(first_port, interfaces, sessions, (workers, &receive))
}

/// [`server_full`] receiving with `receive` (`recvmmsg`, `io_uring`).
pub(crate) fn server_receiving(
    first_port: u16,
    interfaces: &str,
    sessions: &str,
    (workers, receive): (usize, &str),
) -> Server {
    crate::logging::init();
    let toml = format!(
        r#"
        {interfaces}
        [ports]
        min = {first_port}
        max = {}
        [sessions]
        max = 8
        {sessions}
        [runtime]
        workers = {workers}
        receive = "{receive}"
        "#,
        first_port + 63
    );
    let config = Config::from_toml(&toml).unwrap();
    let relay = Relay::start(&config).unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_nonblocking(true).unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let interfaces = config.interfaces.clone();
    let offer_timeout = Duration::from_secs(config.sessions.offer_timeout);
    let final_timeout = config.sessions.final_timeout;
    let strict_source = config.sessions.strict_source;
    let thread = std::thread::spawn(move || {
        let mut control = Control::new(relay, interfaces);
        control.set_offer_timeout(offer_timeout);
        control.set_final_timeout(final_timeout);
        control.set_strict_source(strict_source);
        serve(&mut control, &[sock], &stop_t).unwrap();
    });
    Server {
        addr,
        stop,
        thread: Some(thread),
    }
}

/// Encode a request: `cookie d<sorted pairs>e`. Values are byte strings,
/// lists of byte strings, or integers.
#[derive(Clone, Copy)]
pub(crate) enum V<'a> {
    S(&'a [u8]),
    L(&'a [&'a [u8]]),
    I(i64),
    /// A value already bencoded (a dictionary, say).
    Raw(&'a [u8]),
}

pub(crate) fn request(cookie: &str, pairs: &[(&str, V<'_>)]) -> Vec<u8> {
    let mut sorted: Vec<_> = pairs.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    let mut buf = vec![0u8; 8192];
    let mut e = Encoder::new(&mut buf);
    e.raw(cookie.as_bytes()).unwrap();
    e.raw(b" ").unwrap();
    e.dict().unwrap();
    for (k, v) in sorted {
        e.bytes(k.as_bytes()).unwrap();
        match v {
            V::S(s) => e.bytes(s).unwrap(),
            V::I(n) => e.int(*n).unwrap(),
            V::Raw(r) => e.raw(r).unwrap(),
            V::L(items) => {
                e.list().unwrap();
                for i in *items {
                    e.bytes(i).unwrap();
                }
                e.end().unwrap();
            }
        }
    }
    e.end().unwrap();
    let n = e.len();
    buf.truncate(n);
    buf
}

/// Send a request and return (result, sdp or error-reason).
pub(crate) fn call(
    client: &UdpSocket,
    server: SocketAddr,
    req: &[u8],
) -> (String, Vec<u8>, Vec<u8>) {
    client.send_to(req, server).unwrap();
    let mut buf = vec![0u8; 65_535];
    let (n, _) = client.recv_from(&mut buf).expect("reply");
    let raw = buf[..n].to_vec();
    let space = raw.iter().position(|&b| b == b' ').unwrap();
    let Ok(Value::Dict(d)) = decode(&raw[space + 1..]) else {
        panic!("reply is not a dictionary")
    };
    let result = String::from_utf8(d.get_bytes(b"result").unwrap().to_vec()).unwrap();
    let extra = d
        .get_bytes(b"sdp")
        .or_else(|| d.get_bytes(b"error-reason"))
        .unwrap_or_default()
        .to_vec();
    (result, extra, raw)
}

pub(crate) fn sdp_for(port: u16) -> Vec<u8> {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\na=sendrecv\r\n"
    )
    .into_bytes()
}

pub(crate) fn first_media(sdp: &[u8]) -> Media {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    let n = read_media(sdp, &mut m).unwrap();
    assert_eq!(n, 1);
    m[0]
}

pub(crate) fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}

// ---------------------------------------------------------------- SRTP

pub(crate) const KEY_A_B64: &str = "4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm";

pub(crate) const KEY_A: [u8; 30] = [
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
];

pub(crate) fn rtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0, 0, 0, 0, 0, 0, 160, 1, 2, 3, 4];
    p[2..4].copy_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[9; 40]);
    p
}

// ---------------------------------------------------------------- DTLS-SRTP

pub(crate) fn sdp_line<'a>(sdp: &'a str, prefix: &str) -> Option<&'a str> {
    sdp.split("\r\n").find_map(|l| l.strip_prefix(prefix))
}

// ---------------------------------------------------------------- list, query

/// The reply dictionary of a raw `ng` reply (`cookie SP bencode`).
pub(crate) fn reply_dict(raw: &[u8]) -> Value<'_> {
    let space = raw.iter().position(|&c| c == b' ').unwrap();
    decode(&raw[space + 1..]).expect("bencode reply")
}

/// The value at `path` (dictionary keys) inside `v`.
pub(crate) fn at<'a>(v: Value<'a>, path: &[&[u8]]) -> Option<Value<'a>> {
    path.iter().try_fold(v, |v, k| match v {
        Value::Dict(d) => d.get(k),
        Value::List(l) => {
            let i: usize = std::str::from_utf8(k).ok()?.parse().ok()?;
            l.iter().nth(i)
        }
        _ => None,
    })
}

/// The `m=` ports of an SDP.
pub(crate) fn m_ports(sdp: &[u8]) -> Vec<u16> {
    String::from_utf8_lossy(sdp)
        .split("\r\n")
        .filter(|l| l.starts_with("m="))
        .map(|l| l.split(' ').nth(1).unwrap().parse().unwrap())
        .collect()
}

// ------------------------------------------------- re-INVITEs and hold

/// Offer or answer `sdp` with plain RTP (addresses from the SDP, no
/// learning); returns the rewritten SDP.
pub(crate) fn exchange_sdp(
    client: &UdpSocket,
    srv: SocketAddr,
    cookie: &str,
    command: &[u8],
    tags: (&[u8], Option<&[u8]>),
    sdp: &[u8],
) -> Vec<u8> {
    let mut pairs = vec![
        ("command", V::S(command)),
        ("call-id", V::S(b"reinvite@example")),
        ("from-tag", V::S(tags.0)),
        ("sdp", V::S(sdp)),
        ("flags", V::L(&[b"trust-address"])),
        ("endpoint-learning", V::S(b"off")),
    ];
    if let Some(t) = tags.1 {
        pairs.push(("to-tag", V::S(t)));
    }
    let (result, out, _) = call(client, srv, &request(cookie, &pairs));
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&out));
    out
}

/// One packet each way between `x` (sending to `rx`) and `y` (sending to
/// `ry`), checked intact.
pub(crate) fn both_ways(x: &UdpSocket, rx: SocketAddr, y: &UdpSocket, ry: SocketAddr, seq: u16) {
    let mut buf = [0u8; 2048];
    let p = rtp(seq);
    x.send_to(&p, rx).unwrap();
    let (n, _) = y.recv_from(&mut buf).expect("x -> y");
    assert_eq!(&buf[..n], &p[..]);
    y.send_to(&p, ry).unwrap();
    let (n, _) = x.recv_from(&mut buf).expect("y -> x");
    assert_eq!(&buf[..n], &p[..]);
}

pub(crate) fn relay_addr(sdp: &[u8]) -> SocketAddr {
    SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(sdp).port)
}

// ------------------------------------------------------ G.711 transcoding

pub(crate) fn m_line(sdp: &[u8]) -> String {
    String::from_utf8_lossy(sdp)
        .lines()
        .find(|l| l.starts_with("m="))
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn rtp_with(pt: u8, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = rtp(seq);
    p[1] = pt;
    p.truncate(12);
    p.extend_from_slice(payload);
    p
}
