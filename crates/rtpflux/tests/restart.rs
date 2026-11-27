//! Calls survive a restart: the dialogs are written to the state file and a
//! new relay recreates them on the same ports with the same keys, so the
//! endpoints, which know nothing of the restart, carry on.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::control::Control;
use rtpflux::relay::Relay;
use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
use rtpflux_ng::bencode::{Encoder, Value, decode};
use rtpflux_srtp::{MasterKey, Protect, Unprotect};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const KEY: &str = "4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm";

/// A relay keeping its state in `state`, on 64 ports of its own (the
/// same ones for the same state file, so a restart finds its calls' ports
/// free while other tests run).
fn control(state: &std::path::Path) -> Control {
    static BLOCKS: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());
    logging::init();
    let block = {
        let mut b = BLOCKS.lock().unwrap();
        b.iter().position(|p| p == state).unwrap_or_else(|| {
            b.push(state.to_path_buf());
            b.len() - 1
        })
    };
    let min = 48_000 + 64 * u16::try_from(block).unwrap();
    let toml = format!(
        r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {min}
        max = {}
        [sessions]
        max = 8
        [runtime]
        workers = 2
    "#,
        min + 63
    );
    let config = Config::from_toml(&toml).unwrap();
    let mut c = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    c.set_state_file(Some(state.to_path_buf()));
    c
}

fn request(cookie: &str, pairs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut sorted: Vec<_> = pairs.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    let mut buf = vec![0u8; 8192];
    let mut e = Encoder::new(&mut buf);
    e.raw(cookie.as_bytes()).unwrap();
    e.raw(b" ").unwrap();
    e.dict().unwrap();
    for (k, v) in sorted {
        e.bytes(k.as_bytes()).unwrap();
        e.bytes(v).unwrap();
    }
    e.end().unwrap();
    let n = e.len();
    buf.truncate(n);
    buf
}

fn sdp_of(reply: &[u8]) -> Vec<u8> {
    let space = reply.iter().position(|&c| c == b' ').unwrap();
    let Ok(Value::Dict(d)) = decode(&reply[space + 1..]) else {
        panic!()
    };
    assert_eq!(
        d.get_bytes(b"result"),
        Some(&b"ok"[..]),
        "{}",
        String::from_utf8_lossy(reply)
    );
    d.get_bytes(b"sdp").unwrap_or_default().to_vec()
}

fn media(sdp: &[u8]) -> Media {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(sdp, &mut m).unwrap();
    m[0]
}

fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}

fn rtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0, 0, 0, 0, 0, 0, 160, 0, 0, 0, 7];
    p[2..4].copy_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[3; 40]);
    p
}

/// A (SRTP with `KEY`) sends to `to_relay_a`; B (plain) gets it; B sends
/// back; A decrypts it with the relay's key.
fn media_flows(
    a: &UdpSocket,
    b: &UdpSocket,
    relays: (SocketAddr, SocketAddr),
    tx: &mut Protect,
    rx: &mut Unprotect,
    seq: u16,
) {
    let mut buf = [0u8; 2048];
    let plain = rtp(seq);
    let mut wire = plain.clone();
    wire.resize(plain.len() + 10, 0);
    tx.rtp(&mut wire, plain.len()).unwrap();
    a.send_to(&wire, relays.0).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("B gets A's media");
    assert_eq!(&buf[..n], &plain[..]);
    b.send_to(&plain, relays.1).unwrap();
    let (n, _) = a.recv_from(&mut buf).expect("A gets B's media");
    let n = rx.rtp(&mut buf, n).expect("under the relay's key");
    assert_eq!(&buf[..n], &plain[..]);
}

/// B re-INVITEs (From: B, To: A) with its own SDP, A answers with its
/// original one: the dialog's roles swap, the relay ports (`ports`, towards
/// A and B) and the relay's key towards A stay.
fn answerer_reinvites(
    c: &mut Control,
    (offer, answer): (&str, &str),
    ports: (u16, u16),
    relay_key: MasterKey,
) {
    let reoffer = sdp_of(
        c.handle(&request(
            "2a",
            &[
                ("command", b"offer"),
                ("call-id", b"restart-1"),
                ("from-tag", b"t"),
                ("to-tag", b"f"),
                ("sdp", answer.as_bytes()),
                ("transport-protocol", b"RTP/SAVP"),
                ("endpoint-learning", b"off"),
            ],
        ))
        .unwrap(),
    );
    let again = media(&reoffer);
    assert_eq!(again.port, ports.0, "A's relay port stays");
    assert_eq!(again.crypto.expect("SDES towards A").key, relay_key);
    let reanswer = sdp_of(
        c.handle(&request(
            "2b",
            &[
                ("command", b"answer"),
                ("call-id", b"restart-1"),
                ("from-tag", b"t"),
                ("to-tag", b"f"),
                ("sdp", offer.as_bytes()),
                ("endpoint-learning", b"off"),
            ],
        ))
        .unwrap(),
    );
    assert_eq!(media(&reanswer).port, ports.1, "B's relay port stays");
}

#[test]
fn calls_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let _ = std::fs::remove_file(&state);
    let (a, b) = (endpoint(), endpoint());
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY}\r\n",
        a.local_addr().unwrap().port()
    );
    let answer = format!(
        "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\n",
        b.local_addr().unwrap().port()
    );
    let mut c = control(&state);
    let to_b = sdp_of(
        c.handle(&request(
            "1",
            &[
                ("command", b"offer"),
                ("call-id", b"restart-1"),
                ("from-tag", b"f"),
                ("sdp", offer.as_bytes()),
                ("transport-protocol", b"RTP/AVP"),
                ("endpoint-learning", b"off"),
            ],
        ))
        .unwrap(),
    );
    let to_a = sdp_of(
        c.handle(&request(
            "2",
            &[
                ("command", b"answer"),
                ("call-id", b"restart-1"),
                ("from-tag", b"f"),
                ("to-tag", b"t"),
                ("sdp", answer.as_bytes()),
                ("endpoint-learning", b"off"),
            ],
        ))
        .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(50));
    let (ma, mb) = (media(&to_a), media(&to_b));
    let relays = (
        SocketAddr::new("127.0.0.1".parse().unwrap(), ma.port),
        SocketAddr::new("127.0.0.1".parse().unwrap(), mb.port),
    );
    let mut sdp_key = [Media::EMPTY; MAX_MEDIA];
    read_media(
        format!("m=audio 1 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY}\r\n")
            .as_bytes(),
        &mut sdp_key,
    )
    .unwrap();
    let a_key: MasterKey = sdp_key[0].crypto.unwrap().key;
    let relay_key = ma.crypto.expect("the relay's key towards A").key;
    let (mut tx, mut rx) = (Protect::from_key(&a_key), Unprotect::from_key(&relay_key));
    media_flows(&a, &b, relays, &mut tx, &mut rx, 1);

    answerer_reinvites(&mut c, (&offer, &answer), (ma.port, mb.port), relay_key);
    std::thread::sleep(Duration::from_millis(50));
    media_flows(&a, &b, relays, &mut tx, &mut rx, 2);

    // The relay stops (as on SIGTERM: the state is written) and starts again.
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(100));
    let mut c = control(&state);
    assert_eq!(
        c.restore(),
        1,
        "{}",
        std::fs::read_to_string(&state).unwrap()
    );
    std::thread::sleep(Duration::from_millis(50));
    // The endpoints carry on: same ports, same keys, sequence continuing.
    for seq in 3..6 {
        media_flows(&a, &b, relays, &mut tx, &mut rx, seq);
    }
    let list = c
        .handle(&request("3", &[("command", b"list")]))
        .unwrap()
        .to_vec();
    assert!(
        String::from_utf8_lossy(&list).contains("restart-1"),
        "{}",
        String::from_utf8_lossy(&list)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A mu-law WAV file of `codes`.
fn ulaw_wav(codes: &[u8]) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&u32::try_from(36 + codes.len()).unwrap().to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&7u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&8000u32.to_le_bytes());
    w.extend_from_slice(&8000u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&8u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&u32::try_from(codes.len()).unwrap().to_le_bytes());
    w.extend_from_slice(codes);
    w
}

/// Frames in a pcap file (its header once, then whole records).
fn pcap_frames(path: &std::path::Path) -> usize {
    let pcap = std::fs::read(path).expect("the recording");
    assert_eq!(&pcap[..4], &0xa1b2_c3d4u32.to_le_bytes());
    let (mut at, mut n) = (24, 0);
    while at < pcap.len() {
        let len = u32::from_le_bytes(pcap[at + 8..at + 12].try_into().unwrap()) as usize;
        assert_eq!(pcap[at + 16], 0x45, "a frame, not a second file header");
        at += 16 + len;
        n += 1;
    }
    assert_eq!(at, pcap.len());
    n
}

/// What `s` receives in the next 80 ms: (payload type, SSRC, first
/// payload octet) of each packet.
fn drain(s: &UdpSocket) -> Vec<(u8, u32, u8)> {
    let until = std::time::Instant::now() + Duration::from_millis(80);
    s.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
    let mut buf = [0u8; 2048];
    let mut got = Vec::new();
    while std::time::Instant::now() < until {
        if let Ok(n) = s.recv(&mut buf)
            && n > 12
        {
            let ssrc = u32::from_be_bytes(buf[8..12].try_into().unwrap());
            got.push((buf[1] & 0x7f, ssrc, buf[12]));
        }
    }
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    got
}

/// A request about call `restart-x`; the reply's SDP.
fn x_request(c: &mut Control, cookie: &str, pairs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut all = vec![("call-id", &b"restart-x"[..])];
    all.extend_from_slice(pairs);
    sdp_of(c.handle(&request(cookie, &all)).unwrap())
}

/// A plain PCMU call `restart-x` from `a` (tag `f`) to `b` (tag `t`); the
/// relay's addresses towards A and towards B.
fn plain_call(c: &mut Control, a: &UdpSocket, b: &UdpSocket) -> (SocketAddr, SocketAddr) {
    let sdp = |s: &UdpSocket| {
        let port = s.local_addr().unwrap().port();
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\n"
        )
    };
    let (offer, answer) = (sdp(a), sdp(b));
    let off = ("endpoint-learning", &b"off"[..]);
    let to_b = x_request(
        c,
        "1",
        &[
            ("command", b"offer"),
            ("from-tag", b"f"),
            ("sdp", offer.as_bytes()),
            off,
        ],
    );
    let to_a = x_request(
        c,
        "2",
        &[
            ("command", b"answer"),
            ("from-tag", b"f"),
            ("to-tag", b"t"),
            ("sdp", answer.as_bytes()),
            off,
        ],
    );
    (
        SocketAddr::new("127.0.0.1".parse().unwrap(), media(&to_a).port),
        SocketAddr::new("127.0.0.1".parse().unwrap(), media(&to_b).port),
    )
}

#[test]
fn blocking_recording_and_announcements_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-restart-x-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let _ = std::fs::remove_file(&state);
    // One second of 0x11, then ten of 0x22 (slack for a slow restart on
    // a loaded machine: the second part must still be playing after it).
    let codes: Vec<u8> = (0..88_000)
        .map(|i| if i < 8000 { 0x11 } else { 0x22 })
        .collect();
    let wav = dir.join("hello.wav");
    std::fs::write(&wav, ulaw_wav(&codes)).unwrap();
    let start = |state: &std::path::Path| {
        let mut c = control(state);
        c.set_recording_dir(Some(dir.clone()));
        c
    };
    let (a, b) = (endpoint(), endpoint());
    let mut c = start(&state);
    let relays = plain_call(&mut c, &a, &b);
    let ng = |c: &mut Control, cookie: &str, pairs: &[(&str, &[u8])]| x_request(c, cookie, pairs);
    ng(
        &mut c,
        "3",
        &[("command", b"block media"), ("from-tag", b"t")],
    );
    ng(&mut c, "4", &[("command", b"start recording")]);
    let file = wav.to_str().unwrap().as_bytes();
    ng(
        &mut c,
        "5",
        &[
            ("command", b"play media"),
            ("from-tag", b"t"),
            ("file", file),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    b.send_to(&rtp(1), relays.1).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(drain(&a).is_empty(), "B's media is blocked");
    let heard = drain(&b);
    assert!(
        heard
            .iter()
            .all(|&(pt, ssrc, code)| pt == 0 && ssrc != 7 && code == 0x11),
        "{heard:?}"
    );

    // Past the first second, the relay restarts.
    std::thread::sleep(Duration::from_millis(1100));
    c.save();
    drop(c);
    let recording = dir.join(format!("{}-{}-1.pcap", "restart-x", "f"));
    let before = pcap_frames(&recording);
    assert!(before >= 1, "B's packet was recorded");
    let _ = drain(&b);
    let mut c = start(&state);
    assert_eq!(
        c.restore(),
        1,
        "{}",
        std::fs::read_to_string(&state).unwrap()
    );
    // The announcement goes on from where it was: the second part (allow
    // for a loaded machine: up to eight seconds for its first packets, of
    // the ten it still plays).
    let mut heard = Vec::new();
    let until = std::time::Instant::now() + Duration::from_secs(8);
    while heard.is_empty() && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
        heard.extend(drain(&b));
    }
    assert!(!heard.is_empty(), "the announcement goes on");
    assert!(
        heard
            .iter()
            .all(|&(_, ssrc, code)| ssrc != 7 && code == 0x22),
        "{heard:?}"
    );
    // B stays blocked; A's media to B is still held back for the announcement.
    b.send_to(&rtp(2), relays.1).unwrap();
    a.send_to(&rtp(3), relays.0).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(drain(&a).is_empty(), "B's media is still blocked");
    assert!(drain(&b).iter().all(|&(_, ssrc, _)| ssrc != 7));
    // The recording went on in the same file.
    ng(&mut c, "6", &[("command", b"stop recording")]);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(pcap_frames(&recording), before + 2);
    // Unblocked, B's media flows again.
    ng(
        &mut c,
        "7",
        &[("command", b"unblock media"), ("from-tag", b"t")],
    );
    b.send_to(&rtp(4), relays.1).unwrap();
    let mut buf = [0u8; 2048];
    let n = a.recv(&mut buf).expect("B's media after unblocking");
    assert_eq!(&buf[..n], &rtp(4)[..]);
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A relay on ports 57000-57063 keeping its state in `state`.
fn control_at(state: &std::path::Path) -> Control {
    let toml = r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 57000
        max = 57063
        [sessions]
        max = 8
        [runtime]
        workers = 2
    "#;
    let config = Config::from_toml(toml).unwrap();
    let mut c = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    c.set_state_file(Some(state.to_path_buf()));
    c
}

/// A plain call from `a` to `b`, and an SRTP subscription `rec` to `a`
/// answered by `subscriber`: the relay's address for A, and the
/// subscription's media (its port and the relay's key).
fn call_and_subscription(
    c: &mut Control,
    (a, b): (&UdpSocket, &UdpSocket),
    subscriber: &UdpSocket,
) -> (SocketAddr, Media) {
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let call: &[(&str, &[u8])] = &[
        ("call-id", b"sub-restart"),
        ("from-tag", b"f"),
        ("endpoint-learning", b"off"),
    ];
    let a_sdp = sdp(a);
    let mut offer = vec![("command", &b"offer"[..]), ("sdp", a_sdp.as_bytes())];
    offer.extend_from_slice(call);
    sdp_of(c.handle(&request("s1", &offer)).unwrap());
    let b_sdp = sdp(b);
    let mut answer = vec![
        ("command", &b"answer"[..]),
        ("to-tag", b"t"),
        ("sdp", b_sdp.as_bytes()),
    ];
    answer.extend_from_slice(call);
    let to_a = sdp_of(c.handle(&request("s2", &answer)).unwrap());
    let offer = sdp_of(
        c.handle(&request(
            "s3",
            &[
                ("command", b"subscribe request"),
                ("call-id", b"sub-restart"),
                ("from-tag", b"f"),
                ("to-tag", b"rec"),
                ("transport-protocol", b"RTP/SAVP"),
            ],
        ))
        .unwrap(),
    );
    let answer = format!(
        "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY}\r\na=recvonly\r\n",
        subscriber.local_addr().unwrap().port()
    );
    sdp_of(
        c.handle(&request(
            "s4",
            &[
                ("command", b"subscribe answer"),
                ("call-id", b"sub-restart"),
                ("to-tag", b"rec"),
                ("sdp", answer.as_bytes()),
                ("endpoint-learning", b"off"),
            ],
        ))
        .unwrap(),
    );
    (
        SocketAddr::new("127.0.0.1".parse().unwrap(), media(&to_a).port),
        media(&offer),
    )
}

/// A subscription survives a restart: its ports, the relay's SRTP key
/// towards the subscriber and the copying come back.
#[test]
fn a_subscription_survives_a_restart() {
    logging::init();
    let state = std::env::temp_dir().join(format!("rtpflux-sub-state-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&state);
    let (a, b, subscriber) = (endpoint(), endpoint(), endpoint());
    let mut c = control_at(&state);
    let (to_relay_a, sub) = call_and_subscription(&mut c, (&a, &b), &subscriber);
    let mut rx = Unprotect::from_key(&sub.crypto.expect("the relay's key").key);
    let mut copied = |seq: u16| {
        let plain = rtp(seq);
        a.send_to(&plain, to_relay_a).unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = b.recv_from(&mut buf).expect("B gets A's media");
        assert_eq!(&buf[..n], &plain[..]);
        let (n, src) = subscriber
            .recv_from(&mut buf)
            .expect("the subscriber gets a copy");
        let n = rx.rtp(&mut buf, n).expect("under the relay's key");
        assert_eq!(&buf[..n], &plain[..]);
        src.port()
    };
    assert_eq!(copied(0), sub.port, "from the subscription's port");
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control_at(&state);
    assert_eq!(c.restore(), 1);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        copied(1),
        sub.port,
        "the same port, the same key, still copying"
    );
    // Still a subscription: unsubscribe ends it.
    let raw = c
        .handle(&request(
            "s5",
            &[
                ("command", b"unsubscribe"),
                ("call-id", b"sub-restart"),
                ("to-tag", b"rec"),
            ],
        ))
        .unwrap()
        .to_vec();
    assert!(String::from_utf8_lossy(&raw).contains("ok"));
    let _ = std::fs::remove_file(&state);
}

/// `connect` of a PCMU party with a PCMA one: each hears the other in its
/// own codec (converted), and the connection comes back after a restart.
#[test]
#[allow(clippy::too_many_lines)] // One call, before and after the restart.
fn a_connection_converts_codecs_and_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-connect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let sdp = |s: &UdpSocket, pt: u8| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP {pt}\r\na=sendrecv\r\n",
            s.local_addr().unwrap().port()
        )
    };
    // A call: (caller, callee, relay address for the caller, for the callee).
    let dialog = |c: &mut Control, id: &str, pt: u8| {
        let (caller, callee) = (endpoint(), endpoint());
        let mut msg = |command: &[u8], s: &UdpSocket| {
            let body = sdp(s, pt);
            // Each party labelled: `<call>-caller`, `<call>-callee`.
            let label = format!(
                "{id}-{}",
                if command == b"answer" {
                    "callee"
                } else {
                    "caller"
                }
            );
            let mut pairs: Vec<(&str, &[u8])> = vec![
                ("command", command),
                ("call-id", id.as_bytes()),
                ("from-tag", b"f"),
                ("endpoint-learning", b"off"),
                ("label", label.as_bytes()),
            ];
            if command == b"answer" {
                pairs.push(("to-tag", b"t"));
            }
            let req = {
                let mut p = pairs.clone();
                p.push(("sdp", body.as_bytes()));
                request(&format!("{id}{}", command[0]), &p)
            };
            media(&sdp_of(c.handle(&req).unwrap()))
        };
        let to_callee = msg(b"offer", &caller);
        let to_caller = msg(b"answer", &callee);
        let at = |m: Media| SocketAddr::new("127.0.0.1".parse().unwrap(), m.port);
        (caller, callee, at(to_caller), at(to_callee))
    };
    let (alice, _bob, for_alice, _) = dialog(&mut c, "conn-1", 0);
    let (_carol, dave, _, for_dave) = dialog(&mut c, "conn-2", 8);
    let connect = request(
        "cx",
        &[
            ("command", b"connect"),
            ("call-id", b"conn-1"),
            ("from-label", b"conn-1-caller"),
            ("to-call-id", b"conn-2"),
            ("to-label", b"conn-2-callee"),
        ],
    );
    let reply = c.handle(&connect).unwrap().to_vec();
    assert!(
        String::from_utf8_lossy(&reply).contains("2:ok"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    // μ-law silence (0xff) from Alice reaches Dave as A-law silence (0xd5).
    let mut check = |seq: u16| {
        let mut out = rtp(seq);
        out.truncate(12);
        out.extend_from_slice(&[0xff; 160]);
        alice.send_to(&out, for_alice).unwrap();
        let (n, _) = dave.recv_from(&mut buf).expect("Dave gets Alice's audio");
        let alaw =
            rtpflux_core::g711::converter(rtpflux_core::g711::PT_PCMU, rtpflux_core::g711::PT_PCMA)
                .unwrap()[0xff];
        assert_eq!(
            (buf[1] & 0x7f, n - 12, buf[12]),
            (8, 160, alaw),
            "converted to PCMA"
        );
        let mut back = rtp(seq);
        back[1] = 8;
        back.truncate(12);
        back.extend_from_slice(&[0xd5; 160]);
        dave.send_to(&back, for_dave).unwrap();
        let (n, _) = alice.recv_from(&mut buf).expect("Alice gets Dave's audio");
        let ulaw =
            rtpflux_core::g711::converter(rtpflux_core::g711::PT_PCMA, rtpflux_core::g711::PT_PCMU)
                .unwrap()[0xd5];
        assert_eq!(
            (buf[1] & 0x7f, n - 12, buf[12]),
            (0, 160, ulaw),
            "converted to PCMU"
        );
    };
    check(1);
    // A restart: the new relay connects them again.
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c2 = control(&state);
    assert_eq!(c2.restore(), 2);
    std::thread::sleep(Duration::from_millis(100));
    check(2);
    // The labels too.
    let q = request(
        "q",
        &[
            ("command", b"query"),
            ("call-id", b"conn-2"),
            ("label", b"conn-2-callee"),
        ],
    );
    let reply = String::from_utf8_lossy(c2.handle(&q).unwrap()).into_owned();
    assert!(
        reply.contains("2:ok") && reply.contains("5:label13:conn-2-callee"),
        "{reply}"
    );
    drop(c2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A request whose values are byte strings, or bencode already (`raw`).
fn request_raw(cookie: &str, pairs: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut sorted: Vec<_> = pairs.to_vec();
    sorted.sort_by_key(|(k, _, _)| *k);
    let mut buf = vec![0u8; 8192];
    let mut e = Encoder::new(&mut buf);
    e.raw(cookie.as_bytes()).unwrap();
    e.raw(b" ").unwrap();
    e.dict().unwrap();
    for (k, v, raw) in sorted {
        e.bytes(k.as_bytes()).unwrap();
        if raw {
            e.raw(v).unwrap();
        } else {
            e.bytes(v).unwrap();
        }
    }
    e.end().unwrap();
    let n = e.len();
    buf.truncate(n);
    buf
}

/// An offer whose answer comes after a restart is answered as before it:
/// the relay's transcoding offered to the answerer (PCMU to PCMA) is
/// still known, so the answer taking PCMA is accepted and the audio
/// converted; and `media echo` set on the call goes on after it too.
#[test]
#[allow(clippy::too_many_lines)] // One call, across two restarts.
fn an_offer_is_answered_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-pending-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let sdp = |s: &UdpSocket, pt: u8| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP {pt}\r\na=sendrecv\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let (alice, bob) = (endpoint(), endpoint());
    let at = |m: Media| SocketAddr::new("127.0.0.1".parse().unwrap(), m.port);
    let offer = sdp(&alice, 0);
    let req = request_raw(
        "o",
        &[
            ("command", b"offer", false),
            ("call-id", b"pending-1", false),
            ("from-tag", b"a", false),
            ("endpoint-learning", b"off", false),
            ("codec", b"d9:transcodel4:PCMAee", true),
            ("sdp", offer.as_bytes(), false),
        ],
    );
    let to_bob = sdp_of(c.handle(&req).unwrap());
    assert!(
        String::from_utf8_lossy(&to_bob).contains(" RTP/AVP 0 8"),
        "{}",
        String::from_utf8_lossy(&to_bob)
    );
    let for_bob = at(media(&to_bob));
    // A restart before the answer.
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 1);
    let answer = sdp(&bob, 8);
    let req = request_raw(
        "a",
        &[
            ("command", b"answer", false),
            ("call-id", b"pending-1", false),
            ("from-tag", b"a", false),
            ("to-tag", b"b", false),
            ("endpoint-learning", b"off", false),
            ("media echo", b"backwards", false),
            ("sdp", answer.as_bytes(), false),
        ],
    );
    let to_alice = sdp_of(c.handle(&req).unwrap());
    assert!(
        String::from_utf8_lossy(&to_alice).contains(" RTP/AVP 0\r\n"),
        "{}",
        String::from_utf8_lossy(&to_alice)
    );
    let for_alice = at(media(&to_alice));
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let ulaw = |seq: u16| {
        let mut p = rtp(seq);
        p.truncate(12);
        p.extend_from_slice(&[0xff; 160]);
        p
    };
    let alaw =
        rtpflux_core::g711::converter(rtpflux_core::g711::PT_PCMU, rtpflux_core::g711::PT_PCMA)
            .unwrap()[0xff];
    // `backwards` (on the answer): Bob hears himself, Alice's media is
    // dropped; with the restart in between, before and after.
    let mut check = |seq: u16| {
        bob.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        alice.send_to(&ulaw(seq), for_alice).unwrap();
        assert!(bob.recv_from(&mut buf).is_err(), "Alice's media dropped");
        let mut back = rtp(seq);
        back[1] = 8;
        back.truncate(12);
        back.extend_from_slice(&[alaw; 160]);
        bob.send_to(&back, for_bob).unwrap();
        let (n, _) = bob.recv_from(&mut buf).expect("Bob hears himself");
        assert_eq!((buf[1] & 0x7f, n - 12), (8, 160));
    };
    check(1);
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 1);
    std::thread::sleep(Duration::from_millis(100));
    check(2);
    // Echo off: the PCMA Bob sends reaches Alice as PCMU.
    let req = request_raw(
        "e",
        &[
            ("command", b"answer", false),
            ("call-id", b"pending-1", false),
            ("from-tag", b"a", false),
            ("to-tag", b"b", false),
            ("endpoint-learning", b"off", false),
            ("media echo", b"off", false),
            ("sdp", answer.as_bytes(), false),
        ],
    );
    sdp_of(c.handle(&req).unwrap());
    std::thread::sleep(Duration::from_millis(50));
    let mut back = rtp(3);
    back[1] = 8;
    back.truncate(12);
    back.extend_from_slice(&[alaw; 160]);
    bob.send_to(&back, for_bob).unwrap();
    let (n, _) = alice.recv_from(&mut buf).expect("Alice gets Bob's audio");
    let ulaw =
        rtpflux_core::g711::converter(rtpflux_core::g711::PT_PCMA, rtpflux_core::g711::PT_PCMU)
            .unwrap()[usize::from(alaw)];
    assert_eq!((buf[1] & 0x7f, n - 12, buf[12]), (0, 160, ulaw), "as PCMU");
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The key of an `a=crypto` line (`<tag> <suite> inline:<key>`).
fn crypto_key(line: &str) -> MasterKey {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(
        format!("m=audio 1 RTP/SAVP 0\r\na=crypto:{line}\r\n").as_bytes(),
        &mut m,
    )
    .unwrap();
    m[0].crypto.expect("a key").key
}

/// SRTP offered to the answerer with several suites: the answer, after a
/// restart, takes one of the further ones, whose relay key is still known.
#[test]
fn a_further_srtp_key_is_answered_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-alt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let (a, b) = (endpoint(), endpoint());
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\n",
        a.local_addr().unwrap().port()
    );
    let to_b = String::from_utf8(sdp_of(
        c.handle(&request(
            "1",
            &[
                ("command", b"offer"),
                ("call-id", b"alt-1"),
                ("from-tag", b"f"),
                ("sdp", offer.as_bytes()),
                ("transport-protocol", b"RTP/SAVP"),
                ("endpoint-learning", b"off"),
            ],
        ))
        .unwrap(),
    ))
    .unwrap();
    // A further line with a 30-octet key, as `KEY`.
    let line = to_b
        .lines()
        .filter_map(|l| l.strip_prefix("a=crypto:"))
        .find(|l| !l.starts_with("1 ") && l.contains(" AES_CM_128_HMAC_SHA1_32 "))
        .unwrap_or_else(|| panic!("{to_b}"))
        .to_owned();
    let tag = line.split(' ').next().unwrap().to_owned();
    let relay_key = crypto_key(&line);
    let for_b = SocketAddr::new("127.0.0.1".parse().unwrap(), media(to_b.as_bytes()).port);
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 1);
    let answer = format!(
        "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/SAVP 0\r\na=crypto:{tag} AES_CM_128_HMAC_SHA1_32 inline:{KEY}\r\n",
        b.local_addr().unwrap().port()
    );
    let to_a = sdp_of(
        c.handle(&request(
            "2",
            &[
                ("command", b"answer"),
                ("call-id", b"alt-1"),
                ("from-tag", b"f"),
                ("to-tag", b"t"),
                ("sdp", answer.as_bytes()),
                ("endpoint-learning", b"off"),
            ],
        ))
        .unwrap(),
    );
    let for_a = SocketAddr::new("127.0.0.1".parse().unwrap(), media(&to_a).port);
    std::thread::sleep(Duration::from_millis(50));
    let b_key = crypto_key(&format!("{tag} AES_CM_128_HMAC_SHA1_32 inline:{KEY}"));
    let (mut tx, mut rx) = (Protect::from_key(&b_key), Unprotect::from_key(&relay_key));
    let mut buf = [0u8; 2048];
    // A's plain RTP reaches B under the relay's key of that line.
    a.send_to(&rtp(1), for_a).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("B gets A's media");
    let n = rx.rtp(&mut buf, n).expect("under the chosen line's key");
    assert_eq!(&buf[..n], &rtp(1)[..]);
    // B's SRTP reaches A decrypted.
    let plain = rtp(2);
    let mut wire = plain.clone();
    wire.resize(plain.len() + 10, 0);
    let len = tx.rtp(&mut wire, plain.len()).unwrap();
    b.send_to(&wire[..len], for_b).unwrap();
    let (n, _) = a.recv_from(&mut buf).expect("A gets B's media");
    assert_eq!(&buf[..n], &plain[..]);
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `connect` with `directional` survives a restart: Carol still gets a
/// copy of Alice's media, and still hears Dave.
#[test]
fn directional_copies_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-copies-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\na=sendrecv\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let at = |m: Media| SocketAddr::new("127.0.0.1".parse().unwrap(), m.port);
    // Two dialogs of one call: (offerer, answerer) → relay address for
    // the answerer's media (towards the offerer).
    let dialog = |c: &mut Control, (from, to): (&[u8], &[u8]), x: &UdpSocket, y: &UdpSocket| {
        let (ox, oy) = (sdp(x), sdp(y));
        let base = |cmd: &'static [u8]| {
            vec![
                ("command", cmd, false),
                ("call-id", &b"copies-1"[..], false),
                ("from-tag", from, false),
                ("endpoint-learning", b"off", false),
            ]
        };
        let mut p = base(b"offer");
        p.push(("sdp", ox.as_bytes(), false));
        sdp_of(c.handle(&request_raw("o", &p)).unwrap());
        let mut p = base(b"answer");
        p.push(("to-tag", to, false));
        p.push(("sdp", oy.as_bytes(), false));
        at(media(&sdp_of(c.handle(&request_raw("a", &p)).unwrap())))
    };
    let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
    let alice_to = dialog(&mut c, (b"a", b"b"), &alice, &bob);
    let carol_to = dialog(&mut c, (b"c", b"d"), &carol, &dave);
    let reply = c
        .handle(&request_raw(
            "x",
            &[
                ("command", b"connect", false),
                ("call-id", b"copies-1", false),
                ("from-tag", b"a", false),
                ("to-tag", b"c", false),
                ("flags", b"l11:directionale", true),
            ],
        ))
        .unwrap()
        .to_vec();
    assert!(String::from_utf8_lossy(&reply).contains("2:ok"));
    let mut buf = [0u8; 2048];
    let mut check = |seq: u16| {
        for s in [&bob, &carol, &dave] {
            s.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
        }
        alice.send_to(&rtp(seq), alice_to).unwrap();
        assert!(bob.recv_from(&mut buf).is_ok(), "bob hears alice");
        assert!(carol.recv_from(&mut buf).is_ok(), "carol gets a copy");
        carol.send_to(&rtp(seq), carol_to).unwrap();
        assert!(dave.recv_from(&mut buf).is_ok(), "dave hears carol");
    };
    std::thread::sleep(Duration::from_millis(50));
    check(1);
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 2);
    std::thread::sleep(Duration::from_millis(100));
    check(2);
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// DTMF security survives a restart: the caller's keys still reach the
/// callee as 0.
#[test]
fn dtmf_security_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-dtmfsec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let (caller, callee) = (endpoint(), endpoint());
    let msg = |command: &'static [u8], s: &UdpSocket| {
        let body = sdp(s);
        let mut p: Vec<(&str, &[u8], bool)> = vec![
            ("command", command, false),
            ("call-id", b"sec-1", false),
            ("from-tag", b"f", false),
            ("endpoint-learning", b"off", false),
        ];
        if command == b"answer" {
            p.push(("to-tag", b"t", false));
        }
        p.push(("sdp", body.as_bytes(), false));
        request_raw(std::str::from_utf8(command).unwrap(), &p)
    };
    sdp_of(c.handle(&msg(b"offer", &caller)).unwrap());
    let to_a = sdp_of(c.handle(&msg(b"answer", &callee)).unwrap());
    let for_a = SocketAddr::new("127.0.0.1".parse().unwrap(), media(&to_a).port);
    let reply = c
        .handle(&request_raw(
            "blk",
            &[
                ("command", b"block DTMF", false),
                ("call-id", b"sec-1", false),
                ("from-tag", b"f", false),
                ("DTMF-security", b"zero", false),
            ],
        ))
        .unwrap()
        .to_vec();
    assert!(String::from_utf8_lossy(&reply).contains("2:ok"));
    let mut buf = [0u8; 2048];
    let mut key = |seq: u16, ts: u32| {
        let mut p = vec![0x80, 0xe5];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&[1, 2, 3, 4, 5, 0x8a, 0, 160]);
        caller.send_to(&p, for_a).unwrap();
        let (n, _) = callee.recv_from(&mut buf).expect("the event");
        assert_eq!((n, buf[1] & 0x7f, buf[12]), (16, 101, 0), "key 0");
    };
    std::thread::sleep(Duration::from_millis(50));
    key(1, 1000);
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 1);
    std::thread::sleep(Duration::from_millis(100));
    key(2, 2000);
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A re-offer made with `track-state` and not answered survives a restart:
/// its rollback after it puts back A's first address and the section the
/// re-offer removed.
#[test]
#[allow(clippy::too_many_lines)] // One call, across a restart.
fn a_pending_reoffer_is_rolled_back_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-ckpt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let sdp = |x: &UdpSocket, y: Option<&UdpSocket>| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\nm=audio {} RTP/AVP 0\r\n",
            port(x),
            y.map_or(0, port)
        )
    };
    let at = |p: u16| SocketAddr::new("127.0.0.1".parse().unwrap(), p);
    let ports = |sdp: &[u8]| -> Vec<u16> {
        String::from_utf8_lossy(sdp)
            .lines()
            .filter(|l| l.starts_with("m="))
            .map(|l| l.split(' ').nth(1).unwrap().parse().unwrap())
            .collect()
    };
    let (a1, a2, b1, b2, a_new) = (endpoint(), endpoint(), endpoint(), endpoint(), endpoint());
    let msg = |cmd: &'static [u8], to: Option<&'static [u8]>, body: &str, track: bool| {
        let mut p: Vec<(&str, &[u8], bool)> = vec![
            ("command", cmd, false),
            ("call-id", b"ckpt-1", false),
            ("from-tag", b"f", false),
            ("endpoint-learning", b"off", false),
            ("sdp", body.as_bytes(), false),
        ];
        if let Some(t) = to {
            p.push(("to-tag", t, false));
        }
        if track {
            p.push(("flags", b"l11:track-statee", true));
        }
        p.iter()
            .map(|(k, v, r)| (*k, v.to_vec(), *r))
            .collect::<Vec<_>>()
    };
    let send = |c: &mut Control, cookie: &str, m: Vec<(&str, Vec<u8>, bool)>| {
        let p: Vec<(&str, &[u8], bool)> = m.iter().map(|(k, v, r)| (*k, &v[..], *r)).collect();
        sdp_of(c.handle(&request_raw(cookie, &p)).unwrap())
    };
    let to_b = ports(&send(
        &mut c,
        "o1",
        msg(b"offer", None, &sdp(&a1, Some(&a2)), false),
    ));
    send(
        &mut c,
        "a1",
        msg(b"answer", Some(b"t"), &sdp(&b1, Some(&b2)), false),
    );
    // The tracked re-offer: A elsewhere, section 2 removed. No answer.
    send(
        &mut c,
        "o2",
        msg(b"offer", Some(b"t"), &sdp(&a_new, None), true),
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    for s in [&a1, &a2, &a_new] {
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
    }
    b1.send_to(&rtp(1), at(to_b[0])).unwrap();
    assert!(a_new.recv_from(&mut buf).is_ok(), "the re-offer in force");
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 1);
    std::thread::sleep(Duration::from_millis(100));
    // Rolled back after the restart.
    let reply = c
        .handle(&request_raw(
            "r",
            &[
                ("command", b"rollback", false),
                ("call-id", b"ckpt-1", false),
                ("from-tag", b"f", false),
                ("to-tag", b"t", false),
            ],
        ))
        .unwrap()
        .to_vec();
    assert!(
        String::from_utf8_lossy(&reply).contains("11:rolled-backi1e"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    std::thread::sleep(Duration::from_millis(50));
    b1.send_to(&rtp(2), at(to_b[0])).unwrap();
    assert!(a1.recv_from(&mut buf).is_ok(), "A's first address again");
    b2.send_to(&rtp(2), at(to_b[1])).unwrap();
    assert!(
        a2.recv_from(&mut buf).is_ok(),
        "the removed section is back"
    );
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A party made by `create`, its offer not answered, survives a restart:
/// `create answer` after it, then `connect`, and media flows.
#[test]
fn a_created_party_is_answered_after_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-created-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let at = |m: Media| SocketAddr::new("127.0.0.1".parse().unwrap(), m.port);
    let (alice, bob, server_e) = (endpoint(), endpoint(), endpoint());
    let req = |cookie: &str, pairs: &[(&str, &[u8], bool)]| request_raw(cookie, pairs);
    let (sa, sb) = (sdp(&alice), sdp(&bob));
    let base = [
        ("call-id", &b"created-1"[..], false),
        ("from-tag", b"a", false),
        ("endpoint-learning", b"off", false),
    ];
    let mut p = base.to_vec();
    p.extend([
        ("command", &b"offer"[..], false),
        ("sdp", sa.as_bytes(), false),
    ]);
    sdp_of(c.handle(&req("o", &p)).unwrap());
    let mut p = base.to_vec();
    p.extend([
        ("command", &b"answer"[..], false),
        ("to-tag", b"b", false),
        ("sdp", sb.as_bytes(), false),
    ]);
    let for_alice = at(media(&sdp_of(c.handle(&req("a", &p)).unwrap())));
    let offer = sdp_of(
        c.handle(&req(
            "c",
            &[
                ("command", b"create", false),
                ("call-id", b"created-1", false),
                ("from-tag", b"srv", false),
                ("codec", b"d5:offerl4:PCMUee", true),
            ],
        ))
        .unwrap(),
    );
    let for_server = at(media(&offer));
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 2);
    let se = sdp(&server_e);
    sdp_of(
        c.handle(&req(
            "ca",
            &[
                ("command", b"create answer", false),
                ("call-id", b"created-1", false),
                ("from-tag", b"srv", false),
                ("endpoint-learning", b"off", false),
                ("sdp", se.as_bytes(), false),
            ],
        ))
        .unwrap(),
    );
    sdp_of(
        c.handle(&req(
            "x",
            &[
                ("command", b"connect", false),
                ("call-id", b"created-1", false),
                ("from-tag", b"a", false),
                ("to-tag", b"srv", false),
            ],
        ))
        .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(100));
    let mut buf = [0u8; 2048];
    alice.send_to(&rtp(1), for_alice).unwrap();
    assert!(
        server_e.recv_from(&mut buf).is_ok(),
        "the server hears alice"
    );
    server_e.send_to(&rtp(2), for_server).unwrap();
    assert!(alice.recv_from(&mut buf).is_ok(), "alice hears the server");
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A party made by `create from offer` survives a restart: on its ports,
/// still parked, its re-offer still a re-offer; `connect`ed to a created
/// party after it, media flows.
#[test]
fn a_party_created_from_its_offer_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("rtpflux-from-offer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state.json");
    let mut c = control(&state);
    let sdp = |s: &UdpSocket, version: u32| {
        format!(
            "v=0\r\no=- 1 {version} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let at = |m: Media| SocketAddr::new("127.0.0.1".parse().unwrap(), m.port);
    let (caller, server_e) = (endpoint(), endpoint());
    let req = |cookie: &str, pairs: &[(&str, &[u8], bool)]| request_raw(cookie, pairs);
    let from_offer = |c: &mut Control, cookie: &str, version: u32| {
        let s = sdp(&caller, version);
        at(media(&sdp_of(
            c.handle(&req(
                cookie,
                &[
                    ("command", b"create from offer", false),
                    ("call-id", b"from-offer-1", false),
                    ("from-tag", b"caller", false),
                    ("endpoint-learning", b"off", false),
                    ("sdp", s.as_bytes(), false),
                ],
            ))
            .unwrap(),
        )))
    };
    let for_caller = from_offer(&mut c, "i", 1);
    let for_server = at(media(&sdp_of(
        c.handle(&req(
            "c",
            &[
                ("command", b"create", false),
                ("call-id", b"from-offer-1", false),
                ("from-tag", b"srv", false),
                ("codec", b"d5:offerl4:PCMUee", true),
            ],
        ))
        .unwrap(),
    )));
    c.save();
    drop(c);
    std::thread::sleep(Duration::from_millis(200));
    let mut c = control(&state);
    assert_eq!(c.restore(), 2);
    // Still parked.
    let mut buf = [0u8; 2048];
    caller.send_to(&rtp(1), for_caller).unwrap();
    server_e
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert!(server_e.recv_from(&mut buf).is_err(), "parked");
    // Its re-INVITE: the same port.
    assert_eq!(from_offer(&mut c, "i2", 2), for_caller);
    let se = sdp(&server_e, 1);
    sdp_of(
        c.handle(&req(
            "ca",
            &[
                ("command", b"create answer", false),
                ("call-id", b"from-offer-1", false),
                ("from-tag", b"srv", false),
                ("endpoint-learning", b"off", false),
                ("sdp", se.as_bytes(), false),
            ],
        ))
        .unwrap(),
    );
    sdp_of(
        c.handle(&req(
            "x",
            &[
                ("command", b"connect", false),
                ("call-id", b"from-offer-1", false),
                ("from-tag", b"caller", false),
                ("to-tag", b"srv", false),
            ],
        ))
        .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(100));
    server_e
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    caller.send_to(&rtp(2), for_caller).unwrap();
    assert!(
        server_e.recv_from(&mut buf).is_ok(),
        "the server hears the caller"
    );
    server_e.send_to(&rtp(3), for_server).unwrap();
    assert!(
        caller.recv_from(&mut buf).is_ok(),
        "the caller hears the server"
    );
    drop(c);
    std::fs::remove_dir_all(&dir).unwrap();
}
