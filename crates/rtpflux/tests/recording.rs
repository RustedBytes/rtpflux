//! `start recording` / `stop recording`: the call's packets, as each peer
//! sent them, end up in a pcap file.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::control::Control;
use rtpflux::relay::Relay;
use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
use rtpflux_ng::bencode::{Encoder, Value, decode};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

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

/// The result and SDP of a reply.
fn reply(raw: &[u8]) -> (String, Vec<u8>) {
    let space = raw.iter().position(|&c| c == b' ').unwrap();
    let Ok(Value::Dict(d)) = decode(&raw[space + 1..]) else {
        panic!()
    };
    (
        String::from_utf8_lossy(d.get_bytes(b"result").unwrap_or_default()).into_owned(),
        d.get_bytes(b"sdp").unwrap_or_default().to_vec(),
    )
}

fn port_of(sdp: &[u8]) -> u16 {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(sdp, &mut m).unwrap();
    m[0].port
}

fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}

fn rtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0, 0, 0, 0, 0, 0, 160, 0, 0, 0, 7];
    p[2..4].copy_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0xd5; 20]);
    p
}

/// (source port, destination port, RTP sequence) of each recorded frame,
/// whose payload must be the packet sent.
fn recorded(path: &std::path::Path) -> Vec<(u16, u16, u16)> {
    let pcap = std::fs::read(path).expect("the recording");
    assert_eq!(&pcap[..4], &0xa1b2_c3d4u32.to_le_bytes());
    let mut at = 24;
    let mut seen = Vec::new();
    while at < pcap.len() {
        let len = u32::from_le_bytes(pcap[at + 8..at + 12].try_into().unwrap()) as usize;
        let frame = &pcap[at + 16..at + 16 + len];
        assert_eq!(frame[0], 0x45);
        let (sport, dport) = (
            u16::from_be_bytes([frame[20], frame[21]]),
            u16::from_be_bytes([frame[22], frame[23]]),
        );
        let seq = u16::from_be_bytes([frame[30], frame[31]]);
        assert_eq!(&frame[28..], &rtp(seq)[..]);
        seen.push((sport, dport, seq));
        at += 16 + len;
    }
    seen
}

#[test]
fn a_call_is_recorded_as_pcap() {
    logging::init();
    let dir = std::env::temp_dir().join(format!("rtpflux-recording-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let toml = r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 49600
        max = 49663
        [sessions]
        max = 8
        [runtime]
        workers = 1
    "#;
    let config = Config::from_toml(toml).unwrap();
    let mut c = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    let mut ng =
        |cookie: &str, pairs: &[(&str, &[u8])]| reply(c.handle(&request(cookie, pairs)).unwrap());
    let (a, b) = (endpoint(), endpoint());
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 8\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let common: [(&str, &[u8]); 2] = [("call-id", b"rec/1@x"), ("endpoint-learning", b"off")];
    let (r, to_b) = ng(
        "1",
        &[
            ("command", b"offer"),
            ("from-tag", b"f"),
            ("sdp", sdp(&a).as_bytes()),
            common[0],
            common[1],
        ],
    );
    assert_eq!(r, "ok");
    let (_, to_a) = ng(
        "2",
        &[
            ("command", b"answer"),
            ("from-tag", b"f"),
            ("to-tag", b"t"),
            ("sdp", sdp(&b).as_bytes()),
            common[0],
            common[1],
        ],
    );
    let lo = |p: u16| SocketAddr::new("127.0.0.1".parse().unwrap(), p);
    let (for_a, for_b) = (lo(port_of(&to_a)), lo(port_of(&to_b)));

    // Without a directory, recording is refused.
    assert_eq!(
        ng("3", &[("command", b"start recording"), common[0]]).0,
        "error"
    );
    c.set_recording_dir(Some(dir.clone()));
    let mut ng =
        |cookie: &str, pairs: &[(&str, &[u8])]| reply(c.handle(&request(cookie, pairs)).unwrap());
    assert_eq!(
        ng("4", &[("command", b"start recording"), common[0]]).0,
        "ok"
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    for seq in 0..3 {
        a.send_to(&rtp(seq), for_a).unwrap();
        b.recv_from(&mut buf).expect("B gets A's");
        b.send_to(&rtp(100 + seq), for_b).unwrap();
        a.recv_from(&mut buf).expect("A gets B's");
    }
    assert_eq!(
        ng("5", &[("command", b"stop recording"), common[0]]).0,
        "ok"
    );
    std::thread::sleep(Duration::from_millis(100));
    // Packets after the stop are not recorded.
    a.send_to(&rtp(9), for_a).unwrap();
    b.recv_from(&mut buf).expect("B gets A's");
    std::thread::sleep(Duration::from_millis(50));

    let seen = recorded(&dir.join("rec_1@x-f-1.pcap"));
    let pa = a.local_addr().unwrap().port();
    let pb = b.local_addr().unwrap().port();
    assert_eq!(
        seen,
        vec![
            (pa, for_a.port(), 0),
            (pb, for_b.port(), 100),
            (pa, for_a.port(), 1),
            (pb, for_b.port(), 101),
            (pa, for_a.port(), 2),
            (pb, for_b.port(), 102),
        ]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The RTP sequence numbers recorded in `dir/name`.
fn seqs(dir: &std::path::Path, name: &str) -> Vec<u16> {
    recorded(&dir.join(name))
        .into_iter()
        .map(|(_, _, s)| s)
        .collect()
}

/// `record-call: yes` on the offer records from the start; `pause
/// recording` leaves packets out, `start recording` goes on in the same
/// file.
#[test]
fn record_call_paused_and_resumed() {
    logging::init();
    let dir = std::env::temp_dir().join(format!("rtpflux-recording-pause-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let toml = r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 56500
        max = 56563
        [sessions]
        max = 8
        [runtime]
        workers = 1
    "#;
    let config = Config::from_toml(toml).unwrap();
    let mut c = Control::new(Relay::start(&config).unwrap(), config.interfaces.clone());
    c.set_recording_dir(Some(dir.clone()));
    let mut ng =
        |cookie: &str, pairs: &[(&str, &[u8])]| reply(c.handle(&request(cookie, pairs)).unwrap());
    let (a, b) = (endpoint(), endpoint());
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 8\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let common: [(&str, &[u8]); 2] = [("call-id", b"rec/2@x"), ("endpoint-learning", b"off")];
    let (r, to_b) = ng(
        "1",
        &[
            ("command", b"offer"),
            ("from-tag", b"f"),
            ("sdp", sdp(&a).as_bytes()),
            ("record-call", b"yes"),
            common[0],
            common[1],
        ],
    );
    assert_eq!(r, "ok");
    let (_, to_a) = ng(
        "2",
        &[
            ("command", b"answer"),
            ("from-tag", b"f"),
            ("to-tag", b"t"),
            ("sdp", sdp(&b).as_bytes()),
            common[0],
            common[1],
        ],
    );
    let lo = |p: u16| SocketAddr::new("127.0.0.1".parse().unwrap(), p);
    let for_a = lo(port_of(&to_a));
    let _ = to_b;
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let mut send = |seq: u16| {
        a.send_to(&rtp(seq), for_a).unwrap();
        b.recv_from(&mut buf).expect("B gets A's");
    };
    send(0);
    send(1);
    assert_eq!(
        ng("3", &[("command", b"pause recording"), common[0]]).0,
        "ok"
    );
    std::thread::sleep(Duration::from_millis(50));
    send(2);
    send(3);
    assert_eq!(
        ng("4", &[("command", b"start recording"), common[0]]).0,
        "ok"
    );
    std::thread::sleep(Duration::from_millis(50));
    send(4);
    assert_eq!(
        ng("5", &[("command", b"stop recording"), common[0]]).0,
        "ok"
    );
    std::thread::sleep(Duration::from_millis(100));
    let first = seqs(&dir, "rec_2@x-f-1.pcap");
    assert_eq!(first, vec![0, 1, 4], "nothing while paused, one file");
    // Started again after the stop: a new file; the first is left alone.
    assert_eq!(
        ng("6", &[("command", b"start recording"), common[0]]).0,
        "ok"
    );
    std::thread::sleep(Duration::from_millis(50));
    send(5);
    assert_eq!(
        ng("7", &[("command", b"stop recording"), common[0]]).0,
        "ok"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(seqs(&dir, "rec_2@x-f-1-2.pcap"), vec![5]);
    assert_eq!(seqs(&dir, "rec_2@x-f-1.pcap"), vec![0, 1, 4]);
    std::fs::remove_dir_all(&dir).unwrap();
}
