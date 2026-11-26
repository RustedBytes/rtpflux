//! DTMF transcoding: telephone events to in-band tones and back.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use rtpflux_core::dtmf_inband::key_of;
use rtpflux_core::g711;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn sdp(port: u16, formats: &str, extra: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {formats}\r\n{extra}a=sendrecv\r\n"
    )
}

const TE: &str = "a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n";

fn packet(pt: u8, seq: u16, ts: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, pt | if marker { 0x80 } else { 0 }];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// Key `code` as μ-law audio, frame `k` (20 ms).
fn tone_frame(code: u8, k: usize) -> Vec<u8> {
    const LOW: [f64; 4] = [697.0, 770.0, 852.0, 941.0];
    const HIGH: [f64; 4] = [1209.0, 1336.0, 1477.0, 1633.0];
    let (row, col) = match code {
        0 => (3, 1),
        1..=9 => ((code - 1) / 3, (code - 1) % 3),
        10 => (3, 0),
        11 => (3, 2),
        _ => (code - 12, 3),
    };
    let (f1, f2) = (LOW[usize::from(row)], HIGH[usize::from(col)]);
    (0..160)
        .map(|i| {
            #[allow(clippy::cast_precision_loss)]
            let x = (k * 160 + i) as f64 / 8000.0 * 2.0 * std::f64::consts::PI;
            #[allow(clippy::cast_possible_truncation)]
            let v = (4500.0 * ((f1 * x).sin() + (f2 * x).sin())) as i16;
            g711::linear_to_ulaw(v)
        })
        .collect()
}

/// What `s` receives in `ms`.
fn gather(s: &UdpSocket, ms: u64) -> Vec<Vec<u8>> {
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let end = Instant::now() + Duration::from_millis(ms);
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            out.push(buf[..n].to_vec());
        }
    }
    out
}

/// The keys heard in G.711 μ-law packets.
fn keys_heard(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut keys: Vec<u8> = packets
        .iter()
        .filter(|p| p[1].trailing_zeros() >= 7 && p.len() == 172)
        .filter_map(|p| {
            let x: Vec<i16> = p[12..].iter().map(|&c| g711::ulaw_to_linear(c)).collect();
            key_of(&x)
        })
        .collect();
    keys.dedup();
    keys
}

/// Send telephone event `code` (pt 101) for 120 ms, then three ends.
fn send_event(from: &UdpSocket, to: SocketAddr, code: u8, seq0: u16) {
    for k in 0..6u16 {
        let d = (k + 1) * 160;
        let end = k >= 3;
        let payload = [
            code,
            0x0a | if end { 0x80 } else { 0 },
            (d >> 8) as u8,
            (d & 0xff) as u8,
        ];
        from.send_to(&packet(101, seq0 + k, 1000, k == 0, &payload), to)
            .unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Send key `code` as in-band tones for 200 ms, then silence for 100 ms.
fn send_tones(from: &UdpSocket, to: SocketAddr, code: u8) {
    for k in 0..15u16 {
        let payload = if k < 10 {
            tone_frame(code, usize::from(k))
        } else {
            vec![0xff; 160]
        };
        from.send_to(&packet(0, k, u32::from(k) * 160, k == 0, &payload), to)
            .unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn relay(sdp: &[u8]) -> SocketAddr {
    SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(sdp).port)
}

fn exchange(
    srv: &Server,
    client: &UdpSocket,
    offer: &str,
    answer: &str,
    extra: &[(&str, V<'_>)],
) -> (String, String) {
    let mut pairs = vec![
        ("command", V::S(b"offer")),
        ("call-id", V::S(b"xcode")),
        ("from-tag", V::S(b"f")),
        ("sdp", V::S(offer.as_bytes())),
    ];
    pairs.extend(extra.iter().map(|(k, v)| {
        (
            *k,
            match v {
                V::S(s) => V::S(s),
                V::L(l) => V::L(l),
                V::I(i) => V::I(*i),
                V::Raw(r) => V::Raw(r),
            },
        )
    }));
    let (r, to_b, _) = call(client, srv.addr, &request("x1", &pairs));
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&to_b));
    let (r, to_a, _) = call(
        client,
        srv.addr,
        &request(
            "x2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"xcode")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer.as_bytes())),
            ],
        ),
    );
    assert_eq!(r, "ok");
    (
        String::from_utf8(to_b).unwrap(),
        String::from_utf8(to_a).unwrap(),
    )
}

/// A has no telephone events; the relay offers them to B, which takes
/// them: B's events reach A as tones, A's tones reach B as events.
#[test]
fn events_offered_to_the_answerer() {
    let srv = server(53_700);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (to_b, to_a) = exchange(
        &srv,
        &client,
        &sdp(a.local_addr().unwrap().port(), "0", ""),
        &sdp(b.local_addr().unwrap().port(), "0 101", TE),
        &[("flags", V::L(&[b"codec-transcode-telephone-event"]))],
    );
    assert!(
        to_b.contains(" 0 101\r\n") && to_b.contains("a=rtpmap:101 telephone-event/8000"),
        "{to_b}"
    );
    assert!(
        !to_a.contains("101") && !to_a.contains("telephone-event"),
        "{to_a}"
    );
    let (ra, rb) = (relay(to_a.as_bytes()), relay(to_b.as_bytes()));
    // Latch both sides.
    a.send_to(&packet(0, 1, 0, false, &[0xff; 160]), ra)
        .unwrap();
    b.send_to(&packet(0, 1, 0, false, &[0xff; 160]), rb)
        .unwrap();
    gather(&a, 100);
    gather(&b, 100);
    // B presses 5: A hears it, and no event packet reaches A.
    send_event(&b, rb, 5, 10);
    let heard = gather(&a, 300);
    assert_eq!(keys_heard(&heard), [5], "{} packets", heard.len());
    assert!(heard.iter().all(|p| p[1] & 0x7f != 101));
    // A plays 9 in-band: B gets events for 9, with end packets.
    send_tones(&a, ra, 9);
    let got = gather(&b, 300);
    let events: Vec<&Vec<u8>> = got.iter().filter(|p| p[1] & 0x7f == 101).collect();
    assert!(!events.is_empty(), "{} packets", got.len());
    assert!(events.iter().all(|p| p[12] == 9));
    assert!(
        events.iter().filter(|p| p[13] & 0x80 != 0).count() >= 3,
        "end packets"
    );
}

/// A offers telephone events, B refuses them (`always transcode`): A's
/// events reach B as tones, B's tones reach A as events; A's answer keeps
/// them.
#[test]
fn events_kept_for_the_offerer() {
    let srv = server(53_800);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (to_b, to_a) = exchange(
        &srv,
        &client,
        &sdp(a.local_addr().unwrap().port(), "0 101", TE),
        &sdp(b.local_addr().unwrap().port(), "0", ""),
        &[("flags", V::L(&[b"always transcode"]))],
    );
    assert!(to_b.contains(" 0 101\r\n"), "{to_b}");
    assert!(
        to_a.contains(" 0 101\r\n") && to_a.contains("a=rtpmap:101 telephone-event/8000"),
        "{to_a}"
    );
    let (ra, rb) = (relay(to_a.as_bytes()), relay(to_b.as_bytes()));
    a.send_to(&packet(0, 1, 0, false, &[0xff; 160]), ra)
        .unwrap();
    b.send_to(&packet(0, 1, 0, false, &[0xff; 160]), rb)
        .unwrap();
    gather(&a, 100);
    gather(&b, 100);
    send_event(&a, ra, 3, 10);
    let heard = gather(&b, 300);
    assert_eq!(keys_heard(&heard), [3]);
    assert!(heard.iter().all(|p| p[1] & 0x7f != 101));
    send_tones(&b, rb, 11);
    let got = gather(&a, 300);
    let events: Vec<&Vec<u8>> = got.iter().filter(|p| p[1] & 0x7f == 101).collect();
    assert!(
        !events.is_empty() && events.iter().all(|p| p[12] == 11),
        "{} packets",
        got.len()
    );
}

/// The keys heard in Opus packets (payload type 111), decoded at 8 kHz.
fn keys_heard_opus(packets: &[Vec<u8>]) -> Vec<u8> {
    use rtpflux::codec::Decoder;
    let mut d = Decoder::new(rtpflux_core::sdp::Codec::Opus, 8000).unwrap();
    let mut pcm = [0i16; 2880];
    let mut keys: Vec<u8> = Vec::new();
    for p in packets.iter().filter(|p| p[1] & 0x7f == 111) {
        let Some(n) = d.decode(&p[12..], &mut pcm) else {
            continue;
        };
        keys.extend(pcm[..n].chunks(160).filter_map(key_of));
    }
    keys.dedup();
    keys
}

const OPUS: &str = "a=rtpmap:111 opus/48000/2\r\n";

/// An Opus offerer without telephone events, an answerer with them: the
/// answerer's events reach the offerer as tones encoded in Opus, and tones
/// in the offerer's Opus reach the answerer as events.
#[test]
fn events_and_tones_in_opus() {
    use rtpflux::codec::Encoder;
    let srv = server(57_200);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (to_b, to_a) = exchange(
        &srv,
        &client,
        &sdp(a.local_addr().unwrap().port(), "111", OPUS),
        &sdp(
            b.local_addr().unwrap().port(),
            "111 101",
            &format!("{OPUS}{TE}"),
        ),
        &[("flags", V::L(&[b"codec-transcode-telephone-event"]))],
    );
    assert!(to_b.contains(" 111 101\r\n"), "{to_b}");
    assert!(!to_a.contains("telephone-event"), "{to_a}");
    let (ra, rb) = (relay(to_a.as_bytes()), relay(to_b.as_bytes()));
    // Opus silence (a TOC byte of a 20 ms SILK frame) to latch both sides.
    a.send_to(&packet(111, 1, 0, false, &[0xf8, 0xff, 0xfe]), ra)
        .unwrap();
    b.send_to(&packet(111, 1, 0, false, &[0xf8, 0xff, 0xfe]), rb)
        .unwrap();
    gather(&a, 100);
    gather(&b, 100);
    // B presses 7: A hears it, in Opus.
    send_event(&b, rb, 7, 10);
    let heard = gather(&a, 400);
    assert_eq!(keys_heard_opus(&heard), [7], "{} packets", heard.len());
    // A plays 4 in Opus: B gets events.
    let mut enc = Encoder::new(rtpflux_core::sdp::Codec::Opus, 8000).unwrap();
    let mut out = [0u8; 512];
    for k in 0..15u16 {
        let pcm: Vec<i16> = if k < 10 {
            tone_frame(4, usize::from(k))
                .iter()
                .map(|&c| g711::ulaw_to_linear(c))
                .collect()
        } else {
            vec![0; 160]
        };
        let n = enc.encode(&pcm, &mut out).unwrap();
        a.send_to(
            &packet(111, 100 + k, u32::from(k) * 960, k == 0, &out[..n]),
            ra,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let got = gather(&b, 300);
    let events: Vec<&Vec<u8>> = got.iter().filter(|p| p[1] & 0x7f == 101).collect();
    assert!(
        !events.is_empty() && events.iter().all(|p| p[12] == 4),
        "{} packets",
        got.len()
    );
}
