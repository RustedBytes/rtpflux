//! DTMF security (`block DTMF` with `DTMF-security`, triggers) and
//! `DTMF-delay`: the keys the caller presses, as telephone events or
//! in-band tones, reach the callee replaced, dropped, silenced or late.

use crate::common::*;
use crate::features::dtmf_call;
use rtpflux_core::dtmf_inband::{Change, Detector, FRAME};
use rtpflux_core::g711::{linear_to_ulaw, ulaw_to_linear};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// A telephone event packet (payload type 101): `code`, its `ts`, the E
/// bit, `ms` of it so far.
fn event(seq: u16, ts: u32, code: u8, end: bool, ms: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x65 | if ms == 20 { 0x80 } else { 0 }];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ts.to_be_bytes());
    p.extend_from_slice(&[1, 2, 3, 4]);
    p.extend_from_slice(&[code, if end { 0x80 } else { 0 } | 0x0a]);
    p.extend_from_slice(&(ms * 8).to_be_bytes());
    p
}

/// One key pressed (`ms` long) as events, from sequence number `seq`.
fn press(a: &UdpSocket, to: SocketAddr, seq: &mut u16, ts: u32, code: u8, ms: u16) {
    let mut t = 20;
    while t <= ms {
        a.send_to(&event(*seq, ts, code, t == ms, t), to).unwrap();
        *seq += 1;
        t += 20;
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The codes of the events `b` receives (and how many audio packets),
/// until it has been quiet for `quiet`.
fn received(b: &UdpSocket, quiet: Duration) -> (Vec<u8>, usize) {
    b.set_read_timeout(Some(quiet)).unwrap();
    let mut buf = [0u8; 2048];
    let (mut codes, mut audio) = (Vec::new(), 0);
    while let Ok((n, _)) = b.recv_from(&mut buf) {
        if buf[1] & 0x7f == 101 && n >= 16 {
            if codes.last() != Some(&buf[12]) {
                codes.push(buf[12]);
            }
        } else {
            audio += 1;
        }
    }
    (codes, audio)
}

/// `block DTMF` (or `unblock`) of the caller `f` with `more`.
fn block(client: &UdpSocket, srv: SocketAddr, cookie: &str, on: bool, more: &[(&str, V<'_>)]) {
    let command: &[u8] = if on { b"block DTMF" } else { b"unblock DTMF" };
    let mut p = vec![
        ("command", V::S(command)),
        ("call-id", V::S(b"dtmf-1")),
        ("from-tag", V::S(b"f")),
    ];
    p.extend(more.iter().copied());
    let (r, why, _) = call(client, srv, &request(cookie, &p));
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
}

#[test]
fn keys_are_replaced_dropped_or_silenced() {
    let srv = server(63_800);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    let for_a = relay_addr(&to_a);
    let quiet = Duration::from_millis(250);
    let mut seq = 1;
    // Before: keys pass.
    press(&a, for_a, &mut seq, 1000, 5, 60);
    assert_eq!(received(&b, quiet), (vec![5], 0));
    // A plain `block DTMF`: dropped.
    block(&client, srv.addr, "b0", true, &[]);
    press(&a, for_a, &mut seq, 1500, 5, 60);
    assert_eq!(received(&b, quiet), (vec![], 0));
    // `zero` (in its place): every key is 0.
    block(
        &client,
        srv.addr,
        "b1",
        true,
        &[("DTMF-security", V::S(b"zero"))],
    );
    press(&a, for_a, &mut seq, 2000, 5, 60);
    assert_eq!(received(&b, quiet), (vec![0], 0));
    // `DTMF` with a digit.
    block(
        &client,
        srv.addr,
        "b2",
        true,
        &[("DTMF-security", V::S(b"DTMF")), ("digit", V::S(b"#"))],
    );
    press(&a, for_a, &mut seq, 3000, 5, 60);
    assert_eq!(received(&b, quiet), (vec![11], 0));
    // `random`: another key each time, the same over a key's packets.
    block(
        &client,
        srv.addr,
        "b3",
        true,
        &[("DTMF-security", V::S(b"random"))],
    );
    for k in 0..6 {
        press(&a, for_a, &mut seq, 4000 + k * 1000, 5, 60);
        let (codes, _) = received(&b, quiet);
        assert!(
            codes.len() == 1 && codes[0] != 5 && codes[0] < 16,
            "{codes:?}"
        );
    }
    // `silence`: no event; G.711 silence instead, while the key is held.
    block(
        &client,
        srv.addr,
        "b4",
        true,
        &[("DTMF-security", V::S(b"silence"))],
    );
    press(&a, for_a, &mut seq, 20_000, 5, 100);
    let (codes, audio) = received(&b, quiet);
    assert!(codes.is_empty() && audio >= 3, "{codes:?} {audio}");
    // `drop`: nothing.
    block(
        &client,
        srv.addr,
        "b5",
        true,
        &[("DTMF-security", V::S(b"drop"))],
    );
    press(&a, for_a, &mut seq, 21_000, 5, 60);
    assert_eq!(received(&b, quiet), (vec![], 0));
    // `unblock DTMF`: keys pass again.
    block(&client, srv.addr, "b6", false, &[]);
    press(&a, for_a, &mut seq, 22_000, 5, 60);
    assert_eq!(received(&b, quiet), (vec![5], 0));
    // A mode that is none is refused, by name.
    let (r, why, _) = call(
        &client,
        srv.addr,
        &request(
            "b7",
            &[
                ("command", V::S(b"block DTMF")),
                ("call-id", V::S(b"dtmf-1")),
                ("DTMF-security", V::S(b"frobnicate")),
            ],
        ),
    );
    assert_eq!(r, "error");
    assert!(String::from_utf8_lossy(&why).contains("frobnicate"));
}

/// `trigger` (`*1`) switches to `DTMF-security-trigger` (zero) and
/// `trigger-end` (`#`) back; then `trigger-end-digits`.
#[test]
fn a_trigger_switches_the_mode() {
    let srv = server(64_000);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    let for_a = relay_addr(&to_a);
    let quiet = Duration::from_millis(200);
    block(
        &client,
        srv.addr,
        "t1",
        true,
        &[
            ("trigger", V::S(b"*1")),
            ("DTMF-security-trigger", V::S(b"zero")),
            ("trigger-end", V::S(b"#")),
        ],
    );
    let mut seq = 1;
    let mut keys = |codes: &[u8], ts: u32| {
        for (k, &c) in codes.iter().enumerate() {
            press(
                &a,
                for_a,
                &mut seq,
                ts + 1000 * u32::try_from(k).unwrap(),
                c,
                40,
            );
        }
        received(&b, quiet).0
    };
    assert_eq!(keys(&[10, 1], 1000), vec![10, 1], "the trigger passes");
    assert_eq!(keys(&[4, 2, 11], 10_000), vec![0], "then zeroes, # too");
    assert_eq!(keys(&[7], 20_000), vec![7], "until the end");
    block(
        &client,
        srv.addr,
        "t2",
        true,
        &[
            ("trigger", V::S(b"9")),
            ("DTMF-security-trigger", V::S(b"drop")),
            ("trigger-end-digits", V::I(2)),
        ],
    );
    assert_eq!(keys(&[9, 3, 3, 4], 30_000), vec![9, 4], "two keys dropped");
}

/// `DTMF-delay` on the offer: the caller's keys reach the callee that much
/// later, as events.
#[test]
fn dtmf_delay_holds_keys_back() {
    let srv = server(64_200);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    dtmf_call(&client, srv.addr, &a, &b);
    // Again, with the delay (a re-offer keeps the ports).
    let sdp = format!(
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n",
        a.local_addr().unwrap().port()
    );
    let (r, _, _) = call(
        &client,
        srv.addr,
        &request(
            "dl",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"dtmf-1")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(sdp.as_bytes())),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
                ("DTMF-delay", V::I(400)),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let to_a = {
        let answer = format!(
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n",
            b.local_addr().unwrap().port()
        );
        let (r, sdp, _) = call(
            &client,
            srv.addr,
            &request(
                "dm",
                &[
                    ("command", V::S(b"answer")),
                    ("call-id", V::S(b"dtmf-1")),
                    ("from-tag", V::S(b"f")),
                    ("to-tag", V::S(b"t")),
                    ("sdp", V::S(answer.as_bytes())),
                    ("flags", V::L(&[b"trust-address"])),
                    ("endpoint-learning", V::S(b"off")),
                ],
            ),
        );
        assert_eq!(r, "ok");
        sdp
    };
    let for_a = relay_addr(&to_a);
    std::thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    let mut seq = 1;
    press(&a, for_a, &mut seq, 1000, 7, 60);
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = b.recv_from(&mut buf).expect("the key, later");
    let late = start.elapsed();
    assert!(
        n >= 16 && buf[1] & 0x7f == 101 && buf[12] == 7,
        "an event of 7"
    );
    assert!(late >= Duration::from_millis(350), "{late:?}");
    let (codes, _) = received(&b, Duration::from_millis(300));
    assert!(codes.iter().all(|&c| c == 7), "{codes:?}");
}

/// 20 ms of μ-law: key `code`'s two tones (or silence), from sample `at`.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn tones(code: Option<u8>, at: usize) -> Vec<u8> {
    const LOW: [f64; 4] = [697.0, 770.0, 852.0, 941.0];
    const HIGH: [f64; 4] = [1209.0, 1336.0, 1477.0, 1633.0];
    (0..160)
        .map(|i| {
            let v = code.map_or(0.0, |c| {
                let (r, col) = match c {
                    0 => (3, 1),
                    c => ((c - 1) / 3, (c - 1) % 3),
                };
                let x = (at + i) as f64 / 8000.0 * 2.0 * std::f64::consts::PI;
                8000.0 * ((LOW[usize::from(r)] * x).sin() + (HIGH[usize::from(col)] * x).sin())
            });
            linear_to_ulaw(v as i16)
        })
        .collect()
}

/// In-band keys in the caller's G.711 audio: with `zero`, the callee
/// hears 0's tones (after the first few milliseconds of the key).
#[test]
fn inband_keys_are_replaced() {
    let srv = server(64_400);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    let for_a = relay_addr(&to_a);
    block(
        &client,
        srv.addr,
        "i1",
        true,
        &[("DTMF-security", V::S(b"zero"))],
    );
    // 200 ms of silence, 300 ms of key 5, 300 ms of silence.
    for k in 0..40u16 {
        let key = (10..25).contains(&k).then_some(5);
        a.send_to(&rtp_with(0, k, &tones(key, usize::from(k) * 160)), for_a)
            .unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    b.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 2048];
    let mut detector = Detector::default();
    let mut keys = Vec::new();
    while let Ok((n, _)) = b.recv_from(&mut buf) {
        if buf[1] & 0x7f != 0 {
            continue;
        }
        let pcm: Vec<i16> = buf[12..n].iter().map(|&c| ulaw_to_linear(c)).collect();
        for chunk in pcm.chunks(FRAME) {
            if let Some(Change::Start(k)) = detector.frame(chunk) {
                keys.push(k);
            }
        }
    }
    assert!(keys.contains(&0), "0's tones heard: {keys:?}");
    assert_eq!(keys.last(), Some(&0), "{keys:?}");
}
