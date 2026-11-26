//! `play DTMF`, `silence media` / `unsilence media` and `statistics`.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use crate::features::dtmf_call;
use rtpflux_ng::bencode::Value;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn relay(sdp: &[u8]) -> SocketAddr {
    SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(sdp).port)
}

/// Every datagram `s` receives within `ms`.
fn gather(s: &UdpSocket, ms: u64) -> Vec<Vec<u8>> {
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let end = Instant::now() + Duration::from_millis(ms);
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < end {
        if let Ok((n, _)) = s.recv_from(&mut buf) {
            out.push(buf[..n].to_vec());
        }
    }
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    out
}

fn ok(client: &UdpSocket, srv: SocketAddr, cookie: &str, pairs: &[(&str, V<'_>)]) -> Vec<u8> {
    let (result, extra, raw) = call(client, srv, &request(cookie, pairs));
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&extra));
    raw
}

fn payload_type(p: &[u8]) -> u8 {
    p[1] & 0x7f
}

fn ts(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[4], p[5], p[6], p[7]])
}

/// "1#" pressed for A: B gets RFC 4733 events (payload type 101), one
/// timestamp per key, the marker on its first packet, durations growing by
/// 20 ms, three end packets with the full duration, the volume asked for,
/// one SSRC. A's own media to B is held back meanwhile and flows after.
#[test]
fn play_dtmf_as_telephone_events() {
    let srv = server(51_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    ok(
        &client,
        srv.addr,
        "p1",
        &[
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"dtmf-1")),
            ("from-tag", V::S(b"f")),
            ("code", V::S(b"1#")),
            ("duration", V::I(100)),
            ("pause", V::I(80)),
            ("volume", V::I(10)),
        ],
    );
    let got = gather(&b, 800);
    let events: Vec<&Vec<u8>> = got.iter().filter(|p| p[1] & 0x7f == 101).collect();
    assert!(
        got.iter().all(|p| p[1] & 0x7f == 101),
        "only events while playing"
    );
    // Per key: 100 ms in 20 ms steps (5 packets), then 3 end packets.
    assert_eq!(events.len(), 16, "{}", events.len());
    for (k, key) in events.chunks(8).enumerate() {
        let code = [1u8, 11][k];
        assert_eq!(key[0][1] & 0x80, 0x80, "marker on the first");
        assert!(key[1..].iter().all(|p| p[1] & 0x80 == 0));
        assert!(
            key.iter()
                .all(|p| ts(p) == ts(key[0]) && p[12] == code && p[13] & 0x3f == 10)
        );
        let durations: Vec<u16> = key
            .iter()
            .map(|p| u16::from_be_bytes([p[14], p[15]]))
            .collect();
        assert_eq!(
            durations,
            [160, 320, 480, 640, 800, 800, 800, 800],
            "key {k}"
        );
        let ends: Vec<bool> = key.iter().map(|p| p[13] & 0x80 != 0).collect();
        assert_eq!(ends, [false, false, false, false, false, true, true, true]);
    }
    assert!(ts(events[8]) > ts(events[0]), "the second key later");
    let ssrc = &events[0][8..12];
    assert!(events.iter().all(|p| &p[8..12] == ssrc));
    // Sequence numbers one by one.
    let seqs: Vec<u16> = events
        .iter()
        .map(|p| u16::from_be_bytes([p[2], p[3]]))
        .collect();
    assert!(
        seqs.windows(2).all(|w| w[1] == w[0].wrapping_add(1)),
        "{seqs:?}"
    );
    // After the tones, A's media reaches B again.
    a.send_to(&rtp(1), relay(&to_a)).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = b.recv_from(&mut buf).expect("A's media flows again");
    assert_eq!(&buf[..n], &rtp(1)[..]);
    // B pressing: A hears it.
    ok(
        &client,
        srv.addr,
        "p2",
        &[
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"dtmf-1")),
            ("from-tag", V::S(b"t")),
            ("code", V::I(12)),
            ("duration", V::I(60)),
        ],
    );
    let got = gather(&a, 400);
    assert!(
        got.iter().any(|p| p[1] & 0x7f == 101 && p[12] == 12),
        "A gets 'A'"
    );
    // A value that is not a number is refused (numbers out of range are
    // clamped, as rtpengine does).
    for key in ["duration", "pause", "volume"] {
        let (result, extra, _) = call(
            &client,
            srv.addr,
            &request(
                &format!("nan-{key}"),
                &[
                    ("command", V::S(b"play DTMF")),
                    ("call-id", V::S(b"dtmf-1")),
                    ("from-tag", V::S(b"t")),
                    ("code", V::S(b"1")),
                    (key, V::S(b"loud")),
                ],
            ),
        );
        assert_eq!(result, "error");
        assert!(
            String::from_utf8_lossy(&extra).contains(&format!("{key}: not a number")),
            "{}",
            String::from_utf8_lossy(&extra)
        );
    }
}

/// Without telephone events, the key is played in-band, in the law B
/// receives: the energy is at the key's two frequencies.
#[test]
#[allow(clippy::cast_precision_loss)]
fn play_dtmf_in_band() {
    let srv = server(51_700);
    let client = endpoint();
    let (caller, callee) = (endpoint(), endpoint());
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "i1",
        b"offer",
        (b"f", None),
        &sdp_for(caller.local_addr().unwrap().port()),
    );
    exchange_sdp(
        &client,
        srv.addr,
        "i2",
        b"answer",
        (b"f", Some(b"t")),
        &sdp_for(callee.local_addr().unwrap().port()),
    );
    let _ = to_b;
    std::thread::sleep(Duration::from_millis(50));
    ok(
        &client,
        srv.addr,
        "i3",
        &[
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(b"f")),
            ("code", V::S(b"5")),
            ("duration", V::I(200)),
            ("pause", V::I(0)),
        ],
    );
    let got = gather(&callee, 500);
    let audio: Vec<i16> = got
        .iter()
        .filter(|p| p[1].trailing_zeros() >= 7 && p.len() == 172)
        .flat_map(|p| {
            p[12..]
                .iter()
                .map(|&c| rtpflux_core::g711::ulaw_to_linear(c))
        })
        .collect();
    assert!(audio.len() >= 1600, "{} samples", audio.len());
    // Goertzel power at a frequency.
    let power = |f: f64| {
        let w = 2.0 * std::f64::consts::PI * f / 8000.0;
        let (mut re, mut im) = (0.0, 0.0);
        for (i, &v) in audio[..1600].iter().enumerate() {
            re += f64::from(v) * (w * i as f64).cos();
            im += f64::from(v) * (w * i as f64).sin();
        }
        re * re + im * im
    };
    // '5' is 770 + 1336 Hz; the other row and column frequencies are quiet.
    let (low, high) = (power(770.0), power(1336.0));
    for other in [697.0, 852.0, 941.0, 1209.0, 1477.0, 1633.0] {
        assert!(
            power(other) < low / 100.0 && power(other) < high / 100.0,
            "{other} Hz"
        );
    }
}

/// Silenced, A's G.711 reaches B as silence (the stream goes on); its
/// telephone events pass; another payload type is held back. Unsilenced,
/// the audio is A's again.
#[test]
fn silence_and_unsilence_media() {
    let srv = server(51_800);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    let silence = |cookie: &str, command: &[u8]| {
        ok(
            &client,
            srv.addr,
            cookie,
            &[
                ("command", V::S(command)),
                ("call-id", V::S(b"dtmf-1")),
                ("from-tag", V::S(b"f")),
            ],
        );
    };
    silence("s1", b"silence media");
    let mut buf = [0u8; 2048];
    let send = |pt: u8, seq: u16, payload: &[u8]| {
        a.send_to(&rtp_with(pt, seq, payload), relay(&to_a))
            .unwrap()
    };
    send(0, 1, &[0x55; 160]);
    let (n, _) = b.recv_from(&mut buf).expect("silence");
    assert_eq!((buf[1] & 0x7f, &buf[2..4]), (0, &1u16.to_be_bytes()[..]));
    assert!(buf[12..n].iter().all(|&c| c == 0xff), "μ-law silence");
    send(101, 2, &[5, 0x0a, 0, 160]);
    let (n, _) = b.recv_from(&mut buf).expect("the event");
    assert_eq!(&buf[12..n], &[5, 0x0a, 0, 160]);
    send(96, 3, &[1, 2, 3]);
    b.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(b.recv_from(&mut buf).is_err(), "other audio held back");
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    silence("s2", b"unsilence media");
    send(0, 4, &[0x55; 160]);
    let (n, _) = b.recv_from(&mut buf).expect("A's audio again");
    assert!(buf[12..n].iter().all(|&c| c == 0x55));
}

/// `statistics`: sessions, transcoded media, relayed packets and the
/// requests per command, in rtpengine's form.
#[test]
fn statistics_report_the_relay() {
    let srv = server(51_900);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    a.send_to(&rtp(1), relay(&to_a)).unwrap();
    let mut buf = [0u8; 2048];
    b.recv_from(&mut buf).expect("relayed");
    let raw = ok(&client, srv.addr, "st", &[("command", V::S(b"statistics"))]);
    let reply = reply_dict(&raw);
    let int = |path: &[&[u8]]| match at(reply, path) {
        Some(Value::Int(n)) => n,
        other => panic!("{path:?}: {other:?}"),
    };
    let s: &[u8] = b"statistics";
    assert_eq!(int(&[s, b"currentstatistics", b"sessionsown"]), 1);
    assert_eq!(int(&[s, b"currentstatistics", b"sessionsforeign"]), 0);
    assert_eq!(int(&[s, b"currentstatistics", b"transcodedmedia"]), 0);
    assert!(int(&[s, b"totalstatistics", b"relayedpackets"]) >= 1);
    assert!(int(&[s, b"totalstatistics", b"uptime"]) >= 0);
    assert_eq!(int(&[s, b"controlstatistics", b"requests", b"offer"]), 1);
    assert_eq!(
        int(&[s, b"controlstatistics", b"requests", b"statistics"]),
        1
    );
}

/// `statistics`' rates: 50 packets a second relayed for a few seconds
/// read as about 50 packets and 50 times their size in octets a second
/// (the rates are over the latest second sampled).
#[test]
fn statistics_report_rates() {
    let srv = server(63_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    let mut buf = [0u8; 2048];
    let size = i64::try_from(rtp(0).len()).unwrap();
    for seq in 0..150u16 {
        a.send_to(&rtp(seq), relay(&to_a)).unwrap();
        b.recv_from(&mut buf).expect("relayed");
        std::thread::sleep(Duration::from_millis(20));
    }
    let raw = ok(&client, srv.addr, "sr", &[("command", V::S(b"statistics"))]);
    let reply = reply_dict(&raw);
    let int = |key: &[u8]| match at(reply, &[b"statistics", b"currentstatistics", key]) {
        Some(Value::Int(n)) => n,
        other => panic!("{}: {other:?}", String::from_utf8_lossy(key)),
    };
    // Sleeping 20 ms between sends (and a reply's wait) is a little under
    // 50 a second.
    let rate = int(b"packetrate_user");
    assert!((30..=55).contains(&rate), "{rate}");
    assert_eq!(int(b"packetrate"), rate + int(b"packetrate_kernel"));
    let bytes = int(b"byterate_user");
    assert!(
        (rate - 2) * size <= bytes && bytes <= (rate + 2) * size,
        "{bytes}"
    );
    assert_eq!(int(b"errorrate_user"), 0);
    match at(reply, &[b"statistics", b"totalstatistics", b"relayedbytes"]) {
        Some(Value::Int(n)) => assert_eq!(n, 150 * size),
        other => panic!("{other:?}"),
    }
}

#[test]
fn play_dtmf_errors() {
    let srv = server(52_000);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    dtmf_call(&client, srv.addr, &a, &b);
    let reason = |cookie: &str, pairs: &[(&str, V<'_>)]| {
        let (result, reason, _) = call(&client, srv.addr, &request(cookie, pairs));
        assert_eq!(result, "error");
        String::from_utf8(reason).unwrap()
    };
    let base = |code: Option<V<'static>>| {
        let mut p = vec![
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"dtmf-1")),
            ("from-tag", V::S(b"f")),
        ];
        if let Some(c) = code {
            p.push(("code", c));
        }
        p
    };
    assert_eq!(reason("e1", &base(None)), "missing code");
    assert!(reason("e2", &base(Some(V::S(b"1Z")))).starts_with("code:"));
    assert!(reason("e3", &base(Some(V::I(16)))).starts_with("code:"));
    let mut unknown = base(Some(V::S(b"1")));
    unknown[1] = ("call-id", V::S(b"nope"));
    assert_eq!(reason("e4", &unknown), "unknown call or tag");
}

/// `stop media` while keys still play to a party: the other party's audio
/// stays held back until the keys are over (it was let through at once).
#[test]
fn stop_media_keeps_the_hold_of_keys_still_playing() {
    let srv = server(57_300);
    let client = endpoint();
    let (caller, callee) = (endpoint(), endpoint());
    exchange_sdp(
        &client,
        srv.addr,
        "h1",
        b"offer",
        (b"f", None),
        &sdp_for(caller.local_addr().unwrap().port()),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "h2",
        b"answer",
        (b"f", Some(b"t")),
        &sdp_for(callee.local_addr().unwrap().port()),
    );
    let for_caller = relay_addr(&to_a);
    std::thread::sleep(Duration::from_millis(50));
    // The caller "presses" two keys of a second each: the callee hears them.
    ok(
        &client,
        srv.addr,
        "h3",
        &[
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(b"f")),
            ("code", V::S(b"5*")),
            ("duration", V::I(1000)),
            ("pause", V::I(0)),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    ok(
        &client,
        srv.addr,
        "h4",
        &[
            ("command", V::S(b"stop media")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(b"t")),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    // The caller's own audio does not reach the callee meanwhile.
    let mine = rtp_with(0, 77, &[0x42; 160]);
    for _ in 0..5 {
        caller.send_to(&mine, for_caller).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let got = gather(&callee, 300);
    assert!(!got.is_empty(), "the keys go on");
    assert!(
        got.iter().all(|p| p[12..] != mine[12..]),
        "the caller's audio is held back"
    );
}

/// Keys pressed for A while an announcement plays to B: one stream, whose
/// clock goes at its rate. The announcement's packets keep 160 ticks per
/// 20 ms (the keys' packets do not move it on twice), and the sequence
/// numbers count the packets of both.
#[test]
fn keys_over_an_announcement_keep_the_clock() {
    let srv = server(57_400);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    dtmf_call(&client, srv.addr, &a, &b);
    let blob = crate::features::ulaw_wav(&[0x55; 8000]);
    ok(
        &client,
        srv.addr,
        "k1",
        &[
            ("command", V::S(b"play media")),
            ("call-id", V::S(b"dtmf-1")),
            ("from-tag", V::S(b"t")),
            ("blob", V::S(&blob)),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    ok(
        &client,
        srv.addr,
        "k2",
        &[
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"dtmf-1")),
            ("from-tag", V::S(b"f")),
            ("code", V::S(b"1")),
            ("duration", V::I(200)),
        ],
    );
    let got = gather(&b, 500);
    let seq = |p: &[u8]| u16::from_be_bytes([p[2], p[3]]);
    let audio: Vec<&Vec<u8>> = got.iter().filter(|p| payload_type(p) == 0).collect();
    let events = got.iter().filter(|p| p[1] & 0x7f == 101).count();
    assert!(events >= 10, "keys played: {events}");
    assert!(audio.len() >= 10, "announcement played: {}", audio.len());
    for w in audio.windows(2) {
        let packets = u32::from(seq(w[1]).wrapping_sub(seq(w[0])));
        let ticks = ts(w[1]).wrapping_sub(ts(w[0]));
        // Between two of its packets: 20 ms each, whatever came between.
        assert!(
            ticks == 160 || (packets > 1 && ticks.is_multiple_of(160) && ticks <= 160 * packets),
            "{ticks} ticks over {packets} packets"
        );
    }
    let ssrc = &got[0][8..12];
    assert!(got.iter().all(|p| &p[8..12] == ssrc), "one stream");
    assert!(
        got.windows(2)
            .all(|w| seq(&w[1]) == seq(&w[0]).wrapping_add(1)),
        "sequence numbers count both"
    );
}

/// In-band keys pressed for A while an announcement plays to B (no
/// telephone events offered): both are audio, and one stream carries one
/// of them at a time. While the keys play, the announcement goes on
/// unsent: the packets are the announcement's, then the keys', then the
/// announcement's again, never mixed.
#[test]
fn in_band_keys_over_an_announcement_take_the_stream() {
    let srv = server(57_500);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    exchange_sdp(
        &client,
        srv.addr,
        "o",
        b"offer",
        (b"f", None),
        &sdp_for(port(&a)),
    );
    exchange_sdp(
        &client,
        srv.addr,
        "a",
        b"answer",
        (b"f", Some(b"t")),
        &sdp_for(port(&b)),
    );
    let blob = crate::features::ulaw_wav(&[0x55; 8000]);
    ok(
        &client,
        srv.addr,
        "i1",
        &[
            ("command", V::S(b"play media")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(b"t")),
            ("blob", V::S(&blob)),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    ok(
        &client,
        srv.addr,
        "i2",
        &[
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(b"f")),
            ("code", V::S(b"5")),
            ("duration", V::I(200)),
            ("pause", V::I(0)),
        ],
    );
    let got = gather(&b, 500);
    assert!(got.iter().all(|p| payload_type(p) == 0), "audio only");
    let kinds: String = got
        .iter()
        .map(|p| {
            if p[12..].iter().any(|&c| c != 0x55) {
                'k'
            } else {
                'a'
            }
        })
        .collect();
    let runs = kinds.as_bytes().windows(2).filter(|w| w[0] != w[1]).count();
    assert!(kinds.contains("kkkkkkkk"), "keys played: {kinds}");
    assert!(runs <= 2, "never mixed: {kinds}");
    assert!(
        got.windows(2).all(|w| {
            let d = ts(&w[1]).wrapping_sub(ts(&w[0]));
            d == 160
        }),
        "the clock goes on, 20 ms a packet"
    );
}

/// B's m-line lists only PCMU, with an `a=rtpmap` for telephone events it
/// does not offer: keys pressed for A reach B as tones, not as events of a
/// payload type B never took.
#[test]
fn keys_to_a_party_without_events_listed_are_tones() {
    let srv = server(57_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    crate::codecs::codec_call(&client, srv.addr, b"unlisted-1", (&a, &b), ("0", "0"), &[]);
    ok(
        &client,
        srv.addr,
        "u1",
        &[
            ("command", V::S(b"play DTMF")),
            ("call-id", V::S(b"unlisted-1")),
            ("from-tag", V::S(b"f")),
            ("code", V::S(b"5")),
            ("duration", V::I(100)),
        ],
    );
    let got = gather(&b, 400);
    assert!(!got.is_empty(), "keys played");
    assert!(
        got.iter().all(|p| payload_type(p) == 0),
        "tones in PCMU only"
    );
}
