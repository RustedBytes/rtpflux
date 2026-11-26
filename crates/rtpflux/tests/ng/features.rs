//! DTMF detection, blocking, RTCP statistics and announcements.

use crate::codecs::codec_call;
#[allow(clippy::wildcard_imports)]
use crate::common::*;
use rtpflux_ng::bencode::Value;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

// ---------------------------------------------------------------- DTMF

/// A's telephone events (RFC 4733, payload type 101) are detected once
/// each as they end and reported by `query`; one whose end is lost ends by
/// timing out.
#[test]
fn dtmf_events_are_detected_and_queried() {
    let srv = server(47_800);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_a = dtmf_call(&client, srv.addr, &a, &b);
    let relay_a = SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(&to_a).port);
    let packet = |pt: u8, marker: bool, seq: u16, ts: u32, payload: &[u8]| {
        let mut p = vec![0x80, pt | if marker { 0x80 } else { 0 }];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 9]);
        p.extend_from_slice(payload);
        p
    };
    let event = |code: u8, end: bool, duration: u16| {
        let d = duration.to_be_bytes();
        [code, if end { 0x8a } else { 0x0a }, d[0], d[1]]
    };
    let mut seq = 0u16;
    let mut send = |pt: u8, marker: bool, ts: u32, payload: &[u8]| {
        a.send_to(&packet(pt, marker, seq, ts, payload), relay_a)
            .unwrap();
        seq += 1;
    };
    send(0, false, 0, &[0x55; 160]);
    // '5' at timestamp 1000: 50 ms updates, then the end three times.
    for (i, d) in [400u16, 800, 1200].iter().enumerate() {
        send(101, i == 0, 1000, &event(5, false, *d));
    }
    for _ in 0..3 {
        send(101, false, 1000, &event(5, true, 1600));
    }
    send(0, false, 2600, &[0x55; 160]);
    // '#' at timestamp 4000 whose end packets are lost: it times out.
    send(101, true, 4000, &event(11, false, 400));
    send(101, false, 4000, &event(11, false, 800));
    let mut buf = [0u8; 2048];
    while b.recv_from(&mut buf).is_ok() {}
    std::thread::sleep(Duration::from_millis(1_300)); // a sweep ends '#'

    let (result, _, raw) = call(
        &client,
        srv.addr,
        &request(
            "d3",
            &[("command", V::S(b"query")), ("call-id", V::S(b"dtmf-1"))],
        ),
    );
    assert_eq!(result, "ok");
    let reply = reply_dict(&raw);
    let events: &[&[u8]] = &[b"tags", b"f", b"medias", b"0", b"streams", b"0", b"DTMF"];
    let Some(Value::List(list)) = at(reply, events) else {
        panic!("DTMF list")
    };
    let got: Vec<(Vec<u8>, i64)> = list
        .iter()
        .map(|e| match (at(e, &[b"event"]), at(e, &[b"duration"])) {
            (Some(Value::Bytes(ev)), Some(Value::Int(d))) => (ev.to_vec(), d),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        got,
        vec![(b"5".to_vec(), 200), (b"#".to_vec(), 100)],
        "1600 and 800 units at 8 kHz"
    );
}

/// A plain call whose sides both offer telephone events (PT 101); returns
/// the SDP the relay wrote towards A.
pub(crate) fn dtmf_call(
    client: &UdpSocket,
    srv: SocketAddr,
    a: &UdpSocket,
    b: &UdpSocket,
) -> Vec<u8> {
    let sdp = |port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n"
        )
    };
    let flags: &[&[u8]] = &[b"trust-address"];
    call(
        client,
        srv,
        &request(
            "d1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"dtmf-1")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(sdp(a.local_addr().unwrap().port()).as_bytes())),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    let (_, to_a, _) = call(
        client,
        srv,
        &request(
            "d2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"dtmf-1")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(sdp(b.local_addr().unwrap().port()).as_bytes())),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    std::thread::sleep(Duration::from_millis(50));
    to_a
}

// ------------------------------------------------------ block / unblock

#[test]
fn media_and_dtmf_are_blocked_and_unblocked() {
    let srv = server(48_800);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n",
            s.local_addr().unwrap().port()
        )
        .into_bytes()
    };
    let to_b = exchange_sdp(&client, srv.addr, "k1", b"offer", (b"f", None), &sdp(&a));
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "k2",
        b"answer",
        (b"f", Some(b"t")),
        &sdp(&b),
    );
    let (for_a, for_b) = (relay_addr(&to_a), relay_addr(&to_b));
    let ng = |cookie: &str, command: &[u8], tag: Option<&[u8]>| {
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(b"reinvite@example")),
        ];
        if let Some(t) = tag {
            pairs.push(("from-tag", V::S(t)));
        }
        call(&client, srv.addr, &request(cookie, &pairs)).0
    };
    let event = |seq: u16| {
        let mut p = rtp(seq);
        p[1] = 101;
        p.truncate(12);
        p.extend_from_slice(&[5, 0x0a, 0, 160]);
        p
    };
    // Whether `p` sent from `x` to `to` reaches `y`.
    let passes = |x: &UdpSocket, to: SocketAddr, y: &UdpSocket, p: &[u8]| {
        x.send_to(p, to).unwrap();
        y.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 2048];
        let got = y.recv_from(&mut buf).ok().map(|(n, _)| buf[..n].to_vec());
        y.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        got.as_deref() == Some(p)
    };

    assert!(passes(&a, for_a, &b, &event(1)));
    assert_eq!(ng("k3", b"block DTMF", Some(b"f")), "ok");
    assert!(
        !passes(&a, for_a, &b, &event(2)),
        "A's events are held back"
    );
    assert!(passes(&a, for_a, &b, &rtp(3)), "A's audio passes");
    assert!(passes(&b, for_b, &a, &event(4)), "B's events pass");
    assert_eq!(ng("k4", b"unblock DTMF", Some(b"f")), "ok");
    assert!(passes(&a, for_a, &b, &event(5)));

    assert_eq!(ng("k5", b"block media", Some(b"t")), "ok");
    assert!(!passes(&b, for_b, &a, &rtp(6)), "B's media is held back");
    assert!(passes(&a, for_a, &b, &rtp(7)), "A's passes");
    assert_eq!(ng("k6", b"block media", None), "ok");
    assert!(!passes(&a, for_a, &b, &rtp(8)), "the whole call");
    assert_eq!(ng("k7", b"unblock media", None), "ok");
    assert!(passes(&a, for_a, &b, &rtp(9)));
    assert!(passes(&b, for_b, &a, &rtp(10)));
    assert_eq!(ng("k8", b"block media", Some(b"nobody")), "error");
}

// ------------------------------------------------------- RTCP statistics

#[test]
fn rtcp_reports_reach_query_with_a_round_trip() {
    let srv = server(49_000);
    let client = endpoint();
    let (a, a_rtcp, b, b_rtcp) = (endpoint(), endpoint(), endpoint(), endpoint());
    let sdp = |rtp: &UdpSocket, rtcp: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\na=rtcp:{}\r\n",
            rtp.local_addr().unwrap().port(),
            rtcp.local_addr().unwrap().port()
        )
        .into_bytes()
    };
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "q1",
        b"offer",
        (b"f", None),
        &sdp(&a, &a_rtcp),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "q2",
        b"answer",
        (b"f", Some(b"t")),
        &sdp(&b, &b_rtcp),
    );
    let rtcp_of =
        |s: &[u8]| SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(s).rtcp_port);
    let (for_a, for_b) = (rtcp_of(&to_a), rtcp_of(&to_b));

    // A's SR: NTP 0x0000_1234_5678_0000 (middle word 0x1234_5678), 50
    // packets, 8000 octets, no blocks.
    let mut sr = vec![0x80, 200, 0, 6, 0, 0, 0, 0xaa];
    sr.extend_from_slice(&0x0000_1234_5678_0000u64.to_be_bytes());
    sr.extend_from_slice(&[0, 0, 0, 160]);
    sr.extend_from_slice(&50u32.to_be_bytes());
    sr.extend_from_slice(&8000u32.to_be_bytes());
    a_rtcp.send_to(&sr, for_a).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = b_rtcp.recv_from(&mut buf).expect("B gets A's SR");
    assert_eq!(&buf[..n], &sr[..]);
    std::thread::sleep(Duration::from_millis(30));
    // B's RR about A: 1/4 lost, 3 lost in all, jitter 40, echoing the SR
    // with no delay of its own.
    let mut rr = vec![0x81, 201, 0, 7, 0, 0, 0, 0xbb, 0, 0, 0, 0xaa, 0x40, 0, 0, 3];
    rr.extend_from_slice(&1000u32.to_be_bytes());
    rr.extend_from_slice(&40u32.to_be_bytes());
    rr.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    rr.extend_from_slice(&0u32.to_be_bytes());
    b_rtcp.send_to(&rr, for_b).unwrap();
    let (n, _) = a_rtcp.recv_from(&mut buf).expect("A gets B's RR");
    assert_eq!(&buf[..n], &rr[..]);
    std::thread::sleep(Duration::from_millis(50));

    let (_, _, raw) = call(
        &client,
        srv.addr,
        &request(
            "q3",
            &[
                ("command", V::S(b"query")),
                ("call-id", V::S(b"reinvite@example")),
            ],
        ),
    );
    let rtcp = |tag: &[u8], key: &[u8]| {
        at(
            reply_dict(&raw),
            &[
                b"tags", tag, b"medias", b"0", b"streams", b"1", b"RTCP", key,
            ],
        )
    };
    assert_eq!(rtcp(b"f", b"SSRC"), Some(Value::Int(0xaa)));
    assert_eq!(rtcp(b"f", b"sender packets"), Some(Value::Int(50)));
    assert_eq!(rtcp(b"t", b"fraction lost"), Some(Value::Int(0x40)));
    assert_eq!(rtcp(b"t", b"packets lost"), Some(Value::Int(3)));
    assert_eq!(rtcp(b"t", b"jitter"), Some(Value::Int(40)));
    let Some(Value::Int(ms)) = rtcp(b"t", b"RTT") else {
        panic!("no round trip: {}", String::from_utf8_lossy(&raw))
    };
    assert!((25..1000).contains(&ms), "round trip {ms} ms");
}

// --------------------------------------------------------- announcements

/// A WAV file of μ-law codes.
pub(crate) fn ulaw_wav(codes: &[u8]) -> Vec<u8> {
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

#[test]
fn an_announcement_is_played_to_one_participant() {
    let srv = server(49_800);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (_, _, for_a, for_b) = codec_call(&client, srv.addr, b"play-1", (&a, &b), ("0", "0"), &[]);
    let path = std::env::temp_dir().join(format!("rtpflux-play-{}.wav", std::process::id()));
    let codes: Vec<u8> = (0..400u32)
        .map(|i| u8::try_from(i % 200).unwrap())
        .collect();
    std::fs::write(&path, ulaw_wav(&codes)).unwrap();
    let ng = |cookie: &str, command: &[u8], tag: Option<&[u8]>| {
        let file = path.to_str().unwrap().as_bytes();
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(b"play-1")),
            ("file", V::S(file)),
        ];
        if let Some(t) = tag {
            pairs.push(("from-tag", V::S(t)));
        }
        call(&client, srv.addr, &request(cookie, &pairs))
    };
    assert_eq!(
        ng("p0", b"play media", None).0,
        "error",
        "a listener is needed"
    );
    assert_eq!(ng("p1", b"play media", Some(b"f")).0, "ok");
    // Meanwhile B's audio to A is held back.
    b.send_to(&rtp_with(0, 7, &[1; 160]), for_b).unwrap();
    let mut buf = [0u8; 2048];
    let mut got = Vec::new();
    for _ in 0..3 {
        let (n, src) = a.recv_from(&mut buf).expect("an announcement packet");
        assert_eq!(src, for_a, "from the relay's port facing A");
        got.push(buf[..n].to_vec());
    }
    // Random initial sequence number and timestamp (RFC 3550 §5.1), then
    // one packet of 160 samples after another; the first is marked.
    let seq0 = u16::from_be_bytes([got[0][2], got[0][3]]);
    let ts0 = u32::from_be_bytes([got[0][4], got[0][5], got[0][6], got[0][7]]);
    for (k, p) in got.iter().enumerate() {
        let k16 = u16::try_from(k).unwrap();
        assert_eq!(p.len(), 12 + 160);
        assert_eq!(p[1] & 0x7f, 0, "PCMU");
        assert_eq!(p[1] & 0x80 != 0, k == 0, "the marker on the first only");
        assert_eq!(u16::from_be_bytes([p[2], p[3]]), seq0.wrapping_add(k16));
        assert_eq!(
            u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
            ts0.wrapping_add(160 * u32::from(k16))
        );
        assert_eq!(&p[8..12], &got[0][8..12], "one SSRC");
    }
    assert_eq!(&got[0][12..], &codes[..160]);
    assert_eq!(&got[2][12..92], &codes[320..]);
    assert!(
        got[2][92..].iter().all(|&c| c == 0xFF),
        "padded with silence"
    );
    // Played out: B's audio reaches A again.
    std::thread::sleep(Duration::from_millis(60));
    let p = rtp_with(0, 8, &[2; 160]);
    b.send_to(&p, for_b).unwrap();
    let (n, _) = a.recv_from(&mut buf).expect("B's audio again");
    assert_eq!(&buf[..n], &p[..]);
    std::fs::remove_file(&path).unwrap();
}
