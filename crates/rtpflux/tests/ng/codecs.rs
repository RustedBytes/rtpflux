//! Transcoding between PCMU, PCMA, Opus, G.722, G.729 and (with the `amr`
//! feature) AMR.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Offer `offer_formats` (with the codec flags) and answer
/// `answer_formats`; returns (to B, to A, relay towards A, relay towards B).
pub(crate) fn codec_call(
    client: &UdpSocket,
    srv: SocketAddr,
    call_id: &[u8],
    (a, b): (&UdpSocket, &UdpSocket),
    (offer_formats, answer_formats): (&str, &str),
    flags: &[&[u8]],
) -> (Vec<u8>, Vec<u8>, SocketAddr, SocketAddr) {
    let sdp = |s: &UdpSocket, formats: &str| {
        let opus = if formats.split(' ').any(|f| f == "111") {
            "a=rtpmap:111 opus/48000/2\r\n"
        } else {
            ""
        };
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP {formats}\r\na=rtpmap:101 telephone-event/8000\r\n{opus}",
            s.local_addr().unwrap().port()
        )
        .into_bytes()
    };
    let mut all: Vec<&[u8]> = vec![b"trust-address"];
    all.extend_from_slice(flags);
    let send = |cookie: &str, command: &[u8], to_tag: Option<&[u8]>, body: &[u8]| {
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(call_id)),
            ("from-tag", V::S(b"f")),
            ("sdp", V::S(body)),
            ("flags", V::L(&all)),
            ("endpoint-learning", V::S(b"off")),
        ];
        if let Some(t) = to_tag {
            pairs.push(("to-tag", V::S(t)));
        }
        let (result, out, _) = call(client, srv, &request(cookie, &pairs));
        assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&out));
        out
    };
    let to_b = send(
        &format!("{}o", String::from_utf8_lossy(call_id)),
        b"offer",
        None,
        &sdp(a, offer_formats),
    );
    let to_a = send(
        &format!("{}a", String::from_utf8_lossy(call_id)),
        b"answer",
        Some(b"t"),
        &sdp(b, answer_formats),
    );
    std::thread::sleep(Duration::from_millis(50));
    let (ra, rb) = (relay_addr(&to_a), relay_addr(&to_b));
    (to_b, to_a, ra, rb)
}

/// An Opus-only offerer and a PCMU-only answerer: the relay offers PCMU
/// as well, and once it is taken converts both ways, scaling timestamps
/// between Opus's 48 kHz clock and G.711's 8 kHz one.
#[test]
fn opus_is_transcoded_to_pcmu_when_the_answerer_takes_it() {
    let srv = server(49_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (to_b, to_a, for_a, for_b) = codec_call(
        &client,
        srv.addr,
        b"xcode-opus",
        (&a, &b),
        ("111 101", "0 101"),
        &[b"codec-transcode-PCMU"],
    );
    assert!(
        m_line(&to_b).ends_with("RTP/AVP 111 101 0"),
        "{}",
        m_line(&to_b)
    );
    assert!(String::from_utf8_lossy(&to_b).contains("a=rtpmap:0 PCMU/8000\r\n"));
    assert!(
        m_line(&to_a).ends_with("RTP/AVP 111 101"),
        "{}",
        m_line(&to_a)
    );
    assert!(
        String::from_utf8_lossy(&to_a).contains("a=rtpmap:111 opus/48000/2\r\n"),
        "{}",
        String::from_utf8_lossy(&to_a)
    );

    let mut encoder = opus_rs::OpusEncoder::new(48_000, 1, opus_rs::Application::Voip).unwrap();
    let mut decoder = opus_rs::OpusDecoder::new(48_000, 1).unwrap();
    let with_ts = |pt: u8, seq: u16, ts: u32, payload: &[u8]| {
        let mut p = rtp_with(pt, seq, payload);
        p[4..8].copy_from_slice(&ts.to_be_bytes());
        p
    };
    let mut buf = [0u8; 2048];
    let mut stamps = Vec::new();
    for k in 0..5u16 {
        // A -> B: 20 ms of Opus become 160 μ-law codes.
        let pcm: Vec<i16> = (0..960)
            .map(|i| {
                let t = f64::from(u32::from(k) * 960 + i) / 48_000.0;
                #[allow(clippy::cast_possible_truncation)]
                let s = (6000.0 * (2.0 * std::f64::consts::PI * 300.0 * t).sin()) as i16;
                s
            })
            .collect();
        let mut packet = [0u8; 1275];
        let n = encoder.encode_i16(&pcm, 960, &mut packet).unwrap();
        let ts = 48_000 + 960 * u32::from(k);
        a.send_to(&with_ts(111, k, ts, &packet[..n]), for_a)
            .unwrap();
        let (n, _) = b.recv_from(&mut buf).expect("B gets A's audio as PCMU");
        assert_eq!((buf[1] & 0x7f, n), (0, 12 + 160));
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), k, "sequence kept");
        stamps.push(u32::from_be_bytes(buf[4..8].try_into().unwrap()));
        // B -> A: 160 μ-law codes become 20 ms of Opus.
        let ts = 8000 + 160 * u32::from(k);
        b.send_to(&with_ts(0, k, ts, &[0xd5; 160]), for_b).unwrap();
        let (n, _) = a.recv_from(&mut buf).expect("A gets B's audio as Opus");
        assert_eq!(buf[1] & 0x7f, 111);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), ts * 6);
        let mut out = [0f32; 960];
        assert_eq!(decoder.decode(&buf[12..n], 960, &mut out).unwrap(), 960);
    }
    assert!(
        stamps.windows(2).all(|w| w[1].wrapping_sub(w[0]) == 160),
        "{stamps:?}"
    );
    // Telephone events pass untouched.
    let ev = rtp_with(101, 9, &[5, 0x0a, 0, 160]);
    a.send_to(&ev, for_a).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("B gets the event");
    assert_eq!(&buf[..n], &ev[..]);
}

#[test]
fn pcmu_is_transcoded_to_pcma_when_the_answerer_takes_it() {
    use rtpflux_core::g711::{ALAW_TO_ULAW, ULAW_TO_ALAW};
    let srv = server(49_200);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (to_b, to_a, for_a, for_b) = codec_call(
        &client,
        srv.addr,
        b"xcode-1",
        (&a, &b),
        ("0 101", "8 101"),
        &[b"codec-transcode-PCMA", b"codec-mask-PCMU"],
    );
    assert!(
        m_line(&to_b).ends_with("RTP/AVP 8 101"),
        "{}",
        m_line(&to_b)
    );
    assert!(String::from_utf8_lossy(&to_b).contains("a=rtpmap:8 PCMA/8000\r\n"));
    assert!(
        m_line(&to_a).ends_with("RTP/AVP 0 101"),
        "A keeps PCMU: {}",
        m_line(&to_a)
    );

    let samples: Vec<u8> = (0..=255u8).collect();
    let mut buf = [0u8; 2048];
    // A -> B: μ-law in, A-law out, payload type 8.
    a.send_to(&rtp_with(0, 1, &samples), for_a).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("B gets A's audio");
    let want: Vec<u8> = samples
        .iter()
        .map(|&c| ULAW_TO_ALAW[usize::from(c)])
        .collect();
    assert_eq!((buf[1] & 0x7f, &buf[12..n]), (8, &want[..]));
    // B -> A: A-law in, μ-law out.
    b.send_to(&rtp_with(8, 1, &samples), for_b).unwrap();
    let (n, _) = a.recv_from(&mut buf).expect("A gets B's audio");
    let want: Vec<u8> = samples
        .iter()
        .map(|&c| ALAW_TO_ULAW[usize::from(c)])
        .collect();
    assert_eq!((buf[1] & 0x7f, &buf[12..n]), (0, &want[..]));
    // Telephone events pass untouched.
    let ev = rtp_with(101, 2, &[5, 0x0a, 0, 160]);
    a.send_to(&ev, for_a).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("B gets the event");
    assert_eq!(&buf[..n], &ev[..]);
    // Comfort noise passes too.
    let cn = rtp_with(13, 3, &[40]);
    a.send_to(&cn, for_a).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("B gets comfort noise");
    assert_eq!(&buf[..n], &cn[..]);
    // A payload type nobody negotiated, and an empty μ-law payload, are
    // dropped: B (A-law only) gets the next real packet next.
    a.send_to(&rtp_with(99, 4, &samples), for_a).unwrap();
    a.send_to(&rtp_with(0, 5, &[]), for_a).unwrap();
    a.send_to(&rtp_with(0, 6, &samples), for_a).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("B gets A's audio");
    assert_eq!(
        (buf[1] & 0x7f, &buf[2..4], n),
        (8, &6u16.to_be_bytes()[..], 12 + 256)
    );
}

/// A transcoded call holds ZRTP back: the endpoints' end-to-end keys
/// cannot cover media the relay rewrites.
#[test]
fn a_transcoded_call_drops_zrtp() {
    let srv = server(50_400);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (_, _, for_a, for_b) = codec_call(
        &client,
        srv.addr,
        b"xcode-zrtp",
        (&a, &b),
        ("0 101", "8 101"),
        &[b"codec-transcode-PCMA", b"codec-mask-PCMU"],
    );
    let zrtp = [
        0x10, 0, 0, 1, b'Z', b'R', b'T', b'P', 1, 2, 3, 4, 0, 0, 0, 0,
    ];
    let mut buf = [0u8; 2048];
    a.send_to(&zrtp, for_a).unwrap();
    b.set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .unwrap();
    assert!(b.recv_from(&mut buf).is_err(), "A's ZRTP is not relayed");
    b.send_to(&zrtp, for_b).unwrap();
    a.set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .unwrap();
    assert!(a.recv_from(&mut buf).is_err(), "B's ZRTP is not relayed");
}

#[test]
fn no_transcoding_when_the_answerer_keeps_pcmu() {
    let srv = server(49_400);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (to_b, to_a, for_a, _) = codec_call(
        &client,
        srv.addr,
        b"xcode-2",
        (&a, &b),
        ("0 101", "0 101 8"),
        &[b"codec-transcode-PCMA"],
    );
    assert!(
        m_line(&to_b).ends_with("RTP/AVP 0 101 8"),
        "{}",
        m_line(&to_b)
    );
    assert!(
        m_line(&to_a).ends_with("RTP/AVP 0 101"),
        "8 is withdrawn: {}",
        m_line(&to_a)
    );
    let p = rtp_with(0, 1, &[1, 2, 3, 0xff]);
    a.send_to(&p, for_a).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = b.recv_from(&mut buf).expect("B gets A's audio");
    assert_eq!(&buf[..n], &p[..], "relayed as it is");
}

/// A PCMU caller and answerers that only speak G.722 or G.729: the relay
/// adds the codec with its static payload type and `a=rtpmap`, and once it
/// is taken converts both ways (same RTP clock: timestamps unchanged).
#[test]
fn pcmu_to_g722_and_g729() {
    // (codec, payload type, octets per 20 ms)
    for (k, (name, pt, octets)) in [("G722", 9u8, 160usize), ("G729", 18, 20)]
        .into_iter()
        .enumerate()
    {
        let srv = server(50_800 + 200 * u16::try_from(k).unwrap());
        let client = endpoint();
        let (a, b) = (endpoint(), endpoint());
        let flag = format!("codec-transcode-{name}");
        let (to_b, to_a, for_a, for_b) = codec_call(
            &client,
            srv.addr,
            format!("xcode-{name}").as_bytes(),
            (&a, &b),
            ("0 101", &format!("{pt} 101")),
            &[flag.as_bytes(), b"codec-mask-PCMU"],
        );
        assert!(
            m_line(&to_b).ends_with(&format!("RTP/AVP {pt} 101")),
            "{}",
            m_line(&to_b)
        );
        let rtpmap = format!("a=rtpmap:{pt} {name}/8000\r\n");
        assert!(String::from_utf8_lossy(&to_b).contains(&rtpmap), "{name}");
        assert!(
            m_line(&to_a).ends_with("RTP/AVP 0 101"),
            "A keeps PCMU: {}",
            m_line(&to_a)
        );

        let tone: Vec<u8> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (6000.0
                    * (2.0 * std::f64::consts::PI * 500.0 * f64::from(i) / 8000.0).sin())
                    as i16;
                rtpflux_core::g711::linear_to_ulaw(s)
            })
            .collect();
        let mut buf = [0u8; 2048];
        for seq in 1..=3u16 {
            let mut p = rtp_with(0, seq, &tone);
            let ts = 160 * u32::from(seq);
            p[4..8].copy_from_slice(&ts.to_be_bytes());
            a.send_to(&p, for_a).unwrap();
            let (n, _) = b.recv_from(&mut buf).expect("B gets A's audio");
            assert_eq!((buf[1] & 0x7f, n - 12), (pt, octets), "{name}");
            assert_eq!(&buf[4..8], &ts.to_be_bytes(), "{name}: the clocks agree");
            // B's codec back to PCMU for A.
            let back = buf[..n].to_vec();
            b.send_to(&back, for_b).unwrap();
            let (n, _) = a.recv_from(&mut buf).expect("A gets B's audio");
            assert_eq!((buf[1] & 0x7f, n - 12), (0, 160), "{name}");
        }
    }
}

/// An AMR offer in the default bandwidth-efficient packing (no
/// `octet-align=1`) is not transcoded: nothing is added.
#[test]
fn bandwidth_efficient_amr_is_not_transcoded() {
    let srv = server(51_200);
    let client = endpoint();
    let a = endpoint();
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 96\r\na=rtpmap:96 AMR/8000\r\na=fmtp:96 mode-set=7\r\n",
        a.local_addr().unwrap().port()
    );
    let (result, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "amr2",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"amr-be")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer.as_bytes())),
                ("flags", V::L(&[b"trust-address", b"codec-transcode-PCMU"])),
            ],
        ),
    );
    assert_eq!(result, "ok");
    assert!(m_line(&to_b).ends_with("RTP/AVP 96"), "{}", m_line(&to_b));
}

/// With the `amr` feature: a PCMU caller and an AMR-only answerer. The
/// relay offers AMR octet-aligned, and converts 20 ms of G.711 to one
/// 12.2 kbit/s AMR frame (a CMR octet, a TOC octet and 31 octets of
/// speech) and back.
#[cfg(feature = "amr")]
#[test]
fn pcmu_to_amr_octet_aligned() {
    let srv = server(51_400);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let sdp = |s: &UdpSocket, body: &str| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP {body}",
            s.local_addr().unwrap().port()
        )
    };
    let flags: [&[u8]; 3] = [b"trust-address", b"codec-transcode-AMR", b"codec-mask-PCMU"];
    let send = |cookie: &str, command: &[u8], to_tag: Option<&[u8]>, body: &str| {
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(b"amr-call")),
            ("from-tag", V::S(b"f")),
            ("sdp", V::S(body.as_bytes())),
            ("flags", V::L(&flags)),
            ("endpoint-learning", V::S(b"off")),
        ];
        if let Some(t) = to_tag {
            pairs.push(("to-tag", V::S(t)));
        }
        let (result, out, _) = call(&client, srv.addr, &request(cookie, &pairs));
        assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&out));
        out
    };
    let to_b = send("a1", b"offer", None, &sdp(&a, "0\r\n"));
    let text = String::from_utf8_lossy(&to_b);
    let pt: u8 = m_line(&to_b).rsplit(' ').next().unwrap().parse().unwrap();
    assert!(
        text.contains(&format!("a=rtpmap:{pt} AMR/8000\r\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("a=fmtp:{pt} octet-align=1\r\n")),
        "{text}"
    );
    let to_a = send(
        "a2",
        b"answer",
        Some(b"t"),
        &sdp(
            &b,
            &format!("{pt}\r\na=rtpmap:{pt} AMR/8000\r\na=fmtp:{pt} octet-align=1\r\n"),
        ),
    );
    assert!(m_line(&to_a).ends_with("RTP/AVP 0"), "{}", m_line(&to_a));
    std::thread::sleep(Duration::from_millis(50));
    let (for_a, for_b) = (relay_addr(&to_a), relay_addr(&to_b));
    let mut buf = [0u8; 2048];
    for seq in 1..=3u16 {
        a.send_to(&rtp_with(0, seq, &[0x7f; 160]), for_a).unwrap();
        let (n, _) = b.recv_from(&mut buf).expect("B gets AMR");
        assert_eq!((buf[1] & 0x7f, n - 12), (pt, 33));
        let back = buf[..n].to_vec();
        b.send_to(&back, for_b).unwrap();
        let (n, _) = a.recv_from(&mut buf).expect("A gets PCMU");
        assert_eq!((buf[1] & 0x7f, n - 12), (0, 160));
    }
}

/// An answer must take one of the offered formats (RFC 3264 §6.1): a
/// static codec nobody offered is refused, and the call stays as offered;
/// a dynamic payload type may be renumbered, so it passes.
#[test]
fn an_answer_with_only_unoffered_static_codecs_is_refused() {
    let srv = server(58_400);
    let client = endpoint();
    let sdp = |port: u16, fmts: &str| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} RTP/AVP {fmts}\r\n"
        )
        .into_bytes()
    };
    let send = |cookie: &str, cmd: &[u8], id: &[u8], body: &[u8], flags: &[&[u8]]| {
        let mut pairs = vec![
            ("command", V::S(cmd)),
            ("call-id", V::S(id)),
            ("from-tag", V::S(b"a")),
            ("sdp", V::S(body)),
        ];
        if cmd == b"answer" {
            pairs.push(("to-tag", V::S(b"b")));
        }
        if !flags.is_empty() {
            pairs.push(("flags", V::L(flags)));
        }
        let (r, extra, _) = call(&client, srv.addr, &request(cookie, &pairs));
        (r, String::from_utf8_lossy(&extra).into_owned())
    };
    assert_eq!(send("1", b"offer", b"x", &sdp(4000, "0 101"), &[]).0, "ok");
    let (r, why) = send("2", b"answer", b"x", &sdp(5000, "18"), &[]);
    assert_eq!(r, "error");
    assert!(why.contains("none of its formats was offered"), "{why}");
    // A dynamic payload type passes (it may be a renumbered offer).
    assert_eq!(send("3", b"answer", b"x", &sdp(5000, "97"), &[]).0, "ok");
    // The relay's own transcoding codec counts as offered.
    assert_eq!(
        send(
            "4",
            b"offer",
            b"y",
            &sdp(4002, "0"),
            &[b"codec-transcode-G729"]
        )
        .0,
        "ok"
    );
    assert_eq!(send("5", b"answer", b"y", &sdp(5002, "18"), &[]).0, "ok");
}

/// Codec options that do nothing are reported in the reply's `warning`
/// (rtpengine's key), and the offer still succeeds.
#[test]
fn ignored_codec_options_are_warned_about() {
    let srv = server(58_600);
    let client = endpoint();
    let warning = |cookie: &str, id: &[u8], flags: &[&[u8]]| {
        let (r, _, raw) = call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[
                    ("command", V::S(b"offer")),
                    ("call-id", V::S(id)),
                    ("from-tag", V::S(b"a")),
                    ("sdp", V::S(&sdp_for(4000))),
                    ("flags", V::L(flags)),
                ],
            ),
        );
        assert_eq!(r, "ok");
        at(reply_dict(&raw), &[b"warning"]).map(|v| match v {
            rtpflux_ng::bencode::Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        })
    };
    let w = warning("1", b"u", &[b"codec-transcode-FOO"]).unwrap_or_default();
    assert!(w.contains("codec transcode FOO: unknown, ignored"), "{w}");
    let w = warning("2", b"m", &[b"codec-mask-PCMU"]).unwrap_or_default();
    assert!(w.contains("codec mask: ignored"), "{w}");
    // A mask with a codec to transcode to does what it says: no warning.
    assert_eq!(
        warning("3", b"ok", &[b"codec-mask-PCMU", b"codec-transcode-PCMA"]),
        None
    );
}

/// `codec: strip`, `except` and `offer` choose and order the offerer's
/// formats the answerer is offered; the stripped ones' lines go, and the
/// call works with what was kept.
#[test]
fn codecs_are_stripped_kept_and_reordered() {
    let srv = server(54_000);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (to_b, to_a, ..) = codec_call(
        &client,
        srv.addr,
        b"strip-1",
        (&a, &b),
        ("0 8 111 101", "111 101"),
        &[
            b"codec-strip-all",
            b"codec-offer-opus",
            b"codec-except-telephone-event",
        ],
    );
    assert!(
        m_line(&to_b).ends_with("RTP/AVP 111 101"),
        "{}",
        m_line(&to_b)
    );
    assert!(
        String::from_utf8_lossy(&to_b).contains("a=rtpmap:111 opus/48000/2"),
        "{}",
        String::from_utf8_lossy(&to_b)
    );
    assert!(
        m_line(&to_a).ends_with("RTP/AVP 111 101"),
        "{}",
        m_line(&to_a)
    );

    // `strip` alone; `offer` alone reorders and keeps everything.
    let (to_b, ..) = codec_call(
        &client,
        srv.addr,
        b"strip-2",
        (&endpoint(), &endpoint()),
        ("0 8 101", "8 101"),
        &[b"codec-strip-PCMU"],
    );
    assert!(
        m_line(&to_b).ends_with("RTP/AVP 8 101"),
        "{}",
        m_line(&to_b)
    );
    let (to_b, ..) = codec_call(
        &client,
        srv.addr,
        b"strip-3",
        (&endpoint(), &endpoint()),
        ("0 8 101", "8 101"),
        &[b"codec-offer-PCMA"],
    );
    assert!(
        m_line(&to_b).ends_with("RTP/AVP 8 0 101"),
        "{}",
        m_line(&to_b)
    );

    // Everything stripped but a codec to transcode to: the answerer is
    // offered only that (transcoding forced).
    let (to_b, to_a, ..) = codec_call(
        &client,
        srv.addr,
        b"strip-4",
        (&endpoint(), &endpoint()),
        ("0 101", "8"),
        &[b"codec-strip-all", b"codec-transcode-PCMA"],
    );
    assert!(m_line(&to_b).ends_with("RTP/AVP 8"), "{}", m_line(&to_b));
    assert!(m_line(&to_a).ends_with("RTP/AVP 0"), "{}", m_line(&to_a));

    // `strip all` with `transcode` of a codec the offerer has: kept.
    let (to_b, ..) = codec_call(
        &client,
        srv.addr,
        b"strip-5",
        (&endpoint(), &endpoint()),
        ("0 8 101", "8"),
        &[b"codec-strip-all", b"codec-transcode-PCMA"],
    );
    assert!(m_line(&to_b).ends_with("RTP/AVP 8"), "{}", m_line(&to_b));

    // Nothing left: refused, and nothing is created.
    let (r, why, _) = call(
        &client,
        srv.addr,
        &request(
            "strip-6",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"strip-6")),
                ("from-tag", V::S(b"a")),
                ("sdp", V::S(&sdp_for(4000))),
                ("flags", V::L(&[b"codec-strip-PCMU"])),
            ],
        ),
    );
    assert_eq!(
        (r.as_str(), String::from_utf8_lossy(&why).as_ref()),
        (
            "error",
            "codec strip: no codec left to offer in media section 1"
        )
    );
}

/// Options and flags rtpflux does not act on are named in the reply's
/// `warning`; the offer and the answer still succeed.
#[test]
fn unknown_options_are_warned_about() {
    let srv = server(54_200);
    let client = endpoint();
    let send = |cookie: &str, command: &[u8], extra: Vec<(&str, V<'_>)>| {
        let sdp = sdp_for(if command == b"offer" { 4000 } else { 4002 });
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(b"unknown-1")),
            ("from-tag", V::S(b"a")),
            ("sdp", V::S(&sdp)),
        ];
        pairs.extend(extra);
        let (r, out, raw) = call(&client, srv.addr, &request(cookie, &pairs));
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
        at(reply_dict(&raw), &[b"warning"]).map(|v| match v {
            rtpflux_ng::bencode::Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        })
    };
    let w = send(
        "1",
        b"offer",
        vec![
            ("flags", V::L(&[b"trust-address", b"frobnicate"])),
            ("frobnication", V::S(b"caller")),
            ("replace", V::L(&[b"origin", b"frobnicat"])),
        ],
    )
    .unwrap_or_default();
    assert_eq!(
        w,
        "option frobnication: not supported, ignored; flag frobnicate: not supported, ignored; \
         replace frobnicat: not supported, ignored"
    );
    assert_eq!(
        send(
            "2",
            b"answer",
            vec![
                ("to-tag", V::S(b"b")),
                ("flags", V::L(&[b"trust-address"])),
                ("via-branch", V::S(b"z9hG4bK1")),
            ]
        ),
        None
    );
}

/// `ptime`: the answerer's leg gets packets of that duration (`a=ptime`
/// in its offer, the offerer's audio repacketised), and the offerer keeps
/// its own (the answerer's audio cut back to it, paced).
#[test]
fn ptime_repacketises_each_leg() {
    use std::time::Instant;
    let srv = server(55_000);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let sdp = |s: &UdpSocket, ptime: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:{ptime}\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let send = |cookie: &str, command: &[u8], body: &str, extra: Vec<(&str, V<'_>)>| {
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(b"ptime-1")),
            ("from-tag", V::S(b"f")),
            ("sdp", V::S(body.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
        ];
        pairs.extend(extra);
        let (r, out, _) = call(&client, srv.addr, &request(cookie, &pairs));
        (r, String::from_utf8(out).unwrap())
    };
    let (r, why) = send("0", b"offer", &sdp(&a, 20), vec![("ptime", V::I(25))]);
    assert_eq!(
        (r.as_str(), why.as_str()),
        (
            "error",
            "unsupported option ptime: whole milliseconds, a multiple of 10 from 10 to 200"
        )
    );
    let (r, to_b) = send("1", b"offer", &sdp(&a, 20), vec![("ptime", V::S(b"40"))]);
    assert_eq!(r, "ok", "{to_b}");
    assert_eq!(sdp_line(&to_b, "a=ptime:"), Some("40"), "{to_b}");
    assert_eq!(to_b.matches("a=ptime").count(), 1, "{to_b}");
    let (r, to_a) = send("2", b"answer", &sdp(&b, 40), vec![("to-tag", V::S(b"t"))]);
    assert_eq!(r, "ok", "{to_a}");
    assert_eq!(sdp_line(&to_a, "a=ptime:"), Some("20"), "{to_a}");
    std::thread::sleep(Duration::from_millis(50));
    let (relay_a, relay_b) = (relay_addr(to_a.as_bytes()), relay_addr(to_b.as_bytes()));
    let packet = |seq: u16, ts: u32, ms: usize| {
        let mut p = vec![0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p[4..8].copy_from_slice(&ts.to_be_bytes());
        p.extend((0..8 * ms).map(|i| u8::try_from(i % 251).unwrap()));
        p
    };
    let header = |p: &[u8]| {
        (
            u16::from_be_bytes([p[2], p[3]]),
            u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
            p.len() - 12,
        )
    };
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 2048];
    // A → B: four 20 ms packets become two of 40 ms.
    for k in 0..4u16 {
        a.send_to(&packet(500 + k, 1000 + u32::from(k) * 160, 20), relay_a)
            .unwrap();
    }
    let mut got = Vec::new();
    for _ in 0..2 {
        let (n, _) = b.recv_from(&mut buf).expect("B gets 40 ms packets");
        got.push(header(&buf[..n]));
    }
    assert_eq!(got, [(500, 1000, 320), (501, 1320, 320)]);
    // B → A: one 40 ms packet becomes two of 20 ms, the second 20 ms on.
    b.send_to(&packet(9, 50_000, 40), relay_b).unwrap();
    let (n, _) = a.recv_from(&mut buf).expect("the first half");
    let first = Instant::now();
    assert_eq!(header(&buf[..n]), (9, 50_000, 160));
    let (n, _) = a.recv_from(&mut buf).expect("the second half");
    assert_eq!(header(&buf[..n]), (10, 50_160, 160));
    assert!(first.elapsed() >= Duration::from_millis(10), "paced");
}

/// `transcode: opus/48000/2/<bitrate>` (or `codec: set`) sets the relay's
/// Opus encoder: at 12 kbit/s its packets are about half the size of the
/// default 24 kbit/s. Parameters it cannot apply are warned about.
#[test]
fn the_opus_bitrate_is_set() {
    let srv = server(59_100);
    let client = endpoint();
    // A G.711 caller, a callee that takes the Opus the relay adds: the
    // relay encodes Opus for B. The mean payload of 25 packets of a tone.
    let mean_size = |id: &[u8], flags: &[&[u8]]| {
        let (a, b) = (endpoint(), endpoint());
        let (_, _, for_a, _) =
            codec_call(&client, srv.addr, id, (&a, &b), ("0 101", "111 101"), flags);
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 2048];
        let mut total = 0;
        for k in 0..25u16 {
            let tone: Vec<u8> = (0..160u32)
                .map(|i| {
                    let t = f64::from(u32::from(k) * 160 + i) / 8000.0;
                    #[allow(clippy::cast_possible_truncation)]
                    let s = (8000.0 * (2.0 * std::f64::consts::PI * 440.0 * t).sin()) as i16;
                    rtpflux_core::g711::linear_to_ulaw(s)
                })
                .collect();
            let mut p = rtp_with(0, k, &tone);
            p[4..8].copy_from_slice(&(u32::from(k) * 160).to_be_bytes());
            a.send_to(&p, for_a).unwrap();
            let (n, _) = b.recv_from(&mut buf).expect("B gets Opus");
            assert_eq!(buf[1] & 0x7f, 111);
            total += n - 12;
        }
        total / 25
    };
    let default = mean_size(b"opus-rate-1", &[b"codec-transcode-opus"]);
    let low = mean_size(b"opus-rate-2", &[b"codec-transcode-opus/48000/2/12000"]);
    let set = mean_size(
        b"opus-rate-3",
        &[b"codec-transcode-opus", b"codec-set-opus/48000/2/12000"],
    );
    assert!(
        low * 3 < default * 2 && set * 3 < default * 2,
        "{low} {set} vs {default}"
    );

    let (r, _, raw) = call(
        &client,
        srv.addr,
        &request(
            "w",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"opus-rate-4")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(&sdp_for(4000))),
                (
                    "flags",
                    V::L(&[
                        b"codec-transcode-opus/48000/2/999",
                        b"codec-set-PCMA/8000/1/64000",
                    ]),
                ),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let w = match at(reply_dict(&raw), &[b"warning"]) {
        Some(rtpflux_ng::bencode::Value::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    };
    assert!(
        w.contains("codec transcode opus/48000/2/999: an Opus bitrate is 6000 to 510000 bit/s")
            && w.contains(
                "codec set PCMA/8000/1/64000: only Opus's bitrate and AMR's mode can be set"
            ),
        "{w}"
    );
}

/// `ptime` with Opus: decoded and encoded again, so 20 ms packets reach
/// the answerer as 40 ms ones (one Opus frame each).
#[test]
fn ptime_repacketises_opus() {
    let srv = server(61_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let sdp = |s: &UdpSocket| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\na=ptime:20\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let send = |cookie: &str, command: &[u8], s: &UdpSocket| {
        let body = sdp(s);
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(b"ptime-opus")),
            ("from-tag", V::S(b"f")),
            ("sdp", V::S(body.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
            ("ptime", V::I(40)),
        ];
        if command == b"answer" {
            pairs.push(("to-tag", V::S(b"t")));
        }
        let (r, out, raw) = call(&client, srv.addr, &request(cookie, &pairs));
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
        assert!(!String::from_utf8_lossy(&raw).contains("relayed as it is"));
        relay_addr(&out)
    };
    send("1", b"offer", &a);
    let for_a = send("2", b"answer", &b);
    std::thread::sleep(Duration::from_millis(50));
    let mut encoder = opus_rs::OpusEncoder::new(48_000, 1, opus_rs::Application::Voip).unwrap();
    let mut decoder = opus_rs::OpusDecoder::new(48_000, 1).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 2048];
    for k in 0..4u16 {
        let pcm: Vec<i16> = (0..960)
            .map(|i| {
                let t = f64::from(u32::from(k) * 960 + i) / 48_000.0;
                #[allow(clippy::cast_possible_truncation)]
                let s = (6000.0 * (2.0 * std::f64::consts::PI * 300.0 * t).sin()) as i16;
                s
            })
            .collect();
        let mut packet = [0u8; 1275];
        let n = encoder.encode_i16(&pcm, 960, &mut packet).unwrap();
        let mut p = rtp_with(111, k, &packet[..n]);
        p[4..8].copy_from_slice(&(u32::from(k) * 960).to_be_bytes());
        a.send_to(&p, for_a).unwrap();
    }
    for want_ts in [0u32, 1920] {
        let (n, _) = b.recv_from(&mut buf).expect("B gets 40 ms of Opus");
        assert_eq!(buf[1] & 0x7f, 111);
        assert_eq!(u32::from_be_bytes(buf[4..8].try_into().unwrap()), want_ts);
        let mut out = vec![0f32; 5760];
        let samples = decoder.decode(&buf[12..n], 5760, &mut out).unwrap();
        assert_eq!(samples, 1920, "40 ms");
    }
}

/// `transcode: AMR/8000/1/<bitrate>`: the relay encodes AMR in that mode
/// when the answerer's `mode-set` takes it (7.95 kbit/s is mode 5), else in
/// its default (mode 7).
#[cfg(feature = "amr")]
#[test]
fn the_amr_mode_is_set() {
    let srv = server(62_000);
    let client = endpoint();
    let sdp = |s: &UdpSocket, body: &str| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP {body}",
            s.local_addr().unwrap().port()
        )
    };
    let flags: [&[u8]; 3] = [
        b"trust-address",
        b"codec-transcode-AMR/8000/1/7950",
        b"codec-mask-PCMU",
    ];
    // The AMR frame type B gets, with B's `mode-set`.
    let mode_with = |id: &[u8], mode_set: &str| {
        let (a, b) = (endpoint(), endpoint());
        let send = |cookie: &str, command: &[u8], body: &str| {
            let mut pairs = vec![
                ("command", V::S(command)),
                ("call-id", V::S(id)),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(body.as_bytes())),
                ("flags", V::L(&flags)),
                ("endpoint-learning", V::S(b"off")),
            ];
            if command == b"answer" {
                pairs.push(("to-tag", V::S(b"t")));
            }
            let (result, out, _) = call(&client, srv.addr, &request(cookie, &pairs));
            assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&out));
            out
        };
        let to_b = send("o", b"offer", &sdp(&a, "0\r\n"));
        let pt: u8 = m_line(&to_b).rsplit(' ').next().unwrap().parse().unwrap();
        let to_a = send(
            "a",
            b"answer",
            &sdp(
                &b,
                &format!(
                    "{pt}\r\na=rtpmap:{pt} AMR/8000\r\na=fmtp:{pt} octet-align=1;mode-set={mode_set}\r\n"
                ),
            ),
        );
        std::thread::sleep(Duration::from_millis(50));
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 2048];
        let mut p = rtp_with(0, 1, &[0x55; 160]);
        p[4..8].copy_from_slice(&160u32.to_be_bytes());
        a.send_to(&p, relay_addr(&to_a)).unwrap();
        let (n, _) = b.recv_from(&mut buf).expect("B gets AMR");
        assert!(n > 14);
        // Octet-aligned: CMR, then the ToC (F, FT, Q).
        (buf[13] >> 3) & 0x0f
    };
    assert_eq!(mode_with(b"amr-5", "5,7"), 5, "the mode asked for");
    assert_eq!(
        mode_with(b"amr-7", "7"),
        7,
        "B does not take it: the default"
    );
}
