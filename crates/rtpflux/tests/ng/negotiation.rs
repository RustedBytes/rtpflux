//! Encryption and `rtcp-mux` negotiation options: `SDES`, `DTLS` and
//! `rtcp-mux`, as rtpengine names them.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const HEAD: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n";

/// Send `command` for call `id` with `sdp` and the extra `pairs`; returns
/// (result, SDP or error reason, warning).
fn send(
    client: &UdpSocket,
    srv: SocketAddr,
    (cookie, command, id): (&str, &[u8], &[u8]),
    sdp: &str,
    pairs: Vec<(&str, V<'_>)>,
) -> (String, String, Option<String>) {
    let mut all = vec![
        ("command", V::S(command)),
        ("call-id", V::S(id)),
        ("from-tag", V::S(b"f")),
        ("sdp", V::S(sdp.as_bytes())),
        ("endpoint-learning", V::S(b"off")),
    ];
    if command == b"answer" {
        all.push(("to-tag", V::S(b"t")));
    }
    all.extend(pairs);
    let (r, out, raw) = call(client, srv, &request(cookie, &all));
    let warning = at(reply_dict(&raw), &[b"warning"]).map(|v| match v {
        rtpflux_ng::bencode::Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    });
    (r, String::from_utf8(out).unwrap(), warning)
}

/// `SDES`: `only-` and `no-` choose the suite the relay offers the
/// answerer; `off` with an SDES profile, or options that leave no suite,
/// are refused; values rtpflux does not act on are warned about.
#[test]
fn sdes_options_choose_the_suite() {
    let srv = server(54_400);
    let client = endpoint();
    let plain = format!("{HEAD}m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n");
    let suite = |sdp: &str| {
        sdp_line(sdp, "a=crypto:1 ")
            .and_then(|c| c.split(' ').next())
            .map(str::to_owned)
    };
    let offer = |cookie: &str, id: &[u8], extra: Vec<(&str, V<'_>)>| {
        let mut pairs = vec![
            ("transport-protocol", V::S(b"RTP/SAVP")),
            ("flags", V::L(&[b"trust-address"])),
        ];
        pairs.extend(extra);
        send(&client, srv.addr, (cookie, b"offer", id), &plain, pairs)
    };
    let (r, sdp, w) = offer("1", b"sdes-1", vec![]);
    assert_eq!((r.as_str(), w), ("ok", None), "{sdp}");
    assert_eq!(suite(&sdp).as_deref(), Some("AES_CM_128_HMAC_SHA1_80"));
    let (r, sdp, _) = offer(
        "2",
        b"sdes-2",
        vec![("SDES", V::L(&[b"only-AEAD_AES_256_GCM"]))],
    );
    assert_eq!(r, "ok", "{sdp}");
    assert_eq!(suite(&sdp).as_deref(), Some("AEAD_AES_256_GCM"));
    let (r, sdp, w) = offer(
        "3",
        b"sdes-3",
        vec![(
            "SDES",
            V::L(&[b"no-AES_CM_128_HMAC_SHA1_80", b"frobnicate"]),
        )],
    );
    assert_eq!(r, "ok", "{sdp}");
    assert_eq!(suite(&sdp).as_deref(), Some("AES_CM_128_HMAC_SHA1_32"));
    assert_eq!(
        w.as_deref(),
        Some("SDES frobnicate: not supported, ignored")
    );
    // As flags, the way Kamailio may pass them through.
    let (r, why, _) = send(
        &client,
        srv.addr,
        ("4", b"offer", b"sdes-4"),
        &plain,
        vec![
            ("transport-protocol", V::S(b"RTP/SAVP")),
            (
                "flags",
                V::L(&[b"SDES-only-AEAD_AES_128_GCM", b"SDES-no-AEAD_AES_128_GCM"]),
            ),
        ],
    );
    assert_eq!(
        (r.as_str(), why.as_str()),
        ("error", "SDES: the no-/only- options leave no crypto suite")
    );
    let (r, why, _) = offer("5", b"sdes-5", vec![("SDES", V::L(&[b"off"]))]);
    assert_eq!(
        (r.as_str(), why.as_str()),
        (
            "error",
            "SDES: off, but the answerer is offered an SDES profile (set transport-protocol)"
        )
    );
    // `off` towards a plain answerer is what happens anyway.
    let (r, sdp, w) = send(
        &client,
        srv.addr,
        ("6", b"offer", b"sdes-6"),
        &plain,
        vec![("flags", V::L(&[b"SDES-off"]))],
    );
    assert_eq!((r.as_str(), w), ("ok", None), "{sdp}");
    assert!(!sdp.contains("a=crypto"), "{sdp}");
}

/// `DTLS=active`: the relay offers `active` and starts the handshake once
/// the answerer took `passive`; an answer that does not fit the offered
/// setup is refused; `DTLS=off` towards a DTLS profile is refused.
#[test]
fn dtls_options_set_the_relays_role() {
    use rtpflux::dtls::{Association, Identity};
    use rtpflux_core::dtls::{Fingerprint, Role};
    let srv = server(54_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let peer = Identity::generate().unwrap();
    let offer = |cookie: &str, id: &[u8], dtls: &'static [u8]| {
        send(
            &client,
            srv.addr,
            (cookie, b"offer", id),
            &format!(
                "{HEAD}m=audio {} RTP/AVP 0\r\na=sendrecv\r\n",
                a.local_addr().unwrap().port()
            ),
            vec![
                ("transport-protocol", V::S(b"UDP/TLS/RTP/SAVP")),
                ("flags", V::L(&[b"trust-address"])),
                ("DTLS", V::S(dtls)),
            ],
        )
    };
    let answer = |cookie: &str, id: &[u8], setup: &str| {
        send(
            &client,
            srv.addr,
            (cookie, b"answer", id),
            &format!(
                "{HEAD}m=audio {} UDP/TLS/RTP/SAVP 0\r\na=setup:{setup}\r\na=fingerprint:{}\r\n\
                 a=sendrecv\r\n",
                b.local_addr().unwrap().port(),
                peer.fingerprint()
            ),
            vec![("flags", V::L(&[b"trust-address"]))],
        )
    };
    let (r, why, _) = offer("1", b"dtls-off", b"off");
    assert_eq!(
        (r.as_str(), why.as_str()),
        (
            "error",
            "DTLS=off: the answerer is offered a DTLS-SRTP profile (set transport-protocol)"
        )
    );
    let (r, why, _) = offer("2", b"dtls-bad", b"sometimes");
    assert_eq!(
        (r.as_str(), why.as_str()),
        ("error", "unsupported option DTLS sometimes")
    );

    // Passive offered: an answerer that is passive too is refused.
    let (r, to_b, _) = offer("3", b"dtls-p", b"passive");
    assert_eq!(r, "ok", "{to_b}");
    assert_eq!(sdp_line(&to_b, "a=setup:"), Some("passive"));
    let (r, _, _) = answer("4", b"dtls-p", "passive");
    assert_eq!(r, "error");

    // Active offered, passive answered: the relay is the client.
    let (r, to_b, _) = offer("5", b"dtls-a", b"active");
    assert_eq!(r, "ok", "{to_b}");
    assert_eq!(sdp_line(&to_b, "a=setup:"), Some("active"));
    let relay_fp = sdp_line(&to_b, "a=fingerprint:").unwrap().to_owned();
    let relay_b = first_media(to_b.as_bytes());
    let (r, to_a, _) = answer("6", b"dtls-a", "passive");
    assert_eq!(r, "ok", "{to_a}");
    let relay_a = first_media(to_a.as_bytes());
    let mut dtls = Association::new(
        &peer,
        Role::Server,
        [Fingerprint::parse(relay_fp.as_bytes()), None],
    )
    .unwrap();
    let to_relay_b = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_b.port);
    let to_relay_a = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_a.port);
    let keys = crate::secure::dtls_handshake(&b, to_relay_b, &mut dtls);
    std::thread::sleep(Duration::from_millis(20));
    crate::secure::srtp_both_ways(&b, to_relay_b, &a, to_relay_a, keys);
}

/// `DTLS=active` at the answer: towards an `actpass` offerer the relay
/// answers `active` (and starts the handshake), instead of `passive`.
#[test]
fn dtls_active_answers_an_actpass_offerer() {
    let srv = server(54_700);
    let client = endpoint();
    let offer_sdp = format!(
        "{HEAD}m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\n\
         a=fingerprint:sha-256 {}\r\na=sendrecv\r\n",
        ["AB"; 32].join(":")
    );
    let (r, to_b, _) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"dtls-ans"),
        &offer_sdp,
        vec![
            ("transport-protocol", V::S(b"RTP/AVP")),
            ("flags", V::L(&[b"trust-address"])),
        ],
    );
    assert_eq!(r, "ok", "{to_b}");
    let answer_sdp = format!("{HEAD}m=audio 4002 RTP/AVP 0\r\na=sendrecv\r\n");
    let (r, to_a, w) = send(
        &client,
        srv.addr,
        ("2", b"answer", b"dtls-ans"),
        &answer_sdp,
        vec![
            ("flags", V::L(&[b"trust-address"])),
            ("DTLS", V::S(b"active")),
        ],
    );
    assert_eq!((r.as_str(), w), ("ok", None), "{to_a}");
    assert_eq!(sdp_line(&to_a, "a=setup:"), Some("active"));
}

/// Two sockets on consecutive ports (RTP and RTCP without `rtcp-mux`).
fn rtp_rtcp_pair() -> (UdpSocket, UdpSocket) {
    for _ in 0..50 {
        let rtp = endpoint();
        let port = rtp.local_addr().unwrap().port();
        if let Some(next) = port.checked_add(1)
            && let Ok(rtcp) = UdpSocket::bind(("127.0.0.1", next))
        {
            rtcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            return (rtp, rtcp);
        }
    }
    panic!("no consecutive ports")
}

/// A minimal RTCP receiver report (PT 201) from `ssrc`.
fn rtcp_rr(ssrc: u8) -> Vec<u8> {
    vec![0x80, 201, 0, 1, 0, 0, 0, ssrc]
}

/// `rtcp-mux`: `demux` multiplexes towards the offerer and splits RTCP
/// towards an answerer it is not offered to; `offer` offers it to an
/// answerer whose offerer did not; `reject` and `accept` set what the
/// offerer is answered; an unknown value is refused.
#[test]
fn rtcp_mux_options() {
    let srv = server(54_800);
    let client = endpoint();
    let a = endpoint();
    let (b, b_rtcp) = rtp_rtcp_pair();
    let media = |port: u16, mux: bool| {
        format!(
            "{HEAD}m=audio {port} RTP/AVP 0\r\n{}a=sendrecv\r\n",
            if mux { "a=rtcp-mux\r\n" } else { "" }
        )
    };
    let call_with = |n: &str, mux: (bool, bool), flag: &'static [u8]| {
        let id = format!("mux-{n}");
        let (r, to_b, _) = send(
            &client,
            srv.addr,
            (&format!("{n}o"), b"offer", id.as_bytes()),
            &media(a.local_addr().unwrap().port(), mux.0),
            vec![("flags", V::L(&[b"trust-address", flag]))],
        );
        assert_eq!(r, "ok", "{to_b}");
        let (r, to_a, _) = send(
            &client,
            srv.addr,
            (&format!("{n}a"), b"answer", id.as_bytes()),
            &media(b.local_addr().unwrap().port(), mux.1),
            vec![("flags", V::L(&[b"trust-address"]))],
        );
        assert_eq!(r, "ok", "{to_a}");
        (to_b, to_a)
    };
    let has_mux = |sdp: &str| sdp.contains("a=rtcp-mux\r\n");

    // demux: A muxes, B does not; RTCP crosses between the two forms.
    let (to_b, to_a) = call_with("1", (true, false), b"rtcp-mux-demux");
    assert!(!has_mux(&to_b), "{to_b}");
    assert!(has_mux(&to_a), "{to_a}");
    std::thread::sleep(Duration::from_millis(50));
    let relay_a = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        first_media(to_a.as_bytes()).port,
    );
    let relay_b = first_media(to_b.as_bytes()).port;
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 1500];
    a.send_to(&rtcp_rr(1), relay_a).unwrap();
    let (n, from) = b_rtcp.recv_from(&mut buf).expect("B's RTCP port");
    assert_eq!((&buf[..n], from.port()), (&rtcp_rr(1)[..], relay_b + 1));
    b_rtcp
        .send_to(&rtcp_rr(2), ("127.0.0.1", relay_b + 1))
        .unwrap();
    let (n, from) = a.recv_from(&mut buf).expect("A's muxed port");
    assert_eq!((&buf[..n], from), (&rtcp_rr(2)[..], relay_a));

    // offer: A does not mux, B is offered it and takes it.
    let (to_b, to_a) = call_with("2", (false, true), b"rtcp-mux-offer");
    assert!(has_mux(&to_b), "{to_b}");
    assert!(!has_mux(&to_a), "{to_a}");
    // reject: neither side.
    let (to_b, to_a) = call_with("3", (true, true), b"rtcp-mux-reject");
    assert!(!has_mux(&to_b) && !has_mux(&to_a), "{to_b}\n{to_a}");
    // accept: A is answered with it although B declined.
    let (to_b, to_a) = call_with("4", (true, false), b"rtcp-mux-accept");
    assert!(has_mux(&to_b) && has_mux(&to_a), "{to_b}\n{to_a}");
    // Without the option: only when both take it.
    let (_, to_a) = call_with("5", (true, false), b"symmetric");
    assert!(!has_mux(&to_a), "{to_a}");

    let (r, why, _) = send(
        &client,
        srv.addr,
        ("6", b"offer", b"mux-6"),
        &media(4000, true),
        vec![("rtcp-mux", V::L(&[b"sometimes"]))],
    );
    assert_eq!(
        (r.as_str(), why.as_str()),
        ("error", "unsupported option rtcp-mux sometimes")
    );
}

/// The relay offers an SDES answerer every allowed suite (its preferred
/// one first); the answerer's choice decides the relay's key, and media
/// flows under it. `no-` also chooses among the offerer's own lines.
#[test]
fn sdes_offers_every_suite_and_follows_the_answer() {
    use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
    use rtpflux_srtp::{Protect, Unprotect};
    let srv = server(55_700);
    let client = endpoint();
    let (caller, callee) = (endpoint(), endpoint());
    let plain = format!(
        "{HEAD}m=audio {} RTP/AVP 0\r\na=sendrecv\r\n",
        caller.local_addr().unwrap().port()
    );
    let (r, to_b, _) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"multi-1"),
        &plain,
        vec![
            ("transport-protocol", V::S(b"RTP/SAVP")),
            ("flags", V::L(&[b"trust-address"])),
        ],
    );
    assert_eq!(r, "ok", "{to_b}");
    let mut offered_media = [Media::EMPTY; MAX_MEDIA];
    read_media(to_b.as_bytes(), &mut offered_media).unwrap();
    let offered: Vec<(u32, &str)> = offered_media[0]
        .cryptos
        .iter()
        .flatten()
        .map(|c| (c.tag, c.key.suite.name()))
        .collect();
    assert_eq!(
        offered,
        [
            (1, "AES_CM_128_HMAC_SHA1_80"),
            (2, "AES_CM_128_HMAC_SHA1_32"),
            (3, "AEAD_AES_128_GCM"),
            (4, "AEAD_AES_256_GCM"),
            (5, "AES_256_CM_HMAC_SHA1_80"),
            (6, "AES_256_CM_HMAC_SHA1_32"),
        ]
    );
    // B takes AEAD_AES_256_GCM, with its own key.
    let relay_key = offered_media[0].cryptos[3].unwrap().key;
    let b_key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKyw=";
    let answer = format!(
        "{HEAD}m=audio {} RTP/SAVP 0\r\na=crypto:4 AEAD_AES_256_GCM inline:{b_key}\r\na=sendrecv\r\n",
        callee.local_addr().unwrap().port()
    );
    let (r, to_a, _) = send(
        &client,
        srv.addr,
        ("2", b"answer", b"multi-1"),
        &answer,
        vec![("flags", V::L(&[b"trust-address"]))],
    );
    assert_eq!(r, "ok", "{to_a}");
    let mut answered = [Media::EMPTY; MAX_MEDIA];
    read_media(answer.as_bytes(), &mut answered).unwrap();
    let b_master = answered[0].crypto.expect("B's key parses").key;
    std::thread::sleep(Duration::from_millis(50));
    let relay_a = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        first_media(to_a.as_bytes()).port,
    );
    let relay_b = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        first_media(to_b.as_bytes()).port,
    );
    for s in [&caller, &callee] {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    }
    let mut buf = [0u8; 2048];
    // A → B: encrypted under the relay's GCM key of the offer.
    let pkt = rtp(1);
    caller.send_to(&pkt, relay_a).unwrap();
    let (n, _) = callee.recv_from(&mut buf).expect("B gets SRTP");
    let n = Unprotect::from_key(&relay_key)
        .rtp(&mut buf, n)
        .expect("under the GCM key");
    assert_eq!(&buf[..n], &pkt[..]);
    // B → A: B's key; A gets it in clear.
    let mut wire = rtp(2);
    let len = wire.len();
    wire.resize(len + rtpflux_srtp::MAX_RTP_TAG, 0);
    let len = Protect::from_key(&b_master).rtp(&mut wire, len).unwrap();
    callee.send_to(&wire[..len], relay_b).unwrap();
    let (n, _) = caller.recv_from(&mut buf).expect("A gets RTP");
    assert_eq!(&buf[..n], &rtp(2)[..]);
}

/// `no-` and `only-` choose among the offerer's own `a=crypto` lines.
#[test]
fn sdes_options_choose_among_the_offerers_lines() {
    let srv = server(55_800);
    let client = endpoint();
    // `no-` of A's first line: its second is used (answered with its tag).
    let key80 = "MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P";
    let key32 = "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CB";
    let sdes_offer = format!(
        "{HEAD}m=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key80}\r\n\
         a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:{key32}\r\na=sendrecv\r\n"
    );
    let (r, _, _) = send(
        &client,
        srv.addr,
        ("3", b"offer", b"multi-2"),
        &sdes_offer,
        vec![("SDES", V::L(&[b"no-AES_CM_128_HMAC_SHA1_80"]))],
    );
    assert_eq!(r, "ok");
    let (r, to_a, _) = send(
        &client,
        srv.addr,
        ("4", b"answer", b"multi-2"),
        &format!(
            "{HEAD}m=audio 4002 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:{key32}\r\n"
        ),
        vec![],
    );
    assert_eq!(r, "ok", "{to_a}");
    assert_eq!(
        sdp_line(&to_a, "a=crypto:").map(|l| l.split(' ').take(2).collect::<Vec<_>>()),
        Some(vec!["2", "AES_CM_128_HMAC_SHA1_32"]),
        "{to_a}"
    );
    // Only lines it may not use: refused.
    let (r, why, _) = send(
        &client,
        srv.addr,
        ("5", b"offer", b"multi-3"),
        &sdes_offer,
        vec![("SDES", V::L(&[b"only-AEAD_AES_128_GCM"]))],
    );
    assert_eq!(
        (r.as_str(), why.as_str()),
        (
            "error",
            "SDES: none of the offerer's crypto suites is allowed"
        )
    );
}

/// `SDES: unencrypted_srtp`: the answerer is offered AES-CM suites
/// declaring `UNENCRYPTED_SRTP`, and media goes in clear but
/// authenticated. Without the option such lines stay unusable (the
/// reference model's rule).
#[test]
fn sdes_unencrypted_srtp_on_request() {
    use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
    use rtpflux_srtp::{Protect, Unprotect};
    let srv = server(59_600);
    let client = endpoint();
    let (caller, callee) = (endpoint(), endpoint());
    let plain = format!(
        "{HEAD}m=audio {} RTP/AVP 0\r\na=sendrecv\r\n",
        caller.local_addr().unwrap().port()
    );
    let offer = |cookie: &str, id: &[u8], sdes: &'static [&'static [u8]]| {
        send(
            &client,
            srv.addr,
            (cookie, b"offer", id),
            &plain,
            vec![
                ("transport-protocol", V::S(b"RTP/SAVP")),
                ("flags", V::L(&[b"trust-address"])),
                ("SDES", V::L(sdes)),
            ],
        )
    };
    let (r, to_b, w) = offer("1", b"clear-1", &[b"unencrypted_srtp"]);
    assert_eq!((r.as_str(), w), ("ok", None), "{to_b}");
    let lines: Vec<&str> = to_b
        .lines()
        .filter(|l| l.starts_with("a=crypto:"))
        .collect();
    assert_eq!(lines.len(), 4, "AES_CM suites only: {lines:?}");
    assert!(
        lines
            .iter()
            .all(|l| l.ends_with(" UNENCRYPTED_SRTP") && !l.contains("GCM")),
        "{lines:?}"
    );
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(to_b.as_bytes(), &mut m).unwrap();
    assert_eq!(m[0].crypto, None, "unusable without the option");
    let relay_key = m[0].declared[0].unwrap().key;
    assert!(relay_key.policy.unencrypted_srtp);
    let b_line =
        "AES_CM_128_HMAC_SHA1_80 inline:MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P UNENCRYPTED_SRTP";
    let answer = format!(
        "{HEAD}m=audio {} RTP/SAVP 0\r\na=crypto:1 {b_line}\r\na=sendrecv\r\n",
        callee.local_addr().unwrap().port()
    );
    let (r, to_a, _) = send(
        &client,
        srv.addr,
        ("2", b"answer", b"clear-1"),
        &answer,
        vec![
            ("flags", V::L(&[b"trust-address"])),
            ("SDES", V::L(&[b"unencrypted_srtp"])),
        ],
    );
    assert_eq!(r, "ok", "{to_a}");
    let mut ma = [Media::EMPTY; MAX_MEDIA];
    read_media(answer.as_bytes(), &mut ma).unwrap();
    let b_key = ma[0].declared[0].unwrap().key;
    std::thread::sleep(Duration::from_millis(50));
    let relay_a = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        first_media(to_a.as_bytes()).port,
    );
    let relay_b = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        first_media(to_b.as_bytes()).port,
    );
    for s in [&caller, &callee] {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    }
    let mut buf = [0u8; 2048];
    // Caller → callee: the payload in clear, with an authentication tag.
    let pkt = rtp(1);
    caller.send_to(&pkt, relay_a).unwrap();
    let (n, _) = callee.recv_from(&mut buf).expect("callee gets SRTP");
    assert_eq!(
        (&buf[..pkt.len()], n),
        (&pkt[..], pkt.len() + 10),
        "clear, tagged"
    );
    let n = Unprotect::from_key(&relay_key)
        .rtp(&mut buf, n)
        .expect("authentic");
    assert_eq!(&buf[..n], &pkt[..]);
    // Callee → caller, and a tampered packet is refused.
    let mut wire = rtp(2);
    let len = wire.len();
    wire.resize(len + 10, 0);
    let len = Protect::from_key(&b_key).rtp(&mut wire, len).unwrap();
    let mut forged = wire.clone();
    forged[20] ^= 1;
    callee.send_to(&forged[..len], relay_b).unwrap();
    callee.send_to(&wire[..len], relay_b).unwrap();
    let (n, _) = caller.recv_from(&mut buf).expect("caller gets RTP");
    assert_eq!(
        &buf[..n],
        &rtp(2)[..],
        "the forged one was dropped, the real one passed"
    );
}

/// Without the `SDES` option, lines declaring `UNENCRYPTED_SRTP` stay
/// unusable: an answer with only such a line is refused.
#[test]
fn sdes_session_parameters_stay_unusable_by_default() {
    let srv = server(59_700);
    let client = endpoint();
    let plain = format!("{HEAD}m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n");
    let (r, to_b, _) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"clear-2"),
        &plain,
        vec![("transport-protocol", V::S(b"RTP/SAVP"))],
    );
    assert_eq!(r, "ok");
    assert!(!to_b.contains("UNENCRYPTED"), "{to_b}");
    let answer = format!(
        "{HEAD}m=audio 4002 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 \
         inline:MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P UNENCRYPTED_SRTP\r\n"
    );
    let (r, why, _) = send(
        &client,
        srv.addr,
        ("2", b"answer", b"clear-2"),
        &answer,
        vec![],
    );
    assert_eq!(r, "error", "{why}");
}
