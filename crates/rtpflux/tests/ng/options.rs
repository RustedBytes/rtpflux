//! rtpengine's remaining `offer`/`answer` options: `loop protect`,
//! `replace: origin-full`, `rtcp-mux: require`, the `SDES` values
//! `lifetime`, `nonew`, `order:`, `key-<suite>:`, `prefer`, the `codec`
//! keys `consume`, `ignore`, `accept`, and `DTLS-fingerprint`.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use std::net::{SocketAddr, UdpSocket};

const HEAD: &str = "v=0\r\no=pbx 7 3 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n";

/// `command` for call `id` with `sdp` and `pairs`: (result, SDP or
/// reason).
fn send(
    client: &UdpSocket,
    srv: SocketAddr,
    (cookie, command, id): (&str, &[u8], &[u8]),
    sdp: &str,
    pairs: Vec<(&str, V<'_>)>,
) -> (String, String) {
    let mut all = vec![
        ("command", V::S(command)),
        ("call-id", V::S(id)),
        ("from-tag", V::S(b"f")),
        ("sdp", V::S(sdp.as_bytes())),
    ];
    if command == b"answer" {
        all.push(("to-tag", V::S(b"t")));
    }
    all.extend(pairs);
    let (r, out, _) = call(client, srv, &request(cookie, &all));
    (r, String::from_utf8(out).unwrap())
}

fn crypto_lines(sdp: &str) -> Vec<&str> {
    sdp.lines().filter(|l| l.starts_with("a=crypto:")).collect()
}

/// `loop protect` marks what the relay writes; an SDP with its mark comes
/// back untouched and sets nothing up.
#[test]
fn loop_protect_passes_its_own_sdp() {
    let srv = server(59_800);
    let client = endpoint();
    let offer = format!("{HEAD}m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n");
    let flags = || ("flags", V::L(&[b"loop-protect"]));
    let (r, once) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"loop-1"),
        &offer,
        vec![flags()],
    );
    assert_eq!(r, "ok", "{once}");
    assert!(once.contains("a=rtpflux:"), "{once}");
    // The same SDP back (a loop): returned as it is, no second call.
    let (r, twice) = send(
        &client,
        srv.addr,
        ("2", b"offer", b"loop-2"),
        &once,
        vec![flags()],
    );
    assert_eq!((r.as_str(), twice.as_str()), ("ok", once.as_str()));
    let (r, _, raw) = call(
        &client,
        srv.addr,
        &request("3", &[("command", V::S(b"list"))]),
    );
    assert_eq!(r, "ok");
    let list = String::from_utf8_lossy(&raw);
    assert!(
        list.contains("loop-1") && !list.contains("loop-2"),
        "{list}"
    );
}

/// `replace: origin-full`: the whole `o=` line is the relay's, its session
/// id fixed for the recipient, its version raised only on a change.
#[test]
fn origin_full_keeps_the_origin_line() {
    let srv = server(60_000);
    let client = endpoint();
    let offer = |cookie: &str, origin: &str, direction: &str| {
        let sdp = format!(
            "v=0\r\no={origin} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP 0\r\na={direction}\r\n"
        );
        let (r, out) = send(
            &client,
            srv.addr,
            (cookie, b"offer", b"origin-1"),
            &sdp,
            vec![("replace", V::L(&[b"origin-full"]))],
        );
        assert_eq!(r, "ok", "{out}");
        sdp_line(&out, "o=").unwrap().to_owned()
    };
    assert_eq!(
        offer("1", "pbx 111 5", "sendrecv"),
        "- 111 5 IN IP4 127.0.0.1"
    );
    // Another origin (a transfer), the same media: unchanged.
    assert_eq!(
        offer("2", "other 999 1", "sendrecv"),
        "- 111 5 IN IP4 127.0.0.1"
    );
    // A change (hold): the version only.
    assert_eq!(
        offer("3", "other 999 2", "sendonly"),
        "- 111 6 IN IP4 127.0.0.1"
    );
}

/// `rtcp-mux: require`: the answerer is offered `rtcp-mux` with no RTCP
/// port, and is taken to multiplex even when its answer does not say so.
#[test]
fn rtcp_mux_require() {
    let srv = server(60_200);
    let client = endpoint();
    let offer = format!("{HEAD}m=audio 4000 RTP/AVP 0\r\na=rtcp:4001\r\na=sendrecv\r\n");
    let (r, to_b) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"mux-req"),
        &offer,
        vec![("rtcp-mux", V::L(&[b"require"]))],
    );
    assert_eq!(r, "ok", "{to_b}");
    assert!(
        to_b.contains("a=rtcp-mux\r\n") && !to_b.contains("a=rtcp:"),
        "{to_b}"
    );
    let answer = format!("{HEAD}m=audio 4002 RTP/AVP 0\r\na=sendrecv\r\n");
    let (r, to_a) = send(
        &client,
        srv.addr,
        ("2", b"answer", b"mux-req"),
        &answer,
        vec![],
    );
    assert_eq!(r, "ok", "{to_a}");
    assert!(
        !to_a.contains("a=rtcp-mux"),
        "the offerer did not offer it: {to_a}"
    );
}

/// The `SDES` values `lifetime`, `nonew`, `order:` and `key-<suite>:`,
/// and `prefer` (SDES over DTLS in an offer with both).
#[test]
fn more_sdes_values() {
    let srv = server(60_400);
    let client = endpoint();
    let plain = format!("{HEAD}m=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n");
    let offer = |cookie: &str, id: &[u8], sdp: &str, sdes: &'static [&'static [u8]]| {
        send(
            &client,
            srv.addr,
            (cookie, b"offer", id),
            sdp,
            vec![
                ("transport-protocol", V::S(b"RTP/SAVP")),
                ("SDES", V::L(sdes)),
            ],
        )
    };
    let (_, out) = offer("1", b"sdes-a", &plain, &[b"lifetime"]);
    assert!(
        crypto_lines(&out).iter().all(|l| l.ends_with("|2^31")),
        "{out}"
    );
    let (_, out) = offer(
        "2",
        b"sdes-b",
        &plain,
        &[b"order:AES_256_CM_HMAC_SHA1_32,AEAD_AES_128_GCM"],
    );
    let suites: Vec<&str> = crypto_lines(&out)
        .iter()
        .map(|l| l.split(' ').nth(1).unwrap())
        .collect();
    assert_eq!(
        &suites[..2],
        ["AES_256_CM_HMAC_SHA1_32", "AEAD_AES_128_GCM"],
        "{out}"
    );
    let key = "MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P";
    let supplied = format!("key-AES_CM_128_HMAC_SHA1_80:{key}");
    let supplied: &'static [u8] = Box::leak(supplied.into_bytes().into_boxed_slice());
    let leaked: &'static [&'static [u8]] = Box::leak(Box::new([supplied]));
    let (_, out) = offer("3", b"sdes-c", &plain, leaked);
    assert!(
        crypto_lines(&out)[0].ends_with(&format!("AES_CM_128_HMAC_SHA1_80 inline:{key}")),
        "{out}"
    );
    // `nonew`: only the offerer's own suite.
    let sdes_offer = format!(
        "{HEAD}m=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:{key}\r\n"
    );
    let (_, out) = offer("4", b"sdes-d", &sdes_offer, &[b"nonew"]);
    let lines = crypto_lines(&out);
    assert!(
        lines.len() == 1 && lines[0].contains("AES_CM_128_HMAC_SHA1_32"),
        "{out}"
    );
    // `prefer`: DTLS and SDES offered; SDES is taken, DTLS refused.
    let both = format!(
        "{HEAD}m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\n\
         a=fingerprint:sha-256 {}\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}\r\n",
        ["AB"; 32].join(":")
    );
    let (r, out) = send(
        &client,
        srv.addr,
        ("5", b"offer", b"sdes-e"),
        &both,
        vec![("SDES", V::L(&[b"prefer"]))],
    );
    assert_eq!(r, "ok", "{out}");
    assert!(
        out.contains(" RTP/SAVP 0")
            && !out.contains("fingerprint")
            && !crypto_lines(&out).is_empty(),
        "{out}"
    );
}

/// `codec: consume`, `ignore` and `accept`.
#[test]
fn codec_consume_ignore_accept() {
    let srv = server(60_600);
    let client = endpoint();
    let offer = |cookie: &str, id: &[u8], extra: &'static [&'static [u8]]| {
        let sdp =
            format!("{HEAD}m=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\n");
        let (r, out) = send(
            &client,
            srv.addr,
            (cookie, b"offer", id),
            &sdp,
            vec![("flags", V::L(extra))],
        );
        assert_eq!(r, "ok", "{out}");
        let m = out
            .lines()
            .find(|l| l.starts_with("m="))
            .unwrap()
            .to_owned();
        (out, m)
    };
    // `ignore`: as never offered.
    let (_, m) = offer("1", b"c-1", &[b"codec-ignore-PCMU"]);
    assert!(m.ends_with("RTP/AVP 8 101"), "{m}");
    // `consume`: withheld, the transcoded codec offered instead.
    let (_, m) = offer(
        "2",
        b"c-2",
        &[b"codec-consume-PCMU", b"codec-transcode-G722"],
    );
    assert!(m.ends_with("RTP/AVP 8 101 9"), "{m}");
    // `accept`: the relay transcodes from PCMA, so the offerer is
    // answered with PCMA when the answerer takes G.722.
    let (_, m) = offer(
        "3",
        b"c-3",
        &[b"codec-accept-PCMA", b"codec-transcode-G722"],
    );
    assert!(m.ends_with("RTP/AVP 0 8 101 9"), "{m}");
    let answer = format!("{HEAD}m=audio 4002 RTP/AVP 9\r\n");
    let (r, to_a) = send(&client, srv.addr, ("4", b"answer", b"c-3"), &answer, vec![]);
    assert_eq!(r, "ok", "{to_a}");
    let m = to_a.lines().find(|l| l.starts_with("m=")).unwrap();
    assert!(m.ends_with("RTP/AVP 8"), "{to_a}");
}

/// `DTLS-fingerprint`: the hash of the relay's fingerprint.
#[test]
fn dtls_fingerprint_hash() {
    let srv = server(60_800);
    let client = endpoint();
    let plain = format!("{HEAD}m=audio 4000 RTP/AVP 0\r\n");
    let (r, out) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"fp-1"),
        &plain,
        vec![
            ("transport-protocol", V::S(b"UDP/TLS/RTP/SAVP")),
            ("DTLS-fingerprint", V::S(b"SHA-1")),
        ],
    );
    assert_eq!(r, "ok", "{out}");
    let fp = sdp_line(&out, "a=fingerprint:").unwrap();
    assert!(fp.starts_with("sha-1 ") && fp.len() == 6 + 59, "{fp}");
}

/// `media echo`: `forward` in an offer, the answerer hears itself and the
/// offerer's media is dropped; `both` (in the answer), each hears itself;
/// `off` puts them back in touch.
#[test]
fn media_echo() {
    use std::time::Duration;
    let srv = server(61_000);
    let client = endpoint();
    let (alice, bob) = (endpoint(), endpoint());
    let sdp = |s: &UdpSocket| {
        format!(
            "{HEAD}m=audio {} RTP/AVP 0\r\na=sendrecv\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let msg = |cookie: &str, command: &[u8], s: &UdpSocket, echo: &'static [u8]| {
        let (r, out) = send(
            &client,
            srv.addr,
            (cookie, command, b"echo-1"),
            &sdp(s),
            vec![
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
                ("media echo", V::S(echo)),
            ],
        );
        assert_eq!(r, "ok", "{out}");
        relay_addr(out.as_bytes())
    };
    let for_bob = msg("1", b"offer", &alice, b"forward");
    let for_alice = msg("2", b"answer", &bob, b"forward");
    std::thread::sleep(Duration::from_millis(50));
    for s in [&alice, &bob] {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    let mut buf = [0u8; 2048];
    let heard =
        |s: &UdpSocket, buf: &mut [u8]| s.recv_from(buf).ok().map(|(n, _)| buf[1..n].to_vec());
    // The answer's `forward`: its receiver (alice) hears herself, bob's
    // media is dropped.
    alice.send_to(&rtp(1), for_alice).unwrap();
    assert_eq!(
        heard(&alice, &mut buf),
        Some(rtp(1)[1..].to_vec()),
        "alice hears herself"
    );
    assert_eq!(heard(&bob, &mut buf), None);
    bob.send_to(&rtp(2), for_bob).unwrap();
    assert_eq!(heard(&alice, &mut buf), None, "bob's media dropped");
    // `both`, then `off`.
    msg("3", b"answer", &bob, b"both");
    std::thread::sleep(Duration::from_millis(50));
    bob.send_to(&rtp(3), for_bob).unwrap();
    assert_eq!(
        heard(&bob, &mut buf),
        Some(rtp(3)[1..].to_vec()),
        "bob hears himself"
    );
    msg("4", b"answer", &bob, b"off");
    std::thread::sleep(Duration::from_millis(50));
    bob.send_to(&rtp(4), for_bob).unwrap();
    assert_eq!(
        heard(&alice, &mut buf),
        Some(rtp(4)[1..].to_vec()),
        "back in touch"
    );
}

/// Opportunistic SRTP (RFC 8643): an offer in RTP/AVP with `a=crypto` is
/// passed on as such; SRTP is used when the answerer takes it (media
/// encrypted both ways), plain RTP when it does not, unless `OSRTP:
/// accept`; `OSRTP: offer` turns a plain offer into an opportunistic one.
#[test]
#[allow(clippy::too_many_lines)] // One call per case.
fn opportunistic_srtp() {
    use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
    use rtpflux_srtp::{MasterKey, Protect, Unprotect};
    use std::time::Duration;
    let srv = server(61_200);
    let client = endpoint();
    let key_a = "MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P";
    let key_b = "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CB";
    let osrtp = |s: &UdpSocket, key: Option<&str>| {
        let line = key.map_or(String::new(), |k| {
            format!("a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:{k}\r\n")
        });
        format!(
            "{HEAD}m=audio {} RTP/AVP 0\r\n{line}a=sendrecv\r\n",
            s.local_addr().unwrap().port()
        )
    };
    let relay_key = |sdp: &str| -> Option<MasterKey> {
        let mut m = [Media::EMPTY; MAX_MEDIA];
        read_media(sdp.as_bytes(), &mut m).unwrap();
        m[0].crypto.map(|c| c.key)
    };
    let own = |text: &str| {
        let mut m = [Media::EMPTY; MAX_MEDIA];
        read_media(osrtp(&endpoint(), Some(text)).as_bytes(), &mut m).unwrap();
        m[0].crypto.unwrap().key
    };
    // A call: (offer reply, answer reply, caller, callee).
    let run = |id: &[u8], a_key: Option<&str>, b_key: Option<&str>, osrtp_opt: &'static [u8]| {
        let (caller, callee) = (endpoint(), endpoint());
        let opts = || {
            vec![
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
                ("OSRTP", V::S(osrtp_opt)),
            ]
        };
        let (r, to_b) = send(
            &client,
            srv.addr,
            ("o", b"offer", id),
            &osrtp(&caller, a_key),
            opts(),
        );
        assert_eq!(r, "ok", "{to_b}");
        let (r, to_a) = send(
            &client,
            srv.addr,
            ("a", b"answer", id),
            &osrtp(&callee, b_key),
            opts(),
        );
        assert_eq!(r, "ok", "{to_a}");
        std::thread::sleep(Duration::from_millis(50));
        for s in [&caller, &callee] {
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        }
        (to_b, to_a, caller, callee)
    };
    let addr = |sdp: &str| relay_addr(sdp.as_bytes());
    let mut buf = [0u8; 2048];

    // Pass-through, taken: SRTP both ways, each under its own keys.
    let (to_b, to_a, caller, callee) = run(b"os-1", Some(key_a), Some(key_b), b"");
    assert!(
        to_b.contains(" RTP/AVP 0") && to_a.contains("a=crypto:3 "),
        "{to_b}\n{to_a}"
    );
    let (relay_to_b, relay_to_a) = (relay_key(&to_b).unwrap(), relay_key(&to_a).unwrap());
    let mut wire = rtp(1);
    let len = wire.len();
    wire.resize(len + 10, 0);
    let len = Protect::from_key(&own(key_a)).rtp(&mut wire, len).unwrap();
    caller.send_to(&wire[..len], addr(&to_a)).unwrap();
    let (n, _) = callee.recv_from(&mut buf).unwrap();
    let n = Unprotect::from_key(&relay_to_b)
        .rtp(&mut buf, n)
        .expect("SRTP to the callee");
    assert_eq!(&buf[..n], &rtp(1)[..]);
    let mut wire = rtp(2);
    let len = wire.len();
    wire.resize(len + 10, 0);
    let len = Protect::from_key(&own(key_b)).rtp(&mut wire, len).unwrap();
    callee.send_to(&wire[..len], addr(&to_b)).unwrap();
    let (n, _) = caller.recv_from(&mut buf).unwrap();
    let n = Unprotect::from_key(&relay_to_a)
        .rtp(&mut buf, n)
        .expect("SRTP to the caller");
    assert_eq!(&buf[..n], &rtp(2)[..]);

    // Not taken: plain both ways, no key in the answer.
    let (to_b, to_a, caller, callee) = run(b"os-2", Some(key_a), None, b"");
    assert!(
        relay_key(&to_b).is_some() && relay_key(&to_a).is_none(),
        "{to_a}"
    );
    caller.send_to(&rtp(3), addr(&to_a)).unwrap();
    let (n, _) = callee.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], &rtp(3)[..], "plain");

    // `accept`: the caller's SRTP taken, the callee plain (converted).
    let (to_b, to_a, caller, callee) = run(b"os-3", Some(key_a), None, b"accept");
    let relay_to_a = relay_key(&to_a).expect("accepted");
    callee.send_to(&rtp(4), addr(&to_b)).unwrap();
    let (n, _) = caller.recv_from(&mut buf).unwrap();
    let n = Unprotect::from_key(&relay_to_a)
        .rtp(&mut buf, n)
        .expect("SRTP to the caller");
    assert_eq!(&buf[..n], &rtp(4)[..]);

    // `offer`: a plain offer becomes an opportunistic one.
    let (to_b, ..) = run(b"os-4", None, None, b"offer");
    assert!(
        to_b.contains(" RTP/AVP 0") && relay_key(&to_b).is_some(),
        "{to_b}"
    );
}

/// `DTLS-reverse=active`: towards DTLS offered to it with `actpass`, the
/// relay takes the active role (by default it is passive).
#[test]
fn dtls_reverse_active() {
    let srv = server(61_800);
    let client = endpoint();
    let offer = format!(
        "{HEAD}m=audio 4000 UDP/TLS/RTP/SAVP 0\r\na=setup:actpass\r\n\
         a=fingerprint:sha-256 {}\r\n",
        ["AB"; 32].join(":")
    );
    let answer = format!("{HEAD}m=audio 4002 RTP/AVP 0\r\n");
    for (id, reverse, setup) in [
        (&b"rev-1"[..], &b"active"[..], "active"),
        (b"rev-2", b"passive", "passive"),
    ] {
        let (r, out) = send(
            &client,
            srv.addr,
            ("1", b"offer", id),
            &offer,
            vec![
                ("transport-protocol", V::S(b"RTP/AVP")),
                ("DTLS-reverse", V::S(reverse)),
            ],
        );
        assert_eq!(r, "ok", "{out}");
        let (r, to_a) = send(&client, srv.addr, ("2", b"answer", id), &answer, vec![]);
        assert_eq!(r, "ok", "{to_a}");
        assert_eq!(sdp_line(&to_a, "a=setup:"), Some(setup), "{to_a}");
    }
}

/// Legacy OSRTP: `offer-legacy` offers each stream twice (SRTP with keys,
/// then plain), and the answerer's pick decides (here SRTP, media
/// encrypted to it); `accept-legacy` takes an offerer's doubled stream as
/// one, and answers it doubled again (the SRTP copy taken).
#[test]
#[allow(clippy::too_many_lines)] // One call per case.
fn legacy_osrtp() {
    use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
    use rtpflux_srtp::Unprotect;
    use std::time::Duration;
    let srv = server(62_200);
    let client = endpoint();
    let (caller, callee) = (endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let key = "MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5P";
    let opts = |legacy: &'static [u8]| {
        vec![
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
            ("OSRTP", V::S(legacy)),
        ]
    };
    // offer-legacy.
    let plain = format!(
        "{HEAD}m=audio {} RTP/AVP 0\r\na=sendrecv\r\n",
        port(&caller)
    );
    let (r, to_b) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"leg-1"),
        &plain,
        opts(b"offer-legacy"),
    );
    assert_eq!(r, "ok", "{to_b}");
    let m_lines: Vec<&str> = to_b.lines().filter(|l| l.starts_with("m=")).collect();
    assert_eq!(m_lines.len(), 2, "{to_b}");
    assert!(
        m_lines[0].contains(" RTP/SAVP ") && m_lines[1].contains(" RTP/AVP "),
        "{to_b}"
    );
    let relay_port: u16 = m_lines[0].split(' ').nth(1).unwrap().parse().unwrap();
    let mut m = [Media::EMPTY; MAX_MEDIA];
    read_media(to_b.as_bytes(), &mut m).unwrap();
    let relay_key = m[0].crypto.expect("the SRTP copy's key").key;
    let answer = format!(
        "{HEAD}m=audio {} RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}\r\n\
         m=audio 0 RTP/AVP 0\r\n",
        port(&callee)
    );
    let (r, to_a) = send(
        &client,
        srv.addr,
        ("2", b"answer", b"leg-1"),
        &answer,
        opts(b"offer-legacy"),
    );
    assert_eq!(r, "ok", "{to_a}");
    assert_eq!(
        to_a.lines().filter(|l| l.starts_with("m=")).count(),
        1,
        "{to_a}"
    );
    std::thread::sleep(Duration::from_millis(50));
    callee
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    caller
        .send_to(&rtp(1), ("127.0.0.1", first_media(to_a.as_bytes()).port))
        .unwrap();
    let mut buf = [0u8; 2048];
    let (n, from) = callee.recv_from(&mut buf).expect("SRTP to the callee");
    assert_eq!(from.port(), relay_port);
    let n = Unprotect::from_key(&relay_key)
        .rtp(&mut buf, n)
        .expect("under the relay's key");
    assert_eq!(&buf[..n], &rtp(1)[..]);

    // accept-legacy.
    let doubled = format!(
        "{HEAD}m=audio 5000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}\r\n\
         m=audio 5000 RTP/AVP 0\r\n"
    );
    let (r, to_b) = send(
        &client,
        srv.addr,
        ("3", b"offer", b"leg-2"),
        &doubled,
        opts(b"accept-legacy"),
    );
    assert_eq!(r, "ok", "{to_b}");
    assert_eq!(
        to_b.lines().filter(|l| l.starts_with("m=")).count(),
        1,
        "one stream: {to_b}"
    );
    let (r, to_a) = send(
        &client,
        srv.addr,
        ("4", b"answer", b"leg-2"),
        &format!("{HEAD}m=audio 5002 RTP/AVP 0\r\n"),
        opts(b"accept-legacy"),
    );
    assert_eq!(r, "ok", "{to_a}");
    let m_lines: Vec<&str> = to_a.lines().filter(|l| l.starts_with("m=")).collect();
    assert_eq!(m_lines.len(), 2, "{to_a}");
    assert!(
        m_lines[0].contains(" RTP/SAVP ")
            && !m_lines[0].starts_with("m=audio 0 ")
            && m_lines[1].starts_with("m=audio 0 RTP/AVP"),
        "the SRTP copy taken: {to_a}"
    );
    assert!(to_a.contains("a=crypto:1 "), "{to_a}");
}

/// `ICE=force-relay`: an ICE offer passes as it is (its `m=`, `c=`, ICE,
/// fingerprint; its own relay candidates dropped) with the relay as a
/// relay candidate, and what reaches the relay candidate is relayed as it
/// is; `optional` keeps the endpoints' relay candidates, and without ICE is
/// `force`.
#[test]
#[allow(clippy::too_many_lines)] // One call per case.
fn ice_force_relay_and_optional() {
    use std::time::Duration;
    let srv = server(62_400);
    let client = endpoint();
    let (caller, callee) = (endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let fp = ["AB"; 32].join(":");
    let ice_sdp = |p: u16, ufrag: &str| {
        format!(
            "{HEAD}m=audio {p} UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\n\
             a=ice-ufrag:{ufrag}\r\na=ice-pwd:passwordpasswordpassword\r\n\
             a=candidate:1 1 UDP 2130706431 127.0.0.1 {p} typ host\r\n\
             a=candidate:2 1 UDP 16777215 198.51.100.1 50000 typ relay raddr 0.0.0.0 rport 0\r\n\
             a=setup:actpass\r\na=fingerprint:sha-256 {fp}\r\na=rtcp-mux\r\n"
        )
    };
    let opts = |ice: &'static [u8]| {
        vec![
            ("ICE", V::S(ice)),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"immediate")),
        ]
    };
    let relay_cand = |sdp: &str| -> u16 {
        let l = sdp
            .lines()
            .find(|l| l.starts_with("a=candidate:rtpflux 1 "))
            .unwrap_or_else(|| panic!("no relay candidate: {sdp}"));
        l.split(' ').nth(5).unwrap().parse().unwrap()
    };
    let (r, to_b) = send(
        &client,
        srv.addr,
        ("1", b"offer", b"fr-1"),
        &ice_sdp(port(&caller), "aaaa"),
        opts(b"force-relay"),
    );
    assert_eq!(r, "ok", "{to_b}");
    assert!(
        to_b.contains(&format!("m=audio {} UDP/TLS/RTP/SAVPF 111", port(&caller)))
            && to_b.contains("c=IN IP4 127.0.0.1")
            && to_b.contains("a=ice-ufrag:aaaa")
            && to_b.contains(&format!("a=fingerprint:sha-256 {fp}"))
            && !to_b.contains("198.51.100.1"),
        "{to_b}"
    );
    let for_callee = relay_cand(&to_b);
    let (r, to_a) = send(
        &client,
        srv.addr,
        ("2", b"answer", b"fr-1"),
        &ice_sdp(port(&callee), "bbbb"),
        opts(b"force-relay"),
    );
    assert_eq!(r, "ok", "{to_a}");
    assert!(to_a.contains("a=ice-ufrag:bbbb"), "{to_a}");
    let for_caller = relay_cand(&to_a);
    std::thread::sleep(Duration::from_millis(50));
    for s in [&caller, &callee] {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    }
    // Whatever reaches the relay candidate goes on as it is (a STUN check,
    // DTLS, SRTP: nothing is terminated).
    let mut buf = [0u8; 2048];
    let check = [
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ];
    callee.send_to(&check, ("127.0.0.1", for_callee)).unwrap();
    let (n, from) = caller
        .recv_from(&mut buf)
        .expect("the check reaches the caller");
    assert_eq!((&buf[..n], from.port()), (&check[..], for_caller));
    caller.send_to(&buf[..n], from).unwrap();
    let (n, from) = callee
        .recv_from(&mut buf)
        .expect("and its answer the callee");
    assert_eq!((n, from.port()), (check.len(), for_callee));

    // `optional` keeps the offerer's relay candidates.
    let (r, out) = send(
        &client,
        srv.addr,
        ("3", b"offer", b"fr-2"),
        &ice_sdp(4000, "cccc"),
        opts(b"optional"),
    );
    assert_eq!(r, "ok", "{out}");
    assert!(
        out.contains("198.51.100.1") && out.contains("a=candidate:rtpflux 1 "),
        "{out}"
    );
    // Without ICE, `optional` is `force`: the relay's own ICE.
    let (r, out) = send(
        &client,
        srv.addr,
        ("4", b"offer", b"fr-3"),
        &format!("{HEAD}m=audio 4000 RTP/AVP 0\r\n"),
        opts(b"optional"),
    );
    assert_eq!(r, "ok", "{out}");
    assert!(
        out.contains("a=ice-ufrag:") && !out.contains("typ relay"),
        "{out}"
    );
}
