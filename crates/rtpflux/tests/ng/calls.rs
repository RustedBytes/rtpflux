//! Offer, answer, delete, `list` and `query`.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use rtpflux_ng::bencode::Value;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[test]
fn offer_answer_media_delete() {
    let srv = server(45_000);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());

    let (result, _, _) = call(
        &client,
        srv.addr,
        &request("c1", &[("command", V::S(b"ping"))]),
    );
    assert_eq!(result, "pong");

    let offer_sdp = sdp_for(a.local_addr().unwrap().port());
    let offer = request(
        "c2",
        &[
            ("command", V::S(b"offer")),
            ("call-id", V::S(b"call-1@example")),
            ("from-tag", V::S(b"ftag")),
            ("sdp", V::S(&offer_sdp)),
            ("flags", V::L(&[b"trust-address"])),
            ("replace", V::L(&[b"origin"])),
            ("endpoint-learning", V::S(b"off")),
        ],
    );
    let (result, to_b, offer_reply) = call(&client, srv.addr, &offer);
    assert_eq!(result, "ok");
    let relay_for_b = first_media(&to_b);
    assert_ne!(
        relay_for_b.port,
        a.local_addr().unwrap().port(),
        "port rewritten"
    );
    assert_eq!(relay_for_b.address, Some("127.0.0.1".parse().unwrap()));
    assert!(String::from_utf8_lossy(&to_b).contains("o=- 1 1 IN IP4 127.0.0.1\r\n"));

    // A retransmitted offer (same cookie) gets the same reply, no new call.
    let (_, _, again) = call(&client, srv.addr, &offer);
    assert_eq!(again, offer_reply);

    let answer_sdp = sdp_for(b.local_addr().unwrap().port());
    let (result, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "c3",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"call-1@example")),
                ("from-tag", V::S(b"ftag")),
                ("to-tag", V::S(b"ttag")),
                ("sdp", V::S(&answer_sdp)),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok");
    let relay_for_a = first_media(&to_a);
    assert_ne!(relay_for_a.port, relay_for_b.port);
    std::thread::sleep(Duration::from_millis(50));

    // Media: A sends where the answer told it, B where the offer told it.
    let to_relay_a = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_for_a.port);
    let to_relay_b = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_for_b.port);
    let rtp = [0x80u8, 0, 0, 1, 0, 0, 0, 160, 1, 2, 3, 4, 9, 9, 9];
    let mut buf = [0u8; 2048];
    a.send_to(&rtp, to_relay_a).unwrap();
    let (n, from) = b.recv_from(&mut buf).expect("A's media reaches B");
    assert_eq!((&buf[..n], from), (&rtp[..], to_relay_b));
    b.send_to(&rtp, to_relay_b).unwrap();
    let (n, from) = a.recv_from(&mut buf).expect("B's media reaches A");
    assert_eq!((&buf[..n], from), (&rtp[..], to_relay_a));

    let del = request(
        "c4",
        &[
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"call-1@example")),
        ],
    );
    assert_eq!(call(&client, srv.addr, &del).0, "ok");
    let del2 = request(
        "c5",
        &[
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"call-1@example")),
        ],
    );
    // Gone: `ok` with rtpengine's warning (an error only with `fatal`).
    let (result, _, raw) = call(&client, srv.addr, &del2);
    assert_eq!(result, "ok");
    assert!(String::from_utf8_lossy(&raw).contains("Call-ID not found or tags didn't match"));
}

#[test]
fn errors_are_reported() {
    let srv = server(45_200);
    let client = endpoint();
    let (r, reason, _) = call(
        &client,
        srv.addr,
        &request("e1", &[("command", V::S(b"dance"))]),
    );
    assert_eq!(
        (r.as_str(), reason.as_slice()),
        ("error", &b"unknown command dance"[..])
    );
    let (r, reason, _) = call(
        &client,
        srv.addr,
        &request("e2", &[("command", V::S(b"offer"))]),
    );
    assert_eq!(
        (r.as_str(), reason.as_slice()),
        ("error", &b"missing call-id"[..])
    );
    let answer = request(
        "e3",
        &[
            ("command", V::S(b"answer")),
            ("call-id", V::S(b"nope")),
            ("from-tag", V::S(b"x")),
            ("sdp", V::S(&sdp_for(4000))),
        ],
    );
    let (r, reason, _) = call(&client, srv.addr, &answer);
    assert_eq!(
        (r.as_str(), reason.as_slice()),
        ("error", &b"unknown call (no offer)"[..])
    );
}

#[test]
fn received_from_overrides_the_sdp_address() {
    let srv = server(45_400);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    // A's SDP names a private address; the SIP source is A's real one.
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 10.0.0.5\r\ns=-\r\nc=IN IP4 10.0.0.5\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\n",
        a.local_addr().unwrap().port()
    );
    let (_, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "r1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"nat")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer_sdp.as_bytes())),
                ("received-from", V::L(&[b"IP4", b"127.0.0.1"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    let answer_sdp = sdp_for(b.local_addr().unwrap().port());
    let (_, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "r2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"nat")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(&answer_sdp)),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    std::thread::sleep(Duration::from_millis(50));
    let relay_b = SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(&to_b).port);
    let _relay_a = first_media(&to_a);
    // B's media must reach A at 127.0.0.1 (from received-from), not 10.0.0.5.
    b.send_to(&[0x80, 0, 0, 1], relay_b).unwrap();
    let mut buf = [0u8; 64];
    assert!(
        a.recv_from(&mut buf).is_ok(),
        "media sent to the SIP source address"
    );
}

/// Set up a plain call `call_id` and pass media: 3 packets A→B, 1 B→A.
fn call_with_media(client: &UdpSocket, srv: SocketAddr, call_id: &[u8]) -> SocketAddr {
    let (caller, callee) = (endpoint(), endpoint());
    let flags: &[&[u8]] = &[b"trust-address"];
    let (_, to_b, _) = call(
        client,
        srv,
        &request(
            "q1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(call_id)),
                ("from-tag", V::S(b"alice")),
                ("sdp", V::S(&sdp_for(caller.local_addr().unwrap().port()))),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    let (_, to_a, _) = call(
        client,
        srv,
        &request(
            "q2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(call_id)),
                ("from-tag", V::S(b"alice")),
                ("to-tag", V::S(b"bob")),
                ("sdp", V::S(&sdp_for(callee.local_addr().unwrap().port()))),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    std::thread::sleep(Duration::from_millis(50));
    let relay_a = SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(&to_a).port);
    let relay_b = SocketAddr::new("127.0.0.1".parse().unwrap(), first_media(&to_b).port);
    let mut buf = [0u8; 2048];
    for seq in 0..3 {
        caller.send_to(&rtp(seq), relay_a).unwrap();
        callee.recv_from(&mut buf).unwrap();
    }
    callee.send_to(&rtp(9), relay_b).unwrap();
    caller.recv_from(&mut buf).unwrap();
    relay_a
}

/// `list` names the active calls; `query` reports rtpengine-style counters
/// for a call whose media flowed.
#[test]
fn list_and_query() {
    let srv = server(47_200);
    let client = endpoint();
    let relay_a = call_with_media(&client, srv.addr, b"query-1");

    let (result, _, raw) = call(
        &client,
        srv.addr,
        &request("q3", &[("command", V::S(b"list"))]),
    );
    assert_eq!(result, "ok");
    let Some(Value::List(calls)) = at(reply_dict(&raw), &[b"calls"]) else {
        panic!("calls")
    };
    assert_eq!(
        calls.iter().collect::<Vec<_>>(),
        vec![Value::Bytes(b"query-1")]
    );

    let (result, _, raw) = call(
        &client,
        srv.addr,
        &request(
            "q4",
            &[("command", V::S(b"query")), ("call-id", V::S(b"query-1"))],
        ),
    );
    assert_eq!(result, "ok");
    let reply = reply_dict(&raw);
    assert_eq!(
        at(reply, &[b"totals", b"RTP", b"packets"]),
        Some(Value::Int(4)),
        "3 from A, 1 from B"
    );
    assert_eq!(
        at(reply, &[b"totals", b"RTP", b"bytes"]),
        Some(Value::Int(4 * 52))
    );
    let stream: &[&[u8]] = &[b"tags", b"alice", b"medias", b"0", b"streams", b"0"];
    let port = at(reply, &[stream, &[b"local port"]].concat());
    assert_eq!(port, Some(Value::Int(i64::from(relay_a.port()))));
    assert_eq!(
        at(reply, &[stream, &[b"stats", b"packets"]].concat()),
        Some(Value::Int(3))
    );
    assert!(at(reply, &[b"tags", b"bob"]).is_some());
    let (result, reason, _) = call(
        &client,
        srv.addr,
        &request(
            "q5",
            &[("command", V::S(b"query")), ("call-id", V::S(b"nope"))],
        ),
    );
    assert_eq!(
        (result.as_str(), reason.as_slice()),
        ("error", &b"unknown call"[..])
    );
}

/// `list`'s call-ids.
fn listed(client: &UdpSocket, srv: SocketAddr, cookie: &str) -> Vec<String> {
    let (_, _, raw) = call(client, srv, &request(cookie, &[("command", V::S(b"list"))]));
    let Some(Value::List(calls)) = at(reply_dict(&raw), &[b"calls"]) else {
        panic!("no calls list")
    };
    calls
        .iter()
        .map(|v| match v {
            Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        })
        .collect()
}

#[test]
fn a_long_ring_survives_and_a_silent_call_ends_with_its_dialog() {
    // Media timeout 1 s; an unanswered offer is dropped after 3 s.
    let srv = server_with(46_400, "timeout = 1\noffer_timeout = 3");
    let client = endpoint();
    let offer = |cookie: &str, id: &[u8]| {
        let r = request(
            cookie,
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(id)),
                ("from-tag", V::S(b"a")),
                ("sdp", V::S(&sdp_for(4000))),
            ],
        );
        call(&client, srv.addr, &r).0
    };
    let answer = |cookie: &str, id: &[u8]| {
        let r = request(
            cookie,
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(id)),
                ("from-tag", V::S(b"a")),
                ("to-tag", V::S(b"b")),
                ("sdp", V::S(&sdp_for(5000))),
            ],
        );
        call(&client, srv.addr, &r)
    };
    assert_eq!(offer("t1", b"rings"), "ok");
    assert_eq!(offer("t2", b"never"), "ok");
    // Ringing longer than the media timeout, without media: both live.
    std::thread::sleep(Duration::from_millis(2_000));
    assert_eq!(listed(&client, srv.addr, "t3").len(), 2);
    assert_eq!(answer("t4", b"rings").0, "ok", "answered after a long ring");
    // The unanswered one is dropped at offer_timeout; the answered one,
    // silent, after the media timeout. Their dialogs go with them.
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(listed(&client, srv.addr, "t5"), Vec::<String>::new());
    let (result, reason, _) = answer("t6", b"rings");
    assert_eq!(result, "error", "{}", String::from_utf8_lossy(&reason));
}

/// An offer or answer of `id` with `sdp`.
fn exchange(
    client: &UdpSocket,
    srv: SocketAddr,
    cookie: &str,
    id: &[u8],
    answer: bool,
    sdp: &[u8],
) {
    let mut pairs = vec![
        ("command", V::S(if answer { b"answer" } else { b"offer" })),
        ("call-id", V::S(id)),
        ("from-tag", V::S(b"a")),
        ("sdp", V::S(sdp)),
    ];
    if answer {
        pairs.push(("to-tag", V::S(b"b")));
    }
    let (result, extra, _) = call(client, srv, &request(cookie, &pairs));
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&extra));
}

/// The SDP of [`sdp_for`] with another direction attribute.
fn sdp_dir(port: u16, dir: &str) -> Vec<u8> {
    String::from_utf8(sdp_for(port))
        .unwrap()
        .replace("a=sendrecv", dir)
        .into_bytes()
}

#[test]
fn a_call_on_hold_gets_the_silent_timeout() {
    // Media timeout 1 s; on hold, 4 s.
    let srv = server_with(57_800, "timeout = 1\nsilent_timeout = 4");
    let client = endpoint();
    exchange(&client, srv.addr, "h1", b"held", false, &sdp_for(4000));
    exchange(&client, srv.addr, "h2", b"held", true, &sdp_for(5000));
    // Put on hold: sendonly, answered recvonly. No media either way.
    exchange(
        &client,
        srv.addr,
        "h3",
        b"held",
        false,
        &sdp_dir(4000, "a=sendonly"),
    );
    exchange(
        &client,
        srv.addr,
        "h4",
        b"held",
        true,
        &sdp_dir(5000, "a=recvonly"),
    );
    std::thread::sleep(Duration::from_millis(2_200));
    assert_eq!(
        listed(&client, srv.addr, "h5"),
        vec!["held".to_owned()],
        "held past timeout"
    );
    // Resumed: the 1 s timeout is back.
    exchange(&client, srv.addr, "h6", b"held", false, &sdp_for(4000));
    exchange(&client, srv.addr, "h7", b"held", true, &sdp_for(5000));
    std::thread::sleep(Duration::from_millis(2_200));
    assert_eq!(listed(&client, srv.addr, "h8"), Vec::<String>::new());
    // The old style, c=0.0.0.0, holds too.
    let zero = String::from_utf8(sdp_for(4000))
        .unwrap()
        .replace("c=IN IP4 127.0.0.1", "c=IN IP4 0.0.0.0")
        .into_bytes();
    exchange(&client, srv.addr, "z1", b"zero", false, &sdp_for(4000));
    exchange(&client, srv.addr, "z2", b"zero", true, &sdp_for(5000));
    exchange(&client, srv.addr, "z3", b"zero", false, &zero);
    exchange(&client, srv.addr, "z4", b"zero", true, &sdp_for(5000));
    std::thread::sleep(Duration::from_millis(2_200));
    assert_eq!(listed(&client, srv.addr, "z5"), vec!["zero".to_owned()]);
}

#[test]
fn final_timeout_ends_a_call_whatever_its_media() {
    let srv = server_with(58_000, "final_timeout = 1");
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let pa = a.local_addr().unwrap().port();
    let pb = b.local_addr().unwrap().port();
    exchange(&client, srv.addr, "f1", b"long", false, &sdp_for(pa));
    exchange(&client, srv.addr, "f2", b"long", true, &sdp_for(pb));
    assert_eq!(listed(&client, srv.addr, "f3"), vec!["long".to_owned()]);
    std::thread::sleep(Duration::from_millis(2_300));
    assert_eq!(listed(&client, srv.addr, "f4"), Vec::<String>::new());
}

#[test]
fn strict_source_for_every_call_from_the_configuration() {
    let srv = server_with(58_800, "strict_source = true");
    let client = endpoint();
    let (a, b, stranger) = (endpoint(), endpoint(), endpoint());
    let pa = a.local_addr().unwrap().port();
    let pb = b.local_addr().unwrap().port();
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "s1",
        b"offer",
        (b"a", None),
        &sdp_for(pa),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "s2",
        b"answer",
        (b"a", Some(b"b")),
        &sdp_for(pb),
    );
    let _ = to_b;
    let for_a = relay_addr(&to_a);
    let mut buf = [0u8; 2048];
    b.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    // A's media is relayed, and the relay learns A's address ...
    a.send_to(&rtp(1), for_a).unwrap();
    assert!(b.recv_from(&mut buf).is_ok(), "A's packet was not relayed");
    // ... after which a stranger's packets to A's relay port are dropped.
    stranger.send_to(&rtp(2), for_a).unwrap();
    assert!(
        b.recv_from(&mut buf).is_err(),
        "a stranger's packet was relayed"
    );
    a.send_to(&rtp(3), for_a).unwrap();
    assert!(b.recv_from(&mut buf).is_ok(), "A's packet was not relayed");
}

/// `media-handover`: when the callee's NAT rebinds (a new source port), the
/// caller's audio follows it once the new source has sent a few packets;
/// without the flag the latched address stays.
#[test]
fn media_handover_follows_a_rebinding() {
    let srv = server(55_200);
    let client = endpoint();
    let run = |id: &[u8], handover: bool| {
        let (a, b, b2) = (endpoint(), endpoint(), endpoint());
        let flags: Vec<&[u8]> = if handover {
            vec![b"trust-address", b"media-handover"]
        } else {
            vec![b"trust-address"]
        };
        let send = |cookie: &str, command: &[u8], port: u16| {
            let mut pairs = vec![
                ("command", V::S(command)),
                ("call-id", V::S(id)),
                ("from-tag", V::S(b"f")),
                ("flags", V::L(&flags)),
                ("endpoint-learning", V::S(b"immediate")),
            ];
            let sdp = sdp_for(port);
            pairs.push(("sdp", V::S(&sdp)));
            if command == b"answer" {
                pairs.push(("to-tag", V::S(b"t")));
            }
            let (r, out, _) = call(&client, srv.addr, &request(cookie, &pairs));
            assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
            relay_addr(&out)
        };
        let port = |s: &UdpSocket| s.local_addr().unwrap().port();
        let cookie = String::from_utf8_lossy(id).into_owned();
        // The offer's SDP has the relay's port for B, the answer's for A.
        let relay_b = send(&format!("{cookie}o"), b"offer", port(&a));
        let relay_a = send(&format!("{cookie}a"), b"answer", port(&b));
        std::thread::sleep(Duration::from_millis(50));
        for s in [&a, &b, &b2] {
            s.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
        }
        let mut buf = [0u8; 2048];
        // Both latch.
        a.send_to(&rtp(1), relay_a).unwrap();
        b.recv_from(&mut buf).expect("B gets A's audio");
        b.send_to(&rtp(1), relay_b).unwrap();
        a.recv_from(&mut buf).expect("A gets B's audio");
        // B's NAT rebinds: it now sends from b2.
        for seq in 2..6 {
            b2.send_to(&rtp(seq), relay_b).unwrap();
            a.recv_from(&mut buf).expect("A still gets B's audio");
        }
        a.send_to(&rtp(9), relay_a).unwrap();
        b2.recv_from(&mut buf).is_ok()
    };
    assert!(run(b"handover-1", true), "followed the new source");
    assert!(!run(b"handover-2", false), "stays on the old one");
}

/// IPv4 and IPv6: an IPv6 offerer gets the IPv6 interface by itself;
/// `address-family` bridges to the other family (media both ways);
/// `media-address` is what the SDP says; mismatches are refused.
#[test]
#[allow(clippy::too_many_lines)] // One call per case.
fn address_family_bridges_ipv4_and_ipv6() {
    let srv = server_on(
        55_400,
        "[[interface]]\nname = \"v4\"\naddress = \"127.0.0.1\"\n\
         [[interface]]\nname = \"v6\"\naddress = \"::1\"",
        "",
    );
    let client = endpoint();
    let sdp = |family: &str, addr: &str, port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN {family} {addr}\r\ns=-\r\nc=IN {family} {addr}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=sendrecv\r\n"
        )
    };
    let send = |cookie: &str, command: &[u8], id: &[u8], body: &str, extra: Vec<(&str, V<'_>)>| {
        let mut pairs = vec![
            ("command", V::S(command)),
            ("call-id", V::S(id)),
            ("from-tag", V::S(b"f")),
            ("sdp", V::S(body.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
        ];
        if command == b"answer" {
            pairs.push(("to-tag", V::S(b"t")));
        }
        pairs.extend(extra);
        let (r, out, _) = call(&client, srv.addr, &request(cookie, &pairs));
        (r, String::from_utf8(out).unwrap())
    };
    // An IPv6 offer, no direction: the v6 interface (it used to be refused).
    let (r, to_b) = send("1", b"offer", b"fam-1", &sdp("IP6", "::1", 4000), vec![]);
    assert_eq!(r, "ok", "{to_b}");
    assert!(to_b.contains("c=IN IP6 ::1\r\n"), "{to_b}");

    // IPv4 caller, IPv6 callee, with media.
    let a = endpoint();
    let b = UdpSocket::bind("[::1]:0").unwrap();
    let (r, to_b) = send(
        "2",
        b"offer",
        b"fam-2",
        &sdp("IP4", "127.0.0.1", a.local_addr().unwrap().port()),
        vec![("address-family", V::S(b"IP6"))],
    );
    assert_eq!(r, "ok", "{to_b}");
    assert!(
        to_b.contains("c=IN IP6 ::1\r\n") && to_b.contains("o=- 1 1 IN IP6 ::1\r\n"),
        "{to_b}"
    );
    let (r, to_a) = send(
        "3",
        b"answer",
        b"fam-2",
        &sdp("IP6", "::1", b.local_addr().unwrap().port()),
        vec![],
    );
    assert_eq!(r, "ok", "{to_a}");
    assert!(to_a.contains("c=IN IP4 127.0.0.1\r\n"), "{to_a}");
    std::thread::sleep(Duration::from_millis(50));
    let port = |sdp: &str| first_media(sdp.as_bytes()).port;
    for s in [&a, &b] {
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    }
    let mut buf = [0u8; 2048];
    a.send_to(&rtp(1), ("127.0.0.1", port(&to_a))).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("IPv4 to IPv6");
    assert_eq!(&buf[..n], &rtp(1)[..]);
    b.send_to(&rtp(2), ("::1", port(&to_b))).unwrap();
    let (n, _) = a.recv_from(&mut buf).expect("IPv6 to IPv4");
    assert_eq!(&buf[..n], &rtp(2)[..]);

    // media-address: what the SDP says (of the interface's family).
    let (r, to_b) = send(
        "4",
        b"offer",
        b"fam-3",
        &sdp("IP4", "127.0.0.1", 4000),
        vec![("media-address", V::S(b"203.0.113.10"))],
    );
    assert_eq!(r, "ok", "{to_b}");
    assert!(to_b.contains("c=IN IP4 203.0.113.10\r\n"), "{to_b}");
    let v4 = sdp("IP4", "127.0.0.1", 4000);
    let refused = |cookie: &str, id: &[u8], extra: Vec<(&str, V<'_>)>| {
        let (r, why) = send(cookie, b"offer", id, &v4, extra);
        assert_eq!(r, "error");
        why
    };
    assert_eq!(
        refused("5", b"fam-4", vec![("media-address", V::S(b"2001:db8::1"))]),
        "unsupported option media-address 2001:db8::1: not of interface v4's address family"
    );
    assert_eq!(
        refused("6", b"fam-5", vec![("address-family", V::S(b"IPX"))]),
        "unsupported option address-family IPX"
    );
    assert_eq!(
        refused(
            "7",
            b"fam-6",
            vec![
                ("direction", V::L(&[b"v4", b"v4"])),
                ("address-family", V::S(b"IP6")),
            ]
        ),
        "unsupported option address-family IP6: interface v4 is not"
    );
}

/// The proxy's SDP edits: `sdp-attr` (session and per kind),
/// `strip-extmap`, `generate-mid`, `replace` `username` and
/// `session-name`, and `sdp-version` (the relay's `o=` version, raised
/// only when what the party gets changes).
#[test]
fn sdp_edits_and_versions() {
    let srv = server(55_600);
    let client = endpoint();
    let sdp = |version: u32, direction: &str| {
        format!(
            "v=0\r\no=pbx 1 {version} IN IP4 127.0.0.1\r\ns=secret\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             a=tool:pbx 10.9.8.7\r\nm=audio 4000 RTP/AVP 0\r\na=x-internal:10.9.8.7\r\n\
             a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\na={direction}\r\n"
        )
    };
    // sdp-attr: {audio: {add: [x-relay:1], remove: [x-internal]},
    // global: {remove: [tool]}}
    let attrs: &[u8] =
        b"d5:audiod3:addl9:x-relay:1e6:removel10:x-internalee6:globald6:removel4:tooleee";
    let offer = |cookie: &str, version: u32, direction: &str| {
        let body = sdp(version, direction);
        let (r, out, _) = call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[
                    ("command", V::S(b"offer")),
                    ("call-id", V::S(b"edits-1")),
                    ("from-tag", V::S(b"f")),
                    ("sdp", V::S(body.as_bytes())),
                    (
                        "flags",
                        V::L(&[b"trust-address", b"strip-extmap", b"generate-mid"]),
                    ),
                    (
                        "replace",
                        V::L(&[b"username", b"session-name", b"sdp-version"]),
                    ),
                    ("sdp-attr", V::Raw(attrs)),
                ],
            ),
        );
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
        String::from_utf8(out).unwrap()
    };
    let first = offer("1", 5, "sendrecv");
    for gone in ["a=tool", "x-internal", "a=extmap", "secret", "pbx"] {
        assert!(!first.contains(gone), "{gone}: {first}");
    }
    assert!(
        first.contains("o=- 1 5 IN IP4 127.0.0.1\r\ns=-\r\n"),
        "{first}"
    );
    assert!(
        first.contains("a=mid:0\r\n") && first.contains("a=x-relay:1\r\n"),
        "{first}"
    );
    // The same offer again (a retransmitted re-INVITE with a new version):
    // what B gets is the same, so is the version.
    let again = offer("2", 6, "sendrecv");
    assert!(again.contains("o=- 1 5 "), "{again}");
    // Hold: it changed.
    let hold = offer("3", 7, "sendonly");
    assert!(
        hold.contains("o=- 1 6 ") && hold.contains("a=sendonly"),
        "{hold}"
    );
}

/// `delete` targets the dialog: a fork that lost (another `to-tag`) or
/// another branch (`via-branch`) deletes nothing (`ok` with a warning);
/// the dialog's own tags delete it; `fatal` makes "nothing" an error.
#[test]
fn delete_targets_the_answered_fork() {
    let srv = server(59_000);
    let client = endpoint();
    let send = |cookie: &str, pairs: Vec<(&str, V<'_>)>| {
        let (r, out, raw) = call(&client, srv.addr, &request(cookie, &pairs));
        let warning = at(reply_dict(&raw), &[b"warning"]).is_some();
        (r, String::from_utf8_lossy(&out).into_owned(), warning)
    };
    let offer_sdp = sdp_for(4000);
    let answer_sdp = sdp_for(4002);
    let (r, ..) = send(
        "1",
        vec![
            ("command", V::S(b"offer")),
            ("call-id", V::S(b"fork-1")),
            ("from-tag", V::S(b"caller")),
            ("via-branch", V::S(b"z9hG4bK-a")),
            ("sdp", V::S(&offer_sdp)),
        ],
    );
    assert_eq!(r, "ok");
    let (r, ..) = send(
        "2",
        vec![
            ("command", V::S(b"answer")),
            ("call-id", V::S(b"fork-1")),
            ("from-tag", V::S(b"caller")),
            ("to-tag", V::S(b"phone-2")),
            ("sdp", V::S(&answer_sdp)),
        ],
    );
    assert_eq!(r, "ok");
    let delete = |cookie: &str, extra: Vec<(&str, V<'_>)>| {
        let mut pairs = vec![
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"fork-1")),
            ("from-tag", V::S(b"caller")),
        ];
        pairs.extend(extra);
        send(cookie, pairs)
    };
    let alive = |cookie: &str| {
        send(
            cookie,
            vec![("command", V::S(b"query")), ("call-id", V::S(b"fork-1"))],
        )
        .0 == "ok"
    };
    // The fork that lost.
    let (r, _, warned) = delete("3", vec![("to-tag", V::S(b"phone-1"))]);
    assert!(r == "ok" && warned && alive("4"), "another fork's delete");
    let (r, why, _) = delete(
        "5",
        vec![("to-tag", V::S(b"phone-1")), ("flags", V::L(&[b"fatal"]))],
    );
    assert_eq!((r.as_str(), why.as_str()), ("error", "unknown call"));
    // Another branch.
    let (r, _, warned) = delete("6", vec![("via-branch", V::S(b"z9hG4bK-b"))]);
    assert!(r == "ok" && warned && alive("7"), "another branch's delete");
    // The dialog's own: the callee's BYE, tags the other way round.
    let (r, ..) = send(
        "8",
        vec![
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"fork-1")),
            ("from-tag", V::S(b"phone-2")),
            ("to-tag", V::S(b"caller")),
            ("via-branch", V::S(b"z9hG4bK-a")),
        ],
    );
    assert_eq!(r, "ok");
    assert!(!alive("9"), "deleted");
    // Again: nothing left, a warning.
    let (r, _, warned) = delete("10", vec![]);
    assert!(r == "ok" && warned);
}

/// `connect` (a transfer): A of the first call and D of the second talk
/// to each other through the relay ports they already know; B and C are
/// detached. With the calls on one media worker and on two. When the
/// second call ends, A is left alone.
#[test]
fn connect_joins_parties_of_two_calls() {
    for (port, workers) in [(59_200, 1), (59_400, 2)] {
        let srv = server_full(
            port,
            "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
            "",
            workers,
        );
        let client = endpoint();
        let send = |cookie: String, pairs: Vec<(&str, V<'_>)>| {
            let (r, out, _) = call(&client, srv.addr, &request(&cookie, &pairs));
            assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
            out
        };
        // A call: (caller, callee, relay port for the caller, for the callee).
        let dialog = |id: &[u8]| {
            let (caller, callee) = (endpoint(), endpoint());
            let flags: [&[u8]; 1] = [b"trust-address"];
            let msg = |command: &'static [u8], s: &UdpSocket| {
                let mut p = vec![
                    ("command", V::S(command)),
                    ("call-id", V::S(id)),
                    ("from-tag", V::S(b"f")),
                    ("flags", V::L(&flags)),
                    ("endpoint-learning", V::S(b"off")),
                ];
                if command == b"answer" {
                    p.push(("to-tag", V::S(b"t")));
                }
                (p, sdp_for(s.local_addr().unwrap().port()))
            };
            let (mut p, sdp) = msg(b"offer", &caller);
            p.push(("sdp", V::S(&sdp)));
            let for_callee = relay_addr(&send(format!("{workers}{}o", id[0]), p));
            let (mut p, sdp) = msg(b"answer", &callee);
            p.push(("sdp", V::S(&sdp)));
            let for_caller = relay_addr(&send(format!("{workers}{}a", id[0]), p));
            for s in [&caller, &callee] {
                s.set_read_timeout(Some(Duration::from_millis(400)))
                    .unwrap();
            }
            (caller, callee, for_caller, for_callee)
        };
        let (alice, bob, alice_to, bob_to) = dialog(b"1-call");
        let (carol, dave, _carol_to, dave_to) = dialog(b"2-call");
        std::thread::sleep(Duration::from_millis(50));
        let mut buf = [0u8; 2048];
        // Before: A and B talk.
        alice.send_to(&rtp(1), alice_to).unwrap();
        assert!(bob.recv_from(&mut buf).is_ok(), "{workers}: A to B");
        send(
            format!("{workers}c"),
            vec![
                ("command", V::S(b"connect")),
                ("call-id", V::S(b"1-call")),
                ("from-tag", V::S(b"f")),
                ("to-call-id", V::S(b"2-call")),
                ("to-tag", V::S(b"t")),
            ],
        );
        std::thread::sleep(Duration::from_millis(50));
        // A to D, D to A, each from the relay port it knows.
        alice.send_to(&rtp(2), alice_to).unwrap();
        let (n, from) = dave.recv_from(&mut buf).expect("A to D");
        assert_eq!((&buf[..n], from), (&rtp(2)[..], dave_to), "{workers}");
        dave.send_to(&rtp(3), dave_to).unwrap();
        let (n, from) = alice.recv_from(&mut buf).expect("D to A");
        assert_eq!((&buf[..n], from), (&rtp(3)[..], alice_to), "{workers}");
        // B and C are detached: nothing to or from them.
        assert!(bob.recv_from(&mut buf).is_err() && carol.recv_from(&mut buf).is_err());
        bob.send_to(&rtp(4), bob_to).unwrap();
        assert!(
            alice.recv_from(&mut buf).is_err(),
            "{workers}: B no longer reaches A"
        );
        // The second call ends: A is left alone.
        send(
            format!("{workers}x"),
            vec![("command", V::S(b"delete")), ("call-id", V::S(b"2-call"))],
        );
        std::thread::sleep(Duration::from_millis(50));
        alice.send_to(&rtp(5), alice_to).unwrap();
        assert!(
            dave.recv_from(&mut buf).is_err(),
            "{workers}: nothing after the end"
        );
        alice.send_to(&rtp(6), alice_to).unwrap();
        assert!(dave.recv_from(&mut buf).is_err() && bob.recv_from(&mut buf).is_err());
    }
}

/// A party transferred twice (`connect` again with another party): it
/// talks to the new target only, and the previous target is detached both
/// ways. Calls go to workers in turn, so the order they are made in sets
/// the case: from a connection across workers to one on the same worker
/// (where the old one used to stay), from the same worker to across, and
/// from across to across.
#[test]
#[allow(clippy::too_many_lines)] // Three placements, step by step.
fn connect_again_moves_the_party() {
    // (first port, workers, calls in the order made; `pad` only takes a
    // worker's turn).
    let layouts: [(u16, usize, &[&[u8]]); 3] = [
        (52_200, 2, &[b"x", b"t1", b"t2"]),
        (52_400, 2, &[b"x", b"pad", b"t1", b"t2"]),
        (55_400, 3, &[b"x", b"t1", b"t2"]),
    ];
    for (port, workers, order) in layouts {
        let srv = server_full(
            port,
            "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
            "",
            workers,
        );
        let client = endpoint();
        let send = |cookie: String, pairs: Vec<(&str, V<'_>)>| {
            let (r, out, _) = call(&client, srv.addr, &request(&cookie, &pairs));
            assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
            out
        };
        // A call: (caller, callee, relay address for the caller, for the callee).
        let dialog = |id: &[u8]| {
            let (caller, callee) = (endpoint(), endpoint());
            let flags: [&[u8]; 1] = [b"trust-address"];
            let msg = |command: &'static [u8], s: &UdpSocket| {
                let mut p = vec![
                    ("command", V::S(command)),
                    ("call-id", V::S(id)),
                    ("from-tag", V::S(b"f")),
                    ("flags", V::L(&flags)),
                    ("endpoint-learning", V::S(b"off")),
                ];
                if command == b"answer" {
                    p.push(("to-tag", V::S(b"t")));
                }
                (p, sdp_for(s.local_addr().unwrap().port()))
            };
            let tag = String::from_utf8_lossy(id).into_owned();
            let (mut p, sdp) = msg(b"offer", &caller);
            p.push(("sdp", V::S(&sdp)));
            let for_callee = relay_addr(&send(format!("{workers}{tag}o"), p));
            let (mut p, sdp) = msg(b"answer", &callee);
            p.push(("sdp", V::S(&sdp)));
            let for_caller = relay_addr(&send(format!("{workers}{tag}a"), p));
            for s in [&caller, &callee] {
                s.set_read_timeout(Some(Duration::from_millis(300)))
                    .unwrap();
            }
            (caller, callee, for_caller, for_callee)
        };
        let mut calls = std::collections::HashMap::new();
        for id in order {
            calls.insert(*id, dialog(id));
        }
        let (alice, _, alice_to, _) = &calls[&b"x"[..]];
        let (_, carol, _, carol_to) = &calls[&b"t1"[..]];
        let (_, dave, _, dave_to) = &calls[&b"t2"[..]];
        let connect = |cookie: &str, to: &'static [u8]| {
            send(
                format!("{port}{cookie}"),
                vec![
                    ("command", V::S(b"connect")),
                    ("call-id", V::S(b"x")),
                    ("from-tag", V::S(b"f")),
                    ("to-call-id", V::S(to)),
                    ("to-tag", V::S(b"t")),
                ],
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut buf = [0u8; 2048];
        // `x` reaches `y` (from the relay address `y` sends to).
        let mut reaches = |x: &UdpSocket, x_to: SocketAddr, y: &UdpSocket, y_to, seq| {
            while y.recv_from(&mut buf).is_ok() {}
            x.send_to(&rtp(seq), x_to).unwrap();
            matches!(y.recv_from(&mut buf), Ok((_, from)) if from == y_to)
        };
        connect("c1", b"t1");
        assert!(
            reaches(alice, *alice_to, carol, *carol_to, 1),
            "{port}: A to C"
        );
        assert!(
            reaches(carol, *carol_to, alice, *alice_to, 2),
            "{port}: C to A"
        );
        // Transferred again: Alice talks to Dave, Carol is detached.
        connect("c2", b"t2");
        assert!(
            reaches(alice, *alice_to, dave, *dave_to, 3),
            "{port}: A to D"
        );
        assert!(
            reaches(dave, *dave_to, alice, *alice_to, 4),
            "{port}: D to A"
        );
        assert!(
            !reaches(alice, *alice_to, carol, *carol_to, 5),
            "{port}: A no longer reaches C"
        );
        assert!(
            !reaches(carol, *carol_to, alice, *alice_to, 6),
            "{port}: C no longer reaches A"
        );
    }
}

/// A forked INVITE (`via-branch`): each branch gets its own media; the
/// branch that answers becomes the dialog (in-dialog requests name no
/// branch), and the losing branch's delete removes only its media.
#[test]
fn forked_branches_get_their_own_media() {
    let srv = server(61_400);
    let client = endpoint();
    let (alice, bob1, bob2) = (endpoint(), endpoint(), endpoint());
    let send = |cookie: &str, pairs: Vec<(&str, V<'_>)>| {
        let (r, out, _) = call(&client, srv.addr, &request(cookie, &pairs));
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
        out
    };
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let offer_sdp = sdp_for(port(&alice));
    let offer = |cookie: &str, via: &'static [u8]| {
        relay_addr(&send(
            cookie,
            vec![
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"fork-2")),
                ("from-tag", V::S(b"alice")),
                ("via-branch", V::S(via)),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
                ("sdp", V::S(&offer_sdp)),
            ],
        ))
    };
    let for_bob1 = offer("1", b"z9hG4bK-1");
    let for_bob2 = offer("2", b"z9hG4bK-2");
    assert_ne!(for_bob1, for_bob2, "each branch its own ports");
    // Branch 2 answers.
    let answer_sdp = sdp_for(port(&bob2));
    let for_alice = relay_addr(&send(
        "3",
        vec![
            ("command", V::S(b"answer")),
            ("call-id", V::S(b"fork-2")),
            ("from-tag", V::S(b"alice")),
            ("to-tag", V::S(b"bob2")),
            ("via-branch", V::S(b"z9hG4bK-2")),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
            ("sdp", V::S(&answer_sdp)),
        ],
    ));
    // The proxy cancels branch 1: only its media goes.
    send(
        "4",
        vec![
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"fork-2")),
            ("from-tag", V::S(b"alice")),
            ("via-branch", V::S(b"z9hG4bK-1")),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    for s in [&alice, &bob1, &bob2] {
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
    }
    let mut buf = [0u8; 2048];
    alice.send_to(&rtp(1), for_alice).unwrap();
    assert!(
        bob2.recv_from(&mut buf).is_ok(),
        "alice to the answering branch"
    );
    bob2.send_to(&rtp(2), for_bob2).unwrap();
    assert!(alice.recv_from(&mut buf).is_ok(), "and back");
    assert!(
        bob1.recv_from(&mut buf).is_err(),
        "nothing to the losing branch"
    );
    // A re-INVITE in the dialog (no branch named) finds it, on its ports.
    let again = relay_addr(&send(
        "5",
        vec![
            ("command", V::S(b"offer")),
            ("call-id", V::S(b"fork-2")),
            ("from-tag", V::S(b"alice")),
            ("to-tag", V::S(b"bob2")),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
            ("sdp", V::S(&offer_sdp)),
        ],
    ));
    assert_eq!(again, for_bob2, "the answered branch's ports");
}
