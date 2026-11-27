//! `create` and `create answer`: the relay offers media for a party of its
//! own making, answered by an endpoint (a media server), then joined to
//! the call's other parties.

use crate::common::*;
use rtpflux_ng::bencode::Value;
use std::net::UdpSocket;
use std::time::Duration;

fn text<'a>(v: Value<'a>, key: &[u8]) -> &'a [u8] {
    match at(v, &[key]) {
        Some(Value::Bytes(b)) => b,
        other => panic!("{}: {other:?}", String::from_utf8_lossy(key)),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One call, step by step.
fn a_created_party_is_answered_and_connected() {
    let srv = server(65_000);
    let client = endpoint();
    let ok = |cookie: &str, pairs: &[(&str, V<'_>)]| {
        let (r, why, raw) = call(&client, srv.addr, &request(cookie, pairs));
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
        raw
    };
    let (alice, bob, server_e) = (endpoint(), endpoint(), endpoint());
    for s in [&alice, &bob, &server_e] {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    // Alice calls Bob.
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let flags: &[&[u8]] = &[b"trust-address"];
    let base = |cmd: &'static [u8]| {
        vec![
            ("command", V::S(cmd)),
            ("call-id", V::S(b"create-1")),
            ("from-tag", V::S(b"a")),
            ("flags", V::L(flags)),
            ("endpoint-learning", V::S(b"off")),
        ]
    };
    let (sa, sb) = (sdp_for(port(&alice)), sdp_for(port(&bob)));
    let mut p = base(b"offer");
    p.push(("sdp", V::S(&sa)));
    let raw = ok("o", &p);
    let for_bob = relay_addr(text(reply_dict(&raw), b"sdp"));
    let mut p = base(b"answer");
    p.push(("to-tag", V::S(b"b")));
    p.push(("sdp", V::S(&sb)));
    let raw = ok("a", &p);
    let for_alice = relay_addr(text(reply_dict(&raw), b"sdp"));

    // A party of the relay's making, offered PCMU, labelled.
    let raw = ok(
        "c1",
        &[
            ("command", V::S(b"create")),
            ("call-id", V::S(b"create-1")),
            ("from-tag", V::S(b"srv")),
            ("label", V::S(b"media-server")),
            ("codec", V::Raw(b"d5:offerl4:PCMUee")),
        ],
    );
    let reply = reply_dict(&raw);
    assert_eq!(text(reply, b"from-tag"), b"srv");
    assert_eq!(text(reply, b"call-id"), b"create-1");
    let offer = text(reply, b"sdp");
    let offer_text = String::from_utf8_lossy(offer).into_owned();
    assert!(
        offer_text.contains(" RTP/AVP 0\r\n") && offer_text.contains("c=IN IP4 127.0.0.1"),
        "{offer_text}"
    );
    let for_server = relay_addr(offer);
    // Its endpoint answers.
    let se = sdp_for(port(&server_e));
    ok(
        "c2",
        &[
            ("command", V::S(b"create answer")),
            ("call-id", V::S(b"create-1")),
            ("from-tag", V::S(b"srv")),
            ("sdp", V::S(&se)),
            ("flags", V::L(flags)),
            ("endpoint-learning", V::S(b"off")),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    // Joined to no one yet: its media goes nowhere.
    server_e.send_to(&rtp(1), for_server).unwrap();
    assert!(alice.recv_from(&mut buf).is_err() && bob.recv_from(&mut buf).is_err());
    // `query`: the party, by its label; the relay's own offerer is none.
    let raw = ok(
        "q",
        &[("command", V::S(b"query")), ("call-id", V::S(b"create-1"))],
    );
    let Some(Value::Dict(tags)) = at(reply_dict(&raw), &[b"tags"]) else {
        panic!()
    };
    let names: Vec<&[u8]> = tags.iter().map(|(k, _)| k).collect();
    assert_eq!(names.len(), 3, "{names:?}");
    assert_eq!(
        text(at(reply_dict(&raw), &[b"tags", b"srv"]).unwrap(), b"label"),
        b"media-server"
    );
    // Connected to Alice (by label): they talk; Bob is left alone.
    ok(
        "x",
        &[
            ("command", V::S(b"connect")),
            ("call-id", V::S(b"create-1")),
            ("from-tag", V::S(b"a")),
            ("to-label", V::S(b"media-server")),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    both_ways(&alice, for_alice, &server_e, for_server, 2);
    bob.send_to(&rtp(3), for_bob).unwrap();
    assert!(alice.recv_from(&mut buf).is_err(), "bob is detached");
    // `delete` of the party ends its media.
    ok(
        "d",
        &[
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"create-1")),
            ("from-tag", V::S(b"srv")),
        ],
    );
}

/// Without `call-id` and `from-tag`, both are made up; `medias` gives
/// several sections; SRTP by `transport-protocol`; errors.
#[test]
fn create_makes_up_what_is_missing() {
    let srv = server(65_200);
    let client = endpoint();
    let (r, _, raw) = call(
        &client,
        srv.addr,
        &request(
            "c1",
            &[
                ("command", V::S(b"create")),
                ("transport-protocol", V::S(b"RTP/SAVP")),
                (
                    "medias",
                    V::Raw(b"ld4:type5:audio6:codecsl4:G722eed4:type5:audioee"),
                ),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let reply = reply_dict(&raw);
    assert_eq!(text(reply, b"call-id").len(), 32);
    assert_eq!(text(reply, b"from-tag").len(), 16);
    let sdp = String::from_utf8_lossy(text(reply, b"sdp")).into_owned();
    assert_eq!(sdp.matches("m=audio").count(), 2, "{sdp}");
    assert!(
        sdp.contains(" RTP/SAVP 9\r\n") && sdp.contains(" RTP/SAVP 8 0\r\n"),
        "{sdp}"
    );
    assert!(sdp.contains("a=crypto:1 "), "{sdp}");
    let err = |cookie: &str, pairs: &[(&str, V<'_>)]| {
        let (r, why, _) = call(&client, srv.addr, &request(cookie, pairs));
        assert_eq!(r, "error");
        String::from_utf8(why).unwrap()
    };
    assert!(
        err(
            "e1",
            &[
                ("command", V::S(b"create")),
                ("codec", V::Raw(b"d5:offerl4:frobee")),
            ]
        )
        .contains("frob")
    );
    assert!(
        err(
            "e2",
            &[
                ("command", V::S(b"create answer")),
                ("call-id", V::S(b"nope")),
                ("from-tag", V::S(b"x")),
                ("sdp", V::S(b"v=0\r\n")),
            ]
        )
        .contains("unknown call")
    );
}

/// `inject start`: what Carol (of another call) sends also reaches Bob,
/// one way; `inject stop` ends it. On one worker and across two.
#[test]
#[allow(clippy::too_many_lines)] // Two calls, step by step.
fn media_is_injected_into_another_party() {
    for (port, workers) in [(65_300, 1), (65_400, 2)] {
        let srv = server_full(
            port,
            "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
            "",
            workers,
        );
        let client = endpoint();
        let ok = |cookie: &str, pairs: &[(&str, V<'_>)]| {
            let (r, why, raw) = call(&client, srv.addr, &request(cookie, pairs));
            assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
            raw
        };
        let port_of = |s: &UdpSocket| s.local_addr().unwrap().port();
        let flags: &[&[u8]] = &[b"trust-address"];
        // A call `id` between x (tag f) and y (tag t): the relay's
        // addresses for x and y.
        let dialog = |id: &'static [u8], x: &UdpSocket, y: &UdpSocket| {
            let (sx, sy) = (sdp_for(port_of(x)), sdp_for(port_of(y)));
            let base = |cmd: &'static [u8]| {
                vec![
                    ("command", V::S(cmd)),
                    ("call-id", V::S(id)),
                    ("from-tag", V::S(b"f")),
                    ("flags", V::L(flags)),
                    ("endpoint-learning", V::S(b"off")),
                ]
            };
            let mut p = base(b"offer");
            p.push(("sdp", V::S(&sx)));
            let for_y = relay_addr(text(reply_dict(&ok("o", &p)), b"sdp"));
            let mut p = base(b"answer");
            p.push(("to-tag", V::S(b"t")));
            p.push(("sdp", V::S(&sy)));
            let for_x = relay_addr(text(reply_dict(&ok("a", &p)), b"sdp"));
            (for_x, for_y)
        };
        let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
        for s in [&alice, &bob, &carol, &dave] {
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
        }
        let (_alice_to, bob_to) = dialog(b"inject-1", &alice, &bob);
        let (carol_to, _dave_to) = dialog(b"inject-2", &carol, &dave);
        std::thread::sleep(Duration::from_millis(50));
        let inject = |cookie: &str, command: &'static [u8]| {
            ok(
                cookie,
                &[
                    ("command", V::S(command)),
                    ("call-id", V::S(b"inject-1")),
                    ("to-tag", V::S(b"t")),
                    ("source-call-id", V::S(b"inject-2")),
                    ("source-tag", V::S(b"f")),
                ],
            );
        };
        inject("i1", b"inject start");
        std::thread::sleep(Duration::from_millis(50));
        let mut buf = [0u8; 2048];
        carol.send_to(&rtp(1), carol_to).unwrap();
        assert!(
            dave.recv_from(&mut buf).is_ok(),
            "{workers}: dave hears carol"
        );
        assert!(bob.recv_from(&mut buf).is_ok(), "{workers}: so does bob");
        // One way: Bob's media does not reach Carol.
        bob.send_to(&rtp(2), bob_to).unwrap();
        assert!(alice.recv_from(&mut buf).is_ok());
        assert!(carol.recv_from(&mut buf).is_err(), "{workers}: one way");
        inject("i2", b"inject stop");
        std::thread::sleep(Duration::from_millis(50));
        carol.send_to(&rtp(3), carol_to).unwrap();
        assert!(dave.recv_from(&mut buf).is_ok());
        assert!(bob.recv_from(&mut buf).is_err(), "{workers}: stopped");
        // Errors: no injection to stop, a party to itself, no source.
        let err = |cookie: &str, pairs: &[(&str, V<'_>)]| {
            let (r, _, _) = call(&client, srv.addr, &request(cookie, pairs));
            assert_eq!(r, "error", "{cookie}");
        };
        err(
            "e1",
            &[
                ("command", V::S(b"inject stop")),
                ("call-id", V::S(b"inject-1")),
                ("to-tag", V::S(b"t")),
                ("source-call-id", V::S(b"inject-2")),
                ("source-tag", V::S(b"f")),
            ],
        );
        err(
            "e2",
            &[
                ("command", V::S(b"inject start")),
                ("call-id", V::S(b"inject-1")),
                ("to-tag", V::S(b"t")),
                ("source-tag", V::S(b"t")),
            ],
        );
        err(
            "e3",
            &[
                ("command", V::S(b"inject start")),
                ("call-id", V::S(b"inject-1")),
                ("to-tag", V::S(b"t")),
            ],
        );
    }
}

/// Copies are converted to the listener's codec: Carol (PCMA) injected
/// into Bob (PCMU) reaches him as PCMU. On one worker and across two.
#[test]
fn injected_media_is_transcoded() {
    use rtpflux_core::g711::{PT_PCMA, PT_PCMU, converter};
    for (port, workers) in [(43_400, 1), (43_600, 2)] {
        let srv = server_full(
            port,
            "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
            "",
            workers,
        );
        let client = endpoint();
        let ok = |cookie: &str, pairs: &[(&str, V<'_>)]| {
            let (r, why, raw) = call(&client, srv.addr, &request(cookie, pairs));
            assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
            raw
        };
        let sdp = |s: &UdpSocket, pt: u8| {
            format!(
                "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                 m=audio {} RTP/AVP {pt}\r\n",
                s.local_addr().unwrap().port()
            )
            .into_bytes()
        };
        let flags: &[&[u8]] = &[b"trust-address"];
        let dialog = |id: &'static [u8], x: &UdpSocket, y: &UdpSocket, pt: u8| {
            let (sx, sy) = (sdp(x, pt), sdp(y, pt));
            let base = |cmd: &'static [u8]| {
                vec![
                    ("command", V::S(cmd)),
                    ("call-id", V::S(id)),
                    ("from-tag", V::S(b"f")),
                    ("flags", V::L(flags)),
                    ("endpoint-learning", V::S(b"off")),
                ]
            };
            let mut p = base(b"offer");
            p.push(("sdp", V::S(&sx)));
            ok("o", &p);
            let mut p = base(b"answer");
            p.push(("to-tag", V::S(b"t")));
            p.push(("sdp", V::S(&sy)));
            relay_addr(text(reply_dict(&ok("a", &p)), b"sdp"))
        };
        let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
        for s in [&alice, &bob, &carol, &dave] {
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
        }
        dialog(b"xc-1", &alice, &bob, PT_PCMU.get());
        let carol_to = dialog(b"xc-2", &carol, &dave, PT_PCMA.get());
        let (r, _, raw) = call(
            &client,
            srv.addr,
            &request(
                "i",
                &[
                    ("command", V::S(b"inject start")),
                    ("call-id", V::S(b"xc-1")),
                    ("to-tag", V::S(b"t")),
                    ("source-call-id", V::S(b"xc-2")),
                    ("source-tag", V::S(b"f")),
                ],
            ),
        );
        assert_eq!(r, "ok");
        assert!(
            !String::from_utf8_lossy(&raw).contains("warning"),
            "{}",
            String::from_utf8_lossy(&raw)
        );
        std::thread::sleep(Duration::from_millis(50));
        let alaw = 0xd5;
        carol
            .send_to(&rtp_with(PT_PCMA.get(), 1, &[alaw; 160]), carol_to)
            .unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = dave.recv_from(&mut buf).expect("dave hears carol");
        assert_eq!(
            (buf[1] & 0x7f, buf[12]),
            (PT_PCMA.get(), alaw),
            "as she sent it"
        );
        let (n2, _) = bob.recv_from(&mut buf).expect("bob gets carol's copy");
        let ulaw = converter(PT_PCMA, PT_PCMU).unwrap()[usize::from(alaw)];
        assert_eq!(
            (buf[1] & 0x7f, n2 - 12, buf[12]),
            (PT_PCMU.get(), n - 12, ulaw),
            "{workers}: in his codec"
        );
    }
}

/// `mesh`: Alice (call 1) to Carol (call 2); then, with `unsubscribe` and
/// `bidirectional`, Alice and Carol hear only each other (and Carol's
/// own dialog goes on); errors.
#[test]
#[allow(clippy::too_many_lines)] // Two calls, step by step.
fn mesh_joins_parties_of_calls() {
    let srv = server(43_800);
    let client = endpoint();
    let ok = |cookie: &str, pairs: &[(&str, V<'_>)]| {
        let (r, why, raw) = call(&client, srv.addr, &request(cookie, pairs));
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
        raw
    };
    let port_of = |s: &UdpSocket| s.local_addr().unwrap().port();
    let flags: &[&[u8]] = &[b"trust-address"];
    // A call `id` from tag `x` to tag `y`: the relay's addresses for each.
    let dialog = |id: &'static [u8],
                  (tx, x): (&'static [u8], &UdpSocket),
                  (ty, y): (&'static [u8], &UdpSocket)| {
        let (sx, sy) = (sdp_for(port_of(x)), sdp_for(port_of(y)));
        let base = |cmd: &'static [u8]| {
            vec![
                ("command", V::S(cmd)),
                ("call-id", V::S(id)),
                ("from-tag", V::S(tx)),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ]
        };
        let mut p = base(b"offer");
        p.push(("sdp", V::S(&sx)));
        let for_y = relay_addr(text(reply_dict(&ok("o", &p)), b"sdp"));
        let mut p = base(b"answer");
        p.push(("to-tag", V::S(ty)));
        p.push(("sdp", V::S(&sy)));
        let for_x = relay_addr(text(reply_dict(&ok("a", &p)), b"sdp"));
        (for_x, for_y)
    };
    let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
    for s in [&alice, &bob, &carol, &dave] {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    let (alice_to, bob_to) = dialog(b"mesh-1", (b"a", &alice), (b"b", &bob));
    let (carol_to, _dave_to) = dialog(b"mesh-2", (b"c", &carol), (b"d", &dave));
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let mut hears = |s: &UdpSocket| s.recv_from(&mut buf).is_ok();
    // Alice to Carol: Carol hears her too.
    ok(
        "m1",
        &[
            ("command", V::S(b"mesh")),
            ("calls", V::L(&[b"mesh-1", b"mesh-2"])),
            ("tags", V::Raw(b"ld4:from1:a2:tol1:ceee")),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    alice.send_to(&rtp(1), alice_to).unwrap();
    assert!(hears(&bob) && hears(&carol), "bob and carol hear alice");
    carol.send_to(&rtp(2), carol_to).unwrap();
    assert!(hears(&dave) && !hears(&alice), "one way");
    // Alice and Carol, both ways, Alice off her dialog.
    ok(
        "m2",
        &[
            ("command", V::S(b"mesh")),
            ("calls", V::L(&[b"mesh-1", b"mesh-2"])),
            ("tags", V::Raw(b"ld4:from1:a2:tol1:ceee")),
            ("flags", V::L(&[b"unsubscribe", b"bidirectional"])),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    alice.send_to(&rtp(3), alice_to).unwrap();
    assert!(hears(&carol) && !hears(&bob), "carol, not bob, hears alice");
    carol.send_to(&rtp(4), carol_to).unwrap();
    assert!(hears(&dave) && hears(&alice), "alice hears carol");
    bob.send_to(&rtp(5), bob_to).unwrap();
    assert!(!hears(&alice), "alice no longer hears bob");
    // Errors: no calls, an unknown call, a tag not found, a tag in two.
    let err = |cookie: &str, pairs: &[(&str, V<'_>)]| {
        let (r, why, _) = call(&client, srv.addr, &request(cookie, pairs));
        assert_eq!(r, "error", "{cookie}");
        String::from_utf8(why).unwrap()
    };
    err("e1", &[("command", V::S(b"mesh"))]);
    err(
        "e2",
        &[
            ("command", V::S(b"mesh")),
            ("calls", V::L(&[b"mesh-1", b"nope"])),
        ],
    );
    assert!(
        err(
            "e3",
            &[
                ("command", V::S(b"mesh")),
                ("calls", V::L(&[b"mesh-1"])),
                ("tags", V::Raw(b"ld4:from1:a2:tol1:ceee")),
            ],
        )
        .contains("to-tag c not found")
    );
    let (x, y) = (endpoint(), endpoint());
    dialog(b"mesh-3", (b"a", &x), (b"z", &y));
    assert!(
        err(
            "e4",
            &[
                ("command", V::S(b"mesh")),
                ("calls", V::L(&[b"mesh-1", b"mesh-3"])),
                ("tags", V::Raw(b"ld4:from1:a2:tol1:zeee")),
            ],
        )
        .contains("several calls")
    );
}

/// `create from offer`: an endpoint's offer is answered by the relay with
/// no other party; its media goes nowhere until it is connected (here to
/// a `create`d party of another call, on the other worker); its re-offer
/// keeps the ports and has its direction mirrored; `delete` ends it.
#[test]
#[allow(clippy::too_many_lines)] // Two endpoints, step by step.
fn a_party_is_created_from_its_offer() {
    let srv = server_full(
        65_470,
        "[[interface]]\nname = \"pub\"\naddress = \"127.0.0.1\"",
        "",
        2,
    );
    let client = endpoint();
    let ok = |cookie: &str, pairs: &[(&str, V<'_>)]| {
        let (r, why, raw) = call(&client, srv.addr, &request(cookie, pairs));
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
        raw
    };
    let (caller, ivr) = (endpoint(), endpoint());
    for s in [&caller, &ivr] {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let flags: &[&[u8]] = &[b"trust-address"];
    let offer = |direction: &str| {
        format!(
            "v=0\r\no=- 7 {} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n\
             a={direction}\r\n",
            if direction == "sendrecv" { 1 } else { 2 },
            port(&caller)
        )
    };
    let inbound = |cookie: &str, sdp: &str| {
        let raw = ok(
            cookie,
            &[
                ("command", V::S(b"create from offer")),
                ("call-id", V::S(b"in-1")),
                ("from-tag", V::S(b"caller")),
                ("label", V::S(b"inbound")),
                ("sdp", V::S(sdp.as_bytes())),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        );
        let reply = reply_dict(&raw);
        assert_eq!(text(reply, b"call-id"), b"in-1");
        assert_eq!(text(reply, b"from-tag"), b"caller");
        String::from_utf8_lossy(text(reply, b"sdp")).into_owned()
    };
    // The caller's offer, answered by the relay alone.
    let answer = inbound("i1", &offer("sendrecv"));
    assert!(
        answer.contains(" RTP/AVP 0 8\r\n")
            && answer.contains("a=sendrecv")
            && answer.contains("c=IN IP4 127.0.0.1"),
        "{answer}"
    );
    let for_caller = relay_addr(answer.as_bytes());
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    // Parked: its media goes nowhere, nothing comes back.
    caller.send_to(&rtp(1), for_caller).unwrap();
    assert!(caller.recv_from(&mut buf).is_err() && ivr.recv_from(&mut buf).is_err());
    // `query`: the party by its label; the relay's hidden side is none.
    let raw = ok(
        "q",
        &[("command", V::S(b"query")), ("call-id", V::S(b"in-1"))],
    );
    let Some(Value::Dict(tags)) = at(reply_dict(&raw), &[b"tags"]) else {
        panic!()
    };
    assert_eq!(tags.iter().map(|(k, _)| k).collect::<Vec<_>>(), [b"caller"]);
    assert_eq!(
        text(
            at(reply_dict(&raw), &[b"tags", b"caller"]).unwrap(),
            b"label"
        ),
        b"inbound"
    );
    // An IVR leg of another call, offered by the relay (`create`).
    let raw = ok(
        "c1",
        &[
            ("command", V::S(b"create")),
            ("call-id", V::S(b"out-1")),
            ("from-tag", V::S(b"ivr")),
            ("codec", V::Raw(b"d5:offerl4:PCMUee")),
        ],
    );
    let for_ivr = relay_addr(text(reply_dict(&raw), b"sdp"));
    let se = sdp_for(port(&ivr));
    ok(
        "c2",
        &[
            ("command", V::S(b"create answer")),
            ("call-id", V::S(b"out-1")),
            ("from-tag", V::S(b"ivr")),
            ("sdp", V::S(&se)),
            ("flags", V::L(flags)),
            ("endpoint-learning", V::S(b"off")),
        ],
    );
    // Bridged across calls: they talk.
    ok(
        "x",
        &[
            ("command", V::S(b"connect")),
            ("call-id", V::S(b"in-1")),
            ("from-label", V::S(b"inbound")),
            ("to-call-id", V::S(b"out-1")),
            ("to-tag", V::S(b"ivr")),
        ],
    );
    std::thread::sleep(Duration::from_millis(50));
    both_ways(&caller, for_caller, &ivr, for_ivr, 2);
    // The caller's re-offer puts the call on hold: same port, answered
    // receive-only.
    let held = inbound("i2", &offer("sendonly"));
    assert!(
        held.contains("a=recvonly") && !held.contains("a=sendrecv"),
        "{held}"
    );
    assert_eq!(relay_addr(held.as_bytes()), for_caller);
    // A tag of the relay's own, and a missing offer, are refused.
    for (cookie, pairs) in [
        (
            "e1",
            vec![
                ("command", V::S(b"create from offer")),
                ("from-tag", V::S(b"rtpflux-create:x")),
                ("sdp", V::S(b"v=0\r\n")),
            ],
        ),
        ("e2", vec![("command", V::S(b"create from offer"))]),
    ] {
        let (r, _, _) = call(&client, srv.addr, &request(cookie, &pairs));
        assert_eq!(r, "error", "{cookie}");
    }
    // `delete` of the party ends its media.
    ok(
        "d",
        &[
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"in-1")),
            ("from-tag", V::S(b"caller")),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    while ivr.recv_from(&mut buf).is_ok() {}
    caller.send_to(&rtp(9), for_caller).unwrap();
    assert!(ivr.recv_from(&mut buf).is_err(), "deleted");
}

/// `create from offer` answers an SRTP (SDES) offer with the relay's key,
/// in the offer's profile, and keeps a rejected section rejected; a tag
/// that already offered in an ordinary dialog is refused.
#[test]
fn create_from_offer_answers_srtp_and_refuses_a_dialogs_tag() {
    let srv = server(59_900);
    let client = endpoint();
    let a = endpoint();
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
         a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n\
         m=video 0 RTP/AVP 96\r\n",
        a.local_addr().unwrap().port()
    );
    let (r, why, raw) = call(
        &client,
        srv.addr,
        &request(
            "s",
            &[
                ("command", V::S(b"create from offer")),
                ("call-id", V::S(b"srtp-1")),
                ("from-tag", V::S(b"a")),
                ("sdp", V::S(offer.as_bytes())),
                ("flags", V::L(&[b"trust-address"])),
            ],
        ),
    );
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
    let answer = String::from_utf8_lossy(text(reply_dict(&raw), b"sdp")).into_owned();
    assert!(answer.contains(" RTP/SAVP 0\r\n"), "{answer}");
    assert!(
        answer.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:")
            && !answer.contains("WVNfX19"),
        "{answer}"
    );
    assert!(answer.contains("m=video 0 "), "{answer}");
    // A tag that already offered in an ordinary dialog is not taken over.
    let a = endpoint();
    let sa = sdp_for(a.local_addr().unwrap().port());
    let (r, _, _) = call(
        &client,
        srv.addr,
        &request(
            "o",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"take-1")),
                ("from-tag", V::S(b"a")),
                ("sdp", V::S(&sa)),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let (r, why, _) = call(
        &client,
        srv.addr,
        &request(
            "c",
            &[
                ("command", V::S(b"create from offer")),
                ("call-id", V::S(b"take-1")),
                ("from-tag", V::S(b"a")),
                ("sdp", V::S(&sa)),
            ],
        ),
    );
    assert_eq!(r, "error");
    assert!(String::from_utf8_lossy(&why).contains("already offered"));
}
