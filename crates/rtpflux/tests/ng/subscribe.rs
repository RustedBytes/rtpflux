//! Media subscriptions: `subscribe request`, `subscribe answer` and
//! `unsubscribe`.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use rtpflux_ng::bencode::Value;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const CALL: &[u8] = b"sub@example";

fn party_sdp(port: u16) -> Vec<u8> {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n"
    )
    .into_bytes()
}

fn ok(client: &UdpSocket, srv: SocketAddr, cookie: &str, pairs: &[(&str, V<'_>)]) -> Vec<u8> {
    let (result, extra, raw) = call(client, srv, &request(cookie, pairs));
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&extra));
    raw
}

fn bytes(v: Option<Value<'_>>) -> Vec<u8> {
    match v {
        Some(Value::Bytes(b)) => b.to_vec(),
        other => panic!("not bytes: {other:?}"),
    }
}

/// Whether `s` receives `p` (and nothing else first).
fn receives(s: &UdpSocket, p: &[u8]) -> bool {
    let mut buf = [0u8; 2048];
    matches!(s.recv_from(&mut buf), Ok((n, _)) if buf[..n] == *p)
}

fn silent(s: &UdpSocket) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 2048];
    let quiet = s.recv_from(&mut buf).is_err();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    quiet
}

/// Offer from Alice and answer from Bob (whose sockets are `a` and `b`);
/// the relay's addresses for each.
fn setup(
    client: &UdpSocket,
    srv: SocketAddr,
    a: &UdpSocket,
    b: &UdpSocket,
) -> (SocketAddr, SocketAddr) {
    let trust: &[&[u8]] = &[b"trust-address"];
    let offer = party_sdp(a.local_addr().unwrap().port());
    let raw = ok(
        client,
        srv,
        "c1",
        &[
            ("command", V::S(b"offer")),
            ("call-id", V::S(CALL)),
            ("from-tag", V::S(b"alice")),
            ("sdp", V::S(&offer)),
            ("flags", V::L(trust)),
        ],
    );
    let to_b = bytes(at(reply_dict(&raw), &[b"sdp"]));
    let answer = party_sdp(b.local_addr().unwrap().port());
    let raw = ok(
        client,
        srv,
        "c2",
        &[
            ("command", V::S(b"answer")),
            ("call-id", V::S(CALL)),
            ("from-tag", V::S(b"alice")),
            ("to-tag", V::S(b"bob")),
            ("sdp", V::S(&answer)),
            ("flags", V::L(trust)),
        ],
    );
    let to_a = bytes(at(reply_dict(&raw), &[b"sdp"]));
    (relay_addr(&to_a), relay_addr(&to_b))
}

/// The offer and labels of a SIPREC subscription to Alice and Bob.
fn siprec_labels(reply: Value<'_>, offer: &str) {
    assert_eq!(m_ports(offer.as_bytes()).len(), 2, "{offer}");
    assert_eq!(offer.matches("m=audio ").count(), 2);
    assert_eq!(offer.matches(" RTP/AVP 0 101\r\n").count(), 2, "{offer}");
    assert_eq!(
        offer.matches("a=rtpmap:101 telephone-event/8000").count(),
        2
    );
    assert_eq!(offer.matches("a=sendonly").count(), 2);
    assert!(offer.contains("a=label:1\r\n") && offer.contains("a=label:2\r\n"));
    assert_eq!(bytes(at(reply, &[b"from-tags", b"0"])), b"alice");
    assert_eq!(bytes(at(reply, &[b"from-tags", b"1"])), b"bob");
    assert_eq!(bytes(at(reply, &[b"tag-medias", b"1", b"tag"])), b"bob");
    assert_eq!(
        bytes(at(reply, &[b"tag-medias", b"1", b"medias", b"0", b"label"])),
        b"2"
    );
    assert_eq!(
        at(reply, &[b"tag-medias", b"0", b"medias", b"0", b"index"]),
        Some(Value::Int(1))
    );
    assert_eq!(bytes(at(reply, &[b"media-labels", b"2", b"tag"])), b"bob");
    assert_eq!(
        bytes(at(reply, &[b"media-labels", b"1", b"type"])),
        b"audio"
    );
}

#[test]
fn a_recorder_gets_both_parties() {
    let srv = server(53_900);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let trust: &[&[u8]] = &[b"trust-address"];
    let (ra, rb) = setup(&client, srv.addr, &a, &b);

    // Subscribe to both, as a SIPREC recorder.
    let raw = ok(
        &client,
        srv.addr,
        "s3",
        &[
            ("command", V::S(b"subscribe request")),
            ("call-id", V::S(CALL)),
            ("flags", V::L(&[b"all", b"siprec"])),
        ],
    );
    let reply = reply_dict(&raw);
    let offer = String::from_utf8(bytes(at(reply, &[b"sdp"]))).unwrap();
    let tag = bytes(at(reply, &[b"to-tag"]));
    let ports = m_ports(offer.as_bytes());
    siprec_labels(reply, &offer);

    // Not answered: nothing is copied yet.
    let (r1, r2) = (endpoint(), endpoint());
    let p = rtp(1);
    a.send_to(&p, ra).unwrap();
    assert!(receives(&b, &p));
    b.send_to(&p, rb).unwrap();
    assert!(receives(&a, &p));
    assert!(silent(&r1));

    // A subscriber answer accepting PCMU only.
    let sub_answer = format!(
        "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=recvonly\r\nm=audio {} RTP/AVP 0\r\na=recvonly\r\n",
        r1.local_addr().unwrap().port(),
        r2.local_addr().unwrap().port()
    );
    ok(
        &client,
        srv.addr,
        "s4",
        &[
            ("command", V::S(b"subscribe answer")),
            ("call-id", V::S(CALL)),
            ("to-tag", V::S(&tag)),
            ("sdp", V::S(sub_answer.as_bytes())),
            ("flags", V::L(trust)),
        ],
    );
    // A's media reaches B and the first section; B's the second.
    let p = rtp(2);
    a.send_to(&p, ra).unwrap();
    assert!(receives(&b, &p));
    assert!(receives(&r1, &p));
    let q = rtp(3);
    b.send_to(&q, rb).unwrap();
    assert!(receives(&a, &q));
    assert!(receives(&r2, &q));
    assert!(silent(&r1) && silent(&r2));
    // What the subscriber sends goes nowhere.
    r1.send_to(&rtp(4), SocketAddr::new(ra.ip(), ports[0]))
        .unwrap();
    assert!(silent(&a) && silent(&b) && silent(&r2));

    // Unsubscribed: the call goes on, the copies stop.
    ok(
        &client,
        srv.addr,
        "s5",
        &[
            ("command", V::S(b"unsubscribe")),
            ("call-id", V::S(CALL)),
            ("to-tag", V::S(&tag)),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    let p = rtp(5);
    a.send_to(&p, ra).unwrap();
    assert!(receives(&b, &p));
    assert!(silent(&r1));
    let (result, _, _) = call(
        &client,
        srv.addr,
        &request(
            "s6",
            &[
                ("command", V::S(b"unsubscribe")),
                ("call-id", V::S(CALL)),
                ("to-tag", V::S(&tag)),
            ],
        ),
    );
    assert_eq!(result, "error");
}

#[test]
fn one_party_and_the_call_ending() {
    let srv = server(56_000);
    let client = endpoint();
    let (a, b, r) = (endpoint(), endpoint(), endpoint());
    let trust: &[&[u8]] = &[b"trust-address"];
    let (ra, rb) = setup(&client, srv.addr, &a, &b);
    // Only Bob, under the subscriber's own tag.
    let raw = ok(
        &client,
        srv.addr,
        "o3",
        &[
            ("command", V::S(b"subscribe request")),
            ("call-id", V::S(CALL)),
            ("from-tag", V::S(b"bob")),
            ("to-tag", V::S(b"rec")),
        ],
    );
    let reply = reply_dict(&raw);
    let offer = String::from_utf8(bytes(at(reply, &[b"sdp"]))).unwrap();
    assert_eq!(m_ports(offer.as_bytes()).len(), 1, "{offer}");
    assert!(!offer.contains("a=label"));
    assert_eq!(bytes(at(reply, &[b"to-tag"])), b"rec");
    assert_eq!(bytes(at(reply, &[b"from-tag"])), b"bob");
    assert!(at(reply, &[b"tag-medias"]).is_none());
    // An answer without the offered formats is refused.
    let refuse = format!(
        "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 8\r\na=recvonly\r\n",
        r.local_addr().unwrap().port()
    );
    let subscribe_answer = |cookie: &str, sdp: &str| {
        call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[
                    ("command", V::S(b"subscribe answer")),
                    ("call-id", V::S(CALL)),
                    ("to-tag", V::S(b"rec")),
                    ("sdp", V::S(sdp.as_bytes())),
                    ("flags", V::L(trust)),
                ],
            ),
        )
        .0
    };
    assert_eq!(subscribe_answer("o4", &refuse), "error");
    let accept = refuse.replace("RTP/AVP 8", "RTP/AVP 0 101");
    assert_eq!(subscribe_answer("o5", &accept), "ok");
    let p = rtp(7);
    b.send_to(&p, rb).unwrap();
    assert!(receives(&a, &p));
    assert!(receives(&r, &p));
    // A's media is not copied.
    let p = rtp(8);
    a.send_to(&p, ra).unwrap();
    assert!(receives(&b, &p));
    assert!(silent(&r));
    // The call ends: so does the subscription.
    ok(
        &client,
        srv.addr,
        "o7",
        &[("command", V::S(b"delete")), ("call-id", V::S(CALL))],
    );
    assert_eq!(subscribe_answer("o8", &accept), "error");
}

/// `publish`: a sending party's offer is answered receive-only; a
/// subscriber to its tag receives its media.
#[test]
fn a_published_stream_is_subscribed_to() {
    let srv = server(56_600);
    let client = endpoint();
    let (p, r) = (endpoint(), endpoint());
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\n",
        p.local_addr().unwrap().port()
    );
    let raw = ok(
        &client,
        srv.addr,
        "u1",
        &[
            ("command", V::S(b"publish")),
            ("call-id", V::S(b"pub@example")),
            ("from-tag", V::S(b"cam")),
            ("sdp", V::S(offer.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
        ],
    );
    let answer = String::from_utf8(bytes(at(reply_dict(&raw), &[b"sdp"]))).unwrap();
    assert!(
        answer.contains("a=recvonly") && !answer.contains("a=sendonly"),
        "{answer}"
    );
    assert!(answer.contains(" RTP/AVP 0"), "{answer}");
    let rp = relay_addr(answer.as_bytes());
    assert_ne!(rp.port(), p.local_addr().unwrap().port());
    // Nothing is sent back to the publisher.
    p.send_to(&rtp(1), rp).unwrap();
    assert!(silent(&p));
    // A subscriber to the publisher.
    let raw = ok(
        &client,
        srv.addr,
        "u2",
        &[
            ("command", V::S(b"subscribe request")),
            ("call-id", V::S(b"pub@example")),
            ("from-tag", V::S(b"cam")),
            ("to-tag", V::S(b"viewer")),
        ],
    );
    let sub = String::from_utf8(bytes(at(reply_dict(&raw), &[b"sdp"]))).unwrap();
    assert_eq!(m_ports(sub.as_bytes()).len(), 1, "{sub}");
    let sub_answer = format!(
        "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=recvonly\r\n",
        r.local_addr().unwrap().port()
    );
    ok(
        &client,
        srv.addr,
        "u3",
        &[
            ("command", V::S(b"subscribe answer")),
            ("call-id", V::S(b"pub@example")),
            ("to-tag", V::S(b"viewer")),
            ("sdp", V::S(sub_answer.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
        ],
    );
    let q = rtp(2);
    p.send_to(&q, rp).unwrap();
    assert!(receives(&r, &q));
    // Unpublished with delete: the subscription ends too.
    ok(
        &client,
        srv.addr,
        "u4",
        &[
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"pub@example")),
        ],
    );
    std::thread::sleep(Duration::from_millis(100));
    p.send_to(&rtp(3), rp).unwrap();
    assert!(silent(&r));
}

/// An SRTP (SDES) publisher: its answer carries the relay's key, and a
/// plain subscriber receives its media decrypted.
#[test]
fn an_srtp_publisher_reaches_a_plain_subscriber() {
    use rtpflux_srtp::{MasterKey, Protect, Suite};
    let srv = server(56_700);
    let client = endpoint();
    let (p, r) = (endpoint(), endpoint());
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY_A_B64}\r\na=sendonly\r\n",
        p.local_addr().unwrap().port()
    );
    let raw = ok(
        &client,
        srv.addr,
        "v1",
        &[
            ("command", V::S(b"publish")),
            ("call-id", V::S(b"pub2@example")),
            ("from-tag", V::S(b"cam")),
            ("sdp", V::S(offer.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
        ],
    );
    let answer = bytes(at(reply_dict(&raw), &[b"sdp"]));
    let m = first_media(&answer);
    assert_eq!(m.transport, rtpflux_core::sdp::Transport::Savp);
    assert!(m.crypto.is_some(), "{}", String::from_utf8_lossy(&answer));
    let rp = relay_addr(&answer);
    let raw = ok(
        &client,
        srv.addr,
        "v2",
        &[
            ("command", V::S(b"subscribe request")),
            ("call-id", V::S(b"pub2@example")),
            ("from-tag", V::S(b"cam")),
            ("to-tag", V::S(b"viewer")),
        ],
    );
    let sub = String::from_utf8(bytes(at(reply_dict(&raw), &[b"sdp"]))).unwrap();
    assert!(
        sub.contains(" RTP/AVP 0") && !sub.contains("a=crypto"),
        "{sub}"
    );
    let sub_answer = format!(
        "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=recvonly\r\n",
        r.local_addr().unwrap().port()
    );
    ok(
        &client,
        srv.addr,
        "v3",
        &[
            ("command", V::S(b"subscribe answer")),
            ("call-id", V::S(b"pub2@example")),
            ("to-tag", V::S(b"viewer")),
            ("sdp", V::S(sub_answer.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
        ],
    );
    let mut tx = Protect::from_key(&MasterKey::new(Suite::AesCm128HmacSha1_80, &KEY_A).unwrap());
    let plain = rtp(1);
    let mut wire = plain.clone();
    wire.resize(plain.len() + 10, 0);
    tx.rtp(&mut wire, plain.len()).unwrap();
    p.send_to(&wire, rp).unwrap();
    assert!(receives(&r, &plain), "decrypted for the subscriber");
}

/// An SRTP (SDES) subscriber: the offer carries the relay's key, the
/// copies arrive encrypted under it, and a plain answer is refused.
#[test]
fn an_srtp_subscriber_gets_encrypted_copies() {
    use rtpflux_srtp::Unprotect;
    let srv = server(56_800);
    let client = endpoint();
    let (a, b, r) = (endpoint(), endpoint(), endpoint());
    let (ra, _) = setup(&client, srv.addr, &a, &b);
    let raw = ok(
        &client,
        srv.addr,
        "w1",
        &[
            ("command", V::S(b"subscribe request")),
            ("call-id", V::S(CALL)),
            ("from-tag", V::S(b"alice")),
            ("to-tag", V::S(b"rec")),
            ("transport-protocol", V::S(b"RTP/SAVP")),
        ],
    );
    let offer = bytes(at(reply_dict(&raw), &[b"sdp"]));
    let media = first_media(&offer);
    assert_eq!(media.transport, rtpflux_core::sdp::Transport::Savp);
    let key = media.crypto.expect("the relay's key").key;
    let answer = |proto: &str| {
        format!(
            "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} {proto} 0\r\n{}a=recvonly\r\n",
            r.local_addr().unwrap().port(),
            if proto == "RTP/SAVP" {
                format!("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY_A_B64}\r\n")
            } else {
                String::new()
            }
        )
    };
    let subscribe_answer = |cookie: &str, sdp: &str| {
        call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[
                    ("command", V::S(b"subscribe answer")),
                    ("call-id", V::S(CALL)),
                    ("to-tag", V::S(b"rec")),
                    ("sdp", V::S(sdp.as_bytes())),
                    ("flags", V::L(&[b"trust-address"])),
                ],
            ),
        )
        .0
    };
    assert_eq!(subscribe_answer("w2", &answer("RTP/AVP")), "error");
    assert_eq!(subscribe_answer("w3", &answer("RTP/SAVP")), "ok");
    let mut rx = Unprotect::from_key(&key);
    for seq in 0..3 {
        let sent = rtp(seq);
        a.send_to(&sent, ra).unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = r.recv_from(&mut buf).expect("an SRTP copy");
        assert_ne!(&buf[..n], &sent[..], "encrypted");
        let n = rx.rtp(&mut buf, n).expect("under the offered key");
        assert_eq!(&buf[..n], &sent[..]);
    }
}

/// A call between Alice (`a`) and Bob (`b`), and a subscription `rec` to
/// Bob answered by `r`; the relay's address for Bob.
fn subscribe_to_bob(
    client: &UdpSocket,
    srv: SocketAddr,
    (a, b): (&UdpSocket, &UdpSocket),
    r: &UdpSocket,
) -> SocketAddr {
    let (_, rb) = setup(client, srv, a, b);
    ok(
        client,
        srv,
        "q1",
        &[
            ("command", V::S(b"subscribe request")),
            ("call-id", V::S(CALL)),
            ("from-tag", V::S(b"bob")),
            ("to-tag", V::S(b"rec")),
        ],
    );
    let answer = format!(
        "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\na=recvonly\r\n",
        r.local_addr().unwrap().port()
    );
    ok(
        client,
        srv,
        "q2",
        &[
            ("command", V::S(b"subscribe answer")),
            ("call-id", V::S(CALL)),
            ("to-tag", V::S(b"rec")),
            ("sdp", V::S(answer.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
        ],
    );
    rb
}

/// `query` shows a subscription as a tag of the call (its streams counting
/// the copies sent, and its source), the source's subscribers, and the
/// dialog's parties; `list` lists it.
#[test]
fn query_and_list_show_subscriptions() {
    let srv = server(56_900);
    let client = endpoint();
    let (a, b, r) = (endpoint(), endpoint(), endpoint());
    let rb = subscribe_to_bob(&client, srv.addr, (&a, &b), &r);
    for seq in 0..3 {
        let sent = rtp(seq);
        b.send_to(&sent, rb).unwrap();
        assert!(receives(&r, &sent));
    }
    let raw = ok(
        &client,
        srv.addr,
        "q3",
        &[("command", V::S(b"query")), ("call-id", V::S(CALL))],
    );
    let reply = reply_dict(&raw);
    let tag = |t: &[u8], path: &[&[u8]]| {
        let mut p: Vec<&[u8]> = vec![b"tags", t];
        p.extend_from_slice(path);
        at(reply, &p)
    };
    assert_eq!(
        bytes(tag(b"rec", &[b"subscriptions", b"0", b"tag"])),
        b"bob"
    );
    assert_eq!(
        bytes(tag(b"rec", &[b"subscriptions", b"0", b"type"])),
        b"pub/sub"
    );
    assert_eq!(tag(b"rec", &[b"answered"]), Some(Value::Int(1)));
    assert_eq!(
        tag(
            b"rec",
            &[b"medias", b"0", b"streams", b"0", b"stats", b"packets"]
        ),
        Some(Value::Int(3)),
        "the copies sent"
    );
    assert_eq!(
        tag(
            b"rec",
            &[b"medias", b"0", b"streams", b"0", b"endpoint", b"port"]
        ),
        Some(Value::Int(i64::from(r.local_addr().unwrap().port())))
    );
    assert_eq!(bytes(tag(b"bob", &[b"subscribers", b"0", b"tag"])), b"rec");
    assert_eq!(
        bytes(tag(b"bob", &[b"subscriptions", b"0", b"tag"])),
        b"alice"
    );
    assert_eq!(
        bytes(tag(b"bob", &[b"subscriptions", b"0", b"type"])),
        b"offer/answer"
    );
    assert!(
        matches!(tag(b"alice", &[b"subscribers"]), Some(Value::List(l)) if l.iter().count() == 0)
    );
    // Asked by the subscription's tag: only it.
    let raw = ok(
        &client,
        srv.addr,
        "q4",
        &[
            ("command", V::S(b"query")),
            ("call-id", V::S(CALL)),
            ("from-tag", V::S(b"rec")),
        ],
    );
    assert!(at(reply_dict(&raw), &[b"tags", b"rec"]).is_some());
    let raw = ok(&client, srv.addr, "q5", &[("command", V::S(b"list"))]);
    let reply = reply_dict(&raw);
    assert_eq!(
        bytes(at(reply, &[b"subscriptions", b"0", b"call-id"])),
        CALL
    );
    assert_eq!(
        bytes(at(reply, &[b"subscriptions", b"0", b"to-tag"])),
        b"rec"
    );
    assert_eq!(
        bytes(at(reply, &[b"subscriptions", b"0", b"from-tags", b"0"])),
        b"bob"
    );
}

/// A connectivity check from `viewer` to `to_relay` with the credentials
/// of `offer` gets a signed success response naming `viewer`'s address.
fn ice_check_answered(viewer: &UdpSocket, to_relay: SocketAddr, offer: &str) {
    use rtpflux_core::stun::{CheckRequest, Response, Role as IceRole, read_response, write_check};
    let ufrag = sdp_line(offer, "a=ice-ufrag:").unwrap();
    let pwd = sdp_line(offer, "a=ice-pwd:").unwrap();
    let username = format!("{ufrag}:peer");
    let mut msg = [0u8; 512];
    let n = write_check(
        &mut msg,
        &[7; 12],
        &CheckRequest {
            username: username.as_bytes(),
            pwd: pwd.as_bytes(),
            priority: 1_845_501_695,
            role: IceRole::Controlling,
            tiebreaker: 9,
            use_candidate: true,
        },
    )
    .unwrap();
    viewer.send_to(&msg[..n], to_relay).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = viewer.recv_from(&mut buf).expect("a check response");
    let (tid, response) =
        read_response(&buf[..n], pwd.as_bytes()).expect("signed with the relay's password");
    assert_eq!(tid, [7; 12]);
    assert!(
        matches!(response, Response::Success { mapped } if mapped == viewer.local_addr().unwrap())
    );
}

/// A WebRTC subscriber (DTLS-SRTP): the offer carries ICE-lite credentials
/// and candidates, the relay's fingerprint and `actpass`; nothing goes out
/// before the handshake; then the copies come under the DTLS keys.
#[test]
fn a_dtls_subscriber_gets_copies_after_the_handshake() {
    use rtpflux::dtls::{Association, Identity};
    use rtpflux_core::dtls::{Fingerprint, Role};
    use rtpflux_srtp::Unprotect;
    let srv = server(57_100);
    let client = endpoint();
    let (a, b, viewer) = (endpoint(), endpoint(), endpoint());
    let (ra, _) = setup(&client, srv.addr, &a, &b);
    let raw = ok(
        &client,
        srv.addr,
        "x1",
        &[
            ("command", V::S(b"subscribe request")),
            ("call-id", V::S(CALL)),
            ("from-tag", V::S(b"alice")),
            ("to-tag", V::S(b"web")),
            ("transport-protocol", V::S(b"UDP/TLS/RTP/SAVPF")),
        ],
    );
    let offer = String::from_utf8(bytes(at(reply_dict(&raw), &[b"sdp"]))).unwrap();
    for needed in [
        " UDP/TLS/RTP/SAVPF 0 101\r\n",
        "a=ice-lite\r\n",
        "a=ice-ufrag:",
        "a=ice-pwd:",
        " typ host\r\n",
        "a=setup:actpass\r\n",
        "a=fingerprint:",
        "a=rtcp-mux\r\n",
        "a=mid:1\r\n",
    ] {
        assert!(offer.contains(needed), "{needed:?} in {offer}");
    }
    let relay_fp = sdp_line(&offer, "a=fingerprint:").unwrap().to_owned();
    let to_relay = SocketAddr::new("127.0.0.1".parse().unwrap(), m_ports(offer.as_bytes())[0]);
    let peer = Identity::generate().unwrap();
    let answer = |proto: &str| {
        format!(
            "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} {proto} 0\r\na=setup:active\r\na=fingerprint:{}\r\na=rtcp-mux\r\na=recvonly\r\n",
            viewer.local_addr().unwrap().port(),
            peer.fingerprint()
        )
    };
    let subscribe_answer = |cookie: &str, sdp: &str| {
        call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[
                    ("command", V::S(b"subscribe answer")),
                    ("call-id", V::S(CALL)),
                    ("to-tag", V::S(b"web")),
                    ("sdp", V::S(sdp.as_bytes())),
                    ("flags", V::L(&[b"trust-address"])),
                    ("endpoint-learning", V::S(b"off")),
                ],
            ),
        )
        .0
    };
    assert_eq!(subscribe_answer("x2", &answer("RTP/AVP")), "error");
    assert_eq!(subscribe_answer("x3", &answer("UDP/TLS/RTP/SAVPF")), "ok");
    // No keys yet: nothing leaves for the subscriber.
    a.send_to(&rtp(1), ra).unwrap();
    assert!(silent(&viewer));
    // The subscriber's ICE check (it is the full agent) is answered.
    ice_check_answered(&viewer, to_relay, &offer);
    let mut dtls = Association::new(
        &peer,
        Role::Client,
        [Fingerprint::parse(relay_fp.as_bytes()), None],
    )
    .unwrap();
    let (inbound, _) = crate::secure::dtls_handshake(&viewer, to_relay, &mut dtls);
    std::thread::sleep(Duration::from_millis(20));
    let mut rx = Unprotect::from_key(&inbound);
    let sent = rtp(2);
    a.send_to(&sent, ra).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = viewer.recv_from(&mut buf).expect("an SRTP copy");
    let n = rx.rtp(&mut buf, n).expect("under the DTLS keys");
    assert_eq!(&buf[..n], &sent[..]);
}
