//! `rollback`: a re-offer made with `track-state` is taken back before its
//! answer, the dialog returning to its last agreed media.

use crate::common::*;
use rtpflux_ng::bencode::Value;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const CALL: &[u8] = b"rollback@example";

/// Two audio sections to the ports of `s` and `t` (`t`'s at port 0:
/// removed).
fn sdp(s: &UdpSocket, t: Option<&UdpSocket>) -> Vec<u8> {
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\nm=audio {} RTP/AVP 0\r\n",
        port(s),
        t.map_or(0, port)
    )
    .into_bytes()
}

/// An offer or answer of `body`; the relay's SDP, or the error.
fn send(
    client: &UdpSocket,
    srv: SocketAddr,
    cookie: &str,
    (command, from, to): (&[u8], &[u8], Option<&[u8]>),
    body: &[u8],
    track: bool,
) -> Vec<u8> {
    let flags: &[&[u8]] = if track {
        &[b"trust-address", b"track-state"]
    } else {
        &[b"trust-address"]
    };
    let mut p = vec![
        ("command", V::S(command)),
        ("call-id", V::S(CALL)),
        ("from-tag", V::S(from)),
        ("sdp", V::S(body)),
        ("flags", V::L(flags)),
        ("endpoint-learning", V::S(b"off")),
    ];
    if let Some(t) = to {
        p.push(("to-tag", V::S(t)));
    }
    let (r, out, _) = call(client, srv, &request(cookie, &p));
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&out));
    out
}

/// `rollback` of the dialog f–t: the reply's `rolled-back`.
fn rollback(client: &UdpSocket, srv: SocketAddr, cookie: &str) -> i64 {
    let (r, why, raw) = call(
        client,
        srv,
        &request(
            cookie,
            &[
                ("command", V::S(b"rollback")),
                ("call-id", V::S(CALL)),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
            ],
        ),
    );
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&why));
    match at(reply_dict(&raw), &[b"rolled-back"]) {
        Some(Value::Int(n)) => n,
        other => panic!("{other:?}"),
    }
}

fn reaches(x: &UdpSocket, to: SocketAddr, y: &UdpSocket, seq: u16) -> bool {
    let mut buf = [0u8; 2048];
    x.send_to(&rtp(seq), to).unwrap();
    y.recv_from(&mut buf)
        .is_ok_and(|(n, _)| buf[..n] == rtp(seq)[..])
}

/// Each section's relay port (in the SDP to the other party).
fn ports(sdp: &[u8]) -> Vec<SocketAddr> {
    m_ports(sdp)
        .into_iter()
        .map(|p| SocketAddr::new("127.0.0.1".parse().unwrap(), p))
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)] // One call, step by step.
fn a_reoffer_is_rolled_back() {
    let srv = server(64_600);
    let client = endpoint();
    let (a1, a2, b1, b2) = (endpoint(), endpoint(), endpoint(), endpoint());
    let a_new = endpoint();
    for s in [&a1, &a2, &b1, &b2, &a_new] {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    let to_b = ports(&send(
        &client,
        srv.addr,
        "o1",
        (b"offer", b"f", None),
        &sdp(&a1, Some(&a2)),
        false,
    ));
    let to_a = ports(&send(
        &client,
        srv.addr,
        "a1",
        (b"answer", b"f", Some(b"t")),
        &sdp(&b1, Some(&b2)),
        false,
    ));
    std::thread::sleep(Duration::from_millis(50));
    assert!(reaches(&b1, to_b[0], &a1, 1) && reaches(&b2, to_b[1], &a2, 1));

    // Without `track-state`, nothing to roll back.
    assert_eq!(rollback(&client, srv.addr, "r0"), 0);

    // A tracked re-offer: section 1 moves to another address of A's,
    // section 2 is removed.
    let again = send(
        &client,
        srv.addr,
        "o2",
        (b"offer", b"f", Some(b"t")),
        &sdp(&a_new, None),
        true,
    );
    assert_eq!(m_ports(&again)[1], 0);
    std::thread::sleep(Duration::from_millis(50));
    assert!(reaches(&b1, to_b[0], &a_new, 2), "the re-offer is in force");
    // B rejects the re-INVITE: rolled back.
    assert_eq!(rollback(&client, srv.addr, "r1"), 1);
    std::thread::sleep(Duration::from_millis(50));
    assert!(reaches(&b1, to_b[0], &a1, 3), "A's first address again");
    assert!(reaches(&b2, to_b[1], &a2, 3), "the removed section is back");
    assert!(reaches(&a1, to_a[0], &b1, 3) && reaches(&a2, to_a[1], &b2, 3));
    // Once only.
    assert_eq!(rollback(&client, srv.addr, "r2"), 0);

    // A tracked re-offer that is answered: committed.
    send(
        &client,
        srv.addr,
        "o3",
        (b"offer", b"f", Some(b"t")),
        &sdp(&a_new, None),
        true,
    );
    send(
        &client,
        srv.addr,
        "a3",
        (b"answer", b"f", Some(b"t")),
        &sdp(&b1, None),
        false,
    );
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(rollback(&client, srv.addr, "r3"), 0);
    assert!(reaches(&b1, to_b[0], &a_new, 4));
    assert!(!reaches(&b2, to_b[1], &a2, 4), "the removed section ended");

    // Errors: no dialogue between the tags, no call.
    let err = |cookie: &str, call_id: &[u8], to: &[u8]| {
        let (r, why, _) = call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[
                    ("command", V::S(b"rollback")),
                    ("call-id", V::S(call_id)),
                    ("from-tag", V::S(b"f")),
                    ("to-tag", V::S(to)),
                ],
            ),
        );
        assert_eq!(r, "error");
        String::from_utf8(why).unwrap()
    };
    assert_eq!(err("e1", CALL, b"nobody"), "Unknown dialogue");
    assert!(err("e2", b"nope", b"t").contains("unknown call"));
}

/// The answerer re-offers (its tag first) with `track-state`; the rollback
/// names the dialog either way round and puts it back under the offerer.
#[test]
fn a_reoffer_by_the_answerer_is_rolled_back() {
    let srv = server(64_800);
    let client = endpoint();
    let (a1, a2, b1, b2, b_new) = (endpoint(), endpoint(), endpoint(), endpoint(), endpoint());
    for s in [&a1, &a2, &b1, &b2, &b_new] {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
    }
    let to_b = ports(&send(
        &client,
        srv.addr,
        "o1",
        (b"offer", b"f", None),
        &sdp(&a1, Some(&a2)),
        false,
    ));
    let to_a = ports(&send(
        &client,
        srv.addr,
        "a1",
        (b"answer", b"f", Some(b"t")),
        &sdp(&b1, Some(&b2)),
        false,
    ));
    send(
        &client,
        srv.addr,
        "o2",
        (b"offer", b"t", Some(b"f")),
        &sdp(&b_new, Some(&b2)),
        true,
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(reaches(&a1, to_a[0], &b_new, 1), "the re-offer is in force");
    assert_eq!(rollback(&client, srv.addr, "r1"), 1);
    std::thread::sleep(Duration::from_millis(50));
    assert!(reaches(&a1, to_a[0], &b1, 2), "B's first address again");
    assert!(reaches(&b1, to_b[0], &a1, 2));
    // The original offerer re-offers as before (its dialog, its ports).
    let again = ports(&send(
        &client,
        srv.addr,
        "o3",
        (b"offer", b"f", Some(b"t")),
        &sdp(&a1, Some(&a2)),
        false,
    ));
    assert_eq!(again, to_b);
}
