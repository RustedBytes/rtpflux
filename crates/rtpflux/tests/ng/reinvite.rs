//! Re-INVITEs from either party, streams changed on their own, and hold.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use rtpflux_core::sdp::{MAX_MEDIA, Media, read_media};
use rtpflux_ng::bencode::Value;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[test]
fn the_answerer_re_invites_and_hangs_up() {
    let srv = server(48_200);
    let client = endpoint();
    let (a, b, b2, a2) = (endpoint(), endpoint(), endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "r1",
        b"offer",
        (b"alice", None),
        &sdp_for(port(&a)),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "r2",
        b"answer",
        (b"alice", Some(b"bob")),
        &sdp_for(port(&b)),
    );
    let (for_a, for_b) = (relay_addr(&to_a), relay_addr(&to_b));
    both_ways(&a, for_a, &b, for_b, 1);

    // Bob re-INVITEs from another port: From is Bob, To is Alice.
    let to_a2 = exchange_sdp(
        &client,
        srv.addr,
        "r3",
        b"offer",
        (b"bob", Some(b"alice")),
        &sdp_for(port(&b2)),
    );
    assert_eq!(
        relay_addr(&to_a2),
        for_a,
        "Alice keeps sending to the same port"
    );
    let to_b2 = exchange_sdp(
        &client,
        srv.addr,
        "r4",
        b"answer",
        (b"bob", Some(b"alice")),
        &sdp_for(port(&a2)),
    );
    assert_eq!(
        relay_addr(&to_b2),
        for_b,
        "Bob keeps sending to the same port"
    );
    // Media follows both new addresses through the same relay ports.
    both_ways(&a2, for_a, &b2, for_b, 2);

    // Alice re-INVITEs again (the original direction): still the same call.
    let to_b3 = exchange_sdp(
        &client,
        srv.addr,
        "r5",
        b"offer",
        (b"alice", Some(b"bob")),
        &sdp_for(port(&a)),
    );
    assert_eq!(relay_addr(&to_b3), for_b);
    let to_a3 = exchange_sdp(
        &client,
        srv.addr,
        "r6",
        b"answer",
        (b"alice", Some(b"bob")),
        &sdp_for(port(&b)),
    );
    assert_eq!(relay_addr(&to_a3), for_a);
    both_ways(&a, for_a, &b, for_b, 3);

    query_and_delete_by_the_answerers_tag(&client, srv.addr);
}

/// `query` by Bob's tag finds the dialog (each tag's stream counts its own
/// 3 packets) and `delete` by it ends the dialog.
fn query_and_delete_by_the_answerers_tag(client: &UdpSocket, srv: SocketAddr) {
    let ask = |cookie: &str, command: &[u8], tag: &[u8]| {
        call(
            client,
            srv,
            &request(
                cookie,
                &[
                    ("command", V::S(command)),
                    ("call-id", V::S(b"reinvite@example")),
                    ("from-tag", V::S(tag)),
                ],
            ),
        )
    };
    let (q, _, raw) = ask("r7", b"query", b"bob");
    assert_eq!(q, "ok");
    let packets = |tag: &[u8]| match at(
        reply_dict(&raw),
        &[
            b"tags", tag, b"medias", b"0", b"streams", b"0", b"stats", b"packets",
        ],
    ) {
        Some(Value::Int(n)) => n,
        other => panic!("no packet count for the tag: {other:?}"),
    };
    assert_eq!((packets(b"alice"), packets(b"bob")), (3, 3));
    assert_eq!(ask("r8", b"delete", b"bob").0, "ok");
    // The dialog is gone: deleting it again deletes nothing (`ok` with a
    // warning, as rtpengine).
    let (r, _, raw) = ask("r9", b"delete", b"alice");
    assert_eq!(r, "ok");
    assert!(
        String::from_utf8_lossy(&raw).contains("tags didn't match"),
        "the dialog is gone"
    );
}

#[test]
fn a_stream_is_disabled_and_added_back_without_touching_the_others() {
    let srv = server(48_400);
    let client = endpoint();
    let (a_audio, a_video, b_audio, b_video) = (endpoint(), endpoint(), endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let two = |audio: u16, video: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {audio} RTP/AVP 0\r\nm=video {video} RTP/AVP 96\r\n"
        )
        .into_bytes()
    };
    let media = |sdp: &[u8]| {
        let mut m = [Media::EMPTY; MAX_MEDIA];
        let n = read_media(sdp, &mut m).unwrap();
        (n, m[0].port, m[1].port)
    };
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "v1",
        b"offer",
        (b"f", None),
        &two(port(&a_audio), port(&a_video)),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "v2",
        b"answer",
        (b"f", Some(b"t")),
        &two(port(&b_audio), port(&b_video)),
    );
    let (_, ab, vb) = media(&to_b);
    let (_, aa, va) = media(&to_a);
    let lo = |p: u16| SocketAddr::new("127.0.0.1".parse().unwrap(), p);
    both_ways(&a_audio, lo(aa), &b_audio, lo(ab), 1);
    both_ways(&a_video, lo(va), &b_video, lo(vb), 1);

    // Video off (port 0): audio keeps its ports and flows on.
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "v3",
        b"offer",
        (b"f", Some(b"t")),
        &two(port(&a_audio), 0),
    );
    assert_eq!(media(&to_b), (2, ab, 0));
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "v4",
        b"answer",
        (b"f", Some(b"t")),
        &two(port(&b_audio), 0),
    );
    assert_eq!(media(&to_a), (2, aa, 0));
    both_ways(&a_audio, lo(aa), &b_audio, lo(ab), 2);
    a_video.send_to(&rtp(9), lo(va)).unwrap();
    b_video
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 2048];
    assert!(
        b_video.recv_from(&mut buf).is_err(),
        "the disabled stream relays nothing"
    );
    b_video
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Video back: a new call for it, audio still untouched.
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "v5",
        b"offer",
        (b"f", Some(b"t")),
        &two(port(&a_audio), port(&a_video)),
    );
    let (_, ab2, vb2) = media(&to_b);
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "v6",
        b"answer",
        (b"f", Some(b"t")),
        &two(port(&b_audio), port(&b_video)),
    );
    let (_, aa2, va2) = media(&to_a);
    assert_eq!((ab2, aa2), (ab, aa));
    assert!(vb2 != 0 && va2 != 0);
    both_ways(&a_audio, lo(aa), &b_audio, lo(ab), 3);
    both_ways(&a_video, lo(va2), &b_video, lo(vb2), 3);
}

#[test]
fn hold_with_an_unspecified_address_and_resume() {
    let srv = server(48_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "h1",
        b"offer",
        (b"f", None),
        &sdp_for(port(&a)),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "h2",
        b"answer",
        (b"f", Some(b"t")),
        &sdp_for(port(&b)),
    );
    let (for_a, for_b) = (relay_addr(&to_a), relay_addr(&to_b));
    both_ways(&a, for_a, &b, for_b, 1);

    // RFC 3264 §8.4 (and RFC 2543's c=0.0.0.0): A puts B on hold.
    let hold = format!(
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=sendonly\r\n",
        port(&a)
    );
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "h3",
        b"offer",
        (b"f", Some(b"t")),
        hold.as_bytes(),
    );
    let text = String::from_utf8_lossy(&to_b).into_owned();
    assert!(
        text.contains("a=sendonly\r\n"),
        "the direction passes: {text}"
    );
    assert_eq!(relay_addr(&to_b), for_b, "same port while on hold");
    let answer = format!(
        "v=0\r\no=- 2 3 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=recvonly\r\n",
        port(&b)
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "h4",
        b"answer",
        (b"f", Some(b"t")),
        answer.as_bytes(),
    );
    assert!(String::from_utf8_lossy(&to_a).contains("a=recvonly\r\n"));
    // Music on hold still reaches B; nothing goes to A's unspecified address.
    let mut buf = [0u8; 2048];
    a.send_to(&rtp(2), for_a).unwrap();
    let (n, _) = b.recv_from(&mut buf).expect("A -> B on hold");
    assert_eq!(&buf[..n], &rtp(2)[..]);
    b.send_to(&rtp(3), for_b).unwrap();
    a.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(a.recv_from(&mut buf).is_err(), "nothing towards 0.0.0.0");
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    // Resume: same ports, both ways again.
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "h5",
        b"offer",
        (b"f", Some(b"t")),
        &sdp_for(port(&a)),
    );
    assert_eq!(relay_addr(&to_b), for_b);
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "h6",
        b"answer",
        (b"f", Some(b"t")),
        &sdp_for(port(&b)),
    );
    assert_eq!(relay_addr(&to_a), for_a);
    both_ways(&a, for_a, &b, for_b, 4);
}

/// A re-INVITE that cannot be served (here: an SRTP section without a
/// usable key) is refused, and the call goes on as it was: same ports,
/// same roles, media both ways.
#[test]
fn a_failed_re_invite_leaves_the_call_as_it_was() {
    let srv = server(46_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "f1",
        b"offer",
        (b"alice", None),
        &sdp_for(port(&a)),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "f2",
        b"answer",
        (b"alice", Some(b"bob")),
        &sdp_for(port(&b)),
    );
    let (for_a, for_b) = (relay_addr(&to_a), relay_addr(&to_b));
    both_ways(&a, for_a, &b, for_b, 1);
    // A second, new section is added before the bad one, so the failure
    // comes after a relay call was already made for it.
    let bad = format!(
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\nm=audio 6000 RTP/AVP 0\r\nm=audio 6002 RTP/SAVP 0\r\n",
        port(&a)
    );
    for (cookie, from, to) in [
        ("f3", &b"alice"[..], Some(&b"bob"[..])),
        ("f4", b"bob", Some(b"alice")),
    ] {
        let mut pairs = vec![
            ("command", V::S(b"offer")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(from)),
            ("sdp", V::S(bad.as_bytes())),
            ("flags", V::L(&[b"trust-address"])),
            ("endpoint-learning", V::S(b"off")),
        ];
        if let Some(t) = to {
            pairs.push(("to-tag", V::S(t)));
        }
        let (result, _, _) = call(&client, srv.addr, &request(cookie, &pairs));
        assert_eq!(
            result,
            "error",
            "re-offer from {}",
            String::from_utf8_lossy(from)
        );
        both_ways(&a, for_a, &b, for_b, 2);
    }
    // The roles are Alice's still: her re-offer is a re-offer of the call.
    let again = exchange_sdp(
        &client,
        srv.addr,
        "f5",
        b"offer",
        (b"alice", Some(b"bob")),
        &sdp_for(port(&a)),
    );
    assert_eq!(
        relay_addr(&again),
        for_b,
        "Bob keeps sending to the same port"
    );
}
