//! rtpengine's command options: `play media` from a blob, clipped and
//! repeated for a time; `delete` with a delay.

use crate::codecs::codec_call;
#[allow(clippy::wildcard_imports)]
use crate::common::*;
use crate::features::ulaw_wav;
use rtpflux_ng::bencode::Value;
use std::net::UdpSocket;
use std::time::Duration;

/// Announcement packets `a` receives until `b`'s audio gets through again.
fn announcement(a: &UdpSocket, b: &UdpSocket, for_b: std::net::SocketAddr) -> Vec<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let mut got = Vec::new();
    for seq in 0..40u16 {
        b.send_to(&rtp_with(0, 500 + seq, &[2; 160]), for_b)
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        while let Ok((n, _)) = a.recv_from(&mut buf) {
            if buf[12..n].iter().all(|&c| c == 2) {
                return got;
            }
            got.push(buf[..n].to_vec());
        }
    }
    panic!("B's audio never came back")
}

#[test]
fn play_media_from_a_blob_clipped() {
    let srv = server(56_200);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (_, _, _, for_b) = codec_call(&client, srv.addr, b"play-2", (&a, &b), ("0", "0"), &[]);
    a.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    // 100 ms of codes; from 20 ms, for 40 ms.
    let codes: Vec<u8> = (0..800u32)
        .map(|i| u8::try_from(i % 200).unwrap())
        .collect();
    let blob = ulaw_wav(&codes);
    let (result, _, raw) = call(
        &client,
        srv.addr,
        &request(
            "c1",
            &[
                ("command", V::S(b"play media")),
                ("call-id", V::S(b"play-2")),
                ("from-tag", V::S(b"f")),
                ("blob", V::S(&blob)),
                ("start-pos", V::I(20)),
                ("duration", V::I(40)),
            ],
        ),
    );
    assert_eq!(result, "ok");
    assert_eq!(at(reply_dict(&raw), &[b"duration"]), Some(Value::Int(40)));
    let got = announcement(&a, &b, for_b);
    assert_eq!(got.len(), 2, "40 ms: two packets");
    assert_eq!(&got[0][12..], &codes[160..320]);
    assert_eq!(&got[1][12..], &codes[320..480]);
}

#[test]
fn repeat_duration_cuts_the_repetitions() {
    let srv = server(56_300);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (_, _, _, for_b) = codec_call(&client, srv.addr, b"play-3", (&a, &b), ("0", "0"), &[]);
    a.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    // 50 ms (three packets, the last padded), repeated for 60 ms: the
    // second repetition never starts (whole repetitions would be six).
    let codes: Vec<u8> = (0..400u32)
        .map(|i| u8::try_from(i % 200).unwrap())
        .collect();
    let blob = ulaw_wav(&codes);
    let (result, _, raw) = call(
        &client,
        srv.addr,
        &request(
            "c2",
            &[
                ("command", V::S(b"play media")),
                ("call-id", V::S(b"play-3")),
                ("from-tag", V::S(b"f")),
                ("blob", V::S(&blob)),
                ("repeat-duration", V::I(60)),
            ],
        ),
    );
    assert_eq!(result, "ok");
    assert_eq!(at(reply_dict(&raw), &[b"duration"]), Some(Value::Int(50)));
    assert_eq!(announcement(&a, &b, for_b).len(), 3);
    // Neither a file nor a blob: refused.
    let (result, _, _) = call(
        &client,
        srv.addr,
        &request(
            "c3",
            &[
                ("command", V::S(b"play media")),
                ("call-id", V::S(b"play-3")),
                ("from-tag", V::S(b"f")),
            ],
        ),
    );
    assert_eq!(result, "error");
}

#[test]
fn delete_with_a_delay() {
    let srv = server(56_400);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let (_, _, for_a, _) = codec_call(&client, srv.addr, b"del-1", (&a, &b), ("0", "0"), &[]);
    let query = |cookie: &str| {
        call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[("command", V::S(b"query")), ("call-id", V::S(b"del-1"))],
            ),
        )
        .0
    };
    let (result, _, _) = call(
        &client,
        srv.addr,
        &request(
            "d1",
            &[
                ("command", V::S(b"delete")),
                ("call-id", V::S(b"del-1")),
                ("delete-delay", V::I(1)),
            ],
        ),
    );
    assert_eq!(result, "ok");
    // Still relayed meanwhile.
    let mut buf = [0u8; 2048];
    let p = rtp(1);
    a.send_to(&p, for_a).unwrap();
    assert!(matches!(b.recv_from(&mut buf), Ok((n, _)) if buf[..n] == p[..]));
    assert_eq!(query("d2"), "ok");
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(query("d3"), "error", "deleted once the delay is over");
    b.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    a.send_to(&rtp(2), for_a).unwrap();
    assert!(b.recv_from(&mut buf).is_err());
}

/// A `delete-delay` ends the dialogs it selected, not one made again under
/// the same Call-ID and tags meanwhile.
#[test]
fn a_delayed_delete_spares_a_dialog_made_again() {
    let srv = server(51_100);
    let client = endpoint();
    let (alice, bob) = (endpoint(), endpoint());
    codec_call(&client, srv.addr, b"del-2", (&alice, &bob), ("0", "0"), &[]);
    for (cookie, delay) in [("d1", Some(1)), ("d2", None)] {
        let mut p = vec![("command", V::S(b"delete")), ("call-id", V::S(b"del-2"))];
        if let Some(d) = delay {
            p.push(("delete-delay", V::I(d)));
        }
        assert_eq!(call(&client, srv.addr, &request(cookie, &p)).0, "ok");
    }
    // The same call again, between other endpoints.
    let (carol, dave) = (endpoint(), endpoint());
    let (_, _, for_carol, _) = codec_call(
        &client,
        srv.addr,
        b"del-2",
        (&carol, &dave),
        ("0", "0"),
        &[],
    );
    std::thread::sleep(Duration::from_millis(1_500));
    let q = request(
        "q",
        &[("command", V::S(b"query")), ("call-id", V::S(b"del-2"))],
    );
    assert_eq!(call(&client, srv.addr, &q).0, "ok", "the new dialog stays");
    let mut buf = [0u8; 2048];
    let p = rtp(1);
    carol.send_to(&p, for_carol).unwrap();
    assert!(matches!(dave.recv_from(&mut buf), Ok((n, _)) if buf[..n] == p[..]));
}
