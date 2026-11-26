//! ZRTP (RFC 6189): the endpoints' own key agreement, multiplexed on the
//! RTP port (first octet 0x10, RFC 7983 §7). A plain relay passes it
//! through untouched and leaves `a=zrtp-hash` in the SDP; a relay that
//! terminates SRTP (or transcodes) drops it and removes `a=zrtp-hash`, so
//! the endpoints see that ZRTP is unavailable.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use std::net::UdpSocket;
use std::time::Duration;

/// A ZRTP packet: version 0x10, sequence, the "ZRTP" magic cookie, the
/// source identifier, then an opaque message ("Hello   ...") and CRC.
fn zrtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x10, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(b"ZRTP");
    p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    p.extend_from_slice(&[0x50, 0x5a, 0x00, 0x1e]);
    p.extend_from_slice(b"Hello   1.10GNU ZRTP 4.6.6 ");
    p.extend_from_slice(&[0x11; 32]);
    p
}

const HASH: &str =
    "a=zrtp-hash:1.10 fe30efd02423cb054e50efd0248742ac7a52c8f91bc2df881ae642c371ba46df\r\n";

fn plain_sdp(port: u16, session_hash: bool) -> Vec<u8> {
    let (session, media) = if session_hash { (HASH, "") } else { ("", HASH) };
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n{session}\
         m=audio {port} RTP/AVP 0\r\n{media}a=sendrecv\r\n"
    )
    .into_bytes()
}

fn no_reply(s: &UdpSocket) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 2048];
    let none = s.recv_from(&mut buf).is_err();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    none
}

#[test]
fn a_plain_call_passes_zrtp_and_its_hash_through() {
    let srv = server(50_000);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "z1",
        b"offer",
        (b"f", None),
        &plain_sdp(a.local_addr().unwrap().port(), false),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "z2",
        b"answer",
        (b"f", Some(b"t")),
        &plain_sdp(b.local_addr().unwrap().port(), true),
    );
    // The hashes reach the other side, where they were.
    let (to_b, to_a) = (
        String::from_utf8_lossy(&to_b),
        String::from_utf8_lossy(&to_a),
    );
    assert!(to_b.contains(HASH) && to_a.contains(HASH), "{to_b}\n{to_a}");
    assert!(
        to_a.find(HASH) < to_a.find("m=audio"),
        "session-level stays session-level"
    );

    let (ra, rb) = (relay_addr(to_a.as_bytes()), relay_addr(to_b.as_bytes()));
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    // ZRTP both ways, byte for byte, before and between RTP.
    for seq in 1..=3 {
        let p = zrtp(seq);
        a.send_to(&p, ra).unwrap();
        let (n, from) = b.recv_from(&mut buf).expect("A's ZRTP reaches B");
        assert_eq!((&buf[..n], from), (&p[..], rb));
        b.send_to(&p, rb).unwrap();
        let (n, from) = a.recv_from(&mut buf).expect("B's ZRTP reaches A");
        assert_eq!((&buf[..n], from), (&p[..], ra));
    }
    both_ways(&a, ra, &b, rb, 7);
}

#[test]
fn a_call_with_relay_terminated_srtp_drops_zrtp_and_its_hash() {
    let srv = server(50_200);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    // A offers SDES-SRTP, B gets plain RTP: the relay decrypts and
    // encrypts, so A's and B's ZRTP could never agree across it.
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{KEY_A_B64}\r\n{HASH}a=sendrecv\r\n",
        a.local_addr().unwrap().port()
    );
    let (result, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "y1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"zrtp-srtp")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer.as_bytes())),
                ("transport-protocol", V::S(b"RTP/AVP")),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok");
    let (result, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "y2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"zrtp-srtp")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                (
                    "sdp",
                    V::S(&plain_sdp(b.local_addr().unwrap().port(), false)),
                ),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok");
    for sdp in [&to_b, &to_a] {
        let text = String::from_utf8_lossy(sdp);
        assert!(!text.contains("zrtp-hash"), "{text}");
    }
    let (ra, rb) = (relay_addr(&to_a), relay_addr(&to_b));
    std::thread::sleep(Duration::from_millis(50));
    a.send_to(&zrtp(1), ra).unwrap();
    assert!(no_reply(&b), "A's ZRTP is not relayed");
    b.send_to(&zrtp(1), rb).unwrap();
    assert!(no_reply(&a), "B's ZRTP is not relayed");
    // RTP still flows (through the relay's SRTP on A's side): only ZRTP
    // is held back.
}
