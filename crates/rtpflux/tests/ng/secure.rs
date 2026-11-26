//! SRTP (SDES), ICE-lite and DTLS-SRTP: bridging secure and plain sides.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// An SRTP offerer (SDES, tag 5) and a plain-RTP answerer: the relay
/// answers A in RTP/SAVP with its own key under tag 5, offers B RTP/AVP
/// without keys, and converts the media both ways.
#[test]
fn sdes_offerer_bridged_to_plain_answerer() {
    use rtpflux_srtp::{MasterKey, Protect, Suite, Unprotect};
    let srv = server(45_600);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/SAVP 0\r\na=crypto:5 AES_CM_128_HMAC_SHA1_32 inline:{KEY_A_B64}\r\na=sendrecv\r\n",
        a.local_addr().unwrap().port()
    );
    let (result, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "s1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"srtp-1")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer_sdp.as_bytes())),
                ("transport-protocol", V::S(b"RTP/AVP")),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_b));
    let to_b_text = String::from_utf8_lossy(&to_b);
    assert!(to_b_text.contains(" RTP/AVP 0\r\n"), "{to_b_text}");
    assert!(!to_b_text.contains("a=crypto"), "{to_b_text}");
    let relay_for_b = first_media(&to_b);

    let (result, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "s2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"srtp-1")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(&sdp_for(b.local_addr().unwrap().port()))),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_a));
    let relay_for_a = first_media(&to_a);
    assert_eq!(relay_for_a.transport, rtpflux_core::sdp::Transport::Savp);
    let relay_key = relay_for_a.crypto.expect("the relay's key for A");
    assert_eq!(relay_key.tag, 5, "the accepted tag is echoed");
    assert_eq!(
        relay_key.key.suite,
        Suite::AesCm128HmacSha1_32,
        "and its suite"
    );
    assert_ne!(
        relay_key.key.bytes(),
        &KEY_A[..],
        "the relay uses its own key"
    );
    std::thread::sleep(Duration::from_millis(50));

    let to_relay_a = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_for_a.port);
    let to_relay_b = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_for_b.port);
    let mut a_tx = Protect::from_key(&MasterKey::new(Suite::AesCm128HmacSha1_32, &KEY_A).unwrap());
    let mut a_rx = Unprotect::from_key(&relay_key.key);
    let mut buf = [0u8; 2048];
    for seq in 0..5 {
        let plain = rtp(seq);
        let mut wire = plain.clone();
        wire.resize(plain.len() + 4, 0);
        a_tx.rtp(&mut wire, plain.len()).unwrap();
        a.send_to(&wire, to_relay_a).unwrap();
        let (n, _) = b.recv_from(&mut buf).expect("B gets RTP");
        assert_eq!(&buf[..n], &plain[..]);
        b.send_to(&plain, to_relay_b).unwrap();
        let (n, _) = a.recv_from(&mut buf).expect("A gets SRTP");
        let n = a_rx.rtp(&mut buf, n).expect("under the announced key");
        assert_eq!(&buf[..n], &plain[..]);
    }

    // SRTP without a usable key is refused.
    let bad = offer_sdp.replace(KEY_A_B64, "short");
    let (result, reason, _) = call(
        &client,
        srv.addr,
        &request(
            "s3",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"srtp-2")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(bad.as_bytes())),
            ],
        ),
    );
    assert_eq!(result, "error");
    assert!(String::from_utf8_lossy(&reason).contains("a=crypto"));
}

/// An ICE offerer with rtcp-mux, `ICE-lite=both`: the relay presents itself
/// as ICE-lite to both sides (its own credentials and host candidates, the
/// peer's candidates removed) and passes rtcp-mux through; once the answer
/// accepts it, the offerer gets a single candidate.
#[test]
fn ice_lite_and_rtcp_mux_in_the_sdp() {
    let srv = server(46_000);
    let client = endpoint();
    let offer_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
        a=ice-options:trickle\r\nm=audio 5000 RTP/AVP 0\r\na=ice-ufrag:peer\r\na=ice-pwd:peerpasswordpeerpassword\r\n\
        a=candidate:9 1 UDP 2113937151 192.168.1.5 5000 typ host\r\na=rtcp-mux\r\na=sendrecv\r\n";
    let offer = |cookie: &str, call: &[u8], ice: Option<&[u8]>| {
        let mut pairs = vec![
            ("command", V::S(b"offer")),
            ("call-id", V::S(call)),
            ("from-tag", V::S(b"f")),
            ("sdp", V::S(offer_sdp.as_bytes())),
            ("ICE-lite", V::S(b"both")),
        ];
        if let Some(i) = ice {
            pairs.push(("ICE", V::S(i)));
        }
        request(cookie, &pairs)
    };
    let (result, to_b, _) = call(&client, srv.addr, &offer("i1", b"ice-1", None));
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_b));
    let to_b = String::from_utf8(to_b).unwrap();
    let relay_b = first_media(to_b.as_bytes());
    assert!(to_b.find("a=ice-lite\r\n") < to_b.find("m=audio"), "{to_b}");
    assert!(
        !to_b.contains("peer") && !to_b.contains("192.168.1.5") && !to_b.contains("trickle"),
        "{to_b}"
    );
    assert!(to_b.contains(&format!(
        "a=candidate:1 1 UDP 2130706431 127.0.0.1 {} typ host\r\n",
        relay_b.port
    )));
    assert!(to_b.contains(&format!(
        "a=candidate:1 2 UDP 2130706430 127.0.0.1 {} typ host\r\n",
        relay_b.port + 1
    )));
    assert!(to_b.contains("a=end-of-candidates\r\n") && to_b.contains("a=rtcp-mux\r\n"));
    let ufrag = to_b
        .split("a=ice-ufrag:")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap();
    let pwd = to_b
        .split("a=ice-pwd:")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap();
    assert_eq!((ufrag.len(), pwd.len()), (8, 24));

    let answer_sdp = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
        m=audio 6000 RTP/AVP 0\r\na=rtcp-mux\r\na=sendrecv\r\n";
    let (result, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "i2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"ice-1")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer_sdp.as_bytes())),
            ],
        ),
    );
    assert_eq!(result, "ok");
    let to_a = String::from_utf8(to_a).unwrap();
    let relay_a = first_media(to_a.as_bytes());
    assert!(
        to_a.contains("a=ice-lite\r\n") && to_a.contains("a=rtcp-mux\r\n"),
        "{to_a}"
    );
    assert!(to_a.contains(&format!(
        "a=candidate:1 1 UDP 2130706431 127.0.0.1 {} typ host\r\n",
        relay_a.port
    )));
    assert!(
        !to_a.contains("a=candidate:1 2 "),
        "muxed: no RTCP candidate\n{to_a}"
    );
    let ufrag_a = to_a
        .split("a=ice-ufrag:")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap();
    assert_ne!(ufrag_a, ufrag, "each side has its own credentials");

    // ICE=remove: no ICE at all.
    let (_, plain, _) = call(&client, srv.addr, &offer("i3", b"ice-2", Some(b"remove")));
    let plain = String::from_utf8(plain).unwrap();
    assert!(
        !plain.contains("ice") && !plain.contains("candidate"),
        "{plain}"
    );
}

/// Drive a DTLS association against `to` until keyed.
pub(crate) fn dtls_handshake(
    sock: &UdpSocket,
    to: SocketAddr,
    assoc: &mut rtpflux::dtls::Association,
) -> (rtpflux_srtp::MasterKey, rtpflux_srtp::MasterKey) {
    use rtpflux::dtls::Progress;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 4096];
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    loop {
        for d in assoc.take_output() {
            sock.send_to(&d, to).unwrap();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "handshake did not finish"
        );
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            match assoc.receive(&buf[..n]) {
                Progress::Keyed { inbound, outbound } => {
                    for d in assoc.take_output() {
                        sock.send_to(&d, to).unwrap();
                    }
                    return (inbound, outbound);
                }
                Progress::Failed => panic!("handshake failed"),
                Progress::Pending => {}
            }
        }
    }
}

/// SRTP from `secure` reaches `plain` decrypted, and back encrypted.
pub(crate) fn srtp_both_ways(
    secure: &UdpSocket,
    to_relay_secure: SocketAddr,
    plain: &UdpSocket,
    to_relay_plain: SocketAddr,
    keys: (rtpflux_srtp::MasterKey, rtpflux_srtp::MasterKey),
) {
    use rtpflux_srtp::{Protect, Unprotect};
    let (mut tx, mut rx) = (Protect::from_key(&keys.1), Unprotect::from_key(&keys.0));
    secure
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 2048];
    for seq in 0..5 {
        let p = rtp(seq);
        let mut wire = p.clone();
        wire.resize(p.len() + rtpflux_srtp::MAX_RTP_TAG, 0);
        tx.rtp(&mut wire, p.len()).unwrap();
        secure.send_to(&wire, to_relay_secure).unwrap();
        let (n, _) = plain.recv_from(&mut buf).expect("plain side gets RTP");
        assert_eq!(&buf[..n], &p[..]);
        plain.send_to(&p, to_relay_plain).unwrap();
        let (n, _) = secure.recv_from(&mut buf).expect("secure side gets SRTP");
        let n = rx.rtp(&mut buf, n).expect("under the DTLS keys");
        assert_eq!(&buf[..n], &p[..]);
    }
}

/// A WebRTC-style offerer (DTLS-SRTP, actpass) bridged to a plain-RTP
/// answerer: the relay answers `passive` with its own fingerprint, serves
/// the offerer's handshake, and converts the media.
#[test]
fn dtls_offerer_bridged_to_plain_answerer() {
    use rtpflux::dtls::{Association, Identity};
    use rtpflux_core::dtls::{Fingerprint, Role};
    let srv = server(46_800);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let peer = Identity::generate().unwrap();
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=fingerprint:{}\r\n\
         m=audio {} UDP/TLS/RTP/SAVPF 0\r\na=setup:actpass\r\na=rtcp-mux\r\na=sendrecv\r\n",
        peer.fingerprint(),
        a.local_addr().unwrap().port()
    );
    let (result, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "d1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"dtls-1")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer_sdp.as_bytes())),
                ("transport-protocol", V::S(b"RTP/AVP")),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_b));
    let to_b = String::from_utf8(to_b).unwrap();
    assert!(
        to_b.contains(" RTP/AVP 0\r\n") && !to_b.contains("fingerprint") && !to_b.contains("setup"),
        "{to_b}"
    );
    let relay_b = first_media(to_b.as_bytes());
    let (result, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "d2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"dtls-1")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(&sdp_for(b.local_addr().unwrap().port()))),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_a));
    let to_a = String::from_utf8(to_a).unwrap();
    assert!(to_a.contains(" UDP/TLS/RTP/SAVPF 0\r\n"), "{to_a}");
    assert_eq!(sdp_line(&to_a, "a=setup:"), Some("passive"));
    let relay_fp = sdp_line(&to_a, "a=fingerprint:").expect("the relay's fingerprint");
    assert_ne!(relay_fp, peer.fingerprint());
    let relay_a = first_media(to_a.as_bytes());
    let to_relay_a = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_a.port);
    let to_relay_b = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_b.port);
    let mut dtls = Association::new(
        &peer,
        Role::Client,
        [Fingerprint::parse(relay_fp.as_bytes()), None],
    )
    .unwrap();
    let keys = dtls_handshake(&a, to_relay_a, &mut dtls);
    std::thread::sleep(Duration::from_millis(20));
    srtp_both_ways(&a, to_relay_a, &b, to_relay_b, keys);
}

/// A plain offerer bridged to a DTLS-SRTP answerer that answers `passive`:
/// the relay becomes the DTLS client towards it.
#[test]
fn plain_offerer_bridged_to_passive_dtls_answerer() {
    use rtpflux::dtls::{Association, Identity};
    use rtpflux_core::dtls::{Fingerprint, Role};
    let srv = server(47_000);
    let client = endpoint();
    let (a, b) = (endpoint(), endpoint());
    let peer = Identity::generate().unwrap();
    let (result, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "e1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"dtls-2")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(&sdp_for(a.local_addr().unwrap().port()))),
                ("transport-protocol", V::S(b"UDP/TLS/RTP/SAVP")),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_b));
    let to_b = String::from_utf8(to_b).unwrap();
    assert!(to_b.contains(" UDP/TLS/RTP/SAVP 0\r\n"), "{to_b}");
    assert_eq!(sdp_line(&to_b, "a=setup:"), Some("actpass"));
    let relay_fp = sdp_line(&to_b, "a=fingerprint:")
        .expect("the relay's fingerprint")
        .to_owned();
    let relay_b = first_media(to_b.as_bytes());
    let mut dtls = Association::new(
        &peer,
        Role::Server,
        [Fingerprint::parse(relay_fp.as_bytes()), None],
    )
    .unwrap();
    let answer_sdp = format!(
        "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} UDP/TLS/RTP/SAVP 0\r\na=setup:passive\r\na=fingerprint:{}\r\na=sendrecv\r\n",
        b.local_addr().unwrap().port(),
        peer.fingerprint()
    );
    let (result, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "e2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"dtls-2")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer_sdp.as_bytes())),
                ("flags", V::L(&[b"trust-address"])),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_a));
    let to_a = String::from_utf8(to_a).unwrap();
    assert!(
        to_a.contains(" RTP/AVP 0\r\n") && !to_a.contains("fingerprint"),
        "{to_a}"
    );
    let relay_a = first_media(to_a.as_bytes());
    let to_relay_b = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_b.port);
    let to_relay_a = SocketAddr::new("127.0.0.1".parse().unwrap(), relay_a.port);
    // The relay starts the handshake towards B.
    let keys = dtls_handshake(&b, to_relay_b, &mut dtls);
    std::thread::sleep(Duration::from_millis(20));
    srtp_both_ways(&b, to_relay_b, &a, to_relay_a, keys);
}
