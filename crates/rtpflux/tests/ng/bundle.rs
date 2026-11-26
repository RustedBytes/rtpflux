//! BUNDLE: a bundled offerer and an unbundled answerer, both ways.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use rtpflux_core::sdp::{MAX_MEDIA, Media};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

// ---------------------------------------------------------------- BUNDLE

/// The offerer bundles audio (PT 0) and video (PT 96) on one port; the
/// answerer has a port per section. The relay answers the offerer with one
/// port and the group, and sorts media by payload type (RTCP by sender
/// SSRC) between the shared port and the answerer's two.
#[test]
fn bundle_offerer_to_unbundled_answerer() {
    let srv = server(47_400);
    let client = endpoint();
    let (a, b_audio, b_video) = (endpoint(), endpoint(), endpoint());
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=group:BUNDLE a v\r\n\
         m=audio {} RTP/AVP 0\r\na=mid:a\r\na=rtcp-mux\r\nm=video 0 RTP/AVP 96\r\na=mid:v\r\na=bundle-only\r\na=rtcp-mux\r\n",
        a.local_addr().unwrap().port()
    );
    let flags: &[&[u8]] = &[b"trust-address"];
    let (result, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "b1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"bundle-1")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer_sdp.as_bytes())),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_b));
    let to_b = String::from_utf8(to_b).unwrap();
    assert!(
        !to_b.contains("BUNDLE") && !to_b.contains("bundle-only"),
        "{to_b}"
    );
    let ports_b: Vec<u16> = to_b
        .split("\r\n")
        .filter(|l| l.starts_with("m="))
        .map(|l| l.split(' ').nth(1).unwrap().parse().unwrap())
        .collect();
    assert!(
        ports_b[0] != 0 && ports_b[1] != 0 && ports_b[0] != ports_b[1],
        "{to_b}"
    );
    let answer_sdp = format!(
        "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\nm=video {} RTP/AVP 96\r\n",
        b_audio.local_addr().unwrap().port(),
        b_video.local_addr().unwrap().port()
    );
    let (result, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "b2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"bundle-1")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer_sdp.as_bytes())),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_a));
    let to_a = String::from_utf8(to_a).unwrap();
    assert!(to_a.contains("a=group:BUNDLE a v\r\n"), "{to_a}");
    let ports_a: Vec<u16> = to_a
        .split("\r\n")
        .filter(|l| l.starts_with("m="))
        .map(|l| l.split(' ').nth(1).unwrap().parse().unwrap())
        .collect();
    assert_eq!(ports_a[0], ports_a[1], "one port for the group: {to_a}");
    assert!(
        to_a.contains("a=mid:v\r\na=rtcp-mux") || to_a.contains("a=mid:v"),
        "{to_a}"
    );
    std::thread::sleep(Duration::from_millis(50));

    let shared = SocketAddr::new("127.0.0.1".parse().unwrap(), ports_a[0]);
    bundled_media(&a, &b_audio, &b_video, shared, &ports_b);
}

/// Media of `bundle_offerer_to_unbundled_answerer`: A on the shared port,
/// B on a port per section (`ports_b`: the relay's ports facing B).
fn bundled_media(
    a: &UdpSocket,
    b_audio: &UdpSocket,
    b_video: &UdpSocket,
    shared: SocketAddr,
    ports_b: &[u16],
) {
    let lo = |p: u16| SocketAddr::new("127.0.0.1".parse().unwrap(), p);
    let packet = |pt: u8, ssrc: u32, seq: u16| {
        let mut p = vec![0x80, pt, 0, 0, 0, 0, 0, 0];
        p[2..4].copy_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[7; 20]);
        p
    };
    let mut buf = [0u8; 2048];
    // A -> B: sorted by payload type.
    a.send_to(&packet(0, 0xA0, 1), shared).unwrap();
    a.send_to(&packet(96, 0xB0, 1), shared).unwrap();
    let (n, _) = b_audio
        .recv_from(&mut buf)
        .expect("audio to B's audio port");
    assert_eq!(buf[1], 0, "{:?}", &buf[..n]);
    let (n, _) = b_video
        .recv_from(&mut buf)
        .expect("video to B's video port");
    assert_eq!(buf[1], 96, "{:?}", &buf[..n]);
    // B -> A: both through the shared port.
    b_video
        .send_to(&packet(96, 0xC0, 1), lo(ports_b[1]))
        .unwrap();
    let (_, from) = a.recv_from(&mut buf).expect("video to A");
    assert_eq!((buf[1], from), (96, shared));
    b_audio
        .send_to(&packet(0, 0xD0, 1), lo(ports_b[0]))
        .unwrap();
    let (_, from) = a.recv_from(&mut buf).expect("audio to A");
    assert_eq!((buf[1], from), (0, shared));
    // RTCP from A's video source goes to B's video RTCP port.
    let rtcp_sock =
        UdpSocket::bind(lo(b_video.local_addr().unwrap().port() + 1)).expect("B's video RTCP port");
    rtcp_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let rr = [0x81, 201, 0, 1, 0, 0, 0, 0xB0];
    a.send_to(&rr, shared).unwrap();
    let (n, from) = rtcp_sock
        .recv_from(&mut buf)
        .expect("RTCP to B's video RTCP port");
    assert_eq!((&buf[..n], from.port()), (&rr[..], ports_b[1] + 1));
}

/// The unbundled answerer re-INVITEs the bundled offerer: the relay offers
/// the bundled party its group again on the shared port, answers the
/// re-offerer with a port per section and no group, and media is sorted as
/// before. Then the bundled party re-INVITEs, and the call ends by either
/// tag.
#[test]
fn the_unbundled_answerer_re_invites_a_bundled_offerer() {
    let srv = server(47_500);
    let client = endpoint();
    let (a, b_audio, b_video) = (endpoint(), endpoint(), endpoint());
    let port = |s: &UdpSocket| s.local_addr().unwrap().port();
    let bundled = |p: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=group:BUNDLE a v\r\n\
             m=audio {p} RTP/AVP 0\r\na=mid:a\r\na=rtcp-mux\r\nm=video {p} RTP/AVP 96\r\na=mid:v\r\na=rtcp-mux\r\n"
        )
    };
    let unbundled = format!(
        "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\nm=video {} RTP/AVP 96\r\n",
        port(&b_audio),
        port(&b_video)
    );
    let ex = |cookie: &str, command: &[u8], tags: (&[u8], Option<&[u8]>), sdp: &str| {
        exchange_sdp(&client, srv.addr, cookie, command, tags, sdp.as_bytes())
    };
    let to_b = ex("u1", b"offer", (b"f", None), &bundled(port(&a)));
    let to_a = ex("u2", b"answer", (b"f", Some(b"t")), &unbundled);
    let (ports_a, ports_b) = (m_ports(&to_a), m_ports(&to_b));
    std::thread::sleep(Duration::from_millis(50));
    let shared = SocketAddr::new("127.0.0.1".parse().unwrap(), ports_a[0]);
    bundled_media(&a, &b_audio, &b_video, shared, &ports_b);

    // B re-INVITEs: From is B, To is A.
    let reoffer = ex("u3", b"offer", (b"t", Some(b"f")), &unbundled);
    let text = String::from_utf8_lossy(&reoffer);
    assert_eq!(
        m_ports(&reoffer),
        vec![ports_a[0]; 2],
        "the shared port: {text}"
    );
    assert!(text.contains("a=group:BUNDLE a v\r\n"), "{text}");
    assert!(text.contains("a=mid:a\r\na=rtcp-mux\r\n"), "{text}");
    assert!(text.contains("a=mid:v\r\na=rtcp-mux\r\n"), "{text}");
    let reanswer = ex("u4", b"answer", (b"t", Some(b"f")), &bundled(port(&a)));
    let text = String::from_utf8_lossy(&reanswer);
    assert_eq!(m_ports(&reanswer), ports_b, "B's ports stay: {text}");
    assert!(
        !text.contains("BUNDLE") && !text.contains("a=mid") && !text.contains("rtcp-mux"),
        "B offered no BUNDLE: {text}"
    );
    std::thread::sleep(Duration::from_millis(50));
    bundled_media(&a, &b_audio, &b_video, shared, &ports_b);

    // A re-INVITEs again: the original roles.
    let to_b = ex("u5", b"offer", (b"f", Some(b"t")), &bundled(port(&a)));
    assert_eq!(m_ports(&to_b), ports_b);
    let to_a = ex("u6", b"answer", (b"f", Some(b"t")), &unbundled);
    assert_eq!(m_ports(&to_a), vec![ports_a[0]; 2]);
    assert!(String::from_utf8_lossy(&to_a).contains("a=group:BUNDLE a v\r\n"));
    std::thread::sleep(Duration::from_millis(50));
    bundled_media(&a, &b_audio, &b_video, shared, &ports_b);

    // B re-offers bundled: refused, the call stays.
    let req = request(
        "u7",
        &[
            ("command", V::S(b"offer")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(b"t")),
            ("to-tag", V::S(b"f")),
            ("sdp", V::S(bundled(port(&b_audio)).as_bytes())),
        ],
    );
    assert_eq!(call(&client, srv.addr, &req).0, "error");
    bundled_media(&a, &b_audio, &b_video, shared, &ports_b);
    let req = request(
        "u8",
        &[
            ("command", V::S(b"delete")),
            ("call-id", V::S(b"reinvite@example")),
            ("from-tag", V::S(b"t")),
        ],
    );
    assert_eq!(call(&client, srv.addr, &req).0, "ok");
}

/// SDES sections bundled: each keeps its own keys on the shared port. The
/// relay sorts by the clear header, then decrypts with that section's key,
/// and encrypts towards A with its own key for that section.
#[test]
fn bundled_sdes_sections_keep_their_keys() {
    use rtpflux_core::sdp::read_media;
    use rtpflux_srtp::{MasterKey, Protect, Suite, Unprotect};
    let srv = server(47_600);
    let client = endpoint();
    let (a, b_audio, b_video) = (endpoint(), endpoint(), endpoint());
    let (key_audio, key_video) = (
        "4fl6DT4Bi+DWT6MsBt5BOQ7Gda1Jiv7rtpYLOqvm",
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNk",
    );
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=group:BUNDLE a v\r\n\
         m=audio {p} RTP/SAVP 0\r\na=mid:a\r\na=rtcp-mux\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key_audio}\r\n\
         m=video {p} RTP/SAVP 96\r\na=mid:v\r\na=rtcp-mux\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key_video}\r\n",
        p = a.local_addr().unwrap().port()
    );
    let (to_b, to_a) = offer_answer_two_sections(
        &client,
        srv.addr,
        b"bundle-sdes",
        &offer_sdp,
        &b_audio,
        &b_video,
    );
    let mut mb = [Media::EMPTY; MAX_MEDIA];
    read_media(&to_b, &mut mb).unwrap();
    let mut ma = [Media::EMPTY; MAX_MEDIA];
    read_media(&to_a, &mut ma).unwrap();
    assert_eq!(ma[0].port, ma[1].port, "one port");
    let (relay_audio, relay_video) = (ma[0].crypto.unwrap().key, ma[1].crypto.unwrap().key);
    assert_ne!(relay_audio, relay_video, "a key per section");
    std::thread::sleep(Duration::from_millis(50));

    let shared = SocketAddr::new("127.0.0.1".parse().unwrap(), ma[0].port);
    let lo = |p: u16| SocketAddr::new("127.0.0.1".parse().unwrap(), p);
    let master = |text: &str| {
        let sdp =
            format!("m=audio 1 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{text}\r\n");
        let mut m = [Media::EMPTY; MAX_MEDIA];
        read_media(sdp.as_bytes(), &mut m).unwrap();
        m[0].crypto.unwrap().key
    };
    let (ka, kv): (MasterKey, MasterKey) = (master(key_audio), master(key_video));
    assert_eq!(ka.suite, Suite::AesCm128HmacSha1_80);
    let packet = |pt: u8, ssrc: u32| {
        let mut p = vec![0x80, pt, 0, 1, 0, 0, 0, 0];
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[5; 30]);
        p
    };
    let protect = |k: &MasterKey, p: &[u8]| {
        let mut w = p.to_vec();
        w.resize(p.len() + 10, 0);
        Protect::from_key(k).rtp(&mut w, p.len()).unwrap();
        w
    };
    let mut buf = [0u8; 2048];
    a.send_to(&protect(&ka, &packet(0, 1)), shared).unwrap();
    a.send_to(&protect(&kv, &packet(96, 2)), shared).unwrap();
    let (n, _) = b_audio
        .recv_from(&mut buf)
        .expect("audio decrypted with the audio key");
    assert_eq!(&buf[..n], &packet(0, 1)[..]);
    let (n, _) = b_video
        .recv_from(&mut buf)
        .expect("video decrypted with the video key");
    assert_eq!(&buf[..n], &packet(96, 2)[..]);
    b_video.send_to(&packet(96, 3), lo(mb[1].port)).unwrap();
    let (n, from) = a.recv_from(&mut buf).expect("video to A");
    assert_eq!(from, shared);
    let n = Unprotect::from_key(&relay_video)
        .rtp(&mut buf, n)
        .expect("under the relay's video key");
    assert_eq!(&buf[..n], &packet(96, 3)[..]);
}

/// `offer` (towards plain RTP/AVP) and a plain two-section `answer` from
/// `b_audio`/`b_video`; returns the SDPs the relay wrote towards B and A.
fn offer_answer_two_sections(
    client: &UdpSocket,
    srv: SocketAddr,
    call_id: &[u8],
    offer_sdp: &str,
    b_audio: &UdpSocket,
    b_video: &UdpSocket,
) -> (Vec<u8>, Vec<u8>) {
    let flags: &[&[u8]] = &[b"trust-address"];
    let (result, to_b, _) = call(
        client,
        srv,
        &request(
            "s1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(call_id)),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer_sdp.as_bytes())),
                ("transport-protocol", V::S(b"RTP/AVP")),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_b));
    let answer_sdp = format!(
        "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {} RTP/AVP 0\r\nm=video {} RTP/AVP 96\r\n",
        b_audio.local_addr().unwrap().port(),
        b_video.local_addr().unwrap().port()
    );
    let (result, to_a, _) = call(
        client,
        srv,
        &request(
            "s2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(call_id)),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer_sdp.as_bytes())),
                ("flags", V::L(flags)),
                ("endpoint-learning", V::S(b"off")),
            ],
        ),
    );
    assert_eq!(result, "ok", "{}", String::from_utf8_lossy(&to_a));
    (to_b, to_a)
}
