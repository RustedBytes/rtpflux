//! T.38 fax (ITU-T T.38 over UDPTL, `m=image <port> udptl t38`): the relay
//! carries it like any other stream, packet for packet. UDPTL packets start
//! with a 16-bit sequence number, so their first octet is anything: they
//! are not demultiplexed as STUN, DTLS, ZRTP or RTP.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use std::time::Duration;

fn sdp(audio: u16, image: u16) -> Vec<u8> {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {audio} RTP/AVP 0\r\na=sendrecv\r\n\
         m=image {image} udptl t38\r\na=T38FaxVersion:0\r\na=T38MaxBitRate:14400\r\n\
         a=T38FaxRateManagement:transferredTCF\r\na=T38FaxMaxDatagram:400\r\na=T38FaxUdpEC:t38UDPRedundancy\r\n"
    )
    .into_bytes()
}

/// A UDPTL packet (T.38 Annex A): sequence number, then an IFP packet (a
/// T.30 indicator here) and an empty redundancy list.
fn udptl(seq: u16) -> Vec<u8> {
    let mut p = seq.to_be_bytes().to_vec();
    p.extend_from_slice(&[0x02, 0x00, 0x10, 0x00, 0x00]);
    p
}

#[test]
fn t38_streams_are_relayed_packet_for_packet() {
    let srv = server(50_600);
    let client = endpoint();
    let (a_audio, a_fax, b_audio, b_fax) = (endpoint(), endpoint(), endpoint(), endpoint());
    let port = |s: &std::net::UdpSocket| s.local_addr().unwrap().port();
    let to_b = exchange_sdp(
        &client,
        srv.addr,
        "t1",
        b"offer",
        (b"f", None),
        &sdp(port(&a_audio), port(&a_fax)),
    );
    let to_a = exchange_sdp(
        &client,
        srv.addr,
        "t2",
        b"answer",
        (b"f", Some(b"t")),
        &sdp(port(&b_audio), port(&b_fax)),
    );
    let (to_b, to_a) = (
        String::from_utf8_lossy(&to_b),
        String::from_utf8_lossy(&to_a),
    );
    // The image sections are rewritten like the audio ones, attributes kept.
    for s in [&to_b, &to_a] {
        assert!(
            s.contains(" udptl t38\r\n") && s.contains("a=T38FaxUdpEC:t38UDPRedundancy\r\n"),
            "{s}"
        );
    }
    let image_port = |s: &str| -> u16 {
        s.lines()
            .find(|l| l.starts_with("m=image "))
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    };
    let relay = |p: u16| std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), p);
    let (for_a, for_b) = (relay(image_port(&to_a)), relay(image_port(&to_b)));
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    // Sequence numbers whose first octet would read as STUN (0), ZRTP (16),
    // DTLS (22), RTP (128): all are relayed untouched.
    for seq in [0u16, 1, 0x1000, 0x1600, 0x8000, 0xffff] {
        let p = udptl(seq);
        a_fax.send_to(&p, for_a).unwrap();
        let (n, from) = b_fax.recv_from(&mut buf).expect("A's T.38 reaches B");
        assert_eq!((&buf[..n], from), (&p[..], for_b), "seq {seq}");
        b_fax.send_to(&p, for_b).unwrap();
        let (n, from) = a_fax.recv_from(&mut buf).expect("B's T.38 reaches A");
        assert_eq!((&buf[..n], from), (&p[..], for_a), "seq {seq}");
    }
}
