//! The relay end to end on loopback: real sockets, real worker threads.

#[path = "support/logging.rs"]
mod logging;

use rtpflux::config::Config;
use rtpflux::relay::{
    CallLeg, CallPorts, IceCreds, Inbound, InterfaceId, MasterKey, Relay, Side, Srtp,
};
use rtpflux_core::latch::Learning;
use rtpflux_core::sdp::Suite;
use rtpflux_srtp::MAX_MASTER_LEN;
use rtpflux_srtp::{Protect, Unprotect};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// A config on loopback with a port range of its own per test.
fn relay(first_port: u16, pairs: u16, timeout_s: u64) -> Relay {
    logging::init();
    let toml = format!(
        r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {first_port}
        max = {max}
        [sessions]
        max = {max_calls}
        timeout = {timeout_s}
        silent_timeout = {timeout_s}
        [runtime]
        workers = 2
        batch = 16
        "#,
        max = first_port + 2 * pairs - 1,
        max_calls = pairs / 2,
    );
    Relay::start(&Config::from_toml(&toml).expect("valid test config")).expect("relay starts")
}

fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}

fn side(rtp: Option<SocketAddr>, learning: Learning, strict: bool) -> Side {
    Side {
        interface: InterfaceId::new(0),
        rtp,
        rtcp: None,
        learning,
        strict_source: strict,
        handover: false,
        unidirectional: false,
        srtp: Srtp::default(),
        rtcp_mux: false,
        ice: None,
        dtls: None,
        dtmf: None,
        transcode: None,
        opaque: false,
        dtmf_xcode: None,
        repack: None,
    }
}

fn rtp_packet(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 160, 0xde, 0xad, 0xbe, 0xef]);
    p.extend(std::iter::repeat_n(0x55, 160));
    p
}

fn recv(s: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; 2048];
    s.recv_from(&mut buf)
        .ok()
        .map(|(n, from)| (buf[..n].to_vec(), from))
}

fn call(
    r: &mut Relay,
    a: &UdpSocket,
    b: &UdpSocket,
    learning: Learning,
    strict: bool,
) -> CallPorts {
    r.create_call(
        side(Some(a.local_addr().unwrap()), learning, strict),
        side(Some(b.local_addr().unwrap()), learning, strict),
    )
    .unwrap()
}

#[test]
fn relays_both_directions_unchanged() {
    let mut r = relay(42_000, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let ports = call(&mut r, &a, &b, Learning::Off, false);
    std::thread::sleep(Duration::from_millis(50)); // let the worker install the call

    let pkt = rtp_packet(1);
    a.send_to(&pkt, ports.a).unwrap();
    let (got, from) = recv(&b).expect("B receives A's packet");
    assert_eq!(got, pkt, "payload relayed unchanged");
    assert_eq!(from, ports.b, "sent from the relay's port facing B");

    let pkt = rtp_packet(2);
    b.send_to(&pkt, ports.b).unwrap();
    let (got, from) = recv(&a).expect("A receives B's packet");
    assert_eq!(got, pkt);
    assert_eq!(from, ports.a);
    assert_eq!(r.totals().forwarded, 2);
}

#[test]
fn rtcp_is_relayed_on_the_odd_port() {
    let mut r = relay(42_200, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let (a_rtcp, b_rtcp) = (endpoint(), endpoint());
    let ports = r
        .create_call(
            Side {
                rtcp: Some(a_rtcp.local_addr().unwrap()),
                ..side(Some(a.local_addr().unwrap()), Learning::Off, false)
            },
            Side {
                rtcp: Some(b_rtcp.local_addr().unwrap()),
                ..side(Some(b.local_addr().unwrap()), Learning::Off, false)
            },
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let rr = [0x81, 201, 0, 1, 0, 0, 0, 7];
    let a_rtcp_port = SocketAddr::new(ports.a.ip(), ports.a.port() + 1);
    a_rtcp.send_to(&rr, a_rtcp_port).unwrap();
    let (got, from) = recv(&b_rtcp).expect("RTCP relayed");
    assert_eq!(got, rr);
    assert_eq!(from.port(), ports.b.port() + 1);
}

#[test]
fn latches_onto_the_real_source() {
    let mut r = relay(42_400, 32, 60);
    let (a_sdp, a_real, b) = (endpoint(), endpoint(), endpoint());
    // A's SDP names one address, but A actually sends from another (a NAT).
    let ports = call(&mut r, &a_sdp, &b, Learning::Immediate, false);
    std::thread::sleep(Duration::from_millis(50));
    a_real.send_to(&rtp_packet(1), ports.a).unwrap();
    assert!(recv(&b).is_some());
    b.send_to(&rtp_packet(2), ports.b).unwrap();
    let (_, from) = recv(&a_real).expect("the return path follows the latched source");
    assert_eq!(from, ports.a);
}

#[test]
fn strict_source_drops_strangers() {
    let mut r = relay(42_600, 32, 60);
    let (a, b, stranger) = (endpoint(), endpoint(), endpoint());
    let ports = call(&mut r, &a, &b, Learning::Off, true);
    std::thread::sleep(Duration::from_millis(50));
    stranger.send_to(&rtp_packet(1), ports.a).unwrap();
    b.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(
        recv(&b).is_none(),
        "a packet from an unexpected source is not relayed"
    );
    a.send_to(&rtp_packet(2), ports.a).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert!(recv(&b).is_some());
    let t = r.totals();
    assert_eq!((t.forwarded, t.dropped), (1, 1));
}

#[test]
fn bursts_are_relayed_in_batches_and_in_order() {
    let mut r = relay(42_800, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let ports = call(&mut r, &a, &b, Learning::Off, false);
    std::thread::sleep(Duration::from_millis(50));
    for seq in 0..200u16 {
        a.send_to(&rtp_packet(seq), ports.a).unwrap();
    }
    for seq in 0..200u16 {
        let (got, _) = recv(&b).unwrap_or_else(|| panic!("packet {seq} lost"));
        assert_eq!(u16::from_be_bytes([got[2], got[3]]), seq);
    }
}

#[test]
fn deleted_calls_stop_and_their_ports_are_reused() {
    // 4 pairs, 2 workers: each shard holds one call.
    let mut r = relay(43_000, 4, 60);
    let (a, b) = (endpoint(), endpoint());
    let first = call(&mut r, &a, &b, Learning::Off, false);
    let second = call(&mut r, &a, &b, Learning::Off, false);
    assert!(
        r.create_call(
            side(None, Learning::Off, false),
            side(None, Learning::Off, false)
        )
        .is_err(),
        "ports exhausted"
    );
    assert!(r.delete_call(first.id).unwrap());
    assert!(!r.delete_call(first.id).unwrap(), "already ending");
    // The ports come back once the worker has closed the sockets.
    let deadline = Instant::now() + Duration::from_secs(2);
    let third = loop {
        match r.create_call(
            side(None, Learning::Off, false),
            side(None, Learning::Off, false),
        ) {
            Ok(c) => break c,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("ports not reused: {e}"),
        }
    };
    assert_ne!(third.id, first.id);
    assert_eq!(r.totals().active_calls, 2);
    let _ = second;
}

#[test]
fn idle_calls_time_out() {
    let mut r = relay(43_200, 8, 1);
    let (a, b) = (endpoint(), endpoint());
    let _ports = call(&mut r, &a, &b, Learning::Off, false);
    let deadline = Instant::now() + Duration::from_secs(5);
    while r.totals().calls_ended == 0 {
        assert!(Instant::now() < deadline, "call did not time out");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(r.totals().active_calls, 0);
}

// ---------------------------------------------------------------- SRTP

fn key(fill: u8, suite: Suite) -> MasterKey {
    MasterKey::new(suite, &[fill; MAX_MASTER_LEN][..suite.master_len()]).unwrap()
}

fn protect(p: &mut Protect, plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    buf.resize(plain.len() + 16, 0);
    let n = p.rtp(&mut buf, plain.len()).unwrap();
    buf.truncate(n);
    buf
}

fn unprotect(u: &mut Unprotect, wire: &[u8]) -> Vec<u8> {
    let mut buf = wire.to_vec();
    let n = u.rtp(&mut buf, wire.len()).expect("authentic SRTP");
    buf.truncate(n);
    buf
}

/// SRTP side A (sends with `ka`, receives with `ra`) and plain side B.
fn srtp_call(
    r: &mut Relay,
    a: &UdpSocket,
    b: &UdpSocket,
    ka: MasterKey,
    ra: MasterKey,
) -> CallPorts {
    r.create_call(
        Side {
            srtp: Srtp {
                inbound: Inbound::Key(ka),
                outbound: Some(ra),
            },
            ..side(Some(a.local_addr().unwrap()), Learning::Immediate, false)
        },
        side(Some(b.local_addr().unwrap()), Learning::Immediate, false),
    )
    .unwrap()
}

#[test]
fn bridges_srtp_and_rtp_both_ways() {
    let mut r = relay(44_000, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let (ka, ra) = (
        key(1, Suite::AesCm128HmacSha1_80),
        key(2, Suite::AesCm128HmacSha1_32),
    );
    let ports = srtp_call(&mut r, &a, &b, ka, ra);
    std::thread::sleep(Duration::from_millis(50));
    let (mut a_tx, mut a_rx) = (Protect::from_key(&ka), Unprotect::from_key(&ra));
    for seq in 0..20u16 {
        // A → B: decrypted by the relay.
        let plain = rtp_packet(seq);
        a.send_to(&protect(&mut a_tx, &plain), ports.a).unwrap();
        let (got, _) = recv(&b).expect("B receives plain RTP");
        assert_eq!(got, plain);
        // B → A: encrypted by the relay with its own key (32-bit tag).
        let plain = rtp_packet(1000 + seq);
        b.send_to(&plain, ports.b).unwrap();
        let (got, _) = recv(&a).expect("A receives SRTP");
        assert_eq!(got.len(), plain.len() + 4);
        assert_eq!(unprotect(&mut a_rx, &got), plain);
    }
    assert_eq!(r.totals().srtp_rejected, 0);
}

#[test]
fn forged_and_replayed_srtp_is_dropped_and_does_not_latch() {
    let mut r = relay(44_200, 32, 60);
    let (a, b, mallory) = (endpoint(), endpoint(), endpoint());
    let (ka, ra) = (
        key(3, Suite::AesCm128HmacSha1_80),
        key(4, Suite::AesCm128HmacSha1_80),
    );
    let ports = srtp_call(&mut r, &a, &b, ka, ra);
    std::thread::sleep(Duration::from_millis(50));
    let mut a_tx = Protect::from_key(&ka);
    let good = protect(&mut a_tx, &rtp_packet(1));
    a.send_to(&good, ports.a).unwrap();
    assert!(recv(&b).is_some());
    // A replay, a forgery with a wrong key and a flipped payload bit, all
    // from Mallory's address: none reaches B.
    let mut forged = protect(
        &mut Protect::from_key(&key(9, Suite::AesCm128HmacSha1_80)),
        &rtp_packet(2),
    );
    let mut flipped = protect(&mut a_tx, &rtp_packet(3));
    flipped[20] ^= 1;
    for bad in [&good, &forged, &flipped] {
        mallory.send_to(bad, ports.a).unwrap();
    }
    forged.clear();
    assert!(recv(&b).is_none(), "nothing forged is relayed");
    // The latch stayed on A: B's media still goes to A, not Mallory.
    b.send_to(&rtp_packet(4), ports.b).unwrap();
    assert!(recv(&a).is_some());
    assert!(recv(&mallory).is_none());
    assert_eq!(r.totals().srtp_rejected, 3);
}

#[test]
fn srtp_to_srtp_reencrypts_and_srtcp_works() {
    let mut relay_ = relay(44_400, 32, 60);
    let (a, b, a_rtcp, b_rtcp) = (endpoint(), endpoint(), endpoint(), endpoint());
    let keys = [1, 2, 3, 4].map(|f| key(f + 20, Suite::AesCm128HmacSha1_80));
    let mk = |s: &UdpSocket, c: &UdpSocket, inbound, outbound| Side {
        rtcp: Some(c.local_addr().unwrap()),
        srtp: Srtp {
            inbound: Inbound::Key(inbound),
            outbound: Some(outbound),
        },
        ..side(Some(s.local_addr().unwrap()), Learning::Off, false)
    };
    let ports = relay_
        .create_call(
            mk(&a, &a_rtcp, keys[0], keys[1]),
            mk(&b, &b_rtcp, keys[2], keys[3]),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // A sends with k0; B must receive it under the relay's k3.
    let plain = rtp_packet(7);
    a.send_to(&protect(&mut Protect::from_key(&keys[0]), &plain), ports.a)
        .unwrap();
    let (got, _) = recv(&b).unwrap();
    assert_eq!(unprotect(&mut Unprotect::from_key(&keys[3]), &got), plain);
    // SRTCP the same way.
    let rr = [0x81, 201, 0, 1, 0, 0, 0, 7];
    let mut wire = rr.to_vec();
    wire.resize(rr.len() + 14, 0);
    Protect::from_key(&keys[0])
        .rtcp(&mut wire, rr.len())
        .unwrap();
    a_rtcp
        .send_to(&wire, SocketAddr::new(ports.a.ip(), ports.a.port() + 1))
        .unwrap();
    let (mut got, _) = recv(&b_rtcp).expect("SRTCP relayed");
    let n = got.len();
    let n = Unprotect::from_key(&keys[3]).rtcp(&mut got, n).unwrap();
    assert_eq!(&got[..n], &rr);
}

#[test]
fn pending_keys_drop_until_the_answer_and_srtp_calls_stay_in_userspace() {
    let mut r = relay(44_600, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let kb = key(5, Suite::AesCm128HmacSha1_80);
    let pending = Side {
        srtp: Srtp {
            inbound: Inbound::Pending,
            outbound: Some(key(6, Suite::AesCm128HmacSha1_80)),
        },
        ..side(Some(b.local_addr().unwrap()), Learning::Off, false)
    };
    let ports = r
        .create_call(
            side(Some(a.local_addr().unwrap()), Learning::Off, false),
            pending,
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut b_tx = Protect::from_key(&kb);
    b.send_to(&protect(&mut b_tx, &rtp_packet(1)), ports.b)
        .unwrap();
    assert!(recv(&a).is_none(), "no key yet: dropped");
    // The answer brings B's key.
    let answered = Side {
        srtp: Srtp {
            inbound: Inbound::Key(kb),
            outbound: Some(key(6, Suite::AesCm128HmacSha1_80)),
        },
        ..pending
    };
    assert!(r.update_side(ports.id, CallLeg::B, &answered).unwrap());
    std::thread::sleep(Duration::from_millis(50));
    let plain = rtp_packet(2);
    b.send_to(&protect(&mut b_tx, &plain), ports.b).unwrap();
    assert_eq!(recv(&a).expect("decrypted after the answer").0, plain);
    assert_eq!(r.totals().srtp_rejected, 1);
}

// ---------------------------------------------------------------- rtcp-mux, ICE-lite

#[test]
fn muxed_rtcp_goes_between_rtp_and_rtcp_ports() {
    let mut r = relay(44_800, 32, 60);
    let (a, b, b_rtcp) = (endpoint(), endpoint(), endpoint());
    // A muxes RTCP onto its RTP port; B does not.
    let ports = r
        .create_call(
            Side {
                rtcp: Some(a.local_addr().unwrap()),
                rtcp_mux: true,
                ..side(Some(a.local_addr().unwrap()), Learning::Off, false)
            },
            Side {
                rtcp: Some(b_rtcp.local_addr().unwrap()),
                ..side(Some(b.local_addr().unwrap()), Learning::Off, false)
            },
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let rr = [0x81, 201, 0, 1, 0, 0, 0, 7];
    // A's RTCP arrives on A's RTP port and leaves on B's RTCP port.
    a.send_to(&rr, ports.a).unwrap();
    let (got, from) = recv(&b_rtcp).expect("muxed RTCP reaches B's RTCP socket");
    assert_eq!((got.as_slice(), from.port()), (&rr[..], ports.b.port() + 1));
    // B's RTCP goes back to A's RTP port, from the relay's RTP port.
    b_rtcp
        .send_to(&rr, SocketAddr::new(ports.b.ip(), ports.b.port() + 1))
        .unwrap();
    let (got, from) = recv(&a).expect("RTCP to a muxed side uses its RTP port");
    assert_eq!((got.as_slice(), from), (&rr[..], ports.a));
    // RTP still goes RTP to RTP.
    a.send_to(&rtp_packet(1), ports.a).unwrap();
    assert_eq!(recv(&b).expect("RTP").0, rtp_packet(1));
}

const UFRAG: [u8; 8] = *b"rfxUfrag";
const PWD: [u8; 24] = *b"relayPassword0123456789/";

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// A Binding request as a full ICE agent sends it (RFC 8445 §7.2.4).
fn ice_check(user: &[u8], pwd: &[u8], nominate: bool) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut m = vec![0x00, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42];
    m.extend_from_slice(&[7; 12]);
    let attr = |m: &mut Vec<u8>, t: u16, v: &[u8]| {
        m.extend_from_slice(&t.to_be_bytes());
        m.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
        m.extend_from_slice(v);
        m.resize(m.len() + (4 - v.len() % 4) % 4, 0);
    };
    attr(&mut m, 0x0006, user);
    attr(&mut m, 0x0024, &0x6e00_01ffu32.to_be_bytes());
    if nominate {
        attr(&mut m, 0x0025, &[]);
    }
    let len = |m: &mut Vec<u8>, extra: usize| {
        let l = u16::try_from(m.len() - 20 + extra).unwrap();
        m[2..4].copy_from_slice(&l.to_be_bytes());
    };
    len(&mut m, 24);
    let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(pwd).unwrap();
    mac.update(&m);
    let tag = mac.finalize().into_bytes();
    attr(&mut m, 0x0008, &tag);
    len(&mut m, 8);
    let fp = crc32(&m) ^ 0x5354_554e;
    attr(&mut m, 0x8028, &fp.to_be_bytes());
    m
}

#[test]
fn ice_lite_answers_checks_and_follows_the_nominated_address() {
    let mut r = relay(45_800, 32, 60);
    let (a_sdp, a_real, b) = (endpoint(), endpoint(), endpoint());
    let ice = IceCreds {
        ufrag: UFRAG,
        pwd: PWD,
        lite: true,
    };
    let ports = r
        .create_call(
            Side {
                ice: Some(ice),
                ..side(Some(a_sdp.local_addr().unwrap()), Learning::Off, false)
            },
            side(Some(b.local_addr().unwrap()), Learning::Off, false),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut user = UFRAG.to_vec();
    user.extend_from_slice(b":peer");
    // A wrong password: 401, and nothing changes.
    a_real
        .send_to(
            &ice_check(&user, b"wrong-password-000000000", true),
            ports.a,
        )
        .unwrap();
    let (resp, _) = recv(&a_real).expect("an error response");
    assert_eq!(&resp[..2], &[0x01, 0x11], "Binding error response");
    b.send_to(&rtp_packet(1), ports.b).unwrap();
    assert!(
        recv(&a_sdp).is_some(),
        "media still goes to the SDP address"
    );
    // A valid, nominating check from A's real address.
    a_real
        .send_to(&ice_check(&user, &PWD, true), ports.a)
        .unwrap();
    let (resp, from) = recv(&a_real).expect("a success response");
    assert_eq!((&resp[..2], from), (&[0x01, 0x01][..], ports.a));
    let xport = u16::from_be_bytes([resp[26], resp[27]]) ^ 0x2112;
    assert_eq!(
        xport,
        a_real.local_addr().unwrap().port(),
        "XOR-MAPPED-ADDRESS"
    );
    b.send_to(&rtp_packet(2), ports.b).unwrap();
    assert_eq!(
        recv(&a_real).expect("media follows the check").0,
        rtp_packet(2)
    );
    assert!(recv(&a_sdp).is_none());
}

// ---------------------------------------------------------------- DTLS-SRTP

use rtpflux::dtls::{Association, Identity, Progress};
use rtpflux::relay::{DtlsRole, DtlsSide};
use rtpflux_core::dtls::{Fingerprint, Role};

fn fingerprint(identity: &Identity) -> [Option<Fingerprint>; 2] {
    [Fingerprint::parse(identity.fingerprint().as_bytes()), None]
}

/// Run `assoc` against the relay port `to` over `sock` until keyed.
fn handshake(sock: &UdpSocket, to: SocketAddr, assoc: &mut Association) -> (MasterKey, MasterKey) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 4096];
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    loop {
        for d in assoc.take_output() {
            sock.send_to(&d, to).unwrap();
        }
        assert!(Instant::now() < deadline, "handshake did not finish");
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

fn exchange_media(
    a: &UdpSocket,
    b: &UdpSocket,
    ports: &CallPorts,
    a_in: MasterKey,
    a_out: MasterKey,
) {
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (mut tx, mut rx) = (Protect::from_key(&a_out), Unprotect::from_key(&a_in));
    for seq in 0..5u16 {
        let plain = rtp_packet(seq);
        a.send_to(&protect(&mut tx, &plain), ports.a).unwrap();
        assert_eq!(recv(b).expect("B gets plain RTP").0, plain);
        b.send_to(&plain, ports.b).unwrap();
        let (wire, _) = recv(a).expect("A gets SRTP");
        assert_eq!(unprotect(&mut rx, &wire), plain);
    }
}

#[test]
fn dtls_srtp_with_the_relay_as_server() {
    let mut r = relay(46_200, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let peer = Identity::generate().unwrap();
    let ports = r
        .create_call(
            Side {
                srtp: Srtp {
                    inbound: Inbound::Pending,
                    outbound: None,
                },
                dtls: Some(DtlsSide {
                    role: DtlsRole::Server,
                    remote: fingerprint(&peer),
                }),
                ..side(Some(a.local_addr().unwrap()), Learning::Off, false)
            },
            side(Some(b.local_addr().unwrap()), Learning::Off, false),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // Nothing passes before the keys.
    b.send_to(&rtp_packet(9), ports.b).unwrap();
    a.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert!(
        recv(&a).is_none(),
        "no plain media to a DTLS side before keys"
    );
    let relay_fp = [Fingerprint::parse(r.dtls_fingerprint().as_bytes()), None];
    let mut client = Association::new(&peer, Role::Client, relay_fp).unwrap();
    let (a_in, a_out) = handshake(&a, ports.a, &mut client);
    std::thread::sleep(Duration::from_millis(20));
    exchange_media(&a, &b, &ports, a_in, a_out);
    // The web UI's view of the leg: DTLS keyed, the latch settled.
    let legs = r.query(ports.id).expect("the call");
    assert!(legs.iter().any(|l| l.dtls == Some("keyed")), "{legs:?}");
    let states: Vec<_> = legs.iter().map(|l| (l.local_port, l.dtls)).collect();
    // Side A's RTP leg keyed; its RTCP leg (no rtcp-mux here) has a DTLS
    // association of its own, which this test never completes.
    assert_eq!(
        (states[0].1, states[1].1),
        (Some("keyed"), Some("handshaking")),
        "{states:?}"
    );
    assert_eq!((states[2].1, states[3].1), (None, None), "plain side B");
    // Counted for /metrics.
    let dtls =
        |f: fn(&rtpflux::relay::Stats) -> u64| r.worker_stats().iter().map(|s| f(s)).sum::<u64>();
    assert_eq!(
        dtls(|s| s.dtls_handshakes.load(std::sync::atomic::Ordering::Relaxed)),
        1
    );
    assert_eq!(
        dtls(|s| s.dtls_failures.load(std::sync::atomic::Ordering::Relaxed)),
        0
    );
}

#[test]
fn dtls_srtp_with_the_relay_as_client() {
    let mut r = relay(46_400, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let peer = Identity::generate().unwrap();
    let ports = r
        .create_call(
            Side {
                srtp: Srtp {
                    inbound: Inbound::Pending,
                    outbound: None,
                },
                dtls: Some(DtlsSide {
                    role: DtlsRole::Client,
                    remote: fingerprint(&peer),
                }),
                ..side(Some(a.local_addr().unwrap()), Learning::Off, false)
            },
            side(Some(b.local_addr().unwrap()), Learning::Off, false),
        )
        .unwrap();
    // The relay sends the ClientHello to A's address; A serves.
    let relay_fp = [Fingerprint::parse(r.dtls_fingerprint().as_bytes()), None];
    let mut server = Association::new(&peer, Role::Server, relay_fp).unwrap();
    let (a_in, a_out) = handshake(&a, ports.a, &mut server);
    std::thread::sleep(Duration::from_millis(20));
    exchange_media(&a, &b, &ports, a_in, a_out);
}

#[test]
fn dtls_with_a_wrong_certificate_never_keys() {
    let mut r = relay(46_600, 32, 60);
    let (a, b) = (endpoint(), endpoint());
    let (peer, impostor) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let ports = r
        .create_call(
            Side {
                srtp: Srtp {
                    inbound: Inbound::Pending,
                    outbound: None,
                },
                dtls: Some(DtlsSide {
                    role: DtlsRole::Server,
                    remote: fingerprint(&peer),
                }),
                ..side(Some(a.local_addr().unwrap()), Learning::Off, false)
            },
            side(Some(b.local_addr().unwrap()), Learning::Off, false),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let relay_fp = [Fingerprint::parse(r.dtls_fingerprint().as_bytes()), None];
    let mut client = Association::new(&impostor, Role::Client, relay_fp).unwrap();
    // The impostor completes its side, but the relay installs no keys.
    let (_, a_out) = handshake(&a, ports.a, &mut client);
    std::thread::sleep(Duration::from_millis(20));
    let mut tx = Protect::from_key(&a_out);
    a.send_to(&protect(&mut tx, &rtp_packet(1)), ports.a)
        .unwrap();
    b.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(
        recv(&b).is_none(),
        "nothing is relayed from an unverified peer"
    );
    let keyed: u64 = r
        .worker_stats()
        .iter()
        .map(|s| s.dtls_handshakes.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(keyed, 0, "a wrong certificate never counts as a handshake");
}
