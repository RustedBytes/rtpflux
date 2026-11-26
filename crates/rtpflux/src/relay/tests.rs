//! A call moved into the XDP fast path and back out, with the kernel's flow
//! table replaced by one in memory: the workers' offload decisions, the
//! offload thread, and the kernel's counters reaching `query`.

use super::offload::tests::{Net, Table};
use super::*;
use rtpflux_xdp_common::FlowStats;
use std::time::{Duration, Instant};

fn relay(table: &Table) -> Relay {
    relay_with(table, 1)
}

fn relay_with(table: &Table, workers: usize) -> Relay {
    crate::test_logging::init();
    let config = Config::from_toml(&format!(
        r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 53000
        max = 53063
        [sessions]
        max = 8
        [runtime]
        workers = {workers}
        [xdp]
        devices = ["lo"]
        "#
    ))
    .unwrap();
    Relay::start_with(
        &config,
        Some((Box::new(table.clone()), Box::new(Net))),
        Vec::new(),
    )
    .unwrap()
}

fn endpoint() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}

fn side(rtp: SocketAddr) -> Side {
    Side {
        interface: InterfaceId::new(0),
        rtp: Some(rtp),
        rtcp: None,
        learning: Learning::Off,
        strict_source: false,
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

/// Wait until `cond` holds (up to 5 s).
fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_settled_call_is_offloaded_counted_and_taken_back() {
    let table = Table::default();
    let mut r = relay(&table);
    let (a, b) = (endpoint(), endpoint());
    let ports = r
        .create_call(side(a.local_addr().unwrap()), side(b.local_addr().unwrap()))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 9, 9, 9, 9];
    for _ in 0..12 {
        a.send_to(&pkt, ports.a).unwrap();
        b.recv(&mut buf).unwrap();
        b.send_to(&pkt, ports.b).unwrap();
        a.recv(&mut buf).unwrap();
    }
    // Both directions are settled and have carried traffic: the next sweep
    // moves them into the (fake) kernel.
    until("the flows", || table.0.lock().unwrap().flows.len() == 2);
    // The kernel relays 100 packets from A; its counters reach query.
    let before = r.query(ports.id).unwrap()[0].packets;
    {
        let mut t = table.0.lock().unwrap();
        let key = *t
            .flows
            .keys()
            .find(|k| k.src_port == a.local_addr().unwrap().port().to_be())
            .unwrap();
        t.stats.insert(
            key,
            FlowStats {
                packets: 100,
                bytes: 100 * (rtpflux_xdp_common::headers_len(&key) as u64 + 4),
                last_ns: 0,
            },
        );
    }
    until("the kernel's packets in query", || {
        r.query(ports.id).unwrap()[0].packets == before + 100
    });
    // Blocking stays in the kernel: A's flow drops, B's still relays.
    let a_port = a.local_addr().unwrap().port().to_be();
    let flags_of = |from: u16| {
        let t = table.0.lock().unwrap();
        t.flows
            .iter()
            .find(|(k, _)| k.src_port == from)
            .map(|(_, a)| a.flags)
    };
    let b_port = b.local_addr().unwrap().port().to_be();
    r.block(ports.id, CallLeg::A, Blocked::Media, true).unwrap();
    until("A's flow dropping", || {
        flags_of(a_port) == Some(rtpflux_xdp_common::flags::DROP)
    });
    assert_eq!(flags_of(b_port), Some(0));
    r.block(ports.id, CallLeg::A, Blocked::Media, false)
        .unwrap();
    until("A's flow relaying again", || flags_of(a_port) == Some(0));
    // An announcement to A holds B's media back: B's flow drops.
    let playing = Playing {
        codes: vec![0xff; 8000].into(),
        pt: Pt::PCMU,
        repeat: 1,
        skip: 0,
        limit: None,
    };
    r.play(ports.id, CallLeg::A, Some(playing)).unwrap();
    until("B's flow dropping", || {
        flags_of(b_port) == Some(rtpflux_xdp_common::flags::DROP)
    });
    assert_eq!(flags_of(a_port), Some(0));
    r.play(ports.id, CallLeg::A, None).unwrap();
    until("B's flow relaying again", || flags_of(b_port) == Some(0));
    r.delete_call(ports.id).unwrap();
    until("the flows removed", || {
        table.0.lock().unwrap().flows.is_empty()
    });
}

#[test]
fn errors_and_credentials_print_safely() {
    let cases: [(RelayError, &str); 6] = [
        (
            RelayError::UnknownInterface(InterfaceId::new(3)),
            "no interface with index 3",
        ),
        (RelayError::PortsExhausted, "no free media ports"),
        (RelayError::Busy, "worker queue full"),
        (std::io::Error::other("disk on fire").into(), "disk on fire"),
        (nix::Error::EAGAIN.into(), "EAGAIN: Try again"),
        (
            RelayError::Xdp(rtpflux_xdp::loader::Error::Missing("RTPFLUX_FLOWS")),
            "XDP: ",
        ),
    ];
    for (e, text) in cases {
        assert!(e.to_string().starts_with(text), "{e}");
    }
    let creds = IceCreds {
        ufrag: *b"abcdEFGH",
        pwd: *b"0123456789abcdefghijklmn",
        lite: true,
    };
    let shown = format!("{creds:?}");
    assert_eq!(shown, "IceCreds(abcdEFGH, ..)");
    assert!(!shown.contains("0123"), "never the password");
}

#[test]
fn a_call_with_dtmf_detection_is_offloaded_with_its_events_going_up() {
    let table = Table::default();
    let mut r = relay(&table);
    let (a, b) = (endpoint(), endpoint());
    let with_dtmf = |s: Side| Side {
        dtmf: Some((Pt::new(101).unwrap(), 8000)),
        ..s
    };
    let ports = r
        .create_call(
            with_dtmf(side(a.local_addr().unwrap())),
            side(b.local_addr().unwrap()),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 9, 9, 9, 9];
    for _ in 0..12 {
        a.send_to(&pkt, ports.a).unwrap();
        b.recv(&mut buf).unwrap();
        b.send_to(&pkt, ports.b).unwrap();
        a.recv(&mut buf).unwrap();
    }
    until("the flows", || table.0.lock().unwrap().flows.len() == 2);
    let a_port = a.local_addr().unwrap().port().to_be();
    let t = table.0.lock().unwrap();
    let (_, from_a) = t.flows.iter().find(|(k, _)| k.src_port == a_port).unwrap();
    assert_eq!(
        (from_a.flags, from_a.event_pt),
        (rtpflux_xdp_common::flags::EVENTS_UP, 101)
    );
    let (_, from_b) = t.flows.iter().find(|(k, _)| k.src_port != a_port).unwrap();
    assert_eq!(from_b.flags, 0, "B has no detection");
    drop(t);
    r.delete_call(ports.id).unwrap();
}

#[test]
fn a_recorded_call_stays_in_the_kernel_and_its_samples_reach_the_pcap() {
    use rtpflux_xdp_common::{flags, record_layout as rl};
    let table = Table::default();
    let mut r = relay(&table);
    let (a, b) = (endpoint(), endpoint());
    let ports = r
        .create_call(side(a.local_addr().unwrap()), side(b.local_addr().unwrap()))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 9, 9, 9, 9];
    for _ in 0..12 {
        a.send_to(&pkt, ports.a).unwrap();
        b.recv(&mut buf).unwrap();
        b.send_to(&pkt, ports.b).unwrap();
        a.recv(&mut buf).unwrap();
    }
    until("the flows", || table.0.lock().unwrap().flows.len() == 2);
    let dir = std::env::temp_dir().join(format!("rtpflux-xdp-rec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("call.pcap");
    r.record(
        ports.id,
        Some(crate::recording::Spec {
            path: path.clone(),
            conversion: None,
        }),
    )
    .unwrap();
    until("both flows recording", || {
        let t = table.0.lock().unwrap();
        t.flows.len() == 2 && t.flows.values().all(|a| a.flags & flags::RECORD != 0)
    });
    // The kernel relays a datagram from A and copies it into the ring.
    let key = {
        let a_port = a.local_addr().unwrap().port().to_be();
        let t = table.0.lock().unwrap();
        *t.flows.keys().find(|k| k.src_port == a_port).unwrap()
    };
    let mut sample = vec![0u8; rl::SIZE];
    sample[..16].copy_from_slice(&key.src_addr);
    sample[16..32].copy_from_slice(&key.dst_addr);
    sample[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
    sample[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
    sample[rl::LEN..rl::LEN + 2].copy_from_slice(&16u16.to_ne_bytes());
    sample[rl::DATA..rl::DATA + 16].copy_from_slice(&pkt);
    table.0.lock().unwrap().records.push(sample);
    // Stopping writes the recording out; the flows stop copying.
    let pcap_len = |p: &std::path::Path| std::fs::metadata(p).map_or(0, |m| m.len());
    until("the sample recorded", || {
        if table.0.lock().unwrap().records.is_empty() {
            r.record(ports.id, None).unwrap();
        }
        pcap_len(&path) >= 24 + 16 + 28 + 16
    });
    until("the flows no longer recording", || {
        let t = table.0.lock().unwrap();
        t.flows.values().all(|a| a.flags & flags::RECORD == 0)
    });
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.ends_with(&pkt), "the payload is the last record's");
    r.delete_call(ports.id).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn datagrams_received_through_af_xdp_are_relayed_like_socket_ones() {
    use super::xsk::tests::FakeSource;
    use rtpflux_xdp::testframe::{Spec, build};
    crate::test_logging::init();
    let config = Config::from_toml(
        r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 53100
        max = 53163
        [sessions]
        max = 8
        [runtime]
        workers = 2
        "#,
    )
    .unwrap();
    let (source, frames, signal) = FakeSource::new();
    let mut r = Relay::start_with(&config, None, vec![Box::new(source)]).unwrap();
    let (a, b) = (endpoint(), endpoint());
    let mut buf = [0u8; 2048];
    // Two calls, one on each worker.
    for _ in 0..2 {
        let ports = r
            .create_call(side(a.local_addr().unwrap()), side(b.local_addr().unwrap()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 1, 2, 3, 4];
        let frame = build(&Spec {
            src: a.local_addr().unwrap().ip(),
            dst: ports.a.ip(),
            sport: a.local_addr().unwrap().port(),
            dport: ports.a.port(),
            ttl: 64,
            udp_checksum: true,
            payload: &pkt,
        });
        frames.lock().unwrap().push(frame);
        signal.write(1).unwrap();
        // Relayed to B from the call's B-side port, as from the socket.
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &pkt);
        assert_eq!(from, ports.b);
        // And B's answer, through the socket, reaches A (A is latched).
        b.send_to(&pkt, ports.b).unwrap();
        let (n, from) = a.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&pkt[..], ports.a));
        r.delete_call(ports.id).unwrap();
    }
}

#[test]
fn an_empty_datagram_is_dropped_and_the_worker_keeps_relaying() {
    let table = Table::default();
    let mut r = relay(&table);
    let (a, b) = (endpoint(), endpoint());
    let ports = r
        .create_call(side(a.local_addr().unwrap()), side(b.local_addr().unwrap()))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // Legal UDP: zero octets of payload, on both ports of side A.
    a.send_to(&[], ports.a).unwrap();
    a.send_to(&[], SocketAddr::new(ports.a.ip(), ports.a.port() + 1))
        .unwrap();
    let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 1, 2, 3, 4];
    a.send_to(&pkt, ports.a).unwrap();
    let mut buf = [0u8; 2048];
    let n = b.recv(&mut buf).expect("the worker still relays");
    assert_eq!(&buf[..n], &pkt);
    r.delete_call(ports.id).unwrap();
}

#[test]
fn announcements_continue_one_stream() {
    let table = Table::default();
    let mut r = relay(&table);
    let (a, b) = (endpoint(), endpoint());
    let ports = r
        .create_call(side(a.local_addr().unwrap()), side(b.local_addr().unwrap()))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let play = || Playing {
        codes: vec![0xff; 2 * 160].into(),
        pt: Pt::PCMU,
        repeat: 1,
        skip: 0,
        limit: None,
    };
    // (marker, sequence number, SSRC) of the packets of one announcement.
    let heard = |n: usize| -> Vec<(bool, u16, u32)> {
        let mut buf = [0u8; 2048];
        (0..n)
            .map(|_| {
                let len = a.recv(&mut buf).expect("announcement packet");
                assert_eq!(len, 172);
                (
                    buf[1] & 0x80 != 0,
                    u16::from_be_bytes([buf[2], buf[3]]),
                    u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
                )
            })
            .collect()
    };
    r.play(ports.id, CallLeg::A, Some(play())).unwrap();
    let first = heard(2);
    std::thread::sleep(Duration::from_millis(100));
    r.play(ports.id, CallLeg::A, Some(play())).unwrap();
    let second = heard(2);
    let (ssrc, seq) = (first[0].2, first[0].1);
    assert!(first[0].0 && !first[1].0, "{first:?}");
    assert!(second[0].0, "each announcement starts with the marker bit");
    assert!(
        [first[1], second[0], second[1]]
            .iter()
            .zip(1u16..)
            .all(|(p, i)| p.2 == ssrc && p.1 == seq.wrapping_add(i)),
        "one SSRC, sequence numbers going on: {first:?} {second:?}"
    );
    r.delete_call(ports.id).unwrap();
}

#[test]
fn a_deleted_bundle_member_gets_no_more_media() {
    let table = Table::default();
    let mut r = relay(&table);
    let (caller, callee, member_callee) = (endpoint(), endpoint(), endpoint());
    // A primary and a member sharing the primary's side-A port; payload
    // type 8 is the member's.
    let primary = r
        .create_call(
            side(caller.local_addr().unwrap()),
            side(callee.local_addr().unwrap()),
        )
        .unwrap();
    let member = r
        .create_call_near(
            side(caller.local_addr().unwrap()),
            side(member_callee.local_addr().unwrap()),
            Some(primary.id),
        )
        .unwrap();
    assert!(
        r.bundle(
            primary.id,
            &[(primary.id, vec![Pt::PCMU]), (member.id, vec![Pt::PCMA])]
        )
        .unwrap()
    );
    std::thread::sleep(Duration::from_millis(50));
    let pkt = |pt: u8| [0x80, pt, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 1, 2, 3, 4];
    let mut buf = [0u8; 2048];
    caller.send_to(&pkt(8), primary.a).unwrap();
    assert_eq!(
        member_callee.recv(&mut buf).unwrap(),
        16,
        "sorted into the member"
    );
    // The member ends; a new call gets ports (perhaps the member's).
    r.delete_call(member.id).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let newcomer = endpoint();
    let newcall = r
        .create_call(
            side(endpoint().local_addr().unwrap()),
            side(newcomer.local_addr().unwrap()),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // Payload type 8 on the shared port is the primary's own again.
    caller.send_to(&pkt(8), primary.a).unwrap();
    assert_eq!(callee.recv(&mut buf).unwrap(), 16, "the primary's own leg");
    newcomer
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(
        newcomer.recv(&mut buf).is_err(),
        "nothing leaks into the new call"
    );
    for id in [primary.id, newcall.id] {
        r.delete_call(id).unwrap();
    }
}

#[test]
fn a_payload_type_no_bundle_member_has_is_dropped() {
    let table = Table::default();
    let mut r = relay(&table);
    let (caller, callee, member_callee) = (endpoint(), endpoint(), endpoint());
    let primary = r
        .create_call(
            side(caller.local_addr().unwrap()),
            side(callee.local_addr().unwrap()),
        )
        .unwrap();
    let member = r
        .create_call_near(
            side(caller.local_addr().unwrap()),
            side(member_callee.local_addr().unwrap()),
            Some(primary.id),
        )
        .unwrap();
    assert!(
        r.bundle(
            primary.id,
            &[(primary.id, vec![Pt::PCMU]), (member.id, vec![Pt::PCMA])]
        )
        .unwrap()
    );
    std::thread::sleep(Duration::from_millis(50));
    let pkt = |pt: u8| [0x80, pt, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 1, 2, 3, 4];
    let mut buf = [0u8; 2048];
    for s in [&callee, &member_callee] {
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
    }
    // Payload type 111: no section of the group negotiated it.
    caller.send_to(&pkt(111), primary.a).unwrap();
    assert!(callee.recv(&mut buf).is_err(), "not handed to the primary");
    assert!(member_callee.recv(&mut buf).is_err(), "nor to the member");
    // The group's own types are sorted as before.
    caller.send_to(&pkt(0), primary.a).unwrap();
    assert_eq!(callee.recv(&mut buf).unwrap(), 16);
    caller.send_to(&pkt(8), primary.a).unwrap();
    assert_eq!(member_callee.recv(&mut buf).unwrap(), 16);
    for id in [primary.id, member.id] {
        r.delete_call(id).unwrap();
    }
}

#[test]
fn a_full_worker_hands_new_calls_to_another() {
    crate::test_logging::init();
    // Two workers of 4 port pairs: two calls each.
    let config = Config::from_toml(
        r#"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = 53500
        max = 53515
        [sessions]
        max = 4
        [runtime]
        workers = 2
        "#,
    )
    .unwrap();
    let mut r = Relay::start_with(&config, None, Vec::new()).unwrap();
    let s = || side(endpoint().local_addr().unwrap());
    let first = r.create_call(s(), s()).unwrap(); // worker 0
    let second = r.create_call(s(), s()).unwrap(); // worker 1
    let third = r.create_call_near(s(), s(), Some(first.id)).unwrap(); // worker 0, now full
    // Worker 0's turn, but it is full: worker 1 takes the call.
    let fourth = r.create_call(s(), s()).unwrap();
    // All four ports pairs in use on both: now nothing is left.
    assert!(matches!(
        r.create_call(s(), s()),
        Err(RelayError::PortsExhausted)
    ));
    for c in [first, second, third, fourth] {
        r.delete_call(c.id).unwrap();
    }
}

/// `unidirectional`: a call whose media flows one way (the silent side's
/// address settled, from its SDP) enters the fast path; without the flag it
/// waits for media both ways.
#[test]
fn one_way_media_is_offloaded_with_unidirectional() {
    for unidirectional in [false, true] {
        let table = Table::default();
        let mut r = relay(&table);
        let (a, b) = (endpoint(), endpoint());
        let ports = r
            .create_call(
                Side {
                    unidirectional,
                    ..side(a.local_addr().unwrap())
                },
                side(b.local_addr().unwrap()),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let mut buf = [0u8; 2048];
        let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 9, 9, 9, 9];
        for _ in 0..12 {
            a.send_to(&pkt, ports.a).unwrap();
            b.recv(&mut buf).unwrap();
        }
        if unidirectional {
            until("the flows", || table.0.lock().unwrap().flows.len() == 2);
        } else {
            std::thread::sleep(Duration::from_millis(1500));
            assert!(table.0.lock().unwrap().flows.is_empty(), "both ways needed");
        }
        r.delete_call(ports.id).unwrap();
        drop(r);
    }
}

/// Two calls on one worker, one party of each `connect`ed: once settled,
/// the call pair enters the fast path, the connected parties' flows going
/// to each other and those of the parties left behind dropping.
#[test]
fn connected_calls_are_offloaded() {
    let table = Table::default();
    let mut relay = relay(&table);
    let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
    let addr = |s: &UdpSocket| s.local_addr().unwrap();
    let one = relay
        .create_call(side(addr(&alice)), side(addr(&bob)))
        .unwrap();
    let two = relay
        .create_call(side(addr(&carol)), side(addr(&dave)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        relay
            .connect((one.id, CallLeg::A), (two.id, CallLeg::B), [None, None])
            .unwrap()
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 9, 9, 9, 9];
    for _ in 0..12 {
        alice.send_to(&pkt, one.a).unwrap();
        dave.recv(&mut buf).unwrap();
        dave.send_to(&pkt, two.b).unwrap();
        alice.recv(&mut buf).unwrap();
    }
    until("the four flows", || {
        table.0.lock().unwrap().flows.len() == 4
    });
    let flows = table.0.lock().unwrap();
    let drops = flows
        .flows
        .values()
        .filter(|f| f.flags & rtpflux_xdp_common::flags::DROP != 0)
        .count();
    assert_eq!(drops, 2, "B and C are dropped in the kernel");
    drop(flows);
    // The second call ends: the first leaves the kernel (its flow went to
    // a port that is gone), and comes back with both its parties detached:
    // two flows, both dropping.
    relay.delete_call(two.id).unwrap();
    until("only the first call's flows, dropping", || {
        let t = table.0.lock().unwrap();
        t.flows.len() == 2
            && t.flows
                .values()
                .all(|f| f.flags & rtpflux_xdp_common::flags::DROP != 0)
    });
    relay.delete_call(one.id).unwrap();
    until("the flows removed", || {
        table.0.lock().unwrap().flows.is_empty()
    });
}

/// The same with the two calls on two workers: each publishes its
/// connected leg for the other, and both enter the fast path; when one call
/// ends, the other leaves it.
#[test]
fn calls_connected_across_workers_are_offloaded() {
    let table = Table::default();
    let mut relay = relay_with(&table, 2);
    let (alice, bob, carol, dave) = (endpoint(), endpoint(), endpoint(), endpoint());
    let addr = |s: &UdpSocket| s.local_addr().unwrap();
    let one = relay
        .create_call(side(addr(&alice)), side(addr(&bob)))
        .unwrap();
    let two = relay
        .create_call(side(addr(&carol)), side(addr(&dave)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        relay
            .connect((one.id, CallLeg::A), (two.id, CallLeg::B), [None, None])
            .unwrap()
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut buf = [0u8; 2048];
    let pkt = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 9, 9, 9, 9];
    for _ in 0..12 {
        alice.send_to(&pkt, one.a).unwrap();
        dave.recv(&mut buf).unwrap();
        dave.send_to(&pkt, two.b).unwrap();
        alice.recv(&mut buf).unwrap();
    }
    until("the four flows", || {
        table.0.lock().unwrap().flows.len() == 4
    });
    // The second call ends: the first leaves the kernel (its flow went to
    // a port that is gone), and comes back with both its parties detached:
    // two flows, both dropping.
    relay.delete_call(two.id).unwrap();
    until("only the first call's flows, dropping", || {
        let t = table.0.lock().unwrap();
        t.flows.len() == 2
            && t.flows
                .values()
                .all(|f| f.flags & rtpflux_xdp_common::flags::DROP != 0)
    });
    relay.delete_call(one.id).unwrap();
    until("the flows removed", || {
        table.0.lock().unwrap().flows.is_empty()
    });
}
