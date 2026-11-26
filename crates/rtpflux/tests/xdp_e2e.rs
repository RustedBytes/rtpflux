//! The XDP fast path end to end, in network namespaces. Needs root; run it
//! through `scripts/xdp-e2e.sh`, which builds the topology:
//!
//! ```text
//!   relay netns: rfx0 10.77.0.1 fd77::1  <— veth —>  peer netns: rfx1 10.77.0.2-3 fd77::2-3
//!                rfx2 10.78.0.1 fd78::1  <— veth —>              rfx3 10.78.0.2    fd78::2
//! ```
//!
//! Calls with both sides on rfx0 are relayed with `XDP_TX`; calls with one
//! side on each device cross with `XDP_REDIRECT`; both for IPv4 and IPv6.
//!
//! The test runs in the relay namespace; the peers' sockets are created in
//! the peer namespace (a socket keeps the namespace it was created in).

use nix::sched::{CloneFlags, setns};
use rtpflux::config::Config;
use rtpflux::relay::{Relay, Side, Srtp};
use rtpflux_core::latch::Learning;
use std::fs::File;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set (run scripts/xdp-e2e.sh)"))
}

/// Bind a socket inside the peer namespace, then return to ours.
fn peer_socket(addr: &str) -> UdpSocket {
    let ours = File::open("/proc/thread-self/ns/net").unwrap();
    let peer = File::open(env("RTPFLUX_E2E_PEER_NS")).unwrap();
    setns(&peer, CloneFlags::CLONE_NEWNET).unwrap();
    let s = UdpSocket::bind(addr);
    setns(&ours, CloneFlags::CLONE_NEWNET).unwrap();
    let s = s.unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}

fn packet(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 160, 0xca, 0xfe, 0xba, 0xbe]);
    p.extend(std::iter::repeat_n(u8::try_from(seq % 251).unwrap(), 160));
    p
}

/// Send `n` packets each way and check they arrive intact from the relay's
/// ports.
fn exchange(a: &UdpSocket, b: &UdpSocket, pa: SocketAddr, pb: SocketAddr, from: u16, n: u16) {
    let mut buf = [0u8; 2048];
    for seq in from..from + n {
        let p = packet(seq);
        a.send_to(&p, pa).unwrap();
        let (len, src) = b.recv_from(&mut buf).expect("A -> B relayed");
        assert_eq!((&buf[..len], src), (&p[..], pb), "A -> B packet {seq}");
        b.send_to(&p, pb).unwrap();
        let (len, src) = a.recv_from(&mut buf).expect("B -> A relayed");
        assert_eq!((&buf[..len], src), (&p[..], pa), "B -> A packet {seq}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The relay's configuration: interfaces 0–3 are `10.77.0.1`, `10.78.0.1`,
/// `fd77::1`, `fd78::1`; XDP on rfx0 and rfx2.
fn config() -> Config {
    let toml = format!(
        r#"
        [[interface]]
        name = "a4"
        address = "10.77.0.1"
        [[interface]]
        name = "b4"
        address = "10.78.0.1"
        [[interface]]
        name = "a6"
        address = "fd77::1"
        [[interface]]
        name = "b6"
        address = "fd78::1"
        [ports]
        min = 46000
        max = 46063
        [sessions]
        max = 16
        timeout = 3
        silent_timeout = 3
        [runtime]
        workers = 1
        [xdp]
        enabled = true
        devices = ["rfx0", "rfx2"]
        mode = "{}"
        object = "{}"
        "#,
        std::env::var("RTPFLUX_XDP_MODE").unwrap_or_else(|_| "generic".to_owned()),
        env("RTPFLUX_XDP_OBJECT")
    );
    Config::from_toml(&toml).unwrap()
}

fn side(s: &UdpSocket, interface: usize) -> Side {
    Side {
        interface: rtpflux::relay::InterfaceId::new(interface),
        rtp: Some(s.local_addr().unwrap()),
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

#[test]
#[ignore = "needs root and the namespaces of scripts/xdp-e2e.sh"]
fn calls_move_to_xdp_and_stay_alive() {
    let mut relay = Relay::start(&config()).expect("relay with XDP starts");
    let a = peer_socket("10.77.0.2:0");
    let b = peer_socket("10.77.0.3:0");
    let ports = relay.create_call(side(&a, 0), side(&b, 0)).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    // 1. Userspace relays the first packets; the call settles.
    eprintln!("step 1: userspace relays the first packets");
    userspace_first(&mut relay, &a, &b, ports.a, ports.b, 0, "one device");
    let in_userspace = relay.totals().forwarded;

    // 2. After a sweep the call is offloaded: packets keep flowing, intact,
    //    but userspace no longer forwards them.
    std::thread::sleep(Duration::from_millis(2_500));
    eprintln!("step 2: the kernel relays them (XDP_TX)");
    exchange(&a, &b, ports.a, ports.b, 20, 50);
    assert_eq!(
        relay.totals().forwarded,
        in_userspace,
        "the kernel relayed them"
    );

    // 3. Traffic only through XDP for longer than the 3 s idle timeout: the
    //    counters keep the call alive.
    let until = Instant::now() + Duration::from_secs(5);
    let mut seq = 70;
    while Instant::now() < until {
        exchange(&a, &b, ports.a, ports.b, seq, 5);
        seq += 5;
    }
    assert_eq!(
        relay.totals().active_calls,
        1,
        "kernel-relayed traffic keeps the call"
    );
    // The kernel's counters reach the call's (`query`, polled every second).
    std::thread::sleep(Duration::from_millis(1_500));
    let legs = relay.query(ports.id).expect("query the call");
    let relayed = u64::from(seq);
    for (name, leg) in [("A", &legs[0]), ("B", &legs[2])] {
        assert_eq!(
            leg.packets, relayed,
            "packets from {name}: userspace and kernel"
        );
        assert_eq!(leg.octets, relayed * 172, "UDP payload octets from {name}");
    }
    eprintln!("step 3: {relayed} packets each way counted, userspace and kernel together");

    // 4. Silence: the call times out and its flows are removed.
    let deadline = Instant::now() + Duration::from_secs(8);
    while relay.totals().active_calls > 0 {
        assert!(Instant::now() < deadline, "call did not time out");
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_millis(1_500)); // the controller removes the flows
    a.send_to(&packet(9_999), ports.a).unwrap();
    b.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut buf = [0u8; 2048];
    assert!(
        b.recv_from(&mut buf).is_err(),
        "nothing is relayed after the call ended"
    );
}

/// The first 20 packets each way, the first 9 certainly by userspace: a
/// call is offered to the kernel only once each side sent
/// `OFFLOAD_MIN_PACKETS` (10), at a worker's sweep (every second), which
/// may come before the 20th. `before`: userspace's forwards so far.
fn userspace_first(
    relay: &mut Relay,
    a: &UdpSocket,
    b: &UdpSocket,
    pa: SocketAddr,
    pb: SocketAddr,
    before: u64,
    what: &str,
) {
    exchange(a, b, pa, pb, 0, 9);
    assert_eq!(
        relay.totals().forwarded - before,
        18,
        "{what}: userspace relays the first packets"
    );
    // Settling: by userspace or, after a sweep, already by the kernel.
    exchange(a, b, pa, pb, 9, 11);
}

/// One call: userspace relays the first packets, the kernel the rest
/// (userspace forwards nothing more), and the kernel's counters reach the
/// call's.
fn offloaded_call(relay: &mut Relay, (a, ia): (&str, usize), (b, ib): (&str, usize), what: &str) {
    let (a, b) = (peer_socket(a), peer_socket(b));
    let ports = relay.create_call(side(&a, ia), side(&b, ib)).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let before = relay.totals().forwarded;
    userspace_first(relay, &a, &b, ports.a, ports.b, before, what);
    let in_userspace = relay.totals().forwarded;
    std::thread::sleep(Duration::from_millis(2_500));
    exchange(&a, &b, ports.a, ports.b, 20, 50);
    assert_eq!(
        relay.totals().forwarded,
        in_userspace,
        "{what}: the kernel relayed them"
    );
    std::thread::sleep(Duration::from_millis(1_500));
    let legs = relay.query(ports.id).expect("query the call");
    assert_eq!(
        (legs[0].packets, legs[2].packets),
        (70, 70),
        "{what}: counters"
    );
    eprintln!("{what}: offloaded, 70 packets each way intact");
    relay.delete_call(ports.id).unwrap();
}

#[test]
#[ignore = "needs root and the namespaces of scripts/xdp-e2e.sh"]
fn both_families_on_one_device_and_across_devices() {
    let mut relay = Relay::start(&config()).expect("relay with XDP starts");
    offloaded_call(
        &mut relay,
        ("[fd77::2]:0", 2),
        ("[fd77::3]:0", 2),
        "IPv6, XDP_TX",
    );
    offloaded_call(
        &mut relay,
        ("10.77.0.2:0", 0),
        ("10.78.0.2:0", 1),
        "IPv4, XDP_REDIRECT",
    );
    offloaded_call(
        &mut relay,
        ("[fd77::2]:0", 2),
        ("[fd78::2]:0", 3),
        "IPv6, XDP_REDIRECT",
    );
}
