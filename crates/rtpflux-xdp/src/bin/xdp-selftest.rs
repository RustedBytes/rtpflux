//! Runs the XDP program in the kernel on generated frames
//! (`BPF_PROG_TEST_RUN`: no interface is attached, no traffic is touched)
//! and checks every result against the safe reference implementation in
//! `rtpflux-xdp-common`.
//!
//! Usage (needs root, or `CAP_BPF` + `CAP_NET_ADMIN`):
//!
//!     sudo target/debug/xdp-selftest [OBJECT] [--cases N]
//!
//! `OBJECT` defaults to the release build of `rtpflux-xdp-ebpf`.

use rtpflux_xdp::loader::{FastPath, XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX};
use rtpflux_xdp::testframe::{Spec, build, ip_checksum_ok, udp_checksum_ok};
use rtpflux_xdp_common::{
    Decision, FlowAction, FlowKey, RECORD_MAX, SteerRange, Verdict, classify, decide, flags,
    headers_len, mapped, parse_record, rewrite, unmapped,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::ExitCode;

/// `BPF_PROG_TEST_RUN` runs a frame as if it arrived on the loopback device.
const TEST_RUN_IFINDEX: u32 = 1;

const DEFAULT_OBJECT: &str =
    "crates/rtpflux-xdp-ebpf/target/bpfel-unknown-none/release/rtpflux-xdp";

/// Deterministic xorshift generator (reproducible failures).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }
    fn addr(&mut self) -> [u8; 4] {
        [self.byte(), self.byte(), self.byte(), self.byte()]
    }
    /// A global unicast IPv6 address (never IPv4-mapped).
    fn addr6(&mut self) -> [u8; 16] {
        let mut a = [0u8; 16];
        for b in &mut a {
            *b = self.byte();
        }
        a[0] = 0x20;
        a
    }
    fn ip(&mut self, v6: bool) -> IpAddr {
        if v6 {
            IpAddr::V6(Ipv6Addr::from(self.addr6()))
        } else {
            IpAddr::V4(Ipv4Addr::from(self.addr()))
        }
    }
    fn below(&mut self, n: u64) -> usize {
        usize::try_from(self.next() % n).unwrap_or(0)
    }
}

fn key_of(frame: &[u8]) -> FlowKey {
    match classify(frame) {
        Verdict::Lookup(k) => k,
        Verdict::Pass => FlowKey {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: 0,
            dst_port: 0,
        },
    }
}

/// An action of `key`'s family: back out of the arrival device, or (every
/// fifth) redirected to another one.
fn random_action(rng: &mut Rng, key: &FlowKey, i: usize) -> FlowAction {
    let v6 = unmapped(&key.src_addr).is_none();
    let addr = |rng: &mut Rng| if v6 { rng.addr6() } else { mapped(rng.addr()) };
    FlowAction {
        new_src_addr: addr(rng),
        new_dst_addr: addr(rng),
        new_src_port: u16::from_ne_bytes(rng.u16().to_be_bytes()),
        new_dst_port: u16::from_ne_bytes(rng.u16().to_be_bytes()),
        src_mac: [0x02, 0, 0, 0, rng.byte(), rng.byte()],
        dst_mac: [0x02, 0, 0, 1, rng.byte(), rng.byte()],
        ifindex: match i % 5 {
            0 => 0,
            4 => 1000 + u32::try_from(i).unwrap_or(0),
            _ => TEST_RUN_IFINDEX,
        },
        flags: 0,
        event_pt: 0,
        reserved: [0; 2],
    }
}

fn rtp_payload(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut p: Vec<u8> = (0..len.max(1)).map(|_| rng.byte()).collect();
    p[0] = 0x80 | (p[0] & 0x3f); // version 2
    p
}

struct Report {
    checked: usize,
    failures: Vec<String>,
}

impl Report {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        self.checked += 1;
        if !ok {
            self.failures.push(what());
        }
    }
}

/// Hits: the kernel's rewrite equals the reference rewrite, byte for byte;
/// then the same frames as misses.
fn check_hits(
    fp: &mut FastPath,
    rng: &mut Rng,
    rep: &mut Report,
    cases: usize,
) -> Result<(), rtpflux_xdp::loader::Error> {
    let mut out = vec![0u8; 4096];

    // 1. Hits: the kernel's rewrite equals the reference rewrite, byte for byte.
    for i in 0..cases {
        let len = 12 + rng.below(300);
        let payload = rtp_payload(rng, len);
        let v6 = i % 2 == 1;
        let frame = build(&Spec {
            src: rng.ip(v6),
            dst: rng.ip(v6),
            sport: rng.u16(),
            dport: rng.u16(),
            ttl: 1 + rng.byte() % 128,
            udp_checksum: v6 || i % 4 != 0,
            payload: &payload,
        });
        let key = key_of(&frame);
        let action = random_action(rng, &key, i);
        fp.insert(key, action)?;
        let r = fp.test_run(&frame, &mut out, 1)?;
        let got = &out[..r.len];
        let mut want = frame.clone();
        rewrite(&mut want, &key, &action);
        let want_action = if action.ifindex == 0 || action.ifindex == TEST_RUN_IFINDEX {
            XDP_TX
        } else {
            XDP_REDIRECT
        };
        rep.check(r.action == want_action, || {
            format!("hit {i}: action {} (want {want_action})", r.action)
        });
        rep.check(got == want.as_slice(), || {
            format!("hit {i}: kernel output differs from the reference rewrite")
        });
        rep.check(ip_checksum_ok(got) && udp_checksum_ok(got), || {
            format!("hit {i}: invalid checksum after rewrite")
        });
        let h = headers_len(&key);
        rep.check(got.len() > h && got[h..] == frame[h..], || {
            format!("hit {i}: payload changed")
        });
        // The program counted exactly this frame.
        let st = fp.stats(key)?;
        rep.check(
            st.is_some_and(|s| s.packets == 1 && s.bytes == frame.len() as u64 && s.last_ns > 0),
            || {
                format!(
                    "hit {i}: counters {st:?}, want 1 packet of {} octets",
                    frame.len()
                )
            },
        );

        // The same frame without its flow is passed up untouched, and its
        // counters are gone.
        fp.remove(key)?;
        rep.check(fp.stats(key)?.is_none(), || {
            format!("miss {i}: counters left behind")
        });
        let r = fp.test_run(&frame, &mut out, 1)?;
        rep.check(r.action == XDP_PASS && out[..r.len] == frame[..], || {
            format!("miss {i}: not passed unchanged")
        });
    }
    Ok(())
}

/// Frames the fast path must leave to the stack, even with a matching flow.
fn check_passes(
    fp: &mut FastPath,
    rng: &mut Rng,
    rep: &mut Report,
) -> Result<(), rtpflux_xdp::loader::Error> {
    let mut out = vec![0u8; 4096];
    // 2. Frames the fast path must leave to the stack, even with a matching flow.
    let payload = rtp_payload(rng, 40);
    let base = build(&Spec {
        src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        sport: 4000,
        dport: 30000,
        ttl: 60,
        udp_checksum: true,
        payload: &payload,
    });
    let key = key_of(&base);
    let action = random_action(rng, &key, 1);
    fp.insert(key, action)?;
    let mut cases_pass: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut stun = base.clone();
    stun[42] = 0x00;
    stun[43] = 0x01;
    cases_pass.push(("STUN payload", stun));
    let mut opts = base.clone();
    opts[14] = 0x46;
    cases_pass.push(("IP options", opts));
    let mut mf = base.clone();
    mf[20] |= 0x20;
    cases_pass.push(("more-fragments flag", mf));
    let mut off = base.clone();
    off[21] = 0x08;
    cases_pass.push(("fragment offset", off));
    let mut tcp = base.clone();
    tcp[23] = 6;
    cases_pass.push(("TCP", tcp));
    let mut v6 = base.clone();
    v6[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    cases_pass.push(("IPv4 under the IPv6 ethertype", v6));
    cases_pass.push(("no payload octet", base[..42].to_vec()));
    cases_pass.push(("truncated UDP header", base[..38].to_vec()));
    cases_pass.push(("Ethernet header only", base[..14].to_vec()));
    for (name, frame) in &cases_pass {
        let r = fp.test_run(frame, &mut out, 1)?;
        rep.check(r.action == XDP_PASS && out[..r.len] == frame[..], || {
            format!("{name}: not passed unchanged (action {})", r.action)
        });
    }
    // And the unmodified base frame does hit, so the cases above were real.
    let r = fp.test_run(&base, &mut out, 1)?;
    rep.check(r.action == XDP_TX, || {
        "base frame: expected XDP_TX".to_owned()
    });
    fp.remove(key)?;

    // IPv6 frames the fast path must leave alone.
    let base6 = build(&Spec {
        src: IpAddr::V6("2001:db8::10".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
        dst: IpAddr::V6("2001:db8::1".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
        sport: 4000,
        dport: 30000,
        ttl: 60,
        udp_checksum: true,
        payload: &payload,
    });
    let key6 = key_of(&base6);
    fp.insert(key6, random_action(rng, &key6, 1))?;
    let mut ext = base6.clone();
    ext[20] = 0; // a hop-by-hop options header
    let mut zero = base6.clone();
    zero[60..62].copy_from_slice(&[0, 0]);
    let mut stun6 = base6.clone();
    stun6[62] = 0;
    for (name, frame) in [
        ("IPv6 extension header", ext),
        ("IPv6 zero UDP checksum", zero),
        ("IPv6 STUN payload", stun6),
        ("IPv6 no payload octet", base6[..62].to_vec()),
    ] {
        let r = fp.test_run(&frame, &mut out, 1)?;
        rep.check(r.action == XDP_PASS && out[..r.len] == frame[..], || {
            format!("{name}: not passed unchanged (action {})", r.action)
        });
    }
    let r = fp.test_run(&base6, &mut out, 1)?;
    rep.check(r.action == XDP_TX, || {
        "IPv6 base frame: expected XDP_TX".to_owned()
    });
    fp.remove(key6)?;
    Ok(())
}

/// Flows with flags: telephone events go up, dropped flows are dropped and
/// counted, the rest is relayed; as `decide` says.
fn check_flags(
    fp: &mut FastPath,
    rng: &mut Rng,
    rep: &mut Report,
    cases: usize,
) -> Result<(), rtpflux_xdp::loader::Error> {
    let mut out = vec![0u8; 4096];
    for i in 0..cases {
        let len = 12 + rng.below(200);
        let mut payload = rtp_payload(rng, len);
        let event_pt = 96 + rng.byte() % 32;
        // Half the frames carry the event type (with a random marker).
        if i % 2 == 0 {
            payload[1] = (rng.byte() & 0x80) | event_pt;
        }
        let v6 = i % 3 == 1;
        let frame = build(&Spec {
            src: rng.ip(v6),
            dst: rng.ip(v6),
            sport: rng.u16(),
            dport: rng.u16(),
            ttl: 64,
            udp_checksum: true,
            payload: &payload,
        });
        let key = key_of(&frame);
        let mut action = random_action(rng, &key, i);
        action.flags = [
            0,
            flags::DROP,
            flags::EVENTS_UP,
            flags::DROP | flags::EVENTS_UP,
        ][i % 4];
        action.event_pt = event_pt;
        fp.insert(key, action)?;
        let r = fp.test_run(&frame, &mut out, 1)?;
        let decision = decide(&action, Some(payload[1]));
        let st = fp.stats(key)?;
        match decision {
            Decision::Up => {
                rep.check(r.action == XDP_PASS && out[..r.len] == frame[..], || {
                    format!("flags {i}: event not passed up unchanged ({})", r.action)
                });
                rep.check(st.is_none_or(|s| s.packets == 0), || {
                    format!("flags {i}: an event passed up was counted")
                });
            }
            Decision::Drop => {
                rep.check(r.action == XDP_DROP, || {
                    format!("flags {i}: action {} (want XDP_DROP)", r.action)
                });
                rep.check(st.is_some_and(|s| s.packets == 1), || {
                    format!("flags {i}: dropped frame not counted")
                });
            }
            Decision::Forward => {
                let mut want = frame;
                rewrite(&mut want, &key, &action);
                rep.check(
                    matches!(r.action, XDP_TX | XDP_REDIRECT) && out[..r.len] == want[..],
                    || format!("flags {i}: not relayed as the reference ({})", r.action),
                );
            }
        }
        fp.remove(key)?;
    }
    Ok(())
}

/// Recorded flows: each relayed or dropped datagram is copied into the
/// ring with its flow and payload (cut at `RECORD_MAX`); events going up
/// are not (the relay records them itself).
fn check_records(
    fp: &mut FastPath,
    rng: &mut Rng,
    rep: &mut Report,
    cases: usize,
) -> Result<(), rtpflux_xdp::loader::Error> {
    let mut out = vec![0u8; 4096];
    fp.drain_records(|_| {});
    for i in 0..cases {
        // Some payloads longer than a record holds.
        let len = if i % 7 == 0 {
            RECORD_MAX + 1 + rng.below(100)
        } else {
            12 + rng.below(300)
        };
        let mut payload = rtp_payload(rng, len);
        let up = i % 5 == 0;
        if up {
            payload[1] = 101;
        } else {
            payload[1] &= 0x7f;
            if payload[1] == 101 {
                payload[1] = 0;
            }
        }
        let v6 = i % 2 == 1;
        let frame = build(&Spec {
            src: rng.ip(v6),
            dst: rng.ip(v6),
            sport: rng.u16(),
            dport: rng.u16(),
            ttl: 64,
            udp_checksum: true,
            payload: &payload,
        });
        let key = key_of(&frame);
        let mut action = random_action(rng, &key, i);
        action.flags = flags::RECORD | flags::EVENTS_UP | if i % 3 == 0 { flags::DROP } else { 0 };
        action.event_pt = 101;
        fp.insert(key, action)?;
        let _ = fp.test_run(&frame, &mut out, 1)?;
        fp.remove(key)?;
        let mut got = Vec::new();
        fp.drain_records(|b| {
            if let Some((k, t, data)) = parse_record(b) {
                got.push((k, t, data.to_vec()));
            }
        });
        if up {
            rep.check(got.is_empty(), || {
                format!("record {i}: an event going up was recorded")
            });
            continue;
        }
        let want = &payload[..payload.len().min(RECORD_MAX)];
        rep.check(
            got.len() == 1 && got[0].0 == key && got[0].1 > 0 && got[0].2 == want,
            || {
                format!(
                    "record {i}: {} samples, want one of {} octets",
                    got.len(),
                    want.len()
                )
            },
        );
    }
    // A short frame padded to Ethernet's 60 octets: the padding is not
    // recorded (the UDP length says where the payload ends).
    let payload = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9, 5, 5];
    let mut frame = build(&Spec {
        src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        dst: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        sport: 4000,
        dport: 30_000,
        ttl: 64,
        udp_checksum: true,
        payload: &payload,
    });
    frame.resize(60, 0);
    let key = key_of(&frame);
    let mut action = random_action(rng, &key, 1);
    action.flags = flags::RECORD;
    fp.insert(key, action)?;
    let _ = fp.test_run(&frame, &mut out, 1)?;
    fp.remove(key)?;
    let mut got = Vec::new();
    fp.drain_records(|b| {
        if let Some((_, _, data)) = parse_record(b) {
            got.push(data.to_vec());
        }
    });
    rep.check(got == [payload.to_vec()], || {
        format!(
            "padded frame: recorded {got:?}, want the {} payload octets",
            payload.len()
        )
    });
    Ok(())
}

/// Steering: a datagram to a steered port with no `AF_XDP` socket on its
/// queue falls back to the stack; one for another device, port or address
/// is not steered; a relayed flow wins. With the `af-xdp` feature, a socket
/// on the loopback's queue 0 receives the redirect.
fn check_steering(fp: &mut FastPath, rep: &mut Report) -> Result<(), rtpflux_xdp::loader::Error> {
    let mut out = vec![0u8; 4096];
    let stun = [
        0u8, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ];
    let relay = Ipv4Addr::new(198, 51, 100, 1);
    let to = |port: u16, dst: Ipv4Addr| {
        build(&Spec {
            src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            dst: IpAddr::V4(dst),
            sport: 4000,
            dport: port,
            ttl: 64,
            udp_checksum: true,
            payload: &stun,
        })
    };
    let addr = mapped(relay.octets());
    let range = |ifindex| SteerRange {
        min_port: 30_000,
        max_port: 30_099,
        ifindex,
    };
    fp.steer(addr, range(TEST_RUN_IFINDEX))?;
    for (name, frame) in [
        ("steered, no socket", to(30_010, relay)),
        ("port beyond the range", to(30_100, relay)),
        (
            "another address",
            to(30_010, Ipv4Addr::new(198, 51, 100, 2)),
        ),
    ] {
        let r = fp.test_run(&frame, &mut out, 1)?;
        rep.check(r.action == XDP_PASS && out[..r.len] == frame[..], || {
            format!("steering, {name}: action {} (want XDP_PASS)", r.action)
        });
    }
    #[cfg(feature = "af-xdp")]
    match rtpflux_xdp::xsk::XskReceiver::open(TEST_RUN_IFINDEX, 0, 64) {
        Ok(sock) => {
            fp.set_socket(0, std::os::fd::AsRawFd::as_raw_fd(&sock))?;
            let r = fp.test_run(&to(30_010, relay), &mut out, 1)?;
            rep.check(r.action == XDP_REDIRECT, || {
                format!(
                    "steering to a socket: action {} (want XDP_REDIRECT)",
                    r.action
                )
            });
            // Another device's datagrams stay with the stack.
            fp.steer(addr, range(TEST_RUN_IFINDEX + 1))?;
            let r = fp.test_run(&to(30_010, relay), &mut out, 1)?;
            rep.check(r.action == XDP_PASS, || {
                format!(
                    "steering, another device: action {} (want XDP_PASS)",
                    r.action
                )
            });
            fp.steer(addr, range(TEST_RUN_IFINDEX))?;
            // A relayed RTP flow on a steered port wins over steering.
            let rtp = build(&Spec {
                src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                dst: IpAddr::V4(relay),
                sport: 4000,
                dport: 30_010,
                ttl: 64,
                udp_checksum: true,
                payload: &[0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 7],
            });
            let key = key_of(&rtp);
            let mut action = random_action(&mut Rng(7), &key, 1);
            action.ifindex = 0;
            fp.insert(key, action)?;
            let r = fp.test_run(&rtp, &mut out, 1)?;
            rep.check(r.action == XDP_TX, || {
                format!(
                    "a flow on a steered port: action {} (want XDP_TX)",
                    r.action
                )
            });
            fp.remove(key)?;
        }
        Err(e) => eprintln!("note: no AF_XDP socket on lo ({e}); redirect not checked"),
    }
    fp.unsteer(addr)?;
    Ok(())
}

/// Replacing a flow's action (new flags: blocking, recording) keeps its
/// counters: the relay reads them as running totals.
fn check_replace(
    fp: &mut FastPath,
    rng: &mut Rng,
    rep: &mut Report,
) -> Result<(), rtpflux_xdp::loader::Error> {
    let mut out = vec![0u8; 4096];
    let payload = rtp_payload(rng, 172);
    let frame = build(&Spec {
        src: rng.ip(false),
        dst: rng.ip(false),
        sport: rng.u16(),
        dport: rng.u16(),
        ttl: 64,
        udp_checksum: true,
        payload: &payload,
    });
    let key = key_of(&frame);
    let mut action = random_action(rng, &key, 1);
    fp.insert(key, action)?;
    // Repetitions reuse packet data, so the first rewrite changes the
    // tuple used for subsequent lookups. Start each run with the original.
    for _ in 0..3 {
        fp.test_run(&frame, &mut out, 1)?;
    }
    let before = fp.stats(key)?.map_or(0, |s| s.packets);
    action.flags = flags::DROP;
    fp.insert(key, action)?;
    fp.test_run(&frame, &mut out, 1)?;
    let after = fp.stats(key)?.map_or(0, |s| s.packets);
    rep.check(before == 3 && after == 4, || {
        format!("replace: counters {before} then {after}, want 3 then 4")
    });
    fp.remove(key)?;
    Ok(())
}

fn run(fp: &mut FastPath, cases: usize) -> Result<Report, rtpflux_xdp::loader::Error> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut rep = Report {
        checked: 0,
        failures: Vec::new(),
    };
    check_hits(fp, &mut rng, &mut rep, cases)?;
    check_passes(fp, &mut rng, &mut rep)?;
    check_flags(fp, &mut rng, &mut rep, cases / 4)?;
    check_records(fp, &mut rng, &mut rep, cases / 4)?;
    check_steering(fp, &mut rep)?;
    check_replace(fp, &mut rng, &mut rep)?;
    Ok(rep)
}

/// Per-packet cost of a hit and a miss, measured by the kernel. The hit uses
/// a flow whose rewrite maps the frame to itself, so every repetition hits.
fn timing(fp: &mut FastPath) -> Result<(u128, u128), rtpflux_xdp::loader::Error> {
    const REPEAT: u32 = 100_000;
    let payload = [0x80u8; 172]; // a 20 ms G.711 packet: 12-octet header + 160
    let frame = build(&Spec {
        src: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        sport: 4000,
        dport: 4000,
        ttl: 64,
        udp_checksum: true,
        payload: &payload,
    });
    let key = key_of(&frame);
    let action = FlowAction {
        new_src_addr: key.src_addr,
        new_dst_addr: key.dst_addr,
        new_src_port: key.src_port,
        new_dst_port: key.dst_port,
        src_mac: [0x02, 0, 0, 0, 0, 0xbb],
        dst_mac: [0x02, 0, 0, 0, 0, 0xaa],
        ifindex: 0,
        flags: 0,
        event_pt: 0,
        reserved: [0; 2],
    };
    let mut out = vec![0u8; 4096];
    fp.insert(key, action)?;
    let hit = fp.test_run(&frame, &mut out, REPEAT)?;
    fp.remove(key)?;
    let miss = fp.test_run(&frame, &mut out, REPEAT)?;
    Ok((hit.nanos, miss.nanos))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut object = DEFAULT_OBJECT.to_owned();
    let mut cases = 2_000usize;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--cases" => {
                let Some(n) = it.next().and_then(|n| n.parse().ok()) else {
                    eprintln!("--cases needs a number");
                    return ExitCode::FAILURE;
                };
                cases = n;
            }
            "-h" | "--help" => {
                println!(
                    "usage: xdp-selftest [OBJECT] [--cases N]   (default object: {DEFAULT_OBJECT})"
                );
                return ExitCode::SUCCESS;
            }
            path => path.clone_into(&mut object),
        }
    }
    let bytes = match std::fs::read(&object) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "cannot read {object}: {e} (build it: cd crates/rtpflux-xdp-ebpf && cargo build --release)"
            );
            return ExitCode::FAILURE;
        }
    };
    let mut fp = match FastPath::load(&bytes) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("{e} (run as root?)");
            return ExitCode::FAILURE;
        }
    };
    let rep = match run(&mut fp, cases) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match timing(&mut fp) {
        Ok((hit, miss)) => println!("per packet (kernel-measured): hit {hit} ns, miss {miss} ns"),
        Err(e) => eprintln!("timing: {e}"),
    }
    for f in rep.failures.iter().take(20) {
        println!("FAIL {f}");
    }
    println!("{} checks, {} failed", rep.checked, rep.failures.len());
    if rep.failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
