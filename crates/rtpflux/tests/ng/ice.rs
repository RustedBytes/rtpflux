//! Full ICE through the relay (RFC 8445): endpoints running an ICE agent
//! (or an ICE-lite responder) on real sockets, the relay's agents towards
//! them, media only on valid pairs, restarts and trickled candidates.

#[allow(clippy::wildcard_imports)]
use crate::common::*;
use rtpflux_core::ice::{Agent, Config, RemoteCandidate, Role, TA_MS};
use rtpflux_core::stun;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// An endpoint: its socket, and a full agent or ICE-lite credentials.
struct Peer {
    sock: UdpSocket,
    agent: Option<Agent>,
    lite: Option<(&'static [u8], &'static [u8])>,
    /// RTP received (STUN is handled).
    rtp: Vec<Vec<u8>>,
    /// STUN requests received, raw.
    stun_requests: usize,
    seed: u64,
}

impl Peer {
    fn new() -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        Peer {
            sock,
            agent: None,
            lite: None,
            rtp: Vec::new(),
            stun_requests: 0,
            seed: 7,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.sock.local_addr().unwrap()
    }

    /// Send what the agent has due and handle what arrived.
    fn step(&mut self, now: u64) {
        let mut out = [0u8; 1500];
        let mut buf = [0u8; 2048];
        while let Ok((n, src)) = self.sock.recv_from(&mut buf) {
            let msg = &buf[..n];
            if msg.first().is_some_and(|&b| b < 4) {
                if msg[0] & 0x01 == 0 && msg[1] & 0x10 == 0 {
                    self.stun_requests += 1;
                }
                let reply = if let Some(a) = self.agent.as_mut() {
                    a.on_stun(now, 1, src, msg, &mut out)
                } else if let Some((ufrag, pwd)) = self.lite {
                    match stun::ice_lite(msg, stun::Credentials { ufrag, pwd }, src, &mut out) {
                        stun::Answer::Reply { len, .. } => Some(len),
                        stun::Answer::Ignore => None,
                    }
                } else {
                    None
                };
                if let Some(len) = reply {
                    self.sock.send_to(&out[..len], src).unwrap();
                }
            } else {
                self.rtp.push(msg.to_vec());
            }
        }
        if let Some(a) = self.agent.as_mut() {
            let seed = &mut self.seed;
            let mut random = |b: &mut [u8]| {
                for x in b {
                    *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    *x = (*seed >> 56) as u8;
                }
            };
            while let Some(t) = a.poll(now, &mut out, &mut random) {
                self.sock.send_to(&out[..t.len], t.dst).unwrap();
            }
        }
    }
}

/// Run the endpoints for `ms`; each sends `rtp` every 20 ms to `to` if set.
fn pump(peers: &mut [&mut Peer], ms: u64, media: &[(usize, SocketAddr)]) {
    let start = Instant::now();
    let mut next_rtp = 0;
    let mut seq: u16 = 0;
    while start.elapsed() < Duration::from_millis(ms) {
        let now = u64::try_from(start.elapsed().as_millis()).unwrap() + 1_000_000;
        for p in peers.iter_mut() {
            p.step(now);
        }
        if now >= next_rtp + 1_000_000 {
            for &(k, to) in media {
                seq = seq.wrapping_add(1);
                peers[k].sock.send_to(&rtp(seq), to).unwrap();
            }
            next_rtp += 20;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The value of attribute `name` in `sdp`.
fn attr<'a>(sdp: &'a str, name: &str) -> Option<&'a str> {
    sdp.split("\r\n")
        .find_map(|l| l.strip_prefix(&format!("a={name}:")))
}

/// The relay's first host candidate in `sdp`.
fn relay_candidate(sdp: &str) -> SocketAddr {
    let c = attr(sdp, "candidate").unwrap();
    let w: Vec<&str> = c.split(' ').collect();
    SocketAddr::new(w[4].parse().unwrap(), w[5].parse().unwrap())
}

fn full_agent(role: Role, local: (&[u8], &[u8]), sdp: &str) -> Agent {
    let mut a = Agent::new(&Config {
        role,
        tiebreaker: if role == Role::Controlling { 10 } else { 20 },
        local_ufrag: local.0,
        local_pwd: local.1,
        remote_ufrag: attr(sdp, "ice-ufrag").unwrap().as_bytes(),
        remote_pwd: attr(sdp, "ice-pwd").unwrap().as_bytes(),
        components: 1,
        v6: false,
        ta_ms: TA_MS,
    })
    .unwrap();
    a.add_remote(&RemoteCandidate {
        foundation: b"1",
        component: 1,
        priority: 2_130_706_431,
        addr: relay_candidate(sdp),
    });
    a
}

fn ice_sdp(port: u16, ufrag: &str, pwd: &str, extra: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n{extra}\
         m=audio {port} RTP/AVP 0\r\na=ice-ufrag:{ufrag}\r\na=ice-pwd:{pwd}\r\n\
         a=candidate:1 1 UDP 2130706431 127.0.0.1 {port} typ host\r\na=rtcp-mux\r\na=sendrecv\r\n"
    )
}

const UA: &[u8] = b"aaaa";
const PA: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaa";
const UB: &[u8] = b"bbbb";
const PB: &[u8] = b"bbbbbbbbbbbbbbbbbbbbbb";

/// Offer from A and answer from B, both ICE agents; the relay's SDP towards
/// each side.
fn set_up(
    srv: &Server,
    client: &UdpSocket,
    a: &Peer,
    b_sdp: impl Fn(&str) -> String,
) -> (String, String) {
    let offer = ice_sdp(a.addr().port(), "aaaa", "aaaaaaaaaaaaaaaaaaaaaa", "");
    let (r, to_b, _) = call(
        client,
        srv.addr,
        &request(
            "o1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"ice-call")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer.as_bytes())),
            ],
        ),
    );
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&to_b));
    let to_b = String::from_utf8(to_b).unwrap();
    let answer = b_sdp(&to_b);
    let (r, to_a, _) = call(
        client,
        srv.addr,
        &request(
            "a1",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"ice-call")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer.as_bytes())),
            ],
        ),
    );
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&to_a));
    (to_b, String::from_utf8(to_a).unwrap())
}

/// Two full agents: the relay is controlled towards A (the offerer
/// controls) and controlling towards B; both pairs are nominated, and
/// media flows only once they are valid.
#[test]
fn full_ice_on_both_sides() {
    let srv = server(51_000);
    let client = endpoint();
    let (mut a, mut b) = (Peer::new(), Peer::new());
    let b_port = b.addr().port();
    let (to_b, to_a) = set_up(&srv, &client, &a, |_| {
        ice_sdp(b_port, "bbbb", "bbbbbbbbbbbbbbbbbbbbbb", "")
    });
    // A full agent: no a=ice-lite, ice2.
    for sdp in [&to_b, &to_a] {
        assert!(!sdp.contains("a=ice-lite"), "{sdp}");
        assert!(sdp.contains("a=ice-options:ice2\r\n"), "{sdp}");
    }
    let (relay_a, relay_b) = (relay_candidate(&to_a), relay_candidate(&to_b));
    // Before any check: media from A is held (no valid pair towards B).
    a.sock.send_to(&rtp(1), relay_a).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    b.step(0);
    assert!(b.rtp.is_empty(), "media before ICE");
    a.agent = Some(full_agent(Role::Controlling, (UA, PA), &to_a));
    b.agent = Some(full_agent(Role::Controlled, (UB, PB), &to_b));
    pump(&mut [&mut a, &mut b], 2_500, &[]);
    assert_eq!(a.agent.as_ref().unwrap().selected(1), Some(relay_a));
    assert_eq!(b.agent.as_ref().unwrap().selected(1), Some(relay_b));
    // The relay checked B (B's agent saw requests) and answered A's.
    assert!(b.stun_requests > 0 && a.stun_requests > 0);
    // Media both ways.
    pump(&mut [&mut a, &mut b], 400, &[(0, relay_a), (1, relay_b)]);
    assert!(b.rtp.len() >= 10, "{}", b.rtp.len());
    assert!(a.rtp.len() >= 10, "{}", a.rtp.len());
}

/// An ICE-lite answerer: the relay controls and nominates.
#[test]
fn a_lite_answerer() {
    let srv = server(52_600);
    let client = endpoint();
    let (mut a, mut b) = (Peer::new(), Peer::new());
    let b_port = b.addr().port();
    let (to_b, to_a) = set_up(&srv, &client, &a, |_| {
        ice_sdp(b_port, "bbbb", "bbbbbbbbbbbbbbbbbbbbbb", "a=ice-lite\r\n")
    });
    let (relay_a, relay_b) = (relay_candidate(&to_a), relay_candidate(&to_b));
    a.agent = Some(full_agent(Role::Controlling, (UA, PA), &to_a));
    b.lite = Some((UB, PB));
    pump(&mut [&mut a, &mut b], 2_500, &[]);
    assert!(b.stun_requests > 0, "the relay checks the lite peer");
    pump(&mut [&mut a, &mut b], 400, &[(0, relay_a), (1, relay_b)]);
    assert!(
        b.rtp.len() >= 10 && a.rtp.len() >= 10,
        "{} {}",
        b.rtp.len(),
        a.rtp.len()
    );
}

/// A re-offer from A with new credentials restarts ICE: the relay answers
/// with new credentials too, media keeps flowing, and A's restarted agent
/// completes.
#[test]
fn ice_restart_on_reoffer() {
    let srv = server(52_800);
    let client = endpoint();
    let (mut a, mut b) = (Peer::new(), Peer::new());
    let b_port = b.addr().port();
    let (to_b, to_a) = set_up(&srv, &client, &a, |_| {
        ice_sdp(b_port, "bbbb", "bbbbbbbbbbbbbbbbbbbbbb", "")
    });
    let (relay_a, relay_b) = (relay_candidate(&to_a), relay_candidate(&to_b));
    a.agent = Some(full_agent(Role::Controlling, (UA, PA), &to_a));
    b.agent = Some(full_agent(Role::Controlled, (UB, PB), &to_b));
    pump(&mut [&mut a, &mut b], 2_000, &[]);
    let reoffer = ice_sdp(a.addr().port(), "AAAA", "AAAAAAAAAAAAAAAAAAAAAA", "")
        .replace("o=- 1 1", "o=- 1 2");
    let (r, _, _) = call(
        &client,
        srv.addr,
        &request(
            "o2",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"ice-call")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(reoffer.as_bytes())),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let answer =
        ice_sdp(b_port, "bbbb", "bbbbbbbbbbbbbbbbbbbbbb", "").replace("o=- 1 1", "o=- 1 2");
    let (r, to_a2, _) = call(
        &client,
        srv.addr,
        &request(
            "a2",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"ice-call")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer.as_bytes())),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let to_a2 = String::from_utf8(to_a2).unwrap();
    assert_ne!(
        attr(&to_a2, "ice-ufrag"),
        attr(&to_a, "ice-ufrag"),
        "new credentials"
    );
    assert_ne!(attr(&to_a2, "ice-pwd"), attr(&to_a, "ice-pwd"));
    // Media from B keeps reaching A during the restart.
    a.rtp.clear();
    pump(&mut [&mut a, &mut b], 300, &[(1, relay_b)]);
    assert!(a.rtp.len() >= 5, "{}", a.rtp.len());
    a.agent = Some(full_agent(
        Role::Controlling,
        (b"AAAA", b"AAAAAAAAAAAAAAAAAAAAAA"),
        &to_a2,
    ));
    pump(&mut [&mut a, &mut b], 2_000, &[]);
    assert_eq!(a.agent.as_ref().unwrap().selected(1), Some(relay_a));
    b.rtp.clear();
    pump(&mut [&mut a, &mut b], 300, &[(0, relay_a)]);
    assert!(b.rtp.len() >= 5, "{}", b.rtp.len());
}

/// Candidates trickled through `offer` with the `fragment` flag reach the
/// relay's agent (it checks them); a fragment of another generation does
/// not. The reply carries the relay's credentials towards the other side.
#[test]
fn trickled_candidates() {
    let srv = server(53_000);
    let client = endpoint();
    let (a, b, mut late) = (Peer::new(), Peer::new(), Peer::new());
    let (b_port, late_port) = (b.addr().port(), late.addr().port());
    let offer = ice_sdp(
        a.addr().port(),
        "aaaa",
        "aaaaaaaaaaaaaaaaaaaaaa",
        "a=ice-options:trickle\r\n",
    )
    .replace("m=audio", "a=group:BUNDLE 0\r\nm=audio")
    .replace("a=rtcp-mux\r\n", "a=rtcp-mux\r\na=mid:0\r\n");
    let (r, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "o1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"trickle")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer.as_bytes())),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let to_b = String::from_utf8(to_b).unwrap();
    let answer = ice_sdp(b_port, "bbbb", "bbbbbbbbbbbbbbbbbbbbbb", "")
        .replace("a=rtcp-mux\r\n", "a=rtcp-mux\r\na=mid:0\r\n");
    let (r, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "a1",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"trickle")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(answer.as_bytes())),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let to_a = String::from_utf8(to_a).unwrap();
    assert!(to_a.contains("a=ice-options:trickle ice2\r\n"), "{to_a}");
    let frag = |cookie: &str, ufrag: &str| {
        let body = format!(
            "a=ice-ufrag:{ufrag}\r\na=ice-pwd:aaaaaaaaaaaaaaaaaaaaaa\r\nm=audio 9 RTP/AVP 0\r\na=mid:0\r\n\
             a=candidate:2 1 UDP 2130706430 127.0.0.1 {late_port} typ host\r\na=end-of-candidates\r\n"
        );
        call(
            &client,
            srv.addr,
            &request(
                cookie,
                &[
                    ("command", V::S(b"offer")),
                    ("call-id", V::S(b"trickle")),
                    ("from-tag", V::S(b"f")),
                    ("flags", V::L(&[b"fragment"])),
                    ("sdp", V::S(body.as_bytes())),
                ],
            ),
        )
    };
    // Another generation: ignored.
    let (r, _, _) = frag("f1", "zzzz");
    assert_eq!(r, "ok");
    pump(&mut [&mut late], 500, &[]);
    assert_eq!(late.stun_requests, 0);
    // The current one: the relay checks the new candidate.
    let (r, reply, _) = frag("f2", "aaaa");
    assert_eq!(r, "ok");
    let reply = String::from_utf8(reply).unwrap();
    assert!(
        reply.contains("a=mid:0\r\n") && reply.contains("a=end-of-candidates\r\n"),
        "{reply}"
    );
    assert_eq!(
        attr(&reply, "ice-ufrag"),
        attr(&to_b, "ice-ufrag"),
        "the relay's towards B"
    );
    pump(&mut [&mut late], 600, &[]);
    assert!(late.stun_requests > 0);
}

/// `ICE-lite=forward`: lite towards B only.
#[test]
fn ice_lite_towards_one_side() {
    let srv = server(53_200);
    let client = endpoint();
    let offer = ice_sdp(5000, "aaaa", "aaaaaaaaaaaaaaaaaaaaaa", "");
    let (r, to_b, _) = call(
        &client,
        srv.addr,
        &request(
            "o1",
            &[
                ("command", V::S(b"offer")),
                ("call-id", V::S(b"lite-fwd")),
                ("from-tag", V::S(b"f")),
                ("sdp", V::S(offer.as_bytes())),
                ("ICE-lite", V::S(b"forward")),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let to_b = String::from_utf8(to_b).unwrap();
    assert!(
        to_b.contains("a=ice-lite\r\n") && !to_b.contains("ice2"),
        "{to_b}"
    );
    let (r, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "a1",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"lite-fwd")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                (
                    "sdp",
                    V::S(ice_sdp(6000, "bbbb", "bbbbbbbbbbbbbbbbbbbbbb", "").as_bytes()),
                ),
            ],
        ),
    );
    assert_eq!(r, "ok");
    let to_a = String::from_utf8(to_a).unwrap();
    assert!(
        !to_a.contains("a=ice-lite") && to_a.contains("ice2"),
        "{to_a}"
    );
}

/// A WebRTC offer bridged to a SIP profile: the phone gets no ICE (it was
/// asked for plain SIP media); `ICE=force` still gives it ICE. The browser
/// keeps its ICE either way.
#[test]
fn no_ice_towards_a_phone_bridged_from_webrtc() {
    let srv = server(58_200);
    let client = endpoint();
    let webrtc = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio 5000 UDP/TLS/RTP/SAVPF 0\r\na=ice-ufrag:aaaa\r\na=ice-pwd:aaaaaaaaaaaaaaaaaaaaaa\r\n\
         a=fingerprint:sha-256 AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD:AB:CD\r\n\
         a=setup:actpass\r\na=rtcp-mux\r\na=sendrecv\r\n";
    let offer = |cookie: &str, id: &[u8], ice: Option<&[u8]>| {
        let mut pairs = vec![
            ("command", V::S(b"offer")),
            ("call-id", V::S(id)),
            ("from-tag", V::S(b"f")),
            ("sdp", V::S(webrtc.as_bytes())),
            ("transport-protocol", V::S(b"RTP/AVP")),
        ];
        if let Some(i) = ice {
            pairs.push(("ICE", V::S(i)));
        }
        let (r, to_b, _) = call(&client, srv.addr, &request(cookie, &pairs));
        assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&to_b));
        String::from_utf8(to_b).unwrap()
    };
    let to_b = offer("o1", b"bridged", None);
    assert!(to_b.contains(" RTP/AVP 0\r\n"), "{to_b}");
    assert!(
        !to_b.contains("a=ice-ufrag") && !to_b.contains("a=candidate"),
        "{to_b}"
    );
    let (r, to_a, _) = call(
        &client,
        srv.addr,
        &request(
            "a1",
            &[
                ("command", V::S(b"answer")),
                ("call-id", V::S(b"bridged")),
                ("from-tag", V::S(b"f")),
                ("to-tag", V::S(b"t")),
                ("sdp", V::S(&sdp_for(6000))),
            ],
        ),
    );
    assert_eq!(r, "ok", "{}", String::from_utf8_lossy(&to_a));
    let to_a = String::from_utf8(to_a).unwrap();
    assert!(
        to_a.contains("a=ice-ufrag") && to_a.contains("a=candidate"),
        "{to_a}"
    );
    let forced = offer("o2", b"forced", Some(b"force"));
    assert!(forced.contains("a=ice-ufrag"), "{forced}");
}
