//! Agent tests: two agents (or an agent and a lite responder) wired in
//! memory, with a deterministic clock and random source.

use super::*;
use core::net::{IpAddr, Ipv4Addr};

fn addr(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), port)
}

const UA: &[u8] = b"aaaa";
const PA: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaa";
const UB: &[u8] = b"bbbb";
const PB: &[u8] = b"bbbbbbbbbbbbbbbbbbbbbb";

fn agent(
    role: Role,
    tb: u64,
    local: (&[u8], &[u8]),
    remote: (&[u8], &[u8]),
    components: u8,
) -> Agent {
    Agent::new(&Config {
        role,
        tiebreaker: tb,
        local_ufrag: local.0,
        local_pwd: local.1,
        remote_ufrag: remote.0,
        remote_pwd: remote.1,
        components,
        v6: false,
        ta_ms: TA_MS,
    })
    .unwrap()
}

/// The peer at the other end: a full agent or an ICE-lite responder.
#[allow(clippy::large_enum_variant)]
enum Peer {
    Full(Agent),
    Lite,
}

/// Agent A at `a_addr(c)`, peer B at `b_addr(c)`; `drop` decides, per
/// datagram, what is lost.
struct Net {
    a: Agent,
    b: Peer,
    now: u64,
    seed: u64,
    /// Drop datagrams towards B (`true`) or A at this time.
    drop: fn(u64, bool) -> bool,
    /// STUN requests that reached B.
    requests_to_b: usize,
}

fn a_addr(c: u8) -> SocketAddr {
    addr(1, 5000 + u16::from(c))
}

fn b_addr(c: u8) -> SocketAddr {
    addr(2, 6000 + u16::from(c))
}

fn comp_of(a: SocketAddr) -> u8 {
    u8::try_from(a.port() % 1000).unwrap()
}

fn next(seed: &mut u64, out: &mut [u8]) {
    for b in out {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *b = (*seed >> 56) as u8;
    }
}

impl Net {
    fn new(a: Agent, b: Peer) -> Self {
        Net {
            a,
            b,
            now: 0,
            seed: 1,
            drop: |_, _| false,
            requests_to_b: 0,
        }
    }

    /// Deliver `msg` from `src` to `dst`, and any reply back.
    fn deliver(&mut self, to_b: bool, src: SocketAddr, dst: SocketAddr, msg: &[u8]) {
        // Nobody listens at other addresses.
        let there = if to_b {
            b_addr(comp_of(dst))
        } else {
            a_addr(comp_of(dst))
        };
        if (self.drop)(self.now, to_b) || dst != there {
            return;
        }
        let mut out = [0u8; 1500];
        let now = self.now;
        let reply = if to_b {
            if msg[0] & 0x01 == 0 && msg[1] & 0x10 == 0 {
                self.requests_to_b += 1;
            }
            match &mut self.b {
                Peer::Full(b) => b.on_stun(now, comp_of(dst), src, msg, &mut out),
                Peer::Lite => {
                    match stun::ice_lite(msg, Credentials { ufrag: UB, pwd: PB }, src, &mut out) {
                        stun::Answer::Reply { len, .. } => Some(len),
                        stun::Answer::Ignore => None,
                    }
                }
            }
        } else {
            self.a.on_stun(now, comp_of(dst), src, msg, &mut out)
        };
        if let Some(len) = reply {
            let mut copy = [0u8; 1500];
            copy[..len].copy_from_slice(&out[..len]);
            self.deliver(!to_b, dst, src, &copy[..len]);
        }
    }

    /// Run until `until` ms in steps of 5 ms.
    fn run(&mut self, until: u64) {
        let mut out = [0u8; 1500];
        let mut msg = [0u8; 1500];
        while self.now < until {
            loop {
                let mut seed = self.seed;
                let t = self
                    .a
                    .poll(self.now, &mut out, &mut |b: &mut [u8]| next(&mut seed, b));
                self.seed = seed;
                let Some(t) = t else { break };
                msg[..t.len].copy_from_slice(&out[..t.len]);
                self.deliver(true, a_addr(t.component), t.dst, &msg[..t.len]);
            }
            loop {
                let mut seed = self.seed;
                let t = match &mut self.b {
                    Peer::Full(b) => {
                        b.poll(self.now, &mut out, &mut |b: &mut [u8]| next(&mut seed, b))
                    }
                    Peer::Lite => None,
                };
                self.seed = seed;
                let Some(t) = t else { break };
                msg[..t.len].copy_from_slice(&out[..t.len]);
                self.deliver(false, b_addr(t.component), t.dst, &msg[..t.len]);
            }
            self.now += 5;
        }
    }

    fn b(&self) -> &Agent {
        match &self.b {
            Peer::Full(b) => b,
            Peer::Lite => panic!("lite peer"),
        }
    }

    fn b_mut(&mut self) -> &mut Agent {
        match &mut self.b {
            Peer::Full(b) => b,
            Peer::Lite => panic!("lite peer"),
        }
    }
}

fn host(c: u8, at: SocketAddr) -> RemoteCandidate<'static> {
    RemoteCandidate {
        foundation: b"1",
        component: c,
        priority: checklist::candidate_priority(126, 65_535, u32::from(c)),
        addr: at,
    }
}

fn wired(role_a: Role, tb_a: u64, role_b: Role, tb_b: u64, components: u8) -> Net {
    let mut a = agent(role_a, tb_a, (UA, PA), (UB, PB), components);
    let mut b = agent(role_b, tb_b, (UB, PB), (UA, PA), components);
    for c in 1..=components {
        assert!(a.add_remote(&host(c, b_addr(c))));
        assert!(b.add_remote(&host(c, a_addr(c))));
    }
    Net::new(a, Peer::Full(b))
}

#[test]
fn full_agents_agree_on_the_pair() {
    let mut n = wired(Role::Controlling, 1, Role::Controlled, 2, 1);
    n.run(3_000);
    assert_eq!(n.a.selected(1), Some(b_addr(1)));
    assert_eq!(n.b().selected(1), Some(a_addr(1)));
    assert_eq!(n.a.target(1), Some(b_addr(1)));
    assert_eq!(n.b().target(1), Some(a_addr(1)));
    assert_eq!(n.a.state(), ListState::Completed);
    assert_eq!(n.b().state(), ListState::Completed);
    assert_eq!(n.a.stats.nominations, 1);
}

#[test]
fn two_components() {
    let mut n = wired(Role::Controlling, 1, Role::Controlled, 2, 2);
    n.run(3_000);
    for c in 1..=2 {
        assert_eq!(n.a.selected(c), Some(b_addr(c)));
        assert_eq!(n.b().selected(c), Some(a_addr(c)));
    }
    assert_eq!(n.b().state(), ListState::Completed);
}

#[test]
fn role_conflicts_resolve_by_tiebreaker() {
    for (ra, rb) in [
        (Role::Controlling, Role::Controlling),
        (Role::Controlled, Role::Controlled),
    ] {
        let mut n = wired(ra, 10, rb, 20, 1);
        n.run(4_000);
        // B has the larger tie-breaker: it ends controlling.
        assert_eq!(n.b().role(), Role::Controlling, "{ra:?}");
        assert_eq!(n.a.role(), Role::Controlled, "{ra:?}");
        assert_eq!(n.a.selected(1), Some(b_addr(1)), "{ra:?}");
        assert_eq!(n.b().selected(1), Some(a_addr(1)), "{ra:?}");
        assert!(n.a.stats.role_conflicts + n.b().stats.role_conflicts >= 1);
    }
}

#[test]
fn peer_reflexive_candidates_are_learned() {
    // B knows none of A's candidates: A's check teaches it.
    let mut a = agent(Role::Controlling, 1, (UA, PA), (UB, PB), 1);
    let b = agent(Role::Controlled, 2, (UB, PB), (UA, PA), 1);
    a.add_remote(&host(1, b_addr(1)));
    let mut n = Net::new(a, Peer::Full(b));
    n.run(3_000);
    assert_eq!(n.b().selected(1), Some(a_addr(1)));
    assert_eq!(n.a.selected(1), Some(b_addr(1)));
}

#[test]
fn a_lite_peer_is_nominated() {
    let mut a = agent(Role::Controlling, 1, (UA, PA), (UB, PB), 1);
    a.add_remote(&host(1, b_addr(1)));
    let mut n = Net::new(a, Peer::Lite);
    n.run(3_000);
    assert_eq!(n.a.selected(1), Some(b_addr(1)));
    assert_eq!(n.a.state(), ListState::Completed);
}

#[test]
fn lost_checks_are_retransmitted() {
    let mut n = wired(Role::Controlling, 1, Role::Controlled, 2, 1);
    // Nothing gets through for the first 1.2 s.
    n.drop = |t, _| t < 1_200;
    n.run(6_000);
    assert_eq!(n.a.selected(1), Some(b_addr(1)));
    assert_eq!(n.b().selected(1), Some(a_addr(1)));
}

#[test]
fn no_media_before_a_valid_pair() {
    let n = wired(Role::Controlling, 1, Role::Controlled, 2, 1);
    assert_eq!(n.a.target(1), None);
    assert_eq!(n.a.state(), ListState::Running);
}

#[test]
fn consent_expires_when_the_peer_goes_silent() {
    let mut n = wired(Role::Controlling, 1, Role::Controlled, 2, 1);
    n.run(2_000);
    assert_eq!(n.a.target(1), Some(b_addr(1)));
    let before = n.requests_to_b;
    n.run(20_000);
    // Consent requests every 4–6 s.
    let requests = n.requests_to_b - before;
    assert!((3..=5).contains(&requests), "{requests}");
    assert_eq!(n.a.target(1), Some(b_addr(1)));
    // B stops answering: 30 s after the last response, no more media.
    n.drop = |t, to_b| to_b && t >= 20_000;
    n.run(44_000);
    assert_eq!(n.a.target(1), Some(b_addr(1)), "consent still fresh");
    n.run(52_000);
    assert_eq!(n.a.target(1), None);
    assert!(n.a.consent_lost(1));
    assert_eq!(n.a.stats.consent_lost, 1);
    // B answering again does not bring consent back.
    n.drop = |_, _| false;
    n.run(70_000);
    assert_eq!(n.a.target(1), None);
}

#[test]
fn restart_keeps_media_until_the_new_pair_is_valid() {
    let mut n = wired(Role::Controlling, 1, Role::Controlled, 2, 1);
    n.run(2_000);
    let (ua2, pa2, ub2, pb2): (&[u8], &[u8], &[u8], &[u8]) = (
        b"AAAA",
        b"AAAAAAAAAAAAAAAAAAAAAA",
        b"BBBB",
        b"BBBBBBBBBBBBBBBBBBBBBB",
    );
    assert!(n.a.restart(ua2, pa2, ub2, pb2));
    assert!(n.b_mut().restart(ub2, pb2, ua2, pa2));
    // Until new candidates are paired, media stays on the old pair.
    assert_eq!(n.a.target(1), Some(b_addr(1)));
    assert_eq!(n.a.selected(1), None);
    n.run(2_500);
    assert_eq!(n.a.target(1), Some(b_addr(1)));
    n.a.add_remote(&host(1, b_addr(1)));
    n.b_mut().add_remote(&host(1, a_addr(1)));
    n.run(5_000);
    assert_eq!(n.a.selected(1), Some(b_addr(1)));
    assert_eq!(n.b().selected(1), Some(a_addr(1)));
    assert_eq!(n.a.stats.restarts, 1);
}

#[test]
fn trickled_candidates_are_paired() {
    let a = agent(Role::Controlling, 1, (UA, PA), (UB, PB), 1);
    let mut b = agent(Role::Controlled, 2, (UB, PB), (UA, PA), 1);
    b.add_remote(&host(1, a_addr(1)));
    // B's checks are lost; then B's candidate is trickled to A.
    let mut n = Net::new(a, Peer::Full(b));
    n.drop = |_, to_b| !to_b;
    n.run(300);
    assert_eq!(n.a.pairs(), []);
    assert!(n.a.add_remote(&host(1, b_addr(1))));
    n.drop = |_, _| false;
    n.run(3_000);
    assert_eq!(n.a.selected(1), Some(b_addr(1)));
    // After end-of-candidates nothing more is taken.
    n.a.end_of_candidates();
    assert!(!n.a.add_remote(&host(1, addr(9, 9))));
}

#[test]
fn unanswered_candidates_fail_after_end_of_candidates() {
    let mut a = agent(Role::Controlling, 1, (UA, PA), (UB, PB), 1);
    a.add_remote(&host(1, addr(9, 6001)));
    let mut n = Net::new(a, Peer::Lite);
    n.run(45_000);
    assert_eq!(n.a.pairs()[0].state, PairState::Failed);
    assert_eq!(n.a.state(), ListState::Running);
    n.a.end_of_candidates();
    assert_eq!(n.a.state(), ListState::Failed);
}

#[test]
fn wrong_family_and_component_are_refused() {
    let mut a = agent(Role::Controlling, 1, (UA, PA), (UB, PB), 1);
    assert!(!a.add_remote(&host(2, b_addr(2))));
    let v6 = SocketAddr::new(IpAddr::V6(core::net::Ipv6Addr::LOCALHOST), 9);
    assert!(!a.add_remote(&host(1, v6)));
    assert!(a.add_remote(&host(1, b_addr(1))));
    assert!(!a.add_remote(&host(1, b_addr(1))), "known");
}

/// A late error to a cancelled check does not undo a nomination.
#[test]
fn a_late_error_keeps_the_nomination() {
    let mut a = agent(Role::Controlled, 1, (UA, PA), (UB, PB), 1);
    a.add_remote(&host(1, b_addr(1)));
    let mut out = [0u8; 1500];
    let mut seed = 3u64;
    // A's first check on the pair: in progress.
    let t1 = a
        .poll(0, &mut out, &mut |b: &mut [u8]| next(&mut seed, b))
        .unwrap();
    let tid1: [u8; 12] = out[8..20].try_into().unwrap();
    assert_eq!(t1.dst, b_addr(1));
    // B's check on the same pair cancels it and triggers another.
    let mut msg = [0u8; 1500];
    let check = |m: &mut [u8], tid: &[u8; 12], nominate: bool| {
        stun::write_check(
            m,
            tid,
            &stun::CheckRequest {
                username: b"aaaa:bbbb",
                pwd: PA,
                priority: 1,
                role: Role::Controlling,
                tiebreaker: 9,
                use_candidate: nominate,
            },
        )
        .unwrap()
    };
    let n = check(&mut msg, &[1; 12], false);
    a.on_stun(10, 1, b_addr(1), &msg[..n], &mut out);
    a.poll(100, &mut out, &mut |b: &mut [u8]| next(&mut seed, b))
        .unwrap();
    let tid2: [u8; 12] = out[8..20].try_into().unwrap();
    // Its success, then B nominates.
    let n = stun::write_success(&mut msg, &tid2, a_addr(1), PB).unwrap();
    a.on_stun(120, 1, b_addr(1), &msg[..n], &mut out);
    let n = check(&mut msg, &[2; 12], true);
    a.on_stun(130, 1, b_addr(1), &msg[..n], &mut out);
    assert_eq!(a.selected(1), Some(b_addr(1)));
    // The first check's late error.
    let n = stun::write_error(&mut msg, &tid1, 400, PB).unwrap();
    a.on_stun(140, 1, b_addr(1), &msg[..n], &mut out);
    assert_eq!(a.pairs()[0].state, PairState::Succeeded);
    assert_eq!(a.selected(1), Some(b_addr(1)));
}
