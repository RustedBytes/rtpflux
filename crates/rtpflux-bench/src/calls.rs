//! Setting up the measured calls (offer, answer) and deleting them.

#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------- calls

/// The SRTP keys of a call's endpoints: what A and B send with, and what
/// they receive with (the relay's keys towards them).
#[derive(Clone, Copy)]
pub(super) struct Keys {
    pub(super) a: Option<(MasterKey, MasterKey)>,
    pub(super) b: Option<(MasterKey, MasterKey)>,
}

/// What an endpoint pair keeps across measurement windows: its RTP
/// sequence number and SRTP contexts (a restarted sequence would be a
/// replay to the relay).
pub(super) struct Endpoints {
    pub(super) seq: u16,
    pub(super) a: Option<(Protect, Unprotect)>,
    pub(super) b: Option<(Protect, Unprotect)>,
}

pub(super) struct Call {
    pub(super) id: String,
    pub(super) state: std::sync::Mutex<Endpoints>,
    pub(super) a: UdpSocket,
    pub(super) b: UdpSocket,
    /// Where A sends (the relay port in the answer A received).
    pub(super) a_to: SocketAddr,
    /// Where B sends (the relay port in the offer B received).
    pub(super) b_to: SocketAddr,
}

pub(super) const FLAGS: &[&[u8]] = &[b"trust-address"];

pub(super) const REPLACE: &[&[u8]] = &[b"origin"];

/// Where the endpoints live.
pub(super) struct Peers {
    pub(super) a: IpAddr,
    pub(super) b: IpAddr,
    pub(super) netns: Option<std::fs::File>,
}

impl Peers {
    /// Bind a non-blocking socket on `ip`, inside the peer namespace if one
    /// is set (a socket keeps the namespace it was created in).
    pub(super) fn endpoint(&self, ip: IpAddr) -> UdpSocket {
        let ours = self
            .netns
            .as_ref()
            .map(|_| std::fs::File::open("/proc/thread-self/ns/net").expect("current netns"));
        if let Some(ns) = &self.netns {
            setns(ns, CloneFlags::CLONE_NEWNET).expect("enter the peer netns (needs root)");
        }
        let s = UdpSocket::bind((ip, 0));
        if let Some(ours) = &ours {
            setns(ours, CloneFlags::CLONE_NEWNET).expect("return to our netns");
        }
        let s = s.expect("endpoint socket");
        s.set_nonblocking(true).unwrap();
        s
    }
}

pub(super) fn setup(
    ng: &mut Ng,
    peers: &Peers,
    n: usize,
    step: usize,
    srtp: SrtpMode,
) -> Vec<Call> {
    (0..n)
        .map(|i| {
            let id = format!("bench-{step}-{i}");
            let (a, b) = (peers.endpoint(peers.a), peers.endpoint(peers.b));
            let (ka, kb) = (bench_key(i, 1), bench_key(i, 2));
            let a_srtp = srtp != SrtpMode::None;
            let b_srtp = srtp == SrtpMode::Both;
            let offer = sdp_for(a.local_addr().unwrap(), a_srtp.then_some(&ka));
            let profile: &[u8] = if b_srtp { b"RTP/SAVP" } else { b"RTP/AVP" };
            let to_b = ng.request(
                &[
                    (b"call-id", id.as_bytes()),
                    (b"command", b"offer"),
                    (b"endpoint-learning", b"off"),
                    (b"from-tag", b"a"),
                    (b"sdp", &offer),
                    (b"transport-protocol", profile),
                ],
                &[(b"flags", FLAGS), (b"replace", REPLACE)],
            );
            let answer = sdp_for(b.local_addr().unwrap(), b_srtp.then_some(&kb));
            let to_a = ng.request(
                &[
                    (b"call-id", id.as_bytes()),
                    (b"command", b"answer"),
                    (b"endpoint-learning", b"off"),
                    (b"from-tag", b"a"),
                    (b"sdp", &answer),
                    (b"to-tag", b"b"),
                ],
                &[(b"flags", FLAGS), (b"replace", REPLACE)],
            );
            let keys = Keys {
                a: a_srtp.then(|| (ka, relay_key(&to_a))),
                b: b_srtp.then(|| (kb, relay_key(&to_b))),
            };
            let ctx = |k: Option<(MasterKey, MasterKey)>| {
                k.map(|(s, r)| (Protect::from_key(&s), Unprotect::from_key(&r)))
            };
            Call {
                id,
                state: std::sync::Mutex::new(Endpoints {
                    seq: 0,
                    a: ctx(keys.a),
                    b: ctx(keys.b),
                }),
                a,
                b,
                a_to: relay_port(&to_a),
                b_to: relay_port(&to_b),
            }
        })
        .collect()
}

pub(super) fn teardown(ng: &mut Ng, calls: &[Call]) {
    for c in calls {
        ng.request(
            &[
                (b"call-id", c.id.as_bytes()),
                (b"command", b"delete"),
                (b"from-tag", b"a"),
            ],
            &[],
        );
    }
}
