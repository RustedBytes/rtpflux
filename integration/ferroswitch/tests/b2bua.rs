//! ferrosip's `sip-ua` engines (caller, B2BUA, callee, transfer target) on
//! a deterministic simulated SIP network; the B2BUA anchors every leg's
//! media in a real rtpflux through `rtpflux-client-async`, and real RTP
//! flows through the relay between UDP sockets standing for the phones.
//!
//! Covered: an early and a delayed offer, hold and resume, a renegotiation
//! refused by the remote side (rolled back with `endpoint.abort`), a blind
//! transfer, and that after every BYE nothing
//! is left in the relay's inventory, each endpoint's destruction reported
//! as an event.

#![forbid(unsafe_code)]
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "caller/callee and a/b legs read best side by side; on_event is one dispatch"
)]

use rtpflux::config::Config as RelayConfig;
use rtpflux::daemon::Daemon;
use rtpflux_client_async::{
    ApplyAnswerRequest, AttachBridgeRequest, Config, CreateEndpointRequest, DestroyEndpointRequest,
    EventFilter, EventKind, MediaClient, MediaEventStream, PrepareRequest,
};
use sip_ua::{
    AcceptRequest, CommandError, Dest, EventEnvelope, Generation, HangupRequest, IdAllocator,
    NegotiateMethod, NegotiateRequest, OfferKind, OfferResponse, OperationId, OriginateRequest,
    Proto, ReferNotify, ReferRequest, ReferResponse, RejectRequest, SeededEntropy, UaCommand,
    UaConfig, UaEngine, UaEvent, UaLegId,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

const CALLER: usize = 0;
const B2B: usize = 1;
const CALLEE: usize = 2;
const CAROL: usize = 3;
const ADDRS: [&str; 4] = [
    "10.0.0.1:5060",
    "10.0.0.5:5060",
    "10.0.0.2:5060",
    "10.0.0.3:5060",
];

// ---------------------------------------------------------------- network

struct Node {
    addr: SocketAddr,
    engine: UaEngine,
    events: Vec<EventEnvelope>,
}

/// Engines on fake addresses with a fake clock (ms); every datagram takes
/// 10 ms.
struct Net {
    now: u64,
    nodes: Vec<Node>,
    inflight: VecDeque<(u64, SocketAddr, SocketAddr, Vec<u8>)>,
}

impl Net {
    fn new() -> Self {
        let nodes = ADDRS
            .iter()
            .zip(1u64..)
            .map(|(a, seed)| {
                let addr: SocketAddr = a.parse().unwrap();
                let cfg = UaConfig {
                    local: vec![(Proto::Udp, addr)],
                    ..UaConfig::default()
                };
                let engine = UaEngine::with_entropy(
                    cfg,
                    Box::new(SeededEntropy::new(seed)),
                    IdAllocator::new(),
                );
                Node {
                    addr,
                    engine,
                    events: Vec::new(),
                }
            })
            .collect();
        Net {
            now: 0,
            nodes,
            inflight: VecDeque::new(),
        }
    }

    fn submit(&mut self, n: usize, cmd: UaCommand) -> Result<sip_ua::Accepted, CommandError> {
        let r = self.nodes[n].engine.submit(cmd, self.now);
        self.flush();
        r
    }

    fn flush(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                let from = self.nodes[i].addr;
                while let Some(t) = self.nodes[i].engine.poll_transmit() {
                    moved = true;
                    self.inflight
                        .push_back((self.now + 10, from, t.dest.addr, t.data.to_vec()));
                }
                while let Some(r) = self.nodes[i].engine.poll_resolve() {
                    moved = true;
                    let now = self.now;
                    self.nodes[i]
                        .engine
                        .resolved(r.id, Err("no DNS".into()), now);
                }
                while let Some(e) = self.nodes[i].engine.poll_event() {
                    self.nodes[i].events.push(e);
                }
            }
            if !moved {
                break;
            }
        }
    }

    /// Deliver what is due by the next packet or timer (never past `cap`);
    /// false when nothing is pending.
    fn step(&mut self, cap: u64) -> bool {
        self.flush();
        let next_pkt = self.inflight.iter().map(|p| p.0).min();
        let next_timer = self
            .nodes
            .iter()
            .filter_map(|n| n.engine.next_timeout())
            .min();
        let Some(next) = [next_pkt, next_timer].into_iter().flatten().min() else {
            return false;
        };
        self.now = self.now.max(next.min(cap));
        let now = self.now;
        let (due, later): (VecDeque<_>, VecDeque<_>) =
            self.inflight.drain(..).partition(|p| p.0 <= now);
        self.inflight = later;
        for (_, from, to, data) in due {
            if let Some(n) = self.nodes.iter_mut().find(|n| n.addr == to) {
                n.engine
                    .handle_message(&data, Dest::new(Proto::Udp, from), now);
            }
            self.flush();
        }
        for n in &mut self.nodes {
            n.engine.handle_timeout(now);
        }
        self.flush();
        true
    }

    fn mark(&self, n: usize) -> usize {
        self.nodes[n].events.len()
    }

    /// The first event of node `n` since `mark` that `f` accepts.
    fn since(&self, n: usize, mark: usize, f: impl Fn(&UaEvent) -> bool) -> Option<EventEnvelope> {
        self.nodes[n].events[mark..]
            .iter()
            .find(|e| f(&e.event))
            .cloned()
    }
}

// ---------------------------------------------------------------- B2BUA

/// A local re-offer sent on a leg, awaiting its answer.
struct Reoffer {
    endpoint: String,
    revision: u64,
}

/// A B2BUA anchoring both legs' media in rtpflux, one endpoint per leg:
/// the relay answers each side's offers itself (re-offers included), so a
/// leg's renegotiation never involves the other leg.
struct B2bua {
    media: MediaClient,
    seen: usize,
    target: String,
    peer: HashMap<UaLegId, UaLegId>,
    endpoint: HashMap<UaLegId, String>,
    /// The answer to send with the 2xx, per inbound leg (early offer).
    answer: HashMap<UaLegId, String>,
    /// Inbound legs whose INVITE had no offer.
    delayed: HashSet<UaLegId>,
    reoffers: HashMap<OperationId, Reoffer>,
    /// A transfer's new leg → the leg that asked for it (REFER).
    transfers: HashMap<UaLegId, UaLegId>,
    /// The inbound legs, in order.
    inbound: Vec<UaLegId>,
    /// Every endpoint made, and the ids of those destroyed.
    created: Vec<String>,
    destroyed: Vec<String>,
}

fn offering() -> CreateEndpointRequest {
    CreateEndpointRequest::offering(["PCMU"])
}

impl B2bua {
    fn new(media: MediaClient, target: &str) -> Self {
        B2bua {
            media,
            seen: 0,
            target: target.into(),
            peer: HashMap::new(),
            endpoint: HashMap::new(),
            answer: HashMap::new(),
            delayed: HashSet::new(),
            reoffers: HashMap::new(),
            transfers: HashMap::new(),
            inbound: Vec::new(),
            created: Vec::new(),
            destroyed: Vec::new(),
        }
    }

    async fn create(
        &mut self,
        req: CreateEndpointRequest,
    ) -> Option<rtpflux_client_async::Endpoint> {
        let ep = self.media.create_endpoint(req).await.ok()?;
        self.created.push(ep.endpoint_id.clone());
        Some(ep)
    }

    async fn apply(&self, leg: UaLegId, sdp: &[u8]) {
        let req = ApplyAnswerRequest {
            endpoint_id: self.endpoint[&leg].clone(),
            sdp: String::from_utf8_lossy(sdp).into_owned(),
            expected_generation: None,
            options: None,
            deadline: None,
        };
        self.media.apply_answer(req).await.unwrap();
    }

    async fn bridge(&self, a: UaLegId, b: UaLegId) {
        let (a, b) = (&self.endpoint[&a], &self.endpoint[&b]);
        self.media
            .attach_bridge(AttachBridgeRequest::new(a, b))
            .await
            .unwrap();
    }

    /// A re-offer of `codecs` from the relay on `leg`.
    async fn reoffer(&mut self, net: &mut Net, leg: UaLegId, codecs: &[&str]) {
        let endpoint = self.endpoint[&leg].clone();
        let p = self
            .media
            .prepare(PrepareRequest {
                endpoint_id: endpoint.clone(),
                remote_sdp: None,
                codecs: Some(codecs.iter().map(|c| (*c).to_owned()).collect()),
                expected_revision: None,
                options: None,
                deadline: None,
            })
            .await
            .unwrap();
        let sdp = p.sdp.into_bytes();
        let acc = net
            .submit(
                B2B,
                UaCommand::Negotiate(NegotiateRequest {
                    leg,
                    method: NegotiateMethod::ReInvite,
                    sdp,
                }),
            )
            .unwrap();
        self.reoffers.insert(
            acc.op,
            Reoffer {
                endpoint,
                revision: p.pending_revision,
            },
        );
    }

    async fn on_event(&mut self, ev: &EventEnvelope, net: &mut Net) {
        let leg = ev.leg;
        match &ev.event {
            UaEvent::IncomingInvite(ii) => {
                let inbound = if let Some(o) = ii.sdp.as_deref() {
                    let req = CreateEndpointRequest::answering(String::from_utf8_lossy(o));
                    let Some(ep) = self.create(req).await else {
                        let reject = RejectRequest {
                            leg,
                            code: 488,
                            reason: None,
                            headers: vec![],
                        };
                        net.submit(B2B, UaCommand::Reject(reject)).unwrap();
                        return;
                    };
                    self.answer.insert(leg, ep.sdp);
                    Some(ep.endpoint_id)
                } else {
                    self.delayed.insert(leg);
                    None
                };
                let out = self.create(offering()).await.unwrap();
                let o = OriginateRequest {
                    request_uri: format!("sip:bob@{}", self.target),
                    from: "<sip:b2bua@10.0.0.5>".into(),
                    sdp: Some(out.sdp.into_bytes()),
                    ..Default::default()
                };
                let acc = net.submit(B2B, UaCommand::Originate(Box::new(o))).unwrap();
                if let Some(e) = inbound {
                    self.endpoint.insert(leg, e);
                }
                self.inbound.push(leg);
                self.endpoint.insert(acc.leg, out.endpoint_id);
                self.peer.insert(leg, acc.leg);
                self.peer.insert(acc.leg, leg);
            }
            UaEvent::Accepted(a) => {
                let sdp = a.sdp.as_deref().unwrap();
                self.apply(leg, sdp).await;
                if let Some(referrer) = self.transfers.remove(&leg) {
                    // The transfer target answered: the referrer's peer is
                    // bridged to it, and the referrer let go.
                    let other = self.peer.remove(&referrer).unwrap();
                    self.peer.remove(&other);
                    self.media
                        .detach_bridge(&self.endpoint[&other], None)
                        .await
                        .unwrap();
                    self.bridge(other, leg).await;
                    self.peer.insert(other, leg);
                    self.peer.insert(leg, other);
                    let notify = ReferNotify {
                        leg: referrer,
                        code: 200,
                        reason: None,
                        last: true,
                    };
                    net.submit(B2B, UaCommand::NotifyRefer(notify)).unwrap();
                    let bye = HangupRequest {
                        leg: referrer,
                        reason: None,
                        code: None,
                    };
                    net.submit(B2B, UaCommand::Hangup(bye)).unwrap();
                    return;
                }
                let inb = self.peer[&leg];
                let sdp = if self.delayed.contains(&inb) {
                    // Our offer to the caller; its answer comes in the ACK.
                    let ep = self.create(offering()).await.unwrap();
                    self.endpoint.insert(inb, ep.endpoint_id);
                    ep.sdp
                } else {
                    self.bridge(inb, leg).await;
                    self.answer.remove(&inb).unwrap()
                };
                let accept = AcceptRequest {
                    leg: inb,
                    sdp: Some(sdp.into_bytes()),
                    headers: vec![],
                };
                net.submit(B2B, UaCommand::Accept(accept)).unwrap();
            }
            UaEvent::Ack(a) => {
                if let (Some(sdp), true) = (a.sdp.as_deref(), self.delayed.remove(&leg)) {
                    self.apply(leg, sdp).await;
                    self.bridge(leg, self.peer[&leg]).await;
                }
            }
            UaEvent::RemoteOffer(o) if o.kind != OfferKind::InviteResponse => {
                // The relay answers; a refusal is a 488 to the re-offer.
                let generation: Generation = ev.generation;
                let answer = match o.sdp.as_deref() {
                    Some(s) => self.answer_reoffer(leg, s).await,
                    None => None,
                };
                let r = OfferResponse {
                    leg,
                    generation,
                    sdp: answer.map(String::into_bytes),
                };
                net.submit(B2B, UaCommand::RespondToOffer(r)).unwrap();
            }
            UaEvent::Completed(c) => {
                if let Some(r) = ev.op.and_then(|op| self.reoffers.remove(&op)) {
                    let answer = String::from_utf8_lossy(c.sdp.as_deref().unwrap()).into_owned();
                    self.media
                        .commit(&r.endpoint, r.revision, Some(&answer), None)
                        .await
                        .unwrap();
                }
            }
            UaEvent::Failed(_) => {
                if let Some(r) = ev.op.and_then(|op| self.reoffers.remove(&op)) {
                    self.media
                        .abort(&r.endpoint, r.revision, None)
                        .await
                        .unwrap();
                }
            }
            UaEvent::ReferRequested(r) => {
                net.submit(
                    B2B,
                    UaCommand::RespondToRefer(ReferResponse { leg, accept: true }),
                )
                .unwrap();
                let ep = self.create(offering()).await.unwrap();
                let o = OriginateRequest {
                    request_uri: r.target.clone(),
                    from: "<sip:b2bua@10.0.0.5>".into(),
                    sdp: Some(ep.sdp.into_bytes()),
                    ..Default::default()
                };
                let acc = net.submit(B2B, UaCommand::Originate(Box::new(o))).unwrap();
                self.endpoint.insert(acc.leg, ep.endpoint_id);
                self.transfers.insert(acc.leg, leg);
            }
            UaEvent::Terminated(_) => {
                if let Some(other) = self.peer.remove(&leg) {
                    self.peer.remove(&other);
                    let bye = HangupRequest {
                        leg: other,
                        reason: None,
                        code: None,
                    };
                    let _ = net.submit(B2B, UaCommand::Hangup(bye));
                }
                if let Some(ep) = self.endpoint.remove(&leg) {
                    self.media
                        .destroy_endpoint(DestroyEndpointRequest::new(&ep))
                        .await
                        .unwrap();
                    self.destroyed.push(ep);
                }
            }
            _ => {}
        }
    }

    /// The relay's answer to a re-offer on `leg`, committed; `None` when it
    /// cannot answer it (nothing changes).
    async fn answer_reoffer(&self, leg: UaLegId, offer: &[u8]) -> Option<String> {
        let endpoint = self.endpoint[&leg].clone();
        let p = self
            .media
            .prepare(PrepareRequest {
                endpoint_id: endpoint.clone(),
                remote_sdp: Some(String::from_utf8_lossy(offer).into_owned()),
                codecs: None,
                expected_revision: None,
                options: None,
                deadline: None,
            })
            .await
            .ok()?;
        self.media
            .commit(&endpoint, p.pending_revision, None, None)
            .await
            .unwrap();
        Some(p.sdp)
    }

    /// Run the network until nothing is left to do now.
    async fn settle(&mut self, net: &mut Net) {
        self.run(net, |_| false).await;
    }

    /// Run the network, handling the B2BUA's events, until `cond` holds.
    async fn run(&mut self, net: &mut Net, cond: impl Fn(&Net) -> bool) -> bool {
        for _ in 0..20_000 {
            while self.seen < net.nodes[B2B].events.len() {
                let ev = net.nodes[B2B].events[self.seen].clone();
                self.seen += 1;
                self.on_event(&ev, net).await;
            }
            if cond(net) {
                return true;
            }
            if !net.step(net.now + 20) && self.seen == net.nodes[B2B].events.len() {
                return cond(net);
            }
        }
        false
    }
}

// ---------------------------------------------------------------- media

fn media_sdp(port: u16, direction: &str) -> Vec<u8> {
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na={direction}\r\n"
    )
    .into_bytes()
}

fn audio_port(sdp: &[u8]) -> u16 {
    let s = String::from_utf8_lossy(sdp);
    let m = s.lines().find(|l| l.starts_with("m=audio ")).unwrap();
    m.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn rtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    p.extend(std::iter::repeat_n(0xffu8, 160));
    p
}

/// Send RTP from `from` to the relay's `port` until some reaches `to`.
fn flows(from: &UdpSocket, port: u16, to: &UdpSocket) -> bool {
    to.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut buf = [0u8; 2048];
    while to.recv(&mut buf).is_ok() {}
    for seq in 0..30 {
        from.send_to(&rtp(seq), ("127.0.0.1", port)).unwrap();
        if to.recv(&mut buf).is_ok_and(|n| n >= 12) {
            return true;
        }
    }
    false
}

/// A phone's RTP socket.
fn phone() -> (UdpSocket, u16) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    (s, port)
}

// ---------------------------------------------------------------- setup

struct Setup {
    dir: PathBuf,
    daemon: Option<Daemon>,
    net: Net,
    b2b: B2bua,
    events: MediaEventStream,
}

async fn setup(name: &str, ports: u16) -> Setup {
    let dir = std::env::temp_dir().join(format!("ferroswitch-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("api.sock");
    let config = RelayConfig::from_toml(&format!(
        r#"
        [control]
        listen = ["127.0.0.1:0"]
        native_socket = "{}"
        [[interface]]
        name = "lo"
        address = "127.0.0.1"
        [ports]
        min = {ports}
        max = {}
        [sessions]
        max = 16
        state_file = "{}"
        ledger = "{}"
        [runtime]
        workers = 2
        "#,
        sock.display(),
        ports + 99,
        dir.join("state.json").display(),
        dir.join("ledger.jsonl").display(),
    ))
    .unwrap();
    let daemon = Daemon::start(&config).unwrap();
    let media = MediaClient::connect(Config::unix(&sock)).await.unwrap();
    let events = media
        .subscribe_events(EventFilter {
            types: vec!["endpoint.destroyed".into()],
            ..EventFilter::default()
        })
        .await
        .unwrap();
    Setup {
        dir,
        daemon: Some(daemon),
        net: Net::new(),
        b2b: B2bua::new(media, ADDRS[CALLEE]),
        events,
    }
}

impl Setup {
    /// A call from the caller (`offer`: early, else delayed) answered by
    /// the callee: (caller's leg, callee's leg, the relay's port towards
    /// the caller, towards the callee).
    async fn call(
        &mut self,
        caller: u16,
        callee: u16,
        early: bool,
    ) -> (UaLegId, UaLegId, u16, u16) {
        let (net, b2b) = (&mut self.net, &mut self.b2b);
        let o = OriginateRequest {
            request_uri: format!("sip:b2bua@{}", ADDRS[B2B]),
            from: "<sip:alice@10.0.0.1>".into(),
            sdp: early.then(|| media_sdp(caller, "sendrecv")),
            ..Default::default()
        };
        let a = net
            .submit(CALLER, UaCommand::Originate(Box::new(o)))
            .unwrap()
            .leg;
        let m = net.mark(CALLEE);
        assert!(
            b2b.run(net, |n| n
                .since(CALLEE, m, |e| matches!(e, UaEvent::IncomingInvite(_)))
                .is_some())
                .await
        );
        let inv = net
            .since(CALLEE, m, |e| matches!(e, UaEvent::IncomingInvite(_)))
            .unwrap();
        let UaEvent::IncomingInvite(ii) = &inv.event else {
            unreachable!()
        };
        let to_callee = audio_port(ii.sdp.as_deref().unwrap());
        let accept = AcceptRequest {
            leg: inv.leg,
            sdp: Some(media_sdp(callee, "sendrecv")),
            headers: vec![],
        };
        net.submit(CALLEE, UaCommand::Accept(accept)).unwrap();
        let mc = net.mark(CALLER);
        let to_caller = if early {
            assert!(
                b2b.run(net, |n| n
                    .since(CALLER, mc, |e| matches!(e, UaEvent::Accepted(_)))
                    .is_some())
                    .await
            );
            let acc = net
                .since(CALLER, mc, |e| matches!(e, UaEvent::Accepted(_)))
                .unwrap();
            let UaEvent::Accepted(acc) = acc.event else {
                unreachable!()
            };
            audio_port(acc.sdp.as_deref().unwrap())
        } else {
            // The 2xx carries the relay's offer; the ACK our answer.
            let offer = |e: &UaEvent| matches!(e, UaEvent::RemoteOffer(o) if o.kind == OfferKind::InviteResponse);
            assert!(b2b.run(net, |n| n.since(CALLER, mc, offer).is_some()).await);
            let ro = net.since(CALLER, mc, offer).unwrap();
            let UaEvent::RemoteOffer(o) = &ro.event else {
                unreachable!()
            };
            let port = audio_port(o.sdp.as_deref().unwrap());
            let r = OfferResponse {
                leg: a,
                generation: ro.generation,
                sdp: Some(media_sdp(caller, "sendrecv")),
            };
            net.submit(CALLER, UaCommand::RespondToOffer(r)).unwrap();
            b2b.settle(net).await;
            port
        };
        assert_ne!(to_caller, caller, "the caller sees the relay");
        assert_ne!(to_callee, callee, "the callee sees the relay");
        (a, inv.leg, to_caller, to_callee)
    }

    /// Hang up `leg` of `node`; when every engine is idle, nothing may be
    /// left in the relay, and each endpoint made was reported destroyed.
    async fn hang_up_and_check_clean(mut self, node: usize, leg: UaLegId) {
        let (net, b2b) = (&mut self.net, &mut self.b2b);
        net.submit(
            node,
            UaCommand::Hangup(HangupRequest {
                leg,
                reason: None,
                code: None,
            }),
        )
        .unwrap();
        assert!(
            b2b.run(net, |n| n.nodes.iter().all(|x| x.engine.is_idle()))
                .await
        );
        let mut made = b2b.created.clone();
        let mut gone = b2b.destroyed.clone();
        made.sort();
        gone.sort();
        assert_eq!(made, gone, "every endpoint destroyed");
        let (items, _) = b2b.media.inventory_all("endpoints", 3).await.unwrap();
        assert!(items.is_empty(), "nothing left: {items:?}");
        let mut reported = Vec::new();
        while reported.len() < made.len() {
            let e = tokio::time::timeout(Duration::from_secs(3), self.events.next())
                .await
                .expect("an endpoint.destroyed event per endpoint")
                .unwrap();
            assert_eq!(e.kind, EventKind::EndpointDestroyed, "{e:?}");
            reported.push(e.endpoint_id.unwrap());
        }
        reported.sort();
        assert_eq!(reported, made);
        let report = b2b.media.recovery_report().await.unwrap();
        assert_eq!(report.unknown_operations, [] as [serde_json::Value; 0]);
        let daemon = self.daemon.take().unwrap();
        tokio::task::spawn_blocking(move || daemon.stop())
            .await
            .unwrap();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

// ---------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn early_offer_hold_resume_and_bye() {
    let mut s = setup("early", 64_100).await;
    let ((caller_rtp, caller), (callee_rtp, callee)) = (phone(), phone());
    let (a, b, to_caller, to_callee) = s.call(caller, callee, true).await;
    assert!(
        flows(&caller_rtp, to_caller, &callee_rtp),
        "caller → callee"
    );
    assert!(
        flows(&callee_rtp, to_callee, &caller_rtp),
        "callee → caller"
    );

    // The callee holds and resumes: the relay answers on the same port.
    for direction in ["sendonly", "sendrecv"] {
        let m = s.net.mark(CALLEE);
        let neg = NegotiateRequest {
            leg: b,
            method: NegotiateMethod::ReInvite,
            sdp: media_sdp(callee, direction),
        };
        s.net.submit(CALLEE, UaCommand::Negotiate(neg)).unwrap();
        let done = |e: &UaEvent| matches!(e, UaEvent::Completed(_));
        assert!(
            s.b2b
                .run(&mut s.net, |n| n.since(CALLEE, m, done).is_some())
                .await
        );
        let UaEvent::Completed(c) = s.net.since(CALLEE, m, done).unwrap().event else {
            unreachable!()
        };
        let answer = c.sdp.unwrap();
        assert_eq!(audio_port(&answer), to_callee, "the same relay port");
        let expected = if direction == "sendonly" {
            "a=recvonly"
        } else {
            "a=sendrecv"
        };
        assert!(
            String::from_utf8_lossy(&answer).contains(expected),
            "{}",
            String::from_utf8_lossy(&answer)
        );
    }
    assert!(
        flows(&caller_rtp, to_caller, &callee_rtp),
        "caller → callee after resume"
    );
    assert!(
        flows(&callee_rtp, to_callee, &caller_rtp),
        "callee → caller after resume"
    );
    let _ = a;
    s.hang_up_and_check_clean(CALLEE, b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_offer_and_bye_from_the_caller() {
    let mut s = setup("delayed", 64_300).await;
    let ((caller_rtp, caller), (callee_rtp, callee)) = (phone(), phone());
    let (a, _, to_caller, to_callee) = s.call(caller, callee, false).await;
    s.b2b.settle(&mut s.net).await;
    assert!(
        flows(&caller_rtp, to_caller, &callee_rtp),
        "caller → callee"
    );
    assert!(
        flows(&callee_rtp, to_callee, &caller_rtp),
        "callee → caller"
    );
    s.hang_up_and_check_clean(CALLER, a).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_renegotiation_is_rolled_back() {
    let mut s = setup("failed", 64_500).await;
    let ((caller_rtp, caller), (callee_rtp, callee)) = (phone(), phone());
    let (a, _, to_caller, to_callee) = s.call(caller, callee, true).await;
    // The caller's leg at the B2BUA, and its endpoint.
    let leg = s.b2b.inbound[0];
    let in_ep = (leg, s.b2b.endpoint[&leg].clone());
    let revision = |q: &serde_json::Value| q["revision"].as_u64().unwrap();
    let before = revision(&s.b2b.media.query_endpoint(&in_ep.1, None).await.unwrap());

    // The relay re-offers PCMA to the caller (once the ACK is in), who
    // refuses: rolled back.
    s.b2b.settle(&mut s.net).await;
    let m = s.net.mark(CALLER);
    s.b2b.reoffer(&mut s.net, in_ep.0, &["PCMA"]).await;
    let offer = |e: &UaEvent| matches!(e, UaEvent::RemoteOffer(_));
    assert!(
        s.b2b
            .run(&mut s.net, |n| n.since(CALLER, m, offer).is_some())
            .await
    );
    let ro = s.net.since(CALLER, m, offer).unwrap();
    s.net
        .submit(
            CALLER,
            UaCommand::RespondToOffer(OfferResponse {
                leg: a,
                generation: ro.generation,
                sdp: None,
            }),
        )
        .unwrap();
    s.b2b.settle(&mut s.net).await;
    assert!(s.b2b.reoffers.is_empty(), "the refusal reached the B2BUA");
    let q = s.b2b.media.query_endpoint(&in_ep.1, None).await.unwrap();
    assert_eq!(revision(&q), before, "aborted: {q}");
    assert!(
        flows(&caller_rtp, to_caller, &callee_rtp),
        "caller → callee after the abort"
    );
    assert!(
        flows(&callee_rtp, to_callee, &caller_rtp),
        "callee → caller after the abort"
    );

    s.hang_up_and_check_clean(CALLER, a).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blind_transfer_to_a_third_party() {
    let mut s = setup("transfer", 64_700).await;
    let ((_caller_rtp, caller), (callee_rtp, callee), (carol_rtp, carol)) =
        (phone(), phone(), phone());
    let (a, b, _, to_callee) = s.call(caller, callee, true).await;

    // The caller transfers the callee to Carol.
    let m = s.net.mark(CAROL);
    let refer = ReferRequest {
        leg: a,
        refer_to: format!("sip:carol@{}", ADDRS[CAROL]),
        referred_by: None,
        headers: vec![],
    };
    s.net.submit(CALLER, UaCommand::Refer(refer)).unwrap();
    let invite = |e: &UaEvent| matches!(e, UaEvent::IncomingInvite(_));
    assert!(
        s.b2b
            .run(&mut s.net, |n| n.since(CAROL, m, invite).is_some())
            .await
    );
    let inv = s.net.since(CAROL, m, invite).unwrap();
    let UaEvent::IncomingInvite(ii) = &inv.event else {
        unreachable!()
    };
    let to_carol = audio_port(ii.sdp.as_deref().unwrap());
    let accept = AcceptRequest {
        leg: inv.leg,
        sdp: Some(media_sdp(carol, "sendrecv")),
        headers: vec![],
    };
    s.net.submit(CAROL, UaCommand::Accept(accept)).unwrap();
    // The caller's leg ends; the callee and Carol talk through the relay.
    let gone = |e: &UaEvent| matches!(e, UaEvent::Terminated(_));
    assert!(
        s.b2b
            .run(&mut s.net, |n| n.since(CALLER, 0, gone).is_some())
            .await
    );
    assert!(flows(&callee_rtp, to_callee, &carol_rtp), "callee → Carol");
    assert!(flows(&carol_rtp, to_carol, &callee_rtp), "Carol → callee");
    let _ = b;
    s.hang_up_and_check_clean(CAROL, inv.leg).await;
}
