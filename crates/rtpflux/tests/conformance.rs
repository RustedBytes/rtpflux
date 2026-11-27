//! Differential conformance: rtpflux against vectors produced by an
//! external reference model of the protocols (`docs/conformance.md`).
//!
//! Every line of `conformance/media-vectors.txt` is checked; all mismatches
//! are reported together.

use rtpflux::dtls;
use rtpflux_core::dtls::{self as dtls_core, Setup};
use rtpflux_core::g711;
use rtpflux_core::ice::checklist::{self, CandType, ListState, Pair, PairState};
use rtpflux_core::ice::consent::Consent;
use rtpflux_core::ice::list::List;
use rtpflux_core::ice::{Agent, RemoteCandidate};
use rtpflux_core::rtcp;
use rtpflux_core::rtp::Pt;
use rtpflux_core::sdp::{MAX_MEDIA, Media, Suite, read_media};
use rtpflux_core::stun::{self, Role};
use rtpflux_srtp::{Protect, Unprotect};
use rtpflux_xdp_common::{FlowAction, Verdict, classify, csum_replace2, csum_replace4, rewrite};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

const VECTORS: &str = include_str!("../../../conformance/media-vectors.txt");

fn role(s: &str) -> Role {
    match s {
        "controlling" => Role::Controlling,
        "controlled" => Role::Controlled,
        other => panic!("role {other}"),
    }
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Controlling => "controlling",
        Role::Controlled => "controlled",
    }
}

fn state_of(s: &str) -> PairState {
    match s {
        "F" => PairState::Frozen,
        "W" => PairState::Waiting,
        "I" => PairState::InProgress,
        "S" => PairState::Succeeded,
        "X" => PairState::Failed,
        other => panic!("pair state {other}"),
    }
}

fn letter(s: PairState) -> &'static str {
    match s {
        PairState::Frozen => "F",
        PairState::Waiting => "W",
        PairState::InProgress => "I",
        PairState::Succeeded => "S",
        PairState::Failed => "X",
    }
}

/// A `/`-separated list of numbers and a trailing state letter, per pair;
/// `-` for none.
fn items(field: &str) -> Vec<Vec<&str>> {
    if field == "-" || field.is_empty() {
        return Vec::new();
    }
    field.split(',').map(|p| p.split('/').collect()).collect()
}

fn num<T: std::str::FromStr>(s: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    s.parse().unwrap()
}

/// One replayed agent run (`ice-agent` vectors).
struct Run {
    agent: Agent,
    generation: u32,
    /// Random draws so far: the k-th is k.
    draws: u128,
    /// The generation each check the agent sent was under.
    sent: std::collections::HashMap<u128, u32>,
}

fn local_creds(g: u32) -> (String, String) {
    (format!("L{g:03}"), format!("L{g:03}{}", "x".repeat(18)))
}

fn remote_creds(g: u32) -> (String, String) {
    (format!("R{g:03}"), format!("R{g:03}{}", "y".repeat(18)))
}

fn run_addr(n: u64) -> SocketAddr {
    SocketAddr::from(([10, 1, 0, 1], u16::try_from(10_000 + n).unwrap()))
}

fn tid12(n: u128) -> [u8; 12] {
    n.to_be_bytes()[4..].try_into().unwrap()
}

/// The attributes of a STUN message.
fn stun_attrs(m: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = 20;
    while at + 4 <= m.len() {
        let kind = u16::from_be_bytes([m[at], m[at + 1]]);
        let len = usize::from(u16::from_be_bytes([m[at + 2], m[at + 3]]));
        out.push((kind, &m[at + 4..at + 4 + len]));
        at += 4 + len + (4 - len % 4) % 4;
    }
    out
}

fn role_name_of(r: Role) -> &'static str {
    match r {
        Role::Controlling => "controlling",
        Role::Controlled => "controlled",
    }
}

impl Run {
    fn obs(&self) -> String {
        let addr =
            |a: Option<SocketAddr>| a.map_or("-".to_owned(), |a| (a.port() - 10_000).to_string());
        let state = match self.agent.state() {
            ListState::Running => "running",
            ListState::Completed => "completed",
            ListState::Failed => "failed",
        };
        format!(
            "{} {} {} {} {} {state} {} {} {}",
            role_name_of(self.agent.role()),
            addr(self.agent.target(1)),
            addr(self.agent.target(2)),
            addr(self.agent.selected(1)),
            addr(self.agent.selected(2)),
            u8::from(self.agent.consent_lost(1)),
            u8::from(self.agent.consent_lost(2)),
            self.agent
                .next_ms()
                .map_or("-".to_owned(), |t| t.to_string())
        )
    }

    /// Apply one input; what the agent sent.
    fn apply(&mut self, input: &str) -> Vec<String> {
        let w: Vec<&str> = input.split(' ').collect();
        let mut sent = Vec::new();
        match w[0] {
            "add" => {
                self.agent.add_remote(&RemoteCandidate {
                    foundation: w[1].as_bytes(),
                    component: num(w[2]),
                    priority: num(w[3]),
                    addr: run_addr(num(w[4])),
                });
            }
            "eoc" => self.agent.end_of_candidates(),
            "restart" => {
                self.generation += 1;
                let (lu, lp) = local_creds(self.generation);
                let (ru, rp) = remote_creds(self.generation);
                self.agent
                    .restart(lu.as_bytes(), lp.as_bytes(), ru.as_bytes(), rp.as_bytes());
            }
            "req" => sent.push(self.request(&w)),
            "resp" => {
                if let Some(e) = self.response(&w) {
                    sent.push(e);
                }
            }
            _ => self.poll(num(w[1]), &mut sent),
        }
        sent
    }

    /// A check from the peer; the agent's answer.
    fn request(&mut self, w: &[&str]) -> String {
        let mut out = [0u8; 1500];
        let mut msg = [0u8; 1500];
        let (lu, lp) = local_creds(self.generation);
        let (ru, _) = remote_creds(self.generation);
        let user = format!("{lu}:{ru}");
        let pwd = if w[5] == "1" {
            lp
        } else {
            "wrongpasswordwrongpass".to_owned()
        };
        let n = stun::write_check(
            &mut msg,
            &tid12(num(w[4])),
            &stun::CheckRequest {
                username: user.as_bytes(),
                pwd: pwd.as_bytes(),
                priority: num(w[6]),
                role: role(w[8]),
                tiebreaker: num(w[9]),
                use_candidate: w[7] == "1",
            },
        )
        .unwrap();
        let reply = self.agent.on_stun(
            num(w[1]),
            num(w[2]),
            run_addr(num(w[3])),
            &msg[..n],
            &mut out,
        );
        match reply {
            None => "reply:none".to_owned(),
            Some(len) => {
                let error = out[1] & 0x10 != 0;
                let code = stun_attrs(&out[..len])
                    .iter()
                    .find(|a| a.0 == 0x0009)
                    .map(|a| u16::from(a.1[2]) * 100 + u16::from(a.1[3]));
                match (error, code) {
                    (false, _) => "reply:success".to_owned(),
                    (true, Some(487)) => "reply:conflict".to_owned(),
                    _ => "reply:rejected".to_owned(),
                }
            }
        }
    }

    /// A response to one of the agent's checks; a reply would be wrong.
    fn response(&mut self, w: &[&str]) -> Option<String> {
        let mut out = [0u8; 1500];
        let mut msg = [0u8; 1500];
        let tid: u128 = num(w[4]);
        let g = self.sent.get(&tid).copied().unwrap_or(self.generation);
        let (_, rp) = remote_creds(g);
        let wrong = "wrongpasswordwrongpass".to_owned();
        let n = match w[5] {
            "ok" => stun::write_success(&mut msg, &tid12(tid), run_addr(0), rp.as_bytes()),
            "unauth" => stun::write_success(&mut msg, &tid12(tid), run_addr(0), wrong.as_bytes()),
            e => stun::write_error(&mut msg, &tid12(tid), num(&e[4..]), rp.as_bytes()),
        }
        .unwrap();
        if let Some(len) = self.agent.on_stun(
            num(w[1]),
            num(w[2]),
            run_addr(num(w[3])),
            &msg[..n],
            &mut out,
        ) {
            return Some(format!("unexpected reply of {len} octets"));
        }
        None
    }

    /// Time passes: what the agent sends.
    fn poll(&mut self, now: u64, sent: &mut Vec<String>) {
        let mut out = [0u8; 1500];
        let draws = &mut self.draws;
        let mut random = |b: &mut [u8]| {
            let bytes = draws.to_be_bytes();
            b.copy_from_slice(&bytes[16 - b.len()..]);
            *draws += 1;
        };
        while let Some(t) = self.agent.poll(now, &mut out, &mut random) {
            let m = &out[..t.len];
            let mut tid = [0u8; 16];
            tid[4..].copy_from_slice(&m[8..20]);
            let tid = u128::from_be_bytes(tid);
            let attrs = stun_attrs(m);
            let user = attrs
                .iter()
                .find(|a| a.0 == 0x0006)
                .map_or(&[][..], |a| a.1);
            let g: u32 = std::str::from_utf8(&user[1..4])
                .ok()
                .and_then(|x| x.parse().ok())
                .unwrap_or(u32::MAX);
            self.sent.insert(tid, g);
            let uc = attrs.iter().any(|a| a.0 == 0x0025);
            let r = if attrs.iter().any(|a| a.0 == 0x802A) {
                "controlling"
            } else {
                "controlled"
            };
            sent.push(format!(
                "send:{}/{}/{tid}/{}/{r}/{}",
                t.component,
                t.dst.port() - 10_000,
                u8::from(uc),
                u8::from(g != self.generation)
            ));
        }
    }
}

/// A pair from vector fields (`id`, list, base, remote, foundation,
/// component, priority).
fn mk_pair(id: u16, list: u8, base: u16, remote: u16, f: u32, comp: u8, prio: u64) -> Pair {
    Pair::new(id, list, base, remote, f, comp, prio)
}

/// A compound RTCP packet as the reference renders it.
fn render_rtcp(bytes: &[u8]) -> String {
    let Some(c) = rtcp::compound(bytes) else {
        return "invalid".to_owned();
    };
    let parts: Vec<String> = c
        .map(|p| {
            let short = match p.pt {
                rtcp::PT_SR => "sr-short",
                rtcp::PT_RR => "rr-short",
                pt => return format!("pt {pt}"),
            };
            let Some(r) = rtcp::Report::of(&p) else {
                return short.to_owned();
            };
            let mut out = match r.sender {
                Some(i) => format!(
                    "sr {} {} {} {} {}",
                    r.ssrc, i.ntp, i.rtp_ts, i.packets, i.octets
                ),
                None => format!("rr {}", r.ssrc),
            };
            for b in r.blocks() {
                let _ = write!(
                    out,
                    " b {},{},{},{},{},{},{}",
                    b.ssrc, b.fraction, b.lost, b.highest, b.jitter, b.lsr, b.dlsr
                );
            }
            out
        })
        .collect();
    if parts.is_empty() {
        "empty".to_owned()
    } else {
        parts.join(" | ")
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn master(s: &str) -> Vec<u8> {
    unhex(s)
}

fn suite(s: &str) -> Suite {
    Suite::from_name(s.as_bytes()).expect("known suite")
}

fn media(sdp: &str) -> Result<Media, String> {
    let mut m = [Media::EMPTY; MAX_MEDIA];
    match read_media(sdp.as_bytes(), &mut m) {
        Ok(1) => Ok(m[0]),
        Ok(n) => Err(format!("{n} media sections")),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// What the current section line set up.
enum Section {
    None,
    SrtpSend(Protect),
    SrtpRecv(Unprotect),
    SrtcpSend(Protect),
    SrtcpRecv(Unprotect),
}

#[derive(Default)]
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

fn crypto_of(value: &str) -> Result<Option<String>, String> {
    let m = media(&format!(
        "v=0\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:{value}\r\n"
    ))?;
    Ok(m.crypto.map(|c| {
        let key: String = c.key.bytes().iter().fold(String::new(), |mut k, b| {
            let _ = write!(k, "{b:02x}");
            k
        });
        format!("{} {} {key}", c.tag, c.key.suite.name())
    }))
}

#[test]
#[allow(clippy::too_many_lines)]
fn rtpflux_agrees_with_the_reference_model() {
    let mut r = Report::default();
    let mut section = Section::None;
    let mut buf = vec![0u8; 4096];
    let mut runs: std::collections::HashMap<String, Run> = std::collections::HashMap::new();
    for (n, line) in VECTORS.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let at = n + 1;
        match f[0] {
            "srtp-send" => section = Section::SrtpSend(Protect::new(suite(f[1]), &master(f[2]))),
            "srtp-recv" => section = Section::SrtpRecv(Unprotect::new(suite(f[1]), &master(f[2]))),
            "srtcp-send" => section = Section::SrtcpSend(Protect::new(suite(f[1]), &master(f[2]))),
            "srtcp-recv" => {
                section = Section::SrtcpRecv(Unprotect::new(suite(f[1]), &master(f[2])));
            }
            "pkt" => {
                let (plain, wire) = (unhex(f[1]), unhex(f[2]));
                buf[..plain.len()].copy_from_slice(&plain);
                let out = match &mut section {
                    Section::SrtpSend(p) => p.rtp(&mut buf, plain.len()),
                    Section::SrtcpSend(p) => p.rtcp(&mut buf, plain.len()),
                    _ => panic!("line {at}: pkt outside a send section"),
                };
                r.check(out.is_ok_and(|k| buf[..k] == wire[..]), || {
                    format!(
                        "line {at}: protect gives {out:?} / differs from the reference wire packet"
                    )
                });
            }
            "in" => {
                let wire = unhex(f[1]);
                buf[..wire.len()].copy_from_slice(&wire);
                let out = match &mut section {
                    Section::SrtpRecv(u) => u.rtp(&mut buf, wire.len()),
                    Section::SrtcpRecv(u) => u.rtcp(&mut buf, wire.len()),
                    _ => panic!("line {at}: in outside a receive section"),
                };
                if f[2] == "drop" {
                    r.check(out.is_err(), || {
                        format!("line {at}: accepted, the reference drops it")
                    });
                } else {
                    let plain = unhex(f[2]);
                    r.check(out.is_ok_and(|k| buf[..k] == plain[..]), || {
                        format!("line {at}: unprotect gives {out:?}, the reference accepts it")
                    });
                }
            }
            "crypto" => {
                let expected = (f[2] != "none").then(|| f[2].to_owned());
                let got = crypto_of(f[1]);
                r.check(got.as_ref() == Ok(&expected), || {
                    format!(
                        "line {at}: a=crypto:{:?} gives {got:?}, the reference {expected:?}",
                        f[1]
                    )
                });
            }
            "crypto-select" => {
                let lines = f[2..].iter().fold(String::new(), |mut l, v| {
                    let _ = write!(l, "a=crypto:{v}\r\n");
                    l
                });
                let got = media(&format!("v=0\r\nm=audio 4000 RTP/SAVP 0\r\n{lines}"))
                    .map(|m| m.crypto.map(|c| c.tag));
                let expected = f[1]
                    .parse::<usize>()
                    .ok()
                    .map(|i| f[2 + i].split(' ').next().unwrap().parse::<u32>().unwrap());
                r.check(got == Ok(expected), || {
                    format!("line {at}: selects {got:?}, the reference tag {expected:?}")
                });
            }
            "rtcp" => {
                let expected: u16 = f[1].parse().unwrap();
                let attrs = f[2..].iter().fold(String::new(), |mut l, v| {
                    let _ = write!(l, "a=rtcp:{v}\r\n");
                    l
                });
                let got = media(&format!("v=0\r\nm=audio 4000 RTP/AVP 0\r\n{attrs}"))
                    .map(|m| m.rtcp_port);
                r.check(got == Ok(expected), || {
                    format!(
                        "line {at}: a=rtcp {:?} gives {got:?}, the reference {expected}",
                        &f[2..]
                    )
                });
            }
            "csum2" => {
                let v: Vec<u32> = f[1..].iter().map(|x| x.parse().unwrap()).collect();
                let w = |i: usize| u16::try_from(v[i]).expect("16-bit field");
                let got = csum_replace2(w(0), w(1), w(2));
                r.check(u32::from(got) == v[3], || {
                    format!(
                        "line {at}: csum_replace2({}, {}, {}) = {got}, the reference {}",
                        v[0], v[1], v[2], v[3]
                    )
                });
            }
            "csum4" => {
                let v: Vec<u32> = f[1..].iter().map(|x| x.parse().unwrap()).collect();
                let got = csum_replace4(u16::try_from(v[0]).expect("16-bit checksum"), v[1], v[2]);
                r.check(u32::from(got) == v[3], || {
                    format!(
                        "line {at}: csum_replace4({}, {:#x}, {:#x}) = {got}, the reference {}",
                        v[0], v[1], v[2], v[3]
                    )
                });
            }
            "xdp" => {
                let frame = unhex(f[1]);
                let a16 = |x: &str| <[u8; 16]>::try_from(unhex(x)).expect("16-octet address");
                let mac = |x: &str| <[u8; 6]>::try_from(unhex(x)).expect("MAC");
                let port = |x: &str| x.parse::<u16>().unwrap().to_be();
                let action = FlowAction {
                    new_src_addr: a16(f[2]),
                    new_dst_addr: a16(f[3]),
                    new_src_port: port(f[4]),
                    new_dst_port: port(f[5]),
                    src_mac: mac(f[6]),
                    dst_mac: mac(f[7]),
                    ifindex: 0,
                    flags: 0,
                    event_pt: 0,
                    reserved: [0; 2],
                };
                let got = match classify(&frame) {
                    Verdict::Pass => "pass".to_owned(),
                    Verdict::Lookup(k) => {
                        let mut key = Vec::new();
                        key.extend_from_slice(&k.src_addr);
                        key.extend_from_slice(&k.dst_addr);
                        key.extend_from_slice(&k.src_port.to_ne_bytes());
                        key.extend_from_slice(&k.dst_port.to_ne_bytes());
                        let mut out = frame.clone();
                        rewrite(&mut out, &k, &action);
                        format!("{}\t{}", hex(&key), hex(&out))
                    }
                };
                let want = f[8..].join("\t");
                r.check(got == want, || {
                    format!(
                        "line {at}: frame {} gives {got}, the reference {want}",
                        f[1]
                    )
                });
            }
            "rtcp-report" => {
                let got = render_rtcp(&unhex(f[1]));
                r.check(got == f[2], || {
                    format!(
                        "line {at}: RTCP {} reads as {got:?}, the reference {:?}",
                        f[1], f[2]
                    )
                });
            }
            "rtt" => {
                let v: Vec<u32> = f[1..].iter().map(|x| x.parse().unwrap()).collect();
                let got = rtcp::rtt(v[0], v[1], v[2]);
                r.check(got == v[3], || {
                    format!(
                        "line {at}: rtt({}, {}, {}) = {got}, the reference {}",
                        v[0], v[1], v[2], v[3]
                    )
                });
            }
            "g711-code" => {
                let v: Vec<i32> = f[1..].iter().map(|x| x.parse().unwrap()).collect();
                let c = u8::try_from(v[0]).unwrap();
                let got = [
                    i32::from(g711::ulaw_to_linear(c)),
                    i32::from(g711::alaw_to_linear(c)),
                    i32::from(g711::ULAW_TO_ALAW[usize::from(c)]),
                    i32::from(g711::ALAW_TO_ULAW[usize::from(c)]),
                ];
                r.check(got[..] == v[1..], || {
                    format!(
                        "line {at}: G.711 code {c}: {got:?}, the reference {:?}",
                        &v[1..]
                    )
                });
            }
            "g711-linear" => {
                let v: Vec<i32> = f[1..].iter().map(|x| x.parse().unwrap()).collect();
                let x = i16::try_from(v[0]).unwrap();
                let got = [
                    i32::from(g711::linear_to_ulaw(x)),
                    i32::from(g711::linear_to_alaw(x)),
                ];
                r.check(got[..] == v[1..], || {
                    format!(
                        "line {at}: G.711 of {x}: {got:?}, the reference {:?}",
                        &v[1..]
                    )
                });
            }
            "demux" => {
                let b: u8 = f[1].parse().unwrap();
                let got = match stun::classify(b) {
                    stun::Kind::Stun => "stun",
                    stun::Kind::Dtls => "dtls",
                    stun::Kind::Rtp => "rtp",
                    stun::Kind::Zrtp => "zrtp",
                    stun::Kind::Drop => "drop",
                };
                r.check(got == f[2], || {
                    format!(
                        "line {at}: first octet {b} is {got}, the reference {}",
                        f[2]
                    )
                });
            }
            "ice" => {
                let addr = unhex(f[5]);
                let ip: IpAddr = if f[4] == "6" {
                    IpAddr::from(<[u8; 16]>::try_from(addr.as_slice()).unwrap())
                } else {
                    IpAddr::from(<[u8; 4]>::try_from(addr.as_slice()).unwrap())
                };
                let src = SocketAddr::new(ip, f[6].parse().unwrap());
                let creds = stun::Credentials {
                    ufrag: f[2].as_bytes(),
                    pwd: f[3].as_bytes(),
                };
                let req = unhex(f[7]);
                let got = match stun::ice_lite(&req, creds, src, &mut buf) {
                    stun::Answer::Ignore => "none".to_owned(),
                    stun::Answer::Reply { len, .. } => {
                        buf[..len].iter().fold(String::new(), |mut h, b| {
                            let _ = write!(h, "{b:02x}");
                            h
                        })
                    }
                };
                r.check(got == f[8], || {
                    format!(
                        "line {at}: ICE {}: answers {got}, the reference {}",
                        f[1], f[8]
                    )
                });
            }
            "priority" => {
                let comp: u8 = f[1].parse().unwrap();
                let got = stun::host_priority(comp);
                r.check(got.to_string() == f[2], || {
                    format!(
                        "line {at}: host priority of component {comp} is {got}, the reference {}",
                        f[2]
                    )
                });
            }
            "ice-cand-priority" => {
                let t = match f[1] {
                    "host" => CandType::Host,
                    "srflx" => CandType::Srflx,
                    "prflx" => CandType::Prflx,
                    _ => CandType::Relay,
                };
                let got = checklist::candidate_priority(t.type_pref(), num(f[2]), num(f[3]));
                r.check(got.to_string() == f[4], || {
                    format!("line {at}: {} priority {got}, the reference {}", f[1], f[4])
                });
            }
            "ice-pair-priority" => {
                let got = checklist::pair_priority(role(f[1]), num(f[2]), num(f[3]));
                r.check(got.to_string() == f[4], || {
                    format!("line {at}: pair priority {got}, the reference {}", f[4])
                });
            }
            "ice-check" => {
                let tid: [u8; 12] = unhex(f[2]).try_into().unwrap();
                let tb = u64::from_be_bytes(unhex(f[7]).try_into().unwrap());
                let req = stun::CheckRequest {
                    username: f[3].as_bytes(),
                    pwd: f[4].as_bytes(),
                    priority: checklist::candidate_priority(
                        CandType::Prflx.type_pref(),
                        num(f[5]),
                        num(f[6]),
                    ),
                    role: role(f[1]),
                    tiebreaker: tb,
                    use_candidate: f[8] == "1",
                };
                let len = stun::write_check(&mut buf, &tid, &req).unwrap();
                let got = hex(&buf[..len]);
                r.check(got == f[9], || {
                    format!("line {at}: check {got}, the reference {}", f[9])
                });
            }
            "ice-role" => {
                let (nr, conflict) =
                    stun::on_role_request(role(f[1]), num(f[2]), role(f[3]), num(f[4]));
                let got = format!(
                    "{} {}",
                    role_name(nr),
                    if conflict { "487" } else { "success" }
                );
                let want = format!("{} {}", f[5], f[6]);
                r.check(got == want, || {
                    format!("line {at}: role {got}, the reference {want}")
                });
            }
            "ice-role-reply" => {
                let got = stun::on_role_reply(role(f[1]), role(f[2]), f[3] == "487");
                r.check(role_name(got) == f[4], || {
                    format!(
                        "line {at}: role after reply {}, the reference {}",
                        role_name(got),
                        f[4]
                    )
                });
            }
            "ice-init" => {
                let mut ps: Vec<Pair> = items(f[1])
                    .iter()
                    .enumerate()
                    .map(|(k, p)| {
                        mk_pair(
                            u16::try_from(k).unwrap(),
                            num(p[2]),
                            0,
                            0,
                            num(p[0]),
                            num(p[1]),
                            0,
                        )
                    })
                    .collect();
                checklist::initial_states(&mut ps);
                let got: Vec<&str> = ps.iter().map(|p| letter(p.state)).collect();
                r.check(got.join(",") == f[2], || {
                    format!(
                        "line {at}: initial states {}, the reference {}",
                        got.join(","),
                        f[2]
                    )
                });
            }
            "ice-next" => {
                let queue: Vec<u16> = if f[1] == "-" {
                    Vec::new()
                } else {
                    f[1].split(',').map(num).collect()
                };
                let ps: Vec<Pair> = items(f[2])
                    .iter()
                    .map(|p| {
                        let mut q = mk_pair(num(p[0]), 0, 0, 0, 0, num(p[2]), num(p[1]));
                        q.state = state_of(p[3]);
                        q
                    })
                    .collect();
                let got =
                    checklist::next_check(&queue, &ps).map_or("none".to_owned(), |i| i.to_string());
                r.check(got == f[3], || {
                    format!("line {at}: next check {got}, the reference {}", f[3])
                });
            }
            "ice-rto" => {
                let got = checklist::check_rto(num(f[1]), num(f[2]), num(f[3]), num(f[4]));
                r.check(got.to_string() == f[5], || {
                    format!("line {at}: RTO {got}, the reference {}", f[5])
                });
            }
            "ice-trickle-state" => {
                let ps: Vec<Pair> = items(f[1])
                    .iter()
                    .enumerate()
                    .map(|(k, p)| {
                        let mut q = mk_pair(
                            u16::try_from(k).unwrap(),
                            0,
                            0,
                            0,
                            num(p[0]),
                            num(p[1]),
                            num(p[2]),
                        );
                        q.state = state_of(p[3]);
                        q
                    })
                    .collect();
                let new: Vec<&str> = f[2].split('/').collect();
                let pair = mk_pair(99, 0, 0, 0, num(new[0]), num(new[1]), num(new[2]));
                let got = letter(checklist::new_state(&ps, &pair));
                r.check(got == f[3], || {
                    format!(
                        "line {at}: trickled pair state {got}, the reference {}",
                        f[3]
                    )
                });
            }
            "ice-trickle-insert" => {
                let shape = |q: &Pair| {
                    format!(
                        "{}/{}/{}/{}/{}/{}/{}/{}",
                        q.id,
                        q.list,
                        q.base,
                        q.remote,
                        q.priority,
                        q.foundation,
                        q.component,
                        letter(q.state)
                    )
                };
                let mut list: List<Pair, 100> = List::new(Pair::EMPTY);
                for p in items(f[2]) {
                    let mut q = mk_pair(
                        num(p[0]),
                        num(p[1]),
                        num(p[2]),
                        num(p[3]),
                        num(p[5]),
                        num(p[6]),
                        num(p[4]),
                    );
                    q.state = state_of(p[7]);
                    list.push(q);
                }
                let new: Vec<&str> = f[3].split('/').collect();
                let pair = mk_pair(
                    num(new[0]),
                    num(new[1]),
                    num(new[2]),
                    num(new[3]),
                    num(new[5]),
                    num(new[6]),
                    num(new[4]),
                );
                checklist::insert_pair(num(f[1]), &mut list, pair);
                let got: Vec<String> = list.iter().map(shape).collect();
                r.check(got.join(",") == f[4], || {
                    format!(
                        "line {at}: after insertion {}, the reference {}",
                        got.join(","),
                        f[4]
                    )
                });
            }
            "ice-list-state" => {
                let comps: Vec<u8> = f[3].split(',').map(num).collect();
                let ps: Vec<Pair> = items(f[4])
                    .iter()
                    .enumerate()
                    .map(|(k, p)| {
                        let mut q = mk_pair(u16::try_from(k).unwrap(), 0, 0, 0, 0, num(p[0]), 0);
                        q.state = state_of(p[1]);
                        q.nominated = p[2] == "1";
                        q
                    })
                    .collect();
                let got = match checklist::list_state(f[1] == "1", f[2] == "1", &comps, &ps) {
                    ListState::Running => "running",
                    ListState::Completed => "completed",
                    ListState::Failed => "failed",
                };
                r.check(got == f[5], || {
                    format!("line {at}: checklist {got}, the reference {}", f[5])
                });
            }
            "consent" => {
                let mut consent = Consent::new(5_000);
                let mut outs = Vec::new();
                for e in f[1].split(',').filter(|e| !e.is_empty()) {
                    let (kind, rest) = e.split_at(1);
                    let two = |text: &str| {
                        let (x, y) = text.split_once(':').unwrap();
                        (num::<u64>(x), num::<u64>(y))
                    };
                    match kind {
                        "t" => {
                            if consent.tick(num(rest)) {
                                outs.push("stop".to_owned());
                            }
                        }
                        "s" => consent.succeeded(num(rest)),
                        "x" => {
                            let (tid, d) = two(rest);
                            if consent.send(u128::from(tid), d) {
                                outs.push(format!("c{tid}"));
                            }
                        }
                        "r" => {
                            let (tid, ok) = two(rest);
                            consent.response(u128::from(tid), ok == 1);
                        }
                        _ => consent.restart(),
                    }
                }
                let got = format!(
                    "{} {} {}",
                    if outs.is_empty() {
                        "-".to_owned()
                    } else {
                        outs.join(",")
                    },
                    u8::from(consent.may_send()),
                    u8::from(consent.lost())
                );
                let want = format!("{} {} {}", f[2], f[3], f[4]);
                r.check(got == want, || {
                    format!("line {at}: consent {}: {got}, the reference {want}", f[1])
                });
            }
            "sdpfrag" => {
                let known_body = if f[4] == "-" { Vec::new() } else { unhex(f[4]) };
                let known = rtpflux::trickle::Fragment::parse(&known_body);
                let body = unhex(f[5]);
                let frag = rtpflux::trickle::Fragment::parse(&body);
                let res = rtpflux::trickle::deliver(
                    f[2].as_bytes(),
                    f[3].as_bytes(),
                    |mid| {
                        known
                            .sections
                            .iter()
                            .filter(|s| s.mid == mid)
                            .flat_map(|s| s.candidates.iter().copied())
                            .collect()
                    },
                    &frag,
                );
                let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
                let got = match res {
                    None => "none".to_owned(),
                    Some((eoc, ds)) => {
                        let mut parts = vec![format!("eoc={}", u8::from(eoc))];
                        for d in ds {
                            let cands: Vec<String> = d
                                .candidates
                                .iter()
                                .map(|c| {
                                    format!(
                                        "{}/{}/{}",
                                        text(c.addr),
                                        text(c.port_text),
                                        text(c.component_text)
                                    )
                                })
                                .collect();
                            parts.push(format!(
                                "{}:{}:{}",
                                text(d.mid),
                                u8::from(d.end_of_candidates),
                                cands.join(",")
                            ));
                        }
                        parts.join(";")
                    }
                };
                r.check(got == f[6], || {
                    format!("line {at}: sdpfrag {}: {got}, the reference {}", f[1], f[6])
                });
            }
            "ice-agent-start" => {
                let (lu, lp) = local_creds(0);
                let (ru, rp) = remote_creds(0);
                let agent = Agent::new(&rtpflux_core::ice::Config {
                    role: role(f[2]),
                    tiebreaker: num(f[3]),
                    local_ufrag: lu.as_bytes(),
                    local_pwd: lp.as_bytes(),
                    remote_ufrag: ru.as_bytes(),
                    remote_pwd: rp.as_bytes(),
                    components: num(f[4]),
                    v6: false,
                    ta_ms: num(f[5]),
                })
                .unwrap();
                runs.insert(
                    f[1].to_owned(),
                    Run {
                        agent,
                        generation: 0,
                        draws: 0,
                        sent: std::collections::HashMap::new(),
                    },
                );
            }
            "ice-agent" => {
                let run = runs.get_mut(f[1]).unwrap();
                let sent = run.apply(f[3]);
                let got = if sent.is_empty() {
                    "-".to_owned()
                } else {
                    sent.join(",")
                };
                let obs = run.obs();
                r.check(got == f[4] && obs == f[5], || {
                    format!(
                        "line {at}: run {} step {} ({}): sends {got} / {obs}, the reference {} / {}",
                        f[1], f[2], f[3], f[4], f[5]
                    )
                });
            }
            "setup" => {
                let (o, a) = (
                    Setup::parse(f[1].as_bytes()).unwrap(),
                    Setup::parse(f[2].as_bytes()).unwrap(),
                );
                let got_compat = dtls_core::compatible(o, a).to_string();
                let got_client = match dtls_core::client_is_offerer(a) {
                    Some(true) => "offerer",
                    Some(false) => "answerer",
                    None => "none",
                };
                r.check(got_compat == f[3] && got_client == f[4], || {
                    format!(
                        "line {at}: setup {} / {}: {got_compat} {got_client}, the reference {} {}",
                        f[1], f[2], f[3], f[4]
                    )
                });
            }
            "fingerprint" => {
                let cert = unhex(f[1]);
                let fps: Vec<_> = f[3..]
                    .iter()
                    .filter_map(|v| dtls_core::Fingerprint::parse(v.as_bytes()))
                    .collect();
                let got = if dtls::matches(&fps, &cert) {
                    "proceed"
                } else {
                    "teardown"
                };
                r.check(got == f[2], || {
                    format!(
                        "line {at}: fingerprints {:?}: {got}, the reference {}",
                        &f[3..],
                        f[2]
                    )
                });
            }
            "keying" => {
                let role = if f[1] == "client" {
                    dtls_core::Role::Client
                } else {
                    dtls_core::Role::Server
                };
                let material: [u8; 60] = unhex(f[2]).try_into().unwrap();
                let (send, recv) =
                    dtls_core::split_keys(&material, Suite::AesCm128HmacSha1_80, role).unwrap();
                let (send, recv) = (send.bytes().to_vec(), recv.bytes().to_vec());
                r.check(
                    send[..] == unhex(f[3])[..] && recv[..] == unhex(f[4])[..],
                    || format!("line {at}: {} keys differ from the reference", f[1]),
                );
            }
            "exporter" => {
                let mut got = [0u8; 60];
                dtls::exporter(&unhex(f[1]), &unhex(f[2]), &unhex(f[3]), &mut got);
                r.check(got[..] == unhex(f[4])[..], || {
                    format!("line {at}: exporter output differs from the reference")
                });
            }
            "group" => {
                let got = if rtpflux_core::sdp::keeps_group(f[2].as_bytes()) {
                    "keep"
                } else {
                    "drop"
                };
                r.check(got == f[1], || {
                    format!(
                        "line {at}: a=group:{:?} {got}, the reference {}",
                        f[2], f[1]
                    )
                });
            }
            "bundle-answer" => {
                let ids = |f: &str| -> Vec<Vec<u8>> {
                    f.split(',')
                        .filter(|i| !i.is_empty())
                        .map(|i| i.as_bytes().to_vec())
                        .collect()
                };
                let (offered, refused) = (ids(f[1]), ids(f[2]));
                let offered: Vec<&[u8]> = offered.iter().map(Vec::as_slice).collect();
                let refused: Vec<&[u8]> = refused.iter().map(Vec::as_slice).collect();
                let mut out: Vec<&[u8]> = vec![&[]; offered.len()];
                let n = rtpflux_core::sdp::answer_group(&offered, &refused, &mut out);
                let got = out[..n]
                    .iter()
                    .map(|i| String::from_utf8_lossy(i))
                    .collect::<Vec<_>>()
                    .join(",");
                r.check(got == f[3], || {
                    format!("line {at}: BUNDLE answer {got:?}, the reference {:?}", f[3])
                });
            }
            "dtmf" => {
                use rtpflux_core::dtmf::{Detector, decode};
                let mut d = Detector::new(f[1].parse().unwrap());
                let mut ended = Vec::new();
                for token in f[2].split(' ').filter(|t| !t.is_empty()) {
                    let parts: Vec<&str> = token.split(':').collect();
                    match parts[0] {
                        "r" => {
                            let ev = decode(&unhex(parts[3])).expect("event payload");
                            ended.extend(
                                d.report(parts[1].parse().unwrap(), ev)
                                    .into_iter()
                                    .flatten(),
                            );
                        }
                        "media" => ended.extend(d.media()),
                        "tick" => ended.extend(d.tick(parts[1].parse().unwrap())),
                        other => panic!("line {at}: unknown event {other}"),
                    }
                }
                let got: Vec<String> = ended
                    .iter()
                    .map(|e| format!("{}:{}:{}:{}", e.code, e.ts, e.duration, e.extension))
                    .collect();
                let cur = d
                    .current()
                    .map_or("-".to_owned(), |(c, t, du)| format!("{c}:{t}:{du}"));
                r.check(got.join(" ") == f[3] && cur == f[4], || {
                    format!(
                        "line {at}: DTMF {:?} / {cur}, the reference {:?} / {}",
                        got.join(" "),
                        f[3],
                        f[4]
                    )
                });
            }
            "dtmf-inband" => {
                use rtpflux_core::dtmf_inband::{Change, Detector};
                let mut d = Detector::new();
                let got: Vec<String> = f[1]
                    .split(' ')
                    .filter(|t| !t.is_empty())
                    .map(|t| match d.step(t.parse().ok()) {
                        None => ".".to_owned(),
                        Some(Change::Start(c)) => format!("s{c}"),
                        Some(Change::End) => "e".to_owned(),
                    })
                    .collect();
                let held = d.held().map_or("-".to_owned(), |c| c.to_string());
                r.check(got.join(" ") == f[2] && held == f[3], || {
                    format!(
                        "line {at}: in-band DTMF {:?} / {held}, the reference {:?} / {}",
                        got.join(" "),
                        f[2],
                        f[3]
                    )
                });
            }
            "ng-message" => {
                let got = match rtpflux::ngstream::message_len(&unhex(f[1])) {
                    Ok(Some(n)) => n.to_string(),
                    Ok(None) => "more".to_owned(),
                    Err(_) => "bad".to_owned(),
                };
                r.check(got == f[2], || {
                    format!("line {at}: ng message length {got}, the reference {}", f[2])
                });
            }
            "ng-stream" => {
                let mut framer = rtpflux::ngstream::NgFramer::new();
                let mut got = Vec::new();
                for c in f[1].split(',').filter(|_| !f[1].is_empty()) {
                    got.extend(framer.push(&unhex(c)).iter().map(|m| hex(m)));
                }
                let state = if framer.is_closed() { "closed" } else { "open" };
                r.check(got.join(",") == f[2] && state == f[3], || {
                    format!(
                        "line {at}: ng stream {} messages / {state}, the reference {} / {}",
                        got.len(),
                        f[2].split(',').filter(|m| !m.is_empty()).count(),
                        f[3]
                    )
                });
            }
            "ws-read" => {
                use rtpflux::ngstream::{Parsed, parse_frame};
                let got = match parse_frame(&unhex(f[1])) {
                    Parsed::More => "more".to_owned(),
                    Parsed::Close => "close".to_owned(),
                    Parsed::Frame {
                        fin,
                        op,
                        payload,
                        used,
                    } => {
                        format!("frame {} {op} {} {used}", u8::from(fin), hex(&payload))
                    }
                };
                r.check(got == f[2], || {
                    format!(
                        "line {at}: WebSocket read {got:?}, the reference {:?}",
                        f[2]
                    )
                });
            }
            "taps" => {
                use rtpflux::relay::taps::{Arrival, Taps};
                let mut t = Taps::new(f[1].parse().unwrap());
                let mut target: std::collections::HashMap<u32, u32> =
                    std::collections::HashMap::new();
                let nums =
                    |s: &str| -> Vec<u32> { s.split(',').map(|x| x.parse().unwrap()).collect() };
                let mut got = Vec::new();
                for op in f[2].split(' ') {
                    let (kind, args) = op.split_once(':').unwrap();
                    got.push(match kind {
                        "s" => {
                            t.sink(&nums(args));
                            ".".to_owned()
                        }
                        "t" => {
                            let v = nums(args);
                            let pairs: Vec<(u32, u32)> =
                                v[..v.len() - 1].chunks(2).map(|c| (c[0], c[1])).collect();
                            if t.tap(&pairs, v[v.len() - 1] == 1) {
                                "ok"
                            } else {
                                "no"
                            }
                            .to_owned()
                        }
                        "c" => {
                            t.close(&nums(args));
                            ".".to_owned()
                        }
                        "g" => {
                            let (slot, d) = args.split_once(',').unwrap();
                            match d.parse() {
                                Ok(d) => target.insert(slot.parse().unwrap(), d),
                                Err(_) => target.remove(&slot.parse().unwrap()),
                            };
                            ".".to_owned()
                        }
                        "p" => {
                            let v = nums(args);
                            match t.arrive(v[0] as usize, v[1] == 1) {
                                Arrival::Sink => "S".to_owned(),
                                // Copies go to the taps whose latch knows
                                // where (as the worker sends them).
                                Arrival::Copy(to) => format!(
                                    "c:{}",
                                    to.iter()
                                        .filter_map(|x| target.get(x).map(|d| format!("{x}@{d}")))
                                        .collect::<Vec<_>>()
                                        .join("+")
                                ),
                            }
                        }
                        other => panic!("line {at}: unknown operation {other}"),
                    });
                }
                r.check(got.join(" ") == f[3], || {
                    format!(
                        "line {at}: copies {:?}, the reference {:?}",
                        got.join(" "),
                        f[3]
                    )
                });
            }
            "play" => {
                use rtpflux::relay::play::{Cursor, FRAME, plan};
                let opt = |x: &str| x.parse::<u64>().ok();
                let got = match plan(
                    f[1].parse().unwrap(),
                    f[2].parse().unwrap(),
                    opt(f[3]),
                    f[4].parse().unwrap(),
                    opt(f[5]),
                ) {
                    None => "error".to_owned(),
                    Some(p) => {
                        let k: usize = f[6].parse().unwrap();
                        let mut frames = Vec::new();
                        if let Some(mut c) = Cursor::start(p.len, p.repeat, p.limit, k * FRAME) {
                            while let Some((at, n)) = c.next_frame() {
                                frames.push(format!("{}:{n}", p.start + at));
                            }
                        }
                        format!("{} {}", p.len / 8, frames.join(","))
                    }
                };
                r.check(got == f[7], || {
                    format!("line {at}: play {got:?}, the reference {:?}", f[7])
                });
            }
            "dtmf-plan" => {
                use rtpflux::relay::xcode::{Edit, Plan, plan, settle};
                use rtpflux_core::sdp::Codec;
                let te = |x: &str| {
                    x.split_once(':')
                        .map(|(p, r)| (p.parse::<Pt>().unwrap(), r.parse::<u32>().unwrap()))
                };
                // The reference's audio is a payload type; its codec:
                let audio = |x: &str| {
                    x.parse::<Pt>().ok().map(|pt| {
                        let codec = match pt.get() {
                            111 => Codec::Opus,
                            _ => Codec::of_static(pt).unwrap(),
                        };
                        (pt, codec)
                    })
                };
                let list = |x: &str| -> Vec<Pt> {
                    x.split(',')
                        .filter(|v| !v.is_empty())
                        .map(|v| v.parse().unwrap())
                        .collect()
                };
                let p = plan(&list(f[1]), &list(f[2]), te(f[3]), f[4] == "1", f[5] == "1");
                let s = settle(p, te(f[6]), audio(f[7]), audio(f[8]));
                let conv = |c: Option<rtpflux::relay::DtmfXcode>| {
                    c.map_or("-".to_owned(), |c| {
                        format!(
                            "{}{}{}",
                            c.to_inband
                                .map_or(String::new(), |(pt, _)| format!("i{pt}")),
                            c.to_events
                                .map_or(String::new(), |(pt, r)| format!("e{pt}:{r}")),
                            c.audio.map_or(String::new(), |(pt, _)| format!("a{pt}"))
                        )
                    })
                };
                let got = [
                    match p {
                        Some(Plan::Offered(pt)) => format!("offered:{pt}"),
                        Some(Plan::Kept(pt, r)) => format!("kept:{pt}:{r}"),
                        None => "-".to_owned(),
                    },
                    match s.toward_a {
                        Some(Edit::Remove(pt)) => format!("remove:{pt}"),
                        Some(Edit::Append(pt)) => format!("append:{pt}"),
                        None => "-".to_owned(),
                    },
                    conv(s.a),
                    conv(s.b),
                ];
                r.check(got[..] == f[9..13], || {
                    format!(
                        "line {at}: DTMF transcoding {got:?}, the reference {:?}",
                        &f[9..13]
                    )
                });
            }
            "dtmf-events" => {
                let mut ev = rtpflux::relay::xcode::EventTones::default();
                let got: Vec<String> = f[1]
                    .split(' ')
                    .map(|p| {
                        let v: Vec<u32> = p.split(':').map(|x| x.parse().unwrap()).collect();
                        match ev.packet(v[0], u8::try_from(v[1]).unwrap(), v[2] == 1) {
                            (Some(k), true) => format!("s{k}e"),
                            (Some(k), false) => format!("s{k}"),
                            (None, true) => "e".to_owned(),
                            (None, false) => ".".to_owned(),
                        }
                    })
                    .collect();
                r.check(got.join(" ") == f[2], || {
                    format!(
                        "line {at}: event tones {:?}, the reference {:?}",
                        got.join(" "),
                        f[2]
                    )
                });
            }
            "rec" => {
                use rtpflux::lifecycle::{Rec, RecStep};
                let mut rec = Rec::default();
                let step = |s: RecStep| match s {
                    RecStep::Open(f) => format!("open:{f}"),
                    RecStep::Resume(f) => format!("resume:{f}"),
                    RecStep::Pause(f) => format!("pause:{f}"),
                    RecStep::Close(f) => format!("close:{f}"),
                    RecStep::Nothing => "-".to_owned(),
                };
                let got: Vec<String> = f[1]
                    .split(' ')
                    .map(|op| match op {
                        "start" => step(rec.start()),
                        "pause" => step(rec.pause()),
                        "stop" => step(rec.stop()),
                        _ => rec.writes().map_or("x".to_owned(), |f| format!("w:{f}")),
                    })
                    .collect();
                r.check(got.join(" ") == f[2], || {
                    format!(
                        "line {at}: recording {:?}, the reference {:?}",
                        got.join(" "),
                        f[2]
                    )
                });
            }
            "delays" => {
                let mut d = rtpflux::lifecycle::Delays::<u64, u64>::default();
                let got: Vec<String> = f[1]
                    .split(' ')
                    .map(|op| {
                        let v: Vec<u64> = op[2..].split(':').map(|x| x.parse().unwrap()).collect();
                        if op.starts_with("s:") {
                            d.schedule(v[0], v[1]);
                            ".".to_owned()
                        } else {
                            let due = d.due(v[0]);
                            if due.is_empty() {
                                "-".to_owned()
                            } else {
                                due.iter().map(u64::to_string).collect::<Vec<_>>().join(",")
                            }
                        }
                    })
                    .collect();
                r.check(got.join(" ") == f[2], || {
                    format!(
                        "line {at}: delays {:?}, the reference {:?}",
                        got.join(" "),
                        f[2]
                    )
                });
            }
            "publish-answer" => {
                let got = hex(&rtpflux::publish::sink_answer(&unhex(f[1])));
                r.check(got == f[2], || {
                    format!(
                        "line {at}: publish answer {:?}, the reference {:?}",
                        String::from_utf8_lossy(&unhex(&got)),
                        String::from_utf8_lossy(&unhex(f[2]))
                    )
                });
            }
            "codec-plan" => {
                let got = codec_plan_line(f[1], f[2], f[3]);
                let want = [f[4], f[5], f[6]].join("\t");
                r.check(got == want, || {
                    format!("line {at}: codec plan {got:?}, the reference {want:?}")
                });
            }
            "reply-cache" => {
                let got = reply_cache_line(f[1], f[2]);
                let want = [f[3], f[4]].join("\t");
                r.check(got == want, || {
                    format!("line {at}: reply cache {got:?}, the reference {want:?}")
                });
            }
            "state-side" => {
                use rtpflux::state::SavedSide;
                let saved: SavedSide = serde_json::from_str(f[1]).unwrap();
                let got = saved.side().map(|s| SavedSide::of(&s, (None, None)));
                let want = (f[2] != "-").then(|| serde_json::from_str::<SavedSide>(f[2]).unwrap());
                r.check(got == want, || {
                    format!("line {at}: state side {got:?}, the reference {want:?}")
                });
            }
            "state-rec" => {
                let extras = rtpflux::state::SavedExtras {
                    recording: (f[1] == "1").then(|| "x.pcap".to_owned()),
                    recording_paused: f[2] == "1",
                    recordings_opened: f[3].parse().unwrap(),
                    ..Default::default()
                };
                let rec = extras.rec();
                let got = format!(
                    "{}\t{}",
                    rec.current()
                        .map_or("-".to_owned(), |(f, p)| format!("{f}:{}", u8::from(p))),
                    rec.opened()
                );
                let want = [f[4], f[5]].join("\t");
                r.check(got == want, || {
                    format!("line {at}: restored recording {got}, the reference {want}")
                });
            }
            "state-newer" => {
                let snap = |x: &str| {
                    (x != "-").then(|| rtpflux::state::Saved {
                        version: rtpflux::state::VERSION,
                        saved_ms: x.parse().unwrap(),
                        sessions: Vec::new(),
                        subscriptions: vec![],
                        connections: vec![],
                        labels: vec![],
                        copies: vec![],
                        endpoints: vec![],
                    })
                };
                let (file, redis) = (snap(f[1]), snap(f[2]));
                let got = match rtpflux::state::newer(file.clone(), redis) {
                    None => "-",
                    Some(s) if Some(&s) == file.as_ref() && f[1] != f[2] => "file",
                    Some(_) if f[1] == f[2] => "file",
                    Some(_) => "redis",
                };
                r.check(got == f[3], || {
                    format!("line {at}: newer {got}, the reference {}", f[3])
                });
            }
            "port-alloc" => {
                let first: u16 = f[1].parse().unwrap();
                let mut a =
                    rtpflux_core::ports::PairAllocator::new(first, f[2].parse().unwrap()).unwrap();
                let outs: Vec<String> = f[3]
                    .split(',')
                    .map(|op| match op.split_at(1) {
                        ("a", _) => a.alloc().map_or("-".to_owned(), |p| p.to_string()),
                        ("f", p) => u8::from(a.free(p.parse().unwrap())).to_string(),
                        ("t", p) => u8::from(a.take(p.parse().unwrap())).to_string(),
                        _ => panic!("line {at}: op {op}"),
                    })
                    .collect();
                let got = format!("{}\t{}", outs.join(","), a.in_use());
                let want = [f[4], f[5]].join("\t");
                r.check(got == want, || {
                    format!("line {at}: port allocation {got}, the reference {want}")
                });
            }
            "reoffer-section" => {
                use rtpflux::reoffer::{Action, action};
                let prev = (f[1] != "-").then(|| {
                    let p: Vec<u8> = f[1].split(':').map(|x| x.parse().unwrap()).collect();
                    (p[0] == 1, p[1] == 1, p[2])
                });
                let (a, ends) = action(prev, f[2].parse().unwrap(), &f[3].parse::<u8>().unwrap());
                let name = match a {
                    Action::Keep => "keep",
                    Action::KeepBundled => "keep-bundled",
                    Action::Create => "create",
                    Action::Disabled => "disabled",
                };
                let got = format!("{name}\t{}", u8::from(ends));
                let want = [f[4], f[5]].join("\t");
                r.check(got == want, || {
                    format!("line {at}: re-offer section {got}, the reference {want}")
                });
            }
            "sub-select" => {
                use rtpflux::subscription::{Pick, SelectError, select};
                let dialogs: Vec<(&[u8], Option<&[u8]>)> = if f[1] == "." {
                    Vec::new()
                } else {
                    f[1].split(',')
                        .map(|d| {
                            let (from, to) = d.split_once(':').unwrap();
                            (from.as_bytes(), (to != "-").then_some(to.as_bytes()))
                        })
                        .collect()
                };
                let pick = match f[2].split_once(':') {
                    None if f[2] == "all" => Pick::All,
                    None => Pick::Missing,
                    Some(("one", t)) => Pick::One(t.as_bytes()),
                    Some((_, "")) => Pick::Tags(Vec::new()),
                    Some((_, ts)) => Pick::Tags(ts.split(',').map(str::as_bytes).collect()),
                };
                let got = match select(&dialogs, &pick) {
                    Ok(out) => out
                        .iter()
                        .map(|(k, b, t)| {
                            format!("{k}:{}:{}", u8::from(*b), String::from_utf8_lossy(t))
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    Err(SelectError::UnknownCall) => "!call".to_owned(),
                    Err(SelectError::NoFromTag) => "!from-tag".to_owned(),
                    Err(SelectError::NoSource) => "!none".to_owned(),
                    Err(SelectError::UnknownTag(t)) => {
                        format!("!tag:{}", String::from_utf8_lossy(&t))
                    }
                };
                r.check(got == f[3], || {
                    format!(
                        "line {at}: subscription sources {got}, the reference {}",
                        f[3]
                    )
                });
            }
            "sub-answer" => {
                use rtpflux::subscription::{Answered, Offered, Refusal, check_answer};
                let fmts = |t: &str| -> Vec<Pt> {
                    if t == "." {
                        Vec::new()
                    } else {
                        t.split(' ').map(|x| x.parse().unwrap()).collect()
                    }
                };
                let offered_f: Vec<(bool, bool, Vec<Pt>)> = f[1]
                    .split(';')
                    .map(|s| {
                        let p: Vec<&str> = s.split(':').collect();
                        (p[0] == "1", p[1] == "1", fmts(p[2]))
                    })
                    .collect();
                let answered_f: Vec<(u16, bool, bool, Vec<Pt>)> = if f[2] == "." {
                    Vec::new()
                } else {
                    f[2].split(';')
                        .map(|a| {
                            let p: Vec<&str> = a.split(':').collect();
                            (p[0].parse().unwrap(), p[1] == "1", p[2] == "1", fmts(p[3]))
                        })
                        .collect()
                };
                let offered: Vec<Offered<'_>> = offered_f
                    .iter()
                    .map(|(d, k, fm)| Offered {
                        dtls: *d,
                        key: *k,
                        formats: fm,
                    })
                    .collect();
                let answered: Vec<Answered<'_>> = answered_f
                    .iter()
                    .map(|(p, d, s, fm)| Answered {
                        port: *p,
                        dtls: *d,
                        sdes: *s,
                        formats: fm,
                    })
                    .collect();
                let got = match check_answer(&offered, &answered) {
                    Ok(taps) => format!(
                        "ok:{}",
                        taps.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                    Err((k, why)) => format!(
                        "!{k}:{}",
                        match why {
                            Refusal::Dtls => "dtls",
                            Refusal::Srtp => "srtp",
                            Refusal::Formats => "formats",
                        }
                    ),
                };
                r.check(got == f[3], || {
                    format!(
                        "line {at}: subscriber's answer {got}, the reference {}",
                        f[3]
                    )
                });
            }
            "play-stream" => {
                let p: Vec<u64> = f[1].split(':').map(|x| x.parse().unwrap()).collect();
                let mut s = rtpflux::relay::stream::PlayStream::new(
                    rtpflux_core::rtp::Ssrc::new(0),
                    u16::try_from(p[0]).unwrap(),
                    u32::try_from(p[1]).unwrap(),
                    p[2],
                );
                let per_ms = u32::try_from(p[3]).unwrap();
                let mut outs = Vec::new();
                for op in f[2].split(',') {
                    let (kind, due) = op.split_at(1);
                    let due: u64 = due.parse().unwrap();
                    if kind == "t" {
                        s.advance(due, per_ms);
                    } else {
                        let (seq, ts) = s.packet(due, per_ms);
                        outs.push(format!("{seq}:{ts}"));
                    }
                }
                let got = outs.join(",");
                r.check(got == f[3], || {
                    format!("line {at}: play stream {got}, the reference {}", f[3])
                });
            }
            "play-hold" => {
                use rtpflux::relay::hold::{Hold, Kind};
                let mut h = Hold::new(3);
                let outs: Vec<String> = f[1]
                    .split(',')
                    .map(|op| {
                        let b = op.as_bytes();
                        let kind = if b[1] == b'a' {
                            Kind::Announcement
                        } else {
                            Kind::Keys
                        };
                        let to = usize::from(b[2] - b'0');
                        if b[0] == b's' {
                            h.start(kind, to);
                        } else {
                            h.finish(kind, to);
                        }
                        (0..3).map(|j| if h.held(j) { '1' } else { '0' }).collect()
                    })
                    .collect();
                let got = outs.join(",");
                r.check(got == f[2], || {
                    format!("line {at}: hold {got}, the reference {}", f[2])
                });
            }
            "latch" => {
                use rtpflux_core::latch::{Latch, Learning, Verdict};
                let addr = |t: &str| -> Option<std::net::SocketAddr> {
                    (t != "-").then(|| t.parse().unwrap())
                };
                let mode = match f[1] {
                    "off" => Learning::Off,
                    "immediate" => Learning::Immediate,
                    _ => Learning::Heuristic,
                };
                let mut latch = Latch::new(addr(f[3]), mode, f[2] == "strict");
                let target = |x: &Latch| x.target().map_or("-".to_owned(), |a| a.to_string());
                let outs: Vec<String> = f[4]
                    .split(';')
                    .map(|op| match op.split_at(1) {
                        ("p", rest) => {
                            let (a, now) = rest.split_once('@').unwrap();
                            let now: u64 = now.parse().unwrap();
                            let v = latch.on_packet(a.parse().unwrap(), now);
                            format!(
                                "{}{}{}",
                                if v == Verdict::Accept { "a" } else { "d" },
                                target(&latch),
                                if latch.settled(now) { "!" } else { "" }
                            )
                        }
                        ("c", rest) => {
                            let nominated = rest.ends_with('*');
                            latch.confirm(rest.trim_end_matches('*').parse().unwrap(), nominated);
                            target(&latch)
                        }
                        (_, rest) => {
                            latch.set_expected(addr(rest));
                            target(&latch)
                        }
                    })
                    .collect();
                let got = outs.join(";");
                r.check(got == f[5], || {
                    format!("line {at}: latch {got}, the reference {}", f[5])
                });
            }
            "sdp-read" => {
                let mut media = [Media::EMPTY; MAX_MEDIA];
                let n = read_media(&unhex(f[1]), &mut media).unwrap();
                let opt = |x: Option<String>| x.unwrap_or_else(|| "-".to_owned());
                let got: Vec<String> = media[..n]
                    .iter()
                    .map(|m| {
                        [
                            m.port.to_string(),
                            opt(m.address.map(|a| a.to_string())),
                            m.rtcp_port.to_string(),
                            u8::from(m.rtcp_mux).to_string(),
                            m.transport.name().unwrap_or("other").to_owned(),
                            m.payload_types
                                .as_slice()
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(","),
                            opt(m.telephone_event.map(|(p, r)| format!("{p}:{r}"))),
                            opt(m.opus.map(|p| p.to_string())),
                            opt(m
                                .mid
                                .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned())),
                        ]
                        .join("|")
                    })
                    .collect();
                let got = got.join(";");
                r.check(got == f[2], || {
                    format!("line {at}: SDP read {got}, the reference {}", f[2])
                });
            }
            "sdp-rewrite" => {
                use rtpflux_core::sdp::{Plan, Relayed, rewrite};
                let relayed: Vec<Relayed<'_>> = f[4]
                    .split(',')
                    .map(|p| {
                        let (a, b) = p.split_once(':').unwrap();
                        Relayed::ports(a.parse().unwrap(), b.parse().unwrap())
                    })
                    .collect();
                let plan = Plan {
                    address: f[2].parse().unwrap(),
                    media: &relayed,
                    replace_origin: f[3] == "1",
                    bundle: &[],
                    keep_connection: false,
                    session: rtpflux_core::sdp::SessionEdits::NONE,
                };
                let mut out = vec![0u8; 8192];
                let n = rewrite(&unhex(f[1]), &plan, &mut out).unwrap();
                let got = hex(&out[..n]);
                r.check(got == f[5], || {
                    format!(
                        "line {at}: SDP rewritten {:?}, the reference {:?}",
                        String::from_utf8_lossy(&out[..n]),
                        String::from_utf8_lossy(&unhex(f[5]))
                    )
                });
            }
            "sdp-rewrite-full" => {
                let got = rewrite_full(&unhex(f[1]), f[2], f[3] == "1", f[4], f[5]);
                r.check(got == f[6], || {
                    format!(
                        "line {at}: SDP rewritten {:?}, the reference {:?}",
                        String::from_utf8_lossy(&unhex(&got)),
                        String::from_utf8_lossy(&unhex(f[6]))
                    )
                });
            }
            "sdp-offer-answer" => {
                // A's offer to B, and B's answer to A, each written on by
                // the relay; the reference found the answer A gets valid
                // for its offer (RFC 3264 §6).
                let plain = |sdp: &str, address: &str, ports: &str| {
                    let relayed: Vec<rtpflux_core::sdp::Relayed<'_>> = ports
                        .split(',')
                        .map(|p| {
                            let (a, b) = p.split_once(':').unwrap();
                            rtpflux_core::sdp::Relayed::ports(
                                a.parse().unwrap(),
                                b.parse().unwrap(),
                            )
                        })
                        .collect();
                    let plan = rtpflux_core::sdp::Plan {
                        address: address.parse().unwrap(),
                        media: &relayed,
                        replace_origin: false,
                        bundle: &[],
                        keep_connection: false,
                        session: rtpflux_core::sdp::SessionEdits::NONE,
                    };
                    let mut out = vec![0u8; 16_384];
                    let n = rtpflux_core::sdp::rewrite(&unhex(sdp), &plan, &mut out).unwrap();
                    hex(&out[..n])
                };
                let to_b = plain(f[1], f[2], f[3]);
                let to_a = plain(f[5], f[6], f[7]);
                r.check(f[9] == "valid" && to_b == f[4] && to_a == f[8], || {
                    format!(
                        "line {at}: offer to B {:?} (reference {:?}), answer to A {:?} (reference {:?})",
                        String::from_utf8_lossy(&unhex(&to_b)),
                        String::from_utf8_lossy(&unhex(f[4])),
                        String::from_utf8_lossy(&unhex(&to_a)),
                        String::from_utf8_lossy(&unhex(f[8]))
                    )
                });
            }
            other => panic!("line {at}: unknown vector kind {other}"),
        }
    }
    eprintln!("{} checks, {} mismatches", r.checked, r.failures.len());
    assert!(
        r.failures.is_empty(),
        "{} of {} checks disagree with the reference model:\n{}",
        r.failures.len(),
        r.checked,
        r.failures.join("\n")
    );
}

fn codec_of_name(name: &str) -> Option<rtpflux_core::sdp::Codec> {
    use rtpflux_core::sdp::Codec;
    match name {
        "pcmu" => Some(Codec::Pcmu),
        "pcma" => Some(Codec::Pcma),
        "g722" => Some(Codec::G722),
        "g729" => Some(Codec::G729),
        "opus" => Some(Codec::Opus),
        _ => None,
    }
}

fn codec_name(c: rtpflux_core::sdp::Codec) -> &'static str {
    use rtpflux_core::sdp::Codec;
    match c {
        Codec::Pcmu => "pcmu",
        Codec::Pcma => "pcma",
        Codec::G722 => "g722",
        Codec::G729 => "g729",
        Codec::Opus => "opus",
        Codec::Amr | Codec::AmrWb => "?",
    }
}

fn edit_text(e: rtpflux_core::sdp::FormatEdit) -> String {
    use rtpflux_core::sdp::FormatEdit;
    match e {
        FormatEdit::Append(x) => format!("a{x}"),
        FormatEdit::Replace(x, y) => format!("r{x}:{y}"),
        FormatEdit::Remove(x) => format!("d{x}"),
    }
}

/// The plan for an offer, its change towards B, and how answers settle it.
fn codec_plan_line(offer: &str, transcode: &str, mask: &str) -> String {
    use rtpflux::relay::codecs::{plan, settle};
    let offer: Vec<(Pt, Option<rtpflux_core::sdp::Codec>)> = if offer == "." {
        Vec::new()
    } else {
        offer
            .split(',')
            .map(|f| {
                let (pt, c) = f.split_once(':').unwrap();
                (pt.parse().unwrap(), codec_of_name(c))
            })
            .collect()
    };
    let mask: Vec<_> = if mask == "." {
        Vec::new()
    } else {
        mask.split(',').filter_map(codec_of_name).collect()
    };
    let p = plan(&offer, codec_of_name(transcode), &mask);
    let plan_text = p.map_or("-".to_string(), |p| {
        format!(
            "{}:{}:{}:{}:{}",
            p.a_pt,
            codec_name(p.a),
            p.b_pt,
            codec_name(p.b),
            u8::from(p.masked)
        )
    });
    let towards = p.map_or("-".to_string(), |p| edit_text(p.towards_b()));
    let firsts: Vec<Option<Pt>> = match p {
        Some(p) => vec![None, Some(p.b_pt), Some(p.a_pt), Pt::new(101)],
        None => vec![None, Some(Pt::PCMU)],
    };
    let settles: Vec<String> = firsts
        .iter()
        .map(|&f| {
            let (x, e) = settle(p, f);
            format!(
                "{}={}/{}",
                f.map_or("-".to_string(), |f| f.to_string()),
                u8::from(x.is_some()),
                e.map_or("-".to_string(), edit_text)
            )
        })
        .collect();
    [plan_text, towards, settles.join(",")].join("\t")
}

/// Requests through the reply cache: each reply (`r` ran, `c` from the
/// cache), and the keys kept at the end.
fn reply_cache_line(params: &str, ops: &str) -> String {
    let p: Vec<usize> = params.split(':').map(|x| x.parse().unwrap()).collect();
    let mut cache = rtpflux::ngcache::ReplyCache::<u32, u32>::new(p[0], p[1], p[2] as u64);
    let mut outs = Vec::new();
    for (i, op) in ops.split(',').enumerate() {
        let o: Vec<u64> = op.split(':').map(|x| x.parse().unwrap()).collect();
        let (now, k, size) = (
            o[0],
            u32::try_from(o[1]).unwrap(),
            usize::try_from(o[2]).unwrap(),
        );
        if let Some(v) = cache.get(now, &k) {
            outs.push(format!("{v}c"));
        } else {
            let v = u32::try_from(i).unwrap();
            cache.insert(now, k, v, size);
            outs.push(format!("{v}r"));
        }
    }
    let keys: Vec<String> = cache.keys().map(ToString::to_string).collect();
    [outs.join(","), keys.join(",")].join("\t")
}

/// A description written on with every relay attribute, as a vector's
/// plan says (sections by `;`, fields by `|`).
fn rewrite_full(
    sdp: &[u8],
    address: &str,
    replace_origin: bool,
    plan: &str,
    bundle: &str,
) -> String {
    use rtpflux_core::sdp::{
        Codec, Crypto, DtlsAttrs, FormatEdit, IceAttrs, MasterKey, Plan, Relayed, Transport,
        rewrite,
    };
    let fields: Vec<Vec<&str>> = plan.split(';').map(|m| m.split('|').collect()).collect();
    let keys: Vec<Option<(u32, Vec<u8>)>> = fields
        .iter()
        .map(|f| {
            f[2].split_once(':')
                .map(|(t, k)| (t.parse().unwrap(), unhex(k)))
        })
        .collect();
    let relayed: Vec<Relayed<'_>> = fields
        .iter()
        .zip(&keys)
        .map(|(f, key)| {
            let (rtp, rtcp) = f[0].split_once(':').unwrap();
            let ice = (f[3] != "-").then(|| {
                let i: Vec<&str> = f[3].split(',').collect();
                IceAttrs {
                    ufrag: b"rlyUfrag",
                    pwd: b"relayPassword0123456789xy",
                    rtcp_candidate: i[0] == "1",
                    candidates: i[1] == "1",
                    lite: i[2] == "1",
                    trickle: i[3] == "1",
                    srflx: (i[4] != "-").then(|| i[4].parse().unwrap()),
                }
            });
            let mut formats = [None; 2];
            if f[10] != "-" {
                for (slot, e) in formats.iter_mut().zip(f[10].split(',')) {
                    let (kind, rest) = e.split_at(1);
                    *slot = Some(match kind {
                        "r" => {
                            let (a, b) = rest.split_once('.').unwrap();
                            FormatEdit::Replace(a.parse().unwrap(), b.parse().unwrap())
                        }
                        "d" => FormatEdit::Remove(rest.parse().unwrap()),
                        _ => FormatEdit::Append(rest.parse().unwrap()),
                    });
                }
            }
            Relayed {
                transport: (f[1] != "-").then(|| Transport::parse(f[1].as_bytes())),
                crypto: key.as_ref().map(|(tag, k)| Crypto {
                    tag: *tag,
                    key: MasterKey::new(Suite::AesCm128HmacSha1_80, k).unwrap(),
                }),
                ice,
                mid: (f[4] != "-").then(|| f[4].as_bytes()),
                rtcp_mux: f[5] == "1",
                dynamic: f[6]
                    .split_once(':')
                    .map(|(pt, c)| (pt.parse().unwrap(), Codec::from_name(c.as_bytes()).unwrap())),
                telephone_event: (f[7] != "-").then(|| f[7].parse().unwrap()),
                unbundle: f[8] == "1",
                dtls: f[9].split_once('/').map(|(st, fp)| DtlsAttrs {
                    setup: Setup::parse(st.as_bytes()).unwrap(),
                    fingerprint: fp,
                }),
                formats,
                strip_zrtp: f[11] == "1",
                ..Relayed::ports(rtp.parse().unwrap(), rtcp.parse().unwrap())
            }
        })
        .collect();
    let tags: Vec<&[u8]> = if bundle == "-" {
        Vec::new()
    } else {
        bundle.split(',').map(str::as_bytes).collect()
    };
    let plan = Plan {
        address: address.parse().unwrap(),
        media: &relayed,
        replace_origin,
        bundle: &tags,
        keep_connection: false,
        session: rtpflux_core::sdp::SessionEdits::NONE,
    };
    let mut out = vec![0u8; 16_384];
    let n = rewrite(sdp, &plan, &mut out).unwrap();
    hex(&out[..n])
}
