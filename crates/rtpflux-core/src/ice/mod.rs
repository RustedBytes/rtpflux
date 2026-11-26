//! A full ICE agent (RFC 8445) for one data stream of a media relay, with
//! consent freshness (RFC 7675) and candidates trickled in after checks
//! started (RFC 8838).
//!
//! The relay has one socket per component (1 RTP, 2 RTCP when not muxed),
//! so its local candidates for a component share one base: a host candidate
//! and maybe a server-reflexive one, which pairing replaces by its base
//! (RFC 8445 §6.1.2.4). A pair is therefore named by its component and the
//! remote candidate, and its local priority is the host candidate's.
//!
//! The agent does no I/O ("sans-I/O"): the owner feeds it STUN datagrams
//! received on each component's socket ([`Agent::on_stun`]), sends what
//! [`Agent::poll`] returns from the component's socket, and calls `poll`
//! again at [`Agent::next_ms`]. Media for a component goes to
//! [`Agent::target`]: the nominated pair once there is one, before that the
//! best valid pair (§12.1.1), and nothing without consent.
//!
//! * Checks (§6.1.4, §7.2): paced every Ta, the triggered-check queue first,
//!   otherwise the best Waiting pair, unfreezing idle foundations when none
//!   is Waiting; retransmitted with doubling RTO (§14.3) up to Rc = 7
//!   sends, failed Rm = 16 RTOs after the last; a response counts only when
//!   authenticated, from the address the check went to and on the same
//!   component (§7.2.5.2.1); success unfreezes the pair's foundation.
//! * Incoming checks (§7.3): answered after resolving role conflicts
//!   (§7.3.1.1, 487 to a weaker claim, a role switch to a stronger one);
//!   an unknown source becomes a peer-reflexive candidate (§7.3.1.3) and
//!   gets a triggered check (§7.3.1.4).
//! * Nomination (§8.1.1, regular): the controlling agent nominates, for
//!   each component, the best valid pair once no check is left for it or a
//!   second after its first valid pair, with a check carrying USE-CANDIDATE;
//!   the controlled agent nominates a pair the peer's USE-CANDIDATE names
//!   once its own check on it succeeded (§7.3.1.5). Nomination removes the
//!   component's Waiting and Frozen pairs and stops their checks.
//! * Consent (RFC 7675): on the target pair of each component, from its
//!   last successful check; lost consent stops media for good until a
//!   restart.
//! * Restart (RFC 8445 §9): new credentials, an empty checklist, the same
//!   role; media keeps going to the previous target, under consent with the
//!   previous credentials, until a new pair is valid.
//!
//! Memory is allocated when the agent is created or restarted; handling
//! datagrams and timers stays within the reserved capacity.

pub mod checklist;
pub mod consent;
pub mod list;

use core::net::SocketAddr;

pub use crate::stun::Role;
use crate::stun::{self, CheckRequest, Credentials, Request, Response};
pub use checklist::{CandType, ListState, Pair, PairState};
use consent::Consent;
use list::{Bytes, List};

/// The pacing timer's default (RFC 8445 §14.2, RFC 8839 §5.5).
pub const TA_MS: u64 = 50;
/// Sends of one check (RFC 8489 §6.2.1 Rc).
const RC: u8 = 7;
/// Final wait after the last send, in RTOs (Rm).
const RM: u64 = 16;
/// Pairs in the checklist (RFC 8445 §6.1.2.5).
pub const MAX_PAIRS: usize = 100;
/// Remote candidates kept.
pub const MAX_REMOTES: usize = 64;
/// Transactions in flight.
const MAX_TXNS: usize = 32;
/// The controlling agent nominates this long after a component's first
/// valid pair even if checks are still going.
const NOMINATE_AFTER_MS: u64 = 1_000;
/// Local preference of the relay's candidates.
const LOCAL_PREF: u32 = 65_535;
/// Longest ufrag and password accepted (RFC 8839 §5.4).
const MAX_CRED: usize = 256;

type Cred = Bytes<MAX_CRED>;

/// A remote candidate from the peer's SDP or a trickled fragment.
#[derive(Debug, Clone, Copy)]
pub struct RemoteCandidate<'a> {
    pub foundation: &'a [u8],
    pub component: u8,
    pub priority: u32,
    pub addr: SocketAddr,
}

/// What the agent starts from.
#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    pub role: Role,
    pub tiebreaker: u64,
    /// The relay's credentials towards the peer.
    pub local_ufrag: &'a [u8],
    pub local_pwd: &'a [u8],
    /// The peer's.
    pub remote_ufrag: &'a [u8],
    pub remote_pwd: &'a [u8],
    /// 1 (RTP, RTCP muxed) or 2.
    pub components: u8,
    /// The relay's sockets are IPv6.
    pub v6: bool,
    /// Ta (ms).
    pub ta_ms: u64,
}

/// A datagram to send from a component's socket: `out[..len]` to `dst`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transmit {
    pub component: u8,
    pub dst: SocketAddr,
    pub len: usize,
}

/// Counters for monitoring.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Checks and consent requests sent (retransmissions included).
    pub checks_sent: u64,
    /// Checks answered with success.
    pub checks_answered: u64,
    pub role_conflicts: u64,
    pub nominations: u64,
    pub consent_lost: u64,
    pub restarts: u64,
}

#[derive(Debug, Clone, Copy)]
struct Remote {
    addr: SocketAddr,
    component: u8,
    priority: u32,
    foundation: u32,
}

const NO_ADDR: SocketAddr = SocketAddr::V4(core::net::SocketAddrV4::new(
    core::net::Ipv4Addr::UNSPECIFIED,
    0,
));

const NO_REMOTE: Remote = Remote {
    addr: NO_ADDR,
    component: 0,
    priority: 0,
    foundation: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Check,
    /// A consent request on the current (`prev` false) or previous target.
    Consent {
        prev: bool,
    },
}

#[derive(Debug, Clone, Copy)]
struct Txn {
    tid: [u8; 12],
    kind: Kind,
    pair: u16,
    component: u8,
    dst: SocketAddr,
    role: Role,
    use_candidate: bool,
    sends: u8,
    /// The first RTO; each retransmission doubles the wait.
    rto_ms: u64,
    next_ms: u64,
    /// No more retransmissions; a response is still taken until `next_ms`.
    cancelled: bool,
}

const NO_TXN: Txn = Txn {
    tid: [0; 12],
    kind: Kind::Check,
    pair: 0,
    component: 0,
    dst: NO_ADDR,
    role: Role::Controlled,
    use_candidate: false,
    sends: 0,
    rto_ms: 0,
    next_ms: 0,
    cancelled: false,
};

/// Where media went before a restart, kept until a new pair is valid.
#[derive(Debug, Clone, Copy)]
struct PrevTarget {
    addr: SocketAddr,
    consent: Consent,
}

/// The consent of the pair media goes to on one component.
#[derive(Debug, Clone, Copy)]
struct Bound {
    pair: u16,
    consent: Consent,
}

/// A value per component (1 RTP, 2 RTCP), found by the component's number:
/// a number other than 1 or 2 finds nothing, so no slot is ever indexed by
/// an unchecked one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PerComponent<T>([T; 2]);

impl<T: Copy> PerComponent<T> {
    const fn of(v: T) -> Self {
        PerComponent([v, v])
    }

    fn at(&self, component: u8) -> Option<T> {
        self.0.get(usize::from(component).checked_sub(1)?).copied()
    }

    fn get_mut(&mut self, component: u8) -> Option<&mut T> {
        self.0.get_mut(usize::from(component).checked_sub(1)?)
    }

    fn set(&mut self, component: u8, v: T) {
        if let Some(slot) = self.get_mut(component) {
            *slot = v;
        }
    }
}

/// A full ICE agent for one data stream (see the module documentation).
#[derive(Debug, Clone)]
pub struct Agent {
    role: Role,
    tiebreaker: u64,
    local_ufrag: Cred,
    local_pwd: Cred,
    remote_ufrag: Cred,
    remote_pwd: Cred,
    components: u8,
    v6: bool,
    ta_ms: u64,
    remotes: List<Remote, MAX_REMOTES>,
    pairs: List<Pair, MAX_PAIRS>,
    next_id: u16,
    prflx: u32,
    queue: List<u16, MAX_PAIRS>,
    txns: List<Txn, MAX_TXNS>,
    next_ta: u64,
    eoc: bool,
    first_valid: PerComponent<Option<u64>>,
    consent: PerComponent<Option<Bound>>,
    /// Consent lost on the component: no media until a restart.
    lost: PerComponent<bool>,
    prev: PerComponent<Option<PrevTarget>>,
    /// The credentials of the previous targets (local ufrag, remote ufrag,
    /// remote password).
    prev_creds: (Cred, Cred, Cred),
    now: u64,
    pub stats: Stats,
}

/// FNV-1a: a pair foundation from the remote candidate's (the relay's own
/// foundation is the same for every pair).
fn foundation_id(f: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in f {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    h & 0x7fff_ffff
}

fn tid_u128(t: &[u8; 12]) -> u128 {
    let mut b = [0u8; 16];
    b[4..].copy_from_slice(t);
    u128::from_be_bytes(b)
}

/// Consent granted at `t`.
fn granted(t: u64, period: u64) -> Consent {
    let mut c = Consent::new(period);
    c.tick(t);
    c.succeeded(period);
    c
}

impl Agent {
    /// A new agent; `None` when a credential is longer than 256 bytes.
    #[must_use]
    pub fn new(cfg: &Config<'_>) -> Option<Self> {
        Some(Agent {
            role: cfg.role,
            tiebreaker: cfg.tiebreaker,
            local_ufrag: Cred::new(cfg.local_ufrag)?,
            local_pwd: Cred::new(cfg.local_pwd)?,
            remote_ufrag: Cred::new(cfg.remote_ufrag)?,
            remote_pwd: Cred::new(cfg.remote_pwd)?,
            components: cfg.components.clamp(1, 2),
            v6: cfg.v6,
            ta_ms: cfg.ta_ms.max(5),
            remotes: List::new(NO_REMOTE),
            pairs: List::new(Pair::EMPTY),
            next_id: 0,
            prflx: 0,
            queue: List::new(0),
            txns: List::new(NO_TXN),
            next_ta: 0,
            eoc: false,
            first_valid: PerComponent::of(None),
            consent: PerComponent::of(None),
            lost: PerComponent::of(false),
            prev: PerComponent::of(None),
            prev_creds: (Cred::EMPTY, Cred::EMPTY, Cred::EMPTY),
            now: 0,
            stats: Stats::default(),
        })
    }

    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// 1 (RTCP muxed) or 2.
    #[must_use]
    pub const fn components(&self) -> u8 {
        self.components
    }

    #[must_use]
    pub fn pairs(&self) -> &[Pair] {
        self.pairs.as_slice()
    }

    /// The remote address of a pair.
    #[must_use]
    pub fn remote_of(&self, p: &Pair) -> Option<SocketAddr> {
        self.remotes.get(usize::from(p.remote)).map(|r| r.addr)
    }

    const fn host_priority(component: u8) -> u32 {
        checklist::candidate_priority(CandType::Host.type_pref(), LOCAL_PREF, component as u32)
    }

    fn pair_priority(&self, component: u8, remote: u32) -> u64 {
        checklist::pair_priority(self.role, Self::host_priority(component), remote)
    }

    /// Add the peer's candidates (from its SDP), in the order RFC 8445
    /// pairs them: by component, then priority. Ignored after the peer's
    /// end-of-candidates. Returns how many were added.
    pub fn add_remotes(&mut self, cands: &[RemoteCandidate<'_>]) -> usize {
        let mut order = [0u16; MAX_REMOTES * 2];
        let n = cands.len().min(order.len());
        let order = order.get_mut(..n).unwrap_or_default();
        for (k, o) in order.iter_mut().enumerate() {
            *o = u16::try_from(k).unwrap_or(u16::MAX);
        }
        order.sort_unstable_by_key(|&k| {
            let c = cands.get(usize::from(k));
            (
                c.map(|c| c.component),
                core::cmp::Reverse(c.map(|c| c.priority)),
                k,
            )
        });
        order
            .iter()
            .filter(|&&k| {
                cands
                    .get(usize::from(k))
                    .is_some_and(|c| self.add_remote(c))
            })
            .count()
    }

    /// Add one remote candidate (RFC 8838 §11): UDP of the relay's address
    /// family, a component the stream has. A candidate already known as
    /// peer-reflexive takes the signalled foundation and priority.
    pub fn add_remote(&mut self, c: &RemoteCandidate<'_>) -> bool {
        if self.eoc
            || c.component == 0
            || c.component > self.components
            || c.addr.is_ipv6() != self.v6
        {
            return false;
        }
        if let Some(r) = self
            .remotes
            .iter_mut()
            .find(|r| r.addr == c.addr && r.component == c.component)
        {
            r.foundation = foundation_id(c.foundation);
            r.priority = c.priority;
            let (addr, component, foundation) = (r.addr, r.component, r.foundation);
            let priority = self.pair_priority(component, c.priority);
            if let Some(p) = self
                .pair_index(component, addr)
                .and_then(|k| self.pairs.get_mut(k))
            {
                p.foundation = foundation;
                p.priority = priority;
            }
            return false;
        }
        self.learn(c.addr, c.component, c.priority, foundation_id(c.foundation))
            .is_some()
    }

    /// The peer's end-of-candidates (RFC 8838 §14).
    pub fn end_of_candidates(&mut self) {
        self.eoc = true;
    }

    /// Remember a remote candidate and pair it; the pair's index.
    fn learn(
        &mut self,
        addr: SocketAddr,
        component: u8,
        priority: u32,
        foundation: u32,
    ) -> Option<usize> {
        if self.remotes.is_full() {
            return None;
        }
        let remote = u16::try_from(self.remotes.len()).ok()?;
        self.remotes.push(Remote {
            addr,
            component,
            priority,
            foundation,
        });
        let p = Pair::new(
            self.next_id,
            0,
            u16::from(component),
            remote,
            foundation,
            component,
            self.pair_priority(component, priority),
        );
        self.next_id = self.next_id.wrapping_add(1);
        if !checklist::insert_pair(MAX_PAIRS, &mut self.pairs, p) {
            return None;
        }
        let id = p.id;
        self.queue.retain(|&q| self.pairs.iter().any(|p| p.id == q));
        self.pairs.iter().position(|p| p.id == id)
    }

    fn pair_index(&self, component: u8, addr: SocketAddr) -> Option<usize> {
        self.pairs.iter().position(|p| {
            p.component == component
                && self
                    .remotes
                    .get(usize::from(p.remote))
                    .is_some_and(|r| r.addr == addr)
        })
    }

    fn set_role(&mut self, role: Role) {
        if role == self.role {
            return;
        }
        self.role = role;
        for k in 0..self.pairs.len() {
            let Some(&p) = self.pairs.get(k) else {
                break;
            };
            if let Some(r) = self.remotes.get(usize::from(p.remote)) {
                let priority = self.pair_priority(p.component, r.priority);
                if let Some(p) = self.pairs.get_mut(k) {
                    p.priority = priority;
                }
            }
        }
    }

    /// Feed a STUN datagram received from `src` on `component`'s socket.
    /// Returns the length of a reply written into `out`, to send back to
    /// `src` from the same socket.
    pub fn on_stun(
        &mut self,
        now: u64,
        component: u8,
        src: SocketAddr,
        msg: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        self.now = self.now.max(now);
        let creds = Credentials {
            ufrag: self.local_ufrag.as_slice(),
            pwd: self.local_pwd.as_slice(),
        };
        match stun::check_request(msg, creds, out) {
            Request::Rejected { len } => Some(len),
            Request::Check(c) => self.on_check(component, src, &c, out),
            Request::Ignore => {
                self.on_response(component, src, msg);
                None
            }
        }
    }

    /// An authenticated check (RFC 8445 §7.3.1).
    fn on_check(
        &mut self,
        component: u8,
        src: SocketAddr,
        c: &stun::Check,
        out: &mut [u8],
    ) -> Option<usize> {
        if let Some((peer, peer_tb)) = c.role {
            let (role, conflict) = stun::on_role_request(self.role, self.tiebreaker, peer, peer_tb);
            if conflict {
                self.stats.role_conflicts = self.stats.role_conflicts.saturating_add(1);
                return stun::write_role_conflict(out, &c.tid, self.local_pwd.as_slice());
            }
            if role != self.role {
                self.stats.role_conflicts = self.stats.role_conflicts.saturating_add(1);
                self.set_role(role);
            }
        }
        let len = stun::write_success(out, &c.tid, src, self.local_pwd.as_slice())?;
        self.stats.checks_answered = self.stats.checks_answered.saturating_add(1);
        if component == 0 || component > self.components || src.is_ipv6() != self.v6 {
            return Some(len);
        }
        // §7.3.1.3: an unknown source is a peer-reflexive candidate.
        let k = match self.pair_index(component, src) {
            Some(k) => Some(k),
            None if !self
                .remotes
                .iter()
                .any(|r| r.addr == src && r.component == component) =>
            {
                self.prflx = self.prflx.wrapping_add(1);
                self.learn(
                    src,
                    component,
                    c.priority.unwrap_or(0),
                    0x8000_0000 | self.prflx,
                )
            }
            None => None,
        };
        let Some(k) = k else {
            return Some(len);
        };
        // §7.3.1.4 triggered checks.
        let Some(&pair) = self.pairs.get(k) else {
            return Some(len);
        };
        let id = pair.id;
        match pair.state {
            PairState::Succeeded => {}
            PairState::InProgress => {
                for t in self
                    .txns
                    .iter_mut()
                    .filter(|t| t.kind == Kind::Check && t.pair == id)
                {
                    t.cancelled = true;
                }
                self.set_state(k, PairState::Waiting);
                self.enqueue(id);
            }
            _ => {
                self.set_state(k, PairState::Waiting);
                self.enqueue(id);
            }
        }
        // §7.3.1.5.
        if c.use_candidate && self.role == Role::Controlled {
            if self
                .pairs
                .get(k)
                .is_some_and(|p| p.state == PairState::Succeeded)
            {
                self.nominate(k);
            } else if let Some(p) = self.pairs.get_mut(k) {
                p.nominate_on_success = true;
            }
        }
        Some(len)
    }

    /// Set pair `k`'s state (no pair `k`: nothing).
    fn set_state(&mut self, k: usize, state: PairState) {
        if let Some(p) = self.pairs.get_mut(k) {
            p.state = state;
        }
    }

    fn enqueue(&mut self, id: u16) {
        if !self.queue.as_slice().contains(&id) {
            self.queue.push(id);
        }
    }

    /// A response (RFC 8445 §7.2.5).
    fn on_response(&mut self, component: u8, src: SocketAddr, msg: &[u8]) {
        let Some(tid) = stun::response_tid(msg) else {
            return;
        };
        let Some(t) = self.txns.iter().position(|t| t.tid == tid) else {
            return;
        };
        let Some(&txn) = self.txns.get(t) else {
            return;
        };
        let pwd = if txn.kind == (Kind::Consent { prev: true }) {
            self.prev_creds.2.as_slice()
        } else {
            self.remote_pwd.as_slice()
        };
        let Some((_, resp)) = stun::read_response(msg, pwd) else {
            return;
        };
        self.txns.swap_remove(t);
        let symmetric = src == txn.dst && component == txn.component;
        let ok = symmetric && matches!(resp, Response::Success { .. });
        let tid = txn.tid;
        let comp = txn.component;
        let now = self.now;
        match txn.kind {
            Kind::Consent { prev: true } => {
                if let Some(p) = self.prev.get_mut(comp).and_then(Option::as_mut) {
                    p.consent.tick(self.now);
                    p.consent.response(tid_u128(&tid), ok);
                }
                return;
            }
            Kind::Consent { prev: false } => {
                if let Some(b) = self
                    .consent
                    .get_mut(comp)
                    .and_then(Option::as_mut)
                    .filter(|b| b.pair == txn.pair)
                {
                    b.consent.tick(now);
                    b.consent.response(tid_u128(&tid), ok);
                }
                if ok && let Some(p) = self.pairs.iter_mut().find(|p| p.id == txn.pair) {
                    p.ok_ms = now;
                }
                return;
            }
            Kind::Check => {}
        }
        let Some(k) = self.pairs.iter().position(|p| p.id == txn.pair) else {
            return;
        };
        match resp {
            Response::Success { .. } if symmetric => {
                let Some(p) = self.pairs.get_mut(k) else {
                    return;
                };
                p.state = PairState::Succeeded;
                p.ok_ms = self.now;
                let (foundation, wanted) = (p.foundation, p.nominate_on_success);
                checklist::unfreeze_foundation(self.pairs.as_mut_slice(), foundation);
                if let Some(first) = self.first_valid.get_mut(comp) {
                    first.get_or_insert(now);
                }
                if let Some(b) = self
                    .consent
                    .get_mut(comp)
                    .and_then(Option::as_mut)
                    .filter(|b| b.pair == txn.pair)
                    && !b.consent.lost()
                {
                    // Any authenticated success renews the pair's consent.
                    b.consent = granted(self.now, consent::PERIOD_MS);
                }
                if (txn.use_candidate && txn.role == Role::Controlling)
                    || (wanted && self.role == Role::Controlled)
                {
                    self.nominate(k);
                } else if txn.use_candidate
                    && let Some(p) = self.pairs.get_mut(k)
                {
                    p.nominating = false;
                }
                // A valid pair replaces the target kept from before a restart.
                self.prev.set(comp, None);
            }
            // A late answer (to a check since cancelled) does not undo a
            // nomination.
            _ if self.pairs.get(k).is_some_and(|p| p.nominated) => {}
            Response::Error { code } if code == stun::ROLE_CONFLICT => {
                self.stats.role_conflicts = self.stats.role_conflicts.saturating_add(1);
                let role = stun::on_role_reply(txn.role, self.role, true);
                self.set_role(role);
                self.set_state(k, PairState::Waiting);
                if let Some(id) = self.pairs.get(k).map(|p| p.id) {
                    self.enqueue(id);
                }
            }
            _ => {
                if let Some(p) = self.pairs.get_mut(k) {
                    p.state = PairState::Failed;
                    p.nominating = false;
                }
            }
        }
    }

    /// Nominate pair `k` (RFC 8445 §8.1.1): its component's Waiting and
    /// Frozen pairs go, and checks on its other pairs stop.
    fn nominate(&mut self, k: usize) {
        let Some(pair) = self.pairs.get_mut(k) else {
            return;
        };
        if pair.nominated {
            return;
        }
        pair.nominated = true;
        pair.nominating = false;
        let p = *pair;
        self.stats.nominations = self.stats.nominations.saturating_add(1);
        let c = p.component;
        self.pairs
            .retain(|q| q.component != c || q.id == p.id || !q.state.pending());
        let pairs = &self.pairs;
        self.queue.retain(|id| pairs.iter().any(|q| q.id == *id));
        for t in &mut self.txns {
            if t.kind == Kind::Check && t.component == c && t.pair != p.id {
                t.cancelled = true;
            }
        }
    }

    /// The pair media goes to on `component`: nominated (the highest
    /// priority of several), else the best valid one.
    fn target_pair(&self, component: u8) -> Option<usize> {
        let best = |nominated: bool| {
            self.pairs
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    p.component == component
                        && p.state == PairState::Succeeded
                        && (!nominated || p.nominated)
                })
                .max_by_key(|(_, p)| p.priority)
                .map(|(k, _)| k)
        };
        best(true).or_else(|| best(false))
    }

    /// Where media for `component` goes now, if anywhere.
    #[must_use]
    pub fn target(&self, component: u8) -> Option<SocketAddr> {
        if component == 0 || component > self.components || self.lost.at(component)? {
            return None;
        }
        if let Some(k) = self.target_pair(component) {
            // Consent: an authenticated success within the last 30 s.
            let p = self.pairs.get(k)?;
            return (self.now < p.ok_ms.saturating_add(consent::EXPIRY_MS))
                .then(|| self.remote_of(p))
                .flatten();
        }
        self.prev
            .at(component)
            .flatten()
            .filter(|p| p.consent.may_send())
            .map(|p| p.addr)
    }

    /// The nominated pair's remote address on `component`.
    #[must_use]
    pub fn selected(&self, component: u8) -> Option<SocketAddr> {
        self.pairs
            .iter()
            .filter(|p| p.component == component && p.nominated)
            .max_by_key(|p| p.priority)
            .and_then(|p| self.remote_of(p))
    }

    /// Consent was lost on `component` (media stopped until a restart).
    #[must_use]
    pub fn consent_lost(&self, component: u8) -> bool {
        component <= self.components && self.lost.at(component).unwrap_or(false)
    }

    /// The checklist's state.
    #[must_use]
    pub fn state(&self) -> ListState {
        let comps: &[u8] = if self.components == 2 { &[1, 2] } else { &[1] };
        checklist::list_state(true, self.eoc, comps, self.pairs.as_slice())
    }

    /// Restart ICE (RFC 8445 §9) with new credentials on both sides; the
    /// role stays. Media keeps going to the current targets under consent
    /// until new pairs are valid.
    /// False (nothing changed) when a credential is longer than 256 bytes.
    pub fn restart(
        &mut self,
        local_ufrag: &[u8],
        local_pwd: &[u8],
        remote_ufrag: &[u8],
        remote_pwd: &[u8],
    ) -> bool {
        let (Some(lu), Some(lp), Some(ru), Some(rp)) = (
            Cred::new(local_ufrag),
            Cred::new(local_pwd),
            Cred::new(remote_ufrag),
            Cred::new(remote_pwd),
        ) else {
            return false;
        };
        self.stats.restarts = self.stats.restarts.saturating_add(1);
        let mut kept = PerComponent::of(None);
        for c in 1..=self.components {
            if let (Some(k), Some(addr)) = (self.target_pair(c), self.target(c))
                && let Some(p) = self.pairs.get(k)
            {
                let consent = match self.consent.at(c).flatten() {
                    Some(b) if b.pair == p.id => b.consent,
                    _ => granted(p.ok_ms, consent::PERIOD_MS),
                };
                kept.set(c, Some(PrevTarget { addr, consent }));
            }
        }
        if kept.0.iter().any(Option::is_some) {
            // The previous targets, under the credentials they were checked with.
            self.prev = kept;
            self.prev_creds = (self.local_ufrag, self.remote_ufrag, self.remote_pwd);
            self.txns.clear();
        } else {
            // Still on the targets from before an earlier restart.
            self.txns.retain(|t| t.kind == Kind::Consent { prev: true });
        }
        self.local_ufrag = lu;
        self.local_pwd = lp;
        self.remote_ufrag = ru;
        self.remote_pwd = rp;
        self.remotes.clear();
        self.pairs.clear();
        self.queue.clear();
        self.eoc = false;
        self.first_valid = PerComponent::of(None);
        self.consent = PerComponent::of(None);
        self.lost = PerComponent::of(false);
        true
    }

    /// A check could be sent now: something queued or Waiting, or a Frozen
    /// pair §6.1.4.2 step 2 would unfreeze.
    fn checkable(&self) -> bool {
        !self.queue.is_empty()
            || self.pairs.iter().any(|p| {
                p.state == PairState::Waiting
                    || (p.state == PairState::Frozen
                        && !self.pairs.iter().any(|q| {
                            q.foundation == p.foundation
                                && matches!(q.state, PairState::Waiting | PairState::InProgress)
                        }))
            })
    }

    fn should_nominate(&self, component: u8) -> Option<usize> {
        if self.role != Role::Controlling
            || self
                .pairs
                .iter()
                .any(|p| p.component == component && (p.nominated || p.nominating))
        {
            return None;
        }
        let k = self
            .pairs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.component == component && p.state == PairState::Succeeded)
            .max_by_key(|(_, p)| p.priority)
            .map(|(k, _)| k)?;
        let busy = self.pairs.iter().any(|p| {
            p.component == component
                && matches!(
                    p.state,
                    PairState::Waiting | PairState::Frozen | PairState::InProgress
                )
        });
        let waited = self
            .first_valid
            .at(component)
            .flatten()
            .is_some_and(|t| self.now >= t.saturating_add(NOMINATE_AFTER_MS));
        (!busy || waited).then_some(k)
    }

    /// The next datagram to send, if any is due at `now`: written into
    /// `out`. `random` fills transaction ids and draws consent intervals.
    /// Call until it returns `None`.
    pub fn poll(
        &mut self,
        now: u64,
        out: &mut [u8],
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Option<Transmit> {
        self.now = self.now.max(now);
        if let Some(t) = self.poll_consent(out, random) {
            return Some(t);
        }
        if let Some(t) = self.poll_retransmit(out) {
            return Some(t);
        }
        self.poll_check(out, random)
    }

    fn draw(random: &mut dyn FnMut(&mut [u8])) -> u64 {
        let mut b = [0u8; 2];
        random(&mut b);
        // 4000–6000 ms around the 5 s period.
        4_000u64.wrapping_add(u64::from(u16::from_be_bytes(b)) % 2_001)
    }

    fn poll_consent(
        &mut self,
        out: &mut [u8],
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Option<Transmit> {
        for c in 1..=self.components {
            if self.lost.at(c).unwrap_or(true) {
                continue;
            }
            if let Some(&p) = self.target_pair(c).and_then(|k| self.pairs.get(k)) {
                if self.consent.at(c).flatten().is_none_or(|b| b.pair != p.id) {
                    let mut consent = Consent::default();
                    consent.tick(p.ok_ms);
                    consent.succeeded(Self::draw(random));
                    self.consent.set(
                        c,
                        Some(Bound {
                            pair: p.id,
                            consent,
                        }),
                    );
                }
                let dst = self.remote_of(&p)?;
                let now = self.now;
                let b = self.consent.get_mut(c)?.as_mut()?;
                if b.consent.tick(now) {
                    self.lost.set(c, true);
                    self.stats.consent_lost = self.stats.consent_lost.saturating_add(1);
                    continue;
                }
                if b.consent.due() && self.txns.len() < MAX_TXNS {
                    let mut tid = [0u8; 12];
                    random(&mut tid);
                    let r = Self::draw(random);
                    let b = self.consent.get_mut(c)?.as_mut()?;
                    if b.consent.send(tid_u128(&tid), r) {
                        return self.send_check(
                            out,
                            tid,
                            Kind::Consent { prev: false },
                            p.id,
                            c,
                            dst,
                            false,
                        );
                    }
                }
            } else if let Some(prev) = self.prev.get_mut(c).and_then(Option::as_mut) {
                if prev.consent.tick(self.now) {
                    self.prev.set(c, None);
                    self.lost.set(c, true);
                    self.stats.consent_lost = self.stats.consent_lost.saturating_add(1);
                    continue;
                }
                if prev.consent.due() && self.txns.len() < MAX_TXNS {
                    let mut tid = [0u8; 12];
                    random(&mut tid);
                    let r = Self::draw(random);
                    let prev = self.prev.get_mut(c)?.as_mut()?;
                    if prev.consent.send(tid_u128(&tid), r) {
                        let dst = prev.addr;
                        return self.send_check(
                            out,
                            tid,
                            Kind::Consent { prev: true },
                            u16::MAX,
                            c,
                            dst,
                            false,
                        );
                    }
                }
            }
        }
        None
    }

    fn poll_retransmit(&mut self, out: &mut [u8]) -> Option<Transmit> {
        let mut k = 0;
        while k < self.txns.len() {
            let Some(&t) = self.txns.get(k) else {
                break;
            };
            if t.next_ms > self.now {
                // Below `len`.
                k = k.wrapping_add(1);
                continue;
            }
            if t.kind != Kind::Check || t.cancelled || t.sends >= RC {
                // Timed out.
                self.txns.swap_remove(k);
                if t.kind == Kind::Check
                    && !t.cancelled
                    && let Some(p) = self.pairs.iter_mut().find(|p| p.id == t.pair)
                {
                    if !p.nominated && (p.state == PairState::InProgress || p.nominating) {
                        p.state = PairState::Failed;
                    }
                    p.nominating = false;
                }
                continue;
            }
            let len =
                self.write_check(out, &t.tid, t.kind, t.component, t.use_candidate, t.role)?;
            let now = self.now;
            let txn = self.txns.get_mut(k)?;
            // At most RC (checked above).
            txn.sends = txn.sends.saturating_add(1);
            // RFC 8489 §6.2.1: waits of RTO, 2 RTO, 4 RTO, …; Rm RTO after
            // the last send.
            let wait = if txn.sends >= RC {
                RM.saturating_mul(txn.rto_ms)
            } else {
                // At most 2^5 RTO.
                txn.rto_ms
                    .checked_shl(u32::from(txn.sends.saturating_sub(1)))
                    .unwrap_or(u64::MAX)
            };
            txn.next_ms = now.saturating_add(wait);
            self.stats.checks_sent = self.stats.checks_sent.saturating_add(1);
            return Some(Transmit {
                component: t.component,
                dst: t.dst,
                len,
            });
        }
        None
    }

    fn poll_check(
        &mut self,
        out: &mut [u8],
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Option<Transmit> {
        if self.now < self.next_ta || self.txns.len() >= MAX_TXNS {
            return None;
        }
        for c in 1..=self.components {
            if let Some(p) = self.should_nominate(c).and_then(|k| self.pairs.get_mut(k)) {
                p.nominating = true;
                let id = p.id;
                self.queue.retain(|&q| q != id);
                self.queue.push_front(id);
            }
        }
        let mut next = checklist::next_check(self.queue.as_slice(), self.pairs.as_slice());
        if next.is_none() {
            checklist::unfreeze_idle(self.pairs.as_mut_slice());
            next = checklist::next_check(self.queue.as_slice(), self.pairs.as_slice());
        }
        let id = next?;
        self.queue.retain(|&q| q != id);
        let k = self.pairs.iter().position(|p| p.id == id)?;
        let p = *self.pairs.get(k)?;
        let dst = self.remote_of(&p)?;
        if p.state == PairState::Succeeded && !p.nominating {
            return None;
        }
        if p.state != PairState::Succeeded {
            // A valid pair being nominated stays valid during its check.
            self.set_state(k, PairState::InProgress);
        }
        let mut tid = [0u8; 12];
        random(&mut tid);
        self.next_ta = self.now.saturating_add(self.ta_ms);
        let use_candidate = p.nominating && self.role == Role::Controlling;
        self.send_check(out, tid, Kind::Check, id, p.component, dst, use_candidate)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_check(
        &mut self,
        out: &mut [u8],
        tid: [u8; 12],
        kind: Kind,
        pair: u16,
        component: u8,
        dst: SocketAddr,
        use_candidate: bool,
    ) -> Option<Transmit> {
        let len = self.write_check(out, &tid, kind, component, use_candidate, self.role)?;
        let count = |s: PairState| {
            u64::try_from(self.pairs.iter().filter(|p| p.state == s).count()).unwrap_or(u64::MAX)
        };
        let rto = checklist::check_rto(
            self.ta_ms,
            1,
            count(PairState::Waiting),
            count(PairState::InProgress),
        );
        let next_ms = match kind {
            Kind::Check => self.now.saturating_add(rto),
            // Sent once; a response is taken until consent would expire.
            Kind::Consent { .. } => self.now.saturating_add(consent::EXPIRY_MS),
        };
        if self.txns.len() < MAX_TXNS {
            self.txns.push(Txn {
                tid,
                kind,
                pair,
                component,
                dst,
                role: self.role,
                use_candidate,
                sends: 1,
                rto_ms: rto,
                next_ms,
                cancelled: false,
            });
        }
        self.stats.checks_sent = self.stats.checks_sent.saturating_add(1);
        Some(Transmit {
            component,
            dst,
            len,
        })
    }

    fn write_check(
        &self,
        out: &mut [u8],
        tid: &[u8; 12],
        kind: Kind,
        component: u8,
        use_candidate: bool,
        role: Role,
    ) -> Option<usize> {
        let (local, remote, pwd) = if kind == (Kind::Consent { prev: true }) {
            (&self.prev_creds.0, &self.prev_creds.1, &self.prev_creds.2)
        } else {
            (&self.local_ufrag, &self.remote_ufrag, &self.remote_pwd)
        };
        // `<peer's ufrag>:<own ufrag>`.
        let mut user = [0u8; 2 * MAX_CRED + 1];
        let (r, l) = (remote.as_slice(), local.as_slice());
        let len = r.len().checked_add(1)?.checked_add(l.len())?;
        {
            let (ru, rest) = user.split_at_mut_checked(r.len())?;
            ru.copy_from_slice(r);
            let (colon, rest) = rest.split_first_mut()?;
            *colon = b':';
            rest.get_mut(..l.len())?.copy_from_slice(l);
        }
        let user = user.get(..len)?;
        let pwd = pwd.as_slice();
        let priority = checklist::candidate_priority(
            CandType::Prflx.type_pref(),
            LOCAL_PREF,
            u32::from(component),
        );
        stun::write_check(
            out,
            tid,
            &CheckRequest {
                username: user,
                pwd,
                priority,
                role,
                tiebreaker: self.tiebreaker,
                use_candidate,
            },
        )
    }

    /// When [`Agent::poll`] next has something to do.
    #[must_use]
    pub fn next_ms(&self) -> Option<u64> {
        let mut next = self.txns.iter().map(|t| t.next_ms).min();
        let mut at = |t: u64| next = Some(next.map_or(t, |n| n.min(t)));
        for c in 1..=self.components {
            if let Some(b) = self.consent.at(c).flatten()
                && let Some(t) = b.consent.next_ms()
            {
                at(t);
            }
            if let Some(p) = self.prev.at(c).flatten()
                && let Some(t) = p.consent.next_ms()
            {
                at(t);
            }
        }
        let work =
            self.checkable() || (1..=self.components).any(|c| self.should_nominate(c).is_some());
        if work && self.txns.len() < MAX_TXNS {
            at(self.next_ta);
        }
        if self.role == Role::Controlling {
            for c in 1..=self.components {
                if let Some(t) = self.first_valid.at(c).flatten()
                    && !self
                        .pairs
                        .iter()
                        .any(|p| p.component == c && (p.nominated || p.nominating))
                {
                    at(t.saturating_add(NOMINATE_AFTER_MS).max(self.next_ta));
                }
            }
        }
        // A consent binding starts at the first poll after a pair is valid.
        if (1..=self.components).any(|c| {
            self.target_pair(c).is_some_and(|k| {
                let id = self.pairs.get(k).map(|p| p.id);
                self.consent
                    .at(c)
                    .flatten()
                    .is_none_or(|b| Some(b.pair) != id)
            })
        }) {
            at(self.now);
        }
        next
    }
}

#[cfg(test)]
mod tests;
