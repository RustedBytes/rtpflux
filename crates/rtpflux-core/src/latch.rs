//! Where to send a leg's media: the address from the SDP, or the source
//! address its packets actually come from (symmetric RTP, RFC 4961 §3:
//! endpoints send from the port they receive on, so a relay can "latch"
//! onto the observed source and traverse NATs).
//!
//! Modes follow the `endpoint-learning` option of the `ng` protocol:
//! * `Off` — always use the SDP address; never learn.
//! * `Immediate` — latch onto the source of the first packet.
//! * `Heuristic` — during a learning window, prefer the source that best
//!   matches the SDP: same address and port, then same address, then any;
//!   after the window the choice is fixed.
//!
//! `strict_source` drops packets from any source other than the current
//! target once there is one.
//!
//! With handover (`media-handover`, [`Latch::with_handover`]) a learned
//! target is not fixed: a new source takes it over once it has sent
//! [`HANDOVER_PACKETS`] packets in a row with none from the target in
//! between (a NAT that rebound, a phone that changed networks). Its
//! packets until then are dropped under `strict_source`. A target an ICE
//! check confirmed moves only by ICE.

use core::net::SocketAddr;

/// How a leg learns its peer address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Learning {
    Off,
    Immediate,
    Heuristic,
}

/// Length of the heuristic learning window.
pub const HEURISTIC_WINDOW_MS: u64 = 3_000;

/// Packets in a row from a new source that take a handover leg over.
pub const HANDOVER_PACKETS: u8 = 3;

/// What to do with a received packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// From a source other than the latched or expected one, with
    /// `strict_source` set.
    Drop,
}

/// Peer-address state of one leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Latch {
    expected: Option<SocketAddr>,
    learned: Option<SocketAddr>,
    score: u8,
    mode: Learning,
    strict_source: bool,
    window_end_ms: Option<u64>,
    handover: bool,
    /// A source other than the target, and its packets in a row.
    candidate: Option<(SocketAddr, u8)>,
}

/// The score of an address confirmed by an authenticated ICE check: above
/// anything heuristic learning assigns.
const CONFIRMED: u8 = 4;

impl Latch {
    /// A leg whose SDP announced `expected` (if known).
    #[must_use]
    pub const fn new(expected: Option<SocketAddr>, mode: Learning, strict_source: bool) -> Self {
        Latch {
            expected,
            learned: None,
            score: 0,
            mode,
            strict_source,
            window_end_ms: None,
            handover: false,
            candidate: None,
        }
    }

    /// The same leg, whose learned target a new source can take over.
    #[must_use]
    pub const fn with_handover(mut self) -> Self {
        self.handover = true;
        self
    }

    /// Whether a new source can take the target over.
    #[must_use]
    pub const fn handover(&self) -> bool {
        self.handover
    }

    /// The address media for this leg is sent to.
    #[must_use]
    pub fn target(&self) -> Option<SocketAddr> {
        self.learned.or(self.expected)
    }

    /// Packets from other sources are dropped.
    #[must_use]
    pub const fn strict_source(&self) -> bool {
        self.strict_source
    }

    /// Whether the target was learned from received packets.
    #[must_use]
    pub fn is_learned(&self) -> bool {
        self.learned.is_some()
    }

    /// Whether the target can no longer change by itself: `Off` with an SDP
    /// address, `Immediate` once latched, `Heuristic` once latched and the
    /// learning window has closed. Only settled legs are handed to the XDP
    /// fast path, which does not learn.
    #[must_use]
    pub fn settled(&self, now_ms: u64) -> bool {
        match self.mode {
            _ if self.score == CONFIRMED => true,
            // Never fixed: the fast path does not learn.
            _ if self.handover => false,
            Learning::Off => self.expected.is_some(),
            Learning::Immediate => self.learned.is_some(),
            Learning::Heuristic => {
                self.learned.is_some() && self.window_end_ms.is_some_and(|end| now_ms >= end)
            }
        }
    }

    /// Replace the SDP address (a re-INVITE, for example); learning restarts.
    pub fn set_expected(&mut self, expected: Option<SocketAddr>) {
        self.expected = expected;
        self.learned = None;
        self.score = 0;
        self.window_end_ms = None;
        self.candidate = None;
    }

    /// An authenticated ICE connectivity check arrived from `src` (RFC 8445
    /// §7.3): the peer proved it holds the session's ICE password, which no
    /// media packet does. It sets the target in every learning mode and
    /// ends learning; a later check moves it only when it nominates
    /// (USE-CANDIDATE) or nothing was confirmed yet.
    pub fn confirm(&mut self, src: SocketAddr, nominated: bool) {
        if nominated || self.score < CONFIRMED {
            self.learned = Some(src);
            self.score = CONFIRMED;
            self.window_end_ms = Some(0);
        }
    }

    /// Count `src` towards taking the learned target over.
    fn hand_over(&mut self, src: SocketAddr) {
        let Some(target) = self.learned else {
            return;
        };
        if target == src {
            self.candidate = None;
            return;
        }
        let n = match self.candidate {
            Some((c, n)) if c == src => n.saturating_add(1),
            _ => 1,
        };
        if n >= HANDOVER_PACKETS {
            self.learned = Some(src);
            self.candidate = None;
        } else {
            self.candidate = Some((src, n));
        }
    }

    fn score_of(&self, src: SocketAddr) -> u8 {
        match self.expected {
            Some(e) if e == src => 3,
            Some(e) if e.ip() == src.ip() => 2,
            _ => 1,
        }
    }

    /// Account for a packet from `src` received at `now_ms` (monotonic
    /// milliseconds); returns whether it is accepted.
    pub fn on_packet(&mut self, src: SocketAddr, now_ms: u64) -> Verdict {
        match self.mode {
            Learning::Off => {}
            Learning::Immediate => {
                if self.learned.is_none() {
                    self.learned = Some(src);
                }
            }
            Learning::Heuristic => {
                let window_end = *self
                    .window_end_ms
                    .get_or_insert(now_ms.saturating_add(HEURISTIC_WINDOW_MS));
                let score = self.score_of(src);
                if now_ms < window_end && score > self.score {
                    self.learned = Some(src);
                    self.score = score;
                }
            }
        }
        if self.handover && self.mode != Learning::Off && self.score != CONFIRMED {
            self.hand_over(src);
        }
        if self.strict_source && self.target().is_some_and(|t| t != src) {
            Verdict::Drop
        } else {
            Verdict::Accept
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn off_uses_the_sdp_address() {
        let mut l = Latch::new(Some(sa("192.0.2.1:4000")), Learning::Off, false);
        assert_eq!(l.on_packet(sa("198.51.100.9:5000"), 0), Verdict::Accept);
        assert_eq!(l.target(), Some(sa("192.0.2.1:4000")));
        assert!(!l.is_learned());
    }

    #[test]
    fn immediate_latches_the_first_source() {
        let mut l = Latch::new(Some(sa("10.0.0.5:4000")), Learning::Immediate, false);
        l.on_packet(sa("203.0.113.7:61000"), 0);
        l.on_packet(sa("203.0.113.8:61002"), 5);
        assert_eq!(l.target(), Some(sa("203.0.113.7:61000")));
    }

    #[test]
    fn heuristic_prefers_the_best_sdp_match_within_the_window() {
        let mut l = Latch::new(Some(sa("192.0.2.1:4000")), Learning::Heuristic, false);
        l.on_packet(sa("198.51.100.9:5000"), 0);
        assert_eq!(l.target(), Some(sa("198.51.100.9:5000")));
        l.on_packet(sa("192.0.2.1:4002"), 100); // same IP beats "any"
        assert_eq!(l.target(), Some(sa("192.0.2.1:4002")));
        l.on_packet(sa("198.51.100.9:5000"), 200); // worse match does not replace
        assert_eq!(l.target(), Some(sa("192.0.2.1:4002")));
        l.on_packet(sa("192.0.2.1:4000"), 300); // exact match wins
        assert_eq!(l.target(), Some(sa("192.0.2.1:4000")));
    }

    #[test]
    fn heuristic_choice_is_fixed_after_the_window() {
        let mut l = Latch::new(Some(sa("192.0.2.1:4000")), Learning::Heuristic, false);
        l.on_packet(sa("198.51.100.9:5000"), 1_000);
        l.on_packet(sa("192.0.2.1:4000"), 1_000 + HEURISTIC_WINDOW_MS);
        assert_eq!(l.target(), Some(sa("198.51.100.9:5000")));
    }

    #[test]
    fn strict_source_drops_others() {
        let mut l = Latch::new(None, Learning::Immediate, true);
        assert_eq!(l.on_packet(sa("203.0.113.7:61000"), 0), Verdict::Accept);
        assert_eq!(l.on_packet(sa("203.0.113.7:61001"), 1), Verdict::Drop);
        let mut off = Latch::new(Some(sa("192.0.2.1:4000")), Learning::Off, true);
        assert_eq!(off.on_packet(sa("192.0.2.1:4000"), 0), Verdict::Accept);
        assert_eq!(off.on_packet(sa("192.0.2.66:4000"), 0), Verdict::Drop);
    }

    #[test]
    fn settledness() {
        assert!(Latch::new(Some(sa("192.0.2.1:4000")), Learning::Off, false).settled(0));
        assert!(!Latch::new(None, Learning::Off, false).settled(0));
        let mut i = Latch::new(None, Learning::Immediate, false);
        assert!(!i.settled(0));
        i.on_packet(sa("203.0.113.7:61000"), 0);
        assert!(i.settled(0));
        let mut h = Latch::new(Some(sa("192.0.2.1:4000")), Learning::Heuristic, false);
        h.on_packet(sa("192.0.2.1:4000"), 100);
        assert!(!h.settled(100 + HEURISTIC_WINDOW_MS - 1));
        assert!(h.settled(100 + HEURISTIC_WINDOW_MS));
    }

    #[test]
    fn new_sdp_restarts_learning() {
        let mut l = Latch::new(None, Learning::Immediate, false);
        l.on_packet(sa("203.0.113.7:61000"), 0);
        l.set_expected(Some(sa("192.0.2.1:4000")));
        assert_eq!(l.target(), Some(sa("192.0.2.1:4000")));
        l.on_packet(sa("203.0.113.9:62000"), 10);
        assert_eq!(l.target(), Some(sa("203.0.113.9:62000")));
    }

    #[test]
    fn handover_follows_a_source_that_keeps_sending() {
        let (sdp, old, new, stray) = (
            sa("10.0.0.5:4000"),
            sa("203.0.113.7:61000"),
            sa("203.0.113.7:61500"),
            sa("198.51.100.9:5000"),
        );
        for mode in [Learning::Immediate, Learning::Heuristic] {
            let mut l = Latch::new(Some(sdp), mode, false).with_handover();
            l.on_packet(old, 0);
            assert_eq!(l.target(), Some(old));
            // Long after the learning window.
            let t = 10 * HEURISTIC_WINDOW_MS;
            l.on_packet(stray, t);
            l.on_packet(old, t + 20);
            l.on_packet(new, t + 40);
            l.on_packet(new, t + 60);
            assert_eq!(l.target(), Some(old), "{mode:?}: not yet");
            l.on_packet(old, t + 80);
            l.on_packet(new, t + 100);
            l.on_packet(new, t + 120);
            assert_eq!(
                l.target(),
                Some(old),
                "{mode:?}: the target spoke in between"
            );
            l.on_packet(new, t + 140);
            assert_eq!(l.target(), Some(new), "{mode:?}: three in a row");
            assert!(!l.settled(t + 200), "never handed to the fast path");
        }
        // Without it, the choice stays (the default).
        let mut l = Latch::new(Some(sdp), Learning::Immediate, false);
        l.on_packet(old, 0);
        for k in 0..10 {
            l.on_packet(new, 10 + k);
        }
        assert_eq!(l.target(), Some(old));
        // Off never learns; strict drops the newcomer until it takes over.
        let mut l = Latch::new(Some(sdp), Learning::Off, false).with_handover();
        for k in 0..5 {
            l.on_packet(new, k);
        }
        assert_eq!(l.target(), Some(sdp));
        let mut l = Latch::new(None, Learning::Immediate, true).with_handover();
        assert_eq!(l.on_packet(old, 0), Verdict::Accept);
        assert_eq!(l.on_packet(new, 1), Verdict::Drop);
        assert_eq!(l.on_packet(new, 2), Verdict::Drop);
        assert_eq!(l.on_packet(new, 3), Verdict::Accept, "it took over");
        assert_eq!(l.on_packet(old, 4), Verdict::Drop);
        // An ICE-confirmed target moves only by ICE.
        let mut l = Latch::new(None, Learning::Immediate, false).with_handover();
        l.confirm(old, true);
        for k in 0..5 {
            l.on_packet(new, k);
        }
        assert_eq!(l.target(), Some(old));
    }

    #[test]
    fn ice_checks_confirm_the_target() {
        let (sdp, nat, other) = (
            sa("192.0.2.1:4000"),
            sa("203.0.113.5:6000"),
            sa("198.51.100.9:5000"),
        );
        let mut l = Latch::new(Some(sdp), Learning::Heuristic, false);
        l.on_packet(sdp, 0);
        l.confirm(nat, false);
        assert_eq!(l.target(), Some(nat), "a check beats the SDP address");
        assert!(l.settled(1));
        l.on_packet(sdp, 2);
        assert_eq!(
            l.target(),
            Some(nat),
            "media cannot move a confirmed target"
        );
        l.confirm(other, false);
        assert_eq!(
            l.target(),
            Some(nat),
            "an unnominated check does not move it"
        );
        l.confirm(other, true);
        assert_eq!(l.target(), Some(other), "a nomination does");
        l.set_expected(Some(sdp));
        assert_eq!(l.target(), Some(sdp), "a new SDP address starts over");
    }
}
