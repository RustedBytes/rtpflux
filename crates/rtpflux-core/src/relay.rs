//! The per-packet forwarding decision of the userspace relay.
//!
//! A *leg* is one local socket (an RTP or an RTCP port) together with the
//! peer it talks to. Legs come in partners: what arrives on a leg is sent
//! out of its partner's socket to the partner's peer. Legs live in a table
//! owned by the caller and indexed by socket slot, so a lookup is a direct
//! index; nothing here allocates.

use crate::latch::{Latch, Verdict};
use core::net::SocketAddr;

/// A socket slot: where a local port's socket and its leg are kept. A
/// relay call's RTP port and its RTCP port (the next one) take two slots,
/// the RTP one even, the RTCP one after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot(u32);

impl Slot {
    #[must_use]
    pub const fn new(n: u32) -> Slot {
        Slot(n)
    }

    /// The slot as kept in a table index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// An RTCP slot (odd): the one after its RTP slot.
    #[must_use]
    pub const fn is_rtcp(self) -> bool {
        self.0 % 2 == 1
    }

    /// The RTP slot of a pair (this one, or the one before an RTCP slot).
    #[must_use]
    pub const fn rtp(self) -> Slot {
        Slot(self.0 & !1)
    }

    /// The RTCP slot of a pair.
    #[must_use]
    pub const fn rtcp(self) -> Slot {
        Slot(self.0 | 1)
    }

    /// The other slot of the pair (RTP ↔ RTCP).
    #[must_use]
    pub const fn pair(self) -> Slot {
        Slot(self.0 ^ 1)
    }
}

impl core::fmt::Display for Slot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// One leg of a relayed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leg {
    pub latch: Latch,
    /// Slot of the partner leg (whose socket sends what this leg receives).
    pub partner: Slot,
    /// Monotonic time of the last accepted packet, in milliseconds.
    pub last_active_ms: u64,
    pub packets: u64,
    pub octets: u64,
    pub dropped: u64,
}

impl Leg {
    #[must_use]
    pub const fn new(latch: Latch, partner: Slot, now_ms: u64) -> Self {
        Leg {
            latch,
            partner,
            last_active_ms: now_ms,
            packets: 0,
            octets: 0,
            dropped: 0,
        }
    }
}

/// Outcome for one received packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Send it out of `out_slot`'s socket to `dst`.
    Forward { out_slot: Slot, dst: SocketAddr },
    /// Drop it.
    Drop(DropReason),
}

/// Why a packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// No leg is bound to the receiving slot.
    NoLeg,
    /// The source is not the latched or expected one (`strict-source`).
    WrongSource,
    /// The partner leg is missing or has no destination yet.
    NoDestination,
}

/// Decide what to do with `len` octets from `src` received on `slot` at
/// `now_ms`, updating the leg's latch, activity and counters.
pub fn on_packet(
    legs: &mut [Option<Leg>],
    slot: Slot,
    src: SocketAddr,
    len: usize,
    now_ms: u64,
) -> Decision {
    let Some(leg) = legs.get_mut(slot.index()).and_then(Option::as_mut) else {
        return Decision::Drop(DropReason::NoLeg);
    };
    if leg.latch.on_packet(src, now_ms) == Verdict::Drop {
        leg.dropped = leg.dropped.saturating_add(1);
        return Decision::Drop(DropReason::WrongSource);
    }
    leg.last_active_ms = now_ms;
    leg.packets = leg.packets.saturating_add(1);
    leg.octets = leg.octets.saturating_add(len as u64);
    let partner = leg.partner;
    let dst = legs
        .get(partner.index())
        .and_then(Option::as_ref)
        .and_then(|p| p.latch.target());
    let Some(dst) = dst else {
        if let Some(Some(leg)) = legs.get_mut(slot.index()) {
            leg.dropped = leg.dropped.saturating_add(1);
        }
        return Decision::Drop(DropReason::NoDestination);
    };
    Decision::Forward {
        out_slot: partner,
        dst,
    }
}

/// Whether both legs of a pair have been silent for at least `timeout_ms`.
#[must_use]
pub fn idle(a: &Leg, b: &Leg, now_ms: u64, timeout_ms: u64) -> bool {
    now_ms.saturating_sub(a.last_active_ms.max(b.last_active_ms)) >= timeout_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latch::Learning;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn pair() -> [Option<Leg>; 4] {
        // slot 0 faces the caller, slot 2 the callee (1 and 3 unused here).
        let a = Leg::new(
            Latch::new(Some(sa("192.0.2.1:4000")), Learning::Immediate, true),
            Slot(2),
            0,
        );
        let b = Leg::new(
            Latch::new(Some(sa("198.51.100.2:5000")), Learning::Immediate, true),
            Slot(0),
            0,
        );
        [Some(a), None, Some(b), None]
    }

    #[test]
    fn forwards_to_the_partner_peer() {
        let mut legs = pair();
        let d = on_packet(&mut legs, Slot(0), sa("192.0.2.1:4000"), 172, 10);
        assert_eq!(
            d,
            Decision::Forward {
                out_slot: Slot(2),
                dst: sa("198.51.100.2:5000")
            }
        );
        let d = on_packet(&mut legs, Slot(2), sa("198.51.100.2:5000"), 172, 20);
        assert_eq!(
            d,
            Decision::Forward {
                out_slot: Slot(0),
                dst: sa("192.0.2.1:4000")
            }
        );
        let a = legs[0].unwrap();
        assert_eq!((a.packets, a.octets, a.last_active_ms), (1, 172, 10));
    }

    #[test]
    fn latching_redirects_the_return_path() {
        let mut legs = pair();
        // The caller is behind a NAT: its packets come from another address.
        on_packet(&mut legs, Slot(0), sa("203.0.113.50:61000"), 100, 1);
        let d = on_packet(&mut legs, Slot(2), sa("198.51.100.2:5000"), 100, 2);
        assert_eq!(
            d,
            Decision::Forward {
                out_slot: Slot(0),
                dst: sa("203.0.113.50:61000")
            }
        );
    }

    #[test]
    fn drops() {
        let mut legs = pair();
        on_packet(&mut legs, Slot(0), sa("192.0.2.1:4000"), 10, 0);
        assert_eq!(
            on_packet(&mut legs, Slot(0), sa("192.0.2.66:4000"), 10, 1),
            Decision::Drop(DropReason::WrongSource)
        );
        assert_eq!(
            on_packet(&mut legs, Slot(1), sa("192.0.2.1:4000"), 10, 1),
            Decision::Drop(DropReason::NoLeg)
        );
        assert_eq!(
            on_packet(&mut legs, Slot(9), sa("192.0.2.1:4000"), 10, 1),
            Decision::Drop(DropReason::NoLeg)
        );
        legs[2] = None;
        assert_eq!(
            on_packet(&mut legs, Slot(0), sa("192.0.2.1:4000"), 10, 2),
            Decision::Drop(DropReason::NoDestination)
        );
        assert_eq!(legs[0].unwrap().dropped, 2);
    }

    #[test]
    fn idleness() {
        let legs = pair();
        let (a, b) = (legs[0].unwrap(), legs[2].unwrap());
        assert!(!idle(&a, &b, 59_999, 60_000));
        assert!(idle(&a, &b, 60_000, 60_000));
    }
}
