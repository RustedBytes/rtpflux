//! BUNDLE (RFC 8843): sorting a shared port's media into its sections.

#[allow(clippy::wildcard_imports)]
use super::*;

/// How the shared port of a BUNDLE group (side A of its first member)
/// sorts arriving media into the members (RFC 8843 §9.2).
pub(super) struct BundleRoute {
    /// Payload type → the member's A-RTP slot.
    pub(super) by_pt: [Option<Slot>; 128],
    /// SSRCs seen in RTP → the member's A-RTP slot (for RTCP).
    pub(super) by_ssrc: Vec<(u32, Slot)>,
    /// The other members' A-RTP slots (whose `via` is this shared port).
    pub(super) members: Vec<Slot>,
}

impl BundleRoute {
    /// The member leg an arriving packet belongs to, from its header (in
    /// clear also under SRTP): RTP by payload type, RTCP by sender SSRC
    /// (`fallback` for an SSRC not seen yet, or a packet too short to
    /// tell). `None` for RTP whose payload type no member has: no section
    /// negotiated it, so it is dropped rather than handed to one. Once no
    /// other member is left (they ended), the port is the primary's alone
    /// and everything is its own.
    pub(super) fn member(&self, packet: &[u8], rtcp: bool, fallback: Slot) -> Option<Slot> {
        if self.members.is_empty() {
            return Some(fallback);
        }
        // RTCP: sender SSRC at octets 4..8; RTP: header of 12 octets.
        if packet.len() < if rtcp { 8 } else { 12 } {
            return Some(fallback);
        }
        if rtcp {
            let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
            return Some(
                self.by_ssrc
                    .iter()
                    .find(|(s, _)| *s == ssrc)
                    .map_or(fallback, |&(_, m)| m.rtcp()),
            );
        }
        self.by_pt[usize::from(Pt::of_header(packet[1]))]
    }

    /// An authenticated RTP packet of member `m`: its SSRC sorts RTCP.
    pub(super) fn learn(&mut self, packet: &[u8], m: Slot) {
        let Some(ssrc) = packet.get(8..12) else {
            return;
        };
        let ssrc = u32::from_be_bytes([ssrc[0], ssrc[1], ssrc[2], ssrc[3]]);
        if !self.by_ssrc.iter().any(|(s, _)| *s == ssrc) && self.by_ssrc.len() < 64 {
            self.by_ssrc.push((ssrc, m));
        }
    }
}

/// The leg a packet arriving on `arrived` belongs to: `arrived` itself,
/// unless it is a BUNDLE group's shared port, which sorts it into a member
/// (`None`: no member takes it, so it is dropped).
pub(super) fn sort(
    routes: &PerSlot<Option<Box<BundleRoute>>>,
    arrived: Slot,
    packet: &[u8],
) -> Option<Slot> {
    match routes.get(arrived.rtp()).and_then(Option::as_ref) {
        Some(route) => route.member(packet, arrived.is_rtcp(), arrived),
        None => Some(arrived),
    }
}

impl Worker {
    pub(super) fn bundle(&mut self, primary: CallId, members: &[(CallId, Vec<Pt>)]) {
        let Some(p) = self.calls.get(&primary).map(|c| c.slots[0]) else {
            return;
        };
        // The previous group's members leave it first.
        self.release_members(p);
        let mut route = BundleRoute {
            by_pt: [None; 128],
            by_ssrc: Vec::new(),
            members: Vec::new(),
        };
        for (call, pts) in members {
            let Some(m) = self.calls.get(call).map(|c| c.slots[0]) else {
                continue;
            };
            for &pt in pts {
                route.by_pt[usize::from(pt)].get_or_insert(m);
            }
            if m != p {
                self.via[m] = Some(p);
                self.via[m.rtcp()] = Some(p);
                route.members.push(m);
            }
        }
        self.routes[p] = Some(Box::new(route));
    }

    /// The shared port at A-RTP slot `p` stops carrying its group: its
    /// members no longer send through it (nor copy its peer).
    fn release_members(&mut self, p: Slot) {
        let Some(route) = self.routes.get_mut(p).and_then(Option::take) else {
            return;
        };
        for m in route.members {
            for slot in [m, m.rtcp()] {
                if let Some(v) = self.via.get_mut(slot)
                    && *v == Some(p)
                {
                    *v = None;
                }
            }
        }
    }

    /// The call at A-RTP slot `slot` ends: if it carried a group, the
    /// members leave it; if it was a member, the shared port stops sorting
    /// media into it (its slots may soon be another call's).
    pub(super) fn unbundle(&mut self, slot: Slot) {
        self.release_members(slot);
        let Some(p) = self.via.get(slot).copied().flatten() else {
            return;
        };
        if let Some(Some(route)) = self.routes.get_mut(p) {
            for r in &mut route.by_pt {
                if *r == Some(slot) {
                    *r = None;
                }
            }
            route.by_ssrc.retain(|&(_, member)| member != slot);
            route.members.retain(|&member| member != slot);
        }
    }

    /// Side A of a bundled member has no traffic of its own: its peer is
    /// the shared port's (copied before relaying towards it).
    pub(super) fn sync_via(&mut self, leg: Slot) {
        let Some(partner) = self.legs.get(leg).copied().flatten().map(|l| l.partner) else {
            return;
        };
        if let Some(p) = self.via.get(partner).copied().flatten() {
            let shared = if partner.is_rtcp() { p.rtcp() } else { p };
            if let Some(latch) = self.legs.get(shared).copied().flatten().map(|l| l.latch)
                && let Some(Some(member)) = self.legs.get_mut(partner)
            {
                member.latch = latch;
            }
        }
    }
}
