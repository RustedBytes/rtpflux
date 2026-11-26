//! RTCP statistics of a leg: the latest reports its peer sent, and round
//! trips from the sender reports the relay forwarded (RFC 3550 §6.4.1).

#[allow(clippy::wildcard_imports)]
use super::*;

/// SRs remembered per leg for round trips.
pub(super) const REMEMBERED_SRS: usize = 4;

/// The RTCP state of one leg: the latest reports from its peer, and the
/// SRs the peer sent (NTP middle word, relay time in ms), which the other
/// side's reports echo.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct RtcpLeg {
    pub(super) stats: RtcpStats,
    pub(super) srs: [Option<(u32, u64)>; REMEMBERED_SRS],
    pub(super) next: usize,
}

impl RtcpLeg {
    pub(super) fn remember(&mut self, middle: u32, now: u64) {
        self.srs[self.next] = Some((middle, now));
        self.next = (self.next + 1) % REMEMBERED_SRS;
    }

    pub(super) fn sent_at(&self, middle: u32) -> Option<u64> {
        self.srs
            .iter()
            .flatten()
            .find(|&&(m, _)| m == middle)
            .map(|&(_, t)| t)
    }
}

/// Round trips above this are taken as a mismatch, not a measurement.
pub(super) const MAX_RTT_MS: u32 = 60_000;

/// Read the SRs and RRs of a relayed RTCP packet arriving on `leg` and
/// forwarded out of `out` (the other side's slot): the sender's report
/// goes to `leg`; a block echoing an SR the other side sent (which the
/// relay forwarded to this peer) gives this peer's round trip.
pub(super) fn observe_rtcp(
    rtcp: &mut PerSlot<RtcpLeg>,
    leg: Slot,
    out: Slot,
    pkt: &[u8],
    now: u64,
) {
    use rtpflux_core::rtcp::{Report, compound, ms_of_units, ntp_middle, rtt, units_of_ms};
    let Some(packets) = compound(pkt) else {
        return;
    };
    for p in packets {
        let Some(r) = Report::of(&p) else {
            continue;
        };
        let block = r.blocks().next();
        let round_trip = block
            .filter(|b| b.lsr != 0)
            .and_then(|b| {
                let sent = rtcp.get(out)?.sent_at(b.lsr)?;
                Some(ms_of_units(rtt(
                    units_of_ms(now),
                    units_of_ms(sent),
                    b.dlsr,
                )))
            })
            .filter(|&ms| ms <= MAX_RTT_MS);
        let Some(l) = rtcp.get_mut(leg) else {
            return;
        };
        l.stats.reports += 1;
        l.stats.ssrc = r.ssrc;
        if let Some(s) = r.sender {
            l.stats.sender = Some(s);
            l.remember(ntp_middle(s.ntp), now);
        }
        if block.is_some() {
            l.stats.block = block;
        }
        if round_trip.is_some() {
            l.stats.rtt_ms = round_trip;
        }
    }
}
