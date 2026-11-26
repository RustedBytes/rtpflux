//! Media subscriptions (rtpengine's `subscribe request`): what one side of
//! a call sends is also sent to a subscriber (a recorder, say).
//!
//! A subscription's media lives in relay calls of its own on the source
//! call's worker, whose legs face the subscriber and only send: they are
//! *sinks* (what arrives on them is not relayed). A source leg lists the
//! sink legs it is *tapped* to; each packet it accepts is copied to them as
//! it arrived (decrypted, before blocking, transcoding or DTMF conversion),
//! encrypted for the subscriber if it uses SRTP, and sent to its address.
//! The copy goes through a spare buffer after the batch's (no allocation),
//! and keeps the subscription call from timing out while the source talks.
//! A tapped call stays in userspace.

#[allow(clippy::wildcard_imports)]
use super::*;

use super::features::{BLOCK_COPIES, BLOCK_COPIES_SILENCE};
use crate::relay::taps::Arrival;

impl Worker {
    /// Make `call`'s legs sinks.
    pub(super) fn sink(&mut self, call: CallId) {
        if let Some(c) = self.calls.get(&call) {
            // The taps table keeps slots as numbers (`relay::taps`).
            self.taps.sink(&c.slots.map(Slot::get));
        }
    }

    /// Tap (`on`) or untap side `source_b` of call `source` to side `sub_b`
    /// of the sink call `sub`: its RTP leg to theirs, and its RTCP leg to
    /// theirs. Refused unless `sub` is a sink.
    pub(super) fn tap(
        &mut self,
        source: CallId,
        source_leg: CallLeg,
        sub: CallId,
        sub_leg: CallLeg,
        on: bool,
    ) {
        let (Some(s), Some(t)) = (self.calls.get(&source), self.calls.get(&sub)) else {
            return;
        };
        let k = source_leg.rtp_slot();
        let j = sub_leg.rtp_slot();
        let pairs = [
            (s.slots[k].get(), t.slots[j].get()),
            (s.slots[k].rtcp().get(), t.slots[j].rtcp().get()),
        ];
        if !self.taps.tap(&pairs, on) {
            log::warn!("call {source}: not tapped to call {sub}, which is no subscription");
        }
        self.refresh_offload(source);
    }

    /// The packet at `bufs[at..at + len]` from `leg` (relayed as
    /// `decision`): copied to the legs `leg` is tapped to if accepted. True
    /// when it is not relayed (it arrived on a sink).
    pub(super) fn subscriptions_in(
        &mut self,
        leg: Slot,
        decision: Decision,
        (at, len): (usize, usize),
        now: u64,
    ) -> bool {
        let accepted = !matches!(
            decision,
            Decision::Drop(relay::DropReason::WrongSource | relay::DropReason::NoLeg)
        );
        let tapped = match self.taps.arrive(leg.index(), accepted) {
            Arrival::Sink => return true,
            Arrival::Copy(t) => !t.is_empty(),
        };
        let remote = accepted && self.copied_remote(leg);
        if !tapped && !remote {
            return false;
        }
        // Its copies blocked or silenced (`all: except-offer-answer`).
        let b = self.blocked.get(leg).copied().unwrap_or(0);
        let (at, copy) = if leg.is_rtcp() {
            (at, true)
        } else if b & BLOCK_COPIES != 0 {
            (at, false)
        } else if b & BLOCK_COPIES_SILENCE != 0 && !self.is_event(leg, &self.bufs[at..at + len]) {
            let spare = (self.batch + 1) * self.packet_buffer;
            self.bufs.copy_within(at..at + len, spare);
            // Audio other than G.711 is not copied (as `silence media`
            // holds it back).
            (spare, self.silence(spare, len).is_some())
        } else {
            (at, true)
        };
        if copy {
            // Copies to listeners on other workers (`connect` directional).
            if remote {
                self.copy_to_remote(leg, (at, len));
            }
            if tapped {
                self.copy_to_taps(leg, (at, len), now);
            }
        }
        false
    }

    /// Whether `slot` is tapped.
    pub(super) fn tapped(&self, slot: Slot) -> bool {
        self.taps.tapped(slot.index()) || self.copied_remote(slot)
    }

    /// Whether `slot` is a sink.
    pub(super) fn is_sink(&self, slot: Slot) -> bool {
        self.taps.is_sink(slot.index())
    }

    /// Copy the packet at `bufs[at..at + len]`, accepted from `leg`, to the
    /// sink legs it is tapped to.
    pub(super) fn copy_to_taps(&mut self, leg: Slot, (at, len): (usize, usize), now: u64) {
        let scratch = self.batch * self.packet_buffer;
        let mut k = 0;
        loop {
            let Arrival::Copy(targets) = self.taps.arrive(leg.index(), true) else {
                return;
            };
            let Some(to) = targets.get(k).copied().map(Slot::new) else {
                return;
            };
            k += 1;
            let Some(dst) = self
                .legs
                .get(to)
                .copied()
                .flatten()
                .and_then(|l| l.latch.target())
            else {
                continue;
            };
            self.bufs.copy_within(at..at + len, scratch);
            // Converted to the listener's codec (`connect` directional).
            let size = self.packet_buffer;
            let len = match self
                .copy_xcode
                .get_mut(leg)
                .and_then(|l| l.iter_mut().find(|(d, _)| *d == to))
            {
                Some((_, x)) => match x.packet(&mut self.bufs[scratch..scratch + size], len) {
                    Some(n) => n,
                    None => continue,
                },
                None => len,
            };
            let (send_slot, out) = self.outbound(to, scratch, len);
            let Some(out) = out else {
                continue;
            };
            self.send(send_slot, &[(send_slot, Some(dst), self.batch, out)]);
            if let Some(Some(l)) = self.legs.get_mut(to) {
                l.last_active_ms = now;
            }
            if let Some(c) = self.copied.get_mut(to) {
                c[0] += 1;
                c[1] += out as u64;
            }
        }
    }

    /// `slots` (a call's) close: their taps go, and, for a sink, every tap
    /// to them.
    pub(super) fn untap(&mut self, slots: &[Slot; 4]) {
        self.taps.close(&slots.map(Slot::get));
    }
}
