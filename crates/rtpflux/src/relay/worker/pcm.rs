//! A leg's PCM stream (`stream.start`), on the worker: what the leg's
//! endpoint sends is copied (by value, into a bounded queue; dropped and
//! counted when it is full) for the stream's threads, which do all the
//! signal processing (`crate::pcm::stream`); the G.711 frames they send
//! back are played to the endpoint every 20 ms, in the leg's announcement
//! stream, holding back the other side's audio while they come (as an
//! announcement does). A flush drops the frames queued.

use super::features::{BLOCK_PLAY, Kind, random_stream};
use super::{Slot, Worker};
use crate::pcm::stream::{RtpCopy, WorkerEnd};
use crate::relay::CallId;
use std::sync::atomic::Ordering;

/// Frames without audio after which the other side is heard again.
const RELEASE_AFTER: u32 = 3;

/// A leg's stream.
#[derive(Debug)]
pub(super) struct PcmLeg {
    call: CallId,
    /// The slot whose media is held back while audio is injected.
    other: Slot,
    end: WorkerEnd,
    seen_flushes: u64,
    next_ms: u64,
    holding: bool,
    idle: u32,
    first: bool,
}

impl Worker {
    /// Start (`Some`) or stop the stream of RTP slot `slot` (of `call`).
    pub(super) fn pcm(&mut self, call: CallId, slot: Slot, end: Option<WorkerEnd>) {
        let Some(c) = self.calls.get(&call) else {
            return;
        };
        let other = if c.slots[0] == slot {
            c.slots[2]
        } else {
            c.slots[0]
        };
        self.pcm_release(slot);
        if let Some(p) = self.pcm_legs.get_mut(slot) {
            *p = end.map(|end| {
                Box::new(PcmLeg {
                    call,
                    other,
                    end,
                    seen_flushes: 0,
                    next_ms: 0,
                    holding: false,
                    idle: 0,
                    first: true,
                })
            });
        }
        self.pcm_slots.retain(|&s| s != slot);
        if self.pcm_legs.get(slot).is_some_and(Option::is_some) {
            self.pcm_slots.push(slot);
            let now = self.now_ms();
            if let Some(s) = self.play_streams.get_mut(slot)
                && s.is_none()
            {
                *s = Some(random_stream(now));
            }
        }
        // Copies need the packets: off the kernel fast path.
        self.refresh_offload(call);
    }

    /// The other side of `slot` is heard again, if its stream held it.
    fn pcm_release(&mut self, slot: Slot) {
        let Some(Some(p)) = self.pcm_legs.get_mut(slot) else {
            return;
        };
        if !p.holding {
            return;
        }
        p.holding = false;
        let other = p.other;
        if !self.hold.finish(Kind::Announcement, slot.index())
            && let Some(b) = self.blocked.get_mut(other)
        {
            *b &= !BLOCK_PLAY;
        }
    }

    /// The RTP packet at `bufs[at..at + len]` arrived on `leg`: copied for
    /// its stream, if it has one.
    pub(super) fn pcm_in(&mut self, leg: Slot, (at, len): (usize, usize)) {
        if leg.is_rtcp() {
            return;
        }
        let Some(Some(p)) = self.pcm_legs.get(leg) else {
            return;
        };
        let Ok(pkt) = rtpflux_core::rtp::Packet::parse(&self.bufs[at..at + len]) else {
            return;
        };
        let copy = RtpCopy::new(
            pkt.payload_type().get(),
            (pkt.sequence(), pkt.timestamp()),
            pkt.marker(),
            pkt.ssrc().get(),
            pkt.payload(),
        );
        if p.end.fork.try_send(copy).is_err() {
            p.end.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// When the next injected frame is due.
    pub(super) fn next_pcm_ms(&self) -> Option<u64> {
        self.pcm_slots
            .iter()
            .filter_map(|&s| self.pcm_legs.get(s)?.as_ref())
            .filter(|p| p.end.inject.is_some())
            .map(|p| p.next_ms)
            .min()
    }

    /// Play the injected frames that are due.
    pub(super) fn pcm_due(&mut self, now: u64) {
        for k in 0..self.pcm_slots.len() {
            let Some(&slot) = self.pcm_slots.get(k) else {
                break;
            };
            self.pcm_due_on(slot, now);
        }
    }

    fn pcm_due_on(&mut self, slot: Slot, now: u64) {
        let Some(Some(p)) = self.pcm_legs.get_mut(slot) else {
            return;
        };
        if p.next_ms > now {
            return;
        }
        let Some((rx, pt, clock)) = &p.end.inject else {
            return;
        };
        let (pt, per_ms) = (*pt, *clock / 1000);
        // Barge-in: the frames queued go, and any made before the latest
        // flush that comes later (each counted consumed, for marks).
        let flushes = p.end.flushes.load(Ordering::Relaxed);
        if flushes != p.seen_flushes {
            p.seen_flushes = flushes;
            while rx.try_recv().is_ok() {
                p.end.consumed.fetch_add(1, Ordering::Relaxed);
            }
        }
        let frame = loop {
            match rx.try_recv() {
                Ok(f) if f.flushes() < flushes => {
                    p.end.consumed.fetch_add(1, Ordering::Relaxed);
                }
                Ok(f) => break Some(f),
                Err(_) => break None,
            }
        };
        // Paced at 20 ms; after a stall, start again from now.
        p.next_ms = if now > p.next_ms + 100 {
            now + 20
        } else {
            p.next_ms + 20
        };
        let Some(encoded) = frame else {
            p.idle += 1;
            let release = p.holding && p.idle >= RELEASE_AFTER;
            if p.idle >= RELEASE_AFTER {
                p.first = true;
            }
            if release {
                self.pcm_release(slot);
                let call = p_call(self, slot);
                if let Some(call) = call {
                    self.refresh_offload(call);
                }
            }
            return;
        };
        p.idle = 0;
        p.end.played.fetch_add(1, Ordering::Relaxed);
        p.end.consumed.fetch_add(1, Ordering::Relaxed);
        let (call, other, first, hold) = (p.call, p.other, p.first, !p.holding);
        p.first = false;
        if hold {
            p.holding = true;
            self.hold.start(Kind::Announcement, slot.index());
            if let Some(b) = self.blocked.get_mut(other) {
                *b |= BLOCK_PLAY;
            }
            self.refresh_offload(call);
        }
        let dst = self
            .legs
            .get(slot)
            .copied()
            .flatten()
            .and_then(|l| l.latch.target());
        let Some(Some(stream)) = self.play_streams.get_mut(slot) else {
            return;
        };
        stream.advance(now, per_ms);
        let (ssrc, seq, ts) = (stream.ssrc, stream.take_seq(), stream.ts);
        let codes = encoded.payload();
        let len = 12 + codes.len();
        let buf = &mut self.bufs[..len];
        buf[0] = 0x80;
        buf[1] = pt.header_octet(first);
        buf[2..4].copy_from_slice(&seq.to_be_bytes());
        buf[4..8].copy_from_slice(&ts.to_be_bytes());
        buf[8..12].copy_from_slice(&ssrc.to_be_bytes());
        buf[12..].copy_from_slice(codes);
        let Some(dst) = dst else {
            return;
        };
        let (send_slot, len) = self.outbound(slot, 0, len);
        if let Some(len) = len {
            self.send(send_slot, &[(slot, Some(dst), 0, len)]);
        }
    }

    /// A call ends: its streams end (their threads see the queues go).
    pub(super) fn pcm_forget(&mut self, slots: &[Slot]) {
        for &s in slots {
            if let Some(p) = self.pcm_legs.get_mut(s) {
                *p = None;
            }
        }
        self.pcm_slots.retain(|s| !slots.contains(s));
    }
}

/// The call of the stream on `slot`.
fn p_call(w: &Worker, slot: Slot) -> Option<CallId> {
    w.pcm_legs.get(slot)?.as_ref().map(|p| p.call)
}
