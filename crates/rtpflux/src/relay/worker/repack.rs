//! Repacketisation in the worker (`ptime`): a side's audio, after any
//! transcoding, goes into its leg's [`Repacker`]. The first packet ready
//! goes out in place of the one received; further ones (a packet cut in
//! several) are sent one packet duration apart by [`Worker::repack_due`],
//! as announcements are.

use super::{Slot, Worker};
use crate::relay::repack::Repacker;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

/// A leg's repacketiser and where its packets go.
#[derive(Debug)]
pub(super) struct RepackLeg {
    repacker: Box<Repacker>,
    /// The slot packets go out of and the receiver's address, from the
    /// latest packet relayed.
    route: Option<(Slot, SocketAddr)>,
    /// When the next queued packet is due (worker milliseconds).
    due: u64,
    /// Drops already counted in the worker's statistics.
    counted: u64,
}

impl Worker {
    /// Set (or remove) the repacketiser of `slot`: a new duration starts
    /// afresh, the same one keeps its state.
    pub(super) fn set_repack(&mut self, slot: Slot, config: Option<crate::relay::Repack>) {
        let Some(r) = self.repack.get_mut(slot) else {
            return;
        };
        let now = r.as_ref().map(|l| crate::relay::Repack {
            ms: l.repacker.ms(),
            opus: l.repacker.opus(),
        });
        if now == config {
            return;
        }
        let make = |c: crate::relay::Repack| {
            let r = Repacker::new(c.ms)?;
            match c.opus {
                Some(pt) => r.with_opus(pt),
                None => Some(r),
            }
        };
        *r = config.and_then(make).map(|repacker| RepackLeg {
            repacker: Box::new(repacker),
            route: None,
            due: 0,
            counted: 0,
        });
        let present = r.is_some();
        self.repack_slots.retain(|&s| s != slot);
        if present {
            self.repack_slots.push(slot);
        }
    }

    /// The RTP packet at `bufs[at..at + len]` from `leg`, going out of
    /// `out_slot` to `dst`: through the leg's repacketiser if it has one.
    /// The length of the packet to send in its place, if any.
    pub(super) fn repacked(
        &mut self,
        leg: Slot,
        (at, len): (usize, usize),
        (out_slot, dst): (Slot, SocketAddr),
        now: u64,
    ) -> Option<usize> {
        let size = self.packet_buffer;
        let Some(Some(r)) = self.repack.get_mut(leg) else {
            return Some(len);
        };
        r.route = Some((out_slot, dst));
        r.repacker.push(self.bufs.get(at..at + len)?);
        let out = r.repacker.pop(self.bufs.get_mut(at..at + size)?);
        if r.repacker.ready() {
            r.due = now + u64::from(r.repacker.ms());
        }
        self.count_repack_drops(leg);
        out
    }

    fn count_repack_drops(&mut self, leg: Slot) {
        if let Some(Some(r)) = self.repack.get_mut(leg) {
            let new = r.repacker.dropped - r.counted;
            r.counted = r.repacker.dropped;
            if new > 0 {
                self.stats.dropped.fetch_add(new, Ordering::Relaxed);
            }
        }
    }

    /// When the next queued packet is due.
    pub(super) fn next_repack_ms(&self) -> Option<u64> {
        self.repack_slots
            .iter()
            .filter_map(|&s| self.repack.get(s)?.as_ref())
            .filter(|r| r.repacker.ready())
            .map(|r| r.due)
            .min()
    }

    /// Send the queued packets that are due, one per leg and duration.
    pub(super) fn repack_due(&mut self, now: u64) {
        for k in 0..self.repack_slots.len() {
            let slot = self.repack_slots[k];
            let Some(Some(r)) = self.repack.get_mut(slot) else {
                continue;
            };
            if !r.repacker.ready() || r.due > now {
                continue;
            }
            let Some((out_slot, dst)) = r.route else {
                continue;
            };
            let Some(len) = r.repacker.pop(&mut self.bufs[..self.packet_buffer]) else {
                continue;
            };
            r.due = now + u64::from(r.repacker.ms());
            let (send_slot, len) = self.outbound(out_slot, 0, len);
            if let Some(len) = len {
                self.send(send_slot, &[(out_slot, Some(dst), 0, len)]);
            } else {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
