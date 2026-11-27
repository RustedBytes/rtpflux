//! `connect`: one party of a call joined with a party of another call (a
//! transfer). What each sends goes to the other, from the relay port the
//! receiver already knows; the two parties left behind are detached (their
//! media is dropped, never sent to someone else).
//!
//! Two calls on this worker: their legs are paired again. On two workers:
//! each worker sends what its party sends (decrypted, after any
//! transcoding) into a bounded channel to the other, made when the calls
//! are connected, whose slots are preallocated and whose packets move by
//! value (no allocation per packet, no lock); the other drains it in
//! batches, encrypts for its party and sends. A worker wakes the other once
//! per batch. When either call ends its end of the channel goes, and the
//! other side detaches.

use super::{MAX_BATCH, OffloadMsg, OffloadState, Slot, Worker};
use crate::relay::CallId;
use nix::sys::eventfd::EventFd;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};

/// A partner slot no leg has: packets for it are dropped (no destination).
pub(super) const DETACHED: Slot = Slot::new(!1);

/// Largest packet passed between workers.
pub(super) const FORWARD_MAX: usize = 1536;
/// Packets a channel between two workers holds.
pub const FORWARD_QUEUE: usize = 256;

/// A packet passed to another worker, for its slot `slot`.
pub struct Forwarded {
    slot: Slot,
    len: u16,
    data: [u8; FORWARD_MAX],
}

impl Forwarded {
    /// `packet` (at most [`FORWARD_MAX`] octets; longer is cut) for `slot`.
    pub(super) fn new(slot: Slot, packet: &[u8]) -> Self {
        let len = packet.len().min(FORWARD_MAX);
        let mut f = Forwarded {
            slot,
            len: u16::try_from(len).unwrap_or(0),
            data: [0; FORWARD_MAX],
        };
        f.data[..len].copy_from_slice(&packet[..len]);
        f
    }
}

/// Where a connected leg's packets go on another worker.
#[derive(Debug)]
pub(super) struct RemoteLeg {
    tx: SyncSender<Forwarded>,
    /// The slot (on the other worker) they go out of.
    peer: Slot,
    wake: Arc<EventFd>,
    /// For the fast path: this leg's relay address and settled peer
    /// (`mine`, published for the other worker) and the other's
    /// (`theirs`); read and written only by the offload sweep.
    pub(super) mine: Arc<Mutex<Option<Published>>>,
    pub(super) theirs: Arc<Mutex<Option<Published>>>,
}

/// The references a worker holds to each published cell (its RTP and RTCP
/// legs').
const OWN_REFS: usize = 2;

/// A connected leg's (relay address, settled peer address, `rtcp-mux`),
/// as the other worker needs it to send there from the kernel.
pub type Published = (SocketAddr, SocketAddr, bool);

/// One side of a connection across workers, as installed in a worker.
pub struct RemoteEnd {
    /// This worker's call, and its leg's RTP slot.
    pub call: CallId,
    pub local: Slot,
    /// The other worker's RTP slot of the other party.
    pub peer: Slot,
    pub tx: SyncSender<Forwarded>,
    pub rx: Receiver<Forwarded>,
    pub peer_wake: Arc<EventFd>,
    /// This leg's and the other's published addresses (see
    /// [`RemoteLeg`]).
    pub mine: Arc<Mutex<Option<Published>>>,
    pub theirs: Arc<Mutex<Option<Published>>>,
    /// Converting this party's media for the other (`None`: as it is).
    pub transcode: Option<crate::relay::Transcode>,
}

impl Worker {
    /// The legs of the call holding `slot` other than `slot`'s pair: the
    /// other party's RTP slot.
    fn other_party(&self, slot: Slot) -> Option<Slot> {
        self.calls.values().find_map(|c| {
            if c.slots[0] == slot.rtp() {
                Some(c.slots[2])
            } else if c.slots[2] == slot.rtp() {
                Some(c.slots[0])
            } else {
                None
            }
        })
    }

    /// Point both slots of `from`'s pair at `to`'s pair (or detach them).
    fn pair_to(&mut self, from: Slot, to: Slot) {
        for (f, t) in [(from.rtp(), to.rtp()), (from.rtcp(), to.rtcp())] {
            if let Some(Some(l)) = self.legs.get_mut(f) {
                l.partner = t;
            }
            if let Some(c) = self.connected.get_mut(f) {
                *c = true;
            }
        }
    }

    /// The calls holding these slots leave the kernel fast path, which
    /// pairs a call's own legs.
    fn keep_in_userspace(&mut self, slots: &[Slot]) {
        for call in self
            .calls
            .iter()
            .filter(|(_, c)| slots.iter().any(|s| c.slots.contains(&s.rtp())))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
        {
            self.unoffload(call);
        }
    }

    /// Take `call` off the kernel fast path, if it is on it (or offered).
    fn unoffload(&mut self, call: CallId) {
        let Some(c) = self.calls.get_mut(&call) else {
            return;
        };
        if matches!(c.offload, OffloadState::Pending(_) | OffloadState::Active)
            && let Some(tx) = &self.offload
        {
            let _ = tx.send(OffloadMsg::Remove { call });
        }
        c.offload = OffloadState::No;
    }

    /// Before the leg of RTP slot `slot` is joined anew (keeping `keep`,
    /// its new partner here, if any): whoever still sends to it is
    /// detached (its call's other party, or the party it was connected to
    /// on this worker), and a connection it had to another worker is let
    /// go. Dropping that connection's channels makes the other worker
    /// detach its party at once: its next packet finds the channel gone.
    fn release(&mut self, slot: Slot, keep: Option<Slot>) {
        let slot = slot.rtp();
        let senders: Vec<Slot> = self
            .legs
            .slots()
            .filter(|(s, l)| {
                let s = s.rtp();
                s != slot && Some(s) != keep && l.as_ref().is_some_and(|l| l.partner.rtp() == slot)
            })
            .map(|(s, _)| s.rtp())
            .collect();
        for s in senders {
            self.pair_to(s, DETACHED);
        }
        for s in [slot, slot.rtcp()] {
            if let Some(r) = self.remote.get_mut(s) {
                *r = None;
            }
        }
        self.incoming.retain(|(_, to, _)| *to != Some(slot));
    }

    /// `connect` on this worker: the legs of RTP slots `x` and `y` are
    /// joined; their calls' other parties, and whoever either was
    /// connected to before, are detached.
    pub(super) fn connect_local(
        &mut self,
        x: Slot,
        y: Slot,
        transcode: [Option<crate::relay::Transcode>; 2],
    ) {
        let others = [self.other_party(x), self.other_party(y)];
        self.keep_in_userspace(&[x, y]);
        self.release(x, Some(y.rtp()));
        self.release(y, Some(x.rtp()));
        for other in others.into_iter().flatten().filter(|o| *o != x && *o != y) {
            self.pair_to(other, DETACHED);
        }
        self.pair_to(x, y);
        self.pair_to(y, x);
        self.set_transcode(x, transcode[0]);
        self.set_transcode(y, transcode[1]);
    }

    /// The leg of RTP slot `slot` is detached from whatever it was joined
    /// to (its call's other party, a party it was connected to here or on
    /// another worker): what it sends goes nowhere, and whoever sent to it
    /// is detached too. Its call stays; `connect` joins it again.
    pub(super) fn detach(&mut self, slot: Slot) {
        let local = slot.rtp();
        if self.legs.get(local).is_none_or(Option::is_none) {
            return;
        }
        self.keep_in_userspace(&[local]);
        self.release(local, None);
        self.pair_to(local, DETACHED);
        self.set_transcode(local, None);
    }

    /// The conversion of what the side of RTP slot `slot` sends.
    fn set_transcode(&mut self, slot: Slot, config: Option<crate::relay::Transcode>) {
        if let Some(t) = self.transcode.get_mut(slot.rtp()) {
            *t = config.and_then(crate::relay::transcode::Transcoder::new);
        }
    }

    /// `media echo` of a call whose legs' RTP slots are `slots`: each
    /// side's media goes to the other (`Normal`), back to itself (`Echo`;
    /// its RTCP is dropped), or nowhere (`Discard`).
    pub(super) fn echo(&mut self, slots: [Slot; 2], modes: [crate::relay::Echo; 2]) {
        use crate::relay::Echo;
        if slots
            .iter()
            .any(|&s| self.legs.get(s).is_none_or(Option::is_none))
        {
            return;
        }
        self.keep_in_userspace(&slots);
        for (k, &slot) in slots.iter().enumerate() {
            let other = slots[1 - k];
            let (rtp, rtcp) = match modes[k] {
                Echo::Normal => (other, other.rtcp()),
                Echo::Echo => (slot, DETACHED.rtcp()),
                Echo::Discard => (DETACHED, DETACHED.rtcp()),
            };
            if let Some(e) = self.echoing.get_mut(slot) {
                *e = modes[k] == Echo::Echo;
            }
            for (s, partner) in [(slot, rtp), (slot.rtcp(), rtcp)] {
                if let Some(Some(l)) = self.legs.get_mut(s) {
                    l.partner = partner;
                }
                if let Some(c) = self.connected.get_mut(s) {
                    *c = modes != [Echo::Normal; 2];
                }
            }
        }
    }

    /// `connect` across workers: this worker's end.
    pub(super) fn connect_remote(&mut self, end: RemoteEnd) {
        let local = end.local.rtp();
        if self.legs.get(local).is_none_or(Option::is_none) {
            return;
        }
        self.keep_in_userspace(&[local]);
        if let Some(other) = self.other_party(local).filter(|o| *o != local) {
            self.pair_to(other, DETACHED);
        }
        self.release(local, None);
        // Its own partner: the latch still learns, and nothing is sent here.
        self.pair_to(local, local);
        for (slot, peer) in [(local, end.peer.rtp()), (local.rtcp(), end.peer.rtcp())] {
            if let Some(r) = self.remote.get_mut(slot) {
                *r = Some(RemoteLeg {
                    tx: end.tx.clone(),
                    peer,
                    wake: Arc::clone(&end.peer_wake),
                    mine: Arc::clone(&end.mine),
                    theirs: Arc::clone(&end.theirs),
                });
            }
        }
        self.set_transcode(local, end.transcode);
        self.incoming.push((end.call, Some(local), end.rx));
    }

    /// The packet at `bufs[at..at + len]` from `leg`, when the leg is
    /// connected to another worker: passed there (true), or dropped when
    /// the channel is full or gone.
    pub(super) fn forward_remote(&mut self, leg: Slot, (at, len): (usize, usize)) -> bool {
        let Some(Some(r)) = self.remote.get(leg) else {
            return false;
        };
        let Some(src) = self.bufs.get(at..at + len).filter(|_| len <= FORWARD_MAX) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return true;
        };
        match r.tx.try_send(Forwarded::new(r.peer, src)) {
            Ok(()) => {
                if !self.wake_peers.iter().any(|w| Arc::ptr_eq(w, &r.wake)) {
                    self.wake_peers.push(Arc::clone(&r.wake));
                }
            }
            Err(TrySendError::Full(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // The other call ended: this party is left alone.
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                for s in [leg.rtp(), leg.rtcp()] {
                    if let Some(r) = self.remote.get_mut(s) {
                        *r = None;
                    }
                }
                self.pair_to(leg, DETACHED);
            }
        }
        true
    }

    /// The offload sweep's side of connections across workers: publish
    /// each connected leg's settled addresses for the other worker, and
    /// detach a leg whose other worker let go of the connection (its call
    /// ended), taking its call off the fast path.
    pub(super) fn sweep_remote(&mut self, now: u64) {
        let mut gone = Vec::new();
        for (slot, r) in self.remote.slots() {
            let Some(r) = r else { continue };
            if slot.is_rtcp() {
                continue;
            }
            // Each worker's RTP and RTCP legs hold the other's cell: only
            // this worker's two left, the other let go.
            if Arc::strong_count(&r.theirs) <= OWN_REFS {
                gone.push(slot);
                continue;
            }
            let local = self
                .sockets
                .get(slot)
                .and_then(Option::as_ref)
                .and_then(|s| s.local_addr().ok());
            let leg = self.legs.get(slot).copied().flatten();
            // Only a settled, plain leg (the kernel does no SRTP).
            let plain = self.crypto.get(slot).is_none_or(Option::is_none);
            let muxed = self.muxed.get(slot).copied().unwrap_or(false);
            let published = match (local, leg) {
                (Some(l), Some(leg)) if plain && leg.latch.settled(now) => {
                    leg.latch.target().map(|t| (l, t, muxed))
                }
                _ => None,
            };
            if let Ok(mut m) = r.mine.lock() {
                *m = published;
            }
        }
        for slot in gone {
            for s in [slot, slot.rtcp()] {
                if let Some(r) = self.remote.get_mut(s) {
                    *r = None;
                }
            }
            self.pair_to(slot, DETACHED);
            self.keep_in_userspace(&[slot]);
        }
    }

    /// The other side of a connection across workers, for the fast path:
    /// (its relay address, its settled peer), once published.
    pub(super) fn remote_target(&self, slot: Slot) -> Option<Published> {
        let r = self.remote.get(slot)?.as_ref()?;
        r.theirs.lock().ok().and_then(|t| *t)
    }

    /// Wake the workers this batch passed packets to.
    pub(super) fn wake_peers(&mut self) {
        for w in self.wake_peers.drain(..) {
            let _ = w.write(1);
        }
    }

    /// Send what other workers passed here, in batches.
    pub(super) fn drain_forwarded(&mut self) {
        let size = self.packet_buffer;
        let mut k = 0;
        while k < self.incoming.len() {
            let mut items = [(Slot::new(0), None::<SocketAddr>, 0usize, 0usize); MAX_BATCH];
            let mut n = 0;
            let mut gone = false;
            while n < MAX_BATCH {
                let f = match self.incoming[k].2.try_recv() {
                    Ok(f) => f,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        gone = true;
                        break;
                    }
                };
                let i = n;
                let len = usize::from(f.len);
                let Some(dst) = self
                    .legs
                    .get(f.slot)
                    .and_then(Option::as_ref)
                    .and_then(|l| l.latch.target())
                else {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                self.bufs[i * size..i * size + len].copy_from_slice(&f.data[..len]);
                match self.outbound(f.slot, i * size, len) {
                    (send_slot, Some(len)) => {
                        items[n] = (send_slot, Some(dst), i, len);
                        n += 1;
                    }
                    _ => {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            self.send_grouped(&items[..n]);
            if gone {
                self.incoming.swap_remove(k);
            } else {
                k += 1;
            }
        }
    }

    /// A call ends: what it was connected to is detached, and its ends of
    /// channels to other workers go (so they detach too).
    pub(super) fn disconnect_call(&mut self, call: CallId, slots: &[Slot]) {
        self.incoming.retain(|(c, _, _)| *c != call);
        for &s in slots {
            if let Some(r) = self.remote.get_mut(s) {
                *r = None;
            }
            if let Some(c) = self.connected.get_mut(s) {
                *c = false;
            }
            if let Some(e) = self.echoing.get_mut(s) {
                *e = false;
            }
            if let Some(t) = self.remote_taps.get_mut(s) {
                t.clear();
            }
        }
        let gone: Vec<Slot> = self
            .legs
            .slots()
            .filter(|(_, l)| l.as_ref().is_some_and(|l| slots.contains(&l.partner)))
            .map(|(s, _)| s)
            .collect();
        for &s in &gone {
            if let Some(Some(l)) = self.legs.get_mut(s) {
                l.partner = DETACHED;
            }
        }
        // Their calls' kernel flows sent to the ports that went.
        self.keep_in_userspace(&gone);
    }
}
