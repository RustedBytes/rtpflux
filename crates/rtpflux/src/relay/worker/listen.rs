//! `connect` with `directional`: what a party sends also goes, as a copy,
//! to another party, which keeps its own media (it hears both). On one
//! worker the source leg is tapped to the listener's leg ([`Taps::listen`]);
//! across workers the source's worker passes each copy to the listener's
//! through a bounded channel, as `connect` does, whose worker sends it out
//! of the listener's leg (encrypted for it, from the relay port it knows).
//! Copies are taken as packets arrive (decrypted, before blocking or the
//! source's own transcoding), and converted to the listener's codec when
//! it differs: by a transcoder of each (source, listener) pair, made when
//! the copy is set up, in the spare buffer. A source with copies stays in
//! userspace.
//!
//! [`Taps::listen`]: crate::relay::taps::Taps::listen

use super::connect::{FORWARD_MAX, Forwarded};
use super::{Slot, Worker};
use crate::relay::CallId;
use crate::relay::transcode::Transcoder;
use nix::sys::eventfd::EventFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};

/// Where a source leg's copies go on another worker.
#[derive(Debug)]
pub(super) struct RemoteTap {
    tx: SyncSender<Forwarded>,
    /// The listener's worker and RTP slot there.
    worker: usize,
    peer: Slot,
    wake: Arc<EventFd>,
    /// Converting the copies to the listener's codec.
    xcode: Option<Box<Transcoder>>,
}

/// A copy to another worker, as installed in the source's worker.
pub struct RemoteListen {
    /// The source's RTP slot here.
    pub source: Slot,
    /// The listener's worker and RTP slot there.
    pub worker: usize,
    pub peer: Slot,
    pub tx: SyncSender<Forwarded>,
    pub wake: Arc<EventFd>,
    /// Converting the copies to the listener's codec.
    pub transcode: Option<crate::relay::Transcode>,
}

/// The listener's end of a copy from another worker.
pub struct ListenEnd {
    /// The listener's call (its end goes with it).
    pub call: CallId,
    pub rx: Receiver<Forwarded>,
}

impl Worker {
    /// Copy (`on`) or stop copying what the leg of RTP slot `source`
    /// sends to the leg of RTP slot `dest`, both on this worker.
    pub(super) fn listen_local(
        &mut self,
        source: Slot,
        dest: Slot,
        on: bool,
        transcode: Option<crate::relay::Transcode>,
    ) {
        if [source, dest]
            .iter()
            .any(|&s| self.legs.get(s).is_none_or(Option::is_none))
        {
            return;
        }
        if !self.taps.listen(&[(source.get(), dest.get())], on) {
            log::warn!("slot {source:?}: not copied to {dest:?}");
            return;
        }
        if let Some(list) = self.copy_xcode.get_mut(source) {
            list.retain(|(d, _)| *d != dest);
            if let Some(t) = transcode.filter(|_| on).and_then(Transcoder::new) {
                list.push((dest, Box::new(t)));
            }
        }
        if let Some(call) = self.call_of(source) {
            self.refresh_offload(call);
        }
    }

    /// Copy what the leg of `l.source` sends to a leg on another worker.
    pub(super) fn listen_remote(&mut self, l: RemoteListen) {
        if self.legs.get(l.source).is_none_or(Option::is_none) {
            return;
        }
        let Some(list) = self.remote_taps.get_mut(l.source) else {
            return;
        };
        list.retain(|t| (t.worker, t.peer) != (l.worker, l.peer));
        list.push(RemoteTap {
            tx: l.tx,
            worker: l.worker,
            peer: l.peer,
            wake: l.wake,
            xcode: l.transcode.and_then(Transcoder::new).map(Box::new),
        });
        if let Some(call) = self.call_of(l.source) {
            self.refresh_offload(call);
        }
    }

    /// Stop copying what the leg of `source` sends to slot `peer` of
    /// worker `worker` (its end of the channel goes).
    pub(super) fn unlisten_remote(&mut self, source: Slot, worker: usize, peer: Slot) {
        if let Some(list) = self.remote_taps.get_mut(source) {
            list.retain(|t| (t.worker, t.peer) != (worker, peer));
        }
    }

    /// Whether the leg of `slot` has copies on other workers.
    pub(super) fn copied_remote(&self, slot: Slot) -> bool {
        self.remote_taps.get(slot).is_some_and(|l| !l.is_empty())
    }

    /// Pass the packet at `bufs[at..at + len]`, accepted from `leg`, to the
    /// listeners on other workers. A full channel drops the copy; a
    /// listener whose call ended (its end gone) is dropped from the list.
    pub(super) fn copy_to_remote(&mut self, leg: Slot, (at, len): (usize, usize)) {
        // Each copy is made in the spare buffer (converted there).
        let (scratch, size) = (self.batch * self.packet_buffer, self.packet_buffer);
        let Worker {
            remote_taps,
            bufs,
            wake_peers,
            stats,
            ..
        } = self;
        let Some(list) = remote_taps.get_mut(leg) else {
            return;
        };
        if len > FORWARD_MAX || at + len > bufs.len() {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        list.retain_mut(|t| {
            bufs.copy_within(at..at + len, scratch);
            let n = match t.xcode.as_mut() {
                Some(x) => match x.packet(&mut bufs[scratch..scratch + size], len) {
                    Some(n) if n <= FORWARD_MAX => n,
                    _ => {
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                },
                None => len,
            };
            match t
                .tx
                .try_send(Forwarded::new(t.peer, &bufs[scratch..scratch + n]))
            {
                Ok(()) => {
                    if !wake_peers.iter().any(|w| Arc::ptr_eq(w, &t.wake)) {
                        wake_peers.push(Arc::clone(&t.wake));
                    }
                    true
                }
                Err(TrySendError::Full(_)) => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
    }

    /// The listener's end of a copy from another worker.
    pub(super) fn listen_incoming(&mut self, end: ListenEnd) {
        if self.calls.contains_key(&end.call) {
            self.incoming.push((end.call, None, end.rx));
        }
    }
}
