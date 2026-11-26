//! `runtime.receive = "io_uring"`: the worker's sockets receive through one
//! `io_uring` multishot receiver ([`rtpflux_uring::Receiver`]) instead of
//! epoll and `recvmmsg` per socket. Its completions wake the worker through
//! epoll (the ring's file); each datagram is copied into the batch buffers,
//! and runs of one slot go through [`Worker::relay_batch`], as the `AF_XDP`
//! datagrams do. A slot's token carries a generation, so what a closed
//! socket still completes never reaches the slot's next call.

use super::{MAX_BATCH, Slot, URING, Worker};
use nix::sys::epoll::{Epoll, EpollEvent, EpollFlags};
use std::net::SocketAddr;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::Ordering;

/// Submission entries of a worker's ring (arming, re-arming, cancelling).
const ENTRIES: u32 = 1_024;

/// A worker's receiver of `buffers` buffers for datagrams of
/// `packet_buffer` octets, its completions in `epoll`; `None` (and the
/// worker uses `recvmmsg`) when the kernel cannot.
pub(super) fn receiver(
    index: usize,
    buffers: u16,
    packet_buffer: usize,
    epoll: &Epoll,
) -> Result<rtpflux_uring::Receiver, String> {
    let size = u32::try_from(packet_buffer)
        .ok()
        .and_then(|s| s.checked_add(rtpflux_uring::OVERHEAD))
        .ok_or_else(|| "packet buffer too large".to_owned())?;
    let fallback = |e: &dyn std::fmt::Display| {
        log::warn!("media worker {index}: io_uring: {e}; using recvmmsg");
        e.to_string()
    };
    let r = rtpflux_uring::Receiver::new(ENTRIES, buffers, size).map_err(|e| fallback(&e))?;
    // The ring's file lives as long as the receiver, which the worker
    // keeps as long as its epoll set.
    epoll
        .add(r.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN, URING))
        .map_err(|e| fallback(&e))?;
    log::info!("media worker {index}: receiving with io_uring");
    Ok(r)
}

impl Worker {
    /// Receive on `socket` (of `slot`) through the `io_uring` receiver;
    /// false when there is none (epoll then).
    pub(super) fn uring_arm(&mut self, slot: Slot, socket: BorrowedFd<'_>) -> bool {
        let Some(r) = self.uring.as_mut() else {
            return false;
        };
        let Some(generation) = self.uring_gen.get_mut(slot) else {
            return false;
        };
        *generation = generation.wrapping_add(1);
        let token = (u64::from(*generation) << 32) | u64::from(slot.get());
        match r.arm(socket, token) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("media worker {}: io_uring arm: {e}; epoll", self.index);
                false
            }
        }
    }

    /// Stop receiving for `slot` (its socket closes).
    pub(super) fn uring_disarm(&mut self, slot: Slot) {
        let Some(&generation) = self.uring_gen.get(slot) else {
            return;
        };
        let token = (u64::from(generation) << 32) | u64::from(slot.get());
        match self.uring.as_mut() {
            Some(r) => {
                if let Err(e) = r.disarm(token) {
                    log::warn!("media worker {}: io_uring disarm: {e}", self.index);
                }
            }
            // Draining: once the receiver is back.
            None => self.uring_disarm.push(token),
        }
    }

    /// Relay what the receiver completed, in runs of one slot.
    pub(super) fn drain_uring(&mut self, now: u64) {
        let Some(mut r) = self.uring.take() else {
            return;
        };
        let size = self.packet_buffer;
        let mut meta: [Option<(usize, SocketAddr)>; MAX_BATCH] = [None; MAX_BATCH];
        let mut n = 0;
        let mut run: Option<Slot> = None;
        r.complete(|token, d| {
            let slot = Slot::new(u32::try_from(token & u64::from(u32::MAX)).unwrap_or(u32::MAX));
            let generation = u32::try_from(token >> 32).unwrap_or(0);
            // A socket closed since (its slot taken again): dropped.
            if self.uring_gen.get(slot) != Some(&generation) {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if run.is_some_and(|s| s != slot) || n == self.batch {
                if let Some(s) = run {
                    self.relay_run(s, &meta[..n], now);
                }
                n = 0;
            }
            run = Some(slot);
            let len = d.payload.len();
            let (Some(src), false) = (d.source, d.truncated || len > size) else {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if let Some(buf) = self.bufs.get_mut(n * size..n * size + len) {
                buf.copy_from_slice(d.payload);
                meta[n] = Some((len, src));
                n += 1;
            }
        });
        if let Some(s) = run {
            self.relay_run(s, &meta[..n], now);
        }
        for token in self.uring_disarm.drain(..) {
            if let Err(e) = r.disarm(token) {
                log::warn!("media worker {}: io_uring disarm: {e}", self.index);
            }
        }
        self.uring = Some(r);
    }
}
