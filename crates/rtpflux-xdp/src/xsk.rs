//! `AF_XDP` receive sockets: the steered datagrams of one device queue
//! (`RTPFLUX_XSKS`), read without the kernel's UDP receive path.
//!
//! The second exception to the workspace's `unsafe` ban (AGENTS.md §5),
//! with `pod`. An `AF_XDP` socket shares a memory area (the UMEM) with the
//! kernel, which writes received frames into it. xdpilone sets up the
//! socket and its rings; this module owns the memory and is the only code
//! that reads frames out of it. Every `unsafe` block says why it is sound.
//!
//! Lifecycle: a receiver lives as long as the relay; its memory is never
//! freed (see [`XskReceiver::open`]).
#![allow(unsafe_code)]

use core::num::NonZeroU32;
use core::ptr::NonNull;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use xdpilone::{DeviceQueue, IfInfo, RingRx, Socket, SocketConfig, Umem, UmemConfig, User};

/// Size of one frame in the memory area (the kernel's default).
pub const FRAME_SIZE: u32 = 4096;
/// Alignment of the memory area: the largest Linux page size (64 KiB), so
/// the area is page-aligned whatever the page size.
const AREA_ALIGN: usize = 1 << 16;
/// Frames received per call of [`XskReceiver::receive`], at most.
pub const BATCH: usize = 64;
const BATCH_U32: u32 = 64;
const _: () = assert!(BATCH_U32 as usize == BATCH);

fn errno(e: &xdpilone::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.get_raw())
}

/// One `AF_XDP` socket receiving on one queue of one device.
///
/// Field order is drop order: the rings and sockets go before the area
/// they refer to (which is never freed anyway).
pub struct XskReceiver {
    rx: RingRx,
    fill: DeviceQueue,
    user: User,
    _umem: Umem,
    /// The memory area: `frames * FRAME_SIZE` octets, page-aligned.
    area: NonNull<u8>,
    area_len: usize,
    fd: RawFd,
    /// Frames that found no room on the fill ring (never expected).
    lost: u64,
}

// SAFETY: the receiver exclusively owns its rings and area; nothing in it
// is tied to the thread that created it (raw pointers to memory shared
// only with the kernel). It is moved once, to its receive thread.
unsafe impl Send for XskReceiver {}

impl XskReceiver {
    /// Open a socket on queue `queue` of device `ifindex` with `frames`
    /// frames, all handed to the kernel to fill. Needs `CAP_NET_RAW` (in
    /// practice root) and an XDP program on the device that redirects to it
    /// (`FastPath::set_socket`).
    ///
    /// The memory area is leaked: the kernel may keep writing into it until
    /// the socket is torn down, which completes after the descriptors are
    /// closed. A relay opens one receiver per queue, once.
    ///
    /// # Errors
    ///
    /// The kernel's error when the device or queue does not exist, `AF_XDP`
    /// is unsupported or not permitted.
    pub fn open(ifindex: u32, queue: u32, frames: u32) -> io::Result<Self> {
        let frames = frames
            .max(2)
            .checked_next_power_of_two()
            .ok_or_else(|| io::Error::other("too many frames"))?;
        let area_len = usize::try_from(u64::from(frames) * u64::from(FRAME_SIZE))
            .map_err(|_| io::Error::other("too many frames"))?;
        let layout =
            std::alloc::Layout::from_size_align(area_len, AREA_ALIGN).map_err(io::Error::other)?;
        // SAFETY: `layout` has a non-zero size (at least two frames).
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let area = NonNull::new(raw).ok_or_else(|| io::Error::other("out of memory"))?;
        let region = NonNull::slice_from_raw_parts(area, area_len);
        let config = UmemConfig {
            fill_size: frames,
            complete_size: frames,
            frame_size: FRAME_SIZE,
            headroom: 0,
            flags: 0,
        };
        // SAFETY: `region` is a fresh, zeroed allocation of `area_len`
        // octets, page-aligned (`AREA_ALIGN` is a multiple of every page
        // size), that is never freed or otherwise used: it stays valid for as long as the kernel
        // may access it, as `Umem::new` requires. Frames are read only by
        // `receive`, for descriptors the kernel handed back.
        let umem = unsafe { Umem::new(config, region) }.map_err(|e| errno(&e))?;
        let mut info = IfInfo::invalid();
        info.from_ifindex(ifindex).map_err(|e| errno(&e))?;
        info.set_queue(queue);
        let socket = Socket::with_shared(&info, &umem).map_err(|e| errno(&e))?;
        let mut fill = umem.fq_cq(&socket).map_err(|e| errno(&e))?;
        let user = umem
            .rx_tx(
                &socket,
                &SocketConfig {
                    rx_size: NonZeroU32::new(frames),
                    tx_size: None,
                    bind_flags: SocketConfig::XDP_BIND_NEED_WAKEUP,
                },
            )
            .map_err(|e| errno(&e))?;
        let rx = user.map_rx().map_err(|e| errno(&e))?;
        umem.bind(&user).map_err(|e| errno(&e))?;
        // Every frame to the kernel, to receive into.
        let mut w = fill.fill(frames);
        w.insert((0..u64::from(frames)).map(|i| i * u64::from(FRAME_SIZE)));
        w.commit();
        drop(w);
        let fd = user.as_raw_fd();
        Ok(XskReceiver {
            rx,
            fill,
            user,
            _umem: umem,
            area,
            area_len,
            fd,
            lost: 0,
        })
    }

    /// Hand each received frame (up to [`BATCH`]) to `f`, then give the
    /// frames back to the kernel. Returns how many there were.
    pub fn receive(&mut self, mut f: impl FnMut(&[u8])) -> usize {
        let mut addrs = [0u64; BATCH];
        let mut n = 0;
        {
            let mut rx = self.rx.receive(BATCH_U32);
            while let Some(desc) = rx.read() {
                let start = usize::try_from(desc.addr).unwrap_or(usize::MAX);
                let len = desc.len as usize;
                // Inside the area, and inside its own frame: a bad
                // descriptor never reaches a neighbour the kernel owns.
                let in_frame = (start % FRAME_SIZE as usize)
                    .checked_add(len)
                    .is_some_and(|end| end <= FRAME_SIZE as usize);
                if in_frame
                    && start
                        .checked_add(len)
                        .is_some_and(|end| end <= self.area_len)
                {
                    // In bounds (checked above), so no wrapping happens.
                    let first = self.area.as_ptr().wrapping_add(start);
                    // SAFETY: `[start, start + len)` lies inside the area
                    // and inside one frame (checked above). The kernel gave this frame to us on
                    // the RX ring and does not write it again until it is
                    // back on the fill ring, after `f` returns; the slice
                    // does not outlive this iteration.
                    let frame = unsafe { core::slice::from_raw_parts(first, len) };
                    f(frame);
                }
                // Back to the start of its frame.
                addrs[n] = desc.addr - desc.addr % u64::from(FRAME_SIZE);
                n += 1;
                if n == BATCH {
                    break;
                }
            }
            rx.release();
        }
        // Every frame goes back. A reservation can come back short: the
        // ring's cached view of the kernel is refreshed only once it
        // shows no room. The next one refreshes it; the fill ring holds
        // all the frames, so then there is room for the rest.
        let fill = &mut self.fill;
        let lost = give_back(addrs.get(..n).unwrap_or_default(), |batch| {
            let mut w = fill.fill(u32::try_from(batch.len()).unwrap_or(BATCH_U32));
            let put = w.insert(batch.iter().copied());
            w.commit();
            put as usize
        });
        self.lost = self.lost.saturating_add(lost as u64);
        if self.fill.needs_wakeup() {
            self.fill.wake();
        }
        n
    }

    /// Frames the kernel dropped for want of room, from its statistics,
    /// and any the fill ring had no room for.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.user
            .statistics_v2()
            .map_or(0, |s| s.rx_dropped + s.rx_ring_full)
            .saturating_add(self.lost)
    }
}

/// Hand `addrs` back with `put`, which puts what it can of a batch on the
/// fill ring and says how many; again with the rest until all are back.
/// Returns how many found no room at all (`put` gave 0), which ends the
/// loop: never a busy one.
fn give_back(addrs: &[u64], mut put: impl FnMut(&[u64]) -> usize) -> usize {
    let mut rest = addrs;
    while !rest.is_empty() {
        let done = put(rest);
        match rest.get(done..) {
            Some(r) if done > 0 => rest = r,
            _ => return rest.len(),
        }
    }
    0
}

impl AsFd for XskReceiver {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: `fd` is the socket held open by `self.user` (and the
        // rings) for as long as `self` lives, which bounds the borrow.
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl AsRawFd for XskReceiver {
    /// The socket, to poll for received frames and to register in
    /// `RTPFLUX_XSKS`.
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(test)]
mod tests {
    use super::give_back;

    /// A fill ring like xdpilone's: a reservation counts the free slots
    /// from a cached view of the kernel's consumer, refreshed only when
    /// that view shows none free, so it can grant fewer than asked while
    /// the ring has room.
    struct Ring {
        size: u32,
        producer: u32,
        consumer: u32,
        cached_consumer: u32,
        queued: Vec<u64>,
    }

    impl Ring {
        fn put(&mut self, batch: &[u64]) -> usize {
            let mut free = self.cached_consumer.wrapping_sub(self.producer);
            if free < 1 {
                self.cached_consumer = self.consumer.wrapping_add(self.size);
                free = self.cached_consumer.wrapping_sub(self.producer);
            }
            let n = (free as usize).min(batch.len());
            self.queued.extend_from_slice(&batch[..n]);
            self.producer = self.producer.wrapping_add(u32::try_from(n).unwrap());
            n
        }

        /// The kernel takes `n` frames off the ring (to receive into).
        fn take(&mut self, n: usize) -> Vec<u64> {
            self.consumer = self.consumer.wrapping_add(u32::try_from(n).unwrap());
            self.queued.drain(..n).collect()
        }
    }

    /// Frames received in uneven batches all go back, round after round,
    /// while the kernel takes frames off the fill ring ahead of receiving
    /// into them (as zero-copy drivers do): no frame is lost to a short
    /// reservation (each would starve the ring for good).
    #[test]
    fn every_frame_goes_back_after_short_reservations() {
        let frames = 8u32;
        let mut ring = Ring {
            size: frames,
            producer: 0,
            consumer: 0,
            cached_consumer: frames,
            queued: Vec::new(),
        };
        let all: Vec<u64> = (0..u64::from(frames)).map(|i| i * 4096).collect();
        assert_eq!(give_back(&all, |b| ring.put(b)), 0);
        // Frames the kernel holds (taken, not yet received into).
        let mut held: Vec<u64> = Vec::new();
        let mut short = 0;
        for round in 0..1000usize {
            // The kernel takes some frames ahead, then completes some.
            let ahead = (round * 5 % 4).min(ring.queued.len());
            held.extend(ring.take(ahead));
            if held.is_empty() {
                held.extend(ring.take(1));
            }
            let n = 1 + round * 7 % held.len();
            let received: Vec<u64> = held.drain(..n).collect();
            let mut calls = 0;
            let lost = give_back(&received, |b| {
                calls += 1;
                ring.put(b)
            });
            assert_eq!(lost, 0, "round {round}");
            short += usize::from(calls > 1);
            assert_eq!(
                ring.queued.len() + held.len(),
                frames as usize,
                "round {round}: every frame is on the ring or the kernel's"
            );
        }
        assert!(short > 0, "short reservations happened");
        let mut back: Vec<u64> = ring.queued.iter().chain(&held).copied().collect();
        back.sort_unstable();
        assert_eq!(back, all, "the same frames, each once");
    }

    /// No room at all: what is left is counted, and the loop ends.
    #[test]
    fn no_room_ends_the_loop() {
        assert_eq!(give_back(&[1, 2, 3], |_| 0), 3);
        assert_eq!(give_back(&[1, 2, 3], |b| b.len().min(2).min(1)), 0);
    }
}
