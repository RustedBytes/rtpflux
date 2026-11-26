//! The memory `io_uring` shares with the kernel: the provided buffers it
//! receives datagrams into, the buffer ring that hands them over, and the
//! `msghdr` template of the multishot receives. The one exception to the
//! workspace's `unsafe` ban in this crate (AGENTS.md §5); every `unsafe`
//! says why it is sound.
//!
//! - The buffers are one area, allocated here and never freed (the kernel
//!   may write into it until the ring is torn down, which happens in the
//!   background after its file closes), and never referenced as a whole:
//!   only a received buffer is read, as a slice made for that buffer, while
//!   the kernel owns it no more (it is not in the ring until it is given
//!   back). Who holds each buffer is tracked here, not trusted to the
//!   caller: a buffer is read only after the kernel handed it over
//!   ([`Buffers::take`]), and given back only once, so the ring never
//!   holds more than its `count` entries (a further one would overwrite
//!   an entry the kernel has yet to read).
//! - The buffer ring is page-aligned, allocated here and never freed, for
//!   the same reason. The kernel reads its entries and tail; this side
//!   writes an entry, then publishes the new tail with a release store.
//! - The `msghdr` template lives as long as the program, and only the
//!   two requests this crate makes are queued ([`push_recv`],
//!   [`push_cancel`]): nothing else can hand the kernel a pointer.
#![allow(unsafe_code)]

use io_uring::types::BufRingEntry;
use io_uring::{IoUring, opcode, squeue, types};
use std::alloc::{Layout, alloc_zeroed};
use std::io;
use std::os::fd::RawFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU16, Ordering};

/// Alignment the kernel wants of a buffer ring (a page).
const PAGE: usize = 4096;

/// A buffer ring entry (`struct io_uring_buf`), written field by field
/// through raw pointers: no reference to an entry is made, since the first
/// one's `resv` is the ring's tail, which the kernel reads concurrently.
#[repr(C)]
struct Entry {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
}
const _: () = assert!(size_of::<Entry>() == size_of::<BufRingEntry>());
const _: () = assert!(align_of::<Entry>() <= align_of::<BufRingEntry>());

/// The provided buffers and their ring.
pub(crate) struct Buffers {
    area: NonNull<u8>,
    ring: NonNull<BufRingEntry>,
    /// Buffers, a power of two; each `size` octets.
    count: u16,
    size: u32,
    /// The ring's tail as this side has written it.
    tail: u16,
    /// Bit `bid` set: buffer `bid` is out of the ring (the kernel handed it
    /// over and it was not given back yet).
    out: Vec<u64>,
}

// SAFETY: the area and the ring are plain memory owned by this value (and
// the kernel); nothing ties them to a thread.
unsafe impl Send for Buffers {}

impl Buffers {
    /// `count` buffers (a power of two, at most 32768) of `size` octets,
    /// all in the ring.
    pub(crate) fn new(count: u16, size: u32) -> io::Result<Self> {
        let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_owned());
        if count == 0 || !count.is_power_of_two() || count > 32_768 || size == 0 {
            return Err(bad(
                "buffers: a power of two up to 32768, of a size above 0",
            ));
        }
        let area_len = usize::from(count)
            .checked_mul(usize::try_from(size).map_err(|_| bad("buffer size"))?)
            .ok_or_else(|| bad("buffers too large"))?;
        let area_layout = Layout::from_size_align(area_len, PAGE).map_err(|_| bad("buffers"))?;
        let ring_len = usize::from(count)
            .checked_mul(size_of::<BufRingEntry>())
            .ok_or_else(|| bad("buffers too many"))?;
        let ring_layout = Layout::from_size_align(ring_len, PAGE).map_err(|_| bad("ring"))?;
        // SAFETY: both layouts have a non-zero size (count and size are
        // above 0).
        let area = NonNull::new(unsafe { alloc_zeroed(area_layout) })
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        // SAFETY: as above.
        let ring = NonNull::new(unsafe { alloc_zeroed(ring_layout) })
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?
            .cast::<BufRingEntry>();
        let mut b = Buffers {
            area,
            ring,
            count,
            size,
            tail: 0,
            out: vec![0; usize::from(count).div_ceil(64)],
        };
        for bid in 0..count {
            b.put(bid);
        }
        b.publish();
        Ok(b)
    }

    /// The ring's address, to register.
    pub(crate) fn ring_addr(&self) -> u64 {
        self.ring.as_ptr() as u64
    }

    pub(crate) fn count(&self) -> u16 {
        self.count
    }

    /// The ring's tail as written here (for tests).
    #[cfg(test)]
    pub(crate) fn tail(&self) -> u16 {
        self.tail
    }

    /// Where buffer `bid`'s bit is (`None` out of range).
    fn bit(&self, bid: u16) -> Option<(usize, u64)> {
        (bid < self.count).then(|| (usize::from(bid / 64), 1u64 << (bid % 64)))
    }

    fn is_out(&self, bid: u16) -> bool {
        self.bit(bid)
            .is_some_and(|(w, m)| self.out.get(w).is_some_and(|x| x & m != 0))
    }

    fn mark(&mut self, bid: u16, out: bool) {
        if let Some((w, m)) = self.bit(bid)
            && let Some(x) = self.out.get_mut(w)
        {
            *x = if out { *x | m } else { *x & !m };
        }
    }

    /// The kernel handed buffer `bid` over (a completion says so): it may
    /// be read, and must be given back. False for a buffer out of range.
    pub(crate) fn take(&mut self, bid: u16) -> bool {
        if bid >= self.count {
            return false;
        }
        self.mark(bid, true);
        true
    }

    /// Give buffer `bid` back to the ring (seen by the kernel once
    /// published). Only a buffer the kernel handed over goes back, once:
    /// anything else is ignored.
    pub(crate) fn give(&mut self, bid: u16) {
        if self.is_out(bid) {
            self.mark(bid, false);
            self.put(bid);
        }
    }

    /// Write buffer `bid` at the ring's tail. Each buffer is in the ring at
    /// most once (`new` puts each in once; `give` only one that is out), so
    /// at most `count` entries are unconsumed and the tail's entry is free.
    fn put(&mut self, bid: u16) {
        if bid >= self.count {
            return;
        }
        let index = usize::from(self.tail & (self.count - 1));
        let offset = usize::from(bid) * self.size as usize;
        // In bounds: `index` < count entries.
        let entry = self.ring.as_ptr().wrapping_add(index).cast::<Entry>();
        let addr = self.area.as_ptr().wrapping_add(offset) as u64;
        // The fields, by offset (no place through the pointer is formed).
        let field = |at: usize| entry.wrapping_byte_add(at);
        let addr_at = field(core::mem::offset_of!(Entry, addr)).cast::<u64>();
        let len_at = field(core::mem::offset_of!(Entry, len)).cast::<u32>();
        let bid_at = field(core::mem::offset_of!(Entry, bid)).cast::<u16>();
        // SAFETY: `entry` is one of the ring's `count` entries (allocated,
        // aligned, never freed), which this side may write: the kernel
        // reads only entries below the published tail, and this one is at
        // the (unpublished) tail. Each field is written alone, aligned (an
        // entry is 16-aligned), and no reference to the entry is made: its
        // `resv` may be the tail the kernel reads.
        unsafe { addr_at.write(addr) };
        // SAFETY: as above.
        unsafe { len_at.write(self.size) };
        // SAFETY: as above.
        unsafe { bid_at.write(bid) };
        self.tail = self.tail.wrapping_add(1);
    }

    /// Show the kernel the buffers given since the last call.
    pub(crate) fn publish(&self) {
        // SAFETY: the ring's first entry is initialised (zeroed, then
        // written by `give`); its `resv` field is the ring's tail.
        let tail = unsafe { BufRingEntry::tail(self.ring.as_ptr()) };
        // SAFETY: the tail is a properly aligned u16 inside the ring, which
        // lives forever; the kernel reads it concurrently, so it is written
        // atomically (with release ordering, after the entries).
        let tail = unsafe { AtomicU16::from_ptr(tail.cast_mut()) };
        tail.store(self.tail, Ordering::Release);
    }

    /// The `len` octets the kernel put in buffer `bid` (taken, and not
    /// given back yet); `None` for a buffer still in the ring, or a buffer
    /// or length out of range.
    pub(crate) fn received(&self, bid: u16, len: usize) -> Option<&[u8]> {
        if !self.is_out(bid) || len > self.size as usize {
            return None;
        }
        let first = self
            .area
            .as_ptr()
            .wrapping_add(usize::from(bid) * self.size as usize);
        // SAFETY: `[first, first + len)` lies inside the area (bid < count,
        // len <= size). The buffer is out of the ring (checked above): the
        // kernel does not write it until it is given back, which needs
        // `&mut self`, so not while the slice is borrowed.
        Some(unsafe { core::slice::from_raw_parts(first, len) })
    }
}

/// The `msghdr` of multishot receives: room for an IPv4 or IPv6 source
/// address, no control data, no pointers. Made only here, so that a
/// receive never carries a pointer the kernel could outlive.
#[derive(Clone, Copy)]
pub(crate) struct MsgHdr(&'static libc::msghdr);

impl MsgHdr {
    /// A new one; it lives as long as the program.
    pub(crate) fn new() -> Self {
        // SAFETY: an all-zero `msghdr` is valid (null pointers, zero
        // lengths).
        let mut m: libc::msghdr = unsafe { core::mem::zeroed() };
        m.msg_namelen = u32::try_from(size_of::<libc::sockaddr_storage>()).unwrap_or(128);
        MsgHdr(Box::leak(Box::new(m)))
    }

    pub(crate) fn get(self) -> &'static libc::msghdr {
        self.0
    }
}

fn push(ring: &mut IoUring, entry: &squeue::Entry) -> io::Result<()> {
    // SAFETY: the two entries queued here point at nothing (a cancel) or
    // at a `MsgHdr`, which lives as long as the program and points at
    // nothing; the buffers are the registered group's, never freed. So the
    // kernel never reads freed memory, whenever it runs the entry.
    unsafe { ring.submission().push(entry) }
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "submission queue full"))
}

/// Queue a multishot receive on `fd` into buffer group `group`, its
/// completions carrying `token`.
pub(crate) fn push_recv(
    ring: &mut IoUring,
    fd: RawFd,
    msghdr: MsgHdr,
    group: u16,
    token: u64,
) -> io::Result<()> {
    let entry = opcode::RecvMsgMulti::new(types::Fd(fd), msghdr.get(), group)
        .build()
        .user_data(token);
    push(ring, &entry)
}

/// Queue the cancellation of the requests carrying `token`, its own
/// completion carrying `user_data`.
pub(crate) fn push_cancel(ring: &mut IoUring, token: u64, user_data: u64) -> io::Result<()> {
    let entry = opcode::AsyncCancel2::new(types::CancelBuilder::user_data(token).all())
        .build()
        .user_data(user_data);
    push(ring, &entry)
}

/// Register `buffers`' ring with `ring` as buffer group `group`.
pub(crate) fn register(ring: &IoUring, buffers: &Buffers, group: u16) -> io::Result<()> {
    // SAFETY: the ring memory is page-aligned, `count` entries long and
    // lives as long as the program (it is never freed).
    unsafe {
        ring.submitter().register_buf_ring_with_flags(
            buffers.ring_addr(),
            buffers.count(),
            group,
            0,
        )
    }
}
