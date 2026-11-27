//! A fixed-capacity jitter buffer: RTP packets in, in sequence order and on
//! time out, with the gaps reported for concealment.
//!
//! Sequence numbers are extended to 64 bits as RFC 3550 A.1 does (the
//! 16-bit number nearest the highest one seen), so the 65535 → 0 wrap is
//! ordinary ordering. The buffer holds the window of `N` sequence numbers
//! from the next one to play; each packet goes to slot `ext_seq mod N`
//! with a copy of its payload (at most [`MAX_PAYLOAD`] bytes).
//!
//! # Time
//!
//! There is no clock inside. The caller calls [`JitterBuffer::pop`] once
//! per frame with its own playout clock in RTP timestamp units (e.g. +160
//! per 20 ms at 8 kHz). The first `pop` that finds a packet maps that
//! clock reading to the packet's timestamp (the playout origin); from then
//! on a packet with timestamp `ts` is due once
//! `clock − origin_clock ≥ ts − origin_ts + delay`, where `delay` is the
//! target delay set by [`JitterBuffer::set_delay`] (timestamp units). The
//! first packet thus plays `delay` after the first `pop` that saw it.
//!
//! A packet whose sequence number is behind the next one to play is
//! [`PushOutcome::TooLate`]: latency is bounded by the delay and `N`. A
//! missing packet is reported as [`Pop::Missing`] when a later packet is
//! present and the missing one's timestamp (interpolated between the last
//! packet played and that later one) is due; the caller then conceals.

/// The largest payload a slot holds, in bytes.
pub const MAX_PAYLOAD: usize = 1500;

/// What [`JitterBuffer::push`] did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// Stored for playout.
    Stored,
    /// Already stored: dropped.
    Duplicate,
    /// Behind the playout point (already played or given up as lost):
    /// dropped.
    TooLate,
    /// `N` or more sequence numbers ahead of the next one to play: dropped.
    /// Two such packets in a row, in sequence, restart the buffer at the
    /// second one (the stream jumped, or the reader stalled).
    Overflow,
    /// Payload longer than [`MAX_PAYLOAD`]: dropped.
    Oversized,
}

/// What [`JitterBuffer::pop`] gives for the current playout time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop<'a> {
    /// The next packet, due now.
    Packet {
        /// RTP sequence number.
        seq: u16,
        /// RTP timestamp.
        ts: u32,
        /// RTP marker bit.
        marker: bool,
        /// The payload, borrowed from the buffer until the next call.
        payload: &'a [u8],
    },
    /// The packet with this sequence number is due but missing: conceal
    /// one packet's worth of audio.
    Missing {
        /// RTP sequence number of the missing packet.
        seq: u16,
    },
    /// Nothing is due yet (or the buffer ran dry).
    Empty,
}

/// Counters, cumulative across [`JitterBuffer::reset`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets stored.
    pub stored: u64,
    /// Duplicates dropped.
    pub duplicates: u64,
    /// Late packets dropped.
    pub late: u64,
    /// Packets dropped for being too far ahead, or still buffered when an
    /// overflow restarted the buffer.
    pub overflow: u64,
    /// Oversized payloads dropped.
    pub oversized: u64,
    /// Packets reported [`Pop::Missing`].
    pub lost: u64,
    /// Packets buffered now.
    pub depth: usize,
}

/// One packet's slot.
#[derive(Debug, Clone, Copy)]
struct Slot {
    used: bool,
    marker: bool,
    len: u16,
    ts: u32,
    ext: u64,
    payload: [u8; MAX_PAYLOAD],
}

impl Slot {
    const EMPTY: Slot = Slot {
        used: false,
        marker: false,
        len: 0,
        ts: 0,
        ext: 0,
        payload: [0; MAX_PAYLOAD],
    };
}

/// A jitter buffer of `N` packets (`N` a power of two); about
/// `N` × 1.5 KiB, so keep it in a session's state, not on a small stack.
#[derive(Debug, Clone)]
pub struct JitterBuffer<const N: usize> {
    slots: [Slot; N],
    /// Highest extended sequence number seen (valid when `seen`).
    max_ext: u64,
    seen: bool,
    /// Next extended sequence number to play.
    next: u64,
    /// Playout origin: (clock, timestamp), once the first `pop` found a
    /// packet.
    origin: Option<(u32, u32)>,
    /// The last packet played: (extended sequence number, timestamp).
    last: Option<(u64, u32)>,
    /// Extended sequence number expected after an overflow, to confirm a
    /// jump.
    probation: Option<u64>,
    delay: u32,
    depth: usize,
    stats: Stats,
}

impl<const N: usize> JitterBuffer<N> {
    const MASK: usize = {
        assert!(
            N.is_power_of_two(),
            "JitterBuffer capacity must be a power of two"
        );
        assert!(N <= 32768, "JitterBuffer capacity must be at most 32768");
        N - 1
    };

    /// An empty buffer with a target delay of `delay` timestamp units.
    #[must_use]
    pub const fn new(delay: u32) -> Self {
        let _ = Self::MASK;
        JitterBuffer {
            slots: [Slot::EMPTY; N],
            max_ext: 0,
            seen: false,
            next: 0,
            origin: None,
            last: None,
            probation: None,
            delay,
            depth: 0,
            stats: Stats {
                stored: 0,
                duplicates: 0,
                late: 0,
                overflow: 0,
                oversized: 0,
                lost: 0,
                depth: 0,
            },
        }
    }

    /// Set the target delay, in RTP timestamp units (e.g. 480 = 60 ms at
    /// 8 kHz). Takes effect at the next `pop`.
    pub fn set_delay(&mut self, delay: u32) {
        self.delay = delay;
    }

    /// The target delay, in RTP timestamp units.
    #[must_use]
    pub const fn delay(&self) -> u32 {
        self.delay
    }

    /// Packets buffered now.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// The counters, with the current depth.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        let mut s = self.stats;
        s.depth = self.depth;
        s
    }

    /// Drop every packet and forget the sequence and timing state (a new
    /// SSRC, or a discontinuity); the counters and the delay are kept.
    pub fn reset(&mut self) {
        for s in &mut self.slots {
            s.used = false;
        }
        self.max_ext = 0;
        self.seen = false;
        self.next = 0;
        self.origin = None;
        self.last = None;
        self.probation = None;
        self.depth = 0;
    }

    /// The slot index of an extended sequence number.
    #[allow(clippy::cast_possible_truncation)]
    const fn index(ext: u64) -> usize {
        (ext as usize) & Self::MASK
    }

    /// Extend a 16-bit sequence number to the one nearest the highest seen;
    /// `None` before the start of the extended space.
    fn extend(&self, seq: u16) -> Option<u64> {
        if !self.seen {
            // Start a cycle up, so a reordered predecessor still extends.
            return Some(u64::from(seq).wrapping_add(1 << 16));
        }
        #[allow(clippy::cast_possible_truncation)]
        let delta = seq.wrapping_sub(self.max_ext as u16).cast_signed();
        self.max_ext.checked_add_signed(i64::from(delta))
    }

    /// Offer a packet: RTP sequence number, timestamp, marker bit and
    /// payload (copied).
    pub fn push(&mut self, seq: u16, ts: u32, marker: bool, payload: &[u8]) -> PushOutcome {
        let Ok(len) = u16::try_from(payload.len()) else {
            self.stats.oversized = self.stats.oversized.wrapping_add(1);
            return PushOutcome::Oversized;
        };
        if payload.len() > MAX_PAYLOAD {
            self.stats.oversized = self.stats.oversized.wrapping_add(1);
            return PushOutcome::Oversized;
        }
        let Some(ext) = self.extend(seq) else {
            self.stats.late = self.stats.late.wrapping_add(1);
            return PushOutcome::TooLate;
        };
        let n = N as u64;
        if !self.seen {
            self.seen = true;
            self.max_ext = ext;
            self.next = ext;
        } else if ext < self.next {
            // Before playout started, an earlier packet still fits if the
            // window from it reaches the highest one seen.
            if self.origin.is_none() && self.max_ext.wrapping_sub(ext) < n {
                self.next = ext;
            } else {
                self.stats.late = self.stats.late.wrapping_add(1);
                return PushOutcome::TooLate;
            }
        } else if ext.wrapping_sub(self.next) >= n {
            if self.probation == Some(ext) {
                // A second packet in sequence beyond the window: restart.
                self.stats.overflow = self.stats.overflow.wrapping_add(self.depth as u64);
                self.reset();
                self.seen = true;
                self.max_ext = ext;
                self.next = ext;
            } else {
                self.probation = ext.checked_add(1);
                self.stats.overflow = self.stats.overflow.wrapping_add(1);
                return PushOutcome::Overflow;
            }
        }
        self.probation = None;
        if ext > self.max_ext {
            self.max_ext = ext;
        }
        let Some(slot) = self.slots.get_mut(Self::index(ext)) else {
            return PushOutcome::Overflow;
        };
        if slot.used && slot.ext == ext {
            self.stats.duplicates = self.stats.duplicates.wrapping_add(1);
            return PushOutcome::Duplicate;
        }
        if !slot.used {
            self.depth = self.depth.wrapping_add(1);
        }
        slot.used = true;
        slot.ext = ext;
        slot.ts = ts;
        slot.marker = marker;
        slot.len = len;
        if let Some(dst) = slot.payload.get_mut(..payload.len()) {
            dst.copy_from_slice(payload);
        }
        self.stats.stored = self.stats.stored.wrapping_add(1);
        PushOutcome::Stored
    }

    /// The timestamp of the stored packet `ext`, if present.
    fn stored_ts(&self, ext: u64) -> Option<u32> {
        self.slots
            .get(Self::index(ext))
            .filter(|s| s.used && s.ext == ext)
            .map(|s| s.ts)
    }

    /// The next thing to play at playout clock `clock` (RTP timestamp
    /// units, the caller's own timeline).
    pub fn pop(&mut self, clock: u32) -> Pop<'_> {
        let (clock0, ts0) = if let Some(o) = self.origin {
            o
        } else {
            let Some(ts) = self.stored_ts(self.next) else {
                return Pop::Empty;
            };
            self.origin = Some((clock, ts));
            (clock, ts)
        };
        // The sender timestamp that should be playing now.
        let point = clock
            .wrapping_sub(clock0)
            .wrapping_add(ts0)
            .wrapping_sub(self.delay);
        let due = |ts: u32| ts.wrapping_sub(point).cast_signed() <= 0;

        if let Some(ts) = self.stored_ts(self.next) {
            if !due(ts) {
                return Pop::Empty;
            }
            let ext = self.next;
            self.next = ext.wrapping_add(1);
            self.last = Some((ext, ts));
            self.depth = self.depth.wrapping_sub(1);
            let Some(slot) = self.slots.get_mut(Self::index(ext)) else {
                return Pop::Empty;
            };
            slot.used = false;
            let slot = &*slot;
            #[allow(clippy::cast_possible_truncation)]
            return Pop::Packet {
                seq: ext as u16,
                ts: slot.ts,
                marker: slot.marker,
                payload: slot.payload.get(..usize::from(slot.len)).unwrap_or(&[]),
            };
        }

        // A gap: the nearest later packet, if any.
        let end = self.max_ext.min(self.next.saturating_add(N as u64));
        let mut later = None;
        let mut e = self.next.wrapping_add(1);
        while e <= end {
            if let Some(ts) = self.stored_ts(e) {
                later = Some((e, ts));
                break;
            }
            e = e.wrapping_add(1);
        }
        let Some((le, lts)) = later else {
            return Pop::Empty;
        };
        // Interpolate the missing packet's timestamp.
        let est = match self.last {
            Some((pe, pts)) if pe < self.next => {
                let span = u64::from(lts.wrapping_sub(pts));
                let num = self.next.wrapping_sub(pe);
                let den = le.wrapping_sub(pe);
                let off = span
                    .saturating_mul(num)
                    .checked_div(den)
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(0);
                pts.wrapping_add(off)
            }
            _ => lts,
        };
        if !due(est) {
            return Pop::Empty;
        }
        let ext = self.next;
        self.next = ext.wrapping_add(1);
        self.stats.lost = self.stats.lost.wrapping_add(1);
        #[allow(clippy::cast_possible_truncation)]
        Pop::Missing { seq: ext as u16 }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Pop and summarise: (Some(seq) packet | Missing seq as negative | Empty).
    #[derive(Debug, PartialEq, Eq)]
    enum P {
        Pkt(u16, u32, bool, Vec<u8>),
        Miss(u16),
        Empty,
    }

    fn pop<const N: usize>(jb: &mut JitterBuffer<N>, clock: u32) -> P {
        match jb.pop(clock) {
            Pop::Packet {
                seq,
                ts,
                marker,
                payload,
            } => P::Pkt(seq, ts, marker, payload.to_vec()),
            Pop::Missing { seq } => P::Miss(seq),
            Pop::Empty => P::Empty,
        }
    }

    fn seq_of(p: &P) -> Option<u16> {
        match p {
            P::Pkt(s, ..) => Some(*s),
            _ => None,
        }
    }

    #[test]
    fn in_order_with_delay() {
        let mut jb: JitterBuffer<8> = JitterBuffer::new(320);
        assert_eq!(pop(&mut jb, 0), P::Empty);
        assert_eq!(jb.push(10, 1000, true, b"a"), PushOutcome::Stored);
        // First pop at clock 5000 sets the origin; 320 units of delay.
        assert_eq!(pop(&mut jb, 5000), P::Empty);
        assert_eq!(jb.push(11, 1160, false, b"bb"), PushOutcome::Stored);
        assert_eq!(pop(&mut jb, 5160), P::Empty);
        assert_eq!(pop(&mut jb, 5320), P::Pkt(10, 1000, true, b"a".to_vec()));
        assert_eq!(pop(&mut jb, 5320), P::Empty);
        assert_eq!(pop(&mut jb, 5480), P::Pkt(11, 1160, false, b"bb".to_vec()));
        assert_eq!(pop(&mut jb, 5640), P::Empty);
        let s = jb.stats();
        assert_eq!((s.stored, s.depth, s.lost), (2, 0, 0));
    }

    #[test]
    fn reordering_duplicates_and_late() {
        let mut jb: JitterBuffer<16> = JitterBuffer::new(0);
        for &s in &[1u16, 3, 2, 5, 4] {
            assert_eq!(
                jb.push(s, u32::from(s) * 160, false, &[s as u8]),
                PushOutcome::Stored
            );
        }
        assert_eq!(jb.push(3, 480, false, &[3]), PushOutcome::Duplicate);
        // A predecessor of the first packet before playout starts.
        assert_eq!(jb.push(0, 0, false, &[0]), PushOutcome::Stored);
        let mut got = Vec::new();
        for k in 0..6u32 {
            got.push(seq_of(&pop(&mut jb, k * 160)).unwrap());
        }
        assert_eq!(got, [0, 1, 2, 3, 4, 5]);
        assert_eq!(jb.push(2, 320, false, &[2]), PushOutcome::TooLate);
        let s = jb.stats();
        assert_eq!((s.duplicates, s.late, s.stored), (1, 1, 6));
    }

    #[test]
    fn sequence_wrap() {
        let mut jb: JitterBuffer<8> = JitterBuffer::new(0);
        let mut clock = 0u32;
        let mut seq = 65530u16;
        let mut ts = u32::MAX - 500;
        let mut out = Vec::new();
        for _ in 0..20 {
            assert_eq!(jb.push(seq, ts, false, b"x"), PushOutcome::Stored);
            out.push(seq_of(&pop(&mut jb, clock)).unwrap());
            seq = seq.wrapping_add(1);
            ts = ts.wrapping_add(160);
            clock = clock.wrapping_add(160);
        }
        let want: Vec<u16> = (0..20u16).map(|k| 65530u16.wrapping_add(k)).collect();
        assert_eq!(out, want);
        // Reordering across the wrap.
        let mut jb: JitterBuffer<8> = JitterBuffer::new(0);
        assert_eq!(jb.push(1, 160 * 3, false, b""), PushOutcome::Stored);
        assert_eq!(jb.push(65535, 160, false, b""), PushOutcome::Stored);
        assert_eq!(jb.push(0, 320, false, b""), PushOutcome::Stored);
        assert_eq!(seq_of(&pop(&mut jb, 0)), Some(65535));
        assert_eq!(seq_of(&pop(&mut jb, 160)), Some(0));
        assert_eq!(seq_of(&pop(&mut jb, 320)), Some(1));
    }

    #[test]
    fn gap_is_reported_when_due() {
        let mut jb: JitterBuffer<8> = JitterBuffer::new(0);
        jb.push(100, 0, false, b"a");
        assert_eq!(seq_of(&pop(&mut jb, 0)), Some(100));
        // 101 and 102 lost, 103 arrives early.
        jb.push(103, 480, false, b"d");
        assert_eq!(pop(&mut jb, 100), P::Empty);
        assert_eq!(pop(&mut jb, 160), P::Miss(101));
        assert_eq!(pop(&mut jb, 160), P::Empty);
        assert_eq!(pop(&mut jb, 320), P::Miss(102));
        assert_eq!(seq_of(&pop(&mut jb, 480)), Some(103));
        assert_eq!(jb.stats().lost, 2);
        // Running dry: no later packet, nothing to report.
        assert_eq!(pop(&mut jb, 640), P::Empty);
        // A late arrival of a reported-missing packet.
        assert_eq!(jb.push(101, 160, false, b"b"), PushOutcome::TooLate);
    }

    #[test]
    fn long_loss_and_overflow_restart() {
        let mut jb: JitterBuffer<4> = JitterBuffer::new(0);
        jb.push(0, 0, false, b"a");
        assert_eq!(seq_of(&pop(&mut jb, 0)), Some(0));
        // Window is 1..=4.
        assert_eq!(jb.push(4, 640, false, b""), PushOutcome::Stored);
        assert_eq!(jb.push(5, 800, false, b""), PushOutcome::Overflow);
        // Loss of 1..=3 reported as each is due.
        assert_eq!(pop(&mut jb, 160), P::Miss(1));
        assert_eq!(pop(&mut jb, 320), P::Miss(2));
        assert_eq!(pop(&mut jb, 480), P::Miss(3));
        assert_eq!(seq_of(&pop(&mut jb, 640)), Some(4));
        // A jump far ahead: one packet is dropped, two in sequence restart.
        assert_eq!(jb.push(30000, 9_000_000, false, b""), PushOutcome::Overflow);
        assert_eq!(jb.push(30001, 9_000_160, false, b""), PushOutcome::Stored);
        assert_eq!(jb.push(30002, 9_000_320, false, b""), PushOutcome::Stored);
        // New origin at the next pop.
        assert_eq!(seq_of(&pop(&mut jb, 7)), Some(30001));
        assert_eq!(seq_of(&pop(&mut jb, 167)), Some(30002));
        let s = jb.stats();
        assert_eq!((s.overflow, s.lost), (2, 3));
    }

    #[test]
    fn hostile_input() {
        let mut jb: JitterBuffer<2> = JitterBuffer::new(u32::MAX);
        let big = [0u8; MAX_PAYLOAD + 1];
        assert_eq!(jb.push(1, 0, false, &big), PushOutcome::Oversized);
        let huge = std::vec![0u8; 70000];
        assert_eq!(jb.push(1, 0, false, &huge), PushOutcome::Oversized);
        assert_eq!(jb.stats().oversized, 2);
        assert_eq!(jb.depth(), 0);
        let max = [7u8; MAX_PAYLOAD];
        assert_eq!(jb.push(1, 0, false, &max), PushOutcome::Stored);
        assert_eq!(jb.push(1, 0, false, &[]), PushOutcome::Duplicate);
        // Random sequence numbers and clocks never panic and keep the
        // depth within N.
        let mut x = 0x1234_5678u32;
        for _ in 0..10000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let _ = jb.push(x as u16, x, x & 1 == 0, &max[..(x as usize % 64)]);
            let _ = jb.pop(x.rotate_left(7));
            assert!(jb.depth() <= 2);
        }
        jb.set_delay(0);
        assert_eq!(jb.delay(), 0);
    }

    #[test]
    fn reset_keeps_counters() {
        let mut jb: JitterBuffer<8> = JitterBuffer::new(0);
        jb.push(5, 0, false, b"a");
        jb.push(6, 160, false, b"b");
        jb.reset();
        assert_eq!(jb.depth(), 0);
        assert_eq!(pop(&mut jb, 0), P::Empty);
        assert_eq!(jb.stats().stored, 2);
        // A new stream with unrelated numbers.
        assert_eq!(jb.push(40000, 77, true, b"z"), PushOutcome::Stored);
        assert_eq!(pop(&mut jb, 123), P::Pkt(40000, 77, true, b"z".to_vec()));
    }

    #[test]
    fn against_reference_for_random_reordering() {
        // Packets 0..200 delivered with bounded reordering (each shifted by
        // at most 3 places; the first one first, as it sets the origin) and
        // no loss: with a large enough delay all play in order, none late,
        // none missing.
        let mut order: Vec<u16> = (0..200).collect();
        let mut x = 99u32;
        for block in order[1..197].chunks_mut(4) {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            block.rotate_left((x >> 16) as usize % 4);
            if x & 0x8000_0000 != 0 {
                block.reverse();
            }
        }
        let mut jb: JitterBuffer<16> = JitterBuffer::new(160 * 6);
        let mut played = Vec::new();
        let mut clock = 0u32;
        for &s in &order {
            assert_eq!(
                jb.push(s.wrapping_add(65500), u32::from(s) * 160, false, b"p"),
                PushOutcome::Stored
            );
            if let Some(s) = seq_of(&pop(&mut jb, clock)) {
                played.push(s);
            }
            clock += 160;
        }
        for _ in 0..20 {
            if let Some(s) = seq_of(&pop(&mut jb, clock)) {
                played.push(s);
            }
            clock += 160;
        }
        let want: Vec<u16> = (0..200u16).map(|s| s.wrapping_add(65500)).collect();
        assert_eq!(played, want);
        let s = jb.stats();
        assert_eq!((s.late, s.lost, s.duplicates), (0, 0, 0));
    }
}
