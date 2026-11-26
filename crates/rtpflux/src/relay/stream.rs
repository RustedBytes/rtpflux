//! The RTP stream a relay plays into, per party: announcements and keys
//! (played, or DTMF transcoded into tones) go in one stream whose SSRC,
//! sequence numbers and timestamps go on from one to the next until the
//! call ends. Under SRTP, a stream restarting at the same SSRC and
//! sequence would encrypt again at packet indices already used under the
//! key (and the peer would drop it as a replay).
//!
//! The timestamp follows the clock, not the packets: an announcement and
//! keys playing at once both send, and the stream's clock must not run
//! faster for it.

/// A stream: SSRC, the next sequence number, and the timestamp at
/// `at_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayStream {
    pub ssrc: rtpflux_core::rtp::Ssrc,
    pub seq: u16,
    pub ts: u32,
    pub at_ms: u64,
}

impl PlayStream {
    #[must_use]
    pub fn new(ssrc: rtpflux_core::rtp::Ssrc, seq: u16, ts: u32, at_ms: u64) -> Self {
        PlayStream {
            ssrc,
            seq,
            ts,
            at_ms,
        }
    }

    /// Move the clock on to `due_ms` (a packet's time), at `per_ms` ticks
    /// a millisecond; never back.
    pub fn advance(&mut self, due_ms: u64, per_ms: u32) {
        if due_ms > self.at_ms {
            let ticks = (due_ms - self.at_ms).wrapping_mul(u64::from(per_ms));
            // The timestamp wraps at 2^32 (RFC 3550 §5.1).
            #[allow(clippy::cast_possible_truncation)]
            {
                self.ts = self.ts.wrapping_add(ticks as u32);
            }
            self.at_ms = due_ms;
        }
    }

    /// The sequence number of a packet sent now; the stream moves past it.
    pub fn take_seq(&mut self) -> u16 {
        let s = self.seq;
        self.seq = s.wrapping_add(1);
        s
    }

    /// A packet sent at `due_ms` at `per_ms` ticks a millisecond: its
    /// sequence number and timestamp.
    pub fn packet(&mut self, due_ms: u64, per_ms: u32) -> (u16, u32) {
        self.advance(due_ms, per_ms);
        (self.take_seq(), self.ts)
    }
}
