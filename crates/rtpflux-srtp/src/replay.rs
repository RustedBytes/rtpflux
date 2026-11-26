//! Per-source receive state: rollover-counter estimation (RFC 3711
//! §3.3.1, Appendix A) and the replay window (§3.3.2).

use crate::Ssrc;

#[allow(clippy::wildcard_imports)]
use super::*;

/// 64-packet replay window over 48-bit (SRTP) or 31-bit (SRTCP) indices.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Replay {
    pub(super) highest: Option<u64>,
    pub(super) seen: u64,
}

impl Replay {
    pub(super) fn fresh(&self, index: u64) -> bool {
        let Some(h) = self.highest else { return true };
        // Not behind the highest: new. Behind it: within the window and
        // not seen.
        match h.checked_sub(index) {
            None => true,
            Some(age) => bit(age).is_some_and(|b| self.seen & b == 0),
        }
    }

    pub(super) fn accept(&mut self, index: u64) {
        match self.highest {
            None => {
                self.highest = Some(index);
                self.seen = 1;
            }
            Some(h) => match index.checked_sub(h) {
                // Ahead: the window moves on (past 64, it starts empty).
                Some(shift) if shift > 0 => {
                    let moved = u32::try_from(shift)
                        .ok()
                        .and_then(|s| self.seen.checked_shl(s))
                        .filter(|_| shift < 64)
                        .unwrap_or(0);
                    self.seen = moved | 1;
                    self.highest = Some(index);
                }
                // Behind (or at) the highest: marked, within the window.
                _ => {
                    if let Some(b) = h.checked_sub(index).and_then(bit) {
                        self.seen |= b;
                    }
                }
            },
        }
    }
}

/// Sequence state of one SSRC (Appendix A).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SeqState {
    pub(super) ssrc: Option<Ssrc>,
    pub(super) roc: u32,
    pub(super) highest_seq: u16,
}

impl SeqState {
    /// The rollover counter that `seq` most likely belongs to (Appendix A).
    /// At ROC 0 there is no earlier rollover: a packet more than 2^15
    /// ahead of the first one stays at ROC 0 instead of wrapping to
    /// 2^32 − 1 (which the sender cannot have reached).
    pub(super) fn guess(&self, seq: u16) -> u32 {
        let (s_l, roc) = (self.highest_seq, self.roc);
        if s_l < 0x8000 {
            if seq.checked_sub(s_l).is_some_and(|d| d > 0x8000) {
                roc.saturating_sub(1)
            } else {
                roc
            }
        } else if s_l.wrapping_sub(0x8000) > seq {
            roc.wrapping_add(1)
        } else {
            roc
        }
    }

    pub(super) fn update(&mut self, seq: u16, v: u32) {
        if v == self.roc.wrapping_add(1) {
            self.roc = v;
            self.highest_seq = seq;
        } else if v == self.roc && seq > self.highest_seq {
            self.highest_seq = seq;
        }
    }

    /// The state to use for `ssrc`: this one, or a fresh one for a new
    /// source (first packet, or an SSRC change).
    pub(super) fn for_source(self, ssrc: Ssrc, seq: u16) -> Self {
        if self.ssrc == Some(ssrc) {
            self
        } else {
            SeqState {
                ssrc: Some(ssrc),
                roc: 0,
                highest_seq: seq,
            }
        }
    }
}

/// The window's bit for a packet `age` behind the highest (`None` past
/// the 64-packet window).
fn bit(age: u64) -> Option<u64> {
    1u64.checked_shl(u32::try_from(age).ok()?)
        .filter(|_| age < 64)
}

/// The 48-bit packet index: the rollover counter, then the sequence number.
pub(super) fn index(roc: u32, seq: u16) -> u64 {
    // A u32 shifted by 16 fits in a u64.
    u64::from(roc).wrapping_shl(16) | u64::from(seq)
}

/// Length of an RTP header (fixed part, CSRCs, extension) in `buf`.
pub(super) fn rtp_header_len(buf: &[u8]) -> Result<usize, Error> {
    let first = *buf.first().ok_or(Error::Malformed)?;
    if buf.len() < 12 || first >> 6 != 2 {
        return Err(Error::Malformed);
    }
    // At most 15 CSRCs: 12 + 60, no overflow.
    let mut n = usize::from(first & 0x0f).wrapping_mul(4).wrapping_add(12);
    if first & 0x10 != 0 {
        let at = n.checked_add(2).ok_or(Error::Malformed)?;
        let words = be16(buf, at).ok_or(Error::Malformed)?;
        // At most 4 + 4 * 65535 octets more (fits a 32-bit usize).
        let ext = usize::from(words).wrapping_mul(4).wrapping_add(4);
        n = n.checked_add(ext).ok_or(Error::Malformed)?;
    }
    if n > buf.len() {
        return Err(Error::Malformed);
    }
    Ok(n)
}

/// The big-endian u16 at `buf[at..at + 2]`.
pub(super) fn be16(buf: &[u8], at: usize) -> Option<u16> {
    let b = buf.get(at..)?.first_chunk::<2>()?;
    Some(u16::from_be_bytes(*b))
}

/// The `N` octets at `buf[at..]` (`None` when `buf` is too short).
pub(super) fn at_chunk<const N: usize>(buf: &[u8], at: usize) -> Option<&[u8; N]> {
    buf.get(at..)?.first_chunk::<N>()
}

/// The `N` octets at `buf[at..]`, to write.
pub(super) fn at_chunk_mut<const N: usize>(buf: &mut [u8], at: usize) -> Option<&mut [u8; N]> {
    buf.get_mut(at..)?.first_chunk_mut::<N>()
}

/// The SSRC at `buf[at..at + 4]` (`None` when `buf` is too short).
pub(super) fn ssrc_at(buf: &[u8], at: usize) -> Option<Ssrc> {
    let b = buf.get(at..)?.first_chunk::<4>()?;
    Some(Ssrc::from_be_bytes(*b))
}

/// Sources tracked per direction (RFC 3711 §3.2.3: a context per SSRC;
/// RFC 4568 §6.4: created on the first packet of a new SSRC). Bundled audio,
/// video, simulcast layers and retransmission streams fit. A further SSRC
/// is refused ([`crate::Error::TooManySources`]), never given another
/// source's entry: forgetting a sender's state would encrypt again at
/// indices already used under the key, and forgetting a receiver's would
/// accept replays.
pub const MAX_SOURCES: usize = 16;

/// The per-source part of a context: sequence and replay state of SRTP and
/// SRTCP.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Source {
    pub(super) seq: SeqState,
    pub(super) replay: Replay,
    /// Sender: next SRTCP index. Receiver: unused.
    pub(super) rtcp_index: u32,
    pub(super) rtcp_replay: Replay,
    /// When it was last used (for replacement).
    pub(super) used: u64,
}

/// The sources of one direction, found by SSRC.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Sources {
    pub(super) ssrcs: [Option<Ssrc>; MAX_SOURCES],
    pub(super) state: [Source; MAX_SOURCES],
    pub(super) clock: u64,
}

impl Sources {
    /// The state of `ssrc` (a fresh one, seeded with `seq`, for a new
    /// source) and where it lives. Nothing is changed: commit with
    /// [`Sources::commit`] once the packet is accepted.
    ///
    /// # Errors
    ///
    /// [`crate::Error::TooManySources`] for a new SSRC when every entry is
    /// taken.
    pub(super) fn lookup(
        &self,
        ssrc: Ssrc,
        seq: u16,
    ) -> Result<(Option<usize>, Source), crate::Error> {
        match self.ssrcs.iter().position(|s| *s == Some(ssrc)) {
            Some(i) => Ok((
                Some(i),
                self.state
                    .get(i)
                    .copied()
                    .ok_or(crate::Error::TooManySources)?,
            )),
            None if self.ssrcs.iter().all(Option::is_some) => Err(crate::Error::TooManySources),
            None => Ok((
                None,
                Source {
                    seq: SeqState::default().for_source(ssrc, seq),
                    ..Source::default()
                },
            )),
        }
    }

    /// Store the state of `ssrc`: in place, or (a new source, which
    /// [`Sources::lookup`] found room for) in a free entry.
    pub(super) fn commit(&mut self, at: Option<usize>, ssrc: Ssrc, mut source: Source) {
        self.clock = self.clock.wrapping_add(1);
        source.used = self.clock;
        let Some(i) = at.or_else(|| self.ssrcs.iter().position(Option::is_none)) else {
            return;
        };
        if let (Some(s), Some(st)) = (self.ssrcs.get_mut(i), self.state.get_mut(i)) {
            *s = Some(ssrc);
            *st = source;
        }
    }
}
