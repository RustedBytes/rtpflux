//! Media port allocation: RTP on an even port, RTCP on the next odd one
//! (RFC 3550 §11), handed out in pairs from a contiguous range.
//!
//! A bitmap with a next-fit cursor: O(1) amortised allocation, no heap, and
//! recently freed ports are not reused immediately (the cursor moves on),
//! which keeps stray packets of an ended call away from the next one.

/// Most pairs one allocator can manage (the whole 16-bit port space).
pub const MAX_PAIRS: usize = 32_768;

const WORDS: usize = MAX_PAIRS / 64;

/// Allocator of RTP/RTCP port pairs from `first..first + 2 * pairs`.
#[derive(Debug, Clone)]
pub struct PairAllocator {
    used: [u64; WORDS],
    first: u16,
    pairs: usize,
    cursor: usize,
    in_use: usize,
}

/// Why an allocator cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// The first port is odd or zero.
    BadFirstPort,
    /// No pairs, more than [`MAX_PAIRS`], or past port 65535.
    BadSize,
}

impl PairAllocator {
    /// Manage `pairs` pairs starting at the even port `first`.
    ///
    /// # Errors
    ///
    /// [`RangeError`] when the range is not representable.
    pub fn new(first: u16, pairs: usize) -> Result<Self, RangeError> {
        if first == 0 || !first.is_multiple_of(2) {
            return Err(RangeError::BadFirstPort);
        }
        let end = pairs
            .checked_mul(2)
            .and_then(|n| n.checked_add(usize::from(first)));
        if pairs == 0 || pairs > MAX_PAIRS || end.is_none_or(|end| end > 65_536) {
            return Err(RangeError::BadSize);
        }
        Ok(PairAllocator {
            used: [0; WORDS],
            first,
            pairs,
            cursor: 0,
            in_use: 0,
        })
    }

    /// Pairs managed.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.pairs
    }

    /// Pairs currently allocated.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.in_use
    }

    /// The RTP port of a free pair (RTCP is the next port), or `None` when
    /// the range is exhausted.
    pub fn alloc(&mut self) -> Option<u16> {
        if self.in_use == self.pairs {
            return None;
        }
        // A word (64 pairs) at a time from the cursor's word, round to it
        // again for the pairs below the cursor.
        let words = self.pairs.div_ceil(64);
        let first = self.cursor / 64;
        for k in 0..=words {
            // `words` >= 1 (`pairs` >= 1), at most 1024: no overflow.
            let w = first.wrapping_add(k).checked_rem(words)?;
            let mut free = !*self.used.get(w)?;
            if w.wrapping_add(1) == words && !self.pairs.is_multiple_of(64) {
                // Past the range.
                let tail = u32::try_from(self.pairs % 64).unwrap_or(0);
                free &= 1u64.wrapping_shl(tail).wrapping_sub(1);
            }
            if k == 0 {
                free &= u64::MAX << (self.cursor % 64); // before the cursor
            }
            if free != 0 {
                let b = free.trailing_zeros() as usize;
                // A pair of the range: `w` < 1024, `b` < 64.
                let i = w.wrapping_mul(64).wrapping_add(b);
                *self.used.get_mut(w)? |= 1u64 << b;
                // Below `pairs` (checked above).
                self.in_use = self.in_use.wrapping_add(1);
                self.cursor = i.wrapping_add(1).checked_rem(self.pairs).unwrap_or(0);
                return Some(self.port_of(i));
            }
        }
        None
    }

    /// Allocate the specific pair whose RTP port is `rtp_port` (restoring
    /// a call on its old ports). Returns `false` (and changes nothing) for a
    /// port outside the range, an odd port, or a pair already allocated.
    pub fn take(&mut self, rtp_port: u16) -> bool {
        let Some(i) = self.index_of(rtp_port) else {
            return false;
        };
        let (w, b) = (i / 64, i % 64);
        let Some(word) = self.used.get_mut(w) else {
            return false;
        };
        if *word & (1 << b) != 0 {
            return false;
        }
        *word |= 1 << b;
        // Below `pairs`: this one was free.
        self.in_use = self.in_use.wrapping_add(1);
        true
    }

    /// Return the pair whose RTP port is `rtp_port`. Returns `false` (and
    /// changes nothing) for a port outside the range, an odd port, or a pair
    /// that is not allocated.
    pub fn free(&mut self, rtp_port: u16) -> bool {
        let Some(i) = self.index_of(rtp_port) else {
            return false;
        };
        let (w, b) = (i / 64, i % 64);
        let Some(word) = self.used.get_mut(w) else {
            return false;
        };
        if *word & (1 << b) == 0 {
            return false;
        }
        *word &= !(1 << b);
        // At least this one was in use.
        self.in_use = self.in_use.wrapping_sub(1);
        true
    }

    /// Whether `port` (RTP or RTCP) belongs to this range.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.index_of(port & !1).is_some()
    }

    /// Index of the pair whose RTP port is `rtp_port`.
    #[must_use]
    pub fn index_of(&self, rtp_port: u16) -> Option<usize> {
        if !rtp_port.is_multiple_of(2) {
            return None;
        }
        let i = usize::from(rtp_port.checked_sub(self.first)?) / 2;
        (i < self.pairs).then_some(i)
    }

    fn port_of(&self, i: usize) -> u16 {
        // `i < pairs` and `first + 2 * pairs <= 65536`, so this fits.
        self.first
            .wrapping_add(u16::try_from(i.wrapping_mul(2)).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_every_pair_once() {
        let mut a = PairAllocator::new(30_000, 100).unwrap();
        let mut seen = [false; 100];
        for _ in 0..100 {
            let p = a.alloc().unwrap();
            assert!(p.is_multiple_of(2) && (30_000..30_200).contains(&p));
            let i = a.index_of(p).unwrap();
            assert!(!seen[i]);
            seen[i] = true;
        }
        assert_eq!(a.alloc(), None);
        assert_eq!(a.in_use(), 100);
    }

    #[test]
    fn free_and_next_fit() {
        let mut a = PairAllocator::new(40_000, 4).unwrap();
        let p0 = a.alloc().unwrap();
        let p1 = a.alloc().unwrap();
        assert!(a.free(p0));
        assert!(!a.free(p0), "double free");
        assert!(!a.free(p1 + 1), "RTCP port is not a pair handle");
        assert!(!a.free(50_000), "outside the range");
        // next-fit: the freed pair is not handed out again straight away
        assert_ne!(a.alloc(), Some(p0));
        assert!(a.contains(p1 + 1));
    }

    #[test]
    fn rejects_bad_ranges() {
        assert_eq!(
            PairAllocator::new(30_001, 10).err(),
            Some(RangeError::BadFirstPort)
        );
        assert_eq!(
            PairAllocator::new(0, 10).err(),
            Some(RangeError::BadFirstPort)
        );
        assert_eq!(
            PairAllocator::new(30_000, 0).err(),
            Some(RangeError::BadSize)
        );
        assert_eq!(
            PairAllocator::new(65_534, 2).err(),
            Some(RangeError::BadSize)
        );
        assert!(PairAllocator::new(65_534, 1).is_ok());
    }

    #[test]
    fn take_a_specific_pair() {
        let mut a = PairAllocator::new(30000, 4).unwrap();
        assert!(a.take(30004));
        assert!(!a.take(30004), "already taken");
        assert!(!a.take(30005) && !a.take(29998) && !a.take(30008));
        assert_eq!(a.in_use(), 1);
        let got = [a.alloc(), a.alloc(), a.alloc()];
        assert!(!got.contains(&Some(30004)), "{got:?}");
        assert_eq!(a.alloc(), None, "all four pairs in use");
        assert!(a.free(30004));
    }

    /// Against a plain model: whatever is allocated was free, nothing is
    /// handed out twice, and the range is exhausted exactly when full.
    #[test]
    fn word_scan_agrees_with_a_plain_model() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for pairs in [1usize, 2, 63, 64, 65, 127, 128, 130, 1000] {
            let mut a = PairAllocator::new(10_000, pairs).unwrap();
            let mut taken = [false; 1000];
            for _ in 0..5_000 {
                if rnd() % 3 == 0 {
                    // Free a random taken pair.
                    let i = usize::try_from(rnd()).unwrap() % pairs;
                    if taken[i] {
                        a.free(10_000 + 2 * u16::try_from(i).unwrap());
                        taken[i] = false;
                    }
                } else {
                    match a.alloc() {
                        Some(port) => {
                            let i = usize::from(port - 10_000) / 2;
                            assert!(i < pairs && !taken[i], "pair {i} of {pairs}");
                            taken[i] = true;
                        }
                        None => assert!(taken[..pairs].iter().all(|&t| t), "free pairs left"),
                    }
                }
                assert_eq!(a.in_use(), taken.iter().filter(|&&t| t).count());
            }
        }
    }
}
