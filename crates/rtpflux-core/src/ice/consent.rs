//! Consent freshness on one candidate pair (RFC 7675 §5.1).
//!
//! Consent is obtained when the pair's check succeeds and lasts 30 s;
//! authenticated success responses to consent requests (or to any check)
//! renew it. Requests go out every 4–6 s (0.8–1.2 times a 5 s period,
//! randomized), each with a new transaction id and sent once; a response
//! to any outstanding request counts. Once expired, consent is lost for the
//! pair until an ICE restart: late responses do not restore it, and no more
//! requests are sent.
//!
//! The transaction ids are the caller's (random 96-bit values); the
//! struct remembers the most recent ones so that one is never used twice
//! within its memory.

/// Consent expires after this long without a grant (ms).
pub const EXPIRY_MS: u64 = 30_000;
/// The basic period between consent requests (ms).
pub const PERIOD_MS: u64 = 5_000;
/// The shortest period allowed (ms).
pub const MIN_PERIOD_MS: u64 = 4_000;

/// Transaction ids remembered (outstanding requests and ids used).
const MEMORY: usize = 16;

/// The interval to the next request for a random draw `r` (ms): within
/// 0.8–1.2 times `period`, never below 4 s.
#[must_use]
pub fn interval(period: u64, r: u64) -> u64 {
    let (high, low) = (period.saturating_mul(6) / 5, period.saturating_mul(4) / 5);
    MIN_PERIOD_MS.max(high.min(low.max(r)))
}

/// A small set of transaction ids, oldest dropped first when full.
#[derive(Debug, Clone, Copy, Default)]
struct Ids {
    ids: [u128; MEMORY],
    len: usize,
}

impl Ids {
    fn as_slice(&self) -> &[u128] {
        // `len` <= MEMORY (`push`).
        self.ids.get(..self.len).unwrap_or_default()
    }

    fn contains(&self, t: u128) -> bool {
        self.as_slice().contains(&t)
    }

    fn push(&mut self, t: u128) {
        if self.len == MEMORY {
            self.ids.copy_within(1.., 0);
            self.len = MEMORY - 1;
        }
        if let Some(slot) = self.ids.get_mut(self.len) {
            *slot = t;
            // Below MEMORY (checked above).
            self.len = self.len.wrapping_add(1);
        }
    }

    fn remove(&mut self, t: u128) -> bool {
        let Some(k) = self.as_slice().iter().position(|&x| x == t) else {
            return false;
        };
        // `k` < `len`: the later ones move down by one.
        if let Some(tail) = self.ids.get_mut(k..self.len) {
            tail.rotate_left(1);
        }
        self.len = self.len.wrapping_sub(1);
        true
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// The consent state of one pair.
#[derive(Debug, Clone, Copy)]
pub struct Consent {
    now: u64,
    granted_at: Option<u64>,
    lost: bool,
    outstanding: Ids,
    next_at: u64,
    used: Ids,
    period: u64,
}

impl Default for Consent {
    fn default() -> Self {
        Consent::new(PERIOD_MS)
    }
}

impl Consent {
    /// No consent yet; requests every `period` ms (randomized).
    #[must_use]
    pub const fn new(period: u64) -> Self {
        Consent {
            now: 0,
            granted_at: None,
            lost: false,
            outstanding: Ids {
                ids: [0; MEMORY],
                len: 0,
            },
            next_at: 0,
            used: Ids {
                ids: [0; MEMORY],
                len: 0,
            },
            period,
        }
    }

    /// Time passes; true when consent expires now (cease sending; the
    /// outstanding requests are discarded).
    pub fn tick(&mut self, t: u64) -> bool {
        self.now = self.now.max(t);
        let expired = !self.lost
            && self
                .granted_at
                .is_some_and(|c| c.saturating_add(EXPIRY_MS) <= self.now);
        if expired {
            self.lost = true;
            self.outstanding.clear();
        }
        expired
    }

    /// The pair's check succeeded: consent, unless it was lost (`r` draws
    /// the first interval).
    pub fn succeeded(&mut self, r: u64) {
        if !self.lost && self.granted_at.is_none() {
            self.granted_at = Some(self.now);
            self.next_at = self.now.saturating_add(interval(self.period, r));
        }
    }

    fn fresh(&self) -> bool {
        self.granted_at
            .is_some_and(|c| self.now < c.saturating_add(EXPIRY_MS))
    }

    /// A request is due now.
    #[must_use]
    pub fn due(&self) -> bool {
        self.fresh() && !self.lost && self.next_at <= self.now
    }

    /// Send a request with transaction id `tid` if one is due (`r` draws the
    /// next interval); false when nothing may be sent.
    pub fn send(&mut self, tid: u128, r: u64) -> bool {
        if !self.due() || self.used.contains(tid) {
            return false;
        }
        self.outstanding.push(tid);
        self.used.push(tid);
        self.next_at = self.now.saturating_add(interval(self.period, r));
        true
    }

    /// A response to `tid`; `ok`: authenticated, a success, from the
    /// remote address. True when it renewed consent.
    pub fn response(&mut self, tid: u128, ok: bool) -> bool {
        if ok && !self.lost && self.outstanding.contains(tid) {
            self.outstanding.remove(tid);
            self.granted_at = Some(self.now);
            true
        } else {
            false
        }
    }

    /// An ICE restart: consent must be obtained again.
    pub fn restart(&mut self) {
        self.lost = false;
        self.granted_at = None;
        self.outstanding.clear();
    }

    /// Data may be sent on the pair.
    #[must_use]
    pub fn may_send(&self) -> bool {
        !self.lost && self.fresh()
    }

    #[must_use]
    pub const fn lost(&self) -> bool {
        self.lost
    }

    /// When something happens next: a request falls due or consent expires.
    #[must_use]
    pub fn next_ms(&self) -> Option<u64> {
        if self.lost {
            return None;
        }
        let c = self.granted_at?;
        Some(self.next_at.min(c.saturating_add(EXPIRY_MS)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_until_restart() {
        let mut c = Consent::default();
        c.tick(0);
        c.succeeded(5_000);
        assert!(c.may_send());
        c.tick(5_000);
        assert!(c.send(1, 5_000));
        assert!(!c.send(1, 5_000));
        assert!(c.tick(30_000));
        assert!(!c.may_send());
        assert!(!c.response(1, true));
        c.succeeded(5_000);
        assert!(!c.may_send());
        c.restart();
        c.succeeded(5_000);
        assert!(c.may_send());
    }
}
