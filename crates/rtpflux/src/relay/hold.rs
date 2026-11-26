//! Holding back a party's audio while the relay plays to the other one.
//!
//! While an announcement (`play media`) or keys (`play DTMF`, or DTMF
//! transcoded into tones) play to a party, the other party's audio towards
//! it is held back, so the two do not mix. Each party has at most one
//! announcement and one set of keys at a time (a new one replaces the
//! old). The hold stays exactly while something plays: when one ends,
//! played out or stopped, it goes only if nothing else plays there.

/// What plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Announcement,
    Keys,
}

impl Kind {
    const fn bit(self) -> u8 {
        match self {
            Kind::Announcement => 1,
            Kind::Keys => 2,
        }
    }
}

/// What plays to each slot.
#[derive(Debug, Clone)]
pub struct Hold {
    playing: Vec<u8>,
}

impl Hold {
    #[must_use]
    pub fn new(slots: usize) -> Self {
        Hold {
            playing: vec![0; slots],
        }
    }

    /// Something of `kind` starts to slot `to` (replacing what played of
    /// that kind): it is held.
    pub fn start(&mut self, kind: Kind, to: usize) {
        if let Some(p) = self.playing.get_mut(to) {
            *p |= kind.bit();
        }
    }

    /// What plays of `kind` to `to` ends: whether `to` stays held
    /// (something else still plays there).
    pub fn finish(&mut self, kind: Kind, to: usize) -> bool {
        self.playing.get_mut(to).is_some_and(|p| {
            *p &= !kind.bit();
            *p != 0
        })
    }

    /// Whether `to` is held.
    #[must_use]
    pub fn held(&self, to: usize) -> bool {
        self.playing.get(to).is_some_and(|&p| p != 0)
    }

    /// The slot's call ended.
    pub fn forget(&mut self, to: usize) {
        if let Some(p) = self.playing.get_mut(to) {
            *p = 0;
        }
    }
}
