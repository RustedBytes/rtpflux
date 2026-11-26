//! Media subscriptions' copy table: which legs a leg's packets are copied
//! to, and which legs only send (subscriptions' legs: *sinks*).
//!
//! A leg is tapped to sink legs ([`Taps::tap`] refuses any other target),
//! or, with [`Taps::listen`] (`connect` with `directional`), to a leg of a
//! regular call, which is marked as a *listener*. A sink's or listener's
//! call closing ([`Taps::close`]) takes it out of every list, so a slot
//! reused by another call never receives copies. What
//! arrives on a sink is not relayed; what a leg accepts is copied to its
//! taps, in the order they were added ([`Taps::arrive`]).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taps {
    lists: Vec<Vec<u32>>,
    sink: Vec<bool>,
    /// Legs of regular calls some leg is (or was) tapped to.
    listener: Vec<bool>,
}

/// What becomes of a packet arriving on a leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival<'a> {
    /// The leg is a sink: not relayed.
    Sink,
    /// Relayed as usual, and copied to these legs (none when rejected by
    /// the latch, or untapped).
    Copy(&'a [u32]),
}

impl Taps {
    /// A table for `slots` legs, none tapped or a sink.
    #[must_use]
    pub fn new(slots: usize) -> Self {
        Taps {
            lists: vec![Vec::new(); slots],
            sink: vec![false; slots],
            listener: vec![false; slots],
        }
    }

    /// Make these legs sinks.
    pub fn sink(&mut self, slots: &[u32]) {
        for &s in slots {
            if let Some(k) = self.sink.get_mut(s as usize) {
                *k = true;
            }
        }
    }

    #[must_use]
    pub fn is_sink(&self, slot: usize) -> bool {
        self.sink.get(slot).copied().unwrap_or(false)
    }

    #[must_use]
    pub fn tapped(&self, slot: usize) -> bool {
        self.lists.get(slot).is_some_and(|t| !t.is_empty())
    }

    /// Copy (`on`) or stop copying each pair's first leg to its second.
    /// Copying is refused (nothing changes, `false`) unless every second
    /// leg is a sink.
    pub fn tap(&mut self, pairs: &[(u32, u32)], on: bool) -> bool {
        if on && !pairs.iter().all(|&(_, to)| self.is_sink(to as usize)) {
            return false;
        }
        for &(from, to) in pairs {
            let Some(list) = self.lists.get_mut(from as usize) else {
                continue;
            };
            list.retain(|&x| x != to);
            if on {
                list.push(to);
            }
        }
        true
    }

    /// Copy (`on`) or stop copying each pair's first leg to its second, a
    /// leg of a regular call, which keeps relaying its own media: a
    /// listener. Refused (`false`) for a leg tapped to itself or to a sink.
    pub fn listen(&mut self, pairs: &[(u32, u32)], on: bool) -> bool {
        if pairs
            .iter()
            .any(|&(from, to)| from == to || self.is_sink(to as usize))
        {
            return false;
        }
        for &(from, to) in pairs {
            let Some(list) = self.lists.get_mut(from as usize) else {
                continue;
            };
            list.retain(|&x| x != to);
            if on {
                list.push(to);
                if let Some(l) = self.listener.get_mut(to as usize) {
                    *l = true;
                }
            }
        }
        true
    }

    /// A call's legs close: their own taps go, and, for a subscription's
    /// call (any of them a sink) or a listener's, every tap to them, and
    /// they are sinks and listeners no more.
    pub fn close(&mut self, slots: &[u32]) {
        for &s in slots {
            if let Some(t) = self.lists.get_mut(s as usize) {
                t.clear();
            }
        }
        let listened = |s: u32| self.listener.get(s as usize).copied().unwrap_or(false);
        if slots
            .iter()
            .any(|&s| self.is_sink(s as usize) || listened(s))
        {
            for t in &mut self.lists {
                t.retain(|x| !slots.contains(x));
            }
            for &s in slots {
                if let Some(k) = self.sink.get_mut(s as usize) {
                    *k = false;
                }
                if let Some(l) = self.listener.get_mut(s as usize) {
                    *l = false;
                }
            }
        }
    }

    /// A packet arrives on `leg`; `accepted`: its source passed the latch.
    #[must_use]
    pub fn arrive(&self, leg: usize, accepted: bool) -> Arrival<'_> {
        if self.is_sink(leg) {
            Arrival::Sink
        } else if accepted {
            Arrival::Copy(self.lists.get(leg).map_or(&[], Vec::as_slice))
        } else {
            Arrival::Copy(&[])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listener_gets_copies_until_its_call_closes() {
        let mut t = Taps::new(8);
        assert!(!t.listen(&[(0, 0)], true), "not to itself");
        assert!(t.listen(&[(0, 4), (2, 4)], true));
        assert_eq!(t.arrive(0, true), Arrival::Copy(&[4]));
        assert_eq!(t.arrive(0, false), Arrival::Copy(&[]), "latch refused");
        // A listener relays its own media: not a sink.
        assert_eq!(t.arrive(4, true), Arrival::Copy(&[]));
        // Its call closes: no leg copies to the slot any more.
        t.close(&[4, 5, 6, 7]);
        assert_eq!(t.arrive(0, true), Arrival::Copy(&[]));
        assert_eq!(t.arrive(2, true), Arrival::Copy(&[]));
        // Stopping a copy keeps the others.
        assert!(t.listen(&[(0, 4), (0, 6)], true));
        assert!(t.listen(&[(0, 4)], false));
        assert_eq!(t.arrive(0, true), Arrival::Copy(&[6]));
    }

    #[test]
    fn sinks_take_no_listeners_and_listeners_no_taps() {
        let mut t = Taps::new(8);
        t.sink(&[4]);
        assert!(!t.listen(&[(0, 4)], true));
        assert!(!t.tap(&[(0, 6)], true), "6 is no sink");
        assert!(t.tap(&[(0, 4)], true));
        assert_eq!(t.arrive(4, true), Arrival::Sink);
    }
}
