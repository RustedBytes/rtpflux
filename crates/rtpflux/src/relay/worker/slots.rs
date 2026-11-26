//! What a worker keeps per socket slot, indexed by [`Slot`] only.

use core::ops::{Index, IndexMut};
use rtpflux_core::relay::Slot;

/// One `T` per socket slot. Indexed by a [`Slot`], never by a bare number,
/// so a slot is not mixed up with a count, a length or another index.
#[derive(Debug, Clone)]
pub(super) struct PerSlot<T>(Vec<T>);

impl<T: Clone> PerSlot<T> {
    /// `n` slots, each `v`.
    pub(super) fn filled(n: usize, v: T) -> Self {
        PerSlot(vec![v; n])
    }
}

impl<T> PerSlot<T> {
    /// `n` slots, each made by `f`.
    pub(super) fn with(n: usize, f: impl FnMut() -> T) -> Self {
        let mut f = f;
        PerSlot((0..n).map(|_| f()).collect())
    }

    pub(super) fn get(&self, slot: Slot) -> Option<&T> {
        self.0.get(slot.index())
    }

    pub(super) fn get_mut(&mut self, slot: Slot) -> Option<&mut T> {
        self.0.get_mut(slot.index())
    }

    /// Every slot, with its value.
    pub(super) fn slots(&self) -> impl Iterator<Item = (Slot, &T)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, v)| Some((Slot::new(u32::try_from(i).ok()?), v)))
    }

    /// Every slot, with its value to change.
    pub(super) fn slots_mut(&mut self) -> impl Iterator<Item = (Slot, &mut T)> {
        self.0
            .iter_mut()
            .enumerate()
            .filter_map(|(i, v)| Some((Slot::new(u32::try_from(i).ok()?), v)))
    }

    /// The table as the forwarding decision takes it
    /// (`rtpflux_core::relay::on_packet`).
    pub(super) fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<T> Index<Slot> for PerSlot<T> {
    type Output = T;

    fn index(&self, slot: Slot) -> &T {
        &self.0[slot.index()]
    }
}

impl<T> IndexMut<Slot> for PerSlot<T> {
    fn index_mut(&mut self, slot: Slot) -> &mut T {
        &mut self.0[slot.index()]
    }
}
