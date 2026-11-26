//! A fixed-capacity FIFO ring buffer: storage inline, capacity a power of
//! two (index masking instead of division), never grows. A full ring
//! rejects the push and hands the value back, so callers drop and count.

/// FIFO of `N` values of `T` (`N` a power of two).
#[derive(Debug, Clone)]
pub struct Ring<T: Copy, const N: usize> {
    buf: [T; N],
    head: usize,
    len: usize,
}

impl<T: Copy, const N: usize> Ring<T, N> {
    const MASK: usize = {
        assert!(N.is_power_of_two(), "Ring capacity must be a power of two");
        N - 1
    };

    /// An empty ring; `fill` initialises the unused slots.
    #[must_use]
    pub const fn new(fill: T) -> Self {
        let _ = Self::MASK;
        Ring {
            buf: [fill; N],
            head: 0,
            len: 0,
        }
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Append at the tail.
    ///
    /// # Errors
    ///
    /// Gives `value` back when the ring is full.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.is_full() {
            return Err(value);
        }
        // Masked: always an index of `buf`.
        if let Some(slot) = self
            .buf
            .get_mut(self.head.wrapping_add(self.len) & Self::MASK)
        {
            *slot = value;
        }
        // Below N (not full).
        self.len = self.len.wrapping_add(1);
        Ok(())
    }

    /// Remove from the head.
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let v = *self.buf.get(self.head)?;
        self.head = self.head.wrapping_add(1) & Self::MASK;
        // Not empty (checked above).
        self.len = self.len.wrapping_sub(1);
        Some(v)
    }

    /// The value at the head, without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<T> {
        self.buf
            .get(self.head)
            .copied()
            .filter(|_| !self.is_empty())
    }

    /// Remove every value.
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_order_and_wraparound() {
        let mut r: Ring<u32, 4> = Ring::new(0);
        for round in 0..10u32 {
            for k in 0..3 {
                r.push(round * 10 + k).unwrap();
            }
            for k in 0..3 {
                assert_eq!(r.pop(), Some(round * 10 + k));
            }
        }
        assert!(r.is_empty());
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn full_ring_gives_the_value_back() {
        let mut r: Ring<u8, 2> = Ring::new(0);
        r.push(1).unwrap();
        r.push(2).unwrap();
        assert!(r.is_full());
        assert_eq!(r.push(3), Err(3));
        assert_eq!(r.peek(), Some(1));
        assert_eq!(r.len(), 2);
        r.clear();
        assert!(r.is_empty());
    }
}
