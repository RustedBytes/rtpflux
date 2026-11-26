//! Fixed-capacity storage for the agent (the crate allocates nothing).

/// Up to `N` items of `T`, in order.
#[derive(Debug, Clone, Copy)]
pub struct List<T: Copy, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T: Copy, const N: usize> List<T, N> {
    /// An empty list; `fill` initializes the unused storage.
    #[must_use]
    pub const fn new(fill: T) -> Self {
        List {
            items: [fill; N],
            len: 0,
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        // `len` <= N (`push`, `push_front`, `retain`).
        self.items.get(..self.len).unwrap_or_default()
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.items.get_mut(..self.len).unwrap_or_default()
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

    /// Append; false when full.
    pub fn push(&mut self, t: T) -> bool {
        let Some(slot) = self.items.get_mut(self.len) else {
            return false;
        };
        *slot = t;
        // Below N (`get_mut` above).
        self.len = self.len.wrapping_add(1);
        true
    }

    /// Insert at the front; false when full.
    pub fn push_front(&mut self, t: T) -> bool {
        if self.len == N {
            return false;
        }
        self.items.copy_within(..self.len, 1);
        if let Some(first) = self.items.first_mut() {
            *first = t;
        }
        // Below N (checked above).
        self.len = self.len.wrapping_add(1);
        true
    }

    /// Keep the items `f` accepts, in order.
    pub fn retain(&mut self, mut f: impl FnMut(&T) -> bool) {
        let mut kept = 0usize;
        for k in 0..self.len {
            let Some(&t) = self.items.get(k) else {
                break;
            };
            if f(&t)
                && let Some(slot) = self.items.get_mut(kept)
            {
                *slot = t;
                // At most `k` + 1.
                kept = kept.wrapping_add(1);
            }
        }
        self.len = kept;
    }

    /// Remove item `k`, moving the last one into its place; `None` (and
    /// nothing changes) when there is no item `k`.
    pub fn swap_remove(&mut self, k: usize) -> Option<T> {
        let t = *self.as_slice().get(k)?;
        // `k` < `len`, so `len` >= 1.
        self.len = self.len.wrapping_sub(1);
        let last = *self.items.get(self.len)?;
        *self.items.get_mut(k)? = last;
        Some(t)
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }

    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.as_mut_slice().iter_mut()
    }

    #[must_use]
    pub fn get(&self, k: usize) -> Option<&T> {
        self.as_slice().get(k)
    }

    pub fn get_mut(&mut self, k: usize) -> Option<&mut T> {
        self.as_mut_slice().get_mut(k)
    }
}

impl<'a, T: Copy, const N: usize> IntoIterator for &'a List<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T: Copy, const N: usize> IntoIterator for &'a mut List<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// A byte string of at most `N` bytes.
#[derive(Clone, Copy)]
pub struct Bytes<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> core::fmt::Debug for Bytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<{} bytes>", self.len)
    }
}

impl<const N: usize> Bytes<N> {
    pub const EMPTY: Self = Bytes {
        buf: [0; N],
        len: 0,
    };

    /// `None` when `s` is longer than `N`.
    #[must_use]
    pub fn new(s: &[u8]) -> Option<Self> {
        let mut b = Self::EMPTY;
        b.buf.get_mut(..s.len())?.copy_from_slice(s);
        b.len = s.len();
        Some(b)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // `len` <= N (`new`).
        self.buf.get(..self.len).unwrap_or_default()
    }
}
