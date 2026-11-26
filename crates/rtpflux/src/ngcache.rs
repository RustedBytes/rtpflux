//! The replies kept for `ng` retransmissions.
//!
//! A proxy that gets no reply sends its request again with the same cookie;
//! the relay must answer it with the same reply, not run the command a
//! second time. Replies are kept by (sender, cookie), so two proxies using
//! the same cookie never get each other's. They are kept for a while
//! (`ttl_ms`: a cookie reused later, a proxy having restarted its counter,
//! is a new request) and within a number of entries and of bytes, the
//! oldest going first.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

#[derive(Debug)]
pub struct ReplyCache<K, V> {
    entries: HashMap<K, (u64, V, usize)>,
    /// The keys, oldest first.
    order: VecDeque<K>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    ttl_ms: u64,
}

impl<K: Eq + Hash + Clone, V> ReplyCache<K, V> {
    #[must_use]
    pub fn new(max_entries: usize, max_bytes: usize, ttl_ms: u64) -> Self {
        ReplyCache {
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
            ttl_ms,
        }
    }

    /// The reply kept for `key` at `now_ms` (what is older than the TTL is
    /// forgotten first).
    pub fn get(&mut self, now_ms: u64, key: &K) -> Option<&V> {
        self.expire(now_ms);
        self.entries.get(key).map(|(_, v, _)| v)
    }

    /// Keep `value` (`size` bytes) as the reply to `key`, given at `now_ms`;
    /// the oldest go to make room.
    pub fn insert(&mut self, now_ms: u64, key: K, value: V, size: usize) {
        while !self.order.is_empty()
            && (self.entries.len() >= self.max_entries || self.bytes + size > self.max_bytes)
        {
            self.evict_oldest();
        }
        if let Some((_, _, old)) = self.entries.insert(key.clone(), (now_ms, value, size)) {
            self.bytes -= old;
            self.order.retain(|k| *k != key);
        }
        self.bytes += size;
        self.order.push_back(key);
    }

    /// The keys kept, oldest first.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.order.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn expire(&mut self, now_ms: u64) {
        while let Some(k) = self.order.front() {
            match self.entries.get(k) {
                Some((t, _, _)) if now_ms.saturating_sub(*t) < self.ttl_ms => break,
                _ => self.evict_oldest(),
            }
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(k) = self.order.pop_front()
            && let Some((_, _, size)) = self.entries.remove(&k)
        {
            self.bytes -= size;
        }
    }
}
