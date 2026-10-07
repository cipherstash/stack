//! The per-JWT cache behind [`OidcFederationStrategy`](super::OidcFederationStrategy):
//! a bounded map from a JWT's digest to that user's refresh engine, least
//! recently used out first.
//!
//! Hand-rolled rather than a crate: the policy is forty lines, needs no
//! `unsafe`, and the crate is built for `wasm32-wasip1` and
//! `wasm32-unknown-unknown` with a deliberately small dependency graph.
//! Eviction scans the map (`O(capacity)`), which at the default capacity of
//! 1024 is a few microseconds, paid only on an insert at capacity.

use std::collections::HashMap;

use crate::oidc_refresher::JwtDigest;

/// A bounded, least-recently-used map from JWT digest to engine handle.
///
/// Generic over the handle `T` (an `Arc<AutoRefresh<..>>` in the strategy)
/// so the policy can be tested without building one.
pub(super) struct JwtCache<T> {
    capacity: usize,
    /// A logical clock, bumped on every lookup: the entry with the smallest
    /// stamp is the least recently used one.
    tick: u64,
    entries: HashMap<JwtDigest, Entry<T>>,
}

struct Entry<T> {
    handle: T,
    last_used: u64,
}

impl<T: Clone> JwtCache<T> {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            entries: HashMap::new(),
        }
    }

    /// The handle for `digest`, if there is one; a hit makes it the most
    /// recently used.
    pub(super) fn get(&mut self, digest: JwtDigest) -> Option<T> {
        self.tick += 1;
        let entry = self.entries.get_mut(&digest)?;
        entry.last_used = self.tick;
        Some(entry.handle.clone())
    }

    /// Retain `handle` for `digest` while there is room: at capacity, the
    /// least recently used entry makes way for it, and with a capacity of
    /// zero nothing is retained at all.
    pub(super) fn insert(&mut self, digest: JwtDigest, handle: T) {
        if self.capacity == 0 {
            return;
        }
        self.tick += 1;
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&digest) {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(digest, _)| *digest);
            if let Some(victim) = victim {
                tracing::debug!(
                    capacity = self.capacity,
                    "JWT cache is full; dropping the least recently used JWT's token"
                );
                let _ = self.entries.remove(&victim);
            }
        }
        let _ = self.entries.insert(
            digest,
            Entry {
                handle,
                last_used: self.tick,
            },
        );
    }

    /// Drop the entry for `digest` if `is_it` says the cached handle is the
    /// one the caller means, so a handle that has since been replaced is left
    /// alone.
    pub(super) fn remove_if(&mut self, digest: JwtDigest, is_it: impl FnOnce(&T) -> bool) {
        if self
            .entries
            .get(&digest)
            .is_some_and(|entry| is_it(&entry.handle))
        {
            let _ = self.entries.remove(&digest);
        }
    }

    /// How many digests currently have a cached handle.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretToken;

    fn digest(jwt: &str) -> JwtDigest {
        JwtDigest::of(&SecretToken::new(jwt))
    }

    fn last_used(cache: &JwtCache<u32>, jwt: &str) -> Option<u64> {
        cache.entries.get(&digest(jwt)).map(|entry| entry.last_used)
    }

    /// The clock advances by one per lookup, hit or insert, and a hit restamps
    /// its entry; that is what makes "least recently used" mean used, not
    /// inserted.
    #[test]
    fn every_lookup_advances_the_clock_and_a_hit_restamps_the_entry() {
        let mut cache = JwtCache::new(8);
        assert_eq!(cache.get(digest("a")), None, "a miss returns nothing");
        cache.insert(digest("a"), 1);
        cache.insert(digest("b"), 2);
        assert_eq!(
            (last_used(&cache, "a"), last_used(&cache, "b")),
            (Some(2), Some(3))
        );

        assert_eq!(
            cache.get(digest("a")),
            Some(1),
            "a hit returns the cached handle"
        );
        assert_eq!(cache.tick, 4);
        assert_eq!(last_used(&cache, "a"), Some(4), "a hit restamps");
        assert_eq!(
            last_used(&cache, "b"),
            Some(3),
            "an untouched entry keeps its stamp"
        );
    }

    /// At capacity the entry with the smallest stamp goes: with room for two,
    /// touching A before C arrives keeps A and evicts B.
    #[test]
    fn at_capacity_the_least_recently_used_entry_is_evicted() {
        let mut cache = JwtCache::new(2);
        cache.insert(digest("a"), 1);
        cache.insert(digest("b"), 2);
        let _ = cache.get(digest("a"));
        cache.insert(digest("c"), 3);
        assert_eq!(cache.len(), 2);
        assert_eq!(last_used(&cache, "a"), Some(3));
        assert_eq!(
            last_used(&cache, "b"),
            None,
            "b was the least recently used"
        );
        assert_eq!(last_used(&cache, "c"), Some(4));
    }

    /// Re-inserting a digest that is already cached replaces its handle and
    /// evicts nothing, even at capacity.
    #[test]
    fn inserting_a_cached_digest_replaces_without_evicting() {
        let mut cache = JwtCache::new(2);
        cache.insert(digest("a"), 1);
        cache.insert(digest("b"), 2);
        cache.insert(digest("a"), 10);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(digest("a")), Some(10));
        assert_eq!(cache.get(digest("b")), Some(2), "b survived the re-insert");
    }

    /// Capacity zero retains nothing.
    #[test]
    fn a_zero_capacity_cache_retains_nothing() {
        let mut cache = JwtCache::new(0);
        cache.insert(digest("a"), 1);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get(digest("a")), None);
    }

    /// `remove_if` drops the entry only when the predicate recognises the
    /// cached handle, so a caller holding a stale handle cannot evict its
    /// replacement.
    #[test]
    fn remove_if_drops_only_the_handle_it_is_shown() {
        let mut cache = JwtCache::new(8);
        cache.insert(digest("a"), 1);
        cache.insert(digest("b"), 2);

        cache.remove_if(digest("a"), |handle| *handle == 99);
        assert_eq!(
            cache.len(),
            2,
            "a predicate that does not match removes nothing"
        );

        cache.remove_if(digest("a"), |handle| *handle == 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(last_used(&cache, "a"), None);
        assert_eq!(
            last_used(&cache, "b"),
            Some(2),
            "the other entry is untouched"
        );

        cache.remove_if(digest("zzz"), |_| true);
        assert_eq!(cache.len(), 1, "an absent digest is a no-op");
    }
}
