//! Keysets: the one thing a client holds more than one of.
//!
//! A [`StackCipher`] is scoped to a client — one ZeroKMS client, one client
//! key — and a client may use any number of keysets: one per tenant is the
//! common shape. A [`KeysetCipher`] is the cipher bound to one of them, and
//! it is what every operation that *mints* something binds to: sealing
//! values, sealing records, deriving index terms. Decrypting is not
//! keyset-scoped (a sealed leaf carries the id of the keyset it was sealed
//! under), so it lives on [`StackCipher`] as well, with the [`KeysetCipher`]
//! form adding a constraint rather than a capability — see
//! [`KeysetCipher::decrypt`].
//!
//! Keysets load lazily. [`StackCipher::keyset`] resolves an id or a name
//! through a bounded cache and loads the keyset from ZeroKMS on a miss —
//! one round trip, paid once per keyset per process (or again after
//! eviction). That is the one async point: everything on the returned
//! handle keeps its shape. The default keyset — the one named on the
//! builder, else the client's — is loaded eagerly by
//! [`init`](crate::StackCipherBuilder::init), so a misconfigured client
//! fails at startup, and never evicts.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use stack_kms::IdentifiedBy;
use uuid::Uuid;
use vitaminc_hmac::HmacSha256Prf;

use crate::StackCipher;

/// What the cipher holds per loaded keyset: its resolved id, the name it was
/// loaded under if any, and the PRF keyed by its index key.
pub(crate) struct KeysetState {
    pub(crate) id: Uuid,
    pub(crate) name: Option<String>,
    pub(crate) prf: HmacSha256Prf,
}

impl KeysetState {
    /// Whether `by` names this keyset: its id, or the name it was loaded
    /// under. A keyset loaded by id does not know its name, so a later
    /// lookup by name misses and loads again — ZeroKMS resolves the name to
    /// the same id, and the cache then holds one state under both.
    pub(crate) fn is(&self, by: &IdentifiedBy) -> bool {
        match by {
            IdentifiedBy::Uuid(id) => self.id == *id,
            IdentifiedBy::Name(name) => self.name.as_deref() == Some(&**name),
        }
    }
}

/// The bounded, least-recently-used cache of loaded keysets behind
/// [`StackCipher::keyset`].
///
/// Entries are keyed by id, with a name index beside them for keysets loaded
/// by name. Eviction drops the least recently *used* entry, where a use is
/// any lookup hit; nothing stored depends on the cache (a sealed leaf carries
/// its keyset id, and terms carry nothing), so eviction is invisible except
/// for the round trip the next lookup pays. The default keyset is not in
/// here and never evicts.
///
/// Hits are `O(1)`; an insert into a full cache scans for the oldest entry,
/// `O(n)` in the bound, which is the rare case by construction.
pub(crate) struct KeysetCache {
    capacity: NonZeroUsize,
    /// Monotonic use counter; an entry's tick is the last time it was hit.
    tick: u64,
    by_id: HashMap<Uuid, (Arc<KeysetState>, u64)>,
    by_name: HashMap<String, Uuid>,
}

impl KeysetCache {
    /// The bound a [`StackCipher`] uses unless the builder says otherwise:
    /// a thousand-tenant process pays ZeroKMS once per tenant per cold
    /// start and then not again.
    pub(crate) const DEFAULT_CAPACITY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(1023);

    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            tick: 0,
            by_id: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// Look a keyset up by id or name, marking it most recently used.
    pub(crate) fn get(&mut self, by: &IdentifiedBy) -> Option<Arc<KeysetState>> {
        let id = match by {
            IdentifiedBy::Uuid(id) => *id,
            IdentifiedBy::Name(name) => *self.by_name.get::<str>(name)?,
        };
        let (state, last_used) = self.by_id.get_mut(&id)?;
        self.tick += 1;
        *last_used = self.tick;
        Some(Arc::clone(state))
    }

    /// Insert a freshly loaded keyset, evicting the least recently used
    /// entry first if the cache is full. Loading the same keyset twice
    /// (two lookups racing on the same miss) replaces the entry with an
    /// equivalent one and adds its name if the second load knew it.
    pub(crate) fn insert(&mut self, state: Arc<KeysetState>) {
        if !self.by_id.contains_key(&state.id) && self.by_id.len() >= self.capacity.get() {
            self.evict_oldest();
        }
        if let Some(name) = &state.name {
            let _ = self.by_name.insert(name.clone(), state.id);
        }
        self.tick += 1;
        let _ = self.by_id.insert(state.id, (state, self.tick));
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .by_id
            .iter()
            .min_by_key(|(_, (_, tick))| *tick)
            .map(|(id, _)| *id)
        else {
            return;
        };
        if let Some((state, _)) = self.by_id.remove(&oldest) {
            if let Some(name) = &state.name {
                let _ = self.by_name.remove(name);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// A [`StackCipher`] bound to one keyset: what sealing and term derivation
/// bind to, and what a decrypt that must stay within one keyset binds to.
///
/// Obtained from [`StackCipher::keyset`] (any keyset, loaded on first use)
/// or [`StackCipher::default_keyset`]. Cheap to clone and to hold: a
/// reference to the cipher plus a shared handle on the keyset's loaded
/// state, so a request handler can take one per tenant and hand it around.
///
/// The type a caller holds states the guarantee it gets. A `KeysetCipher`
/// for tenant A mints every data key under A's keyset, derives every term
/// under A's index key, and refuses — before any ZeroKMS call — to open a
/// leaf sealed under any other keyset ([`Error::ForeignKeyset`]). The
/// [`StackCipher`] it came from opens leaves from any keyset the client
/// is authorised for.
///
/// [`Error::ForeignKeyset`]: crate::Error::ForeignKeyset
pub struct KeysetCipher<'k, K> {
    cipher: &'k StackCipher<K>,
    state: Arc<KeysetState>,
}

impl<K> Clone for KeysetCipher<'_, K> {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher,
            state: Arc::clone(&self.state),
        }
    }
}

impl<'k, K> KeysetCipher<'k, K> {
    pub(crate) fn new(cipher: &'k StackCipher<K>, state: Arc<KeysetState>) -> Self {
        Self { cipher, state }
    }

    /// The client-scoped cipher this keyset belongs to.
    pub fn cipher(&self) -> &'k StackCipher<K> {
        self.cipher
    }

    /// The keyset every data key this handle mints is generated under, and
    /// whose index key keys [`prf`](Self::prf). Resolved: a keyset selected
    /// by name reports its id here.
    pub fn keyset_id(&self) -> Uuid {
        self.state.id
    }

    /// The name this keyset was selected by, if it was selected by name
    /// (the default keyset knows its name only when the builder named it).
    pub fn keyset_name(&self) -> Option<&str> {
        self.state.name.as_deref()
    }

    /// The PRF index terms are derived from, keyed by this keyset's index
    /// key.
    ///
    /// Public so that other crates can implement their own term types
    /// against this cipher (see [`crate::sem`]).
    pub fn prf(&self) -> &HmacSha256Prf {
        &self.state.prf
    }

    /// The underlying data-key source.
    pub fn kms(&self) -> &'k K {
        self.cipher.kms()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use vitaminc_prf::PrfKeyInit;
    use vitaminc_protected::Protected;

    fn state(id: u128, name: Option<&str>) -> Arc<KeysetState> {
        Arc::new(KeysetState {
            id: Uuid::from_u128(id),
            name: name.map(str::to_owned),
            prf: HmacSha256Prf::new(Protected::new([id as u8; 32])),
        })
    }

    fn name(name: &str) -> IdentifiedBy {
        IdentifiedBy::Name(name.to_string().into())
    }

    fn cache(capacity: usize) -> KeysetCache {
        KeysetCache::new(NonZeroUsize::new(capacity).unwrap())
    }

    #[test]
    fn a_keyset_is_found_by_id_and_by_the_name_it_loaded_under() {
        let mut cache = cache(4);
        cache.insert(state(1, Some("customers")));

        assert!(cache.get(&Uuid::from_u128(1).into()).is_some());
        assert!(cache.get(&name("customers")).is_some());
        assert!(cache.get(&name("staff")).is_none());
        assert!(cache.get(&Uuid::from_u128(2).into()).is_none());
    }

    #[test]
    fn a_keyset_loaded_by_id_is_not_found_by_name() {
        let mut cache = cache(4);
        cache.insert(state(1, None));

        assert!(cache.get(&Uuid::from_u128(1).into()).is_some());
        assert!(cache.get(&name("customers")).is_none());
    }

    #[test]
    fn the_least_recently_used_keyset_is_evicted_first() {
        let mut cache = cache(2);
        cache.insert(state(1, Some("one")));
        cache.insert(state(2, Some("two")));
        // Touch 1 so 2 is the oldest.
        assert!(cache.get(&Uuid::from_u128(1).into()).is_some());

        cache.insert(state(3, Some("three")));

        assert_eq!(cache.len(), 2);
        assert!(
            cache.get(&Uuid::from_u128(2).into()).is_none(),
            "2 was oldest"
        );
        assert!(
            cache.get(&name("two")).is_none(),
            "the evicted keyset's name goes with it"
        );
        assert!(cache.get(&Uuid::from_u128(1).into()).is_some());
        assert!(cache.get(&Uuid::from_u128(3).into()).is_some());
    }

    #[test]
    fn reinserting_a_cached_keyset_does_not_evict() {
        let mut cache = cache(2);
        cache.insert(state(1, None));
        cache.insert(state(2, None));

        // Same id again, now with a name: replaces, evicts nothing.
        cache.insert(state(1, Some("one")));

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&Uuid::from_u128(2).into()).is_some());
        assert!(cache.get(&name("one")).is_some());
    }

    #[test]
    fn a_cache_of_one_holds_the_latest_keyset() {
        let mut cache = cache(1);
        cache.insert(state(1, None));
        cache.insert(state(2, None));

        assert_eq!(cache.len(), 1);
        assert!(cache.get(&Uuid::from_u128(1).into()).is_none());
        assert!(cache.get(&Uuid::from_u128(2).into()).is_some());
    }

    #[test]
    fn state_matches_its_id_and_its_name() {
        let named = state(1, Some("customers"));
        assert!(named.is(&Uuid::from_u128(1).into()));
        assert!(named.is(&name("customers")));
        assert!(!named.is(&name("staff")));
        assert!(!named.is(&Uuid::from_u128(2).into()));

        let anonymous = state(1, None);
        assert!(anonymous.is(&Uuid::from_u128(1).into()));
        assert!(!anonymous.is(&name("customers")));
    }
}
