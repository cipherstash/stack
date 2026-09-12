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
//!
//! # Ids are identity; names are looked up
//!
//! A keyset's id is its identity: a sealed leaf carries it, and an id
//! selection never needs re-checking. A name is a lookup ZeroKMS answers,
//! and ZeroKMS lets a keyset be renamed, so a name the cipher resolved
//! earlier can point at a different keyset later. The cache therefore
//! treats a name-to-id binding as fresh for a bounded time
//! ([`DEFAULT_NAME_TTL`], `StackCipherBuilder::keyset_name_ttl`) and
//! re-asks ZeroKMS after that — the way a resolver treats a DNS record.
//! Within the window a rename is invisible; a `Duration::ZERO` window makes
//! every name selection a round trip. The default keyset's builder-time
//! name is bound the same way: after the window, selecting it by name asks
//! ZeroKMS again.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use stack_kms::IdentifiedBy;
use uuid::Uuid;
use vitaminc_hmac::HmacSha256Prf;

use crate::StackCipher;

/// How long a name-to-id binding is trusted before a selection by that
/// name asks ZeroKMS again. Five minutes bounds how long a rename can go
/// unnoticed by a running process; `StackCipherBuilder::keyset_name_ttl`
/// changes it.
pub const DEFAULT_NAME_TTL: Duration = Duration::from_secs(5 * 60);

/// What the cipher holds per loaded keyset: its resolved id, the name it was
/// loaded under if any, and the PRF keyed by its index key.
pub(crate) struct KeysetState {
    pub(crate) id: Uuid,
    pub(crate) name: Option<String>,
    pub(crate) prf: HmacSha256Prf,
}

/// A loaded keyset in the cache, with every name it has been resolved
/// under — kept across replacement so a name bound to this id is dropped
/// when the id is evicted, however the entry was last loaded.
struct Entry {
    state: Arc<KeysetState>,
    last_used: u64,
    names: Vec<String>,
}

/// A name-to-id binding, and when ZeroKMS last confirmed it.
struct Alias {
    id: Uuid,
    resolved_at: Instant,
}

/// What a lookup found.
pub(crate) enum Lookup {
    /// A loaded keyset, and (for a name) a binding within its window.
    Hit(Arc<KeysetState>),
    /// A name binding past its window (the keyset it named may still be
    /// loaded, but whether the name still means it is ZeroKMS's to say): the
    /// caller re-resolves the name with ZeroKMS and [`insert`]s the result,
    /// which refreshes the binding — or moves it, if the name did.
    ///
    /// [`insert`]: KeysetCache::insert
    Stale,
    /// Nothing loaded for this id, or no binding for this name.
    Miss,
}

/// The bounded, least-recently-used cache of loaded keysets behind
/// [`StackCipher::keyset`].
///
/// Entries are keyed by id, with a name index beside them for the names
/// each id has been resolved under. Eviction drops the least recently
/// *used* entry, where a use is any lookup hit, together with every name
/// bound to it; nothing stored depends on the cache (a sealed leaf carries
/// its keyset id, and terms carry nothing), so eviction is invisible except
/// for the round trip the next lookup pays. The default keyset is held
/// apart and never evicts, though its name binding ages like any other.
///
/// Hits are `O(1)`; an insert into a full cache scans for the oldest entry,
/// `O(n)` in the bound, which is the rare case by construction. The name
/// index is bounded by the entries it serves: every binding names either
/// the default or a cached id, and goes when that id does.
pub(crate) struct KeysetCache {
    capacity: NonZeroUsize,
    name_ttl: Duration,
    /// Monotonic use counter; an entry's tick is the last time it was hit.
    tick: u64,
    default: Arc<KeysetState>,
    by_id: HashMap<Uuid, Entry>,
    by_name: HashMap<String, Alias>,
}

impl KeysetCache {
    /// The bound a [`StackCipher`] uses unless the builder says otherwise:
    /// a thousand-tenant process pays ZeroKMS once per tenant per cold
    /// start and then not again.
    pub(crate) const DEFAULT_CAPACITY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(1023);

    /// A cache holding `default` apart from the bound; its builder-time
    /// name, if any, is bound now.
    pub(crate) fn new(
        capacity: NonZeroUsize,
        name_ttl: Duration,
        default: Arc<KeysetState>,
    ) -> Self {
        let mut by_name = HashMap::new();
        if let Some(name) = &default.name {
            let _ = by_name.insert(
                name.clone(),
                Alias {
                    id: default.id,
                    resolved_at: Instant::now(),
                },
            );
        }
        Self {
            capacity,
            name_ttl,
            tick: 0,
            default,
            by_id: HashMap::new(),
            by_name,
        }
    }

    /// Look a keyset up by id or name, marking it most recently used.
    pub(crate) fn get(&mut self, by: &IdentifiedBy) -> Lookup {
        let (id, fresh) = match by {
            IdentifiedBy::Uuid(id) => (*id, true),
            IdentifiedBy::Name(name) => match self.by_name.get::<str>(name) {
                Some(alias) => (alias.id, alias.resolved_at.elapsed() <= self.name_ttl),
                None => return Lookup::Miss,
            },
        };
        let state = if id == self.default.id {
            Arc::clone(&self.default)
        } else {
            match self.by_id.get_mut(&id) {
                Some(entry) => {
                    self.tick += 1;
                    entry.last_used = self.tick;
                    Arc::clone(&entry.state)
                }
                None => return Lookup::Miss,
            }
        };
        if fresh {
            Lookup::Hit(state)
        } else {
            Lookup::Stale
        }
    }

    /// Record a keyset ZeroKMS just resolved, evicting the least recently
    /// used entry first if the cache is full and the id is new. The name it
    /// was resolved under (if any) is bound to its id as of now — refreshing
    /// a binding that had aged, or moving one whose keyset was renamed — and
    /// every name an existing entry already carried is kept, so no binding
    /// outlives the id it names. Resolving the default keyset again only
    /// refreshes its binding: its state is never replaced.
    pub(crate) fn insert(&mut self, state: Arc<KeysetState>) {
        if let Some(name) = &state.name {
            let _ = self.by_name.insert(
                name.clone(),
                Alias {
                    id: state.id,
                    resolved_at: Instant::now(),
                },
            );
        }
        if state.id == self.default.id {
            return;
        }
        if !self.by_id.contains_key(&state.id) && self.by_id.len() >= self.capacity.get() {
            self.evict_oldest();
        }
        self.tick += 1;
        match self.by_id.get_mut(&state.id) {
            Some(entry) => {
                if let Some(name) = &state.name {
                    if !entry.names.contains(name) {
                        entry.names.push(name.clone());
                    }
                }
                entry.state = state;
                entry.last_used = self.tick;
            }
            None => {
                let names = state.name.iter().cloned().collect();
                let _ = self.by_id.insert(
                    state.id,
                    Entry {
                        state,
                        last_used: self.tick,
                        names,
                    },
                );
            }
        }
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .by_id
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(id, _)| *id)
        else {
            return;
        };
        if let Some(entry) = self.by_id.remove(&oldest) {
            for name in entry.names {
                // A name that has since moved to another id keeps its
                // binding: only this id's bindings go with it.
                if self
                    .by_name
                    .get(&name)
                    .is_some_and(|alias| alias.id == oldest)
                {
                    let _ = self.by_name.remove(&name);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }

    #[cfg(test)]
    pub(crate) fn names(&self) -> usize {
        self.by_name.len()
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
    /// A label from the time of selection, not an identity: see the
    /// [module docs](self#ids-are-identity-names-are-looked-up).
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

    fn id(id: u128) -> IdentifiedBy {
        IdentifiedBy::Uuid(Uuid::from_u128(id))
    }

    /// A cache whose default is keyset 0 (unnamed) and whose name window
    /// never closes.
    fn cache(capacity: usize) -> KeysetCache {
        KeysetCache::new(
            NonZeroUsize::new(capacity).unwrap(),
            Duration::MAX,
            state(0, None),
        )
    }

    fn hit(lookup: Lookup) -> Option<Uuid> {
        match lookup {
            Lookup::Hit(state) => Some(state.id),
            Lookup::Stale | Lookup::Miss => None,
        }
    }

    #[test]
    fn a_keyset_is_found_by_id_and_by_the_name_it_loaded_under() {
        let mut cache = cache(4);
        cache.insert(state(1, Some("customers")));

        assert_eq!(hit(cache.get(&id(1))), Some(Uuid::from_u128(1)));
        assert_eq!(hit(cache.get(&name("customers"))), Some(Uuid::from_u128(1)));
        assert!(matches!(cache.get(&name("staff")), Lookup::Miss));
        assert!(matches!(cache.get(&id(2)), Lookup::Miss));
    }

    #[test]
    fn a_keyset_loaded_by_id_is_not_found_by_name() {
        let mut cache = cache(4);
        cache.insert(state(1, None));

        assert!(matches!(cache.get(&id(1)), Lookup::Hit(_)));
        assert!(matches!(cache.get(&name("customers")), Lookup::Miss));
    }

    #[test]
    fn the_default_is_found_by_id_and_its_builder_name_but_never_stored() {
        let mut cache = KeysetCache::new(
            NonZeroUsize::new(1).unwrap(),
            Duration::MAX,
            state(0, Some("primary")),
        );
        assert_eq!(hit(cache.get(&id(0))), Some(Uuid::from_u128(0)));
        assert_eq!(hit(cache.get(&name("primary"))), Some(Uuid::from_u128(0)));

        // Filling the one slot evicts nothing of the default's.
        cache.insert(state(1, None));
        cache.insert(state(2, None));
        assert_eq!(cache.len(), 1);
        assert_eq!(hit(cache.get(&id(0))), Some(Uuid::from_u128(0)));
        assert_eq!(hit(cache.get(&name("primary"))), Some(Uuid::from_u128(0)));

        // Re-resolving the default by name refreshes its binding, and does
        // not put a second copy of it in the bounded part.
        cache.insert(state(0, Some("primary")));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn the_least_recently_used_keyset_is_evicted_with_its_names() {
        let mut cache = cache(2);
        cache.insert(state(1, Some("one")));
        cache.insert(state(2, Some("two")));
        // Touch 1 so 2 is the oldest.
        assert!(matches!(cache.get(&id(1)), Lookup::Hit(_)));

        cache.insert(state(3, Some("three")));

        assert_eq!(cache.len(), 2);
        assert!(matches!(cache.get(&id(2)), Lookup::Miss), "2 was oldest");
        assert!(
            matches!(cache.get(&name("two")), Lookup::Miss),
            "the evicted keyset's name goes with it"
        );
        assert!(matches!(cache.get(&id(1)), Lookup::Hit(_)));
        assert!(matches!(cache.get(&id(3)), Lookup::Hit(_)));
    }

    /// The order two cold lookups on the same keyset can land in: by name
    /// first, then by id. The id load carries no name, but must not shed
    /// the binding the name load made — or eviction would later leave that
    /// binding pointing at an id the cache no longer holds.
    #[test]
    fn a_reload_by_id_keeps_the_names_a_keyset_was_bound_under() {
        let mut cache = cache(1);
        cache.insert(state(1, Some("one")));
        cache.insert(state(1, None));
        assert_eq!(cache.len(), 1);
        assert_eq!(hit(cache.get(&name("one"))), Some(Uuid::from_u128(1)));

        // Evicting 1 takes "one" with it, whichever load was last.
        cache.insert(state(2, None));
        assert!(matches!(cache.get(&id(1)), Lookup::Miss));
        assert!(matches!(cache.get(&name("one")), Lookup::Miss));
        assert_eq!(cache.names(), 0);

        // And reloading 1 by id does not resurrect the binding.
        cache.insert(state(1, None));
        assert!(matches!(cache.get(&name("one")), Lookup::Miss));
    }

    /// Bindings never outnumber the keysets they name: churning names
    /// through a one-slot cache leaves one binding, not a thousand.
    #[test]
    fn the_name_index_is_bounded_by_the_cache() {
        let mut cache = cache(1);
        for i in 1..=1000u128 {
            cache.insert(state(i, Some(&format!("tenant-{i}"))));
            cache.insert(state(i, None));
        }
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.names(), 1);
        assert_eq!(
            hit(cache.get(&name("tenant-1000"))),
            Some(Uuid::from_u128(1000))
        );
    }

    /// A keyset resolved under two names carries both, and both go when it
    /// does.
    #[test]
    fn a_keyset_can_be_bound_under_several_names() {
        let mut cache = cache(1);
        cache.insert(state(1, Some("one")));
        cache.insert(state(1, Some("uno")));
        assert_eq!(hit(cache.get(&name("one"))), Some(Uuid::from_u128(1)));
        assert_eq!(hit(cache.get(&name("uno"))), Some(Uuid::from_u128(1)));

        cache.insert(state(2, None));
        assert_eq!(cache.names(), 0);
    }

    /// A rename: the name now resolves to another id. The binding moves,
    /// and evicting the id it used to name does not take it away.
    #[test]
    fn a_name_that_moved_to_another_keyset_follows_it() {
        let mut cache = cache(2);
        cache.insert(state(1, Some("acme")));
        cache.insert(state(2, Some("acme")));
        assert_eq!(hit(cache.get(&name("acme"))), Some(Uuid::from_u128(2)));

        // Evict 1 (the oldest): "acme" belongs to 2 now and stays.
        assert!(matches!(cache.get(&id(2)), Lookup::Hit(_)));
        cache.insert(state(3, None));
        assert!(matches!(cache.get(&id(1)), Lookup::Miss));
        assert_eq!(hit(cache.get(&name("acme"))), Some(Uuid::from_u128(2)));
    }

    /// Past the window a name lookup is stale — the keyset is still there,
    /// the binding is not trusted — and a re-resolution refreshes it.
    #[test]
    fn a_name_binding_ages_out_and_is_refreshed_by_reinsertion() {
        let mut cache = KeysetCache::new(
            NonZeroUsize::new(4).unwrap(),
            Duration::ZERO,
            state(0, Some("primary")),
        );
        cache.insert(state(1, Some("one")));

        assert!(matches!(cache.get(&name("one")), Lookup::Stale));
        assert!(matches!(cache.get(&name("primary")), Lookup::Stale));
        assert!(
            matches!(cache.get(&id(1)), Lookup::Hit(_)),
            "an id never ages"
        );

        // A zero window is stale again immediately after a refresh, which is
        // the point of a zero window; a wide one is fresh.
        cache.insert(state(1, Some("one")));
        assert!(matches!(cache.get(&name("one")), Lookup::Stale));
        cache.name_ttl = Duration::MAX;
        assert!(matches!(cache.get(&name("one")), Lookup::Hit(_)));
    }
}
