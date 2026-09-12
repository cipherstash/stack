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
//!
//! A keyset has one name at a time in ZeroKMS, so the cache keeps one name
//! per keyset: resolving a keyset under a new name means its old name was
//! renamed away, and that binding goes. And because resolutions run outside
//! the lock, their answers can land in any order; a binding follows the
//! *later lookup*, whichever answer arrives first, so an answer from before
//! a rename cannot overwrite one from after it — neither under the same
//! name, nor by taking back the name the keyset has since left, nor by
//! arriving after eviction has dropped the binding it would have lost to.

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

/// A loaded keyset in the cache, with the name it is currently bound under
/// if any — kept across replacement so the binding is dropped when the id
/// is evicted, however the entry was last loaded — and the lookup whose
/// answer last spoke for it.
struct Entry {
    state: Arc<KeysetState>,
    last_used: u64,
    name: Option<String>,
    resolution: Resolution,
}

/// A name-to-id binding: when ZeroKMS last confirmed it, and which lookup
/// asked.
struct Alias {
    id: Uuid,
    resolved_at: Instant,
    resolution: Resolution,
}

/// A lookup's place in the order of lookups that went to ZeroKMS. The
/// caller carries it from [`get`](KeysetCache::get) to
/// [`insert`](KeysetCache::insert), where an answer is applied only if it is
/// later than the one that already spoke for that keyset, and its name only
/// if it is later than the one that produced that name's binding — answers
/// land in any order, and a later question has the later answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Resolution(u64);

/// What a lookup found.
pub(crate) enum Lookup {
    /// A loaded keyset, and (for a name) a binding within its window.
    Hit(Arc<KeysetState>),
    /// A name binding past its window (the keyset it named may still be
    /// loaded, but whether the name still means it is ZeroKMS's to say): the
    /// caller re-resolves the name with ZeroKMS and [`insert`]s the result
    /// with this ticket, which refreshes the binding — or moves it, if the
    /// name did.
    ///
    /// [`insert`]: KeysetCache::insert
    Stale(Resolution),
    /// Nothing loaded for this id, or no binding for this name: the caller
    /// loads it and [`insert`]s the result with this ticket.
    ///
    /// [`insert`]: KeysetCache::insert
    Miss(Resolution),
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
/// index is bounded by the entries it serves: one binding per cached id at
/// most, plus the default's, and a binding goes when its id does or when
/// the keyset is resolved under another name. What an evicted binding
/// leaves behind is one watermark, not a record per name: see
/// [`evicted_binding`](Self::evicted_binding).
pub(crate) struct KeysetCache {
    capacity: NonZeroUsize,
    name_ttl: Duration,
    /// Monotonic use counter; an entry's tick is the last time it was hit.
    tick: u64,
    /// Monotonic lookup counter; see [`Resolution`].
    resolutions: u64,
    default: Arc<KeysetState>,
    /// The name the default is currently bound under, if any: its
    /// builder-time name until a resolution binds it under another.
    default_name: Option<String>,
    /// The lookup whose answer last spoke for the default; the builder's
    /// own for a cipher that has resolved nothing yet.
    default_resolution: Resolution,
    /// The latest lookup whose name binding eviction dropped.
    ///
    /// A keyset carries the order of the answers that spoke for it; evicting
    /// it drops that with the rest of the entry, and an answer older than the
    /// binding that went would then find nothing left to say it is the older
    /// one. So no binding is made from an answer older than this. It is one
    /// watermark for all names rather than one per forgotten name — a cache
    /// whose whole contract is a bound must not grow a record per name it has
    /// evicted — so it also refuses some bindings an older lookup could have
    /// made safely. That costs a round trip on the next selection by such a
    /// name, in the eviction regime that is already paying them.
    evicted_binding: Resolution,
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
                    resolution: Resolution(0),
                },
            );
        }
        Self {
            capacity,
            name_ttl,
            tick: 0,
            resolutions: 0,
            default_name: default.name.clone(),
            default_resolution: Resolution(0),
            evicted_binding: Resolution(0),
            default,
            by_id: HashMap::new(),
            by_name,
        }
    }

    /// The ticket for a lookup that is about to go to ZeroKMS.
    fn resolution(&mut self) -> Resolution {
        self.resolutions += 1;
        Resolution(self.resolutions)
    }

    /// Look a keyset up by id or name, marking it most recently used.
    pub(crate) fn get(&mut self, by: &IdentifiedBy) -> Lookup {
        let (id, fresh) = match by {
            IdentifiedBy::Uuid(id) => (*id, true),
            IdentifiedBy::Name(name) => match self.by_name.get::<str>(name) {
                // Strictly within the window: a zero window is never fresh,
                // whatever the clock's resolution.
                Some(alias) => (alias.id, alias.resolved_at.elapsed() < self.name_ttl),
                None => return Lookup::Miss(self.resolution()),
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
                None => return Lookup::Miss(self.resolution()),
            }
        };
        if fresh {
            Lookup::Hit(state)
        } else {
            Lookup::Stale(self.resolution())
        }
    }

    /// Record a keyset ZeroKMS just resolved for the lookup `resolution`,
    /// evicting the least recently used entry first if the cache is full
    /// and the id is new. Resolving the default keyset again never replaces
    /// its state.
    ///
    /// The name it was resolved under (if any) is bound to its id as of now
    /// — refreshing a binding that had aged, or moving one whose keyset was
    /// renamed — unless a later lookup has already bound that name, in
    /// which case this answer is the older one and the binding stands. A
    /// keyset has one name, so binding it under a new name drops the old
    /// one; and a name that moved to this keyset is dropped from the keyset
    /// it used to name. No binding outlives the id it names.
    ///
    /// An answer older than the one this keyset already holds is dropped
    /// whole. It has nothing newer to say about the keyset, and applying it
    /// would undo what a later lookup applied — restoring, under a full
    /// window, a name the keyset has since been renamed away from.
    pub(crate) fn insert(&mut self, state: Arc<KeysetState>, resolution: Resolution) {
        if self
            .last_resolution_of(state.id)
            .is_some_and(|applied| applied > resolution)
        {
            return;
        }
        let bound = match &state.name {
            Some(name) => self.bind(name, state.id, resolution),
            None => false,
        };
        if state.id == self.default.id {
            self.default_resolution = resolution;
            return;
        }
        if !self.by_id.contains_key(&state.id) && self.by_id.len() >= self.capacity.get() {
            self.evict_oldest();
        }
        self.tick += 1;
        match self.by_id.get_mut(&state.id) {
            Some(entry) => {
                if bound {
                    entry.name.clone_from(&state.name);
                }
                entry.state = state;
                entry.last_used = self.tick;
                entry.resolution = resolution;
            }
            None => {
                let name = bound.then(|| state.name.clone()).flatten();
                let _ = self.by_id.insert(
                    state.id,
                    Entry {
                        state,
                        last_used: self.tick,
                        name,
                        resolution,
                    },
                );
            }
        }
    }

    /// Bind `name` to `id` for the lookup `resolution`; false if a later
    /// lookup already bound it, or if eviction has since dropped a binding
    /// this answer is older than ([`evicted_binding`]). Also unbinds the name
    /// this id was bound under before, and unbinds this name from the id it
    /// named before.
    ///
    /// [`evicted_binding`]: Self::evicted_binding
    fn bind(&mut self, name: &str, id: Uuid, resolution: Resolution) -> bool {
        if resolution < self.evicted_binding {
            return false;
        }
        if let Some(alias) = self.by_name.get(name) {
            if alias.resolution > resolution {
                return false;
            }
            if alias.id != id {
                self.forget_name_of(alias.id, name);
            }
        }
        if let Some(previous) = self.current_name_of(id) {
            if previous != name {
                let _ = self.by_name.remove(&previous);
            }
        }
        let _ = self.by_name.insert(
            name.to_owned(),
            Alias {
                id,
                resolved_at: Instant::now(),
                resolution,
            },
        );
        if id == self.default.id {
            self.default_name = Some(name.to_owned());
        }
        true
    }

    /// The lookup whose answer last spoke for `id`, if the cache holds it.
    /// An id it has never held (or has evicted) has nothing to supersede.
    fn last_resolution_of(&self, id: Uuid) -> Option<Resolution> {
        if id == self.default.id {
            Some(self.default_resolution)
        } else {
            self.by_id.get(&id).map(|entry| entry.resolution)
        }
    }

    /// The name `id` is currently bound under, if any.
    fn current_name_of(&self, id: Uuid) -> Option<String> {
        if id == self.default.id {
            self.default_name.clone()
        } else {
            self.by_id.get(&id).and_then(|entry| entry.name.clone())
        }
    }

    /// `name` moved away from `id`: the id no longer claims it.
    fn forget_name_of(&mut self, id: Uuid, name: &str) {
        if id == self.default.id {
            if self.default_name.as_deref() == Some(name) {
                self.default_name = None;
            }
        } else if let Some(entry) = self.by_id.get_mut(&id) {
            if entry.name.as_deref() == Some(name) {
                entry.name = None;
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
            if let Some(name) = entry.name {
                // A name that has since moved to another id keeps its
                // binding: only this id's binding goes with it. Its place in
                // the order of lookups outlives it as a watermark, so an
                // answer older than it cannot bind a name once there is no
                // entry left to order it against.
                if let Some(alias) = self.by_name.get(&name) {
                    if alias.id == oldest {
                        self.evicted_binding = self.evicted_binding.max(alias.resolution);
                        let _ = self.by_name.remove(&name);
                    }
                }
            }
        }
    }

    /// Insert as a fresh, in-order resolution — what every test that is not
    /// about ordering wants.
    #[cfg(test)]
    pub(crate) fn load(&mut self, state: Arc<KeysetState>) {
        let resolution = self.resolution();
        self.insert(state, resolution);
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
            Lookup::Stale(_) | Lookup::Miss(_) => None,
        }
    }

    fn ticket(lookup: Lookup) -> Resolution {
        match lookup {
            Lookup::Stale(r) | Lookup::Miss(r) => r,
            Lookup::Hit(_) => panic!("expected a lookup that goes to ZeroKMS"),
        }
    }

    #[test]
    fn a_keyset_is_found_by_id_and_by_the_name_it_loaded_under() {
        let mut cache = cache(4);
        cache.load(state(1, Some("customers")));

        assert_eq!(hit(cache.get(&id(1))), Some(Uuid::from_u128(1)));
        assert_eq!(hit(cache.get(&name("customers"))), Some(Uuid::from_u128(1)));
        assert!(matches!(cache.get(&name("staff")), Lookup::Miss(_)));
        assert!(matches!(cache.get(&id(2)), Lookup::Miss(_)));
    }

    #[test]
    fn a_keyset_loaded_by_id_is_not_found_by_name() {
        let mut cache = cache(4);
        cache.load(state(1, None));

        assert!(matches!(cache.get(&id(1)), Lookup::Hit(_)));
        assert!(matches!(cache.get(&name("customers")), Lookup::Miss(_)));
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
        cache.load(state(1, None));
        cache.load(state(2, None));
        assert_eq!(cache.len(), 1);
        assert_eq!(hit(cache.get(&id(0))), Some(Uuid::from_u128(0)));
        assert_eq!(hit(cache.get(&name("primary"))), Some(Uuid::from_u128(0)));

        // Re-resolving the default by name refreshes its binding, and does
        // not put a second copy of it in the bounded part.
        cache.load(state(0, Some("primary")));
        assert_eq!(cache.len(), 1);

        // The default renamed: its old name no longer selects it.
        cache.load(state(0, Some("main")));
        assert_eq!(hit(cache.get(&name("main"))), Some(Uuid::from_u128(0)));
        assert!(matches!(cache.get(&name("primary")), Lookup::Miss(_)));
        assert_eq!(cache.names(), 1);
    }

    #[test]
    fn the_least_recently_used_keyset_is_evicted_with_its_names() {
        let mut cache = cache(2);
        cache.load(state(1, Some("one")));
        cache.load(state(2, Some("two")));
        // Touch 1 so 2 is the oldest.
        assert!(matches!(cache.get(&id(1)), Lookup::Hit(_)));

        cache.load(state(3, Some("three")));

        assert_eq!(cache.len(), 2);
        assert!(matches!(cache.get(&id(2)), Lookup::Miss(_)), "2 was oldest");
        assert!(
            matches!(cache.get(&name("two")), Lookup::Miss(_)),
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
        cache.load(state(1, Some("one")));
        cache.load(state(1, None));
        assert_eq!(cache.len(), 1);
        assert_eq!(hit(cache.get(&name("one"))), Some(Uuid::from_u128(1)));

        // Evicting 1 takes "one" with it, whichever load was last.
        cache.load(state(2, None));
        assert!(matches!(cache.get(&id(1)), Lookup::Miss(_)));
        assert!(matches!(cache.get(&name("one")), Lookup::Miss(_)));
        assert_eq!(cache.names(), 0);

        // And reloading 1 by id does not resurrect the binding.
        cache.load(state(1, None));
        assert!(matches!(cache.get(&name("one")), Lookup::Miss(_)));
    }

    /// Bindings never outnumber the keysets they name: churning names
    /// through a one-slot cache leaves one binding, not a thousand.
    #[test]
    fn the_name_index_is_bounded_by_the_cache() {
        let mut cache = cache(1);
        for i in 1..=1000u128 {
            cache.load(state(i, Some(&format!("tenant-{i}"))));
            cache.load(state(i, None));
        }
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.names(), 1);
        assert_eq!(
            hit(cache.get(&name("tenant-1000"))),
            Some(Uuid::from_u128(1000))
        );
    }

    /// A keyset has one name at a time: resolved under a new one, its old
    /// name was renamed away and no longer selects it. The index therefore
    /// never holds more bindings than keysets, however often one is renamed.
    #[test]
    fn a_keysets_newer_name_replaces_its_older_one() {
        let mut cache = cache(1);
        cache.load(state(1, Some("one")));
        cache.load(state(1, Some("uno")));
        assert_eq!(hit(cache.get(&name("uno"))), Some(Uuid::from_u128(1)));
        assert!(matches!(cache.get(&name("one")), Lookup::Miss(_)));
        assert_eq!(cache.names(), 1);

        for i in 0..1000 {
            cache.load(state(1, Some(&format!("name-{i}"))));
        }
        assert_eq!(cache.names(), 1);

        cache.load(state(2, None));
        assert_eq!(cache.names(), 0);
    }

    /// Resolutions run outside the lock and their answers land in any
    /// order. The binding follows the later lookup: an answer from before a
    /// rename that arrives after the answer from after it must not move the
    /// name back. Key material is cached by id either way.
    #[test]
    fn a_binding_follows_the_later_lookup_whichever_answer_lands_first() {
        let mut cache = cache(4);
        let earlier = ticket(cache.get(&name("acme")));
        let later = ticket(cache.get(&name("acme")));

        cache.insert(state(2, Some("acme")), later);
        cache.insert(state(1, Some("acme")), earlier);

        assert_eq!(hit(cache.get(&name("acme"))), Some(Uuid::from_u128(2)));
        assert!(matches!(cache.get(&id(1)), Lookup::Hit(_)));
        assert_eq!(cache.names(), 1);

        // In order, the later answer moves it as usual.
        let next = ticket(cache.get(&name("other")));
        cache.insert(state(1, Some("acme")), next);
        assert_eq!(hit(cache.get(&name("acme"))), Some(Uuid::from_u128(1)));
        assert_eq!(cache.names(), 1, "2 no longer claims the name");
    }

    /// The same race with the two lookups asking *different* names, which
    /// is the shape a rename actually takes: a selection by the old name
    /// starts, the keyset is renamed, a selection by the new name starts
    /// and answers first. The older answer must not take the old name back
    /// — it would route that name, which ZeroKMS may have given to another
    /// keyset, here for a whole window.
    #[test]
    fn an_older_answer_does_not_restore_a_name_the_keyset_has_left() {
        let mut cache = cache(4);
        cache.load(state(1, Some("acme")));

        cache.name_ttl = Duration::ZERO;
        let earlier = ticket(cache.get(&name("acme")));
        let later = ticket(cache.get(&name("acme-corp")));
        cache.name_ttl = Duration::MAX;

        cache.insert(state(1, Some("acme-corp")), later);
        cache.insert(state(1, Some("acme")), earlier);

        assert_eq!(hit(cache.get(&name("acme-corp"))), Some(Uuid::from_u128(1)));
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Miss(_)),
            "the name the keyset was renamed away from is not bound again"
        );
        assert_eq!(cache.names(), 1);
    }

    /// And the default keyset, held apart from the bound, orders its
    /// answers the same way.
    #[test]
    fn the_defaults_binding_also_follows_the_later_lookup() {
        let mut cache = KeysetCache::new(
            NonZeroUsize::new(4).unwrap(),
            Duration::ZERO,
            state(0, Some("primary")),
        );

        let earlier = ticket(cache.get(&name("primary")));
        let later = ticket(cache.get(&name("main")));
        cache.name_ttl = Duration::MAX;

        cache.insert(state(0, Some("main")), later);
        cache.insert(state(0, Some("primary")), earlier);

        assert_eq!(hit(cache.get(&name("main"))), Some(Uuid::from_u128(0)));
        assert!(matches!(cache.get(&name("primary")), Lookup::Miss(_)));
        assert_eq!(cache.names(), 1);
    }

    /// A rename: the name now resolves to another id. The binding moves,
    /// and evicting the id it used to name does not take it away.
    #[test]
    fn a_name_that_moved_to_another_keyset_follows_it() {
        let mut cache = cache(2);
        cache.load(state(1, Some("acme")));
        cache.load(state(2, Some("acme")));
        assert_eq!(hit(cache.get(&name("acme"))), Some(Uuid::from_u128(2)));

        // Evict 1 (the oldest): "acme" belongs to 2 now and stays.
        assert!(matches!(cache.get(&id(2)), Lookup::Hit(_)));
        cache.load(state(3, None));
        assert!(matches!(cache.get(&id(1)), Lookup::Miss(_)));
        assert_eq!(hit(cache.get(&name("acme"))), Some(Uuid::from_u128(2)));
    }

    /// Eviction must not lose the order either: the keyset the later answer
    /// named can be evicted — taking the binding, and the entry that ordered
    /// it — while the earlier answer is still in flight. Landing in a cache
    /// that holds neither id and no binding for the name, it must still not
    /// bind the name it asked under.
    #[test]
    fn an_older_answer_does_not_bind_a_name_eviction_has_forgotten() {
        let mut cache = cache(1);
        let earlier = ticket(cache.get(&name("acme")));
        let later = ticket(cache.get(&name("acme")));

        cache.insert(state(2, Some("acme")), later);
        // 2 is evicted, and "acme" goes with it.
        cache.load(state(3, None));
        assert_eq!(cache.names(), 0);

        cache.insert(state(1, Some("acme")), earlier);
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Miss(_)),
            "the name the later lookup moved away is not taken back"
        );
        assert_eq!(cache.names(), 0);

        // A lookup later than the evicted binding still binds: the watermark
        // does not close the name index for good.
        let next = ticket(cache.get(&name("acme")));
        cache.insert(state(1, Some("acme")), next);
        assert_eq!(hit(cache.get(&name("acme"))), Some(Uuid::from_u128(1)));
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
        cache.load(state(1, Some("one")));

        assert!(matches!(cache.get(&name("one")), Lookup::Stale(_)));
        assert!(matches!(cache.get(&name("primary")), Lookup::Stale(_)));
        assert!(
            matches!(cache.get(&id(1)), Lookup::Hit(_)),
            "an id never ages"
        );

        // A zero window is stale again immediately after a refresh — with
        // no time elapsed at all, on the coarsest clock — which is the point
        // of a zero window; a wide one is fresh.
        cache.load(state(1, Some("one")));
        assert!(matches!(cache.get(&name("one")), Lookup::Stale(_)));
        cache.name_ttl = Duration::MAX;
        assert!(matches!(cache.get(&name("one")), Lookup::Hit(_)));
    }
}
