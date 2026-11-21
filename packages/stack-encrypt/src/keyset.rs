//! Keysets: the one thing a client holds more than one of.
//!
//! A [`StackCipher`] belongs to a client — one ZeroKMS client, one client
//! key — and a client may use any number of keysets: one per tenant is the
//! common shape. A [`KeysetCipher`] is the cipher bound to one of them, and
//! it is what every operation that *mints* something binds to: sealing
//! values, sealing records, deriving index terms. Decrypting is not bound
//! to a keyset (a sealed leaf carries the id of the keyset it was sealed
//! under). For an owned scalar, import [`DecryptFrom`](crate::DecryptFrom)
//! and use `i32::decrypt_from(ciphertext, &cipher)`; [`KeysetCipher::decrypt`]
//! adds the keyset constraint. For a structural tree, [`StackCipher::decrypt`]
//! opens across keysets and [`KeysetCipher::decrypt_tree`] adds that constraint.
//!
//! Keysets load lazily. [`StackCipher::keyset`] selects a keyset by id or
//! by name, makes no request and cannot fail. The first call on the handle
//! that is awaited resolves the keyset through a bounded cache and loads
//! it from ZeroKMS on a miss: one round trip, paid once per keyset per
//! process (or again after eviction). The default keyset — the one named
//! on the builder, else the client's — is loaded eagerly by
//! [`init`](crate::StackCipherBuilder::init), so a misconfigured client
//! fails at startup, and never evicts. A key source that takes a
//! credential with each call is the exception: `init` has no credential
//! to load the default keyset with, so the first call on the default
//! keyset that is awaited loads it ([`StackCipher::default_keyset`]). A
//! call on any other keyset loads that keyset, and not the default one.
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
//! arriving after eviction has forgotten the answer it would have lost to,
//! nor after ZeroKMS has answered a later lookup that the name is bound to
//! nothing.

use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use stack_kms::IdentifiedBy;
use uuid::Uuid;
use vitaminc_hmac::HmacSha256Prf;

#[cfg(test)]
use crate::credential::KeySource;
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
///
/// The default keyset is an `Entry` too, held apart from the bound rather
/// than shaped differently: its state never changes and it never evicts, but
/// its name binding ages, moves and reorders like any other, and every
/// accessor on [`KeysetCache`] reaches it through the same two lines
/// ([`entry`](KeysetCache::entry) / [`entry_mut`](KeysetCache::entry_mut)).
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

impl Alias {
    /// Whether the binding is still trusted at `now`. Strictly within the
    /// window: a zero window is never fresh, whatever the clock's
    /// resolution — even read at the very instant it was bound, which is
    /// what a coarse clock reports for a binding made moments ago.
    fn is_fresh_at(&self, now: Instant, ttl: Duration) -> bool {
        now.saturating_duration_since(self.resolved_at) < ttl
    }
}

/// A lookup's place in the order of lookups that went to ZeroKMS. The
/// caller carries it from [`get`](KeysetCache::get) to
/// [`insert`](KeysetCache::insert), where an answer is applied only if it is
/// later than the one that already spoke for that keyset, and its name only
/// if it is later than the one that produced that name's binding — answers
/// land in any order, and a later question has the later answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Resolution(u64);

impl Resolution {
    /// Whether this lookup came after `other`: the one comparison every
    /// ordering rule in [`KeysetCache`] is written in. Strict — each lookup
    /// takes its own ticket, so two answers never share one, and "later"
    /// never includes the answer itself.
    fn is_later_than(self, other: Resolution) -> bool {
        self > other
    }
}

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
/// the keyset is resolved under another name. What an evicted entry — or a
/// name ZeroKMS answered is bound to nothing — leaves behind is one
/// watermark, not a record per name: see [`watermark`](Self::watermark).
pub(crate) struct KeysetCache {
    capacity: NonZeroUsize,
    name_ttl: Duration,
    /// Monotonic use counter; an entry's tick is the last time it was hit.
    tick: u64,
    /// Monotonic lookup counter; see [`Resolution`].
    resolutions: u64,
    /// The default keyset's entry, held apart from the bound: it never
    /// evicts, and [`insert`](Self::insert) never replaces its state.
    /// `None` until the default keyset is loaded
    /// ([`hold_default`](Self::hold_default)). A cipher whose key source
    /// takes a credential with each call selects keysets before that.
    default: Option<Entry>,
    /// The latest lookup whose answer the cache holds nothing of to order
    /// an older answer against: one eviction has forgotten, or one ZeroKMS
    /// answered with "no keyset has this name".
    ///
    /// A keyset carries the order of the answers that spoke for it, and a
    /// binding the order of the lookup that made it; evicting the keyset
    /// drops both, and an answer older than what went would then find
    /// nothing left to say it is the older one. So every eviction leaves the
    /// entry's place here — its own bindings never sat later in the order
    /// than it does, since the insert that binds a name is the insert that
    /// stamps the entry — and no binding is made from an answer older than
    /// this. A negative answer is the same case from the start: it is an
    /// answer about a name that the cache holds no binding for, so it too
    /// leaves its place here ([`forget`](Self::forget)), and an earlier
    /// positive answer still in flight cannot bind the name after it. The
    /// name is the only thing an answer too old to order can get wrong: an
    /// id's key material is the same whichever lookup asked, so it still
    /// caches.
    ///
    /// It is one watermark for all names rather than one per forgotten name
    /// — a cache whose whole contract is a bound must not grow a record per
    /// name it has evicted or been told is unbound — so it also refuses some
    /// bindings an older lookup could have made safely. That costs a round
    /// trip on the next selection by such a name, in the eviction regime
    /// that is already paying them.
    watermark: Resolution,
    by_id: HashMap<Uuid, Entry>,
    by_name: HashMap<String, Alias>,
}

impl KeysetCache {
    /// The bound a [`StackCipher`] uses unless the builder says otherwise:
    /// a thousand-tenant process pays ZeroKMS once per tenant per cold
    /// start and then not again.
    pub(crate) const DEFAULT_CAPACITY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(1023);

    /// An empty cache. The default keyset is not loaded yet.
    pub(crate) fn new(capacity: NonZeroUsize, name_ttl: Duration) -> Self {
        Self {
            capacity,
            name_ttl,
            tick: 0,
            resolutions: 0,
            watermark: Resolution(0),
            default: None,
            by_id: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    /// The default keyset is loaded: hold `default` apart from the bound
    /// from now on. The first call decides, and a second changes nothing.
    ///
    /// A selection by id or by name may have loaded this keyset already,
    /// as one of the bounded entries. That entry leaves the bound. It
    /// keeps its name binding and its place in the order of lookups, and
    /// takes the state given here, so every later lookup is answered with
    /// the state the cipher holds as its default.
    ///
    /// Otherwise the entry is new, and its builder-time name, if any, is
    /// bound now, as the answer older than every lookup.
    pub(crate) fn hold_default(&mut self, default: Arc<KeysetState>) {
        if self.default.is_some() {
            return;
        }
        if let Some(entry) = self.by_id.remove(&default.id) {
            self.default = Some(Entry {
                state: default,
                ..entry
            });
            return;
        }
        let (id, name) = (default.id, default.name.clone());
        self.default = Some(Entry {
            state: default,
            last_used: 0,
            name: None,
            resolution: Resolution(0),
        });
        if let Some(name) = name {
            let _ = self.bind(&name, id, Resolution(0));
        }
    }

    /// The ticket for a lookup that is about to go to ZeroKMS.
    fn resolution(&mut self) -> Resolution {
        self.resolutions += 1;
        Resolution(self.resolutions)
    }

    /// Whether `id` is the keyset held apart from the bound.
    fn is_default(&self, id: Uuid) -> bool {
        self.default
            .as_ref()
            .is_some_and(|default| default.state.id == id)
    }

    /// The entry for `id`, whether it is the default's or one of the bounded
    /// ones. This and [`entry_mut`](Self::entry_mut) are the only two places
    /// that know the default is held apart, so every rule below — ordering,
    /// binding, forgetting a name — is written once and applies to it too.
    fn entry(&self, id: Uuid) -> Option<&Entry> {
        if self.is_default(id) {
            self.default.as_ref()
        } else {
            self.by_id.get(&id)
        }
    }

    /// [`entry`](Self::entry), mutably.
    fn entry_mut(&mut self, id: Uuid) -> Option<&mut Entry> {
        if self.is_default(id) {
            self.default.as_mut()
        } else {
            self.by_id.get_mut(&id)
        }
    }

    /// Mark `id` most recently used and hand back its state, if the cache
    /// holds it at all.
    fn touch(&mut self, id: Uuid) -> Option<Arc<KeysetState>> {
        let tick = self.tick + 1;
        let entry = self.entry_mut(id)?;
        entry.last_used = tick;
        let state = Arc::clone(&entry.state);
        self.tick = tick;
        Some(state)
    }

    /// Look a keyset up by id or name, marking it most recently used.
    pub(crate) fn get(&mut self, by: &IdentifiedBy) -> Lookup {
        let (id, fresh) = match by {
            IdentifiedBy::Uuid(id) => (*id, true),
            IdentifiedBy::Name(name) => match self.by_name.get::<str>(name) {
                Some(alias) => (alias.id, alias.is_fresh_at(Instant::now(), self.name_ttl)),
                None => return Lookup::Miss(self.resolution()),
            },
        };
        let Some(state) = self.touch(id) else {
            return Lookup::Miss(self.resolution());
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
    ///
    /// Returns what the lookup should be answered with, which is not always
    /// what ZeroKMS said: when a later lookup has already spoken — for the
    /// name this one asked under first, else for this keyset — the caller
    /// gets that later answer, the same one every selection after it gets.
    /// The name comes first because it is what the caller asked: an answer
    /// older than what its keyset holds *and* than what its name is bound
    /// to is answered by the name, since the keyset's later answer may have
    /// come under another name. The answer that lost is not handed out even
    /// once, and that is decided before this insert evicts anything: the
    /// entry it evicts can be the very winner. An answer nothing later
    /// contradicts is returned as it is, whether or not its name bound (an
    /// answer older than the watermark has no binding left to lose to, and
    /// is still the latest thing the cache knows about its name).
    pub(crate) fn insert(
        &mut self,
        state: Arc<KeysetState>,
        resolution: Resolution,
    ) -> Arc<KeysetState> {
        // A name lookup is answered with whatever the name means now: when
        // a later lookup has already bound it — to this keyset or another —
        // the caller gets that keyset (held, since no binding outlives its
        // id), and `bind` below refuses this answer as the older one. Taken
        // first: before the keyset's own order is consulted, since the name
        // is what was asked, and before eviction, which can take that very
        // binding with the entry it evicts and leave this answer looking
        // uncontradicted.
        let later = state
            .name
            .as_deref()
            .and_then(|name| self.by_name.get(name))
            .filter(|alias| alias.resolution.is_later_than(resolution))
            .and_then(|alias| self.entry(alias.id))
            .map(|entry| Arc::clone(&entry.state));
        if let Some(entry) = self.entry(state.id) {
            if entry.resolution.is_later_than(resolution) {
                return later.unwrap_or_else(|| Arc::clone(&entry.state));
            }
        }
        // Evict before binding: the entry that goes may be the one whose
        // answer this one is older than, and its place in the order must be
        // on the watermark before `bind` consults it — or an answer from
        // before a rename binds a name it should have lost to the entry its
        // own insert evicts.
        if !self.is_default(state.id)
            && !self.by_id.contains_key(&state.id)
            && self.by_id.len() >= self.capacity.get()
        {
            self.evict_oldest();
        }
        // `bind` gives the entry the name it binds, when the cache already
        // holds one; a first insert carries it over below instead.
        let bound = match &state.name {
            Some(name) => self.bind(name, state.id, resolution),
            None => false,
        };
        let answer = later.unwrap_or_else(|| Arc::clone(&state));
        if self.is_default(state.id) {
            if let Some(default) = &mut self.default {
                default.resolution = resolution;
            }
            return answer;
        }
        self.tick += 1;
        match self.by_id.get_mut(&state.id) {
            Some(entry) => {
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
        answer
    }

    /// Bind `name` to `id` for the lookup `resolution`; false if a later
    /// lookup already bound it, or if this answer is older than a place in
    /// the order the cache has since let go of ([`watermark`]). Also
    /// unbinds the name this id was bound under before, and unbinds this
    /// name from the id it named before.
    ///
    /// [`watermark`]: Self::watermark
    fn bind(&mut self, name: &str, id: Uuid, resolution: Resolution) -> bool {
        if self.watermark.is_later_than(resolution) {
            return false;
        }
        if let Some(alias) = self.by_name.get(name) {
            if alias.resolution.is_later_than(resolution) {
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
        // The keyset claims the name it is now bound under, so eviction can
        // take the binding with it. An id the cache does not hold yet is
        // about to be inserted by `insert`, which carries the name over.
        if let Some(entry) = self.entry_mut(id) {
            entry.name = Some(name.to_owned());
        }
        true
    }

    /// The name `id` is currently bound under, if any.
    fn current_name_of(&self, id: Uuid) -> Option<String> {
        self.entry(id).and_then(|entry| entry.name.clone())
    }

    /// ZeroKMS answered the lookup `resolution` for `name` with "no keyset
    /// has this name". That is an answer about the name, and it orders
    /// like one: a binding an earlier lookup made goes (a later lookup's
    /// stands — the name may have been given out again since), and the
    /// [`watermark`](Self::watermark) rises to this lookup, so an earlier
    /// positive answer still in flight cannot bind the name after ZeroKMS
    /// has said it is bound to nothing. Only ZeroKMS's own answer counts:
    /// a lookup that failed to get one (transport, auth) says nothing about
    /// the name and must not come here.
    pub(crate) fn forget(&mut self, name: &str, resolution: Resolution) {
        self.watermark = self.watermark.max(resolution);
        let Some(alias) = self.by_name.get(name) else {
            return;
        };
        if alias.resolution.is_later_than(resolution) {
            return;
        }
        let id = alias.id;
        let _ = self.by_name.remove(name);
        self.forget_name_of(id, name);
    }

    /// `name` moved away from `id`: the id no longer claims it.
    fn forget_name_of(&mut self, id: Uuid, name: &str) {
        if let Some(entry) = self.entry_mut(id) {
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
            // The entry's place in the order outlives it as a watermark:
            // once it is gone there is nothing left to order an older answer
            // for this keyset against. It is taken whether or not the entry
            // still owns a name — a keyset whose name has already moved to
            // another keyset is precisely the one an older answer would
            // rebind, and the binding it would have lost to is no longer
            // here to say so.
            self.watermark = self.watermark.max(entry.resolution);
            if let Some(name) = entry.name {
                // A name that has since moved to another id keeps its
                // binding: only this id's binding goes with it.
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

    /// Insert as a fresh, in-order resolution — what every test that is not
    /// about ordering wants.
    #[cfg(test)]
    pub(crate) fn load(&mut self, state: Arc<KeysetState>) {
        let resolution = self.resolution();
        let _ = self.insert(state, resolution);
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
/// Obtained from [`StackCipher::keyset`] (any keyset, by id or by name) or
/// [`StackCipher::default_keyset`]. Cheap to clone and to hold: a reference
/// to the cipher plus a shared handle on the keyset's loaded state, so a
/// request handler can take one per tenant and hand it around.
///
/// # Taking a handle makes no request
///
/// Neither method loads anything. A handle is on a keyset the cipher has
/// loaded, or on one it has not loaded yet. Every call on the handle works
/// either way: awaiting the call loads the keyset first, once for the
/// cipher, and the handle then keeps that keyset loaded for as long as it
/// is held. A keyset that ZeroKMS does not know, or has disabled, is that
/// call's [`Error::Kms`](crate::Error::Kms).
///
/// The default keyset is loaded by
/// [`init`](crate::StackCipherBuilder::init), unless the key source takes
/// a credential with each call. Any other keyset is loaded by the first
/// call that uses it.
///
/// What reads the loaded keyset is a call too, for the same reason:
/// [`keyset_id`](Self::keyset_id), [`keyset_name`](Self::keyset_name) and
/// [`with_prf`](Self::with_prf) each return a
/// [`Pending`](crate::Pending).
///
/// The type a caller holds states the guarantee it gets. A `KeysetCipher`
/// for tenant A mints every data key under A's keyset, derives every term
/// under A's index key, and refuses — before any data key is requested —
/// to open a leaf sealed under any other keyset
/// ([`Error::ForeignKeyset`]). The [`StackCipher`] it came from opens
/// leaves from any keyset the client is authorised for.
///
/// [`Error::ForeignKeyset`]: crate::Error::ForeignKeyset
pub struct KeysetCipher<'k, K> {
    cipher: &'k StackCipher<K>,
    /// Which keyset this is a handle on.
    selected: Selected,
    /// The keyset's loaded state, from the first time this handle found
    /// the keyset loaded: see [`loaded_state`](Self::loaded_state). Shared
    /// with this handle's clones, and with every call built through it
    /// before the keyset was loaded.
    state: Kept,
}

/// The loaded state a [`KeysetCipher`] keeps once its keyset is loaded.
///
/// A call built through the handle before the load shares it
/// ([`KeysetSelector::not_loaded`](crate::target::KeysetSelector)). The
/// first of those calls to settle loads the keyset and sets it. Every
/// other one then settles under that keyset, and does not resolve the
/// handle's id or name again. So everything made through one handle is
/// under one keyset, whatever a name comes to mean in between.
pub(crate) type Kept = Arc<OnceLock<Arc<KeysetState>>>;

/// The keyset a handle was taken for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Selected {
    /// The client's default keyset.
    Default,
    /// The keyset with this id, or of this name.
    By(IdentifiedBy),
}

impl<K> Clone for KeysetCipher<'_, K> {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher,
            selected: self.selected.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

/// Opaque: the keyset's identity (which is in every sealed leaf already, and
/// in ZeroKMS's own logs) and nothing else. The index-key PRF this handle
/// carries is key material and never appears, and neither does the cipher —
/// whose own [`Debug`](fmt::Debug) is opaque for the same reason. The
/// identity is `None` until the keyset is loaded.
impl<K> fmt::Debug for KeysetCipher<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.loaded_state();
        f.debug_struct("KeysetCipher")
            .field("keyset_id", &state.map(|state| state.id))
            .field(
                "keyset_name",
                &state.and_then(|state| state.name.as_deref()),
            )
            .field("kms", &std::any::type_name::<K>())
            .finish_non_exhaustive()
    }
}

impl<'k, K> KeysetCipher<'k, K> {
    /// A handle on a keyset that is loaded.
    pub(crate) fn new(cipher: &'k StackCipher<K>, state: Arc<KeysetState>) -> Self {
        Self {
            cipher,
            selected: Selected::By(IdentifiedBy::Uuid(state.id)),
            state: Arc::new(OnceLock::from(state)),
        }
    }

    /// A handle on the keyset `selected`, whether or not the cipher has
    /// loaded it. No request is made.
    pub(crate) fn selected(cipher: &'k StackCipher<K>, selected: Selected) -> Self {
        Self {
            cipher,
            selected,
            state: Kept::default(),
        }
    }

    /// The keyset's loaded state, or `None` for a keyset that the cipher
    /// has not loaded yet. A handle taken before the load finds the state
    /// in the cipher once a call has loaded it, and keeps it from then on.
    pub(crate) fn loaded_state(&self) -> Option<&Arc<KeysetState>> {
        if let Some(state) = self.state.get() {
            return Some(state);
        }
        let found = match &self.selected {
            Selected::Default => self.cipher.loaded_default().cloned(),
            Selected::By(keyset) => self.cipher.loaded_keyset(keyset),
        }?;
        Some(self.state.get_or_init(|| found))
    }

    /// The keyset's loaded state, for a caller that has already read
    /// [`loaded_state`](Self::loaded_state) and found the keyset loaded,
    /// or was handed this handle by a call that loaded it. A handle keeps
    /// the state it found, so this does not fail for that caller.
    pub(crate) fn loaded_now(&self) -> Result<&Arc<KeysetState>, crate::Error> {
        self.loaded_state().ok_or_else(|| {
            crate::Error::Other("a keyset was read before the call loaded it".into())
        })
    }

    /// The keyset a pending built through this handle works under.
    pub(crate) fn selector(&self) -> crate::target::KeysetSelector {
        match self.loaded_state() {
            Some(state) => crate::target::KeysetSelector::keyset(state.id),
            None => crate::target::KeysetSelector::not_loaded(
                self.selected.clone(),
                Arc::clone(&self.state),
            ),
        }
    }

    /// A value that is derived from this keyset's loaded state, such as a
    /// term under its index key, for a keyset that is not loaded yet. The
    /// pending asks for the keyset, and `derive` runs when the pending
    /// settles and has loaded it. So `derive` owns what it reads.
    ///
    /// A caller reads [`loaded_state`](Self::loaded_state) first, and
    /// derives at once when the keyset is loaded. That path does not come
    /// through here, so a call on a loaded keyset moves its plaintext
    /// through no extra frame.
    pub(crate) fn deferred<'s, T, F>(&'s self, derive: F) -> crate::target::Pending<'s, T, K>
    where
        T: stack_kms::MaybeSend + 's,
        F: FnOnce(&Arc<KeysetState>) -> Result<T, crate::Error> + stack_kms::MaybeSend + 's,
    {
        crate::target::Pending::request(
            self,
            vec![crate::target::Request::selected_keyset()],
            move |responses| derive(&responses.next_keyset()?),
        )
    }

    /// A value read from this keyset's loaded state: now when the keyset
    /// is loaded, and when the pending has loaded it otherwise.
    fn reading<'s, T, F>(&'s self, read: F) -> crate::target::Pending<'s, T, K>
    where
        T: stack_kms::MaybeSend + 's,
        F: FnOnce(&Arc<KeysetState>) -> Result<T, crate::Error> + stack_kms::MaybeSend + 's,
    {
        match self.loaded_state() {
            Some(state) => crate::target::Pending::ready(self, read(state)),
            None => self.deferred(read),
        }
    }

    /// The client's cipher, which this keyset belongs to.
    pub fn cipher(&self) -> &'k StackCipher<K> {
        self.cipher
    }

    /// The keyset every data key this handle mints is generated under, and
    /// whose index key its terms are derived under. Resolved: a keyset
    /// selected by name reports its id here.
    ///
    /// A [`Pending`](crate::Pending), because a keyset that the cipher has
    /// not loaded yet is loaded when it is awaited. With the keyset
    /// loaded, awaiting it makes no request.
    ///
    /// # Errors
    ///
    /// Awaiting fails with [`Error::Kms`](crate::Error::Kms) if the keyset
    /// is not loaded yet and the load fails.
    pub fn keyset_id(&self) -> crate::target::Pending<'_, Uuid, K> {
        self.reading(|keyset| Ok(keyset.id))
    }

    /// The name this keyset's loaded state was last resolved under, if any.
    /// That is the name of the lookup that loaded (or last refreshed) it,
    /// not necessarily of the selection that produced this handle: a
    /// selection by id returns state another selection may have loaded by
    /// name, and the default keyset knows its name only when the builder
    /// named it. A label from the time of loading, not an identity: see the
    /// [module docs](self#ids-are-identity-names-are-looked-up).
    ///
    /// A [`Pending`](crate::Pending), and it fails, as
    /// [`keyset_id`](Self::keyset_id) does.
    pub fn keyset_name(&self) -> crate::target::Pending<'_, Option<String>, K> {
        self.reading(|keyset| Ok(keyset.name.clone()))
    }

    /// A value derived under this keyset's index key: `derive` is handed
    /// the PRF that index terms are derived from.
    ///
    /// For other crates that implement their own term types against this
    /// cipher (see [`crate::sem`]). With the keyset loaded, `derive` runs
    /// now and the pending carries no request. With a keyset that is not
    /// loaded yet, it runs when the pending is awaited and has loaded the
    /// keyset. So `derive` owns what it reads.
    pub fn with_prf<'s, T, F>(&'s self, derive: F) -> crate::target::Pending<'s, T, K>
    where
        T: stack_kms::MaybeSend + 's,
        F: FnOnce(&HmacSha256Prf) -> Result<T, crate::Error> + stack_kms::MaybeSend + 's,
    {
        self.reading(move |keyset| derive(&keyset.prf))
    }

    /// The underlying data-key source.
    pub fn kms(&self) -> &'k K {
        self.cipher.kms()
    }
}

#[cfg(test)]
impl<'k, K> KeysetCipher<'k, K> {
    /// This handle, on a keyset that is loaded, for a test that reads the
    /// keyset's state. A keyset that is not loaded yet is loaded here, as
    /// `identity`.
    pub(crate) async fn loaded<I>(self, identity: &I) -> Result<Self, crate::Error>
    where
        K: KeySource<I>,
    {
        if self.loaded_state().is_none() {
            let state = self.cipher.selected_state(&self.selected, identity).await?;
            let _ = self.state.set(state);
        }
        Ok(self)
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

    /// A cache that holds `default` as its default keyset from the start,
    /// as the cache of a cipher whose `init` loaded it.
    fn holding(
        capacity: NonZeroUsize,
        name_ttl: Duration,
        default: Arc<KeysetState>,
    ) -> KeysetCache {
        let mut cache = KeysetCache::new(capacity, name_ttl);
        cache.hold_default(default);
        cache
    }

    /// A cache whose default is keyset 0 (unnamed) and whose name window
    /// never closes.
    fn cache(capacity: usize) -> KeysetCache {
        holding(
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

        assert_eq!(
            hit(cache.get(&id(1))),
            Some(Uuid::from_u128(1)),
            "a loaded keyset is found by its id"
        );
        assert_eq!(
            hit(cache.get(&name("customers"))),
            Some(Uuid::from_u128(1)),
            "and by the name it loaded under"
        );
        assert!(
            matches!(cache.get(&name("staff")), Lookup::Miss(_)),
            "a name nothing was loaded under is a miss"
        );
        assert!(
            matches!(cache.get(&id(2)), Lookup::Miss(_)),
            "an id nothing was loaded under is a miss"
        );
    }

    #[test]
    fn a_keyset_loaded_by_id_is_not_found_by_name() {
        let mut cache = cache(4);
        cache.load(state(1, None));

        assert!(
            matches!(cache.get(&id(1)), Lookup::Hit(_)),
            "the id it loaded under finds it"
        );
        assert!(
            matches!(cache.get(&name("customers")), Lookup::Miss(_)),
            "a load by id binds no name, so no name finds it"
        );
    }

    /// The documented bound on how long a rename can go unnoticed.
    #[test]
    fn a_name_binding_is_trusted_for_five_minutes_by_default() {
        assert_eq!(
            DEFAULT_NAME_TTL,
            Duration::from_secs(300),
            "name bindings should be trusted for five minutes by default"
        );
    }

    /// Every ordering rule in the cache is written in `is_later_than`, so
    /// its strictness is pinned here once: a lookup is not later than
    /// itself, nor than one after it.
    #[test]
    fn later_is_strictly_later() {
        assert!(
            Resolution(2).is_later_than(Resolution(1)),
            "a later resolution should compare later"
        );
        assert!(
            !Resolution(1).is_later_than(Resolution(1)),
            "a resolution should not be later than itself"
        );
        assert!(
            !Resolution(1).is_later_than(Resolution(2)),
            "an earlier resolution should not compare later"
        );
    }

    /// A binding is fresh strictly inside its window. The zero-window case
    /// is read at the very instant of binding — what a coarse clock (a
    /// millisecond `performance.now()`, say) reports for a binding made
    /// moments ago — and is still stale.
    #[test]
    fn a_binding_is_fresh_strictly_within_its_window() {
        let bound = Instant::now();
        let alias = Alias {
            id: Uuid::from_u128(1),
            resolved_at: bound,
            resolution: Resolution(1),
        };
        let ttl = Duration::from_secs(60);

        assert!(
            alias.is_fresh_at(bound, ttl),
            "a binding should be fresh at its start"
        );
        assert!(
            alias.is_fresh_at(bound + ttl - Duration::from_nanos(1), ttl),
            "a binding should be fresh just before expiry"
        );
        assert!(
            !alias.is_fresh_at(bound + ttl, ttl),
            "the window's end is outside it"
        );
        assert!(
            !alias.is_fresh_at(bound, Duration::ZERO),
            "a zero window is never fresh"
        );
    }

    /// No two uses are ever tied for least recently used — a load is newer
    /// than every use before it, and so is a hit — so eviction takes the
    /// same keyset in every cache, whatever order its hasher's seed happens
    /// to iterate the entries in.
    #[test]
    fn eviction_follows_use_order_not_hash_order() {
        for _ in 0..64 {
            let (mut loads, mut hits) = (cache(2), cache(2));

            loads.load(state(1, None));
            loads.load(state(2, None));
            loads.load(state(3, None));
            assert!(
                matches!(loads.get(&id(1)), Lookup::Miss(_)),
                "the first loaded is the least recently used"
            );
            assert!(
                matches!(loads.get(&id(2)), Lookup::Hit(_)),
                "the second loaded keyset should remain cached"
            );

            hits.load(state(1, None));
            hits.load(state(2, None));
            assert!(
                matches!(hits.get(&id(1)), Lookup::Hit(_)),
                "the first keyset should be cached before its hit"
            );
            hits.load(state(3, None));
            assert!(
                matches!(hits.get(&id(2)), Lookup::Miss(_)),
                "a hit makes 1 newer than the 2 loaded after it"
            );
            assert!(
                matches!(hits.get(&id(1)), Lookup::Hit(_)),
                "the recently used keyset should survive eviction"
            );
        }
    }

    /// A name that moved to another keyset is no longer the old keyset's to
    /// give up: renaming the old keyset afterwards must not unbind the name
    /// from the keyset that now answers to it.
    #[test]
    fn renaming_the_keyset_a_name_left_does_not_take_the_name() {
        let mut cache = cache(4);
        cache.load(state(1, Some("acme")));
        cache.load(state(2, Some("acme")));
        cache.load(state(1, Some("legacy")));

        assert_eq!(
            hit(cache.get(&name("acme"))),
            Some(Uuid::from_u128(2)),
            "the name stays with the keyset it moved to"
        );
        assert_eq!(
            hit(cache.get(&name("legacy"))),
            Some(Uuid::from_u128(1)),
            "and the old keyset answers to its new name"
        );
        assert_eq!(
            cache.names(),
            2,
            "both names should remain bound after the rename"
        );
    }

    /// A cipher whose key source takes a credential with each call selects
    /// keysets before its default keyset is loaded. The cache works with no
    /// default: every keyset is in the bound, the nil id included.
    #[test]
    fn a_cache_with_no_default_holds_every_keyset_in_the_bound() {
        let mut cache = KeysetCache::new(NonZeroUsize::new(2).unwrap(), Duration::MAX);
        assert_eq!(hit(cache.get(&id(0))), None, "nothing is held apart yet");

        cache.load(state(0, None));
        cache.load(state(1, Some("tenant")));
        assert_eq!(cache.len(), 2);
        assert_eq!(hit(cache.get(&id(0))), Some(Uuid::from_u128(0)));
        assert_eq!(hit(cache.get(&name("tenant"))), Some(Uuid::from_u128(1)));

        // The bound applies to all of them: a third keyset evicts the one
        // used least recently, which is keyset 0.
        cache.load(state(2, None));
        assert_eq!(cache.len(), 2);
        assert_eq!(hit(cache.get(&id(0))), None, "evicted like any other");
        assert_eq!(hit(cache.get(&name("tenant"))), Some(Uuid::from_u128(1)));
    }

    /// The default keyset is loaded after other keysets were selected. It
    /// is held apart from then on, and what the cache held stays.
    #[test]
    fn a_default_loaded_late_is_held_apart_from_the_keysets_already_cached() {
        let mut cache = KeysetCache::new(NonZeroUsize::new(1).unwrap(), Duration::MAX);
        cache.load(state(1, Some("tenant")));

        cache.hold_default(state(7, None));
        assert_eq!(cache.len(), 1, "the default takes no slot of the bound");
        assert_eq!(hit(cache.get(&id(7))), Some(Uuid::from_u128(7)));
        assert_eq!(hit(cache.get(&name("tenant"))), Some(Uuid::from_u128(1)));

        // Filling the one slot evicts the tenant keyset, never the default.
        cache.load(state(2, None));
        assert_eq!(cache.len(), 1);
        assert_eq!(hit(cache.get(&id(1))), None);
        assert_eq!(hit(cache.get(&id(7))), Some(Uuid::from_u128(7)));
    }

    /// A selection by name loaded the keyset that turns out to be the
    /// default. Its entry leaves the bound and keeps its name, and lookups
    /// are answered with the state the cipher holds as its default.
    #[test]
    fn a_cached_keyset_that_is_the_default_leaves_the_bound_and_keeps_its_name() {
        let mut cache = KeysetCache::new(NonZeroUsize::new(1).unwrap(), Duration::MAX);
        cache.load(state(7, Some("primary")));
        assert_eq!(cache.len(), 1);

        let default = state(7, None);
        cache.hold_default(Arc::clone(&default));
        assert_eq!(cache.len(), 0, "the entry left the bound");
        assert_eq!(cache.names(), 1, "and kept its name binding");
        for by in [id(7), name("primary")] {
            match cache.get(&by) {
                Lookup::Hit(state) => assert!(
                    Arc::ptr_eq(&state, &default),
                    "answered with the default's state"
                ),
                Lookup::Stale(_) | Lookup::Miss(_) => panic!("the default is held"),
            }
        }

        // The slot it left is free, and filling it twice over evicts
        // nothing of the default's.
        cache.load(state(1, None));
        cache.load(state(2, None));
        assert_eq!(cache.len(), 1);
        assert_eq!(hit(cache.get(&id(7))), Some(Uuid::from_u128(7)));
        assert_eq!(hit(cache.get(&name("primary"))), Some(Uuid::from_u128(7)));
    }

    /// A cached keyset that becomes the default keeps its place in the
    /// order of lookups. An answer from before its rename, landing after,
    /// is still the older one: it does not bring the old name back.
    #[test]
    fn a_cached_keyset_that_is_the_default_keeps_its_place_in_the_order() {
        let mut cache = KeysetCache::new(NonZeroUsize::new(2).unwrap(), Duration::MAX);
        let Lookup::Miss(before_rename) = cache.get(&name("old")) else {
            panic!("nothing is cached yet");
        };
        let Lookup::Miss(after_rename) = cache.get(&name("new")) else {
            panic!("nothing is cached yet");
        };
        let _ = cache.insert(state(7, Some("new")), after_rename);

        cache.hold_default(state(7, None));
        let _ = cache.insert(state(7, Some("old")), before_rename);

        assert_eq!(hit(cache.get(&name("new"))), Some(Uuid::from_u128(7)));
        assert_eq!(
            hit(cache.get(&name("old"))),
            None,
            "the older answer must not bind the name the keyset left"
        );
    }

    /// The default keyset is decided once. A second answer changes nothing.
    #[test]
    fn the_default_is_decided_by_the_first_load() {
        let mut cache = KeysetCache::new(NonZeroUsize::new(1).unwrap(), Duration::MAX);
        cache.hold_default(state(7, None));
        cache.hold_default(state(8, None));

        assert_eq!(hit(cache.get(&id(7))), Some(Uuid::from_u128(7)));
        assert_eq!(hit(cache.get(&id(8))), None, "keyset 8 was never held");
    }

    /// The default here is keyset 7, not the nil id the other tests' caches
    /// default to: a cache that mistook the nil id for its default would
    /// pass every test whose default *is* nil.
    #[test]
    fn the_default_is_found_by_id_and_its_builder_name_but_never_stored() {
        let mut cache = holding(
            NonZeroUsize::new(1).unwrap(),
            Duration::MAX,
            state(7, Some("primary")),
        );
        assert_eq!(
            hit(cache.get(&id(7))),
            Some(Uuid::from_u128(7)),
            "the default is found by its id"
        );
        assert_eq!(
            hit(cache.get(&name("primary"))),
            Some(Uuid::from_u128(7)),
            "and by the name the builder gave it"
        );

        // Filling the one slot evicts nothing of the default's.
        cache.load(state(1, None));
        cache.load(state(2, None));
        assert_eq!(cache.len(), 1, "the bounded part holds its one slot");
        assert_eq!(
            hit(cache.get(&id(7))),
            Some(Uuid::from_u128(7)),
            "the default survives an eviction that filled the bound"
        );
        assert_eq!(
            hit(cache.get(&name("primary"))),
            Some(Uuid::from_u128(7)),
            "and so does its name binding"
        );

        // Re-resolving the default by name refreshes its binding, and does
        // not put a second copy of it in the bounded part.
        cache.load(state(7, Some("primary")));
        assert_eq!(
            cache.len(),
            1,
            "re-resolving the default must not store a second copy of it"
        );

        // The default renamed: its old name no longer selects it.
        cache.load(state(7, Some("main")));
        assert_eq!(
            hit(cache.get(&name("main"))),
            Some(Uuid::from_u128(7)),
            "the default's new name selects it"
        );
        assert!(
            matches!(cache.get(&name("primary")), Lookup::Miss(_)),
            "the name it was renamed away from no longer selects it"
        );
        assert_eq!(cache.names(), 1, "a keyset holds one name at a time");
    }

    #[test]
    fn the_least_recently_used_keyset_is_evicted_with_its_names() {
        let mut cache = cache(2);
        cache.load(state(1, Some("one")));
        cache.load(state(2, Some("two")));
        // Touch 1 so 2 is the oldest.
        assert!(
            matches!(cache.get(&id(1)), Lookup::Hit(_)),
            "touching 1 makes 2 the least recently used"
        );

        cache.load(state(3, Some("three")));

        assert_eq!(cache.len(), 2, "the cache stays at its bound");
        assert!(matches!(cache.get(&id(2)), Lookup::Miss(_)), "2 was oldest");
        assert!(
            matches!(cache.get(&name("two")), Lookup::Miss(_)),
            "the evicted keyset's name goes with it"
        );
        assert!(
            matches!(cache.get(&id(1)), Lookup::Hit(_)),
            "the touched keyset stayed"
        );
        assert!(
            matches!(cache.get(&id(3)), Lookup::Hit(_)),
            "and the newly loaded one is held"
        );
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
        assert_eq!(cache.len(), 1, "the same id replaces, never adds");
        assert_eq!(
            hit(cache.get(&name("one"))),
            Some(Uuid::from_u128(1)),
            "a reload by id must not shed the binding the name load made"
        );

        // Evicting 1 takes "one" with it, whichever load was last.
        cache.load(state(2, None));
        assert!(
            matches!(cache.get(&id(1)), Lookup::Miss(_)),
            "1 was evicted by 2"
        );
        assert!(
            matches!(cache.get(&name("one")), Lookup::Miss(_)),
            "no binding outlives the id it names"
        );
        assert_eq!(cache.names(), 0, "the name index emptied with the entry");

        // And reloading 1 by id does not resurrect the binding.
        cache.load(state(1, None));
        assert!(
            matches!(cache.get(&name("one")), Lookup::Miss(_)),
            "a reload by id binds no name"
        );
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
        assert_eq!(cache.len(), 1, "the cache holds its bound, not 1000");
        assert_eq!(
            cache.names(),
            1,
            "the name index is bounded by the entries it serves"
        );
        assert_eq!(
            hit(cache.get(&name("tenant-1000"))),
            Some(Uuid::from_u128(1000)),
            "the surviving binding is the last one made"
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
        assert_eq!(
            hit(cache.get(&name("uno"))),
            Some(Uuid::from_u128(1)),
            "the newer name selects the keyset"
        );
        assert!(
            matches!(cache.get(&name("one")), Lookup::Miss(_)),
            "the older name was renamed away and no longer selects it"
        );
        assert_eq!(cache.names(), 1, "one name per keyset");

        for i in 0..1000 {
            cache.load(state(1, Some(&format!("name-{i}"))));
        }
        assert_eq!(
            cache.names(),
            1,
            "a thousand renames of one keyset leave one binding"
        );

        cache.load(state(2, None));
        assert_eq!(
            cache.names(),
            0,
            "evicting the keyset takes its one binding with it"
        );
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

        assert_eq!(
            hit(cache.get(&name("acme"))),
            Some(Uuid::from_u128(2)),
            "the binding follows the later lookup, not the later arrival"
        );
        assert!(
            matches!(cache.get(&id(1)), Lookup::Hit(_)),
            "the older answer's key material still caches, by id"
        );
        assert_eq!(cache.names(), 1, "one binding for the one name");

        // In order, the later answer moves it as usual.
        let next = ticket(cache.get(&name("other")));
        cache.insert(state(1, Some("acme")), next);
        assert_eq!(
            hit(cache.get(&name("acme"))),
            Some(Uuid::from_u128(1)),
            "a genuinely later answer moves the binding"
        );
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

        assert_eq!(
            hit(cache.get(&name("acme-corp"))),
            Some(Uuid::from_u128(1)),
            "the later answer's name stands"
        );
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Miss(_)),
            "the name the keyset was renamed away from is not bound again"
        );
        assert_eq!(cache.names(), 1, "and it was not bound alongside");
    }

    /// And the default keyset, held apart from the bound, orders its
    /// answers the same way.
    #[test]
    fn the_defaults_binding_also_follows_the_later_lookup() {
        let mut cache = holding(
            NonZeroUsize::new(4).unwrap(),
            Duration::ZERO,
            state(0, Some("primary")),
        );

        let earlier = ticket(cache.get(&name("primary")));
        let later = ticket(cache.get(&name("main")));
        cache.name_ttl = Duration::MAX;

        cache.insert(state(0, Some("main")), later);
        cache.insert(state(0, Some("primary")), earlier);

        assert_eq!(
            hit(cache.get(&name("main"))),
            Some(Uuid::from_u128(0)),
            "the default's binding follows the later lookup too"
        );
        assert!(
            matches!(cache.get(&name("primary")), Lookup::Miss(_)),
            "the older answer does not restore the builder-time name"
        );
        assert_eq!(cache.names(), 1, "one name for the default as well");
    }

    /// A rename: the name now resolves to another id. The binding moves,
    /// and evicting the id it used to name does not take it away.
    #[test]
    fn a_name_that_moved_to_another_keyset_follows_it() {
        let mut cache = cache(2);
        cache.load(state(1, Some("acme")));
        cache.load(state(2, Some("acme")));
        assert_eq!(
            hit(cache.get(&name("acme"))),
            Some(Uuid::from_u128(2)),
            "the name moved to the keyset that now answers to it"
        );

        // Evict 1 (the oldest): "acme" belongs to 2 now and stays.
        assert!(matches!(cache.get(&id(2)), Lookup::Hit(_)), "touch 2");
        cache.load(state(3, None));
        assert!(
            matches!(cache.get(&id(1)), Lookup::Miss(_)),
            "1 was the least recently used and went"
        );
        assert_eq!(
            hit(cache.get(&name("acme"))),
            Some(Uuid::from_u128(2)),
            "evicting the keyset a name has left must not take the binding"
        );
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
        assert_eq!(cache.names(), 0, "the binding went with the entry");

        cache.insert(state(1, Some("acme")), earlier);
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Miss(_)),
            "the name the later lookup moved away is not taken back"
        );
        assert_eq!(cache.names(), 0, "and nothing else was bound either");

        // A lookup later than the evicted binding still binds: the watermark
        // does not close the name index for good.
        let next = ticket(cache.get(&name("acme")));
        cache.insert(state(1, Some("acme")), next);
        assert_eq!(
            hit(cache.get(&name("acme"))),
            Some(Uuid::from_u128(1)),
            "a lookup later than the watermark binds as usual"
        );
    }

    /// An entry carries its place in the order whether or not it still owns
    /// a name, and eviction must leave that place behind either way. A
    /// keyset whose name has already moved to another keyset is exactly the
    /// one an old answer would rebind: here three lookups resolve `old` to
    /// keyset 1, then `new` to keyset 1, then `new` to keyset 2, and the
    /// first answer — from before either rename — lands last, into a cache
    /// that evicted keyset 1 after taking `new` off it.
    #[test]
    fn an_evicted_keyset_leaves_its_place_in_the_order_with_or_without_a_name() {
        let mut cache = cache(1);
        let oldest = ticket(cache.get(&name("old")));
        let middle = ticket(cache.get(&name("new")));
        let newest = ticket(cache.get(&name("new")));

        // `new` meant 1, then 2: binding the later answer takes the name off
        // 1, and caching 2 evicts 1 with no name of its own to leave behind.
        cache.insert(state(1, Some("new")), middle);
        cache.insert(state(2, Some("new")), newest);
        assert_eq!(
            hit(cache.get(&name("new"))),
            Some(Uuid::from_u128(2)),
            "`new` means keyset 2 after the second rename"
        );

        cache.insert(state(1, Some("old")), oldest);
        assert!(
            matches!(cache.get(&name("old")), Lookup::Miss(_)),
            "a name from before two renames is not bound by the answer that lands last"
        );
        assert_eq!(cache.names(), 0, "and no other binding was made");
    }

    /// The entry an old answer's own insert evicts can be the very one its
    /// binding should lose to, so eviction must happen before the binding
    /// is tried: with room for one, `old` resolves to keyset 1, then to
    /// keyset 2, then keyset 2 is renamed `new`, and the first answer lands
    /// last — into a cache that holds keyset 2 under `new` and has no
    /// binding for `old` at all. Caching keyset 1 evicts keyset 2; the
    /// watermark that eviction leaves is what refuses the stale `old`.
    #[test]
    fn an_older_answer_does_not_bind_a_name_past_the_entry_its_own_insert_evicts() {
        let mut cache = cache(1);
        let oldest = ticket(cache.get(&name("old")));
        let middle = ticket(cache.get(&name("old")));
        let _ = cache.insert(state(2, Some("old")), middle);
        let newest = ticket(cache.get(&name("new")));
        let _ = cache.insert(state(2, Some("new")), newest);
        assert!(
            matches!(cache.get(&name("old")), Lookup::Miss(_)),
            "renaming keyset 2 to `new` took `old` off it"
        );

        let answer = cache.insert(state(1, Some("old")), oldest);
        assert_eq!(
            answer.id,
            Uuid::from_u128(1),
            "nothing later is known about `old`, so the answer stands for this lookup"
        );
        assert_eq!(
            hit(cache.get(&id(1))),
            Some(Uuid::from_u128(1)),
            "and keyset 1 is cached by id, evicting keyset 2"
        );
        assert!(
            matches!(cache.get(&name("old")), Lookup::Miss(_)),
            "but an answer older than the entry its insert evicted binds no name"
        );
        assert_eq!(cache.names(), 0, "and no other binding was made");
    }

    /// The caller of a lookup whose answer lost to a later one is answered
    /// with the later one — the keyset every selection after it gets — not
    /// with the answer that lost, which would mint under a keyset the name
    /// has since left.
    #[test]
    fn a_lookup_whose_answer_lost_is_answered_with_the_one_that_won() {
        let mut cache = cache(4);
        let earlier = ticket(cache.get(&name("acme")));
        let later = ticket(cache.get(&name("acme")));

        // `acme` moved from keyset 1 to keyset 2 between the two lookups,
        // and the later answer lands first.
        let _ = cache.insert(state(2, Some("acme")), later);
        let answer = cache.insert(state(1, Some("acme")), earlier);
        assert_eq!(
            answer.id,
            Uuid::from_u128(2),
            "the earlier lookup is answered with what `acme` means now"
        );
        assert_eq!(
            hit(cache.get(&id(1))),
            Some(Uuid::from_u128(1)),
            "keyset 1 is still cached by id: its key material is right whichever lookup asked"
        );

        // The same keyset resolved under a newer name: the older answer is
        // dropped whole, and its caller gets the state the keyset holds.
        let earlier = ticket(cache.get(&name("acme-corp")));
        let later = ticket(cache.get(&name("acme-corp")));
        let _ = cache.insert(state(3, Some("acme-corp")), later);
        let answer = cache.insert(state(3, Some("acme")), earlier);
        assert_eq!(
            answer.name.as_deref(),
            Some("acme-corp"),
            "an answer older than the keyset's own is replaced by the keyset's"
        );
    }

    /// The later answer reaches the earlier caller even when caching the
    /// earlier one evicts it: what the name means is decided before the
    /// eviction, or the eviction the losing insert triggers would take the
    /// winner — alias and all — and leave the loser as the only answer.
    #[test]
    fn a_lookup_whose_answer_lost_is_answered_with_the_winner_its_own_insert_evicts() {
        let mut cache = cache(1);
        let earlier = ticket(cache.get(&name("acme")));
        let later = ticket(cache.get(&name("acme")));
        let _ = cache.insert(state(2, Some("acme")), later);

        let answer = cache.insert(state(1, Some("acme")), earlier);
        assert_eq!(
            answer.id,
            Uuid::from_u128(2),
            "the earlier lookup is answered with what `acme` means now, though caching its answer evicted keyset 2"
        );
        assert_eq!(
            hit(cache.get(&id(1))),
            Some(Uuid::from_u128(1)),
            "keyset 1 is cached by id all the same"
        );
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Miss(_)),
            "and the loser bound no name: it is older than the watermark keyset 2 left"
        );
    }

    /// Newer information can exist for both the name asked and the keyset
    /// answered: `old` resolves to keyset 1, then `old` moves to keyset 2,
    /// then keyset 1 is resolved under `new`, and the first answer lands
    /// last. It is older than what keyset 1 holds, so it is dropped whole —
    /// but its caller asked for `old`, and `old` means keyset 2 now.
    #[test]
    fn a_dropped_answer_is_answered_by_its_name_before_its_keyset() {
        let mut cache = cache(4);
        let oldest = ticket(cache.get(&name("old")));
        let middle = ticket(cache.get(&name("old")));
        let newest = ticket(cache.get(&name("new")));
        let _ = cache.insert(state(2, Some("old")), middle);
        let _ = cache.insert(state(1, Some("new")), newest);

        let answer = cache.insert(state(1, Some("old")), oldest);
        assert_eq!(
            answer.id,
            Uuid::from_u128(2),
            "the caller asked for `old`, which means keyset 2 now — not keyset 1, whose own later answer came under `new`"
        );
        assert_eq!(
            hit(cache.get(&name("old"))),
            Some(Uuid::from_u128(2)),
            "`old` still means keyset 2"
        );
        assert_eq!(
            hit(cache.get(&name("new"))),
            Some(Uuid::from_u128(1)),
            "and `new` still means keyset 1"
        );
        assert_eq!(cache.names(), 2, "no other binding was made");
    }

    /// ZeroKMS answering "no keyset has this name" is an answer about the
    /// name: the binding an earlier lookup made goes, an earlier positive
    /// answer still in flight cannot bind the name after it, a later lookup
    /// binds as usual, and a negative answer older than the binding that
    /// stands leaves it standing. A zero window, so every name lookup is a
    /// lookup with a ticket and a bound name reads as `Stale`.
    #[test]
    fn a_negative_answer_unbinds_a_name_and_refuses_earlier_answers_for_it() {
        let mut cache = holding(
            NonZeroUsize::new(4).unwrap(),
            Duration::ZERO,
            state(0, None),
        );
        cache.load(state(1, Some("acme")));
        let earlier = ticket(cache.get(&name("acme")));
        let negative = ticket(cache.get(&name("acme")));

        cache.forget("acme", negative);
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Miss(_)),
            "the binding the earlier load made is gone"
        );
        assert_eq!(
            hit(cache.get(&id(1))),
            Some(Uuid::from_u128(1)),
            "the keyset itself stays cached: only the name was answered"
        );

        let answer = cache.insert(state(1, Some("acme")), earlier);
        assert_eq!(
            answer.id,
            Uuid::from_u128(1),
            "nothing later positive is known about `acme`, so the answer stands for its own caller"
        );
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Miss(_)),
            "but it binds no name: ZeroKMS has since said `acme` is bound to nothing"
        );

        let later = ticket(cache.get(&name("acme")));
        let _ = cache.insert(state(2, Some("acme")), later);
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Stale(_)),
            "a lookup later than the negative answer binds as usual"
        );

        let stale_negative = ticket(cache.get(&name("acme")));
        let fresher = ticket(cache.get(&name("acme")));
        let _ = cache.insert(state(3, Some("acme")), fresher);
        cache.forget("acme", stale_negative);
        assert!(
            matches!(cache.get(&name("acme")), Lookup::Stale(_)),
            "a negative answer older than the binding that stands says nothing about it"
        );
    }

    /// Past the window a name lookup is stale — the keyset is still there,
    /// the binding is not trusted — and a re-resolution refreshes it.
    #[test]
    fn a_name_binding_ages_out_and_is_refreshed_by_reinsertion() {
        let mut cache = holding(
            NonZeroUsize::new(4).unwrap(),
            Duration::ZERO,
            state(0, Some("primary")),
        );
        cache.load(state(1, Some("one")));

        assert!(
            matches!(cache.get(&name("one")), Lookup::Stale(_)),
            "past its window a name binding is not trusted"
        );
        assert!(
            matches!(cache.get(&name("primary")), Lookup::Stale(_)),
            "the default's builder-time name ages the same way"
        );
        assert!(
            matches!(cache.get(&id(1)), Lookup::Hit(_)),
            "an id never ages"
        );

        // A zero window is stale again immediately after a refresh — with
        // no time elapsed at all, on the coarsest clock — which is the point
        // of a zero window; a wide one is fresh.
        cache.load(state(1, Some("one")));
        assert!(
            matches!(cache.get(&name("one")), Lookup::Stale(_)),
            "a zero window is stale again the instant it is refreshed"
        );
        cache.name_ttl = Duration::MAX;
        assert!(
            matches!(cache.get(&name("one")), Lookup::Hit(_)),
            "a wide window is fresh"
        );
    }
}
