//! [`Pending`]: the request carrier [`StackCipher`] hands back from
//! [`EncryptTarget`](super::EncryptTarget) / [`DecryptSource`](super::DecryptSource),
//! and the single place the target layer talks to ZeroKMS.
//!
//! A `Pending` is built synchronously and settled once. Combining pendings
//! merges their [`Request`]s without doing any I/O; awaiting the combined
//! result issues the batched ZeroKMS calls ([`dispatch`]) — one
//! `generate_keys` for every generate, since a pending mints under one
//! keyset, and one `retrieve_keys` per keyset the leaves being opened were
//! sealed under — and then runs each fulfilment over exactly the
//! [`Responses`] its own requests asked for.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::Arc;

use stack_kms::{
    DataKey, DataKeySource, GenerateKeyPayload, IndexKeySource, Iv, MaybeSend, RetrieveKeyPayload,
    UnverifiedContext,
};
use uuid::Uuid;

use super::request::{tally, KeysetAnswer, Request, RequestKind, Responses};
use crate::audit::{AuditMetadata, Audited, Unverified};
use crate::contexts::CallContexts;
use crate::credential::{KeySource, WithCredential};
use crate::keyset::{Kept, KeysetState, Selected};
use crate::OwnIdentity;
use crate::{Descriptor, Error, KeysetCipher, StackCipher};
use vitaminc_aead::ContextPiece;

/// The boxed fulfilment: consumes this pending's slice of the responses and
/// produces the output, or does part of the work and returns the rest
/// ([`Fulfilled::More`]). The `Send` split mirrors
/// [`kms::MaybeSend`](crate::kms::MaybeSend) — the underlying ZeroKMS
/// futures are not `Send` on wasm32.
#[cfg(not(target_arch = "wasm32"))]
type FulfilBox<'a, T> =
    Box<dyn FnOnce(&mut Responses) -> Result<Fulfilled<'a, T>, Error> + Send + 'a>;
/// See the native definition above; identical minus the `Send` bound.
#[cfg(target_arch = "wasm32")]
type FulfilBox<'a, T> = Box<dyn FnOnce(&mut Responses) -> Result<Fulfilled<'a, T>, Error> + 'a>;

/// What one run of a fulfilment produced.
///
/// Only a column ([`Pending::all`]) in a wasm guest stops part way: after about
/// [`YIELD_EVERY`] data keys' worth of items it returns the rest of itself,
/// and [`settle_with`](Pending::settle_with) yields to the async runtime
/// before it runs the rest. A host that cannot preempt the work (the Go
/// SDK's wasm guest, whose garbage collector waits for a running guest
/// call) gets control back between chunks. Everything else runs a
/// fulfilment to its end without yielding ([`finish`]).
enum Fulfilled<'a, T> {
    /// The output.
    Done(T),
    /// The rest of the fulfilment, over the same responses. Dropping it
    /// drops what the work recovered so far as an error would: a column's
    /// recovered items are released, and wiped, by its guard. Only a wasm
    /// guest's column makes one.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    More(FulfilBox<'a, T>),
}

/// How many data keys' worth of items a column fulfils between yields, in
/// a wasm guest. `stack-kms` has its own copy (`futures::YIELD_EVERY`, for
/// deriving keys), and the two are meant to stay equal.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const YIELD_EVERY: usize = 64;

/// Run `fulfil` to its end, without yielding.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
fn finish<'a, T>(mut fulfil: FulfilBox<'a, T>, responses: &mut Responses) -> Result<T, Error> {
    loop {
        match fulfil(responses)? {
            Fulfilled::Done(value) => return Ok(value),
            Fulfilled::More(rest) => fulfil = rest,
        }
    }
}

/// `fulfil`, then `f` on its output, keeping its chunks: a [`Fulfilled::More`]
/// comes back as the rest followed by `f`.
fn then<'a, T: 'a, U: 'a>(
    fulfil: FulfilBox<'a, T>,
    f: impl FnOnce(T) -> Result<U, Error> + MaybeSend + 'a,
) -> FulfilBox<'a, U> {
    Box::new(move |responses| match fulfil(responses)? {
        Fulfilled::Done(value) => f(value).map(Fulfilled::Done),
        Fulfilled::More(rest) => Ok(Fulfilled::More(then(rest, f))),
    })
}

/// Yield to the async runtime once: wake this task and return pending, so
/// the runtime polls it again after other work. On tokio that reschedules
/// the task. In a wasm guest's step loop it hands control back to the host
/// (see `stack-guest-abi`'s step module). `stack-kms` has its own copy
/// (`futures::YieldNow`), and the two are meant to stay equal.
struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if self.0 {
            return std::task::Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    }
}

/// How to wipe a recovered value in place. A decrypt sets it on the pending
/// it returns ([`wiping`](Pending::wiping)), so that [`zip`](Pending::zip) and
/// [`all`](Pending::all) can wipe that value when a later operation in the
/// same batch fails. `Send` split as above.
#[cfg(not(target_arch = "wasm32"))]
type WipeHook<'a, T> = Arc<dyn Fn(&mut T) + Send + Sync + 'a>;
/// See the native definition above; identical minus the `Send` and `Sync`
/// bounds.
#[cfg(target_arch = "wasm32")]
type WipeHook<'a, T> = Arc<dyn Fn(&mut T) + 'a>;

/// What builds a pending once its keyset is loaded: see
/// [`Pending::after_load`]. `Send` split as above.
#[cfg(not(target_arch = "wasm32"))]
type BuildBox<'a, T, K> = Box<dyn FnOnce(&KeysetCipher<'a, K>) -> Pending<'a, T, K> + Send + 'a>;
/// See the native definition above; identical minus the `Send` bound.
#[cfg(target_arch = "wasm32")]
type BuildBox<'a, T, K> = Box<dyn FnOnce(&KeysetCipher<'a, K>) -> Pending<'a, T, K> + 'a>;

/// The boxed future a [`Pending`] settles through; `Send` split as above.
#[cfg(not(target_arch = "wasm32"))]
pub type PendingFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
/// See the native definition above; identical minus the `Send` bound.
#[cfg(target_arch = "wasm32")]
pub type PendingFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + 'a>>;

/// A request carrier resolving to `T`, built by the cipher executing an
/// encryption or decryption declaration.
///
/// **Not a future** until awaited. A `Pending` holds the ZeroKMS requests its
/// value needs plus the fulfilment that shapes the responses; combining
/// pendings ([`zip`](Self::zip), [`map`](Self::map), [`all`](Self::all))
/// merges requests *without doing any I/O*, which is where batching comes
/// from: however many pendings are merged, awaiting the result issues **one**
/// batched ZeroKMS call per request kind and then runs every fulfilment over
/// the shared response set.
///
/// Construct leaves with [`ready`](Self::ready) (value already derived,
/// nothing to request) or [`request`](Self::request) (value needs ZeroKMS
/// responses).
// `T: 'a` is written out: the compiler inferred it from `fulfil` until the
// type came to name itself in `build`, and code that takes a
// `Pending<'_, T, K>` relies on it.
#[must_use = "a Pending does nothing until it is awaited or merged into one that is; \
              dropping it silently discards the value and any error that produced it"]
pub struct Pending<'a, T: 'a, K> {
    /// The cipher the settled batch dispatches through. Which
    /// [`StackCipher`] value it is does not constrain merging — see
    /// [`zip`](Self::zip) — only which client issues the calls.
    cipher: &'a StackCipher<K>,
    /// The keyset this pending is confined to: the one a [`KeysetCipher`]
    /// built it through, or none when it was built through the
    /// [`StackCipher`]. A pending confined to a keyset mints every data key
    /// under it and opens leaves from no other; one with no keyset mints
    /// nothing ([`Error::NoKeyset`]) and opens leaves from any keyset, one
    /// retrieve call per keyset. Merging two pendings confined to different
    /// keysets is [`Error::KeysetMismatch`].
    ///
    /// A pending built through a keyset that was not loaded yet works
    /// under that keyset without its id
    /// ([`KeysetSelector::not_loaded`]). Settling the pending loads the
    /// keyset and applies the rules above then.
    keyset: KeysetSelector,
    requests: Vec<Request>,
    /// Set when the value already failed during the synchronous build
    /// (`ready(Err(..))`, a keyset mismatch, a failed sibling). A failed
    /// pending carries no requests, and merging one into an assembly drops
    /// the assembly's requests too, so settling it does no I/O: a record
    /// with one misconfigured field never mints data keys it will throw away.
    /// When set, `fulfil` is never called.
    failed: Option<Error>,
    /// The query context and the stored context of every leaf this pending
    /// seals or indexes, in the order the leaves ran. What
    /// [`context`](Self::context) shows. A failed pending carries none, as
    /// it carries no requests.
    contexts: Vec<(ContextPiece<'static>, ContextPiece<'static>)>,
    /// How to wipe this pending's output, when the output is recovered
    /// plaintext. A batch calls it when a later operation fails after this
    /// one's output was recovered. `None` for an output that is not
    /// plaintext, or whose type is not known to be `Zeroize` here.
    wipe: Option<WipeHook<'a, T>>,
    fulfil: FulfilBox<'a, T>,
    /// Set for a pending that cannot be built until its keyset is
    /// loaded ([`after_load`](Self::after_load)). Settling it loads the
    /// keyset, builds the pending this returns, and settles that one. The
    /// requests and `fulfil` above are unused until then.
    build: Option<BuildBox<'a, T, K>>,
}

/// Which keyset a [`CipherRef`] or a [`Pending`] works under: none, one
/// whose id is known, or one that was selected and is not loaded yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeysetSelector {
    /// The keyset's id, when it is known.
    id: Option<Uuid>,
    /// Keysets that were selected and were not loaded when a call was
    /// built through them: the default keyset, or one selected by id or by
    /// name. Settling a pending loads each one. Merged pendings can name
    /// more than one, and all of them must turn out to be one keyset.
    not_loaded: Vec<NotLoaded>,
}

/// A keyset that was selected and not loaded when a call was built through
/// its handle, with what the handle keeps of the keyset once it is loaded.
#[derive(Clone)]
struct NotLoaded {
    selected: Selected,
    /// Shared with the handle. Settling a pending sets it if it is empty,
    /// and reads it otherwise: see [`Kept`].
    kept: Kept,
}

/// Two are the same when they came from one handle, or from its clones.
impl PartialEq for NotLoaded {
    fn eq(&self, other: &Self) -> bool {
        self.selected == other.selected && Arc::ptr_eq(&self.kept, &other.kept)
    }
}

impl Eq for NotLoaded {}

/// Shows the selection. The kept state holds an index key, and is not
/// shown.
impl std::fmt::Debug for NotLoaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.selected.fmt(f)
    }
}

impl KeysetSelector {
    /// No keyset: what a reference to the client has.
    pub(crate) const ANY: Self = Self {
        id: None,
        not_loaded: Vec::new(),
    };

    /// The keyset `id`, loaded.
    pub(crate) fn keyset(id: Uuid) -> Self {
        Self {
            id: Some(id),
            not_loaded: Vec::new(),
        }
    }

    /// The keyset `selected`, which is not loaded yet, with what its handle
    /// keeps of it. Its id is known only when it was selected by id.
    pub(crate) fn not_loaded(selected: Selected, kept: Kept) -> Self {
        let id = match &selected {
            Selected::By(stack_kms::IdentifiedBy::Uuid(id)) => Some(*id),
            Selected::By(stack_kms::IdentifiedBy::Name(_)) | Selected::Default => None,
        };
        Self {
            id,
            not_loaded: vec![NotLoaded { selected, kept }],
        }
    }

    /// The keyset's id, when it is known.
    pub(crate) fn id(&self) -> Option<Uuid> {
        self.id
    }

    /// Whether this names no keyset at all.
    fn is_any(&self) -> bool {
        self.id.is_none() && self.not_loaded.is_empty()
    }

    /// The keyset two merged pendings work under: either's when the other
    /// names none, [`Error::KeysetMismatch`] when both give an id and the
    /// two differ. A keyset that is not loaded yet cannot be compared
    /// here. [`resolved_id`] compares it when the pending settles.
    fn merge(mut self, other: Self) -> Result<Self, Error> {
        self.id = match (self.id, other.id) {
            (Some(left), Some(right)) if left != right => {
                return Err(Error::KeysetMismatch { left, right })
            }
            (left, right) => left.or(right),
        };
        for selected in other.not_loaded {
            if !self.not_loaded.contains(&selected) {
                self.not_loaded.push(selected);
            }
        }
        Ok(self)
    }
}

/// The cipher that a [`Pending`] operation runs through: a borrowed
/// client, and the ID of one keyset if the operation is limited to it.
///
/// # How to pass one
///
/// You do not need to name this type. Each entry point that can run
/// through either cipher accepts `impl Into<CipherRef>`, so pass `&cipher`
/// or `&keyset`. These entry points are:
///
/// - the decrypt entry points, such as
///   [`DecryptFrom::decrypt_from`](super::DecryptFrom::decrypt_from) and
///   `dynamic::record::decrypt`
/// - the [`Pending`] constructors
///
/// An entry point that encrypts needs a keyset to generate keys under.
/// That entry point accepts a [`KeysetCipher`], and not a `CipherRef`.
///
/// # What each reference can do
///
/// A `CipherRef` comes from a reference to a [`StackCipher`], or from a
/// [`KeysetCipher`], borrowed or owned:
///
/// - A reference to a [`StackCipher`] is limited to no keyset. The
///   operation opens a leaf sealed under any keyset the client can use.
///   The operation cannot generate a key ([`Error::NoKeyset`]).
/// - A [`KeysetCipher`] limits the operation to that keyset. The
///   operation refuses a leaf from another keyset before it retrieves any
///   key ([`Error::ForeignKeyset`]).
///
/// No other conversion makes a `CipherRef`. The keyset in a `CipherRef`
/// is therefore one that the cipher loaded from ZeroKMS, or one that was
/// selected and is loaded when the call is awaited. Both rules above apply
/// to every [`Pending`].
///
/// # Lifetime
///
/// A `CipherRef` made from a [`KeysetCipher`] keeps the keyset's ID and
/// the borrowed client, and does not keep the `KeysetCipher`. The
/// `CipherRef` is valid for as long as the client is, even when the
/// `KeysetCipher` is a temporary value. It is `Clone` and not `Copy`: a
/// keyset selected by name that is not loaded yet is kept by its name.
///
/// ```
/// use stack_encrypt::{CipherRef, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// let any = CipherRef::from(&cipher);
/// assert_eq!(any.keyset_id(), None);
/// let one = CipherRef::from(&keyset);
/// assert_eq!(one.keyset_id(), Some(keyset.keyset_id().await?));
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
pub struct CipherRef<'c, K> {
    cipher: &'c StackCipher<K>,
    keyset: KeysetSelector,
}

impl<'c, K> CipherRef<'c, K> {
    /// The client that the pending operation runs through.
    pub(crate) fn cipher(&self) -> &'c StackCipher<K> {
        self.cipher
    }

    /// The keyset the operation works under.
    pub(crate) fn keyset(&self) -> &KeysetSelector {
        &self.keyset
    }

    /// Returns the ID of the keyset that this reference is limited to.
    ///
    /// Returns `None` for a reference to a [`StackCipher`]. That
    /// reference is limited to no keyset.
    ///
    /// Also returns `None` for a keyset that the cipher has not loaded
    /// yet, unless it was selected by its ID. That reference is limited to
    /// the keyset, and the ID is known once a call has loaded it. See
    /// [`KeysetCipher`].
    pub fn keyset_id(&self) -> Option<Uuid> {
        self.keyset.id()
    }
}

impl<K> Clone for CipherRef<'_, K> {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher,
            keyset: self.keyset.clone(),
        }
    }
}

// Written by hand, so that `K: Debug` is not needed. A data-key source
// rarely implements `Debug`.
impl<K> std::fmt::Debug for CipherRef<'_, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherRef")
            .field("keyset_id", &self.keyset.id())
            .finish_non_exhaustive()
    }
}

impl<'c, K> From<&'c StackCipher<K>> for CipherRef<'c, K> {
    fn from(cipher: &'c StackCipher<K>) -> Self {
        Self {
            cipher,
            keyset: KeysetSelector::ANY,
        }
    }
}

impl<'c, K> From<&KeysetCipher<'c, K>> for CipherRef<'c, K> {
    fn from(keyset: &KeysetCipher<'c, K>) -> Self {
        Self {
            cipher: keyset.cipher(),
            keyset: keyset.selector(),
        }
    }
}

impl<'c, K> From<KeysetCipher<'c, K>> for CipherRef<'c, K> {
    fn from(keyset: KeysetCipher<'c, K>) -> Self {
        Self::from(&keyset)
    }
}

impl<'a, T: 'a, K> Pending<'a, T, K> {
    /// A pending with no requests: `result` was fully derived during the
    /// synchronous build. Awaiting it does no I/O.
    pub fn ready(cipher_ref: impl Into<CipherRef<'a, K>>, result: Result<T, Error>) -> Self
    where
        T: MaybeSend,
    {
        let cipher_ref: CipherRef<'a, K> = cipher_ref.into();
        match result {
            Ok(value) => Self {
                cipher: cipher_ref.cipher(),
                keyset: cipher_ref.keyset().clone(),
                requests: Vec::new(),
                failed: None,
                contexts: Vec::new(),
                wipe: None,
                fulfil: Box::new(move |_| Ok(Fulfilled::Done(value))),
                build: None,
            },
            Err(error) => Self::failed(cipher_ref, error),
        }
    }

    /// A pending that already failed. No requests, no `T` bound (nothing of
    /// type `T` is ever produced), and any assembly it is merged into fails
    /// without I/O — see the `failed` field.
    ///
    /// Public because a hand-written `EncryptTarget` / `DecryptSource` that
    /// works with a [`CipherRef`] directly reaches for it when a contract is
    /// broken — e.g. [`Error::NotOpened`] for a field whose type declared
    /// [`DECRYPTABLE`](super::Decryptable::DECRYPTABLE) but was passed over.
    /// Inside an operation description, [`Encryption::failed`] and
    /// [`Decryption::failed`] are the same thing without the cipher; the
    /// derives' generated code uses those.
    ///
    /// [`Encryption::failed`]: super::Encryption::failed
    /// [`Decryption::failed`]: super::Decryption::failed
    pub fn failed(cipher_ref: impl Into<CipherRef<'a, K>>, error: Error) -> Self {
        let cipher_ref: CipherRef<'a, K> = cipher_ref.into();
        Self {
            cipher: cipher_ref.cipher(),
            keyset: cipher_ref.keyset().clone(),
            requests: Vec::new(),
            failed: Some(error),
            contexts: Vec::new(),
            wipe: None,
            // Unreachable: `settle` returns the stored error before any
            // fulfilment runs. Kept honest rather than panicking.
            fulfil: Box::new(|_| {
                Err(Error::Other(
                    "fulfilment invoked on an already-failed pending".into(),
                ))
            }),
            build: None,
        }
    }

    /// A pending whose value needs ZeroKMS responses. `fulfil` runs after the
    /// batched call, over exactly the responses `requests` asked for —
    /// drawing more (or another kind) is [`Error::ResponseShape`], and can
    /// never consume a sibling pending's responses.
    ///
    /// The match is exact in both directions: a fulfilment must also consume
    /// *every* response it asked for. Leaving one behind is
    /// [`Error::ResponseShape`] too — the key was minted at ZeroKMS, and
    /// silently discarding it means the pending's declared requests do not
    /// describe what it actually does.
    ///
    /// The keyset rules apply at construction, before any I/O: a generate
    /// request through a [`StackCipher`] is [`Error::NoKeyset`], and a
    /// retrieve request that names another keyset than the
    /// [`KeysetCipher`]'s is [`Error::ForeignKeyset`].
    pub fn request<F>(
        cipher_ref: impl Into<CipherRef<'a, K>>,
        requests: Vec<Request>,
        fulfil: F,
    ) -> Self
    where
        F: FnOnce(&mut Responses) -> Result<T, Error> + MaybeSend + 'a,
    {
        let cipher_ref: CipherRef<'a, K> = cipher_ref.into();
        let (generated, retrieved, keysets) = tally(&requests);
        if let Err(error) = check_keyset(cipher_ref.keyset(), &requests) {
            return Self::failed(cipher_ref, error);
        }
        Self {
            cipher: cipher_ref.cipher(),
            keyset: cipher_ref.keyset().clone(),
            requests,
            failed: None,
            contexts: Vec::new(),
            wipe: None,
            fulfil: Box::new(move |responses| {
                let mut own = responses.split_front(generated, retrieved, keysets)?;
                let value = fulfil(&mut own)?;
                if !own.is_exhausted() {
                    return Err(Error::ResponseShape);
                }
                Ok(Fulfilled::Done(value))
            }),
            build: None,
        }
    }

    /// A pending that can only be built once its keyset is loaded: its
    /// requests depend on something derived under the keyset's index key,
    /// such as the key a JSON read opens its rows with.
    ///
    /// `keyset` is a handle on a keyset that is not loaded yet. Settling
    /// the pending loads the keyset, calls `build` with a handle on the
    /// loaded keyset, and settles the pending `build` returns. So `build`
    /// owns what it reads.
    ///
    /// Every other call derives what it needs when its responses arrive
    /// ([`KeysetCipher::deferred`]). This one has no requests until it is
    /// built. It still merges like any pending ([`zip`](Self::zip),
    /// [`all`](Self::all)): the merged pending is built when it settles
    /// too, and then makes one request for each kind.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn after_load<F>(keyset: &KeysetCipher<'a, K>, build: F) -> Self
    where
        F: FnOnce(&KeysetCipher<'a, K>) -> Pending<'a, T, K> + MaybeSend + 'a,
    {
        let cipher_ref = CipherRef::from(keyset);
        Self::unbuilt(
            cipher_ref.cipher(),
            cipher_ref.keyset().clone(),
            Box::new(build),
        )
    }

    /// A pending that `build` makes when it settles, under `keyset`.
    fn unbuilt(
        cipher: &'a StackCipher<K>,
        keyset: KeysetSelector,
        build: BuildBox<'a, T, K>,
    ) -> Self {
        Self {
            cipher,
            keyset,
            requests: Vec::new(),
            failed: None,
            contexts: Vec::new(),
            // What `build` returns carries its own.
            wipe: None,
            fulfil: Box::new(|_| {
                Err(Error::Other(
                    "fulfilment invoked on a pending that is not built".into(),
                ))
            }),
            build: Some(build),
        }
    }

    /// This pending, changed by `change` once it is built. For a pending
    /// from [`after_load`](Self::after_load) only.
    fn rebuilt<U: 'a>(
        self,
        build: BuildBox<'a, T, K>,
        change: impl FnOnce(Pending<'a, T, K>) -> Pending<'a, U, K> + MaybeSend + 'a,
    ) -> Pending<'a, U, K> {
        Pending::unbuilt(
            self.cipher,
            self.keyset,
            Box::new(move |keyset| change(build(keyset))),
        )
    }

    /// This pending without its cipher: what a merged pending that is not
    /// built yet keeps of each side. A reference to the cipher would make
    /// what keeps it `Send` only for a `Sync` key source.
    fn detached(self) -> Detached<'a, T, K> {
        Detached {
            keyset: self.keyset,
            requests: self.requests,
            failed: self.failed,
            contexts: self.contexts,
            wipe: self.wipe,
            fulfil: self.fulfil,
            build: self.build,
        }
    }

    /// Transform the resolved value. No I/O, no new requests.
    pub fn map<U: 'a, F>(self, f: F) -> Pending<'a, U, K>
    where
        F: FnOnce(T) -> U + MaybeSend + 'a,
    {
        let mut pending = self;
        if let Some(build) = pending.build.take() {
            return pending.rebuilt(build, move |built| built.map(f));
        }
        let fulfil = pending.fulfil;
        Pending {
            cipher: pending.cipher,
            keyset: pending.keyset,
            requests: pending.requests,
            failed: pending.failed,
            contexts: pending.contexts,
            // The output is a new value. Whether it holds plaintext is not
            // known here.
            wipe: None,
            fulfil: then(fulfil, move |value| Ok(f(value))),
            build: None,
        }
    }

    /// Fallibly transform the resolved value without issuing another request.
    pub fn try_map<U: 'a, F>(self, f: F) -> Pending<'a, U, K>
    where
        F: FnOnce(T) -> Result<U, Error> + MaybeSend + 'a,
    {
        let mut pending = self;
        if let Some(build) = pending.build.take() {
            return pending.rebuilt(build, move |built| built.try_map(f));
        }
        let fulfil = pending.fulfil;
        Pending {
            cipher: pending.cipher,
            keyset: pending.keyset,
            requests: pending.requests,
            failed: pending.failed,
            contexts: pending.contexts,
            wipe: None,
            fulfil: then(fulfil, f),
            build: None,
        }
    }

    /// Send `metadata` with every key request that this call makes, for
    /// the ZeroKMS audit log. Audit metadata is optional: a call without it
    /// sends none.
    ///
    /// ```
    /// use stack_encrypt::{AuditMetadata, Ciphertext, StackCipher};
    ///
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
    /// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
    /// // the environment, or from the profile that `npx stash auth login` writes.
    /// let cipher = StackCipher::builder()
    /// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    ///     .init()
    ///     .await?;
    /// let keyset = cipher.default_keyset();
    /// let purpose = AuditMetadata::new().with("purpose", "store api key");
    ///
    /// let stored: Ciphertext = keyset
    ///     .encrypt(String::from("sk_live_1234"))
    ///     .audit(purpose)
    ///     .await?;
    /// # let _ = stored;
    /// # Ok::<(), stack_encrypt::Error>(())
    /// # }).unwrap();
    /// ```
    ///
    /// ZeroKMS does not verify the metadata. A decrypt does not need it.
    /// ZeroKMS writes the metadata to its logs, so do not send plaintext or
    /// secrets. See [`AuditMetadata`] for the full rules.
    ///
    /// # One map for each call
    ///
    /// A call can make several key requests: one `generate_keys`, and one
    /// `retrieve_keys` for each keyset it decrypts leaves from. Each
    /// request is sent with the same metadata.
    ///
    /// Some calls request no data key: a query term, for example, or a
    /// call over an empty list. Those calls send no metadata, because they
    /// make no request to send it with. Those calls still succeed.
    /// [`Audited`] lists them. Empty metadata sends none either.
    ///
    /// # Attach it last
    ///
    /// The result is an [`Audited`] call. You can only await it. So call
    /// [`zip`](Self::zip), [`all`](Self::all), and [`map`](Self::map)
    /// first. Then attach the metadata to the whole call.
    pub fn audit(self, metadata: AuditMetadata) -> Audited<Self> {
        Audited::new(self, metadata)
    }

    /// Mark this pending's output as plaintext that can be wiped in place.
    /// [`zip`](Self::zip) and [`all`](Self::all) then wipe it if a later
    /// operation in the same batch fails after it was recovered. Every
    /// [`DecryptFrom`](super::DecryptFrom) call marks the pending it returns,
    /// and so does each leaf a [`Decryption`](super::Decryption) opens
    /// ([`open`](super::open) and the targets' own openings), so that a
    /// [`Decryption::zip`](super::Decryption::zip) or
    /// [`Decryption::all`](super::Decryption::all) written by hand wipes too.
    ///
    /// A pending that is built when it settles
    /// ([`after_load`](Self::after_load)) is marked when it is built.
    pub(crate) fn wiping(mut self) -> Self
    where
        T: zeroize::Zeroize,
    {
        if let Some(build) = self.build.take() {
            return self.rebuilt(build, Pending::wiping);
        }
        if self.failed.is_none() {
            let wipe: WipeHook<'a, T> = Arc::new(|value: &mut T| value.zeroize());
            self.wipe = Some(wipe);
        }
        self
    }

    /// The contexts this call will use, with the caller's values filled in.
    ///
    /// Each distinct context appears once, in the order the call's leaves
    /// run. No key has been requested: a pending holds its requests until it
    /// is awaited. A pending that has already failed shows no context, and
    /// says that it failed.
    ///
    /// See [`CallContexts`] for an example, and
    /// [`Encryption::contexts`](super::Encryption::contexts) for the same
    /// view of a declaration, with placeholders for the caller's parts.
    pub fn context(&self) -> CallContexts {
        CallContexts::from_pieces(&self.contexts, self.failed.is_some())
    }

    /// Record that this pending's leaf derives its terms under `query` and
    /// its key and AAD under `stored`. The leaf operations call it once
    /// each, with the contexts they validated. A ciphertext alone has one
    /// context, passed twice.
    pub(crate) fn under_context(
        mut self,
        query: ContextPiece<'static>,
        stored: ContextPiece<'static>,
    ) -> Self {
        if self.failed.is_none() {
            self.contexts.push((query, stored));
        }
        self
    }

    /// The cipher and the keyset this pending runs through.
    fn cipher_ref(&self) -> CipherRef<'a, K> {
        CipherRef {
            cipher: self.cipher,
            keyset: self.keyset.clone(),
        }
    }

    #[cfg(test)]
    /// [`confined_to`](Self::confined_to), for a keyset given by its id.
    pub(crate) fn confined_to_id(self, keyset: Uuid) -> Self {
        self.confined_to(&KeysetSelector::keyset(keyset))
    }

    /// Confine this pending to `keyset`, the keyset of the reference the
    /// caller ran it through: what a [`KeysetCipher`]'s decrypt does to the
    /// pending its [`StackCipher`] built, so that opening a leaf from any
    /// other keyset fails before any key is retrieved. A reference to the
    /// client names no keyset, and changes nothing. Confining a pending
    /// already confined to another keyset is [`Error::KeysetMismatch`].
    pub(crate) fn confined_to(self, keyset: &KeysetSelector) -> Self {
        let keyset = match self.keyset.clone().merge(keyset.clone()) {
            Ok(keyset) => keyset,
            Err(error) => return Pending::failed(self.cipher_ref(), error),
        };
        if let Err(error) = check_keyset(&keyset, &self.requests) {
            return Pending::failed(self.cipher_ref(), error);
        }
        Pending { keyset, ..self }
    }

    /// Merge two pendings into one resolving to the pair. Their requests
    /// concatenate — awaiting the result is still one batched call per
    /// request kind.
    ///
    /// Both must agree on a keyset if both are confined to one: the merged
    /// assembly mints every key under one keyset, so merging one tenant's
    /// pending with another's is [`Error::KeysetMismatch`], not a debug
    /// assertion. A pending confined to a keyset, merged with one that has
    /// no keyset, gives a pending confined to that keyset. If either side
    /// already failed, the result is that failure and carries no requests.
    ///
    /// The keyset is the whole rule: the two sides need not have been built
    /// through the *same* [`StackCipher`] value. The merged assembly
    /// dispatches through one of them, and every request it carries is
    /// keyset-addressed — a generate mints under the merged keyset, a
    /// retrieve names the keyset its leaf was sealed under. A keyset id is
    /// global, and a cipher only holds a keyset ZeroKMS resolved for its
    /// client, so either side's client can dispatch the batch; a client that
    /// is *not* authorised for the keyset is refused at ZeroKMS
    /// ([`Error::Kms`]), exactly as it would be on its own.
    ///
    /// When the right side fails after the left side recovered plaintext
    /// (a decrypt whose key arrived), the left side's plaintext is wiped
    /// before the error is returned. A decrypt such as
    /// [`DecryptFrom::decrypt_from`](super::DecryptFrom::decrypt_from) marks
    /// its pending for this. A pending built by [`ready`](Self::ready),
    /// [`request`](Self::request) or [`map`](Self::map) is not marked, and
    /// its output is dropped as it is.
    pub fn zip<U: 'a>(self, other: Pending<'a, U, K>) -> Pending<'a, (T, U), K> {
        self.zip_releasing(other, drop)
    }

    /// [`zip`](Self::zip) for recovered plaintext. The right side can fail at
    /// fulfilment, with an authentication or type failure after its key
    /// arrives. It can also panic in its conversion.
    ///
    /// In both cases, the left side's recovered value is wiped before the
    /// error is returned or the panic unwinds. It is not dropped as it is. A
    /// record's fields open through this method.
    pub(crate) fn zip_wiping<U: 'a>(self, other: Pending<'a, U, K>) -> Pending<'a, (T, U), K>
    where
        T: zeroize::Zeroize,
    {
        self.zip_releasing(other, |mut first: T| zeroize::Zeroize::zeroize(&mut first))
    }

    /// The builder behind every pair. `release` is given the left side's
    /// output when the right side fails or panics after it, after the left
    /// side's own wipe has run if it has one. It is not called when both
    /// sides succeed.
    fn zip_releasing<U: 'a>(
        self,
        other: Pending<'a, U, K>,
        release: impl FnOnce(T) + MaybeSend + 'a,
    ) -> Pending<'a, (T, U), K> {
        let keyset = match self.keyset.clone().merge(other.keyset.clone()) {
            Ok(keyset) => keyset,
            Err(error) => return Pending::failed(self.cipher, error),
        };
        if self.failed.is_some() || other.failed.is_some() {
            let error = self.failed.or(other.failed).unwrap_or(Error::ResponseShape);
            return Pending::failed(self.cipher, error);
        }
        if self.build.is_some() || other.build.is_some() {
            // A side that is not built yet has no requests to merge. The
            // pair is built when it settles, and merged then.
            let cipher = self.cipher;
            let (left, right) = (self.detached(), other.detached());
            return Pending::unbuilt(
                cipher,
                keyset,
                Box::new(move |loaded| {
                    left.built(loaded)
                        .zip_releasing(right.built(loaded), release)
                }),
            );
        }
        let mut requests = self.requests;
        requests.extend(other.requests);
        if let Err(error) = check_keyset(&keyset, &requests) {
            return Pending::failed(self.cipher, error);
        }
        let mut contexts = self.contexts;
        contexts.extend(other.contexts);
        let first = self.fulfil;
        let second = other.fulfil;
        // The pair is wiped by wiping each side that can be wiped.
        let wipe = match (self.wipe.clone(), other.wipe) {
            (None, None) => None,
            (left, right) => {
                let wipe: WipeHook<'a, (T, U)> = Arc::new(move |(t, u): &mut (T, U)| {
                    if let Some(left) = &left {
                        left(t);
                    }
                    if let Some(right) = &right {
                        right(u);
                    }
                });
                Some(wipe)
            }
        };
        // The left side is wiped, if it can be, before `release` takes it.
        let left_wipe = self.wipe;
        let release = move |mut first: T| {
            if let Some(wipe) = &left_wipe {
                wipe(&mut first);
            }
            release(first);
        };
        Pending {
            cipher: self.cipher,
            keyset,
            requests,
            failed: None,
            contexts,
            wipe,
            fulfil: fulfil_pair(first, second, release),
            build: None,
        }
    }

    /// Merge any number of same-typed pendings into one resolving to the
    /// `Vec` — [`zip`](Self::zip) at scale, used by the `Vec<T>`
    /// implementations to make a whole column one batched call. Same rule as
    /// `zip`: every item must agree with `cipher_ref`'s keyset — which cipher
    /// value each was built through does not matter, for the reason `zip`
    /// gives — and the first failed item fails the whole column with no I/O.
    ///
    /// When an item fails after the items before it recovered plaintext,
    /// each of those items that a decrypt marked is wiped before the error
    /// is returned, as [`zip`](Self::zip) does for its left side.
    pub fn all(
        cipher_ref: impl Into<CipherRef<'a, K>>,
        items: Vec<Pending<'a, T, K>>,
    ) -> Pending<'a, Vec<T>, K> {
        Self::collect(cipher_ref, items)
    }

    /// Build a collection lazily, stopping at the first local failure so a bad
    /// context does not repeat work for every remaining row.
    pub(crate) fn collect(
        cipher_ref: impl Into<CipherRef<'a, K>>,
        items: impl IntoIterator<Item = Pending<'a, T, K>>,
    ) -> Pending<'a, Vec<T>, K> {
        let cipher_ref: CipherRef<'a, K> = cipher_ref.into();
        Self::collect_releasing(cipher_ref, items, drop)
    }

    /// The same as [`collect`](Self::collect), but for a collection of
    /// recovered plaintext. `collect` wipes only the items recovered before
    /// a failure that a decrypt marked ([`wiping`](Self::wiping)), and drops
    /// the rest. This function wipes them all.
    ///
    /// The wipe applies when a later item fails at fulfilment, after its key
    /// arrived. That failure can be an authentication failure, a type
    /// failure, or a panic in the item's conversion. The items recovered
    /// before it are wiped before the error is returned, or before the panic
    /// unwinds. A failure before fulfilment recovers nothing, so there is
    /// nothing to wipe.
    pub(crate) fn collect_wiping(
        cipher_ref: impl Into<CipherRef<'a, K>>,
        items: impl IntoIterator<Item = Pending<'a, T, K>>,
    ) -> Pending<'a, Vec<T>, K>
    where
        T: zeroize::Zeroize,
    {
        let cipher_ref: CipherRef<'a, K> = cipher_ref.into();
        Self::collect_releasing(cipher_ref, items, |mut recovered| {
            zeroize::Zeroize::zeroize(&mut recovered)
        })
    }

    /// The collection builder that `collect` and `collect_wiping` both use.
    /// When an item fails or panics, `release` receives the items fulfilled
    /// before it, after each item's own wipe has run if it has one. When
    /// every item succeeds, `release` is not called.
    fn collect_releasing(
        cipher_ref: CipherRef<'a, K>,
        items: impl IntoIterator<Item = Pending<'a, T, K>>,
        release: impl FnOnce(Vec<T>) + MaybeSend + 'a,
    ) -> Pending<'a, Vec<T>, K> {
        let items = items.into_iter();
        let cipher = cipher_ref.cipher();
        let mut keyset = cipher_ref.keyset().clone();
        // Items are taken one at a time, and none after the first that
        // failed: a lazy column stops building there.
        let mut column: Vec<Pending<'a, T, K>> = Vec::with_capacity(items.size_hint().0);
        let mut unbuilt = false;
        for item in items {
            keyset = match keyset.merge(item.keyset.clone()) {
                Ok(keyset) => keyset,
                Err(error) => return Pending::failed(cipher, error),
            };
            if let Some(error) = item.failed {
                return Pending::failed(cipher, error);
            }
            unbuilt |= item.build.is_some();
            column.push(item);
        }
        if unbuilt {
            // An item that is not built yet has no requests to merge. The
            // column is built when it settles, and merged then.
            let column: Vec<_> = column.into_iter().map(Pending::detached).collect();
            return Pending::unbuilt(
                cipher,
                keyset,
                Box::new(move |loaded| {
                    let column: Vec<_> =
                        column.into_iter().map(|item| item.built(loaded)).collect();
                    Pending::collect_releasing(CipherRef::from(loaded), column, release)
                }),
            );
        }
        let mut requests = Vec::new();
        let mut contexts = Vec::new();
        let mut fulfils = Vec::with_capacity(column.len());
        let mut wipes = Vec::with_capacity(column.len());
        for item in column {
            // An item's weight is the data keys it asked for: what its
            // fulfilment opens or seals.
            let weight = item.requests.len();
            requests.extend(item.requests);
            contexts.extend(item.contexts);
            fulfils.push((item.fulfil, weight));
            wipes.push(item.wipe);
        }
        if let Err(error) = check_keyset(&keyset, &requests) {
            return Pending::failed(cipher, error);
        }
        // Each item is wiped by its own hook, if it has one. The items
        // recovered before a failure are wiped before `release` takes them.
        let wipes: Option<Arc<[Option<WipeHook<'a, T>>]>> =
            wipes.iter().any(Option::is_some).then(|| wipes.into());
        let wipe = wipes.clone().map(|wipes| {
            let wipe: WipeHook<'a, Vec<T>> = Arc::new(move |items: &mut Vec<T>| {
                wipe_each(items, &wipes);
            });
            wipe
        });
        let release = move |mut items: Vec<T>| {
            if let Some(wipes) = &wipes {
                wipe_each(&mut items, wipes);
            }
            release(items);
        };
        Pending {
            cipher,
            keyset,
            requests,
            failed: None,
            contexts,
            wipe,
            // The recovered items are held in a guard so that an item whose
            // fulfilment panics releases the prefix during the unwind, as an
            // error does, and so does a column dropped between its chunks.
            fulfil: fulfil_column(fulfils.into_iter(), release),
            build: None,
        }
    }
}

/// A column's fulfilment: each item's fulfilment in turn, the recovered
/// items held in a guard that passes them to `release` if a later item
/// fails, panics, or the column is dropped part way.
///
/// In a wasm guest it stops after about [`YIELD_EVERY`] data keys' worth of
/// items and returns the rest of itself, taking the guard with it, so the
/// host gets control back between chunks. Natively it runs to its end: a
/// chunk would hold recovered items across a yield, and a native
/// fulfilment must be `Send`, which would ask `T` to be `Send` too.
#[cfg(not(target_arch = "wasm32"))]
fn fulfil_column<'a, T: 'a, R: FnOnce(Vec<T>) + MaybeSend + 'a>(
    rest: std::vec::IntoIter<(FulfilBox<'a, T>, usize)>,
    release: R,
) -> FulfilBox<'a, Vec<T>> {
    Box::new(move |responses| {
        let mut recovered = Recovered {
            items: Vec::with_capacity(rest.len()),
            release: Some(release),
        };
        for (fulfil, _) in rest {
            recovered.items.push(finish(fulfil, responses)?);
        }
        Ok(Fulfilled::Done(recovered.keep()))
    })
}

/// See the native definition above.
#[cfg(target_arch = "wasm32")]
fn fulfil_column<'a, T: 'a, R: FnOnce(Vec<T>) + 'a>(
    rest: std::vec::IntoIter<(FulfilBox<'a, T>, usize)>,
    release: R,
) -> FulfilBox<'a, Vec<T>> {
    let recovered = Recovered {
        items: Vec::with_capacity(rest.len()),
        release: Some(release),
    };
    fulfil_column_from(rest, recovered)
}

/// The rest of a wasm guest's column, from `rest` on, with the items before
/// it in `recovered`.
#[cfg(target_arch = "wasm32")]
fn fulfil_column_from<'a, T: 'a, R: FnOnce(Vec<T>) + 'a>(
    mut rest: std::vec::IntoIter<(FulfilBox<'a, T>, usize)>,
    mut recovered: Recovered<T, R>,
) -> FulfilBox<'a, Vec<T>> {
    Box::new(move |responses| {
        let mut weight = 0;
        while let Some((fulfil, w)) = rest.next() {
            match fulfil(responses)? {
                Fulfilled::Done(item) => recovered.items.push(item),
                // An item that is a column itself yields on its own: the
                // rest of it runs first, then the rest of this column.
                Fulfilled::More(item) => {
                    return Ok(Fulfilled::More(fulfil_column_item(item, rest, recovered)))
                }
            }
            weight += w;
            if weight >= YIELD_EVERY && rest.len() > 0 {
                return Ok(Fulfilled::More(fulfil_column_from(rest, recovered)));
            }
        }
        Ok(Fulfilled::Done(recovered.keep()))
    })
}

/// The rest of a wasm guest's column whose next item stopped part way:
/// `item`, then the items in `rest`.
#[cfg(target_arch = "wasm32")]
fn fulfil_column_item<'a, T: 'a, R: FnOnce(Vec<T>) + 'a>(
    item: FulfilBox<'a, T>,
    rest: std::vec::IntoIter<(FulfilBox<'a, T>, usize)>,
    mut recovered: Recovered<T, R>,
) -> FulfilBox<'a, Vec<T>> {
    Box::new(move |responses| match item(responses)? {
        Fulfilled::Done(item) => {
            recovered.items.push(item);
            fulfil_column_from(rest, recovered)(responses)
        }
        Fulfilled::More(item) => Ok(Fulfilled::More(fulfil_column_item(item, rest, recovered))),
    })
}

/// A pair's fulfilment: the left side, held in a guard that passes it to
/// `release` if the right side fails, panics, or the pair is dropped part
/// way, then the right side.
///
/// In a wasm guest either side may stop part way (a column) and the pair
/// passes that on, so a batch of records yields between its rows. Natively
/// both sides run to their end, for the reason [`fulfil_column`] gives.
#[cfg(not(target_arch = "wasm32"))]
fn fulfil_pair<'a, T: 'a, U: 'a, R: FnOnce(T) + MaybeSend + 'a>(
    first: FulfilBox<'a, T>,
    second: FulfilBox<'a, U>,
    release: R,
) -> FulfilBox<'a, (T, U)> {
    Box::new(move |responses| {
        let held = Held {
            item: Some(finish(first, responses)?),
            release: Some(release),
        };
        let second = finish(second, responses)?;
        Ok(Fulfilled::Done((held.keep(), second)))
    })
}

/// See the native definition above.
#[cfg(target_arch = "wasm32")]
fn fulfil_pair<'a, T: 'a, U: 'a, R: FnOnce(T) + 'a>(
    first: FulfilBox<'a, T>,
    second: FulfilBox<'a, U>,
    release: R,
) -> FulfilBox<'a, (T, U)> {
    Box::new(move |responses| match first(responses)? {
        Fulfilled::More(first) => Ok(Fulfilled::More(fulfil_pair(first, second, release))),
        Fulfilled::Done(item) => {
            let held = Held {
                item: Some(item),
                release: Some(release),
            };
            fulfil_pair_right(held, second)(responses)
        }
    })
}

/// The right side of a wasm guest's pair, with the left side held.
#[cfg(target_arch = "wasm32")]
fn fulfil_pair_right<'a, T: 'a, U: 'a, R: FnOnce(T) + 'a>(
    held: Held<T, R>,
    second: FulfilBox<'a, U>,
) -> FulfilBox<'a, (T, U)> {
    Box::new(move |responses| match second(responses)? {
        Fulfilled::Done(second) => Ok(Fulfilled::Done((held.keep(), second))),
        Fulfilled::More(second) => Ok(Fulfilled::More(fulfil_pair_right(held, second))),
    })
}

/// A [`Pending`] without its cipher: see [`Pending::detached`].
struct Detached<'a, T, K> {
    keyset: KeysetSelector,
    requests: Vec<Request>,
    failed: Option<Error>,
    contexts: Vec<(ContextPiece<'static>, ContextPiece<'static>)>,
    wipe: Option<WipeHook<'a, T>>,
    fulfil: FulfilBox<'a, T>,
    build: Option<BuildBox<'a, T, K>>,
}

impl<'a, T: 'a, K> Detached<'a, T, K> {
    /// The pending again, on the cipher of `loaded`, and built through
    /// `loaded` if it was not built yet.
    fn built(self, loaded: &KeysetCipher<'a, K>) -> Pending<'a, T, K> {
        match self.build {
            Some(build) => build(loaded),
            None => Pending {
                cipher: loaded.cipher(),
                keyset: self.keyset,
                requests: self.requests,
                failed: self.failed,
                contexts: self.contexts,
                wipe: self.wipe,
                fulfil: self.fulfil,
                build: None,
            },
        }
    }
}

/// Wipe each item with the hook at the same position, where there is one.
fn wipe_each<T>(items: &mut [T], wipes: &[Option<WipeHook<'_, T>>]) {
    for (item, wipe) in items.iter_mut().zip(wipes) {
        if let Some(wipe) = wipe {
            wipe(item);
        }
    }
}

/// The items a collection has recovered so far. If this guard is dropped
/// before [`keep`](Self::keep) is called, by an early return or an unwind, it
/// passes the items to `release`.
struct Recovered<T, R: FnOnce(Vec<T>)> {
    items: Vec<T>,
    release: Option<R>,
}

impl<T, R: FnOnce(Vec<T>)> Recovered<T, R> {
    /// Returns the items as the output, without releasing them. Call this
    /// when every item has succeeded.
    fn keep(mut self) -> Vec<T> {
        self.release = None;
        std::mem::take(&mut self.items)
    }
}

impl<T, R: FnOnce(Vec<T>)> Drop for Recovered<T, R> {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release(std::mem::take(&mut self.items));
        }
    }
}

/// The left side of a pair, recovered before the right side is fulfilled. If
/// it is dropped before [`keep`](Self::keep), by an early return or an unwind,
/// it passes the value to `release`.
struct Held<T, R: FnOnce(T)> {
    item: Option<T>,
    release: Option<R>,
}

impl<T, R: FnOnce(T)> Held<T, R> {
    /// The right side succeeded. So the value is the output. It is not
    /// released.
    fn keep(mut self) -> T {
        self.release = None;
        self.item
            .take()
            .unwrap_or_else(|| unreachable!("a held value is kept once"))
    }
}

impl<T, R: FnOnce(T)> Drop for Held<T, R> {
    fn drop(&mut self) {
        if let (Some(release), Some(item)) = (self.release.take(), self.item.take()) {
            release(item);
        }
    }
}

impl<'a, T: 'a, K> Pending<'a, T, K> {
    /// Settle: one batched ZeroKMS call per request kind (none at all for an
    /// all-[`ready`](Pending::ready) assembly), then the fulfilments shape the
    /// responses. This is the only place I/O happens — the cipher-directed
    /// API ([`KeysetCipher::encrypt`] / [`StackCipher::decrypt`]) settles
    /// through here too, so there is exactly one path to ZeroKMS.
    ///
    /// Unboxed, so it carries no `Send`/`Sync` demands beyond the backend's
    /// own; the public [`IntoFuture`] impl boxes it.
    pub(crate) async fn settle(self) -> Result<T, Error>
    where
        K: KeySource<OwnIdentity>,
    {
        self.settle_with(None, &OwnIdentity).await
    }

    /// Settle as [`settle`](Self::settle) does. `audit` is sent with every
    /// key request: an [`Audited`] call settles through this method.
    /// Every request is made as `identity`, the load of a keyset included:
    /// the key source's own identity, or the credential of a
    /// [`WithCredential`] call.
    pub(crate) async fn settle_with<I>(self, audit: Unverified, identity: &I) -> Result<T, Error>
    where
        K: KeySource<I>,
    {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if let Some(build) = self.build {
            // Not built yet: load the keyset, build through a handle on
            // it, and settle what was built, confined to that keyset. A
            // keyset this pending was confined to since is the same one,
            // or `resolved_id` has refused it.
            let Some(id) = Box::pin(resolved_id(self.cipher, &self.keyset, identity)).await? else {
                return Err(Error::NoKeyset);
            };
            let loaded = Box::pin(self.cipher.keyset_state(id, identity)).await?;
            let keyset = KeysetCipher::new(self.cipher, loaded);
            let built = build(&keyset).confined_to(&KeysetSelector::keyset(id));
            // Boxed: the call is recursive, though a built pending has
            // nothing more to build.
            return Box::pin(built.settle_with(audit, identity)).await;
        }
        let unresolved = !self.keyset.not_loaded.is_empty()
            || self.requests.iter().any(Request::is_selected_keyset);
        let (keyset, requests) = if unresolved {
            // Boxed: see `dispatch` on what a future holds on the stack.
            Box::pin(resolved(self.cipher, &self.keyset, self.requests, identity)).await?
        } else {
            (self.keyset.id(), self.requests)
        };
        let mut responses = if requests.is_empty() {
            // Nothing to ask ZeroKMS for: the value was derived during the
            // build. `dispatch` is not entered, so it builds none of the
            // futures it boxes, and nothing the build left on the stack is
            // copied into one.
            Responses::new(Vec::new(), Vec::new())
        } else {
            dispatch(self.cipher, keyset, requests, audit.as_deref(), identity).await?
        };
        let mut fulfil = self.fulfil;
        loop {
            // The rest of the work is held across the yield, and with it
            // the items recovered so far, which can be plaintext. Its guard
            // releases and wipes them if the operation is dropped at the
            // yield.
            fulfil = match fulfil(&mut responses)? {
                Fulfilled::Done(value) => return Ok(value),
                Fulfilled::More(rest) => rest,
            };
            YieldNow(false).await;
        }
    }
}

/// The id of the keyset `keyset` names, with every keyset it names that
/// was not loaded now loaded, as `identity`, and kept by the handle it was
/// selected through. Merged
/// pendings can name more than one, and all must be one keyset:
/// [`Error::KeysetMismatch`] otherwise. `None` for a selector that names
/// no keyset.
async fn resolved_id<K: KeySource<I>, I>(
    cipher: &StackCipher<K>,
    keyset: &KeysetSelector,
    identity: &I,
) -> Result<Option<Uuid>, Error> {
    let mut id = keyset.id();
    for NotLoaded { selected, kept } in &keyset.not_loaded {
        let found = match kept.get() {
            // A call through the same handle has loaded the keyset since
            // this one was built. It is used as the handle holds it, and
            // the id or name is not resolved again: a name can come to
            // mean another keyset.
            Some(loaded) => loaded.id,
            None => {
                let loaded = cipher.selected_state(selected, identity).await?;
                // If a call through the same handle set it meanwhile, that
                // one stands for both.
                kept.get_or_init(|| loaded).id
            }
        };
        match id {
            Some(known) if known != found => {
                return Err(Error::KeysetMismatch {
                    left: known,
                    right: found,
                })
            }
            _ => id = Some(found),
        }
    }
    Ok(id)
}

/// The keyset and the requests of a pending that was built through a
/// keyset before the cipher had loaded it.
///
/// Loads the keyset if no call has yet, as `identity`. Then applies
/// what the build could not: the keyset rules ([`check_keyset`]), and
/// [`Error::KeysetMismatch`] when the pending was merged with one under
/// another keyset. A request for the selected keyset's state becomes a
/// request for that keyset by id, which `dispatch` answers from the cache.
async fn resolved<K: KeySource<I>, I>(
    cipher: &StackCipher<K>,
    keyset: &KeysetSelector,
    mut requests: Vec<Request>,
    identity: &I,
) -> Result<(Option<Uuid>, Vec<Request>), Error> {
    let id = resolved_id(cipher, keyset, identity).await?;
    let loaded = match id {
        Some(id) => {
            for request in &mut requests {
                request.resolve_selected_keyset(id);
            }
            KeysetSelector::keyset(id)
        }
        None => KeysetSelector::ANY,
    };
    check_keyset(&loaded, &requests)?;
    Ok((id, requests))
}

/// The keyset rules over a request list, applied wherever requests meet a
/// keyset (construction, confining, merging), so a violation fails the
/// pending before any I/O: a request that needs a keyset (one that mints a
/// data key, or asks for the selected keyset) has none through the client
/// ([`Error::NoKeyset`]), and a retrieve request in a pending confined to
/// a keyset must name that keyset ([`Error::ForeignKeyset`]).
///
/// A keyset that is not loaded yet is a keyset to mint under, and gives no
/// id to compare a retrieve request with unless it was selected by id.
/// [`resolved`] applies the rules again when the pending settles and the
/// id is known.
fn check_keyset(keyset: &KeysetSelector, requests: &[Request]) -> Result<(), Error> {
    for request in requests {
        if request.needs_keyset() && keyset.is_any() {
            return Err(Error::NoKeyset);
        }
        match (keyset.id(), request.retrieve_keyset()) {
            (Some(expected), Some(found)) if expected != found => {
                return Err(Error::ForeignKeyset { expected, found });
            }
            _ => {}
        }
    }
    Ok(())
}

impl<'a, T: 'a, K: stack_kms::CredentialKeySource> Pending<'a, T, K> {
    /// Send every key request that this call makes with `credential`, so
    /// that ZeroKMS serves and logs the request as that caller. For a
    /// `stack_auth::OidcFederationStrategy`, the credential is a JWT, most
    /// often that of the end user who signed in.
    ///
    /// A keyset that the call needs and the cipher has not loaded yet is
    /// loaded with the credential too.
    ///
    /// # Attach it last
    ///
    /// The result is a [`WithCredential`] call. You can await it, or call
    /// `.audit(..)` on it and await that. So call [`zip`](Self::zip),
    /// [`all`](Self::all), and [`map`](Self::map) first. Then attach the
    /// credential to the whole call. See [`WithCredential`] for an
    /// example.
    ///
    /// Only a call through a key source that takes a credential with each
    /// call has this method
    /// ([`CredentialKeySource`](stack_kms::CredentialKeySource)). Such a
    /// call is not a future until it has a credential, so it cannot be
    /// awaited without this method.
    pub fn with_credential(self, credential: stack_kms::SecretToken) -> WithCredential<Self> {
        WithCredential::new(self, credential)
    }
}

impl<'a, T: 'a, K: stack_kms::CredentialKeySource> Audited<Pending<'a, T, K>> {
    /// Send the audited call's key requests with `credential`. See
    /// [`Pending::with_credential`].
    pub fn with_credential(
        self,
        credential: stack_kms::SecretToken,
    ) -> Audited<WithCredential<Pending<'a, T, K>>> {
        self.rewrap(|pending| WithCredential::new(pending, credential))
    }
}

impl<'a, T: 'a, K> WithCredential<Pending<'a, T, K>> {
    /// Send `metadata` with every key request that this call makes, for
    /// the ZeroKMS audit log. See [`Pending::audit`].
    pub fn audit(self, metadata: AuditMetadata) -> Audited<Self> {
        Audited::new(self, metadata)
    }
}

/// Awaiting a `Pending` settles it. The boxed future is `Send` on native
/// targets (see [`PendingFuture`]), which is what requires `K: Sync` there:
/// the future holds `&StackCipher<K>`. On wasm32 the future is not `Send`,
/// so the `Sync` demand would only shut out the `Rc`/`RefCell`-shaped
/// sources that are natural on that target — it is dropped, mirroring the
/// [`MaybeSend`] split.
#[cfg(not(target_arch = "wasm32"))]
impl<'a, T: 'a, K> IntoFuture for Pending<'a, T, K>
where
    K: DataKeySource + IndexKeySource + Sync,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.settle())
    }
}

/// See the native impl above; identical minus the `Sync` bound.
#[cfg(target_arch = "wasm32")]
impl<'a, T: 'a, K> IntoFuture for Pending<'a, T, K>
where
    K: DataKeySource + IndexKeySource,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.settle())
    }
}

/// Awaiting an audited `Pending` settles it, as awaiting the `Pending`
/// does, with the audit metadata on every key request.
#[cfg(not(target_arch = "wasm32"))]
impl<'a, T: 'a, K> IntoFuture for Audited<Pending<'a, T, K>>
where
    K: DataKeySource + IndexKeySource + Sync,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        let (pending, audit) = self.into_parts();
        Box::pin(async move { pending.settle_with(audit, &OwnIdentity).await })
    }
}

/// See the native impl above. This one is the same, without the `Sync`
/// bound.
#[cfg(target_arch = "wasm32")]
impl<'a, T: 'a, K> IntoFuture for Audited<Pending<'a, T, K>>
where
    K: DataKeySource + IndexKeySource,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        let (pending, audit) = self.into_parts();
        Box::pin(async move { pending.settle_with(audit, &OwnIdentity).await })
    }
}

/// Awaiting a `Pending` with a credential settles it, as awaiting the
/// `Pending` does, with every key request made with the credential.
///
/// This is the only way to await a call through a key source that takes a
/// credential with each call
/// ([`CredentialKeySource`](stack_kms::CredentialKeySource)). Such a key
/// source is not a [`DataKeySource`], so the call alone is not a future.
#[cfg(not(target_arch = "wasm32"))]
impl<'a, T: 'a, K> IntoFuture for WithCredential<Pending<'a, T, K>>
where
    K: stack_kms::CredentialKeySource + Sync,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        let (pending, credential) = self.into_parts();
        Box::pin(async move { pending.settle_with(None, &credential).await })
    }
}

/// See the native impl above. This one is the same, without the `Sync`
/// bound.
#[cfg(target_arch = "wasm32")]
impl<'a, T: 'a, K> IntoFuture for WithCredential<Pending<'a, T, K>>
where
    K: stack_kms::CredentialKeySource,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        let (pending, credential) = self.into_parts();
        Box::pin(async move { pending.settle_with(None, &credential).await })
    }
}

/// Awaiting an audited `Pending` with a credential settles it with both.
#[cfg(not(target_arch = "wasm32"))]
impl<'a, T: 'a, K> IntoFuture for Audited<WithCredential<Pending<'a, T, K>>>
where
    K: stack_kms::CredentialKeySource + Sync,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        let (call, audit) = self.into_parts();
        let (pending, credential) = call.into_parts();
        Box::pin(async move { pending.settle_with(audit, &credential).await })
    }
}

/// See the native impl above. This one is the same, without the `Sync`
/// bound.
#[cfg(target_arch = "wasm32")]
impl<'a, T: 'a, K> IntoFuture for Audited<WithCredential<Pending<'a, T, K>>>
where
    K: stack_kms::CredentialKeySource,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        let (call, audit) = self.into_parts();
        let (pending, credential) = call.into_parts();
        Box::pin(async move { pending.settle_with(audit, &credential).await })
    }
}

/// One [`RequestKind::RetrieveDataKey`], unpacked for
/// [`dispatch`]: the retrieves are grouped by `keyset_id` and read back by
/// index, so they are held as a list of their own rather than as requests.
struct Retrieve {
    iv: Iv,
    tag: Vec<u8>,
    descriptor: Descriptor,
    keyset_id: Uuid,
}

/// Issue the batched ZeroKMS calls for `requests`: at most one
/// `generate_keys` (under the pending's keyset), one `retrieve_keys` per
/// keyset the retrieved leaves were sealed under, and one keyset load per
/// keyset the keyset requests name that the cipher has not cached, the
/// loads running beside the retrieves, whatever the request count. When
/// ZeroKMS grows a combined operation (data keys + PRF derivations in one
/// round-trip), this is the one place that changes.
///
/// Every call is made as `identity`: the key source's own, or the
/// credential of the call.
async fn dispatch<K: KeySource<I>, I>(
    cipher: &StackCipher<K>,
    keyset: Option<Uuid>,
    requests: Vec<Request>,
    audit: Option<&UnverifiedContext>,
    identity: &I,
) -> Result<Responses, Error> {
    let mut generates: Vec<Descriptor> = Vec::new();
    let mut retrieves: Vec<Retrieve> = Vec::new();
    let mut loads: Vec<Uuid> = Vec::new();
    for request in requests {
        match request.into_kind() {
            RequestKind::GenerateDataKey { descriptor } => generates.push(descriptor),
            RequestKind::LoadKeyset { keyset_id } => loads.push(keyset_id),
            // `settle_with` names the pending's keyset by its id before it
            // dispatches, so none reaches here.
            RequestKind::SelectedKeyset => return Err(Error::ResponseShape),
            RequestKind::RetrieveDataKey {
                iv,
                tag,
                descriptor,
                keyset_id,
            } => retrieves.push(Retrieve {
                iv,
                tag,
                descriptor,
                keyset_id,
            }),
        }
    }

    // ZeroKMS binds a descriptor into a fixed-size block and does not check
    // the length itself. This is the gate: every request passes through
    // here, including ones built directly from the `pub` constructors. The
    // entry points check the root descriptor earlier as well, so a tree of
    // ten thousand leaves is refused before ten thousand requests exist —
    // a fast path, not a second rule.
    generates
        .iter()
        .chain(retrieves.iter().map(|retrieve| &retrieve.descriptor))
        .try_for_each(Descriptor::check)?;

    // The retrieves and the keyset loads run beside each other, after the
    // generates. Both sides are built here, before any key has been through
    // the stack, and boxed: a future is built on the stack and moved with
    // every byte it does not initialise, and a joined future holds each
    // side in a slot as wide as the side, replacing the whole slot with the
    // side's output from a stack temporary when it is done. A side built
    // early and boxed is a pointer wide at both moments, and its output is
    // kept narrow too (an error travels boxed, a keyset's outcome shared).
    // `tests/heap_hygiene.rs` is what notices.
    //
    // A side with nothing to do is not built at all. A call that only
    // generates keys, such as an encrypt, derives its terms before it gets
    // here, and a future built now would be moved to the heap with whatever
    // that derivation left on the stack.
    let retrieve_keys = (!retrieves.is_empty()).then(|| {
        let retrieving = retrieve_data_keys(cipher, &retrieves, audit, identity);
        Box::pin(async move { retrieving.await.map_err(Box::new) })
    });
    let load_keysets =
        (!loads.is_empty()).then(|| Box::pin(load_keysets(cipher, &loads, identity)));

    let generated = if generates.is_empty() {
        Vec::new()
    } else {
        // Every constructor checks this before any I/O (`check_keyset`), so
        // a generate with no keyset cannot reach here; kept as the rule, not
        // as an assumption.
        let keyset = keyset.ok_or(Error::NoKeyset)?;
        // Each leaf's descriptor is its context, rendered; the lock context
        // stays empty — see the descriptor module docs.
        let payloads: Vec<GenerateKeyPayload<'_>> = generates
            .iter()
            .map(|descriptor| GenerateKeyPayload::new(descriptor.as_str(), Cow::Owned(Vec::new())))
            .collect();
        let expected = payloads.len();
        let keys = crate::credential::generate_keys(
            cipher.kms(),
            identity,
            payloads,
            Some(keyset),
            audit.map(Cow::Borrowed),
        )
        .await?;
        if keys.len() != expected {
            return Err(Error::KeyCountMismatch {
                expected,
                received: keys.len(),
            });
        }
        keys
    };

    let (retrieved, keysets) = match (retrieve_keys, load_keysets) {
        (None, None) => (Vec::new(), Vec::new()),
        (Some(retrieve_keys), None) => (retrieve_keys.await.map_err(|error| *error)?, Vec::new()),
        (None, Some(load_keysets)) => (Vec::new(), load_keysets.await),
        (Some(retrieve_keys), Some(load_keysets)) => {
            let (retrieved, keysets) = futures::future::join(retrieve_keys, load_keysets).await;
            (retrieved.map_err(|error| *error)?, keysets)
        }
    };
    Ok(Responses::new(generated, retrieved).with_keysets(keysets))
}

/// The data keys of `retrieves`, in request order: one `retrieve_keys` per
/// keyset the leaves were sealed under, in first-seen order, the keys
/// scattered back into request order, which is the order the fulfilments
/// draw them in.
async fn retrieve_data_keys<K: KeySource<I>, I>(
    cipher: &StackCipher<K>,
    retrieves: &[Retrieve],
    audit: Option<&UnverifiedContext>,
    identity: &I,
) -> Result<Vec<DataKey>, Error> {
    let mut groups: Vec<(Uuid, Vec<usize>)> = Vec::new();
    let mut group_of: HashMap<Uuid, usize> = HashMap::new();
    for (index, retrieve) in retrieves.iter().enumerate() {
        let group = *group_of.entry(retrieve.keyset_id).or_insert_with(|| {
            groups.push((retrieve.keyset_id, Vec::new()));
            groups.len() - 1
        });
        groups[group].1.push(index);
    }
    let mut retrieved: Vec<Option<DataKey>> = std::iter::repeat_with(|| None)
        .take(retrieves.len())
        .collect();
    for (keyset_id, indices) in groups {
        let payloads: Vec<RetrieveKeyPayload<'_>> = indices
            .iter()
            .map(|&index| {
                let retrieve = &retrieves[index];
                RetrieveKeyPayload::new(retrieve.iv, retrieve.descriptor.as_str(), &retrieve.tag)
            })
            .collect();
        let expected = payloads.len();
        let keys = crate::credential::retrieve_keys(
            cipher.kms(),
            identity,
            payloads,
            Some(keyset_id),
            audit,
        )
        .await?;
        if keys.len() != expected {
            return Err(Error::KeyCountMismatch {
                expected,
                received: keys.len(),
            });
        }
        // Cloned, not moved: a data key wipes itself when it drops, and one
        // moved out of `keys` would leave its bytes in the buffer `keys`
        // frees. The originals drop here, in place.
        for (index, key) in indices.into_iter().zip(&keys) {
            retrieved[index] = Some(key.clone());
        }
    }
    // Every slot was filled by exactly one group; a hole would mean the
    // grouping above lost a request, which is a bug here, not a data error.
    // Cloned out for the same reason; `retrieved` drops its keys in place.
    retrieved
        .iter()
        .map(|key| key.clone().ok_or(Error::ResponseShape))
        .collect()
}

/// The answers to the keyset requests naming `loads`, in request order. A
/// keyset is answered from the cipher's cache, and loaded from ZeroKMS only
/// on a miss, as selecting it would load it; each distinct keyset is loaded
/// once however many requests name it (a column of documents names one),
/// the loads running together. A load that fails answers the requests that
/// named that keyset with its error and no other.
///
/// The per-keyset futures are built when this is called, not when the
/// returned future is first polled, for the reason `dispatch` builds its
/// sides early.
fn load_keysets<'c, K: KeySource<I>, I>(
    cipher: &'c StackCipher<K>,
    loads: &'c [Uuid],
    identity: &'c I,
) -> impl Future<Output = Vec<KeysetAnswer>> + 'c {
    let mut distinct: Vec<Uuid> = Vec::new();
    for keyset_id in loads {
        if !distinct.contains(keyset_id) {
            distinct.push(*keyset_id);
        }
    }
    let loading = futures::future::join_all(distinct.iter().map(|&id| {
        Box::pin(async move { cipher.keyset_state(id, identity).await.map_err(Arc::new) })
    }));
    async move {
        let by_keyset: HashMap<Uuid, Result<Arc<KeysetState>, Arc<Error>>> =
            distinct.into_iter().zip(loading.await).collect();
        loads
            .iter()
            .map(|keyset_id| KeysetAnswer {
                keyset_id: *keyset_id,
                // Every keyset named was loaded above; a hole would be a bug
                // here, reported as a response shape, never a panic.
                outcome: by_keyset
                    .get(keyset_id)
                    .cloned()
                    .unwrap_or_else(|| Err(Arc::new(Error::ResponseShape))),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use stack_kms::{FakeDataKeySource, IdentifiedBy, IndexKey, IndexKeySource, UnverifiedContext};
    use uuid::Uuid;

    use super::*;

    /// A reference to the client names no keyset. A reference to a keyset,
    /// borrowed or owned, names that keyset, and settles through the same
    /// client.
    #[tokio::test]
    async fn a_cipher_ref_names_the_keyset_it_was_built_from() {
        let cipher = StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .unwrap();
        let keyset = cipher.default_keyset();
        let any = CipherRef::from(&cipher);
        assert_eq!(any.keyset_id(), None);
        assert!(std::ptr::eq(any.cipher(), &cipher));
        let borrowed = CipherRef::from(&keyset);
        let owned = CipherRef::from(keyset.clone());
        for one in [borrowed.clone(), owned] {
            assert_eq!(one.keyset_id(), Some(keyset.keyset_id().await.unwrap()));
            assert!(std::ptr::eq(one.cipher(), &cipher));
        }
        // A pending keeps the keyset of the reference it was built through.
        let pending = Pending::ready(&keyset, Ok(()));
        assert_eq!(
            pending.keyset,
            KeysetSelector::keyset(keyset.keyset_id().await.unwrap())
        );
        let pending = Pending::ready(&cipher, Ok(()));
        assert_eq!(pending.keyset, KeysetSelector::ANY);
        let shown = format!("{any:?} {borrowed:?}");
        assert!(shown.contains("keyset_id: None"), "{shown}");
        assert!(
            shown.contains(&format!("{:?}", keyset.keyset_id().await.unwrap())),
            "{shown}"
        );
    }

    /// Counts ZeroKMS *calls* (not keys) so the batching claim — one call per
    /// request kind however many pendings were merged — is testable. Delegates
    /// everything else to the stub.
    #[derive(Default)]
    struct CountingSource {
        inner: FakeDataKeySource,
        generate_calls: AtomicUsize,
        retrieve_calls: AtomicUsize,
        /// The descriptors of every payload sent, per call, in payload order.
        generate_descriptors: Mutex<Vec<Vec<String>>>,
        retrieve_descriptors: Mutex<Vec<Vec<String>>>,
        /// The keyset each call named, in call order.
        generate_keysets: Mutex<Vec<Option<Uuid>>>,
        retrieve_keysets: Mutex<Vec<Option<Uuid>>>,
        /// Index-key loads, and an id every load answers with instead of the
        /// one asked for, when set.
        load_calls: AtomicUsize,
        answers_as: Mutex<Option<Uuid>>,
    }

    impl CountingSource {
        fn generate_calls(&self) -> usize {
            self.generate_calls.load(Ordering::Relaxed)
        }

        fn retrieve_calls(&self) -> usize {
            self.retrieve_calls.load(Ordering::Relaxed)
        }

        fn generate_descriptors(&self) -> Vec<Vec<String>> {
            self.generate_descriptors.lock().unwrap().clone()
        }

        fn retrieve_descriptors(&self) -> Vec<Vec<String>> {
            self.retrieve_descriptors.lock().unwrap().clone()
        }

        fn generate_keysets(&self) -> Vec<Option<Uuid>> {
            self.generate_keysets.lock().unwrap().clone()
        }

        fn retrieve_keysets(&self) -> Vec<Option<Uuid>> {
            self.retrieve_keysets.lock().unwrap().clone()
        }

        fn load_calls(&self) -> usize {
            self.load_calls.load(Ordering::Relaxed)
        }
    }

    impl stack_kms::KeySourceKind for CountingSource {
        type Kind = stack_kms::OwnIdentity;
    }

    impl DataKeySource for CountingSource {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<stack_kms::DataKeyWithTag>, stack_kms::Error> {
            self.generate_calls.fetch_add(1, Ordering::Relaxed);
            self.generate_descriptors
                .lock()
                .unwrap()
                .push(payloads.iter().map(|p| p.descriptor.to_owned()).collect());
            self.generate_keysets.lock().unwrap().push(keyset_id);
            self.inner
                .generate_keys(payloads, keyset_id, unverified_context)
                .await
        }

        async fn retrieve_keys(
            &self,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<stack_kms::DataKey>, stack_kms::Error> {
            self.retrieve_calls.fetch_add(1, Ordering::Relaxed);
            self.retrieve_descriptors
                .lock()
                .unwrap()
                .push(payloads.iter().map(|p| p.descriptor.to_owned()).collect());
            self.retrieve_keysets.lock().unwrap().push(keyset_id);
            self.inner
                .retrieve_keys(payloads, keyset_id, unverified_context)
                .await
        }
    }

    impl IndexKeySource for CountingSource {
        async fn load_index_key(
            &self,
            keyset_id: Option<IdentifiedBy>,
        ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
            self.load_calls.fetch_add(1, Ordering::Relaxed);
            let (id, key) = self.inner.load_index_key(keyset_id).await?;
            Ok((self.answers_as.lock().unwrap().unwrap_or(id), key))
        }
    }

    /// A pending that asks for the loaded state of `keyset` and resolves to
    /// its id.
    fn loading(
        cipher: &StackCipher<CountingSource>,
        keyset: Uuid,
    ) -> Pending<'_, Uuid, CountingSource> {
        Pending::request(cipher, vec![Request::load_keyset(keyset)], |responses| {
            Ok(responses.next_keyset()?.id)
        })
    }

    /// Keyset requests are answered once per keyset however many pendings
    /// ask, from ZeroKMS on a miss and from the cache after.
    #[tokio::test]
    async fn keyset_requests_load_each_keyset_once_and_then_hit_the_cache() {
        let cipher = cipher().await;
        let at_init = cipher.kms().load_calls();
        let other = FakeDataKeySource::new()
            .load_index_key(Some(IdentifiedBy::Uuid(Uuid::from_u128(42))))
            .await
            .unwrap()
            .0;
        let pair = loading(&cipher, other)
            .zip(loading(&cipher, other))
            .await
            .unwrap();
        assert_eq!(
            pair,
            (other, other),
            "both answered with the keyset asked for"
        );
        assert_eq!(
            cipher.kms().load_calls(),
            at_init + 1,
            "one load for two requests"
        );
        assert_eq!(loading(&cipher, other).await.unwrap(), other);
        assert_eq!(cipher.kms().load_calls(), at_init + 1, "then the cache");
        let default = cipher.default_keyset().keyset_id().await.unwrap();
        assert_eq!(loading(&cipher, default).await.unwrap(), default);
        assert_eq!(
            cipher.kms().load_calls(),
            at_init + 1,
            "the default is never loaded again"
        );
    }

    /// A source that answers a load by id for another keyset is refused,
    /// as the load of that keyset, and nothing is cached under either id.
    #[tokio::test]
    async fn a_keyset_answered_for_another_id_is_refused() {
        let cipher = cipher().await;
        let asked = Uuid::from_u128(42);
        let answered = Uuid::from_u128(43);
        *cipher.kms().answers_as.lock().unwrap() = Some(answered);
        let refused = loading(&cipher, asked).await;
        assert!(
            matches!(
                &refused,
                Err(Error::KeysetLoad { keyset_id, source })
                    if *keyset_id == asked
                        && matches!(**source, Error::KeysetMismatch { left, right } if left == asked && right == answered)
            ),
            "{refused:?}"
        );
        let loads = cipher.kms().load_calls();
        let _ = loading(&cipher, asked).await;
        assert_eq!(cipher.kms().load_calls(), loads + 1, "nothing was cached");
    }

    /// A keyset that cannot be loaded fails the fulfilment that asked for
    /// it and nothing else: the data key beside it is retrieved, the
    /// fulfilment draws it, and the keyset request alone comes back as the
    /// load's error; a sibling pending that needs no keyset is answered.
    #[tokio::test]
    async fn a_failed_keyset_load_fails_only_the_fulfilment_that_needed_it() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let (iv, tag) = generating_pairs(&keyset, 1).await.unwrap().remove(0);
        let failing = Uuid::from_u128(42);
        *cipher.kms().answers_as.lock().unwrap() = Some(Uuid::from_u128(43));
        let drew_key = Arc::new(AtomicUsize::new(0));
        let drawn = Arc::clone(&drew_key);
        let requests = vec![
            Request::retrieve_under(iv, tag.clone(), d(), keyset.keyset_id().await.unwrap()),
            Request::load_keyset(failing),
        ];
        let result = Pending::request(&cipher, requests, move |responses| {
            let _key = responses.next_retrieved_key()?;
            drawn.fetch_add(1, Ordering::SeqCst);
            responses.next_keyset().map(|state| state.id)
        })
        .await;
        assert!(
            matches!(result, Err(Error::KeysetLoad { keyset_id, .. }) if keyset_id == failing),
            "{result:?}"
        );
        assert_eq!(
            drew_key.load(Ordering::SeqCst),
            1,
            "the fulfilment ran and drew its data key before the keyset"
        );
        assert_eq!(cipher.kms().retrieve_calls(), 1, "the retrieve was made");

        let retrieving = Pending::request(
            &cipher,
            vec![Request::retrieve_under(
                iv,
                tag,
                d(),
                keyset.keyset_id().await.unwrap(),
            )],
            |responses| responses.next_retrieved_key().map(|_| ()),
        );
        let zipped = retrieving.zip(loading(&cipher, failing)).await;
        assert!(
            matches!(zipped, Err(Error::KeysetLoad { keyset_id, .. }) if keyset_id == failing),
            "the pair fails with the keyset's error, not a dispatch failure: {zipped:?}"
        );
        assert_eq!(cipher.kms().retrieve_calls(), 2, "its sibling was answered");
    }

    fn d() -> Descriptor {
        Descriptor::of("test/field")
    }

    fn by_name(name: &str) -> Selected {
        Selected::By(IdentifiedBy::Name(name.to_string().into()))
    }

    /// The keysets a selector still has to load, as they were selected.
    fn to_load(selector: &KeysetSelector) -> Vec<Selected> {
        selector
            .not_loaded
            .iter()
            .map(|one| one.selected.clone())
            .collect()
    }

    /// Two selectors merge to the keyset either names. A keyset that is
    /// not loaded yet stays in the merged selector, beside an id it must
    /// turn out to be.
    #[test]
    fn selectors_merge_by_id_and_keep_a_keyset_that_is_not_loaded() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let any = || KeysetSelector::ANY;
        // One handle on the default keyset, not loaded: every selector made
        // from it shares what the handle keeps.
        let handle = Kept::default();
        let default = || KeysetSelector::not_loaded(Selected::Default, Arc::clone(&handle));
        let loaded = KeysetSelector::keyset;
        assert!(any().is_any());
        assert!(!default().is_any());
        assert!(!loaded(a).is_any());

        assert_eq!(any().merge(any()).unwrap(), any());
        for (left, right) in [
            (any(), loaded(a)),
            (loaded(a), any()),
            (loaded(a), loaded(a)),
        ] {
            assert_eq!(left.merge(right).unwrap(), loaded(a));
        }
        assert!(matches!(
            loaded(a).merge(loaded(b)),
            Err(Error::KeysetMismatch { left, right }) if left == a && right == b
        ));

        for (left, right) in [
            (default(), any()),
            (any(), default()),
            (default(), default()),
        ] {
            assert_eq!(left.merge(right).unwrap(), default());
        }
        for (left, right) in [(default(), loaded(a)), (loaded(a), default())] {
            let merged = left.merge(right).unwrap();
            assert_eq!(merged.id(), Some(a));
            assert_eq!(
                to_load(&merged),
                [Selected::Default],
                "still to be compared with the default"
            );
        }

        // A keyset selected by id gives its id before it is loaded, so two
        // of them are compared at once. One selected by name gives none.
        let by_id =
            |id| KeysetSelector::not_loaded(Selected::By(IdentifiedBy::Uuid(id)), Kept::default());
        assert_eq!(by_id(a).id(), Some(a));
        assert!(matches!(
            by_id(a).merge(by_id(b)),
            Err(Error::KeysetMismatch { .. })
        ));
        let named = KeysetSelector::not_loaded(by_name("acme"), Kept::default());
        assert_eq!(named.id(), None);
        let both = named.merge(default()).unwrap();
        assert_eq!(to_load(&both), [by_name("acme"), Selected::Default]);

        // Two handles on the default keyset are two selections: each keeps
        // its own keyset once it is loaded.
        let another = KeysetSelector::not_loaded(Selected::Default, Kept::default());
        let two = default().merge(another).unwrap();
        assert_eq!(to_load(&two), [Selected::Default, Selected::Default]);
    }

    /// The keyset rules under a keyset that is not loaded yet: there is a
    /// keyset to mint under, and nothing to compare a retrieve request
    /// with until the pending settles.
    #[test]
    fn a_keyset_that_is_not_loaded_can_mint_and_compares_later() {
        let other = Uuid::from_u128(7);
        let requests = vec![
            Request::generate_under(d()),
            Request::retrieve_under(Iv::default(), vec![1], d(), other),
            Request::selected_keyset(),
        ];
        let default = KeysetSelector::not_loaded(Selected::Default, Kept::default());
        assert!(check_keyset(&default, &requests).is_ok());
        assert!(matches!(
            check_keyset(&KeysetSelector::ANY, &requests),
            Err(Error::NoKeyset)
        ));
        assert!(check_keyset(&KeysetSelector::keyset(other), &requests).is_ok());
        assert!(matches!(
            check_keyset(&KeysetSelector::keyset(Uuid::from_u128(8)), &requests),
            Err(Error::ForeignKeyset { found, .. }) if found == other
        ));
        // A request for the pending's keyset needs the pending to have one.
        assert!(matches!(
            check_keyset(&KeysetSelector::ANY, &[Request::selected_keyset()]),
            Err(Error::NoKeyset)
        ));
    }

    /// A request for the pending's keyset is answered with that keyset
    /// when the pending settles: the default keyset, or one selected by
    /// name. Two keysets that are not loaded yet are compared then.
    #[tokio::test]
    async fn a_request_for_the_selected_keyset_is_answered_when_the_pending_settles() {
        fn asking<'a>(
            keyset: &'a KeysetCipher<'_, CountingSource>,
        ) -> Pending<'a, Uuid, CountingSource> {
            Pending::request(keyset, vec![Request::selected_keyset()], |responses| {
                Ok(responses.next_keyset()?.id)
            })
        }
        let cipher = cipher().await;
        let default = cipher.default_keyset();
        let default_id = default.keyset_id().await.unwrap();
        assert_eq!(asking(&default).await.unwrap(), default_id);

        let other = cipher.keyset(IdentifiedBy::Name("other".to_string().into()));
        assert!(other.loaded_state().is_none(), "selecting loads nothing");
        // What shows a selector that is not loaded is the selection. The
        // state the handle keeps holds an index key, and is not shown.
        let shown = format!("{:?}", other.selector());
        assert!(shown.contains("other"), "{shown}");
        assert!(!shown.contains("kept"), "{shown}");
        let other_id = asking(&other).await.unwrap();
        assert_ne!(other_id, default_id);
        assert_eq!(
            other.loaded_state().map(|keyset| keyset.id),
            Some(other_id),
            "the handle finds the keyset loaded afterwards"
        );
        // A new handle on a keyset the cipher has loaded is on a loaded
        // keyset from the start, by the name or by the id: it reads the
        // cipher's cache when it is taken, and no call has to settle first.
        for selection in [
            IdentifiedBy::Name("other".to_string().into()),
            IdentifiedBy::Uuid(other_id),
        ] {
            assert_eq!(
                cipher
                    .keyset(selection)
                    .loaded_state()
                    .map(|keyset| keyset.id),
                Some(other_id),
            );
        }

        // Not loaded on one side, loaded on the other: compared when the
        // merged pending settles.
        let late = cipher.keyset(IdentifiedBy::Name("late".to_string().into()));
        let crossed = asking(&late).zip(asking(&default)).await;
        assert!(
            matches!(crossed, Err(Error::KeysetMismatch { .. })),
            "{crossed:?}"
        );
    }

    /// A pending built after the load is built through a handle on the
    /// loaded keyset, and the load is made with the credential of the
    /// call. What was done to the pending before it was built applies to
    /// what is built, and it merges like any pending.
    #[tokio::test]
    async fn a_pending_built_after_the_load_is_built_through_the_loaded_keyset() {
        use stack_kms::{FakeCredentialKeySource, SecretToken};

        async fn not_loaded() -> StackCipher<FakeCredentialKeySource> {
            StackCipher::builder()
                .kms(FakeCredentialKeySource::new())
                .init()
                .await
                .unwrap()
        }
        fn deferred<'a>(
            keyset: &KeysetCipher<'a, FakeCredentialKeySource>,
        ) -> Pending<'a, Uuid, FakeCredentialKeySource> {
            Pending::after_load(keyset, |loaded| {
                Pending::ready(loaded, loaded.loaded_now().map(|keyset| keyset.id))
            })
        }
        let alice = || SecretToken::new("alice.jwt");

        let cipher = not_loaded().await;
        let keyset = cipher.default_keyset();
        let pending = deferred(&keyset)
            .map(|id| (id, 2))
            .try_map(|(id, n)| Ok((id, n + 1)));
        assert!(cipher.kms().credentials_seen().is_empty(), "not built yet");
        let (id, n) = pending.with_credential(alice()).await.unwrap();
        assert_eq!(n, 3, "both changes apply to the pending that was built");
        assert_eq!(
            id,
            keyset.keyset_id().with_credential(alice()).await.unwrap()
        );
        assert_eq!(
            cipher.kms().credentials_seen(),
            ["alice.jwt"],
            "one load, with the credential of the call"
        );

        // Confined to another keyset before it is built: refused once the
        // default keyset is known.
        let cipher = not_loaded().await;
        let keyset = cipher.default_keyset();
        let other = Uuid::from_u128(9);
        let crossed = deferred(&keyset)
            .confined_to_id(other)
            .with_credential(alice())
            .await;
        assert!(
            matches!(crossed, Err(Error::KeysetMismatch { .. })),
            "{crossed:?}"
        );

        // Merged before it is built, on either side or in a collection: the
        // merged pending is built when it settles, with one load.
        let cipher = not_loaded().await;
        let keyset = cipher.default_keyset();
        let ready = || Pending::ready(&cipher, Ok(1u8));
        let (left, one) = deferred(&keyset)
            .zip(ready())
            .with_credential(alice())
            .await
            .unwrap();
        let (two, right) = ready()
            .zip(deferred(&keyset))
            .with_credential(alice())
            .await
            .unwrap();
        let column = Pending::all(&keyset, vec![deferred(&keyset), deferred(&keyset)])
            .with_credential(alice())
            .await
            .unwrap();
        let id = keyset.keyset_id().with_credential(alice()).await.unwrap();
        assert_eq!((left, one, two, right), (id, 1, 1, id));
        assert_eq!(column, [id, id]);
        assert_eq!(
            cipher.kms().credentials_seen(),
            ["alice.jwt"],
            "the keyset is loaded once, by the first of them"
        );
    }

    /// A pending built after the load keeps the mark a decrypt gives it
    /// ([`wiping`](Pending::wiping)). So what it recovered is wiped when a
    /// later operation of the same call fails, in a pair and in a column.
    /// A pending with no mark is dropped as it is.
    #[tokio::test]
    async fn a_pending_built_after_the_load_is_wiped_when_a_later_one_fails() {
        use stack_kms::{FakeCredentialKeySource, SecretToken};
        use std::sync::atomic::{AtomicBool, Ordering};

        /// Stands for recovered plaintext. It records that it was wiped.
        struct Plain(Arc<AtomicBool>);
        impl zeroize::Zeroize for Plain {
            fn zeroize(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        type Source = FakeCredentialKeySource;
        fn deferred<'a>(
            keyset: &KeysetCipher<'a, Source>,
            wiped: &Arc<AtomicBool>,
        ) -> Pending<'a, Plain, Source> {
            let wiped = Arc::clone(wiped);
            Pending::after_load(keyset, move |loaded| {
                Pending::ready(loaded, Ok(Plain(wiped)))
            })
        }
        /// Fails when it is fulfilled, after the operations before it.
        fn failing<'a>(keyset: &KeysetCipher<'a, Source>) -> Pending<'a, Plain, Source> {
            Pending::request(keyset, Vec::new(), |_| Err(Error::ResponseShape))
        }
        let alice = || SecretToken::new("alice.jwt");
        let flag = || Arc::new(AtomicBool::new(false));

        let cipher = StackCipher::builder()
            .kms(Source::new())
            .init()
            .await
            .unwrap();
        let keyset = cipher.default_keyset();

        let (marked, unmarked, in_a_column) = (flag(), flag(), flag());
        let pair = deferred(&keyset, &marked)
            .wiping()
            .zip(failing(&keyset))
            .with_credential(alice())
            .await;
        assert!(matches!(pair, Err(Error::ResponseShape)));
        assert!(marked.load(Ordering::SeqCst), "the marked side is wiped");

        let pair = deferred(&keyset, &unmarked)
            .zip(failing(&keyset))
            .with_credential(alice())
            .await;
        assert!(matches!(pair, Err(Error::ResponseShape)));
        assert!(!unmarked.load(Ordering::SeqCst), "no mark, no wipe");

        let column = Pending::all(
            &keyset,
            vec![deferred(&keyset, &in_a_column).wiping(), failing(&keyset)],
        )
        .with_credential(alice())
        .await;
        assert!(matches!(column, Err(Error::ResponseShape)));
        assert!(in_a_column.load(Ordering::SeqCst), "a marked item is wiped");
    }

    /// A pending that failed while it was built keeps its error and loads
    /// nothing. Every other pending settles under its keyset, so it loads
    /// the keyset first, even when it has no request of its own.
    #[tokio::test]
    async fn a_pending_through_a_keyset_that_is_not_loaded_loads_it_unless_it_failed() {
        use stack_kms::{FakeCredentialKeySource, SecretToken};

        let cipher = StackCipher::builder()
            .kms(FakeCredentialKeySource::new())
            .init()
            .await
            .unwrap();
        let alice = || SecretToken::new("alice.jwt");
        let keyset = cipher.default_keyset();
        assert_eq!(to_load(&keyset.selector()), [Selected::Default]);
        assert_eq!(keyset.selector().id(), None);
        let failed: Pending<'_, (), _> = Pending::failed(&keyset, Error::NoKeyset);
        assert!(
            matches!(failed.with_credential(alice()).await, Err(Error::NoKeyset)),
            "a failed pending keeps its own error"
        );
        assert!(
            cipher.kms().credentials_seen().is_empty(),
            "and asks for nothing"
        );
        // A ready value still settles under the keyset, so the keyset is
        // loaded.
        let ready = Pending::ready(&keyset, Ok(1u8))
            .with_credential(alice())
            .await;
        assert!(matches!(ready, Ok(1)), "{ready:?}");
        assert_eq!(cipher.kms().credentials_seen(), ["alice.jwt"]);
    }

    async fn cipher() -> StackCipher<CountingSource> {
        StackCipher::builder()
            .kms(CountingSource::default())
            .init()
            .await
            .unwrap()
    }

    /// A pending that asks for `n` data keys and resolves to their tags.
    fn generating<'a>(
        keyset: &'a KeysetCipher<'_, CountingSource>,
        n: usize,
    ) -> Pending<'a, Vec<Vec<u8>>, CountingSource> {
        let requests = std::iter::repeat_with(|| Request::generate_under(d()))
            .take(n)
            .collect();
        Pending::request(keyset, requests, move |responses| {
            (0..n)
                .map(|_| responses.next_generated_key().map(|key| key.tag))
                .collect()
        })
    }

    #[tokio::test]
    async fn a_ready_pending_resolves_without_any_io() {
        let cipher = cipher().await;
        let value: u32 = Pending::ready(&cipher, Ok(7)).await.unwrap();

        assert_eq!(value, 7, "a ready pending resolves to the value it holds");
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "a ready pending must not generate any key"
        );
        assert_eq!(cipher.kms().retrieve_calls(), 0, "nor retrieve one");
    }

    #[tokio::test]
    async fn a_ready_pending_propagates_its_error() {
        let cipher = cipher().await;
        let result: Result<u32, Error> = Pending::ready(&cipher, Err(Error::Aead)).await;

        assert!(
            matches!(result, Err(Error::Aead)),
            "the error a ready pending was given comes back: {result:?}"
        );
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "a failed pending does no I/O"
        );
    }

    #[tokio::test]
    async fn map_transforms_the_resolved_value() {
        let cipher = cipher().await;
        let value = Pending::ready(&cipher, Ok(7u32))
            .map(|v| v * 3)
            .await
            .unwrap();

        assert_eq!(value, 21, "map runs over the resolved value");
    }

    #[tokio::test]
    async fn map_does_not_run_on_an_error() {
        let cipher = cipher().await;
        let result: Result<u32, Error> = Pending::ready(&cipher, Err(Error::Aead))
            .map(|_: u32| panic!("map must not run on an error"))
            .await;

        assert!(
            matches!(result, Err(Error::Aead)),
            "the error passes through untouched: {result:?}"
        );
    }

    #[tokio::test]
    async fn map_carries_the_requests_through() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let tags = generating(&keyset, 3).map(|tags| tags.len()).await.unwrap();

        assert_eq!(tags, 3, "map sees all three keys the pending asked for");
        assert_eq!(
            cipher.kms().generate_calls(),
            1,
            "mapping does not split the batch"
        );
    }

    #[tokio::test]
    async fn one_pending_asking_for_many_keys_is_one_call() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let tags = generating(&keyset, 5).await.unwrap();

        assert_eq!(tags.len(), 5, "every requested key comes back");
        assert_eq!(
            cipher.kms().generate_calls(),
            1,
            "five keys, one generate_keys call"
        );
    }

    #[tokio::test]
    async fn zip_merges_requests_into_one_call() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let (left, right) = generating(&keyset, 2)
            .zip(generating(&keyset, 3))
            .await
            .unwrap();

        assert_eq!(
            (left.len(), right.len()),
            (2, 3),
            "each side draws exactly its own keys"
        );
        assert_eq!(
            cipher.kms().generate_calls(),
            1,
            "zipping merges the two request lists into one call"
        );
    }

    /// The response guarantee at the `Pending` level: zipped fulfilments draw
    /// disjoint response slices, in build order.
    #[tokio::test]
    async fn zipped_fulfilments_never_share_key_material() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let (left, right) = generating(&keyset, 2)
            .zip(generating(&keyset, 2))
            .await
            .unwrap();

        for tag in &left {
            assert!(!right.contains(tag), "a sibling drew the same key");
        }
    }

    #[tokio::test]
    async fn zip_of_two_ready_pendings_does_no_io() {
        let cipher = cipher().await;
        let pair = Pending::ready(&cipher, Ok(1u32))
            .zip(Pending::ready(&cipher, Ok("two")))
            .await
            .unwrap();

        assert_eq!(pair, (1, "two"), "both ready values resolve, in order");
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "nothing was requested, so nothing is dispatched"
        );
    }

    #[tokio::test]
    async fn zip_propagates_an_error_from_either_side() {
        let cipher = cipher().await;
        let result = Pending::ready(&cipher, Err(Error::Aead))
            .zip(Pending::ready(&cipher, Ok(1u32)))
            .await;
        assert!(
            matches!(result, Err::<(u32, u32), _>(Error::Aead)),
            "a failure on the left fails the pair: {result:?}"
        );

        let result = Pending::ready(&cipher, Ok(1u32))
            .zip(Pending::ready(&cipher, Err(Error::Aead)))
            .await;
        assert!(
            matches!(result, Err::<(u32, u32), _>(Error::Aead)),
            "and so does one on the right: {result:?}"
        );
    }

    #[tokio::test]
    async fn all_merges_a_column_into_one_call_preserving_order() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let items = (0..5).map(|_| generating(&keyset, 1)).collect();
        let column = Pending::all(&cipher, items).await.unwrap();

        assert_eq!(column.len(), 5, "every item resolves, in build order");
        assert_eq!(
            cipher.kms().generate_calls(),
            1,
            "a whole column is one generate_keys call"
        );

        // Every row drew its own key.
        let mut tags: Vec<&Vec<u8>> = column.iter().flatten().collect();
        tags.sort();
        tags.dedup();
        assert_eq!(tags.len(), 5, "no two rows drew the same key");
    }

    #[tokio::test]
    async fn all_of_nothing_resolves_empty_without_io() {
        let cipher = cipher().await;
        let column: Vec<u32> = Pending::all(&cipher, Vec::new()).await.unwrap();

        assert!(column.is_empty(), "an empty column resolves empty");
        assert_eq!(cipher.kms().generate_calls(), 0, "and dispatches nothing");
    }

    #[tokio::test]
    async fn all_propagates_the_first_error() {
        let cipher = cipher().await;
        let items = vec![
            Pending::ready(&cipher, Ok(1u32)),
            Pending::ready(&cipher, Err(Error::Aead)),
        ];
        let result = Pending::all(&cipher, items).await;

        assert!(
            matches!(result, Err::<Vec<u32>, _>(Error::Aead)),
            "the first failed item fails the column: {result:?}"
        );
    }

    #[tokio::test]
    async fn a_lazy_column_stops_building_after_a_local_failure() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let built = AtomicUsize::new(0);
        let items = (0..10_000).map(|index| {
            built.fetch_add(1, Ordering::Relaxed);
            if index == 1 {
                Pending::failed(&keyset, Error::Aead)
            } else {
                generating(&keyset, 1)
            }
        });
        let result = Pending::collect(&keyset, items).await;
        assert!(matches!(result, Err(Error::Aead)));
        assert_eq!(built.load(Ordering::Relaxed), 2);
        assert_eq!(cipher.kms().generate_calls(), 0);
    }

    /// Over-drawing is the fulfilment's own error, not a stolen sibling key:
    /// the second pending still resolves to the key it asked for.
    #[tokio::test]
    async fn over_drawing_responses_is_a_response_shape_error() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let greedy: Pending<'_, Vec<u8>, _> =
            Pending::request(&keyset, vec![Request::generate_under(d())], |responses| {
                let _ = responses.next_generated_key()?;
                // One request, two draws.
                responses.next_generated_key().map(|key| key.tag)
            });
        let result = greedy.zip(generating(&keyset, 1)).await;

        assert!(
            matches!(
                result,
                Err::<(Vec<u8>, Vec<Vec<u8>>), _>(Error::ResponseShape)
            ),
            "drawing past its own requests is the fulfilment's own error: {result:?}"
        );
    }

    /// Under-drawing is an error for the same reason over-drawing is: the
    /// pending's declared requests must describe what it actually consumes.
    /// A key was minted at ZeroKMS; leaving it behind is a composition bug,
    /// not a cheaper request.
    ///
    /// (That it does not *shift* a sibling's slice is a separate guarantee,
    /// covered by `Responses::split_front`'s own tests.)
    #[tokio::test]
    async fn under_drawing_responses_is_a_response_shape_error() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let lazy: Pending<'_, (), _> =
            Pending::request(&keyset, vec![Request::generate_under(d())], |_| Ok(()));
        let result = lazy.zip(generating(&keyset, 1)).await;

        assert!(
            matches!(result, Err::<((), Vec<Vec<u8>>), _>(Error::ResponseShape)),
            "leaving a minted key unconsumed is a composition bug: {result:?}"
        );
    }

    /// Partial consumption counts too: two requested, one drawn.
    #[tokio::test]
    async fn drawing_fewer_responses_than_requested_is_a_response_shape_error() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let requests = vec![Request::generate_under(d()), Request::generate_under(d())];
        let lazy: Pending<'_, Vec<u8>, _> = Pending::request(&keyset, requests, |responses| {
            responses.next_generated_key().map(|key| key.tag)
        });

        let result = lazy.await;
        assert!(
            matches!(result, Err::<Vec<u8>, _>(Error::ResponseShape)),
            "two requested, one drawn, is still an under-draw: {result:?}"
        );
    }

    /// The two kinds are tracked separately: consuming every generated key
    /// but none of the retrieved ones is still an under-draw.
    #[tokio::test]
    async fn leaving_the_other_kind_unconsumed_is_a_response_shape_error() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let mut pairs = generating_pairs(&keyset, 1).await.unwrap();
        let (iv, tag) = pairs.remove(0);
        let requests = vec![
            Request::generate_under(d()),
            Request::retrieve_under(iv, tag, d(), keyset.keyset_id().await.unwrap()),
        ];
        let lazy: Pending<'_, Vec<u8>, _> = Pending::request(&keyset, requests, |responses| {
            responses.next_generated_key().map(|key| key.tag)
        });

        let result = lazy.await;
        assert!(
            matches!(result, Err::<Vec<u8>, _>(Error::ResponseShape)),
            "the retrieved key was left behind: {result:?}"
        );
    }

    #[tokio::test]
    async fn a_pending_with_no_requests_dispatches_nothing() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let value: u32 = Pending::request(&keyset, Vec::new(), |_| Ok(9))
            .await
            .unwrap();

        assert_eq!(value, 9, "a request-free pending still resolves");
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "no requests, no generate_keys call"
        );
        assert_eq!(
            cipher.kms().retrieve_calls(),
            0,
            "no requests, no retrieve_keys call"
        );
    }

    /// A pending that asks for `n` data keys and resolves to the `(iv, tag)`
    /// pairs needed to retrieve them again.
    fn generating_pairs<'a>(
        keyset: &'a KeysetCipher<'_, CountingSource>,
        n: usize,
    ) -> Pending<'a, Vec<(Iv, Vec<u8>)>, CountingSource> {
        let requests = std::iter::repeat_with(|| Request::generate_under(d()))
            .take(n)
            .collect();
        Pending::request(keyset, requests, move |responses| {
            (0..n)
                .map(|_| {
                    responses
                        .next_generated_key()
                        .map(|key| (key.key.iv, key.tag))
                })
                .collect()
        })
    }

    /// The two request kinds dispatch independently: mixing them in one
    /// awaited assembly is one `generate_keys` *and* one `retrieve_keys`.
    #[tokio::test]
    async fn generate_and_retrieve_are_one_call_each() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let pairs = generating_pairs(&keyset, 2).await.unwrap();
        assert_eq!(
            cipher.kms().generate_calls(),
            1,
            "the setup seal is one call"
        );

        let keyset_id = keyset.keyset_id().await.unwrap();
        let requests: Vec<Request> = pairs
            .iter()
            .map(|(iv, tag)| Request::retrieve_under(*iv, tag.clone(), d(), keyset_id))
            .collect();
        let retrieve: Pending<'_, usize, _> = Pending::request(&keyset, requests, |responses| {
            Ok(responses.drain_retrieved().count())
        });
        let (count, fresh) = retrieve.zip(generating(&keyset, 1)).await.unwrap();

        assert_eq!(count, 2, "both keys were retrieved");
        assert_eq!(fresh.len(), 1, "and the fresh key was generated");
        assert_eq!(
            cipher.kms().generate_calls(),
            2,
            "one generate for the setup, one for the mixed assembly"
        );
        assert_eq!(
            cipher.kms().retrieve_calls(),
            1,
            "the mixed assembly retrieves in one call"
        );
    }

    /// Every request's descriptor reaches ZeroKMS on its own payload, in
    /// request order, on both the generate and the retrieve call: the
    /// descriptor is what binds the key to its field at ZeroKMS.
    #[tokio::test]
    async fn dispatch_forwards_each_requests_descriptor_in_order() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let requests = vec![
            Request::generate_under(Descriptor::of(("users", "email"))),
            Request::generate_under(Descriptor::of(("users", "name"))),
        ];
        let pairs: Vec<(Iv, Vec<u8>)> = Pending::request(&keyset, requests, |responses| {
            (0..2)
                .map(|_| {
                    responses
                        .next_generated_key()
                        .map(|key| (key.key.iv, key.tag))
                })
                .collect()
        })
        .await
        .unwrap();
        assert_eq!(
            cipher.kms().generate_descriptors(),
            vec![vec!["users/email".to_owned(), "users/name".to_owned()]]
        );

        let keyset_id = keyset.keyset_id().await.unwrap();
        let requests: Vec<Request> = pairs
            .iter()
            .zip([("users", "name"), ("users", "email")])
            .map(|((iv, tag), descriptor)| {
                Request::retrieve_under(*iv, tag.clone(), Descriptor::of(descriptor), keyset_id)
            })
            .collect();
        let count: usize = Pending::request(&keyset, requests, |responses| {
            Ok(responses.drain_retrieved().count())
        })
        .await
        .unwrap();

        assert_eq!(count, 2, "both keys were retrieved");
        assert_eq!(
            cipher.kms().retrieve_descriptors(),
            vec![vec!["users/name".to_owned(), "users/email".to_owned()]]
        );
    }

    /// ZeroKMS copies a descriptor into a fixed 512-byte block without a
    /// length check, so an over-long one must never reach it: the batch is
    /// refused before either call, with no key minted or retrieved.
    #[tokio::test]
    async fn an_over_long_descriptor_is_refused_before_any_call() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let long = Descriptor::of("a".repeat(Descriptor::MAX_LEN + 1));
        let requests = vec![
            Request::generate_under(Descriptor::of("users/email")),
            Request::generate_under(long.clone()),
        ];
        let Err(err) = dispatch(
            &cipher,
            Some(keyset.keyset_id().await.unwrap()),
            requests,
            None,
            &OwnIdentity,
        )
        .await
        else {
            panic!("an over-long descriptor must be refused");
        };
        assert!(
            matches!(err, Error::DescriptorTooLong { len } if len == Descriptor::MAX_LEN + 1),
            "{err}"
        );
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "no key is minted for a batch that is refused"
        );

        let mut pairs = generating_pairs(&keyset, 1).await.unwrap();
        let (iv, tag) = pairs.remove(0);
        let requests = vec![Request::retrieve_under(
            iv,
            tag,
            long,
            keyset.keyset_id().await.unwrap(),
        )];
        let Err(err) = dispatch(
            &cipher,
            Some(keyset.keyset_id().await.unwrap()),
            requests,
            None,
            &OwnIdentity,
        )
        .await
        else {
            panic!("an over-long descriptor must be refused");
        };
        assert!(matches!(err, Error::DescriptorTooLong { .. }), "{err}");
        assert_eq!(
            cipher.kms().retrieve_calls(),
            0,
            "and none is retrieved either"
        );

        // At the limit is fine.
        let before = cipher.kms().generate_calls();

        let requests = vec![Request::generate_under(Descriptor::of(
            "a".repeat(Descriptor::MAX_LEN),
        ))];
        assert!(
            dispatch(
                &cipher,
                Some(keyset.keyset_id().await.unwrap()),
                requests,
                None,
                &OwnIdentity
            )
            .await
            .is_ok(),
            "at the limit"
        );
        assert_eq!(
            cipher.kms().generate_calls(),
            before + 1,
            "a descriptor exactly at the limit is dispatched"
        );
    }

    // =========================================================================
    // Confined to a keyset
    // =========================================================================

    /// A generate request needs a keyset to mint under, and only a
    /// `KeysetCipher` has one: through the `StackCipher` it fails at
    /// construction, with no I/O.
    #[tokio::test]
    async fn a_generate_request_through_the_client_has_no_keyset() {
        let cipher = cipher().await;
        let pending: Pending<'_, Vec<u8>, _> =
            Pending::request(&cipher, vec![Request::generate_under(d())], |responses| {
                responses.next_generated_key().map(|key| key.tag)
            });
        let result = pending.await;

        assert!(matches!(result, Err(Error::NoKeyset)), "{result:?}");
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "refused at construction, before any call"
        );
    }

    /// Data keys are minted under the handle's keyset, and that is what
    /// reaches ZeroKMS.
    #[tokio::test]
    async fn generates_are_minted_under_the_handles_keyset() {
        let cipher = cipher().await;
        let tenant = cipher
            .keyset(Uuid::from_u128(9))
            .loaded(&OwnIdentity)
            .await
            .unwrap();
        generating(&tenant, 2).await.unwrap();

        assert_eq!(
            cipher.kms().generate_keysets(),
            vec![Some(Uuid::from_u128(9))],
            "the handle's keyset is what ZeroKMS is asked to mint under"
        );
    }

    /// A retrieve request naming another keyset than the handle's is refused
    /// at construction, before any key is retrieved.
    #[tokio::test]
    async fn a_retrieve_from_another_keyset_is_foreign_through_a_keyset() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let other = Uuid::from_u128(2);
        let pending: Pending<'_, usize, _> = Pending::request(
            &keyset,
            vec![Request::retrieve_under(Iv::default(), vec![1], d(), other)],
            |responses| Ok(responses.drain_retrieved().count()),
        );
        let result = pending.await;

        assert!(
            matches!(
                result,
                Err(Error::ForeignKeyset { expected, found })
                    if expected == keyset.keyset_id().await.unwrap() && found == other
            ),
            "{result:?}"
        );
        assert_eq!(
            cipher.kms().retrieve_calls(),
            0,
            "refused at construction, before any key is retrieved"
        );
    }

    /// Confining a pending built through the client (the constrained decrypt
    /// path) applies the same rule to the requests it already carries.
    #[tokio::test]
    async fn confining_a_pending_refuses_its_foreign_retrieves() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let other = Uuid::from_u128(2);
        let pending: Pending<'_, usize, _> = Pending::request(
            &cipher,
            vec![Request::retrieve_under(Iv::default(), vec![1], d(), other)],
            |responses| Ok(responses.drain_retrieved().count()),
        );
        let result = pending
            .confined_to_id(keyset.keyset_id().await.unwrap())
            .await;

        assert!(
            matches!(result, Err(Error::ForeignKeyset { .. })),
            "{result:?}"
        );
        assert_eq!(
            cipher.kms().retrieve_calls(),
            0,
            "confining applies the rule before any key is retrieved"
        );
    }

    /// Two pendings confined to different keysets are one tenant's row and
    /// another's: merging them is a composition bug, caught with no I/O.
    #[tokio::test]
    async fn pendings_confined_to_different_keysets_refuse_to_merge() {
        let cipher = cipher().await;
        let a = cipher
            .keyset(Uuid::from_u128(1))
            .loaded(&OwnIdentity)
            .await
            .unwrap();
        let b = cipher
            .keyset(Uuid::from_u128(2))
            .loaded(&OwnIdentity)
            .await
            .unwrap();

        let result = generating(&a, 1).zip(generating(&b, 1)).await;
        assert!(
            matches!(result, Err(Error::KeysetMismatch { left, right })
                if left == Uuid::from_u128(1) && right == Uuid::from_u128(2)),
            "{result:?}"
        );

        let result = Pending::all(&a, vec![generating(&a, 1), generating(&b, 1)]).await;
        assert!(
            matches!(result, Err(Error::KeysetMismatch { .. })),
            "{result:?}"
        );
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "a mismatched merge mints nothing"
        );
    }

    /// Confining a pending that is already confined checks the two agree:
    /// the same keyset again is a no-op, another one is the mismatch `zip`
    /// reports — never a silent change that mints under the second.
    #[tokio::test]
    async fn confining_to_another_keyset_is_a_mismatch() {
        let cipher = cipher().await;
        let a = cipher
            .keyset(Uuid::from_u128(1))
            .loaded(&OwnIdentity)
            .await
            .unwrap();

        let result = generating(&a, 1).confined_to_id(Uuid::from_u128(2)).await;
        assert!(
            matches!(result, Err(Error::KeysetMismatch { left, right })
                if left == Uuid::from_u128(1) && right == Uuid::from_u128(2)),
            "{result:?}"
        );
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "a mismatched keyset mints nothing"
        );

        let tags = generating(&a, 1)
            .confined_to_id(a.keyset_id().await.unwrap())
            .await
            .expect("confining to its own keyset changes nothing");
        assert_eq!(
            tags.len(),
            1,
            "confining to the same keyset should produce one tag"
        );
        assert_eq!(
            cipher.kms().generate_keysets(),
            vec![Some(a.keyset_id().await.unwrap())],
            "minted under the one keyset it was confined to"
        );
    }

    /// The keyset a pending is confined to is the one it keeps: merged
    /// afterwards with another tenant's pending, it is a mismatch, not a
    /// value with no keyset that the other side's keyset absorbs.
    #[tokio::test]
    async fn a_confined_pending_keeps_its_keyset_through_a_merge() {
        let cipher = cipher().await;
        let a = cipher
            .keyset(Uuid::from_u128(1))
            .loaded(&OwnIdentity)
            .await
            .unwrap();
        let b = cipher
            .keyset(Uuid::from_u128(2))
            .loaded(&OwnIdentity)
            .await
            .unwrap();

        let confined = Pending::ready(&cipher, Ok(())).confined_to_id(a.keyset_id().await.unwrap());
        let result = confined.zip(generating(&b, 1)).await;
        assert!(
            matches!(result, Err(Error::KeysetMismatch { left, right })
                if left == a.keyset_id().await.unwrap() && right == b.keyset_id().await.unwrap()),
            "{result:?}"
        );
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "a mismatched merge should not mint a key"
        );
    }

    /// A generate built through the client fails where it is built,
    /// so merging it into a tenant's batch afterwards cannot launder it into
    /// a key minted under that tenant's keyset.
    #[tokio::test]
    async fn a_generate_with_no_keyset_is_not_adopted_by_a_merge() {
        let cipher = cipher().await;
        let tenant = cipher
            .keyset(Uuid::from_u128(9))
            .loaded(&OwnIdentity)
            .await
            .unwrap();
        let no_keyset: Pending<'_, Vec<u8>, _> =
            Pending::request(&cipher, vec![Request::generate_under(d())], |responses| {
                responses.next_generated_key().map(|key| key.tag)
            });

        let result = no_keyset.zip(generating(&tenant, 1)).await;
        assert!(matches!(result, Err(Error::NoKeyset)), "{result:?}");
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "the tenant's keyset mints nothing for it"
        );
    }

    /// A pending with no keyset, merged with one confined to a keyset, is
    /// confined to that keyset: a
    /// ready value beside a tenant's data keys is still that tenant's batch.
    #[tokio::test]
    async fn a_pending_with_no_keyset_takes_the_keyset_it_is_merged_with() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let (n, tags) = Pending::ready(&cipher, Ok(7u32))
            .zip(generating(&keyset, 1))
            .await
            .unwrap();

        assert_eq!(
            (n, tags.len()),
            (7, 1),
            "both sides resolve: the ready value and the minted key"
        );
        assert_eq!(
            cipher.kms().generate_keysets(),
            vec![Some(keyset.keyset_id().await.unwrap())],
            "the merged assembly took the confined side's keyset"
        );
    }

    /// Through the client, retrieves from several keysets settle in one
    /// assembly: one `retrieve_keys` call per keyset, in first-seen order,
    /// with the keys back in request order.
    #[tokio::test]
    async fn retrieves_group_by_keyset_and_return_in_request_order() {
        let cipher = cipher().await;
        let a = cipher
            .keyset(Uuid::from_u128(1))
            .loaded(&OwnIdentity)
            .await
            .unwrap();
        let b = cipher
            .keyset(Uuid::from_u128(2))
            .loaded(&OwnIdentity)
            .await
            .unwrap();
        let mut from_a = generating_pairs(&a, 2).await.unwrap();
        let mut from_b = generating_pairs(&b, 1).await.unwrap();
        let (a1, a2) = (from_a.remove(0), from_a.remove(0));
        let b1 = from_b.remove(0);

        // Interleaved: A, B, A.
        let requests = vec![
            Request::retrieve_under(a1.0, a1.1.clone(), d(), a.keyset_id().await.unwrap()),
            Request::retrieve_under(b1.0, b1.1.clone(), d(), b.keyset_id().await.unwrap()),
            Request::retrieve_under(a2.0, a2.1.clone(), d(), a.keyset_id().await.unwrap()),
        ];
        let ivs: Vec<Iv> = Pending::request(&cipher, requests, |responses| {
            Ok(responses.drain_retrieved().map(|key| key.iv).collect())
        })
        .await
        .unwrap();

        assert_eq!(
            ivs,
            vec![a1.0, b1.0, a2.0],
            "keys must come back in request order"
        );
        assert_eq!(
            cipher.kms().retrieve_calls(),
            2,
            "two keysets, two retrieve_keys calls"
        );
        assert_eq!(
            cipher.kms().retrieve_keysets(),
            vec![
                Some(a.keyset_id().await.unwrap()),
                Some(b.keyset_id().await.unwrap())
            ],
            "one call per keyset, first seen first"
        );
    }
}
