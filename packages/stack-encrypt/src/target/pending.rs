//! [`Pending`]: the request carrier [`StackCipher`] hands back from
//! [`EncryptFrom`](super::EncryptFrom) / [`DecryptInto`](super::DecryptInto),
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

use stack_kms::{DataKey, DataKeySource, GenerateKeyPayload, Iv, MaybeSend, RetrieveKeyPayload};
use uuid::Uuid;

use super::request::{tally, Request, RequestKind, Responses};
use crate::{Descriptor, Error, KeysetCipher, StackCipher};

/// The boxed fulfilment: consumes this pending's slice of the responses and
/// produces the output. The `Send` split mirrors [`stack_kms::MaybeSend`] —
/// the underlying ZeroKMS futures are not `Send` on wasm32.
#[cfg(not(target_arch = "wasm32"))]
type FulfilBox<'a, T> = Box<dyn FnOnce(&mut Responses) -> Result<T, Error> + Send + 'a>;
/// See the native definition above; identical minus the `Send` bound.
#[cfg(target_arch = "wasm32")]
type FulfilBox<'a, T> = Box<dyn FnOnce(&mut Responses) -> Result<T, Error> + 'a>;

/// The boxed future a [`Pending`] settles through; `Send` split as above.
#[cfg(not(target_arch = "wasm32"))]
pub type PendingFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'a>>;
/// See the native definition above; identical minus the `Send` bound.
#[cfg(target_arch = "wasm32")]
pub type PendingFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + 'a>>;

/// A request carrier resolving to `T`: [`StackCipher`]'s
/// [`EncryptTarget::Output`](super::EncryptTarget::Output) /
/// [`DecryptTarget::Output`](super::DecryptTarget::Output).
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
#[must_use = "a Pending does nothing until it is awaited or merged into one that is; \
              dropping it silently discards the value and any error that produced it"]
pub struct Pending<'a, T, K> {
    /// The cipher the settled batch dispatches through. Which
    /// [`StackCipher`] value it is does not constrain merging — see
    /// [`zip`](Self::zip) — only which client issues the calls.
    cipher: &'a StackCipher<K>,
    /// The keyset this pending is scoped to: the one a [`KeysetCipher`]
    /// built it through, or none when it was built through the
    /// [`StackCipher`]. A scoped pending mints every data key under this
    /// keyset and opens leaves from no other; an unscoped one mints nothing
    /// ([`Error::NoKeyset`]) and opens leaves from any keyset, one retrieve
    /// call per keyset. Merging two scopes is [`Error::KeysetMismatch`].
    keyset: Option<Uuid>,
    requests: Vec<Request>,
    /// Set when the value already failed during the synchronous build
    /// (`ready(Err(..))`, a keyset mismatch, a failed sibling). A failed
    /// pending carries no requests, and merging one into an assembly drops
    /// the assembly's requests too, so settling it does no I/O: a record
    /// with one misconfigured field never mints data keys it will throw away.
    /// When set, `fulfil` is never called.
    failed: Option<Error>,
    fulfil: FulfilBox<'a, T>,
}

/// What a [`Pending`] is built through: a [`StackCipher`] (no keyset
/// scope) or a [`KeysetCipher`] (scoped to its keyset). Implemented for
/// references to both, so the constructors take either.
///
/// Sealed: the two scopes are the two shapes, and a scope is how the target
/// layer asks a cipher what it is bound to — not an extension point. An
/// outside implementation could name any keyset id without holding the
/// keyset, which would make [`Pending`]'s scope rules
/// ([`Error::NoKeyset`], [`Error::ForeignKeyset`]) say less than they do:
/// a scope's id is one the cipher loaded from ZeroKMS. Downstream code
/// implements [`EncryptFrom`](super::EncryptFrom) and passes the scope it
/// was handed; it never needs one of its own.
pub trait CipherScope<'a, K>: sealed::Sealed {
    /// The client-scoped cipher the pending settles through.
    fn cipher(&self) -> &'a StackCipher<K>;
    /// The keyset the pending is scoped to, if any.
    fn keyset(&self) -> Option<Uuid>;
}

mod sealed {
    pub trait Sealed {}
    impl<K> Sealed for &crate::StackCipher<K> {}
    impl<K> Sealed for &crate::KeysetCipher<'_, K> {}
}

impl<'a, K> CipherScope<'a, K> for &'a StackCipher<K> {
    fn cipher(&self) -> &'a StackCipher<K> {
        self
    }

    fn keyset(&self) -> Option<Uuid> {
        None
    }
}

impl<'a, K> CipherScope<'a, K> for &'a KeysetCipher<'_, K> {
    fn cipher(&self) -> &'a StackCipher<K> {
        KeysetCipher::cipher(self)
    }

    fn keyset(&self) -> Option<Uuid> {
        Some(self.keyset_id())
    }
}

impl<'a, T: 'a, K> Pending<'a, T, K> {
    /// A pending with no requests: `result` was fully derived during the
    /// synchronous build. Awaiting it does no I/O.
    pub fn ready(scope: impl CipherScope<'a, K>, result: Result<T, Error>) -> Self
    where
        T: MaybeSend,
    {
        match result {
            Ok(value) => Self {
                cipher: scope.cipher(),
                keyset: scope.keyset(),
                requests: Vec::new(),
                failed: None,
                fulfil: Box::new(move |_| Ok(value)),
            },
            Err(error) => Self::failed(scope, error),
        }
    }

    /// A pending that already failed. No requests, no `T` bound (nothing of
    /// type `T` is ever produced), and any assembly it is merged into fails
    /// without I/O — see the `failed` field.
    ///
    /// Public because a [`DecryptField`](super::DecryptField) implementation
    /// (including the derive's generated code) reaches for it when a
    /// contract is broken at decrypt time — e.g.
    /// [`Error::NotOpened`] for a field whose type declared
    /// [`DECRYPTABLE`](super::Decryptable::DECRYPTABLE) but was passed over.
    pub fn failed(scope: impl CipherScope<'a, K>, error: Error) -> Self {
        Self {
            cipher: scope.cipher(),
            keyset: scope.keyset(),
            requests: Vec::new(),
            failed: Some(error),
            // Unreachable: `settle` returns the stored error before any
            // fulfilment runs. Kept honest rather than panicking.
            fulfil: Box::new(|_| {
                Err(Error::Other(
                    "fulfilment invoked on an already-failed pending".into(),
                ))
            }),
        }
    }

    /// A pending whose value needs ZeroKMS responses. `fulfil` runs after the
    /// batched call, scoped to exactly the responses `requests` asked for —
    /// drawing more (or another kind) is [`Error::ResponseShape`], and can
    /// never consume a sibling pending's responses.
    ///
    /// The scope is exact in both directions: a fulfilment must also consume
    /// *every* response it asked for. Leaving one behind is
    /// [`Error::ResponseShape`] too — the key was minted at ZeroKMS, and
    /// silently discarding it means the pending's declared requests do not
    /// describe what it actually does.
    ///
    /// The keyset rules apply at construction, before any I/O: a generate
    /// request through a [`StackCipher`] scope is [`Error::NoKeyset`], and
    /// a retrieve request naming another keyset than a [`KeysetCipher`]
    /// scope's is [`Error::ForeignKeyset`].
    pub fn request<F>(scope: impl CipherScope<'a, K>, requests: Vec<Request>, fulfil: F) -> Self
    where
        F: FnOnce(&mut Responses) -> Result<T, Error> + MaybeSend + 'a,
    {
        let (generated, retrieved) = tally(&requests);
        if let Err(error) = check_scope(scope.keyset(), &requests) {
            return Self::failed(scope, error);
        }
        Self {
            cipher: scope.cipher(),
            keyset: scope.keyset(),
            requests,
            failed: None,
            fulfil: Box::new(move |responses| {
                let mut own = responses.split_front(generated, retrieved)?;
                let value = fulfil(&mut own)?;
                if !own.is_exhausted() {
                    return Err(Error::ResponseShape);
                }
                Ok(value)
            }),
        }
    }

    /// Transform the resolved value. No I/O, no new requests.
    pub fn map<U: 'a, F>(self, f: F) -> Pending<'a, U, K>
    where
        F: FnOnce(T) -> U + MaybeSend + 'a,
    {
        let fulfil = self.fulfil;
        Pending {
            cipher: self.cipher,
            keyset: self.keyset,
            requests: self.requests,
            failed: self.failed,
            fulfil: Box::new(move |responses| fulfil(responses).map(f)),
        }
    }

    /// Fallibly transform the resolved value without issuing another request.
    pub fn try_map<U: 'a, F>(self, f: F) -> Pending<'a, U, K>
    where
        F: FnOnce(T) -> Result<U, Error> + MaybeSend + 'a,
    {
        let fulfil = self.fulfil;
        Pending {
            cipher: self.cipher,
            keyset: self.keyset,
            requests: self.requests,
            failed: self.failed,
            fulfil: Box::new(move |responses| fulfil(responses).and_then(f)),
        }
    }

    /// Scope this pending to `keyset`: what a [`KeysetCipher`]'s decrypt
    /// does to the pending its [`StackCipher`] built, so that opening a
    /// leaf from any other keyset fails before any key is retrieved.
    /// Scoping a pending already scoped to another keyset is
    /// [`Error::KeysetMismatch`].
    pub(crate) fn scoped_to(self, keyset: Uuid) -> Self {
        if let Some(existing) = self.keyset {
            if existing != keyset {
                return Pending::failed(
                    self.cipher,
                    Error::KeysetMismatch {
                        left: existing,
                        right: keyset,
                    },
                );
            }
        }
        if let Err(error) = check_scope(Some(keyset), &self.requests) {
            return Pending::failed(self.cipher, error);
        }
        Pending {
            keyset: Some(keyset),
            ..self
        }
    }

    /// Merge two pendings into one resolving to the pair. Their requests
    /// concatenate — awaiting the result is still one batched call per
    /// request kind.
    ///
    /// Both must agree on a keyset if both are scoped to one: the merged
    /// assembly mints every key under one keyset, so merging one tenant's
    /// pending with another's is [`Error::KeysetMismatch`], not a debug
    /// assertion. A scoped pending merged with an unscoped one takes the
    /// scope. If either side already failed, the result is that failure and
    /// carries no requests.
    ///
    /// The keyset is the whole rule: the two sides need not have been built
    /// through the *same* [`StackCipher`] value. The merged assembly
    /// dispatches through one of them, and every request it carries is
    /// keyset-addressed — a generate mints under the merged scope, a
    /// retrieve names the keyset its leaf was sealed under. A keyset id is
    /// global, and a cipher only holds a keyset ZeroKMS resolved for its
    /// client, so either side's client can dispatch the batch; a client that
    /// is *not* authorised for the keyset is refused at ZeroKMS
    /// ([`Error::Kms`]), exactly as it would be on its own.
    pub fn zip<U: 'a>(self, other: Pending<'a, U, K>) -> Pending<'a, (T, U), K> {
        let keyset = match merge_scopes(self.keyset, other.keyset) {
            Ok(keyset) => keyset,
            Err(error) => return Pending::failed(self.cipher, error),
        };
        if let Some(error) = self.failed.or(other.failed) {
            return Pending::failed(self.cipher, error);
        }
        let mut requests = self.requests;
        requests.extend(other.requests);
        if let Err(error) = check_scope(keyset, &requests) {
            return Pending::failed(self.cipher, error);
        }
        let first = self.fulfil;
        let second = other.fulfil;
        Pending {
            cipher: self.cipher,
            keyset,
            requests,
            failed: None,
            fulfil: Box::new(move |responses| Ok((first(responses)?, second(responses)?))),
        }
    }

    /// Merge any number of same-typed pendings into one resolving to the
    /// `Vec` — [`zip`](Self::zip) at scale, used by the `Vec<T>`
    /// implementations to make a whole column one batched call. Same rule as
    /// `zip`: every item must agree with `scope`'s keyset — which cipher
    /// value each was built through does not matter, for the reason `zip`
    /// gives — and the first failed item fails the whole column with no I/O.
    pub fn all(
        scope: impl CipherScope<'a, K>,
        items: Vec<Pending<'a, T, K>>,
    ) -> Pending<'a, Vec<T>, K> {
        let cipher = scope.cipher();
        let mut keyset = scope.keyset();
        let mut requests = Vec::new();
        let mut fulfils = Vec::with_capacity(items.len());
        for item in items {
            keyset = match merge_scopes(keyset, item.keyset) {
                Ok(keyset) => keyset,
                Err(error) => return Pending::failed(cipher, error),
            };
            if let Some(error) = item.failed {
                return Pending::failed(cipher, error);
            }
            requests.extend(item.requests);
            fulfils.push(item.fulfil);
        }
        if let Err(error) = check_scope(keyset, &requests) {
            return Pending::failed(cipher, error);
        }
        Pending {
            cipher,
            keyset,
            requests,
            failed: None,
            fulfil: Box::new(move |responses| {
                fulfils
                    .into_iter()
                    .map(|fulfil| fulfil(responses))
                    .collect()
            }),
        }
    }
}

impl<'a, T: 'a, K> Pending<'a, T, K>
where
    K: DataKeySource,
{
    /// Settle: one batched ZeroKMS call per request kind (none at all for an
    /// all-[`ready`](Pending::ready) assembly), then the fulfilments shape the
    /// responses. This is the only place I/O happens — the cipher-directed
    /// API ([`StackCipher::encrypt`] / [`StackCipher::decipher`]) settles
    /// through here too, so there is exactly one path to ZeroKMS.
    ///
    /// Unboxed, so it carries no `Send`/`Sync` demands beyond the backend's
    /// own; the public [`IntoFuture`] impl boxes it.
    pub(crate) async fn settle(self) -> Result<T, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let mut responses = dispatch(self.cipher, self.keyset, self.requests).await?;
        (self.fulfil)(&mut responses)
    }
}

/// The keyset two merged pendings share: either's when the other has none,
/// [`Error::KeysetMismatch`] when both have one and they differ.
fn merge_scopes(left: Option<Uuid>, right: Option<Uuid>) -> Result<Option<Uuid>, Error> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => Err(Error::KeysetMismatch { left, right }),
        (Some(keyset), _) | (_, Some(keyset)) => Ok(Some(keyset)),
        (None, None) => Ok(None),
    }
}

/// The keyset rules over a request list, applied wherever requests meet a
/// scope — construction, scoping, merging — so a violation fails the
/// pending before any I/O: a generate request needs a keyset to mint under
/// ([`Error::NoKeyset`]), and a retrieve request in a scoped pending must
/// name that keyset ([`Error::ForeignKeyset`]).
fn check_scope(keyset: Option<Uuid>, requests: &[Request]) -> Result<(), Error> {
    for request in requests {
        match (keyset, request.retrieve_keyset()) {
            (None, None) => return Err(Error::NoKeyset),
            (Some(expected), Some(found)) if expected != found => {
                return Err(Error::ForeignKeyset { expected, found });
            }
            _ => {}
        }
    }
    Ok(())
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
    K: DataKeySource + Sync,
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
    K: DataKeySource,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.settle())
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
/// `generate_keys` (under the pending's keyset) and one `retrieve_keys` per
/// keyset the retrieved leaves were sealed under, whatever the request
/// count. When ZeroKMS grows a combined operation (data keys + PRF
/// derivations in one round-trip), this is the one place that changes.
async fn dispatch<K: DataKeySource>(
    cipher: &StackCipher<K>,
    keyset: Option<Uuid>,
    requests: Vec<Request>,
) -> Result<Responses, Error> {
    let mut generates: Vec<Descriptor> = Vec::new();
    let mut retrieves: Vec<Retrieve> = Vec::new();
    for request in requests {
        match request.into_kind() {
            RequestKind::GenerateDataKey { descriptor } => generates.push(descriptor),
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

    let generated = if generates.is_empty() {
        Vec::new()
    } else {
        // Every constructor checks this before any I/O (`check_scope`), so
        // an unscoped generate cannot reach here; kept as the rule, not
        // as an assumption.
        let keyset = keyset.ok_or(Error::NoKeyset)?;
        // Each leaf's descriptor is its context, rendered; the lock context
        // stays empty — see the descriptor module docs.
        let payloads: Vec<GenerateKeyPayload<'_>> = generates
            .iter()
            .map(|descriptor| GenerateKeyPayload::new(descriptor.as_str(), Cow::Owned(Vec::new())))
            .collect();
        let expected = payloads.len();
        let keys = cipher
            .kms()
            .generate_keys(payloads, Some(keyset), None)
            .await?;
        if keys.len() != expected {
            return Err(Error::KeyCountMismatch {
                expected,
                received: keys.len(),
            });
        }
        keys
    };

    // Retrieves group by the keyset each leaf names — one call per keyset,
    // in first-seen order — and the keys scatter back into request order,
    // which is the order the fulfilments draw them in.
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
        let keys = cipher
            .kms()
            .retrieve_keys(payloads, Some(keyset_id), None)
            .await?;
        if keys.len() != expected {
            return Err(Error::KeyCountMismatch {
                expected,
                received: keys.len(),
            });
        }
        for (index, key) in indices.into_iter().zip(keys) {
            retrieved[index] = Some(key);
        }
    }
    // Every slot was filled by exactly one group; a hole would mean the
    // grouping above lost a request, which is a bug here, not a data error.
    let retrieved: Vec<DataKey> = retrieved
        .into_iter()
        .map(|key| key.ok_or(Error::ResponseShape))
        .collect::<Result<_, _>>()?;

    Ok(Responses::new(generated, retrieved))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use stack_kms::{FakeDataKeySource, IdentifiedBy, IndexKey, IndexKeySource, UnverifiedContext};
    use uuid::Uuid;

    use super::*;

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
            self.inner.load_index_key(keyset_id).await
        }
    }

    fn d() -> Descriptor {
        Descriptor::of("test/field")
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
        let requests = std::iter::repeat_with(|| Request::generate_data_key(d()))
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

    /// The scoping guarantee at the `Pending` level: zipped fulfilments draw
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

    /// Over-drawing is the fulfilment's own error, not a stolen sibling key:
    /// the second pending still resolves to the key it asked for.
    #[tokio::test]
    async fn over_drawing_responses_is_a_response_shape_error() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let greedy: Pending<'_, Vec<u8>, _> = Pending::request(
            &keyset,
            vec![Request::generate_data_key(d())],
            |responses| {
                let _ = responses.next_generated_key()?;
                // One request, two draws.
                responses.next_generated_key().map(|key| key.tag)
            },
        );
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
            Pending::request(&keyset, vec![Request::generate_data_key(d())], |_| Ok(()));
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
        let requests = vec![
            Request::generate_data_key(d()),
            Request::generate_data_key(d()),
        ];
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
            Request::generate_data_key(d()),
            Request::retrieve_data_key(iv, tag, d(), keyset.keyset_id()),
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
        let requests = std::iter::repeat_with(|| Request::generate_data_key(d()))
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

        let requests: Vec<Request> = pairs
            .iter()
            .map(|(iv, tag)| Request::retrieve_data_key(*iv, tag.clone(), d(), keyset.keyset_id()))
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
            Request::generate_data_key(Descriptor::of("users/email")),
            Request::generate_data_key(Descriptor::of("users/name")),
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

        let requests: Vec<Request> = pairs
            .iter()
            .zip(["users/name", "users/email"])
            .map(|((iv, tag), descriptor)| {
                Request::retrieve_data_key(
                    *iv,
                    tag.clone(),
                    Descriptor::of(descriptor),
                    keyset.keyset_id(),
                )
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
            Request::generate_data_key(Descriptor::of("users/email")),
            Request::generate_data_key(long.clone()),
        ];
        let Err(err) = dispatch(&cipher, Some(keyset.keyset_id()), requests).await else {
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
        let requests = vec![Request::retrieve_data_key(
            iv,
            tag,
            long,
            keyset.keyset_id(),
        )];
        let Err(err) = dispatch(&cipher, Some(keyset.keyset_id()), requests).await else {
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

        let requests = vec![Request::generate_data_key(Descriptor::of(
            "a".repeat(Descriptor::MAX_LEN),
        ))];
        assert!(
            dispatch(&cipher, Some(keyset.keyset_id()), requests)
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
    // Keyset scope
    // =========================================================================

    /// A generate request needs a keyset to mint under, and only a
    /// `KeysetCipher` scope has one: through the `StackCipher` it fails at
    /// construction, with no I/O.
    #[tokio::test]
    async fn a_generate_request_through_the_client_scope_has_no_keyset() {
        let cipher = cipher().await;
        let pending: Pending<'_, Vec<u8>, _> = Pending::request(
            &cipher,
            vec![Request::generate_data_key(d())],
            |responses| responses.next_generated_key().map(|key| key.tag),
        );
        let result = pending.await;

        assert!(matches!(result, Err(Error::NoKeyset)), "{result:?}");
        assert_eq!(
            cipher.kms().generate_calls(),
            0,
            "refused at construction, before any call"
        );
    }

    /// Data keys are minted under the scope's keyset, and that is what
    /// reaches ZeroKMS.
    #[tokio::test]
    async fn generates_are_minted_under_the_scopes_keyset() {
        let cipher = cipher().await;
        let tenant = cipher.keyset(Uuid::from_u128(9)).await.unwrap();
        generating(&tenant, 2).await.unwrap();

        assert_eq!(
            cipher.kms().generate_keysets(),
            vec![Some(Uuid::from_u128(9))],
            "the scope's keyset is what ZeroKMS is asked to mint under"
        );
    }

    /// A retrieve request naming another keyset than the scope's is refused
    /// at construction, before any key is retrieved.
    #[tokio::test]
    async fn a_retrieve_from_another_keyset_is_foreign_in_a_keyset_scope() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let other = Uuid::from_u128(2);
        let pending: Pending<'_, usize, _> = Pending::request(
            &keyset,
            vec![Request::retrieve_data_key(
                Iv::default(),
                vec![1],
                d(),
                other,
            )],
            |responses| Ok(responses.drain_retrieved().count()),
        );
        let result = pending.await;

        assert!(
            matches!(
                result,
                Err(Error::ForeignKeyset { expected, found })
                    if expected == keyset.keyset_id() && found == other
            ),
            "{result:?}"
        );
        assert_eq!(
            cipher.kms().retrieve_calls(),
            0,
            "refused at construction, before any key is retrieved"
        );
    }

    /// Scoping a pending built through the client (the constrained decrypt
    /// path) applies the same rule to the requests it already carries.
    #[tokio::test]
    async fn scoping_an_unscoped_pending_refuses_its_foreign_retrieves() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let other = Uuid::from_u128(2);
        let pending: Pending<'_, usize, _> = Pending::request(
            &cipher,
            vec![Request::retrieve_data_key(
                Iv::default(),
                vec![1],
                d(),
                other,
            )],
            |responses| Ok(responses.drain_retrieved().count()),
        );
        let result = pending.scoped_to(keyset.keyset_id()).await;

        assert!(
            matches!(result, Err(Error::ForeignKeyset { .. })),
            "{result:?}"
        );
        assert_eq!(
            cipher.kms().retrieve_calls(),
            0,
            "scoping applies the rule before any key is retrieved"
        );
    }

    /// Two pendings scoped to different keysets are one tenant's row and
    /// another's: merging them is a composition bug, caught with no I/O.
    #[tokio::test]
    async fn pendings_scoped_to_different_keysets_refuse_to_merge() {
        let cipher = cipher().await;
        let a = cipher.keyset(Uuid::from_u128(1)).await.unwrap();
        let b = cipher.keyset(Uuid::from_u128(2)).await.unwrap();

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

    /// An unscoped pending merged with a scoped one takes the scope: a
    /// ready value beside a tenant's data keys is still that tenant's batch.
    #[tokio::test]
    async fn an_unscoped_pending_merged_with_a_scoped_one_takes_the_scope() {
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
            vec![Some(keyset.keyset_id())],
            "the merged assembly took the scoped side's keyset"
        );
    }

    /// Through the client scope, retrieves from several keysets settle in one
    /// assembly: one `retrieve_keys` call per keyset, in first-seen order,
    /// with the keys back in request order.
    #[tokio::test]
    async fn retrieves_group_by_keyset_and_return_in_request_order() {
        let cipher = cipher().await;
        let a = cipher.keyset(Uuid::from_u128(1)).await.unwrap();
        let b = cipher.keyset(Uuid::from_u128(2)).await.unwrap();
        let mut from_a = generating_pairs(&a, 2).await.unwrap();
        let mut from_b = generating_pairs(&b, 1).await.unwrap();
        let (a1, a2) = (from_a.remove(0), from_a.remove(0));
        let b1 = from_b.remove(0);

        // Interleaved: A, B, A.
        let requests = vec![
            Request::retrieve_data_key(a1.0, a1.1.clone(), d(), a.keyset_id()),
            Request::retrieve_data_key(b1.0, b1.1.clone(), d(), b.keyset_id()),
            Request::retrieve_data_key(a2.0, a2.1.clone(), d(), a.keyset_id()),
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
            vec![Some(a.keyset_id()), Some(b.keyset_id())],
            "one call per keyset, first seen first"
        );
    }
}
