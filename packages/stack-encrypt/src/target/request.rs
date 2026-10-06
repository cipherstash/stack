//! The ZeroKMS work a [`Pending`](super::Pending) carries, and the responses
//! it settles against.
//!
//! A [`Request`] is one unit of work — "generate a data key", "re-derive the
//! data key identified by this `iv` + `tag`". Requests accumulate as pendings
//! are combined, and awaiting the combined [`Pending`](super::Pending) turns
//! the whole accumulated list into **one** ZeroKMS call per kind.
//! [`Responses`] is what comes back: one queue per kind, in request order.
//!
//! The two halves are deliberately dumb — no I/O, no cipher, no futures — so
//! the response-scoping rules that keep one fulfilment from consuming a
//! sibling's key material are unit-testable on their own.

use super::context::AeadContext;
use std::collections::VecDeque;

use vitaminc_kms::GeneratedDataKey;

use crate::registry::KeysetId;
use crate::{Descriptor, Error};

/// One retrieved data key's material, in the `Protected` that
/// `vitaminc-kms` was built against.
pub type ProviderKey = vitaminc_protected_kms::Protected<[u8; 32]>;

/// One unit of ZeroKMS work a [`Pending`](super::Pending) needs:
/// constructible, otherwise opaque, so new request kinds (a PRF derivation, a
/// keyset override) can be added without breaking implementations.
#[derive(Debug, Clone)]
pub struct Request(RequestKind);

#[derive(Debug, Clone)]
pub(super) enum RequestKind {
    /// Generate one fresh data key under the pending's keyset, bound to
    /// `descriptor`.
    GenerateDataKey { descriptor: Descriptor },
    /// Re-derive the data key `key_id` names, under the `descriptor` it was
    /// generated with, from the keyset it was minted under.
    RetrieveDataKey {
        key_id: Vec<u8>,
        descriptor: Descriptor,
        keyset_id: KeysetId,
        /// Whether the leaf is format 1 ([`SealedValue::FORMAT_VERSION_V1`]):
        /// its key id is ZeroKMS's `iv ‖ tag`, so only a registry that reads
        /// format-1 leaves may be asked for it.
        ///
        /// [`SealedValue::FORMAT_VERSION_V1`]: crate::SealedValue::FORMAT_VERSION_V1
        v1_leaf: bool,
    },
}

impl Request {
    /// Request one fresh data key (encrypt side), minted under `context`.
    ///
    /// The [`Descriptor`] is rendered here rather than supplied, so a request
    /// cannot carry a descriptor that disagrees with its own `context`
    /// (ADR-0004, decision 4). ZeroKMS HMACs the descriptor into the key
    /// `tag`, so the key re-derives only under the same one. What this does
    /// not relate is the request to the leaf sealed with the key: a
    /// [`SealedValue`](crate::SealedValue) is still assembled from raw parts
    /// at the extension point, and its AEAD context is the caller's to keep
    /// in agreement with this one.
    ///
    /// A descriptor is rendered from the context's parts, so the context
    /// need only convert into an [`AeadContext`]: any `IntoContext` type a
    /// [`StackCipherText`](crate::StackCipherText) seals under can request
    /// the key it seals with, and a [`CallerContext`](super::CallerContext)
    /// converts as it is.
    pub fn generate_data_key(context: impl Into<AeadContext>) -> Self {
        Self::generate_under(Descriptor::of(context.into()))
    }

    /// Request re-derivation of the data key `key_id` names
    /// (decrypt side), under `context` — which must be the one the key was
    /// generated under, or a bound backend refuses — from `keyset_id`, the keyset it
    /// was minted under (a [`SealedValue`] carries it).
    ///
    /// [`SealedValue`]: crate::SealedValue
    pub fn retrieve_data_key(
        key_id: Vec<u8>,
        context: impl Into<AeadContext>,
        keyset_id: KeysetId,
    ) -> Self {
        Self::retrieve_under(key_id, Descriptor::of(context.into()), keyset_id)
    }

    /// [`generate_data_key`](Self::generate_data_key) over a descriptor that
    /// has already been rendered.
    ///
    /// Crate-internal: the batching paths derive one descriptor from one
    /// context and reuse it across every leaf of a tree, and re-rendering it
    /// per request would cost a context encoding per leaf. The public
    /// constructor takes the context so that a request's descriptor and the
    /// context it was asked for under cannot disagree.
    pub(crate) fn generate_under(descriptor: Descriptor) -> Self {
        Self(RequestKind::GenerateDataKey { descriptor })
    }

    /// [`retrieve_data_key`](Self::retrieve_data_key) over an already
    /// rendered descriptor. Crate-internal, as
    /// [`generate_under`](Self::generate_under).
    pub(crate) fn retrieve_under(
        key_id: Vec<u8>,
        descriptor: Descriptor,
        keyset_id: KeysetId,
    ) -> Self {
        Self(RequestKind::RetrieveDataKey {
            key_id,
            descriptor,
            keyset_id,
            v1_leaf: false,
        })
    }

    /// The retrieve request for `leaf`'s data key, under an already rendered
    /// descriptor. Carries the leaf's format, so that the dispatch can
    /// refuse a format-1 leaf to a registry that does not read them.
    pub(crate) fn retrieve_leaf(leaf: &crate::SealedValue, descriptor: Descriptor) -> Self {
        Self(RequestKind::RetrieveDataKey {
            key_id: leaf.key_id().to_vec(),
            descriptor,
            keyset_id: leaf.keyset_id(),
            v1_leaf: leaf.format_version() == crate::SealedValue::FORMAT_VERSION_V1,
        })
    }

    /// Consume the request, yielding what it asks for.
    pub(super) fn into_kind(self) -> RequestKind {
        self.0
    }

    /// The keyset a retrieve request names; `None` for a generate request,
    /// which mints under the pending's keyset.
    pub(super) fn retrieve_keyset(&self) -> Option<KeysetId> {
        match &self.0 {
            RequestKind::GenerateDataKey { .. } => None,
            RequestKind::RetrieveDataKey { keyset_id, .. } => Some(*keyset_id),
        }
    }
}

/// How many requests of each kind `requests` holds, as
/// `(generate, retrieve)` — the shape a fulfilment is scoped to.
pub(super) fn tally(requests: &[Request]) -> (usize, usize) {
    let (mut generate, mut retrieve) = (0usize, 0usize);
    for request in requests {
        match request.0 {
            RequestKind::GenerateDataKey { .. } => generate += 1,
            RequestKind::RetrieveDataKey { .. } => retrieve += 1,
        }
    }
    (generate, retrieve)
}

/// The responses a fulfilment draws from — one queue per request kind, in
/// request order. A fulfilment sees exactly the responses its own requests
/// asked for (never a neighbour's), and drawing past that is
/// [`Error::ResponseShape`].
pub struct Responses {
    generated: VecDeque<GeneratedDataKey<32>>,
    retrieved: VecDeque<ProviderKey>,
}

impl Responses {
    /// The full response set of one batched dispatch, in request order.
    pub(super) fn new(generated: Vec<GeneratedDataKey<32>>, retrieved: Vec<ProviderKey>) -> Self {
        Self {
            generated: generated.into(),
            retrieved: retrieved.into(),
        }
    }

    /// The next generated data key, in [`Request::generate_data_key`] order.
    pub fn next_generated_key(&mut self) -> Result<GeneratedDataKey<32>, Error> {
        self.generated.pop_front().ok_or(Error::ResponseShape)
    }

    /// The next retrieved data key, in [`Request::retrieve_data_key`] order.
    pub fn next_retrieved_key(&mut self) -> Result<ProviderKey, Error> {
        self.retrieved.pop_front().ok_or(Error::ResponseShape)
    }

    /// Split off the first `generated` + `retrieved` responses — the
    /// per-fulfilment view [`Pending::request`](super::Pending::request)
    /// scopes each fulfilment to. Short of either count is
    /// [`Error::ResponseShape`], and nothing is consumed.
    pub(super) fn split_front(
        &mut self,
        generated: usize,
        retrieved: usize,
    ) -> Result<Responses, Error> {
        if self.generated.len() < generated || self.retrieved.len() < retrieved {
            return Err(Error::ResponseShape);
        }
        Ok(Responses {
            generated: self.generated.drain(..generated).collect(),
            retrieved: self.retrieved.drain(..retrieved).collect(),
        })
    }

    /// Whether every response in this view has been drawn. Checked after a
    /// fulfilment returns: a fulfilment that asked for a key and left it
    /// behind is a composition bug, not a cheaper request.
    pub(super) fn is_exhausted(&self) -> bool {
        self.generated.is_empty() && self.retrieved.is_empty()
    }

    pub(crate) fn drain_generated(&mut self) -> impl Iterator<Item = GeneratedDataKey<32>> + '_ {
        self.generated.drain(..)
    }

    pub(crate) fn drain_retrieved(&mut self) -> impl Iterator<Item = ProviderKey> + '_ {
        self.retrieved.drain(..)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use vitaminc_protected_kms::Controlled as _;

    use super::*;
    use crate::{ContextPiece, IntoContext, MaybeEmpty, NonEmpty};

    fn d() -> Descriptor {
        Descriptor::of("test/field")
    }

    /// `n` real generated keys, plus the retrieved keys for the same `n`
    /// (`iv`, `tag`) pairs — the stub round-trips, which is all these tests
    /// need from it.
    async fn key_pairs(n: usize) -> (Vec<GeneratedDataKey<32>>, Vec<ProviderKey>) {
        use vitaminc_kms::provider::{Binding, FakeKeyProvider, KeyProvider as _};

        let provider = FakeKeyProvider::<32>::new();
        let bindings: Vec<Binding<'_>> = (0..n).map(|_| Binding::EMPTY).collect();
        let generated = provider.generate_keys(&bindings).await.unwrap();
        let pairs: Vec<_> = generated
            .iter()
            .map(|key| (key.key_id.clone(), Binding::EMPTY))
            .collect();
        let retrieved = provider.retrieve_keys(&pairs).await.unwrap();
        (generated, retrieved)
    }

    fn ks() -> KeysetId {
        KeysetId::new(uuid::Uuid::from_u128(7))
    }

    async fn responses(generated: usize, retrieved: usize) -> Responses {
        let (g, _) = key_pairs(generated).await;
        let (_, r) = key_pairs(retrieved).await;
        Responses::new(g, r)
    }

    #[test]
    fn tally_counts_nothing_for_no_requests() {
        assert_eq!(tally(&[]), (0, 0));
    }

    #[test]
    fn tally_separates_the_two_kinds() {
        let requests = vec![
            Request::generate_under(d()),
            Request::retrieve_under(vec![1], d(), ks()),
            Request::generate_under(d()),
            Request::retrieve_under(vec![2], d(), ks()),
            Request::generate_under(d()),
        ];
        assert_eq!(tally(&requests), (3, 2));
    }

    /// The public constructors render the descriptor themselves, from the
    /// context, so a request cannot carry one that disagrees with its own
    /// context (ADR-0004, decision 4) — and rendering through an
    /// `AeadContext` preserves the context's structured identity.
    #[test]
    fn a_public_request_renders_its_descriptor_from_its_context() {
        let context = crate::nonempty!("users/email").with(7u64);
        let expected = Descriptor::of(context);
        match Request::generate_data_key(context).into_kind() {
            RequestKind::GenerateDataKey { descriptor } => assert_eq!(descriptor, expected),
            RequestKind::RetrieveDataKey { .. } => panic!("expected a generate request"),
        }
        match Request::retrieve_data_key(vec![1], context, ks()).into_kind() {
            RequestKind::RetrieveDataKey { descriptor, .. } => assert_eq!(descriptor, expected),
            RequestKind::GenerateDataKey { .. } => panic!("expected a retrieve request"),
        }
    }

    /// A plain `IntoContext` type, as an `AeadContext` target declares.
    #[derive(Clone)]
    struct Tenant(String);
    impl MaybeEmpty for Tenant {
        fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
    }
    impl<'a> IntoContext<'a> for Tenant {
        fn into_context(self) -> ContextPiece<'a> {
            self.0.into_context()
        }
    }

    /// A descriptor is rendered from the context's parts, so the context a
    /// `StackCipherText` seals under — any `IntoContext` type, as an
    /// `AeadContext` — can request the data key it seals with. Requiring a
    /// `CallerContext` here would shut an `AeadContext` target out of the
    /// `Pending::request` extension point for no reason.
    #[test]
    fn an_aead_only_context_can_request_a_data_key() {
        let context = NonEmpty::new(Tenant("acme".into())).unwrap();
        match Request::generate_data_key(context.clone()).into_kind() {
            RequestKind::GenerateDataKey { descriptor } => assert_eq!(descriptor.as_str(), "acme"),
            RequestKind::RetrieveDataKey { .. } => panic!("expected a generate request"),
        }
        match Request::retrieve_data_key(vec![1], context, ks()).into_kind() {
            RequestKind::RetrieveDataKey { descriptor, .. } => {
                assert_eq!(descriptor.as_str(), "acme")
            }
            RequestKind::GenerateDataKey { .. } => panic!("expected a retrieve request"),
        }
    }

    #[test]
    fn a_generate_request_carries_its_descriptor() {
        match Request::generate_under(d()).into_kind() {
            RequestKind::GenerateDataKey { descriptor } => assert_eq!(descriptor, d()),
            RequestKind::RetrieveDataKey { .. } => panic!("expected a generate request"),
        }
    }

    #[test]
    fn a_retrieve_request_carries_its_key_id_keyset_and_descriptor() {
        let request = Request::retrieve_under(vec![7, 8, 9], d(), ks());
        match request.into_kind() {
            RequestKind::RetrieveDataKey {
                key_id,
                descriptor,
                keyset_id,
                v1_leaf,
            } => {
                assert!(
                    !v1_leaf,
                    "a request built from parts is not a format-1 leaf"
                );
                assert_eq!(keyset_id, ks());
                assert_eq!(key_id, vec![7, 8, 9]);
                assert_eq!(descriptor, d());
            }
            RequestKind::GenerateDataKey { .. } => panic!("expected a retrieve request"),
        }
    }

    #[tokio::test]
    async fn generated_keys_come_back_in_request_order() {
        let (generated, _) = key_pairs(3).await;
        let ids: Vec<Vec<u8>> = generated
            .iter()
            .map(|key| key.key_id.as_bytes().to_vec())
            .collect();
        let mut responses = Responses::new(generated, Vec::new());

        for id in ids {
            assert_eq!(
                responses.next_generated_key().unwrap().key_id.as_bytes(),
                id
            );
        }
    }

    #[tokio::test]
    async fn retrieved_keys_come_back_in_request_order() {
        let (_, retrieved) = key_pairs(3).await;
        // A retrieved key is material, not a handle — its own bytes are the
        // only thing that identifies it in order.
        let material: Vec<[u8; 32]> = retrieved
            .iter()
            .map(|key| key.clone().risky_unwrap())
            .collect();
        let mut responses = Responses::new(Vec::new(), retrieved);

        for bytes in material {
            assert_eq!(
                responses.next_retrieved_key().unwrap().risky_unwrap(),
                bytes
            );
        }
    }

    #[tokio::test]
    async fn drawing_a_generated_key_past_the_end_is_a_response_shape_error() {
        let mut responses = responses(1, 0).await;
        assert!(responses.next_generated_key().is_ok());
        assert!(matches!(
            responses.next_generated_key(),
            Err(Error::ResponseShape)
        ));
    }

    #[tokio::test]
    async fn drawing_a_retrieved_key_past_the_end_is_a_response_shape_error() {
        let mut responses = responses(0, 1).await;
        assert!(responses.next_retrieved_key().is_ok());
        assert!(matches!(
            responses.next_retrieved_key(),
            Err(Error::ResponseShape)
        ));
    }

    /// The kinds are separate queues: a generate response can never be drawn
    /// as a retrieve response, however many of the other kind are waiting.
    #[tokio::test]
    async fn the_two_kinds_do_not_substitute_for_each_other() {
        let mut generated_only = responses(2, 0).await;
        assert!(matches!(
            generated_only.next_retrieved_key(),
            Err(Error::ResponseShape)
        ));

        let mut retrieved_only = responses(0, 2).await;
        assert!(matches!(
            retrieved_only.next_generated_key(),
            Err(Error::ResponseShape)
        ));
    }

    #[tokio::test]
    async fn split_front_takes_exactly_what_was_asked_for() {
        let mut responses = responses(3, 2).await;
        let own = responses.split_front(2, 1).unwrap();

        assert_eq!((own.generated.len(), own.retrieved.len()), (2, 1));
        assert_eq!(
            (responses.generated.len(), responses.retrieved.len()),
            (1, 1)
        );
    }

    /// The scoping guarantee: a fulfilment's view holds *its* responses, and
    /// the responses left behind are the ones its siblings will draw.
    #[tokio::test]
    async fn split_front_takes_from_the_front_and_leaves_the_rest() {
        let (generated, _) = key_pairs(3).await;
        let ids: Vec<Vec<u8>> = generated
            .iter()
            .map(|key| key.key_id.as_bytes().to_vec())
            .collect();
        let mut responses = Responses::new(generated, Vec::new());

        let mut first = responses.split_front(1, 0).unwrap();
        assert_eq!(
            first.next_generated_key().unwrap().key_id.as_bytes(),
            ids[0]
        );

        let mut rest = responses.split_front(2, 0).unwrap();
        assert_eq!(rest.next_generated_key().unwrap().key_id.as_bytes(), ids[1]);
        assert_eq!(rest.next_generated_key().unwrap().key_id.as_bytes(), ids[2]);
    }

    #[tokio::test]
    async fn split_front_of_nothing_yields_an_empty_view() {
        let mut responses = responses(2, 2).await;
        let mut own = responses.split_front(0, 0).unwrap();

        assert!(matches!(
            own.next_generated_key(),
            Err(Error::ResponseShape)
        ));
        assert!(matches!(
            own.next_retrieved_key(),
            Err(Error::ResponseShape)
        ));
        // The siblings' responses are untouched.
        assert_eq!(
            (responses.generated.len(), responses.retrieved.len()),
            (2, 2)
        );
    }

    #[tokio::test]
    async fn split_front_short_of_generated_responses_errors_without_consuming() {
        let mut responses = responses(1, 0).await;
        assert!(matches!(
            responses.split_front(2, 0),
            Err(Error::ResponseShape)
        ));
        assert_eq!(responses.generated.len(), 1);
    }

    #[tokio::test]
    async fn split_front_short_of_retrieved_responses_errors_without_consuming() {
        let mut responses = responses(2, 1).await;
        assert!(matches!(
            responses.split_front(2, 2),
            Err(Error::ResponseShape)
        ));
        // Neither queue was drained: the check happens before the split.
        assert_eq!(
            (responses.generated.len(), responses.retrieved.len()),
            (2, 1)
        );
    }

    #[tokio::test]
    async fn draining_consumes_every_response_of_that_kind() {
        let mut responses = responses(3, 2).await;

        assert_eq!(responses.drain_generated().count(), 3);
        assert_eq!(responses.retrieved.len(), 2);
        assert_eq!(responses.drain_retrieved().count(), 2);

        assert!(matches!(
            responses.next_generated_key(),
            Err(Error::ResponseShape)
        ));
        assert!(matches!(
            responses.next_retrieved_key(),
            Err(Error::ResponseShape)
        ));
    }
}
