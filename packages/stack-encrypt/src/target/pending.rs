//! [`Pending`]: the request carrier [`StackCipher`] hands back from
//! [`EncryptedFrom`](super::EncryptedFrom) / [`DecryptedFrom`](super::DecryptedFrom),
//! and the single place the target layer talks to ZeroKMS.
//!
//! A `Pending` is built synchronously and settled once. Combining pendings
//! merges their [`Request`]s without doing any I/O; awaiting the combined
//! result issues one batched ZeroKMS call per request kind
//! ([`dispatch`]) and then runs each fulfilment over exactly the
//! [`Responses`] its own requests asked for.

use std::borrow::Cow;
use std::future::{Future, IntoFuture};
use std::pin::Pin;

use stack_kms::{DataKeySource, GenerateKeyPayload, Iv, MaybeSend, RetrieveKeyPayload};

use super::request::{tally, Request, RequestKind, Responses};
use crate::{Error, StackCipher};

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
pub struct Pending<'a, T, K> {
    cipher: &'a StackCipher<K>,
    requests: Vec<Request>,
    fulfil: FulfilBox<'a, T>,
}

impl<'a, T: 'a, K> Pending<'a, T, K> {
    /// A pending with no requests: `result` was fully derived during the
    /// synchronous build. Awaiting it does no I/O.
    pub fn ready(cipher: &'a StackCipher<K>, result: Result<T, Error>) -> Self
    where
        T: MaybeSend,
    {
        Self {
            cipher,
            requests: Vec::new(),
            fulfil: Box::new(move |_| result),
        }
    }

    /// A pending whose value needs ZeroKMS responses. `fulfil` runs after the
    /// batched call, scoped to exactly the responses `requests` asked for —
    /// drawing more (or another kind) is [`Error::ResponseShape`], and can
    /// never consume a sibling pending's responses.
    pub fn request<F>(cipher: &'a StackCipher<K>, requests: Vec<Request>, fulfil: F) -> Self
    where
        F: FnOnce(&mut Responses) -> Result<T, Error> + MaybeSend + 'a,
    {
        let (generated, retrieved) = tally(&requests);
        Self {
            cipher,
            requests,
            fulfil: Box::new(move |responses| {
                let mut own = responses.split_front(generated, retrieved)?;
                fulfil(&mut own)
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
            requests: self.requests,
            fulfil: Box::new(move |responses| fulfil(responses).map(f)),
        }
    }

    /// Merge two pendings into one resolving to the pair. Their requests
    /// concatenate — awaiting the result is still one batched call per
    /// request kind. Both must come from the same cipher.
    pub fn zip<U: 'a>(mut self, other: Pending<'a, U, K>) -> Pending<'a, (T, U), K> {
        debug_assert!(
            std::ptr::eq(self.cipher, other.cipher),
            "zipped pendings must be built from the same cipher"
        );
        self.requests.extend(other.requests);
        let first = self.fulfil;
        let second = other.fulfil;
        Pending {
            cipher: self.cipher,
            requests: self.requests,
            fulfil: Box::new(move |responses| Ok((first(responses)?, second(responses)?))),
        }
    }

    /// Merge any number of same-typed pendings into one resolving to the
    /// `Vec` — [`zip`](Self::zip) at scale, used by the `Vec<T>`
    /// implementations to make a whole column one batched call.
    pub fn all(
        cipher: &'a StackCipher<K>,
        items: Vec<Pending<'a, T, K>>,
    ) -> Pending<'a, Vec<T>, K> {
        let mut requests = Vec::new();
        let mut fulfils = Vec::with_capacity(items.len());
        for item in items {
            debug_assert!(
                std::ptr::eq(cipher, item.cipher),
                "merged pendings must be built from the same cipher"
            );
            requests.extend(item.requests);
            fulfils.push(item.fulfil);
        }
        Pending {
            cipher,
            requests,
            fulfil: Box::new(move |responses| {
                fulfils
                    .into_iter()
                    .map(|fulfil| fulfil(responses))
                    .collect()
            }),
        }
    }
}

impl<'a, T: 'a, K> IntoFuture for Pending<'a, T, K>
where
    K: DataKeySource + Sync,
{
    type Output = Result<T, Error>;
    type IntoFuture = PendingFuture<'a, T>;

    /// The only place I/O happens: one batched ZeroKMS call per request kind
    /// (none at all for an all-[`ready`](Pending::ready) assembly), then the
    /// fulfilments shape the responses.
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut responses = dispatch(self.cipher, self.requests).await?;
            (self.fulfil)(&mut responses)
        })
    }
}

/// Issue the batched ZeroKMS calls for `requests`: at most one
/// `generate_keys` and one `retrieve_keys`, whatever the request count. When
/// ZeroKMS grows a combined operation (data keys + PRF derivations in one
/// round-trip), this is the one place that changes.
async fn dispatch<K: DataKeySource>(
    cipher: &StackCipher<K>,
    requests: Vec<Request>,
) -> Result<Responses, Error> {
    let mut generate = 0usize;
    let mut retrieves: Vec<(Iv, Vec<u8>)> = Vec::new();
    for request in requests {
        match request.into_kind() {
            RequestKind::GenerateDataKey => generate += 1,
            RequestKind::RetrieveDataKey { iv, tag } => retrieves.push((iv, tag)),
        }
    }

    let generated = if generate == 0 {
        Vec::new()
    } else {
        // Empty descriptor + empty context for every leaf — see the
        // wire-format note in the cipher module docs.
        let payloads: Vec<GenerateKeyPayload<'_>> = (0..generate)
            .map(|_| GenerateKeyPayload::new("", Cow::Owned(Vec::new())))
            .collect();
        let keys = cipher
            .kms()
            .generate_keys(payloads, Some(cipher.keyset_id()), None)
            .await?;
        if keys.len() != generate {
            return Err(Error::KeyCountMismatch {
                expected: generate,
                received: keys.len(),
            });
        }
        keys
    };

    let retrieved = if retrieves.is_empty() {
        Vec::new()
    } else {
        let payloads: Vec<RetrieveKeyPayload<'_>> = retrieves
            .iter()
            .map(|(iv, tag)| RetrieveKeyPayload::new(*iv, "", tag))
            .collect();
        let expected = payloads.len();
        let keys = cipher
            .kms()
            .retrieve_keys(payloads, Some(cipher.keyset_id()), None)
            .await?;
        if keys.len() != expected {
            return Err(Error::KeyCountMismatch {
                expected,
                received: keys.len(),
            });
        }
        keys
    };

    Ok(Responses::new(generated, retrieved))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};

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
    }

    impl CountingSource {
        fn generate_calls(&self) -> usize {
            self.generate_calls.load(Ordering::Relaxed)
        }

        fn retrieve_calls(&self) -> usize {
            self.retrieve_calls.load(Ordering::Relaxed)
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

    async fn cipher() -> StackCipher<CountingSource> {
        StackCipher::builder()
            .kms(CountingSource::default())
            .init()
            .await
            .unwrap()
    }

    /// A pending that asks for `n` data keys and resolves to their tags.
    fn generating<'a>(
        cipher: &'a StackCipher<CountingSource>,
        n: usize,
    ) -> Pending<'a, Vec<Vec<u8>>, CountingSource> {
        let requests = std::iter::repeat_with(Request::generate_data_key)
            .take(n)
            .collect();
        Pending::request(cipher, requests, move |responses| {
            (0..n)
                .map(|_| responses.next_generated_key().map(|key| key.tag))
                .collect()
        })
    }

    #[tokio::test]
    async fn a_ready_pending_resolves_without_any_io() {
        let cipher = cipher().await;
        let value: u32 = Pending::ready(&cipher, Ok(7)).await.unwrap();

        assert_eq!(value, 7);
        assert_eq!(cipher.kms().generate_calls(), 0);
        assert_eq!(cipher.kms().retrieve_calls(), 0);
    }

    #[tokio::test]
    async fn a_ready_pending_propagates_its_error() {
        let cipher = cipher().await;
        let result: Result<u32, Error> = Pending::ready(&cipher, Err(Error::EmptyContext)).await;

        assert!(matches!(result, Err(Error::EmptyContext)));
        assert_eq!(cipher.kms().generate_calls(), 0);
    }

    #[tokio::test]
    async fn map_transforms_the_resolved_value() {
        let cipher = cipher().await;
        let value = Pending::ready(&cipher, Ok(7u32))
            .map(|v| v * 3)
            .await
            .unwrap();

        assert_eq!(value, 21);
    }

    #[tokio::test]
    async fn map_does_not_run_on_an_error() {
        let cipher = cipher().await;
        let result: Result<u32, Error> = Pending::ready(&cipher, Err(Error::EmptyContext))
            .map(|_: u32| panic!("map must not run on an error"))
            .await;

        assert!(matches!(result, Err(Error::EmptyContext)));
    }

    #[tokio::test]
    async fn map_carries_the_requests_through() {
        let cipher = cipher().await;
        let tags = generating(&cipher, 3).map(|tags| tags.len()).await.unwrap();

        assert_eq!(tags, 3);
        assert_eq!(cipher.kms().generate_calls(), 1);
    }

    #[tokio::test]
    async fn one_pending_asking_for_many_keys_is_one_call() {
        let cipher = cipher().await;
        let tags = generating(&cipher, 5).await.unwrap();

        assert_eq!(tags.len(), 5);
        assert_eq!(cipher.kms().generate_calls(), 1);
    }

    #[tokio::test]
    async fn zip_merges_requests_into_one_call() {
        let cipher = cipher().await;
        let (left, right) = generating(&cipher, 2)
            .zip(generating(&cipher, 3))
            .await
            .unwrap();

        assert_eq!((left.len(), right.len()), (2, 3));
        assert_eq!(cipher.kms().generate_calls(), 1);
    }

    /// The scoping guarantee at the `Pending` level: zipped fulfilments draw
    /// disjoint response slices, in build order.
    #[tokio::test]
    async fn zipped_fulfilments_never_share_key_material() {
        let cipher = cipher().await;
        let (left, right) = generating(&cipher, 2)
            .zip(generating(&cipher, 2))
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

        assert_eq!(pair, (1, "two"));
        assert_eq!(cipher.kms().generate_calls(), 0);
    }

    #[tokio::test]
    async fn zip_propagates_an_error_from_either_side() {
        let cipher = cipher().await;
        let result = Pending::ready(&cipher, Err(Error::EmptyContext))
            .zip(Pending::ready(&cipher, Ok(1u32)))
            .await;
        assert!(matches!(result, Err::<(u32, u32), _>(Error::EmptyContext)));

        let result = Pending::ready(&cipher, Ok(1u32))
            .zip(Pending::ready(&cipher, Err(Error::EmptyContext)))
            .await;
        assert!(matches!(result, Err::<(u32, u32), _>(Error::EmptyContext)));
    }

    #[tokio::test]
    async fn all_merges_a_column_into_one_call_preserving_order() {
        let cipher = cipher().await;
        let items = (0..5).map(|_| generating(&cipher, 1)).collect();
        let column = Pending::all(&cipher, items).await.unwrap();

        assert_eq!(column.len(), 5);
        assert_eq!(cipher.kms().generate_calls(), 1);

        // Every row drew its own key.
        let mut tags: Vec<&Vec<u8>> = column.iter().flatten().collect();
        tags.sort();
        tags.dedup();
        assert_eq!(tags.len(), 5);
    }

    #[tokio::test]
    async fn all_of_nothing_resolves_empty_without_io() {
        let cipher = cipher().await;
        let column: Vec<u32> = Pending::all(&cipher, Vec::new()).await.unwrap();

        assert!(column.is_empty());
        assert_eq!(cipher.kms().generate_calls(), 0);
    }

    #[tokio::test]
    async fn all_propagates_the_first_error() {
        let cipher = cipher().await;
        let items = vec![
            Pending::ready(&cipher, Ok(1u32)),
            Pending::ready(&cipher, Err(Error::EmptyContext)),
        ];
        let result = Pending::all(&cipher, items).await;

        assert!(matches!(result, Err::<Vec<u32>, _>(Error::EmptyContext)));
    }

    /// Over-drawing is the fulfilment's own error, not a stolen sibling key:
    /// the second pending still resolves to the key it asked for.
    #[tokio::test]
    async fn over_drawing_responses_is_a_response_shape_error() {
        let cipher = cipher().await;
        let greedy: Pending<'_, Vec<u8>, _> =
            Pending::request(&cipher, vec![Request::generate_data_key()], |responses| {
                let _ = responses.next_generated_key()?;
                // One request, two draws.
                responses.next_generated_key().map(|key| key.tag)
            });
        let result = greedy.zip(generating(&cipher, 1)).await;

        assert!(matches!(
            result,
            Err::<(Vec<u8>, Vec<Vec<u8>>), _>(Error::ResponseShape)
        ));
    }

    /// A pending that under-draws leaves its unused responses behind rather
    /// than shifting every sibling's slice.
    #[tokio::test]
    async fn under_drawing_does_not_shift_a_siblings_responses() {
        let cipher = cipher().await;
        let lazy: Pending<'_, (), _> =
            Pending::request(&cipher, vec![Request::generate_data_key()], |_| Ok(()));
        let ((), tags) = lazy.zip(generating(&cipher, 1)).await.unwrap();

        assert_eq!(tags.len(), 1);
        assert_eq!(cipher.kms().generate_calls(), 1);
    }

    #[tokio::test]
    async fn a_pending_with_no_requests_dispatches_nothing() {
        let cipher = cipher().await;
        let value: u32 = Pending::request(&cipher, Vec::new(), |_| Ok(9))
            .await
            .unwrap();

        assert_eq!(value, 9);
        assert_eq!(cipher.kms().generate_calls(), 0);
        assert_eq!(cipher.kms().retrieve_calls(), 0);
    }

    /// A pending that asks for `n` data keys and resolves to the `(iv, tag)`
    /// pairs needed to retrieve them again.
    fn generating_pairs(
        cipher: &StackCipher<CountingSource>,
        n: usize,
    ) -> Pending<'_, Vec<(Iv, Vec<u8>)>, CountingSource> {
        let requests = std::iter::repeat_with(Request::generate_data_key)
            .take(n)
            .collect();
        Pending::request(cipher, requests, move |responses| {
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
        let pairs = generating_pairs(&cipher, 2).await.unwrap();
        assert_eq!(cipher.kms().generate_calls(), 1);

        let requests: Vec<Request> = pairs
            .iter()
            .map(|(iv, tag)| Request::retrieve_data_key(*iv, tag.clone()))
            .collect();
        let retrieve: Pending<'_, usize, _> = Pending::request(&cipher, requests, |responses| {
            Ok(responses.drain_retrieved().count())
        });
        let (count, fresh) = retrieve.zip(generating(&cipher, 1)).await.unwrap();

        assert_eq!(count, 2);
        assert_eq!(fresh.len(), 1);
        assert_eq!(cipher.kms().generate_calls(), 2);
        assert_eq!(cipher.kms().retrieve_calls(), 1);
    }
}
