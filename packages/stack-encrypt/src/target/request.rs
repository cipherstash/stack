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

use std::collections::VecDeque;

use stack_kms::{DataKey, DataKeyWithTag, Iv};

use crate::Error;

/// One unit of ZeroKMS work a [`Pending`](super::Pending) needs:
/// constructible, otherwise opaque, so new request kinds (a PRF derivation, a
/// keyset override) can be added without breaking implementations.
#[derive(Debug, Clone)]
pub struct Request(RequestKind);

#[derive(Debug, Clone)]
pub(super) enum RequestKind {
    /// Generate one fresh data key under the cipher's keyset.
    GenerateDataKey,
    /// Re-derive the data key identified by `iv` + `tag`.
    RetrieveDataKey { iv: Iv, tag: Vec<u8> },
}

impl Request {
    /// Request one fresh data key (encrypt side).
    pub fn generate_data_key() -> Self {
        Self(RequestKind::GenerateDataKey)
    }

    /// Request re-derivation of the data key identified by `iv` + `tag`
    /// (decrypt side).
    pub fn retrieve_data_key(iv: Iv, tag: Vec<u8>) -> Self {
        Self(RequestKind::RetrieveDataKey { iv, tag })
    }

    /// Consume the request, yielding what it asks for.
    pub(super) fn into_kind(self) -> RequestKind {
        self.0
    }
}

/// How many requests of each kind `requests` holds, as
/// `(generate, retrieve)` — the shape a fulfilment is scoped to.
pub(super) fn tally(requests: &[Request]) -> (usize, usize) {
    let (mut generate, mut retrieve) = (0usize, 0usize);
    for request in requests {
        match request.0 {
            RequestKind::GenerateDataKey => generate += 1,
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
    generated: VecDeque<DataKeyWithTag>,
    retrieved: VecDeque<DataKey>,
}

impl Responses {
    /// The full response set of one batched dispatch, in request order.
    pub(super) fn new(generated: Vec<DataKeyWithTag>, retrieved: Vec<DataKey>) -> Self {
        Self {
            generated: generated.into(),
            retrieved: retrieved.into(),
        }
    }

    /// The next generated data key, in [`Request::generate_data_key`] order.
    pub fn next_generated_key(&mut self) -> Result<DataKeyWithTag, Error> {
        self.generated.pop_front().ok_or(Error::ResponseShape)
    }

    /// The next retrieved data key, in [`Request::retrieve_data_key`] order.
    pub fn next_retrieved_key(&mut self) -> Result<DataKey, Error> {
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

    pub(crate) fn drain_generated(&mut self) -> impl Iterator<Item = DataKeyWithTag> + '_ {
        self.generated.drain(..)
    }

    pub(crate) fn drain_retrieved(&mut self) -> impl Iterator<Item = DataKey> + '_ {
        self.retrieved.drain(..)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::borrow::Cow;

    use stack_kms::{DataKeySource, FakeDataKeySource, GenerateKeyPayload, RetrieveKeyPayload};

    use super::*;

    /// `n` real generated keys, plus the retrieved keys for the same `n`
    /// (`iv`, `tag`) pairs — the stub round-trips, which is all these tests
    /// need from it.
    async fn key_pairs(n: usize) -> (Vec<DataKeyWithTag>, Vec<DataKey>) {
        let kms = FakeDataKeySource::new();
        let generated = kms
            .generate_keys(
                (0..n)
                    .map(|_| GenerateKeyPayload::new("", Cow::Owned(Vec::new())))
                    .collect(),
                None,
                None,
            )
            .await
            .unwrap();
        let retrieved = kms
            .retrieve_keys(
                generated
                    .iter()
                    .map(|key| RetrieveKeyPayload::new(key.key.iv, "", &key.tag))
                    .collect(),
                None,
                None,
            )
            .await
            .unwrap();
        (generated, retrieved)
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
            Request::generate_data_key(),
            Request::retrieve_data_key(Iv::default(), vec![1]),
            Request::generate_data_key(),
            Request::retrieve_data_key(Iv::default(), vec![2]),
            Request::generate_data_key(),
        ];
        assert_eq!(tally(&requests), (3, 2));
    }

    #[test]
    fn a_generate_request_is_a_generate_kind() {
        assert!(matches!(
            Request::generate_data_key().into_kind(),
            RequestKind::GenerateDataKey
        ));
    }

    #[test]
    fn a_retrieve_request_carries_its_iv_and_tag() {
        let request = Request::retrieve_data_key(Iv::default(), vec![7, 8, 9]);
        match request.into_kind() {
            RequestKind::RetrieveDataKey { iv, tag } => {
                assert_eq!(iv, Iv::default());
                assert_eq!(tag, vec![7, 8, 9]);
            }
            RequestKind::GenerateDataKey => panic!("expected a retrieve request"),
        }
    }

    #[tokio::test]
    async fn generated_keys_come_back_in_request_order() {
        let (generated, _) = key_pairs(3).await;
        let tags: Vec<Vec<u8>> = generated.iter().map(|key| key.tag.clone()).collect();
        let mut responses = Responses::new(generated, Vec::new());

        for tag in tags {
            assert_eq!(responses.next_generated_key().unwrap().tag, tag);
        }
    }

    #[tokio::test]
    async fn retrieved_keys_come_back_in_request_order() {
        let (_, retrieved) = key_pairs(3).await;
        let ivs: Vec<Iv> = retrieved.iter().map(|key| key.iv).collect();
        let mut responses = Responses::new(Vec::new(), retrieved);

        for iv in ivs {
            assert_eq!(responses.next_retrieved_key().unwrap().iv, iv);
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
        let tags: Vec<Vec<u8>> = generated.iter().map(|key| key.tag.clone()).collect();
        let mut responses = Responses::new(generated, Vec::new());

        let mut first = responses.split_front(1, 0).unwrap();
        assert_eq!(first.next_generated_key().unwrap().tag, tags[0]);

        let mut rest = responses.split_front(2, 0).unwrap();
        assert_eq!(rest.next_generated_key().unwrap().tag, tags[1]);
        assert_eq!(rest.next_generated_key().unwrap().tag, tags[2]);
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
