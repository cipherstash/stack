//! `impl KeysetRegistry for Arc<StackKms>`: the one backend implementation
//! this crate carries.
//!
//! It lives here rather than in `stack-kms` because the orphan rule puts it
//! here — local trait, foreign type — and so it can only be tested here.
//! `stack-kms`'s `test-support` feature exports the in-memory
//! `ZeroKMSConnection` that makes that possible without a network.
//!
//! What is worth pinning is the *shape of the answer*, because the cache
//! above treats the three outcomes differently: `Ok(Some(_))` is an answer,
//! `Ok(None)` is also an answer (a definite "no such keyset", which unbinds
//! a cached name), and `Err(_)` is not an answer at all and must leave the
//! cache alone. Collapsing any pair of those is invisible to a type checker.

#![cfg(all(feature = "zerokms", not(target_arch = "wasm32")))]

use std::sync::Arc;

use stack_auth::StaticTokenStrategy;
use stack_encrypt::registry::{KeysetRef, KeysetRegistry};
use stack_encrypt::KeysetId;
use stack_kms::test_connection::{
    load_keyset_response, random_client_key, TestConnection, TestConnectionBuilder, TEST_KEYSET_ID,
};
use stack_kms::{ClientOpts, StackKms};
use zerokms_protocol::{LoadKeysetRequest, ViturRequestError, ViturRequestErrorKind};

type Registry = Arc<StackKms<StaticTokenStrategy, TestConnection>>;

/// A `StackKms` over a stub connection the callback configures. The stub
/// panics on an unstubbed endpoint, so a test that expects exactly one
/// `load_keyset` gets that checked for free.
fn build_kms(callback: impl FnOnce(TestConnectionBuilder) -> TestConnectionBuilder) -> Registry {
    let opts = ClientOpts::new(callback(TestConnectionBuilder::new()));
    Arc::new(
        StackKms::<_, TestConnection>::connect(
            opts,
            StaticTokenStrategy::new("static-token"),
            random_client_key(),
        )
        .expect("connect over a test connection"),
    )
}

fn vitur(kind: ViturRequestErrorKind) -> ViturRequestError {
    ViturRequestError::new(kind, "stubbed", std::io::Error::other("boom"))
}

/// The positive answer, and the two things it must carry: the id ZeroKMS
/// resolved, and a provider that already holds the keyset's index key —
/// loading it eagerly is the point of doing this in one round trip.
#[tokio::test]
async fn a_resolved_keyset_carries_its_id_and_its_index_key() {
    let kms = build_kms(|b| b.add_success_response::<LoadKeysetRequest>(load_keyset_response()));

    let resolved = kms
        .resolve(&KeysetRef::Default)
        .await
        .expect("the stub answers")
        .expect("the default keyset exists");

    assert_eq!(
        resolved.id,
        KeysetId::new(TEST_KEYSET_ID),
        "the id must be the one ZeroKMS resolved, not one this crate invented"
    );
    assert_eq!(
        resolved.name, None,
        "nothing was looked up by name, so the answer carries none"
    );
    // The provider is only useful if it can serve the keyset's index key
    // without another round trip; the stub would panic on a second request.
    let _ = vitaminc_kms::provider::IndexKeyProvider::load_index_key(&resolved.provider)
        .await
        .expect("the index key came back in the same load_keyset call");
}

/// A name selection carries the name it asked under — the cache binds names,
/// and a binding it cannot attribute is a binding it cannot expire.
#[tokio::test]
async fn a_name_selection_carries_the_name_it_asked_under() {
    let kms = build_kms(|b| b.add_success_response::<LoadKeysetRequest>(load_keyset_response()));

    let resolved = kms
        .resolve(&KeysetRef::Name("acme".to_owned()))
        .await
        .expect("the stub answers")
        .expect("the keyset exists");

    assert_eq!(resolved.name.as_deref(), Some("acme"));
}

/// ZeroKMS's 404 is an *answer*: it holds no such keyset. That has to arrive
/// as `Ok(None)` and not as an error, because the cache unbinds a name on the
/// former and leaves it alone on the latter.
#[tokio::test]
async fn a_keyset_zerokms_does_not_hold_is_an_answer_not_a_failure() {
    let kms = build_kms(|b| {
        b.add_failed_response::<LoadKeysetRequest>(vitur(ViturRequestErrorKind::NotFound))
    });

    let answer = kms
        .resolve(&KeysetRef::Name("nope".to_owned()))
        .await
        .expect("a 404 is an answer, so `resolve` must not fail");

    assert!(answer.is_none(), "and the answer is that there is none");
}

/// Everything else is *not* an answer. A refused credential says nothing
/// about whether the keyset exists, so it must not be flattened into
/// `Ok(None)` — that would let a cached name be unbound by a transport
/// hiccup.
#[tokio::test]
async fn a_request_that_got_no_verdict_is_an_error() {
    for kind in [
        ViturRequestErrorKind::Unauthorized,
        ViturRequestErrorKind::Forbidden,
        ViturRequestErrorKind::Other,
    ] {
        let named = format!("{kind:?}");
        let kms = build_kms(|b| b.add_failed_response::<LoadKeysetRequest>(vitur(kind)));
        let result = kms.resolve(&KeysetRef::Name("acme".to_owned())).await;
        assert!(
            result.is_err(),
            "{named} is not an answer about the keyset, got {:?}",
            result.map(|r| r.map(|r| r.id))
        );
    }
}
