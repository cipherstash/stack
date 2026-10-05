//! Fixtures shared by the integration test binaries.
//!
//! Everything runs on [`FakeKeysetRegistry`], which gives each keyset its
//! own provider — its own index key and its own key material — so a test
//! that crosses keysets is testing something. The provider counts *calls*,
//! not keys: the design's whole claim is that an assembly of any size
//! settles in one batched call per request kind, and the tests hold it to
//! that.
//!
//! The fake provider is `Bound`, so retrieving a key under a descriptor it
//! was not minted with fails here exactly as it would at ZeroKMS. Tests
//! assert against the bindings it records, never against a stub's
//! (non-)enforcement.

// Each test binary uses a subset of these.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;

use stack_encrypt::registry::fake::{Calls, FakeKeysetRegistry, FakeProvider};
use stack_encrypt::{StackCipher, StackCipherBuilder};

/// The name the secondary keyset is registered under, for tests that cross
/// keysets.
pub const OTHER_KEYSET: &str = "other";

/// A cipher over the deterministic fake registry. The fake index key is
/// deterministic per keyset, so two separately built ciphers stand in for
/// the write path and a query path in another process.
pub async fn stack_cipher() -> StackCipher<FakeKeysetRegistry> {
    cipher_over(FakeKeysetRegistry::new()).await
}

/// A cipher over the fake registry, with its counter of keyset lookups
/// (`resolve` calls), zeroed once the cipher has loaded its default keyset.
pub async fn loads_counting_cipher() -> (StackCipher<FakeKeysetRegistry>, Arc<AtomicUsize>) {
    let registry = FakeKeysetRegistry::new();
    let loads = registry.resolves();
    let cipher = cipher_over(registry).await;
    loads.store(0, AtomicOrdering::SeqCst);
    (cipher, loads)
}

/// A cipher over `registry`.
pub async fn cipher_over(registry: FakeKeysetRegistry) -> StackCipher<FakeKeysetRegistry> {
    StackCipherBuilder::new()
        .registry(registry)
        .init()
        .await
        .expect("build cipher")
}

/// A cipher and the provider serving its default keyset, which counts the
/// batched calls it serves and records every binding it is sent.
///
/// One handle for both: the provider *is* the counter and the recorder, so
/// there is nothing to keep in step.
pub async fn counting_cipher() -> (StackCipher<FakeKeysetRegistry>, FakeProvider) {
    let registry = FakeKeysetRegistry::new();
    let (_, provider) = registry.default_keyset();
    (cipher_over(registry).await, provider)
}

/// Alias for [`counting_cipher`]: the same fixture, named for the tests
/// that care about descriptors rather than call counts.
pub async fn recording_cipher() -> (StackCipher<FakeKeysetRegistry>, FakeProvider) {
    counting_cipher().await
}

/// A cipher, its default keyset's provider, and the second keyset's id and
/// provider — for tests that cross keysets.
pub async fn two_keyset_cipher() -> (
    StackCipher<FakeKeysetRegistry>,
    FakeProvider,
    stack_encrypt::KeysetId,
    FakeProvider,
) {
    let registry = FakeKeysetRegistry::new();
    let (_, default) = registry.default_keyset();
    let (other_id, other) = registry.keyset(OTHER_KEYSET).expect("registered keyset");
    (cipher_over(registry).await, default, other_id, other)
}

/// Every binding sent to `provider`, grouped by call.
pub fn sent(provider: &FakeProvider) -> Calls {
    provider.calls()
}
