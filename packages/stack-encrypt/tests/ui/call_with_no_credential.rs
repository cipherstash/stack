//! A key source that takes a credential with each call
//! (`CredentialKeySource`) has no request without one. A call through it
//! is therefore not a future until it has a credential: a request handler
//! that forgets `.with_credential(..)` does not compile. The test source
//! `FakeCredentialKeySource` is such a key source, and so is a ZeroKMS
//! client over an OIDC strategy built with `credential_per_call`. An
//! audited call, a value sealed under a context and a zipped call are
//! refused the same way.

use stack_auth::{CredentialPerCall, OidcFederationStrategy};
use stack_encrypt::kms::{FakeCredentialKeySource, StackKms};
use stack_encrypt::{
    nonempty, AuditMetadata, Ciphertext, EncryptInto, KeysetCipher, Pending, StackCipherText,
};

type OverOidc = StackKms<OidcFederationStrategy<CredentialPerCall>>;

async fn over_a_test_source(call: Pending<'_, Ciphertext, FakeCredentialKeySource>) {
    let _ = call.await;
}

async fn over_an_oidc_strategy(call: Pending<'_, Ciphertext, OverOidc>) {
    let _ = call.await;
}

async fn audited(call: Pending<'_, Ciphertext, FakeCredentialKeySource>) {
    let _ = call.audit(AuditMetadata::new()).await;
}

async fn under_a_context(keyset: &KeysetCipher<'_, FakeCredentialKeySource>, email: String) {
    let _ = email
        .encrypt_into_with_context::<StackCipherText, _>(keyset, nonempty!("users/email"))
        .await;
}

async fn zipped(keyset: &KeysetCipher<'_, FakeCredentialKeySource>) {
    let _ = keyset.encrypt(1i64).zip(keyset.encrypt(2i64)).await;
}

fn main() {}
