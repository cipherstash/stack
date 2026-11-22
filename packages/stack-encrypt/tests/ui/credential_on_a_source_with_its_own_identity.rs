//! A credential is passed only to a key source that sends it with the
//! request (`CredentialKeySource`). `DeterministicSource` makes every
//! request as itself, and so does a ZeroKMS client over an access key. A
//! call through either has no `with_credential`: the credential cannot be
//! accepted and then ignored.
//!
//! A ZeroKMS client over an OIDC strategy with a provider is the same. The
//! rule is stack-auth's: such a strategy has no method that takes a JWT
//! from its caller. Stack Encrypt adds no check of its own, and this case
//! shows that the rule reaches a call.

use stack_auth::{AccessKeyStrategy, OidcFederationStrategy, OidcProvider};
use stack_encrypt::kms::{DeterministicSource, SecretToken, StackKms};
use stack_encrypt::{Ciphertext, Pending};

fn over_a_test_source(call: Pending<'_, Ciphertext, DeterministicSource>) {
    let _ = call.with_credential(SecretToken::new("alice.jwt"));
}

fn over_an_access_key(call: Pending<'_, Ciphertext, StackKms<AccessKeyStrategy>>) {
    let _ = call.with_credential(SecretToken::new("alice.jwt"));
}

fn over_an_oidc_provider<P: OidcProvider + 'static>(
    call: Pending<'_, Ciphertext, StackKms<OidcFederationStrategy<P>>>,
) {
    let _ = call.with_credential(SecretToken::new("alice.jwt"));
}

fn main() {}
