//! The two kinds of OIDC strategy, and the calls that must compile over
//! each.
//!
//! Which kind takes a credential is stack-auth's rule, held by its two
//! strategy traits. Stack Encrypt adds no check of its own. These cases
//! show that the rule reaches a call, through Stack KMS.
//!
//! A strategy with a provider asks the provider who each request is for.
//! A call through it is awaited as it is: a pending, an audited call, a
//! value sealed under a context and a zipped call. It has no
//! `with_credential`, and
//! `tests/ui/credential_on_a_source_with_its_own_identity.rs` holds that
//! refusal.
//!
//! A strategy built with `credential_per_call` has no provider. A call
//! through it is awaited once it has a credential, and
//! `tests/ui/call_with_no_credential.rs` holds the refusal of a call with
//! none.
use stack_auth::{CredentialPerCall, OidcFederationStrategy, OidcProvider};
use stack_encrypt::kms::{SecretToken, StackKms};
use stack_encrypt::{
    nonempty, AuditMetadata, Ciphertext, EncryptInto, Error, Pending, StackCipher,
    StackCipherText,
};

type WithProvider<P> = StackKms<OidcFederationStrategy<P>>;
type PerCall = StackKms<OidcFederationStrategy<CredentialPerCall>>;

async fn with_a_provider<P: OidcProvider + 'static>(
    cipher: &StackCipher<WithProvider<P>>,
) -> Result<(), Error> {
    let keyset = cipher.default_keyset();
    let email = String::from("bob@example.com");
    let seal = || -> Pending<'_, Ciphertext, WithProvider<P>> { keyset.encrypt(1i64) };

    let stored = seal().await?;
    let _: i64 = keyset.decrypt(stored).await?;
    let _ = seal().audit(AuditMetadata::new()).await?;
    let _: StackCipherText = email
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await?;
    let _ = seal().zip(seal()).await?;
    Ok(())
}

async fn with_a_credential_per_call(cipher: &StackCipher<PerCall>) -> Result<(), Error> {
    let keyset = cipher.default_keyset();
    let email = String::from("bob@example.com");
    let jwt = || SecretToken::new("header.payload.signature");
    let seal = || -> Pending<'_, Ciphertext, PerCall> { keyset.encrypt(1i64) };

    let stored = seal().with_credential(jwt()).await?;
    let _: i64 = keyset.decrypt(stored).with_credential(jwt()).await?;
    let _ = seal()
        .audit(AuditMetadata::new())
        .with_credential(jwt())
        .await?;
    let _: StackCipherText = email
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .with_credential(jwt())
        .await?;
    let _ = seal().zip(seal()).with_credential(jwt()).await?;
    Ok(())
}

fn main() {}
