//! Calls made with a credential: [`WithCredential`], a call whose key
//! requests are sent with one caller's credential.
//!
//! # The case
//!
//! A web server decrypts each row as the end user who signed in, so that
//! ZeroKMS serves and logs every key request as that person. Its auth
//! strategy is a `stack_auth::OidcFederationStrategy`, which exchanges a
//! user's JWT for a ZeroKMS token naming that user. The server has one
//! cipher and many users. Two requests arrive together: Alice's with the
//! JWT `alice.jwt`, and Bob's with `bob.jwt`.
//!
//! The server builds its cipher at startup, with
//! [`StackCipherBuilder::init`](crate::StackCipherBuilder::init), as any
//! program does. At startup there is no user, and the strategy takes a
//! credential with each call. So `init` makes no request.
//!
//! Alice's request handler builds its call as any program does, and then
//! attaches her JWT to it: `keyset.decrypt(stored).with_credential(jwt)`.
//! Every key request that call makes is sent with the token for
//! `alice.jwt`. Hers is the first request, so her call also loads the
//! client's default keyset, with her token. Bob's handler does the same
//! with `bob.jwt`, on the same cipher, at the same time. Its key requests
//! are sent with the token for `bob.jwt`, and it finds the default keyset
//! loaded. Neither handler sets a task-local variable, and the strategy
//! has no callback to read one.
//!
//! [`WithCredential`] has this case as an example that runs.
//!
//! # Attach it last
//!
//! `.with_credential(..)` is the last call before `.await`, as
//! [`.audit(..)`](crate::Pending::audit) is. Merge first
//! ([`zip`](crate::Pending::zip), [`all`](crate::Pending::all)), then
//! attach the credential to the whole call.
//! The result can only be awaited, or audited and then awaited. So one
//! call has one credential, and two credentials never meet.
//!
//! A cipher, a keyset and a call hold no credential. Only the call that is
//! being awaited does.
//!
//! # A call cannot forget it
//!
//! A key source is one of two kinds ([`KeySource`]). One kind has an
//! identity of its own, such as an access key. The other takes a
//! credential with each call, as the server's does here.
//!
//! On the second kind, a call is not a future until it has a credential:
//! `keyset.decrypt(stored).await` does not compile, and
//! `keyset.decrypt(stored).with_credential(jwt).await` does. On the first
//! kind it is the other way round: the call is awaited as it is, and has
//! no `.with_credential(..)`. So a credential is never forgotten, and
//! never ignored.
//!
//! This holds for a call that makes no request too, such as a query term
//! derived under a keyset that is already loaded. The compiler cannot
//! know which calls those are.
//!
//! # What the credential reaches
//!
//! Every request the awaited call makes: one `generate_keys`, one
//! `retrieve_keys` per keyset, and the load of any keyset the call needs
//! that the cipher has not loaded.
//!
//! # What it does not reach
//!
//! A keyset's index key is loaded once and kept for every caller. The load
//! is made with the credential of whichever call needed the keyset first.
//! Search terms are then derived locally and make no request. So the
//! ZeroKMS log shows each data key request under the caller's own
//! credential, and shows each keyset load under the first caller's only.
//!
//! This is a fact about the log, not about access. ZeroKMS grants a keyset
//! to a client, and a cipher has one client, so every caller of the cipher
//! can use the same keysets.

use std::borrow::Cow;
use std::fmt;
use std::future::Future;

use stack_kms::{
    CredentialKeySource, DataKey, DataKeySource, DataKeyWithTag, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, MaybeSend, OwnIdentity, RetrieveKeyPayload, SecretToken,
    UnverifiedContext,
};
use uuid::Uuid;

mod sealed {
    pub trait Sealed<I> {}
}

/// A key source that a cipher can make its key requests through.
///
/// `I` is what a key request needs to say whom it is made as. A key source
/// is one of two kinds, and `I` follows from the kind:
///
/// - [`OwnIdentity`], for a key source with an identity of its own
///   ([`DataKeySource`] and [`IndexKeySource`]). Every request is made as
///   that identity. A call on the cipher is awaited as it is.
/// - [`SecretToken`], for a key source that takes a credential with each
///   call ([`CredentialKeySource`]). Every request is made with the
///   credential of the call it belongs to. A call on the cipher is awaited
///   only after `.with_credential(..)`
///   ([`Pending::with_credential`](crate::Pending::with_credential)).
///
/// You never write `I`. Where it appears, as in
/// [`StackCipherBuilder::init`](crate::StackCipherBuilder::init), the
/// compiler works it out from the key source.
///
/// Sealed: it is implemented for every key source of either kind, and for
/// nothing else. To supply a key source, implement the traits of its kind.
pub trait KeySource<I>: sealed::Sealed<I> {
    /// The identity to load the default keyset as when the cipher is
    /// built, when no caller is present: the key source's own, or `None`
    /// for a key source that takes a credential with each call.
    #[doc(hidden)]
    fn identity_at_init() -> Option<I>;

    /// One `generate_keys` request, made as `identity`.
    #[doc(hidden)]
    fn generate_keys_as(
        &self,
        identity: &I,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> impl Future<Output = Result<Vec<DataKeyWithTag>, stack_kms::Error>> + MaybeSend;

    /// One `retrieve_keys` request, made as `identity`.
    #[doc(hidden)]
    fn retrieve_keys_as(
        &self,
        identity: &I,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> impl Future<Output = Result<Vec<DataKey>, stack_kms::Error>> + MaybeSend;

    /// One `load_index_key` request, made as `identity`.
    #[doc(hidden)]
    fn load_index_key_as(
        &self,
        identity: &I,
        keyset_id: Option<IdentifiedBy>,
    ) -> impl Future<Output = Result<(Uuid, IndexKey), stack_kms::Error>> + MaybeSend;
}

impl<K: DataKeySource + IndexKeySource> sealed::Sealed<OwnIdentity> for K {}

/// A key source with an identity of its own: every request is the plain
/// one.
impl<K: DataKeySource + IndexKeySource> KeySource<OwnIdentity> for K {
    fn identity_at_init() -> Option<OwnIdentity> {
        Some(OwnIdentity)
    }

    fn generate_keys_as(
        &self,
        _identity: &OwnIdentity,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> impl Future<Output = Result<Vec<DataKeyWithTag>, stack_kms::Error>> + MaybeSend {
        self.generate_keys(payloads, keyset_id, unverified_context)
    }

    fn retrieve_keys_as(
        &self,
        _identity: &OwnIdentity,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> impl Future<Output = Result<Vec<DataKey>, stack_kms::Error>> + MaybeSend {
        self.retrieve_keys(payloads, keyset_id, unverified_context)
    }

    fn load_index_key_as(
        &self,
        _identity: &OwnIdentity,
        keyset_id: Option<IdentifiedBy>,
    ) -> impl Future<Output = Result<(Uuid, IndexKey), stack_kms::Error>> + MaybeSend {
        self.load_index_key(keyset_id)
    }
}

impl<K: CredentialKeySource> sealed::Sealed<SecretToken> for K {}

/// A key source that takes a credential with each call: every request is
/// made with the credential of the call. There is no request without one.
impl<K: CredentialKeySource> KeySource<SecretToken> for K {
    fn identity_at_init() -> Option<SecretToken> {
        None
    }

    fn generate_keys_as(
        &self,
        credential: &SecretToken,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> impl Future<Output = Result<Vec<DataKeyWithTag>, stack_kms::Error>> + MaybeSend {
        self.generate_keys_with_credential(credential, payloads, keyset_id, unverified_context)
    }

    fn retrieve_keys_as(
        &self,
        credential: &SecretToken,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> impl Future<Output = Result<Vec<DataKey>, stack_kms::Error>> + MaybeSend {
        self.retrieve_keys_with_credential(credential, payloads, keyset_id, unverified_context)
    }

    fn load_index_key_as(
        &self,
        credential: &SecretToken,
        keyset_id: Option<IdentifiedBy>,
    ) -> impl Future<Output = Result<(Uuid, IndexKey), stack_kms::Error>> + MaybeSend {
        self.load_index_key_with_credential(credential, keyset_id)
    }
}

/// `generate_keys` on `kms`, made as `identity`.
///
/// The three functions here are what the cipher calls, not the trait's
/// methods. Each is one more `async fn` around the request, on purpose: the
/// future of a call is built on the stack and moved to the heap with every
/// byte it does not initialise, so its size and layout decide which stale
/// stack bytes go with it. `tests/heap_hygiene.rs`, and the EQL test crate's
/// file of the same name, watch for plaintext among them. See `dispatch` in
/// `target/pending.rs`.
pub(crate) async fn generate_keys<K: KeySource<I>, I>(
    kms: &K,
    identity: &I,
    payloads: Vec<GenerateKeyPayload<'_>>,
    keyset_id: Option<Uuid>,
    unverified_context: Option<Cow<'_, UnverifiedContext>>,
) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
    kms.generate_keys_as(identity, payloads, keyset_id, unverified_context)
        .await
}

/// `retrieve_keys` on `kms`, made as `identity`.
pub(crate) async fn retrieve_keys<K: KeySource<I>, I>(
    kms: &K,
    identity: &I,
    payloads: Vec<RetrieveKeyPayload<'_>>,
    keyset_id: Option<Uuid>,
    unverified_context: Option<&UnverifiedContext>,
) -> Result<Vec<DataKey>, stack_kms::Error> {
    kms.retrieve_keys_as(identity, payloads, keyset_id, unverified_context)
        .await
}

/// `load_index_key` on `kms`, made as `identity`.
pub(crate) async fn load_index_key<K: KeySource<I>, I>(
    kms: &K,
    identity: &I,
    keyset_id: Option<IdentifiedBy>,
) -> Result<(Uuid, IndexKey), stack_kms::Error> {
    kms.load_index_key_as(identity, keyset_id).await
}

/// A call with one caller's credential: every request that the call makes
/// is sent with it, so ZeroKMS serves and logs the request as that caller.
///
/// A keyset is loaded once for the cipher, and kept. So a call makes that
/// request only when it is the first to need the keyset, and the ZeroKMS
/// log shows the load under that caller alone. See the
/// [module docs](self#what-it-does-not-reach).
///
/// `.with_credential(..)` returns a `WithCredential`. Every call is a
/// [`Pending`](crate::Pending), which has that method. You can await a
/// `WithCredential`, or call `.audit(..)` on it and await that. It has no
/// other method. So attach the credential last, to the whole call.
///
/// The credential is whatever the key source's auth strategy exchanges for
/// a ZeroKMS token. For a `stack_auth::OidcFederationStrategy`, it is a JWT
/// from an identity provider, most often that of the end user who signed
/// in.
///
/// Only a call through a key source that takes a credential with each
/// call has the method ([`CredentialKeySource`]), and such a call can be
/// awaited in no other way. A cipher over an access key or a saved login
/// has an identity of its own, and `.with_credential(..)` does not compile
/// for its calls. So a credential is never forgotten, and never ignored.
///
/// # Example
///
/// Two users on one cipher. `FakeCredentialKeySource` is a test double:
/// it records the credential of each key request, where a real key source
/// sends it to ZeroKMS. It takes a credential with each call, as a ZeroKMS
/// client does over an OIDC strategy built with `credential_per_call`.
///
/// ```
/// use stack_encrypt::kms::{FakeCredentialKeySource, SecretToken};
/// use stack_encrypt::{Ciphertext, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // Once, at startup. No request is made, so no user is needed.
/// let cipher = StackCipher::builder()
///     .kms(FakeCredentialKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
/// assert!(cipher.kms().credentials_seen().is_empty());
///
/// // Alice's request: the JWT comes from the request. Hers is the first
/// // call, so it loads the default keyset, and then requests its key.
/// let stored: Ciphertext = keyset
///     .encrypt(String::from("sk_live_1234"))
///     .with_credential(SecretToken::new("alice.jwt"))
///     .await?;
/// assert_eq!(cipher.kms().credentials_seen(), ["alice.jwt", "alice.jwt"]);
///
/// // Bob's request, on the same cipher. Its only request is its own.
/// let api_key: String = keyset
///     .decrypt(stored)
///     .with_credential(SecretToken::new("bob.jwt"))
///     .await?;
/// assert_eq!(api_key, "sk_live_1234");
/// assert_eq!(
///     cipher.kms().credentials_seen(),
///     ["alice.jwt", "alice.jwt", "bob.jwt"]
/// );
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
///
/// A call on that cipher is not a future until it has a credential. The
/// following code does not compile:
///
/// ```compile_fail,E0277
/// use stack_encrypt::kms::FakeCredentialKeySource;
/// use stack_encrypt::{Ciphertext, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder()
///     .kms(FakeCredentialKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// // No `.with_credential(..)`.
/// let stored: Ciphertext = keyset.encrypt(String::from("sk_live_1234")).await?;
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
///
/// A call with a credential does not merge. The following code does not
/// compile:
///
/// ```compile_fail,E0599
/// use stack_encrypt::kms::{FakeCredentialKeySource, SecretToken};
/// use stack_encrypt::{Ciphertext, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder()
///     .kms(FakeCredentialKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// let (first, second): (Ciphertext, Ciphertext) = keyset
///     .encrypt(1i64)
///     .with_credential(SecretToken::new("alice.jwt"))
///     .zip(keyset.encrypt(2i64))
///     .await?;
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
#[must_use = "a call with a credential does nothing until it is awaited"]
pub struct WithCredential<C> {
    call: C,
    // Not named `with_credential`, for the reason `Audited` gives.
    secret: SecretToken,
}

impl<C> WithCredential<C> {
    /// Wrap `call`, so that its key requests are sent with `credential`.
    /// Called only by a `with_credential` method, each of which is on a
    /// call whose key source takes a credential ([`CredentialKeySource`]).
    pub(crate) fn new(call: C, credential: SecretToken) -> Self {
        Self {
            call,
            secret: credential,
        }
    }

    /// The call, and the credential to send its key requests with.
    pub(crate) fn into_parts(self) -> (C, SecretToken) {
        (self.call, self.secret)
    }
}

/// Shows the call and nothing of the credential, which is a secret.
impl<C: fmt::Debug> fmt::Debug for WithCredential<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithCredential")
            .field("call", &self.call)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credential is a secret: a call that holds one prints the call
    /// and nothing of the credential.
    #[test]
    fn debug_shows_the_call_and_no_credential() {
        let call = WithCredential::new("the call", SecretToken::new("alice.jwt"));
        let shown = format!("{call:?}");
        assert!(!shown.contains("alice"), "{shown}");
        assert!(shown.contains("WithCredential"), "{shown}");
        assert!(shown.contains("the call"), "{shown}");
    }
}
