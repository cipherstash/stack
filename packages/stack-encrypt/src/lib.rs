#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
// Security lints
#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
// Prevent mem::forget from bypassing ZeroizeOnDrop
#![warn(clippy::mem_forget)]
// Prevent accidental data leaks via output
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
// Code quality
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
// Relax in tests
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]
//! Encrypt Rust values under per-value ZeroKMS data keys.
//!
//! A [`StackCipher`] is scoped to one ZeroKMS client, and a [`KeysetCipher`] —
//! the cipher bound to one of that client's keysets, from
//! [`default_keyset`](StackCipher::default_keyset) or
//! [`keyset`](StackCipher::keyset) — encrypts any value that implements
//! [`Encrypt`] (`String`, `Vec<T>`, `HashMap<K, V>`, `Option<T>`,
//! `Protected<T>`, your own types, and any nesting of them). Either cipher
//! decrypts back into any [`Decrypt`] type. Every scalar inside the value is
//! sealed under its **own** ZeroKMS data key, so each value access is an
//! individually auditable key retrieval — there is no long-lived key in your
//! process.
//!
//! # Quick start
//!
// `StackCipher::new()` builds a ZeroKMS client from the environment, so it
// only exists with `http`. Without it the entry point is
// `StackCipher::builder().kms(..)` over an explicit data-key source — the
// shape the WASI/wazero guest builds against; see "Testing without ZeroKMS"
// below for the same call over the in-memory stub.
#![cfg_attr(
    feature = "http",
    doc = r#"```no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use stack_encrypt::StackCipher;

// Credentials: `npx stash auth login` on a developer machine, or
// CS_CLIENT_ID / CS_CLIENT_KEY + CS_CLIENT_ACCESS_KEY / CS_WORKSPACE_CRN in CI.
let cipher = StackCipher::new().await?;
let keyset = cipher.default_keyset();

// A `&str` encrypts as it is; decryption is owned, so it comes back a
// `String` — nothing borrows from a ciphertext.
let ciphertext = keyset.encrypt("secret message", ()).await?;
let plaintext: String = cipher.decrypt(ciphertext, ()).await?;
assert_eq!(plaintext, "secret message");
# Ok(())
# }
```"#
)]
#![cfg_attr(
    not(feature = "http"),
    doc = "Without the `http` feature a cipher is built over an explicit\
 data-key source — `StackCipher::builder().kms(..).init()` — rather than from\
 the environment. Enable `http` for `StackCipher::new()`, which discovers\
 ZeroKMS credentials itself."
)]
//!
//! Encrypting binds to a keyset (every data key is minted under one); decrypting
//! does not (every sealed leaf carries the id of the keyset it was sealed
//! under), so it goes through the client-scoped `cipher` — or through the
//! `keyset`, which then refuses leaves from any other keyset.
//! [`default_keyset`](StackCipher::default_keyset) is the client's own —
//! the keyset a ZeroKMS administrator set for it — and is always that one.
//! A client may use many others, one per tenant say; [`StackCipher::keyset`]
//! selects any of them by id or name, loading it on first use. The [`keyset`](crate::keyset)
//! module docs lay out the model.
//!
//! The second argument is the *associated data* (AAD): anything that implements
//! [`IntoAad`] — `()`, `&[u8]`, `&str`, a tuple, or a derived [`Context`]. It is
//! authenticated, not encrypted, and must be supplied identically on decrypt.
//! Use it to bind a ciphertext to its context (a table name, a tenant, a record
//! id) so it cannot be replayed elsewhere:
//!
//! ```no_run
//! # async fn example<K: stack_encrypt::kms::DataKeySource>(cipher: stack_encrypt::StackCipher<K>) -> Result<(), stack_encrypt::Error> {
//! # let keyset = cipher.default_keyset();
//! let ct = keyset.encrypt("4111 1111 1111 1111", "users/42/card").await?;
//! let card: String = cipher.decrypt(ct, "users/42/card").await?; // ok
//! # Ok(())
//! # }
//! ```
//!
// Credentials only exist on the `http` path: without it there is no client
// to authenticate, only the `DataKeySource` the caller supplies.
#![cfg_attr(
    feature = "http",
    doc = r#"# Credentials

A cipher needs two credentials, resolved independently of each other:

- a **client key** — an id and key material, which data keys are derived
  against; and
- an **auth strategy** — whatever obtains a token ZeroKMS will accept.

Each is looked for in the environment first, then in the current workspace of
the CLI's profile directory (`~/.cipherstash`), which `npx stash auth login`
writes. A logged-in developer machine has both there, so
`StackCipher::new()` usually just works with nothing else set.

Where there is no profile — CI, a container, wasm — the environment carries
them. `CS_CLIENT_ID` + `CS_CLIENT_KEY` are the client key.
`CS_CLIENT_ACCESS_KEY` is the auth strategy `AutoStrategy` detects, and it
needs a workspace CRN (`CS_WORKSPACE_CRN`) alongside it: the profile is what
supplies that otherwise, and its region drives service discovery while its
workspace id verifies every token issued.

An access key is not the only way to authenticate, and often not the one a
service wants. A `stack_auth::OidcFederationStrategy` federates a
third-party OIDC JWT (Clerk, Supabase, Auth0) into a CipherStash token, so
the deployment holds no long-lived CipherStash credential of its own. What
`AutoStrategy` detects is only the two above — access key, then profile — so
any other strategy is named explicitly, and that is what
[`kms`](StackCipherBuilder::kms) is for: build the
[`StackKms`](crate::kms::StackKms) over the strategy you want and hand it to
the builder.

```no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use stack_auth::{AuthError, AuthStrategyFn, SecretToken, ServiceToken};
use stack_encrypt::StackCipher;
use stack_encrypt::kms::{EnvKeyProvider, StackKmsBuilder};

// Any `AuthStrategy` goes in this slot — `AccessKeyStrategy`,
// `OidcFederationStrategy`, `DeviceSessionStrategy`, or, as here,
// `AuthStrategyFn` over a closure of your own. The closure is called
// whenever ZeroKMS needs a fresh token, so refresh belongs inside it. Note
// what holds the token: `SecretToken` is zeroized on drop and prints as
// `***`, so a long-lived credential neither lingers in freed memory nor
// lands in a log line.
let token = SecretToken::new(std::env::var("MY_SERVICE_TOKEN")?);
let strategy = AuthStrategyFn::new(move || {
    let token = token.clone();
    async move { Ok::<_, AuthError>(ServiceToken::new(token)) }
});

// The client key is the other half, and has its own provider: `EnvKeyProvider`
// reads CS_CLIENT_ID / CS_CLIENT_KEY, or supply a `KeyProvider` of your own.
let kms = StackKmsBuilder::new(strategy)
    .with_key_provider(EnvKeyProvider)
    .build()
    .await?;

let cipher = StackCipher::builder().kms(kms).init().await?;
# Ok(())
# }
```

The built-in strategies are constructed from a workspace CRN
(`stack_auth::Crn`) rather than read from the environment —
`OidcFederationStrategy::new(crn, provider)` — and otherwise reach the
builder through the same `kms` seam.

`examples/zerokms_auth.rs` runs this end to end against a live ZeroKMS,
alongside the default path and the errors each half fails with. The
transport knobs — timeouts, batch size, concurrency, an alternate ZeroKMS
endpoint — are `StackKmsBuilder`'s, and the two keyset-cache knobs are
[`keyset_cache_size`](StackCipherBuilder::keyset_cache_size) and
[`keyset_name_ttl`](StackCipherBuilder::keyset_name_ttl).
"#
)]
//!
//! # Testing without ZeroKMS
//!
//! `stack_encrypt::kms::FakeDataKeySource` is an in-memory stub that needs no
//! credentials or network: it hands out a fresh random data key per request and
//! remembers it in memory, so a `generate` followed by the matching `retrieve`
//! round-trips within one process (the key material itself differs run to run,
//! and nothing survives the process). It models none of ZeroKMS's
//! authorization behaviour (context, identity claims, decryption policies) —
//! those are the service's, and tests of them belong against a real ZeroKMS.
//! It lives behind this crate's `test-support` feature, so add
//! `stack-encrypt = { version = "..", features = ["test-support"] }` to your
//! `[dev-dependencies]`. stack-kms is re-exported as [`kms`], so
//! there is no separate stack-kms dependency to keep in step:
//!
//! ```
//! use stack_encrypt::StackCipher;
//! use stack_encrypt::kms::FakeDataKeySource;
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder()
//!     .kms(FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let ct = keyset.encrypt(vec!["a".to_string(), "b".to_string()], ()).await?;
//! let pt: Vec<String> = cipher.decrypt(ct, ()).await?;
//! assert_eq!(pt, vec!["a", "b"]);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! # Storing ciphertext
//!
//! [`encrypt`](KeysetCipher::encrypt) returns a [`StackCipherText`]: a tree whose
//! shape mirrors the value (a scalar is a single leaf, a `Vec` a sequence of
//! leaves, a map a set of named leaves) and whose leaves are [`SealedValue`]s.
//! A `SealedValue` is the persistable unit: its canonical, frozen byte
//! encoding is [`to_bytes`](SealedValue::to_bytes) /
//! [`from_bytes`](SealedValue::from_bytes) — the format a database column
//! holds and every language binding reads. Each leaf carries the id of the
//! keyset it was sealed under, which is what lets a column be opened with no
//! keyset named. For callers that manage their own
//! storage format it also implements `serde` `Serialize`/`Deserialize` and
//! offers [`into_parts`](SealedValue::into_parts) /
//! [`from_parts`](SealedValue::from_parts). Map keys are stored in the clear
//! (and authenticated); nothing else about a value is visible without its
//! data keys. Index terms have their own frozen encodings — see
//! [`sem`](crate::sem#byte-encodings).
//!
//! # What is authenticated
//!
//! Besides your AAD, the *shape* of a value is authenticated: an element cannot
//! be spliced out of a sequence and passed off as a scalar, a map value cannot
//! be moved under a different key, and "absent" / "empty" are themselves
//! sealed markers rather than inferable from structure. A tampered or
//! re-homed ciphertext fails with [`Error::Aead`]; a failed or denied key
//! retrieval surfaces as [`Error::Kms`]. A ciphertext opened under the
//! *wrong context* is refused by ZeroKMS first: every data key is bound to
//! its context's [`Descriptor`], so the retrieve is denied
//! ([`Error::Kms`], a forbidden request) before the AEAD runs — as
//! `examples/encrypted_record.rs` shows against a live ZeroKMS. Only a key
//! source that ignores descriptors (`FakeDataKeySource`, in tests) lets a
//! wrong context reach the AEAD, where it is [`Error::Aead`].
//!
//! For one-row reads of a batch-encrypted collection, decrypt as
//! [`Element<T>`](Element) under the same AAD used for the whole collection:
//! the derivation that binds an element to its position is applied by the
//! type, not by the caller. That is the general rule here — every leaf's AAD
//! is derived from the context its key was minted under, and there is no
//! entry point that lets a caller supply one of its own.
//!
//! # Relationship to vitaminc
//!
//! A `KeysetCipher` is a vitaminc [`Cipher`]; everything a vitaminc cipher can
//! encrypt, it can encrypt, and the AEAD, AAD derivations and leaf wire format
//! are vitaminc's (`vitaminc_encrypt::Aes256Cipher`, AES-256-GCM under a random
//! per-leaf nonce vitaminc generates itself). The ZeroKMS `iv` a [`SealedValue`]
//! carries is *not* that nonce: it identifies the data key, and is sent back to
//! ZeroKMS with the key `tag` to re-derive it — under the same [`Descriptor`]
//! (the leaf's context, rendered) the key was generated with, which ZeroKMS
//! binds into the tag and logs. The types a caller needs from
//! vitaminc are re-exported here. The [`cipher`] module docs describe the
//! internals (batching, AAD derivation, wire format).

/// This crate's version, for a binding to put in the `user-agent` of the
/// ZeroKMS requests it makes.
///
/// A request is identified by the library that makes it, not by whichever
/// binding shim is carrying it: a product token of `stack-encrypt/0.1.0`
/// (the `product/version` spelling a `user-agent` is made of, with the
/// host in a comment after it — the Go guest sends
/// `stack-encrypt/0.1.0 (Go)`) means the same thing from the WASI guest
/// under Go as from a native cdylib under Python. The
/// native Rust client does not go through a binding and identifies itself
/// as `stack-kms` (see `stack_kms`'s user agent) — the crate that actually
/// makes its requests.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cipher;
#[cfg(test)]
mod codes;
pub mod descriptor;
#[cfg(feature = "dynamic")]
pub mod dynamic;
pub mod keyset;
pub mod plan;
pub mod sem;
pub mod target;

pub use cipher::{
    BoxedPassthrough, Error, FromEnv, LeafBytesError, PendingStackCipherText, SealedValue,
    StackCipher, StackCipherBuilder, StackCipherText, StackDecipher,
};
pub use descriptor::{Describe, Description, Descriptor, Label, LabelError};
pub use keyset::KeysetCipher;
pub use plan::{all, Plan, PlanError};
// stack-kms is a public dependency: `StackCipher` is generic over its
// `DataKeySource`, and `StackCipherBuilder::kms` takes its `StackKms`. It is
// versioned on its own (release-plz.toml), so a caller reaches it through
// here and always gets the version this crate was built against, never a
// second copy whose types do not fit `StackCipher`'s bounds.
pub use stack_kms as kms;
/// The trait every error here implements to hand over its structured
/// fields, with the rule for what an error may contain, and the helpers that
/// go with it. Shared by `stack-profile`, `stack-auth`, `stack-kms` and this
/// crate, so a binding encodes an error from any of them the same way.
pub use stack_kms::{diagnostic, ErrorPayload};
pub use target::{
    CallerContext, CipherScope, DecryptField, DecryptFrom, DecryptInto, Decryptable, Decryption,
    EncryptFrom, EncryptInto, Encrypted, Encryption, Equality, Index, IndexSpec, Indexes, Match,
    Ope, Ore, Pending, PendingFuture, Request, Responses, TermSet,
};

// Re-export the vitaminc AEAD surface callers need to drive the cipher, so they
// don't have to depend on `vitaminc-aead` directly for the common path. A
// context type of your own implements `IntoContext` once; `IntoAad` and
// `IntoPrfContext` are vitaminc's blankets over it, so both derivations see
// the same bytes.
pub use vitaminc_aead::{
    Cipher, CipherText, Context, ContextPiece, ContextTag, Decipher, Decrypt, Element, Encrypt,
    IntoAad, IntoContext, Unspecified,
};
// The vitaminc 0.4 names, deprecated there; re-exported for one transition so
// a caller that spelled them keeps compiling with a warning.
#[allow(deprecated)]
pub use vitaminc_aead::{Aad, AadPiece};

// Likewise the PRF context surface, so a caller who needs the PRF view of a
// context has no direct `vitaminc-prf` dependency for it.
pub use vitaminc_prf::IntoPrfContext;
#[allow(deprecated)]
pub use vitaminc_prf::PrfContext;

// And the proof every target-directed leaf asks for: a `NonEmpty<T>` is what
// `encrypt_into_with_context` / `decrypt_into` take, built with `nonempty!`
// (a literal, checked at compile time) or `NonEmpty::new` (a runtime value,
// checked once); `MaybeEmpty` is what a context type of your own implements
// to be wrapped. `#[derive(EncryptFrom)]` names these through this crate.
pub use vitaminc_protected::{nonempty, nonempty_bytes, EmptyError, MaybeEmpty, NonEmpty};
