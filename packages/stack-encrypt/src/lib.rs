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
//! [`keyset`](StackCipher::keyset) — consumes a scalar with
//! [`KeysetCipher::encrypt`] and returns one opaque [`Ciphertext`]. Use
//! [`KeysetCipher::decrypt`] to open it under the same keyset. Each ciphertext
//! has its own ZeroKMS data key and independently auditable retrieval.
//!
//! Structural encryption, searchable targets and derives use the existing
//! plan/target engine. Its [`StackCipherText`] nodes and Vitamin C
//! [`Encrypt`]/[`Decrypt`] visitors remain available through the low-level
//! API while the owned Rust interface is extended beyond scalars.
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

// Encryption consumes and wipes the owned plaintext.
let ciphertext = keyset.encrypt("secret message".to_owned()).await?;
let plaintext: String = keyset.decrypt(ciphertext).await?;
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
//! under). Open an owned scalar through the client with
//! `String::decrypt_from(ciphertext, &cipher)` (import [`DecryptFrom`]), or
//! through [`KeysetCipher::decrypt`] to refuse leaves from any other keyset.
//! [`StackCipher::decrypt`] still opens structural [`StackCipherText`] values;
//! its keyset-constrained counterpart is [`KeysetCipher::decrypt_tree`].
//! [`default_keyset`](StackCipher::default_keyset) is the client's own —
//! the keyset a ZeroKMS administrator set for it — and is always that one.
//! A client may use many others, one per tenant say; [`StackCipher::keyset`]
//! selects any of them by id or name, loading it on first use. The [`keyset`](crate::keyset)
//! module docs lay out the model.
//!
//! Use `encrypt_with_context` and `decrypt_with_context` for *associated data*
//! (AAD): anything implementing [`IntoContext`] — `()`, `&[u8]`, `&str`, a tuple,
//! or a derived [`Context`]. It is
//! authenticated, not encrypted, and must be supplied identically on decrypt.
//! Use it to bind a ciphertext to its context (a table name, a tenant, a record
//! id) so it cannot be replayed elsewhere:
//!
//! ```no_run
//! # async fn example<K: stack_encrypt::kms::DataKeySource + stack_encrypt::kms::IndexKeySource + Sync + 'static>(cipher: stack_encrypt::StackCipher<K>) -> Result<(), stack_encrypt::Error> {
//! # let keyset = cipher.default_keyset();
//! let ct = keyset.encrypt_with_context("4111 1111 1111 1111".to_owned(), "users/42/card").await?;
//! let card: String = keyset.decrypt_with_context(ct, "users/42/card").await?; // ok
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
//! let ct = keyset.encrypt(42i32).await?;
//! let pt: i32 = keyset.decrypt(ct).await?;
//! assert_eq!(pt, 42);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! # Storing ciphertext
//!
//! [`KeysetCipher::encrypt`] returns one opaque [`Ciphertext`]. Persist it with
//! [`Ciphertext::to_bytes`] and restore it with [`Ciphertext::from_bytes`].
//! These bytes are exactly the existing [`SealedValue`] v1 envelope, with no
//! extra wrapper. Its Serde form is those bytes: padded standard Base64 in a
//! human-readable format such as JSON, raw bytes in a binary one. Parsing
//! does not authenticate a value; decryption does.
//!
//! The scalar API accepts owned [`OpaqueEncode`] values. It wipes the owned source
//! before returning the pending request, including on planning failure. A
//! successful decrypt returns an ordinary owned value: the caller is then
//! responsible for its cleanup. A whole value decrypted as an
//! [`OpaqueBlob<T>`](crate::OpaqueBlob) is wiped on drop. Copy types may still have copies held by the
//! caller, and this is not a guarantee about every compiler-generated copy.
//!
//! For target-directed conversion, import [`EncryptInto`] and [`DecryptFrom`]:
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::{Ciphertext, EncryptInto, DecryptFrom, StackCipher};
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let encrypted: Ciphertext = 42i32.encrypt_into(&keyset).await?;
//! let plain = i32::decrypt_from(encrypted, &keyset).await?;
//! assert_eq!(plain, 42);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! # Collections
//!
//! [`EncryptInto`] encrypts a `Vec` of owned plaintexts into a `Vec` of any
//! owned target, and [`DecryptFrom`] decrypts it back. A caller context is
//! optional, as it is for a single value.
//!
//! Each element is encrypted under its own data key and authenticated on its
//! own, so [`KeysetCipher::decrypt`] can decrypt any one element alone. An
//! element's position in the `Vec`, and the number of elements, are not part
//! of what is authenticated. So you can decrypt the elements in a different
//! order, or decrypt only some of them.
//!
//! This suits a very common case: storing each element in its own database
//! row. A database can return rows in any order. A query can also return only
//! some of them. If your application needs the order or the length of a
//! `Vec` to be authenticated, this API does not provide that.
//!
//! A collection makes one logical batch of key requests, with the requests
//! in element order:
//!
//! - Encrypting a collection makes one `generate_keys` call.
//! - Decrypting a collection makes one `retrieve_keys` call for each keyset.
//! - An empty collection makes no call.
//!
//! The key source can still split one logical batch into several requests to
//! its provider.
//!
//! The plaintext `Vec` is wiped before the pending request is returned, as a
//! single value is. Sometimes an element fails to decrypt after earlier
//! elements succeeded. The earlier plaintexts are then wiped before the error
//! is returned. If an element's conversion panics, they are wiped before the
//! panic unwinds.
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, StackCipher};
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//!
//! // Without a caller context, each element is encrypted under the empty context.
//! let ages: Vec<Ciphertext> = vec![29i32, 34, 41].encrypt_into(&keyset).await?;
//! assert_eq!(Vec::<i32>::decrypt_from(ages.clone(), &keyset).await?, [29, 34, 41]);
//! // Each element is an ordinary ciphertext, which decrypts on its own.
//! assert_eq!(keyset.decrypt::<i32>(ages[1].clone()).await?, 34);
//!
//! // With a caller context, the context is bound to every element.
//! let names: Vec<Ciphertext> = vec!["ada".to_owned(), "grace".to_owned()]
//!     .encrypt_into_with_context(&keyset, ("users", "name"))
//!     .await?;
//! let names = Vec::<String>::decrypt_from_with_context(names, &keyset, ("users", "name")).await?;
//! assert_eq!(names, ["ada", "grace"]);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! A collection follows its element target's rules for a caller context. If
//! the element target requires a context, the collection requires one. If
//! the element target accepts no context, the collection cannot be given
//! one.
//!
//! A `Vec<u8>` is one byte string, not a collection of bytes. Vitamin C
//! encrypts a `Vec<u8>` as a single value, and `u8` is not an
//! [`OpaqueEncode`] type. So a `Vec<u8>` encrypts into one `Ciphertext`, and
//! a `Vec<Vec<u8>>` is a collection of byte strings.
//!
//! # Whole values as one ciphertext
//!
//! `encrypt` refuses a struct, a map, or any `Vec` other than the byte
//! string `Vec<u8>`, because none of them is a scalar. The crate has no
//! `Serialize` fallback. To encrypt a whole value as **one** ciphertext,
//! wrap it in [`OpaqueBlob`].
//!
//! `OpaqueBlob` encodes the value with Vitamin C's versioned storage
//! profile. The Go SDK's opaque structs use the same profile. `OpaqueBlob`
//! then seals the encoded bytes as one leaf, in the same way as a scalar.
//! The [`blob`] module docs cover the format, the errors, what the
//! ciphertext's length reveals, and what is wiped.
//!
//! ```
//! # use serde::{Deserialize, Serialize};
//! # use zeroize::Zeroize;
//! # #[derive(Serialize, Deserialize, Zeroize)]
//! # struct Card { number: String, expiry: (u8, u16) }
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::{OpaqueBlob, StackCipher};
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let card = Card { number: "4111 1111 1111 1111".into(), expiry: (12, 2031) };
//! let ct = keyset.encrypt_with_context(OpaqueBlob::new(card), "users/42/card").await?;
//! let card: OpaqueBlob<Card> = keyset.decrypt_with_context(ct, "users/42/card").await?;
//! assert_eq!(card.get().expiry, (12, 2031));
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//!
//! # Records
//!
//! A struct encrypts field by field into a record type that states its own
//! layout: `#[derive(EncryptTarget, DecryptSource)]` with
//! `#[stash(struct = User, context = "users")]`. A field whose type is a
//! target (a [`Ciphertext`], a record, a term) is derived from the plaintext
//! field of its name under the pair `("users", "<field>")`; a
//! `#[stash(passthrough)]` field is carried into the record in the clear,
//! **moved** rather than copied and neither encrypted nor authenticated; a
//! `#[stash(from = ..)]` renames the plaintext field a field is taken from.
//! The conversion wipes the plaintext fields it seals and moves the ones it
//! passes through, so the plaintext type is `Zeroize` and nothing is cloned.
//! A caller's context extends every field's pair
//! ([`ContextExtension`]); omitted, the pairs stand as declared.
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::target::{DecryptSource, EncryptTarget};
//! use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, StackCipher};
//!
//! #[derive(Debug, PartialEq, zeroize::Zeroize)]
//! struct User { id: u64, name: String, email: String }
//!
//! #[derive(EncryptTarget, DecryptSource, serde::Serialize, serde::Deserialize)]
//! #[stash(struct = User, context = "users")]
//! struct EncryptedUser {
//!     #[stash(passthrough)]
//!     id: u64,
//!     name: Ciphertext,   // under ("users", "name")
//!     email: Ciphertext,  // under ("users", "email")
//! }
//!
//! let cipher = StackCipher::builder()
//!     .kms(stack_encrypt::kms::FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//! let user = User { id: 42, name: "Alice".into(), email: "alice@example.com".into() };
//!
//! // One conversion, one batched key request for both sealed fields.
//! let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;
//! assert_eq!(encrypted.id, 42);
//! let stored = serde_json::to_vec(&encrypted).unwrap();
//!
//! let loaded: EncryptedUser = serde_json::from_slice(&stored).unwrap();
//! let restored = User::decrypt_from(loaded, &cipher).await?;
//! assert_eq!(restored.email, "alice@example.com");
//!
//! // Bound to a row: the same extension is needed to open it.
//! let user = User { id: 43, name: "Bob".into(), email: "bob@example.com".into() };
//! let encrypted: EncryptedUser = user.encrypt_into_with_context(&keyset, 43u64).await?;
//! let restored = User::decrypt_from_with_context(encrypted, &cipher, 43u64).await?;
//! assert_eq!(restored.id, 43);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! A `#[stash(plaintext = String)]` record is the other shape: every field
//! is derived from the whole value under the one context the caller must
//! supply ([`target::RequiredContext`]) — a [`Ciphertext`] beside an
//! [`sem::EqualityTerm`] is a searchable scalar — and it is a field of a
//! `struct` record like any target. A `Vec` of plaintext structs encrypts
//! into a `Vec` of records as one batch. The derive crate's documentation
//! lists every attribute; [`target`] describes the declaration traits a
//! hand-written target implements, and how a record field's context is
//! composed.
//!
//! Existing structural plans and derives (`#[derive(EncryptFrom, DecryptInto)]`)
//! still use [`StackCipherText`], a tree
//! of sealed leaves, over a borrowed plaintext. Their low-level direct entry points are
//! [`KeysetCipher::encrypt_tree`] and [`KeysetCipher::decrypt_tree`]; their
//! borrowed conversion helpers live in [`target::legacy`]. They are separate
//! from the owned scalar API. An owned record is also a structural
//! declaration (its derive emits the bridge), so it is a field of a
//! structural record or a typed plan field too. There is no generic
//! `Serialize` fallback.
//!
//! A struct sealed through the structural API, or as an owned record, is one
//! ciphertext per field. A struct in an [`OpaqueBlob`] is one ciphertext.
//!
//! # What is authenticated
//!
//! Besides your AAD, the *shape* of a value is authenticated: an element cannot
//! be spliced out of a sequence and passed off as a scalar, a map value cannot
//! be moved under a different key, "empty" is itself a sealed marker rather
//! than inferable from structure, and "absent" is a sealed null leaf. Every
//! leaf records its own type, so a leaf cannot be read back as another. A tampered or
//! re-homed ciphertext fails with [`Error::Aead`]; a failed or denied key
//! retrieval surfaces as [`Error::Kms`]. A ciphertext opened under the
//! *wrong context* is refused by ZeroKMS first: every data key is bound to
//! its context's [`Descriptor`], so the retrieve is denied
//! ([`Error::Kms`], a forbidden request) before the AEAD runs — as
//! `examples/encrypted_record.rs` shows against a live ZeroKMS. Only a key
//! source that ignores descriptors (`FakeDataKeySource`, in tests) lets a
//! wrong context reach the AEAD, where it is [`Error::Aead`].
//!
//! Every leaf's AAD is derived from the context its key was minted under,
//! and there is no entry point that lets a caller supply one of its own.
//!
//! # Relationship to vitaminc
//!
//! A `KeysetCipher` seals through a vitaminc `Cipher`; everything vitaminc
//! can encrypt remains available through the structural engine. Its data model, AAD derivations and
//! the leaf wire format are vitaminc's (`vitaminc_encrypt::Aes256Cipher`, AES-256-GCM under a random
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

pub mod blob;
pub mod cipher;
mod scalar;
pub use blob::{BlobError, OpaqueBlob};
pub use scalar::{Ciphertext, OpaqueDecode, OpaqueEncode};
#[cfg(test)]
mod codes;
pub mod descriptor;
#[cfg(feature = "dynamic")]
pub mod dynamic;
pub mod json;
pub mod keyset;
pub mod op;
pub mod plan;
pub mod sem;
pub mod target;
pub mod value;

pub use cipher::{
    Error, FromEnv, LeafBytesError, PendingStackCipherText, SealedValue, StackCipher,
    StackCipherBuilder, StackCipherText,
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
    CallerContext, CipherScope, ContextExtension, DecryptField, DecryptFrom, DecryptInto,
    DecryptSource, Decryptable, Decryption, EncryptFrom, EncryptInto, EncryptTarget, Encrypted,
    Encryption, Equality, Index, IndexSpec, Indexes, Json, Match, Ope, Ore, OreBlock, Pending,
    PendingFuture, Request, Responses, TermSet,
};

// Re-export the vitaminc AEAD surface callers need to drive the cipher, so they
// don't have to depend on `vitaminc-aead` directly for the common path: a
// value describes itself once (`Encrypt`) and names the sink that reads it
// back (`Decrypt`). A context type of your own implements `IntoContext` once;
// `IntoAad` and `IntoPrfContext` are vitaminc's blankets over it, so both
// derivations see the same bytes.
pub use vitaminc_aead::{
    CipherText, Context, ContextPiece, ContextTag, DecodeError, Decrypt, Encrypt, IntoAad,
    IntoContext, Node, PassthroughFrame, Unspecified,
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

// The nonempty proof used by searchable targets and legacy declarations,
// built with `nonempty!`
// (a literal, checked at compile time) or `NonEmpty::new` (a runtime value,
// checked once); `MaybeEmpty` is what a context type of your own implements
// to be wrapped. `#[derive(EncryptFrom)]` names these through this crate.
pub use vitaminc_protected::{nonempty, nonempty_bytes, EmptyError, MaybeEmpty, NonEmpty};

// And the wrapper plaintext comes back in (`ValueFrame::into_inner`, a
// decrypted `Protected<T>`), with the trait that reads it, and the wiping
// buffer the re-exported frame writer writes into (`dynamic::frame`). The
// frame readers take a `ProtectedRef` of bytes, which that buffer lends
// through `AsProtectedRef`.
pub use vitaminc_protected::{AsProtectedRef, Buffer, Controlled, Protected, ProtectedRef};
