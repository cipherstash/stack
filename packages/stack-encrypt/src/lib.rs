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
//! A [`StackCipher`] belongs to one ZeroKMS client, and a [`KeysetCipher`] —
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

`AutoStrategy` detects an access key or a CLI login, and nothing else. To
authenticate any other way, pass the strategy to
[`auth_strategy`](StackCipherBuilder::auth_strategy). Then name the source of
the client key with [`key_provider`](StackCipherBuilder::key_provider). After
`auth_strategy`, the builder only reads a client key from the provider you
name.

For example, a `stack_auth::OidcFederationStrategy` exchanges a JWT from your
identity provider (Clerk, Supabase, Auth0) for a CipherStash token. Your
deployment then needs no long-lived CipherStash credential of its own.
ZeroKMS receives each request as the user that the JWT names.

`init` loads the index key of the default keyset, with one request to
ZeroKMS. Call `init` where the strategy can return a token. If the provider
returns the JWT of the current request's user, call `init` while your program
handles a request.

After `init`, ZeroKMS receives each data key request as the user that the
strategy returns a token for. The cipher loads the default keyset's index key
once, in `init`, and uses that key for every user. So the ZeroKMS log shows
that one load under the caller who made it, and each data key request under
its own caller: see [`auth_strategy`](StackCipherBuilder::auth_strategy).

```no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use stack_auth::{AuthError, OidcFederationStrategy, OidcProviderFn, SecretToken};
use stack_encrypt::StackCipher;
use stack_encrypt::kms::EnvKeyProvider;

// `OidcProviderFn` wraps a closure. Any type that implements
// `stack_auth::OidcProvider` works in its place.
let provider = OidcProviderFn::new(|| async {
    // Return the JWT of the user who made the current request.
    Ok::<_, AuthError>(SecretToken::new("header.payload.signature".to_string()))
});
// The workspace is `CS_WORKSPACE_CRN`, or the CLI's current workspace.
let strategy = OidcFederationStrategy::with_detected_workspace(provider)?;

// Run this while your program handles a request.
let cipher = StackCipher::builder()
    .auth_strategy(strategy)
    // `EnvKeyProvider` reads `CS_CLIENT_ID` and `CS_CLIENT_KEY`.
    .key_provider(EnvKeyProvider)
    .init()
    .await?;
# Ok(())
# }
```

To name the workspace yourself, build the strategy with
`OidcFederationStrategy::new(crn, provider)`. `crn` is a `stack_auth::Crn`.

Any other `AuthStrategy` goes to the builder the same way: an
`AccessKeyStrategy`, a `DeviceSessionStrategy`, or an `AuthStrategyFn` that
calls a function of your own.

```no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use stack_auth::{AuthError, AuthStrategyFn, SecretToken, ServiceToken};
use stack_encrypt::StackCipher;
use stack_encrypt::kms::EnvKeyProvider;

// The cipher calls the closure whenever a ZeroKMS request needs a token, so
// refresh the token inside the closure. `SecretToken` wipes the token when
// it is dropped and prints as `***`. The token therefore stays out of freed
// memory and out of logs.
let token = SecretToken::new(std::env::var("MY_SERVICE_TOKEN")?);
let strategy = AuthStrategyFn::new(move || {
    let token = token.clone();
    async move { Ok::<_, AuthError>(ServiceToken::new(token)) }
});

let cipher = StackCipher::builder()
    .auth_strategy(strategy)
    .key_provider(EnvKeyProvider)
    .init()
    .await?;
# Ok(())
# }
```

The key providers are in [`kms`]. `EnvKeyProvider` reads `CS_CLIENT_ID` and
`CS_CLIENT_KEY`. On native targets, `ProfileKeyProvider` reads the key that
`npx stash auth login` saved. `FallbackKeyProvider` tries one provider, then
another. You can also implement `KeyProvider` yourself.

To choose the transport settings as well, build a
[`StackKms`](crate::kms::StackKms) with `StackKmsBuilder` and pass it to
[`kms`](StackCipherBuilder::kms).

## A credential with each call

A server that decrypts as the end user who signed in has no identity of its
own. At startup there is no user, and each request has a different one.
[`credential`] covers this case. The code differs from the access key path
in two places:

- The strategy is an `OidcFederationStrategy` built with
  `credential_per_call`. It needs no callback to find the JWT, so the
  application needs no task-local variable for a callback to read.
- Each request handler attaches its user's JWT to the call, with
  [`with_credential`](Pending::with_credential). Every request that the
  call makes is made as that user.

[`init`](StackCipherBuilder::init) is the same call. With an access key it
loads the default keyset, so wrong credentials fail at startup. With this
strategy it has no credential to load the keyset with, so it makes no
request. The first call on the default keyset that is awaited loads it, with
the credential of that call. A call on a keyset selected by id or by name
loads that keyset only.

```
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
use stack_auth::OidcFederationStrategy;
use stack_encrypt::kms::StaticKeyProvider;
use stack_encrypt::StackCipher;

# // A generated key stands in for the client key.
# let client_key = stack_encrypt::kms::ClientKey::generate_for_test();
let crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse()?;
let strategy = OidcFederationStrategy::credential_per_call(crn)?;

// Once, at startup. No request goes to ZeroKMS, so no user is needed.
let cipher = StackCipher::builder()
    .auth_strategy(strategy)
    // `EnvKeyProvider` reads `CS_CLIENT_ID` and `CS_CLIENT_KEY` instead.
    .key_provider(StaticKeyProvider::new(client_key))
    .init()
    .await?;
# let _ = cipher;
# Ok(())
# }
# tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
```

A request handler then works as usual, and ends each call with the
credential: `keyset.encrypt(..).with_credential(SecretToken::new(jwt)).await`.
A record, a query and a zipped call take it the same way. [`WithCredential`]
has that half as an example that runs, over a key source that needs no
network.

A call on this cipher is not a future until it has a credential, so a
handler that forgets `.with_credential(..)` does not compile. A call on a
cipher with an identity of its own is the other way round: it is awaited
as it is, and has no `with_credential`. That covers an access key, a saved
login, and an `OidcFederationStrategy` built with a provider callback.

`examples/zerokms_auth.rs` runs the access-key path end to end against a live ZeroKMS,
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
//! # Seeing the context
//!
//! A wrong context loses data silently: a query under the wrong context
//! matches nothing, and gives no error. So every declaration and every call
//! can show the context it uses, before any key is requested. A derived
//! record has `contexts()`, a plan that is data has
//! `dynamic::record::Plan::contexts` (with the `dynamic` feature), and a
//! prepared call has [`Pending::context`](target::Pending::context). The
//! `testing` feature adds `assert_context!`, which pins a context in a
//! test. See [`contexts`] for the rendering. A field with a binding shows
//! its query context and its stored context; see
//! [`CallerContext`] for the two.
//!
//! ```
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::target::{DecryptSource, EncryptTarget};
//! use stack_encrypt::{Encrypted, StackCipherText};
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User { email: String, notes: String }
//!
//! #[derive(EncryptTarget, DecryptSource)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     email: Encrypted<EqualityTerm>,
//!     notes: StackCipherText,
//! }
//!
//! println!("{}", EncryptedUser::contexts());
//! // email
//! //   context: users / email
//! // notes
//! //   context: users / notes
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
//! ## A JSON document
//!
//! A JSON document is a single value to the cipher: wrap a
//! `serde_json::Value` in [`JsonPlaintext`](json::JsonPlaintext) and
//! `encrypt` returns one ciphertext. The plaintext of that ciphertext is
//! the document's JSON text. Every language reads JSON text the same way,
//! so use it for a document that another SDK also reads. Nothing inside it
//! can be searched. The [`json`] index is for a document that is queried.
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use serde_json::json;
//! use stack_encrypt::json::JsonPlaintext;
//! # let cipher = stack_encrypt::StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//! #     .init()
//! #     .await?;
//! # let keyset = cipher.default_keyset();
//! let settings = JsonPlaintext::from(json!({"theme": "dark", "beta": true}));
//! let ct = keyset.encrypt_with_context(settings, "users/42/settings").await?;
//! let settings: JsonPlaintext = keyset.decrypt_with_context(ct, "users/42/settings").await?;
//! assert_eq!(settings.value()["theme"], "dark");
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! # Records
//!
//! A record is a struct that is encrypted field by field. You declare the
//! stored form of a plaintext struct as a second struct, and derive
//! `EncryptTarget` and `DecryptSource` on it. In
//! `#[stash(struct = User, scope = "users")]`, `User` is the plaintext
//! type. The string `"users"` is the record's name. It is the first scope of
//! every field's context, and the field's name is the next.
//!
//! Each field of the record is one of these:
//!
//! - **A sealed field.** Its type is a target, such as a [`Ciphertext`], a
//!   term or another record. It is derived from the plaintext field of the
//!   same name, under the context `("users", "<field>")`. Use
//!   `#[stash(from = ..)]` when the plaintext field has another name.
//! - **A passthrough field,** marked `#[stash(passthrough)]`. The plaintext
//!   field is moved into the record as it is. A passthrough field is **not
//!   encrypted and not authenticated**. Anyone with access to the stored
//!   record can read it, change it, or remove it, and the sealed fields
//!   still decrypt. Use it only for values that are not secret. Treat the
//!   value you read back as untrusted input. Never let it decide
//!   authorisation, tenancy, or which record to trust. A value that must be
//!   readable and also tamper-evident belongs in the context instead.
//!
//! The record must name every field of the plaintext, as a sealed or a
//! passthrough field. A plaintext field it leaves out is a compile error.
//!
//! Encrypting a plaintext consumes it. The conversion wipes each field it
//! seals and moves each passthrough field, so no field is copied. This is
//! why the plaintext type must implement `Zeroize`.
//!
//! **Decrypt into a [`Protected`].** The plaintext type cannot wipe itself
//! when it is dropped. The derive moves the fields out of the plaintext
//! struct, and Rust does not allow that for a type that implements `Drop`.
//! So the derive also implements `DecryptSource<Protected<User>>`:
//! `Protected::<User>::decrypt_from(record, &cipher)` returns the plaintext
//! inside a `Protected`, which wipes it when it is dropped. A `Vec` of
//! records decrypts into a `Vec<Protected<User>>`.
//!
//! On the plaintext type:
//!
//! - derive `OpaqueDebug` from `vitaminc::protected`, not `Debug`, so that
//!   printing the value shows its field names with each value hidden;
//! - derive `TimingSafeEq` from `vitaminc::protected`, not `PartialEq`, so
//!   that a comparison runs in constant time;
//! - do not derive `Clone`, because each clone is another copy to wipe.
//!
//! Each field is sealed under its own context and nothing else, and the
//! caller cannot add to it ([`target::DeclaredScopes`]). So two records of
//! the same type can exchange a sealed field, and both still decrypt.
//! Binding each field to its row needs the row ID declared on the record as
//! a binding. The attributes that declare a caller's scope or binding are
//! not built yet.
//!
//! ```
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use stack_encrypt::target::{DecryptSource, EncryptTarget};
//! use stack_encrypt::{Ciphertext, Controlled, DecryptFrom, EncryptInto, Protected, StackCipher};
//!
//! // The plaintext derives `Zeroize` and nothing else.
//! #[derive(zeroize::Zeroize)]
//! struct User { id: u64, name: String, email: String }
//!
//! #[derive(EncryptTarget, DecryptSource, serde::Serialize, serde::Deserialize)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     // Not encrypted and not authenticated.
//!     #[stash(passthrough)]
//!     id: u64,
//!     name: Ciphertext,   // sealed under ("users", "name")
//!     email: Ciphertext,  // sealed under ("users", "email")
//! }
//!
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let id = 42u64;
//! let user = User { id, name: "Alice".into(), email: "alice@example.com".into() };
//!
//! // One call, and one batched key request for both sealed fields.
//! let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;
//! let stored = serde_json::to_vec(&encrypted)?;
//!
//! let loaded: EncryptedUser = serde_json::from_slice(&stored)?;
//! let restored = Protected::<User>::decrypt_from(loaded, &cipher).await?;
//! # assert_eq!(restored.risky_ref().id, id);
//! // `restored` wipes the plaintext when it is dropped.
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! A record can also be derived from one whole value, with
//! `#[stash(plaintext = String)]`. Every field is then derived from that
//! value, under one context that the caller must supply
//! ([`target::RequiredContext`]). For example, a [`Ciphertext`] field and an
//! [`sem::EqualityTerm`] field make a value you can search for. A record of
//! this kind can be a field of a `struct` record, like any target.
//!
//! A `Vec` of plaintext structs encrypts into a `Vec` of records with one
//! batched key request. The derive crate's documentation lists every
//! attribute. The [`target`] module describes the traits a hand-written
//! target implements, and how the context of a record field is built.
//!
//! A [`StackCipherText`] is a tree of sealed leaves, one for each field of
//! the value. [`KeysetCipher::encrypt_tree`] seals a whole value as a tree,
//! under one context, and [`KeysetCipher::decrypt_tree`] opens it. A derived
//! record's ciphertext fields are trees of the same leaves.
//!
//! A struct sealed as a tree, or as a derived record, is one ciphertext per
//! field. A struct in an [`OpaqueBlob`] is one ciphertext.
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
//! can encrypt remains available through [`KeysetCipher::encrypt_tree`]. Its data model, AAD derivations and
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

pub mod audit;
pub mod blob;
pub mod cipher;
pub mod contexts;
pub mod credential;
mod scalar;
pub use audit::{AuditMetadata, AuditValue, Audited};
pub use blob::{BlobError, OpaqueBlob};
pub use credential::{KeySource, WithCredential};
pub use scalar::{Ciphertext, OpaqueDecode, OpaqueEncode};
/// The identity of a key source that has one of its own: an access key, a
/// saved login, or a test double. It is stack-auth's type.
///
/// A cipher over such a key source makes every key request as that
/// identity, so its calls are awaited as they are. You do not name this
/// type. It appears in the bound of
/// [`StackCipherBuilder::init`], where the compiler works it out from the
/// key source.
pub use stack_kms::OwnIdentity;
#[cfg(test)]
mod codes;
pub mod descriptor;
#[cfg(feature = "dynamic")]
pub mod dynamic;
pub mod field_reference;
pub mod json;
pub mod keyset;
pub mod op;
pub mod plan;
pub mod refusal;
pub mod sem;
pub mod target;
#[cfg(feature = "testing")]
pub mod testing;
pub mod value;

#[cfg(feature = "http")]
pub use cipher::WithAuthStrategy;
pub use cipher::{
    Error, FromEnv, LeafBytesError, PendingStackCipherText, SealedValue, StackCipher,
    StackCipherBuilder, StackCipherText, WithKeySource,
};
pub use contexts::{
    CallContexts, CallerShape, ContextTree, Contexts, FieldContext, Kind, LeafContext, Placeholder,
    SuppliedContext,
};
pub use descriptor::{Describe, Description, Descriptor, Label, LabelError};
pub use field_reference::{
    BetweenQuery, FieldQuery, FieldReference, Needs, QueryInput, Ready, ScopeInput,
};
pub use keyset::KeysetCipher;
pub use plan::PlanError;
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
    CallerContext, CipherRef, DecryptField, DecryptFrom, DecryptSource, Decryptable, Decryption,
    EncryptInto, EncryptTarget, Encrypted, Encryption, Equality, Index, IndexSpec, Indexes, Json,
    Match, Ope, Ore, OreBlock, Pending, PendingFuture, Request, Responses, TermSet,
};

// Re-export the vitaminc AEAD surface callers need to drive the cipher, so they
// don't have to depend on `vitaminc-aead` directly for the common path: a
// value describes itself once (`Encrypt`) and names the sink that reads it
// back (`Decrypt`). A context type of your own implements `IntoContext` once;
// `IntoAad` and `IntoPrfContext` are vitaminc's blankets over it, so both
// derivations see the same bytes.
pub use vitaminc_aead::{
    CipherText, Context, ContextPiece, ContextTag, DecodeError, Decrypt, Encrypt, EncryptRef,
    IntoAad, IntoContext, Node, PassthroughFrame, Unspecified,
};
/// A type with an order target of its own: what an order index
/// ([`Ore`], [`Ope`], [`OreBlock`]), an order term ([`sem::OreTerm`],
/// [`sem::OpeTerm`], [`sem::OreBlockTerm`]) and the ordering operators
/// ([`op::Lt`] and the others) are bounded by. It is vitaminc-ore's trait,
/// and its table is vitaminc-ore's. This crate names no target.
///
/// | Type | Target |
/// | --- | --- |
/// | `u16` to `u128`, `i16` to `i128` | the integer at its own width |
/// | `f32`, `f64` | `F64`: an `f32` widens to it exactly, `-0.0` ties `0.0`, every NaN is one value after `+Infinity` |
/// | `String`, `&str` | `Text`: Unicode 16 NFC with case and accents folded |
/// | `value::Date` | `Date`: the day |
/// | `value::Timestamp` | `Timestamp`: the instant truncated to the microsecond, so instants in one microsecond tie |
/// | `value::Decimal` | `Decimal`: the number with its scale normalised, so `1.5` ties `1.50` |
///
/// A reference to each is `Orderable` too. An order index reads its value
/// in place, so it also asks for [`EncryptRef`], and in `Owned` mode for
/// `Zeroize` ([`target::WipeSource`]).
///
/// Bytes have no order term. No ordering operator compares bytes, so such
/// a term would answer no query, and would still reveal the order of the
/// rows. vitaminc-ore orders bytes only into a target that is named, and
/// this crate does not name one.
///
/// A `bool`, a `u8` and an `i8` have no target. An order term over a domain
/// that small tells anyone holding the column too much: with two values it
/// says which rows are `true`, and with 256 it puts every row in one of
/// 256 ranks, which a few known rows resolve to the values. Each keeps its
/// equality term.
///
/// ```compile_fail
/// use stack_encrypt::sem::OreTerm;
///
/// let _: Option<OreTerm<bool>> = None; // `bool` is not `Orderable`
/// ```
///
/// ```compile_fail
/// use stack_encrypt::sem::OpeTerm;
///
/// let _: Option<OpeTerm<u8>> = None; // `u8` is not `Orderable`
/// ```
///
/// ```compile_fail
/// use stack_encrypt::sem::OreTerm;
///
/// let _: Option<OreTerm<Vec<u8>>> = None; // bytes are not `Orderable`
/// ```
pub use vitaminc_ore::Orderable;
// The vitaminc 0.4 names, deprecated there; re-exported for one transition so
// a caller that spelled them keeps compiling with a warning.
#[allow(deprecated)]
pub use vitaminc_aead::{Aad, AadPiece};

// Likewise the PRF context surface, so a caller who needs the PRF view of a
// context has no direct `vitaminc-prf` dependency for it.
pub use vitaminc_prf::IntoPrfContext;
#[allow(deprecated)]
pub use vitaminc_prf::PrfContext;

// The nonempty proof used by searchable targets, built with `nonempty!`
// (a literal, checked at compile time) or `NonEmpty::new` (a runtime value,
// checked once); `MaybeEmpty` is what a context type of your own implements
// to be wrapped. `#[derive(EncryptTarget)]` names these through this crate.
pub use vitaminc_protected::{nonempty, nonempty_bytes, EmptyError, MaybeEmpty, NonEmpty};

// And the wrapper plaintext comes back in (`ValueFrame::into_inner`, a
// decrypted `Protected<T>`), with the trait that reads it, and the wiping
// buffer the re-exported frame writer writes into (`dynamic::frame`). The
// frame readers take a `ProtectedRef` of bytes, which that buffer lends
// through `AsProtectedRef`.
pub use vitaminc_protected::{AsProtectedRef, Buffer, Controlled, Protected, ProtectedRef};
