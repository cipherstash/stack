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

let ciphertext = keyset.encrypt("secret message".to_string(), ()).await?;
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
//! `keyset`, which then refuses leaves from any other keyset. A client may use
//! many keysets, one per tenant say; [`StackCipher::keyset`] selects any of
//! them by id or name, loading it on first use. The [`keyset`](crate::keyset)
//! module docs lay out the model.
//!
//! The second argument is the *associated data* (AAD): anything that implements
//! [`IntoAad`] — `()`, `&[u8]`, `&str`, a tuple, or a derived [`Aad`]. It is
//! authenticated, not encrypted, and must be supplied identically on decrypt.
//! Use it to bind a ciphertext to its context (a table name, a tenant, a record
//! id) so it cannot be replayed elsewhere:
//!
//! ```no_run
//! # async fn example<K: stack_kms::DataKeySource>(cipher: stack_encrypt::StackCipher<K>) -> Result<(), stack_encrypt::Error> {
//! # let keyset = cipher.default_keyset();
//! let ct = keyset.encrypt("4111 1111 1111 1111".to_string(), "users/42/card").await?;
//! let card: String = cipher.decrypt(ct, "users/42/card").await?; // ok
//! # Ok(())
//! # }
//! ```
//!
//! # Testing without ZeroKMS
//!
//! `stack_kms::FakeDataKeySource` is an in-memory stub that needs no
//! credentials or network: it hands out a fresh random data key per request and
//! remembers it in memory, so a `generate` followed by the matching `retrieve`
//! round-trips within one process (the key material itself differs run to run,
//! and nothing survives the process). It models none of ZeroKMS's
//! authorization behaviour (context, identity claims, decryption policies) —
//! those are the service's, and tests of them belong against a real ZeroKMS.
//! It lives behind stack-kms's `test-support` feature, so add
//! `stack-kms = { version = "..", features = ["test-support"] }` to your
//! `[dev-dependencies]`:
//!
//! ```
//! use stack_encrypt::StackCipher;
//! use stack_kms::FakeDataKeySource;
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
//! [`Element<T>`](Element) under the same AAD used for the whole collection.
//! For finer control (custom `Decrypt` drivers, manual AAD derivations) use
//! [`StackCipher::decipher`] and drive the returned [`StackDecipher`] yourself.
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

pub mod cipher;
pub mod descriptor;
pub mod keyset;
pub mod sem;
pub mod target;

pub use cipher::{
    BoxedPassthrough, Error, FromEnv, LeafBytesError, PendingStackCipherText, SealedValue,
    StackCipher, StackCipherBuilder, StackCipherText, StackDecipher,
};
pub use descriptor::Descriptor;
pub use keyset::KeysetCipher;
pub use target::{
    CipherScope, DecryptField, DecryptFrom, DecryptInto, DecryptTarget, Decryptable,
    ElementContext, EncryptFrom, EncryptInto, EncryptTarget, Pending, PendingFuture, Request,
    Responses,
};

// Re-export the vitaminc AEAD surface callers need to drive the cipher, so they
// don't have to depend on `vitaminc-aead` directly for the common path.
pub use vitaminc_aead::{
    Aad, AadPiece, Cipher, CipherText, ContextTag, Decipher, Decrypt, Element, Encrypt, IntoAad,
    Unspecified,
};

// Likewise the PRF context surface: a context type of your own implements
// `IntoPrfContext` alongside `IntoAad`, and should not need a direct
// `vitaminc-prf` dependency for it.
pub use vitaminc_prf::{IntoPrfContext, PrfContext};

// And the proof every target-directed leaf asks for: a `NonEmpty<T>` is what
// `encrypt_into_with_context` / `decrypt_into` take, built with `nonempty!`
// (a literal, checked at compile time) or `NonEmpty::new` (a runtime value,
// checked once); `MaybeEmpty` is what a context type of your own implements
// to be wrapped. `#[derive(EncryptFrom)]` names these through this crate.
pub use vitaminc_protected::{nonempty, nonempty_bytes, EmptyError, MaybeEmpty, NonEmpty};
