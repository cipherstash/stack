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
//! [`StackCipher`] encrypts any value that implements [`Encrypt`] (`String`,
//! `Vec<T>`, `HashMap<K, V>`, `Option<T>`, `Protected<T>`, your own types, and
//! any nesting of them) and decrypts back into any [`Decrypt`] type. Every
//! scalar inside the value is sealed under its **own** ZeroKMS data key, so each
//! value access is an individually auditable key retrieval — there is no
//! long-lived key in your process.
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

let ciphertext = cipher.encrypt("secret message".to_string(), ()).await?;
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
//! The second argument is the *associated data* (AAD): anything that implements
//! [`IntoAad`] — `()`, `&[u8]`, `&str`, a tuple, or a derived [`Aad`]. It is
//! authenticated, not encrypted, and must be supplied identically on decrypt.
//! Use it to bind a ciphertext to its context (a table name, a tenant, a record
//! id) so it cannot be replayed elsewhere:
//!
//! ```no_run
//! # async fn example<K: stack_kms::DataKeySource>(cipher: stack_encrypt::StackCipher<K>) -> Result<(), stack_encrypt::Error> {
//! let ct = cipher.encrypt("4111 1111 1111 1111".to_string(), "users/42/card").await?;
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
//! let ct = cipher.encrypt(vec!["a".to_string(), "b".to_string()], ()).await?;
//! let pt: Vec<String> = cipher.decrypt(ct, ()).await?;
//! assert_eq!(pt, vec!["a", "b"]);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! # Storing ciphertext
//!
//! [`encrypt`](StackCipher::encrypt) returns a [`StackCipherText`]: a tree whose
//! shape mirrors the value (a scalar is a single leaf, a `Vec` a sequence of
//! leaves, a map a set of named leaves) and whose leaves are [`SealedValue`]s.
//! A `SealedValue` is the persistable unit: its canonical, frozen byte
//! encoding is [`to_bytes`](SealedValue::to_bytes) /
//! [`from_bytes`](SealedValue::from_bytes) — the format a database column
//! holds and every language binding reads. For callers that manage their own
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
//! sealed markers rather than inferable from structure. A tampered, re-homed,
//! or wrong-context ciphertext fails with [`Error::Aead`]; a failed or denied
//! key retrieval surfaces as [`Error::Kms`].
//!
//! For one-row reads of a batch-encrypted collection, decrypt as
//! [`Element<T>`](Element) under the same AAD used for the whole collection.
//! For finer control (custom `Decrypt` drivers, manual AAD derivations) use
//! [`StackCipher::decipher`] and drive the returned [`StackDecipher`] yourself.
//!
//! # Relationship to vitaminc
//!
//! `StackCipher` is a vitaminc [`Cipher`]; everything a vitaminc cipher can
//! encrypt, it can encrypt, and the AEAD, AAD derivations and leaf wire format
//! are vitaminc's (`vitaminc_encrypt::Aes256Cipher`, AES-256-GCM under a random
//! per-leaf nonce vitaminc generates itself). The ZeroKMS `iv` a [`SealedValue`]
//! carries is *not* that nonce: it identifies the data key, and is sent back to
//! ZeroKMS with the key `tag` to re-derive it. The types a caller needs from
//! vitaminc are re-exported here. The [`cipher`] module docs describe the
//! internals (batching, AAD derivation, wire format).

pub mod cipher;
pub mod sem;
pub mod target;

pub use cipher::{
    BoxedPassthrough, Error, FromEnv, LeafBytesError, PendingStackCipherText, SealedValue,
    StackCipher, StackCipherBuilder, StackCipherText, StackDecipher,
};
pub use target::{
    DecryptContext, DecryptField, DecryptFrom, DecryptInto, DecryptTarget, Decryptable,
    EncryptContext, EncryptFrom, EncryptInto, EncryptTarget, Pending, PendingFuture, Request,
    Responses, SuppliedContext,
};

// Re-export the vitaminc AEAD surface callers need to drive the cipher, so they
// don't have to depend on `vitaminc-aead` directly for the common path.
pub use vitaminc_aead::{
    Aad, Cipher, CipherText, ContextTag, Decipher, Decrypt, Element, Encrypt, IntoAad, Unspecified,
};

// Likewise the PRF context surface: a context newtype (the `SuppliedContext`
// opt-in recipe) needs `IntoPrfContext` alongside `IntoAad`, and should not
// need a direct `vitaminc-prf` dependency for it.
pub use vitaminc_prf::{IntoPrfContext, PrfContext};
