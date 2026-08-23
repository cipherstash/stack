#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
#![deny(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::mem_forget,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo,
    clippy::unimplemented
)]
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
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use stack_encrypt::StackCipher;
//! use stack_kms::StackKmsBuilder;
//!
//! // Credentials and the client key come from the environment
//! // (CS_CLIENT_ID / CS_CLIENT_KEY, plus an access token strategy).
//! let kms = StackKmsBuilder::auto()?
//!     .with_key_provider(stack_kms::EnvKeyProvider)
//!     .build()
//!     .await?;
//! let cipher = StackCipher::new(kms);
//!
//! let ciphertext = cipher.encrypt("secret message".to_string(), ()).await?;
//! let plaintext: String = cipher.decrypt(ciphertext, ()).await?;
//! assert_eq!(plaintext, "secret message");
//! # Ok(())
//! # }
//! ```
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
//! `stack_kms::FakeDataKeySource` is a deterministic in-process key source that
//! needs no credentials or network. It lives behind stack-kms's `test-support`
//! feature, so add
//! `stack-kms = { version = "..", features = ["test-support"] }` to your
//! `[dev-dependencies]`:
//!
//! ```no_run
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::StackCipher;
//! use stack_kms::FakeDataKeySource;
//!
//! let cipher = StackCipher::new(FakeDataKeySource::new());
//! let ct = cipher.encrypt(vec!["a".to_string(), "b".to_string()], ()).await?;
//! let pt: Vec<String> = cipher.decrypt(ct, ()).await?;
//! assert_eq!(pt, vec!["a", "b"]);
//! # Ok(())
//! # }
//! ```
//!
//! # Storing ciphertext
//!
//! [`encrypt`](StackCipher::encrypt) returns a [`StackCipherText`]: a tree whose
//! shape mirrors the value (a scalar is a single leaf, a `Vec` a sequence of
//! leaves, a map a set of named leaves) and whose leaves are [`SealedValue`]s.
//! A `SealedValue` is the persistable unit — it implements `serde`
//! `Serialize`/`Deserialize` and offers [`into_parts`](SealedValue::into_parts)
//! / [`from_parts`](SealedValue::from_parts) for callers that manage their own
//! storage format. Map keys are stored in the clear (and authenticated);
//! nothing else about a value is visible without its data keys.
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
//! are vitaminc's (`vitaminc_encrypt::Aes256Cipher`, AES-256-GCM). The types a
//! caller needs from vitaminc are re-exported here. The module-level docs in
//! `src/cipher.rs` describe the internals (batching, AAD derivation, wire
//! format).

mod cipher;

pub use cipher::{
    BoxedPassthrough, Error, PendingStackCipherText, SealedValue, StackCipher, StackCipherText,
    StackDecipher,
};

// Re-export the vitaminc AEAD surface callers need to drive the cipher, so they
// don't have to depend on `vitaminc-aead` directly for the common path.
pub use vitaminc_aead::{
    Aad, Cipher, CipherText, ContextTag, Decipher, Decrypt, Element, Encrypt, IntoAad, Unspecified,
};
