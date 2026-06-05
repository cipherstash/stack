#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! `stack-encrypt` bridges ZeroKMS data keys into the vitaminc encryption
//! ecosystem.
//!
//! [`ZeroKmsCipher`] implements the vitaminc [`Cipher`](vitaminc_aead::Cipher)
//! trait and decrypts via the [`Decrypt`](vitaminc_aead::Decrypt) trait, but —
//! unlike a fixed-key cipher — every leaf of a value is sealed under its own
//! ZeroKMS data key, fetched lazily. Encrypting builds a pending tree with no
//! I/O; a single batched `generate_keys` call then seals it. Decrypting batches
//! one `retrieve_keys` call, then drives the value's `Decrypt` impl over the
//! recovered plaintext, so arbitrary nested `Vec` / `HashMap` / `Option` /
//! `Protected` values round-trip exactly as with `vitaminc_encrypt::Aes256Cipher`.
//!
//! The data keys are sourced through a [`stack_kms::DataKeySource`]
//! (production: `stack_kms::StackKms`; tests: `stack_kms::FakeDataKeySource`).
//!
//! ```no_run
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::ZeroKmsCipher;
//! use stack_kms::FakeDataKeySource;
//!
//! let cipher = ZeroKmsCipher::new(FakeDataKeySource::new());
//!
//! let ciphertext = cipher.encrypt("secret message".to_string(), ()).await?;
//! let plaintext: String = cipher.decrypt(ciphertext, ()).await?;
//!
//! assert_eq!(plaintext, "secret message");
//! # Ok(())
//! # }
//! ```

mod cipher;

pub use cipher::{DataKeyCipherText, Error, PendingCipherText, ZeroKmsCipher, ZeroKmsCipherText};

// Re-export the vitaminc AEAD surface callers need to drive the cipher, so they
// don't have to depend on `vitaminc-aead` directly for the common path.
pub use vitaminc_aead::{Aad, Cipher, ContextTag, Decrypt, Encrypt, IntoAad, Unspecified};
