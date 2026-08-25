#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod aad;
mod cipher;
mod ciphertext;
mod container;
mod context;
mod decipher;
mod decrypt;
mod element;
mod encrypt;
#[cfg(feature = "hlist")]
pub mod hlist;
mod nonce;
#[cfg(test)]
mod test_util;

#[doc(inline)]
pub use aad::{Aad, IntoAad};
#[doc(inline)]
pub use cipher::{Cipher, MapCipher, SeqCipher, Unspecified};
#[doc(inline)]
pub use ciphertext::{CipherTextBuilder, LocalCipherText, WIRE_VERSION};
#[doc(inline)]
pub use container::CipherText;
#[doc(inline)]
pub use context::ContextTag;
#[doc(inline)]
pub use decipher::{Decipher, DecipherVisitor, MapAccess, SeqAccess};
#[doc(inline)]
pub use decrypt::Decrypt;
#[doc(inline)]
pub use element::Element;
#[doc(inline)]
pub use encrypt::Encrypt;
#[doc(inline)]
pub use nonce::{Nonce, NonceGenerator, RandomNonceGenerator};
// Inlined rather than linked, so the macros' own documentation — the
// `#[aead(...)]` reference in particular — renders here instead of sending the
// reader to another crate. There is still only one copy of that text.
#[doc(inline)]
pub use vitaminc_aead_derive::{Decrypt, Encrypt};
