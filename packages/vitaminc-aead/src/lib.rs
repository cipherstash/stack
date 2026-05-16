#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod aad;
mod cipher;
mod ciphertext;
mod decipher;
mod encrypt;
#[cfg(feature = "hlist")]
pub mod hlist;
mod nonce;

#[doc(inline)]
pub use aad::{Aad, IntoAad};
#[doc(inline)]
pub use cipher::{Cipher, MapCipher, SeqCipher, Unspecified};
#[doc(inline)]
pub use ciphertext::{CipherTextBuilder, LocalCipherText};
#[doc(inline)]
pub use decipher::{Decipher, DecipherVisitor, Decrypt, MapAccess, SeqAccess};
#[doc(inline)]
pub use encrypt::Encrypt;
#[doc(inline)]
pub use nonce::{Nonce, NonceGenerator, RandomNonceGenerator};
