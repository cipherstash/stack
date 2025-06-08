#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod aad;
mod cipher;
mod ciphertext;
mod decrypt;
mod encrypt;
mod nonce;

#[doc(inline)]
pub use aad::{Aad, IntoAad};
#[doc(inline)]
pub use cipher::Cipher;
#[doc(inline)]
pub use ciphertext::{CipherTextBuilder, LocalCipherText};
#[doc(inline)]
pub use decrypt::Decrypt;
#[doc(inline)]
pub use encrypt::Encrypt;
#[doc(inline)]
pub use nonce::{Nonce, NonceGenerator, RandomNonceGenerator};
