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
mod encrypt_sink;
pub mod frame;
#[cfg(feature = "hlist")]
pub mod hlist;
pub mod leaf;
mod nonce;
mod passthrough;
pub mod plaintext;
pub mod seal;
pub mod tags;
#[cfg(test)]
mod test_util;
pub mod typed;
mod walk;

#[doc(inline)]
pub use encrypt_sink::{encrypt, encrypt_async, plan, EncryptError, EncryptSink, Unencryptable};
#[doc(inline)]
pub use frame::{to_frame, Frame, FrameWriter, PassthroughFrame};
#[doc(inline)]
pub use plaintext::{
    Bytes, Float, Int, Logical, MapSink, Physical, Plaintext, Raw, SeqSink, Sink, SourceError, Tee,
    TimeUnit, UnknownLogical,
};
#[doc(inline)]
pub use seal::{Node, Opened, Pending};
#[doc(inline)]
pub use typed::{decrypt, decrypt_async, DecodeError, DecryptProtected, FromScalar};
#[doc(inline)]
pub use walk::{decrypt_into, decrypt_into_async, decrypt_to_frame, walk, DecryptError};

#[doc(inline)]
#[allow(deprecated)]
pub use aad::{Aad, AadPiece};
pub use aad::{Context, ContextPiece, IntoAad, IntoContext};
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

#[doc(inline)]
pub use passthrough::Passthrough;
