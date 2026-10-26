#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod aad;
mod ciphertext;
mod container;
mod context;
mod encrypt_sink;
pub mod frame;
#[cfg(feature = "hlist")]
#[cfg_attr(docsrs, doc(cfg(feature = "hlist")))]
pub mod hlist;
pub mod leaf;
mod nonce;
pub mod plaintext;
pub mod seal;
pub mod shape;
pub mod tags;
#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
mod timestamp;
pub mod typed;
mod unspecified;
mod walk;

// The data model: sources, sinks and the scalar kinds.
#[doc(inline)]
pub use plaintext::{
    Bytes, Encrypt, FixedType, Float, Int, Kind, KnownLogical, Logical, MapSink, Physical, Raw,
    SeqSink, Sink, SourceError, Tee, TimeUnit, UnknownLogical, UnknownLogicalId, Width,
};
/// Derive [`Encrypt`] for a struct or a fieldless enum. A struct walks as
/// a map keyed by field name; a fieldless enum as an int leaf holding the
/// variant's discriminant. Pair it with [`Decrypt`] to read the value back.
/// Inlined so the `#[aead(...)]` reference renders here.
#[doc(inline)]
pub use vitaminc_aead_derive::Encrypt;
// Encryption: the sink, the ciphers and the entry points.
#[doc(inline)]
pub use encrypt_sink::{encrypt, encrypt_async, plan, EncryptError, EncryptSink};
#[doc(inline)]
pub use seal::{AsyncCipher, Cipher, Node, Opened, Pending};
#[doc(inline)]
pub use shape::{Refusal, Unencryptable};
// Decryption: typed targets, and sinks of any kind.
#[doc(inline)]
pub use typed::{decrypt, decrypt_async, DecodeError, Decrypt, DecryptProtected, FromScalar};
#[doc(inline)]
pub use walk::{decrypt_into, decrypt_into_async, decrypt_to_frame, walk, DecryptError};
// The frame: a value as transport bytes, and back.
#[doc(inline)]
pub use frame::{to_frame, Frame, FrameWriter, PassthroughFrame};
// A UTC instant that always encrypts.
#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
#[doc(inline)]
pub use timestamp::{LeapSecond, Timestamp};

#[doc(inline)]
#[allow(deprecated)]
pub use aad::{Aad, AadPiece};
pub use aad::{Context, ContextPiece, IntoAad, IntoContext, LeafTypeAad};
#[doc(inline)]
pub use ciphertext::{CipherTextBuilder, LocalCipherText, WIRE_VERSION};
#[doc(inline)]
pub use container::CipherText;
#[doc(inline)]
pub use context::ContextTag;
#[doc(inline)]
pub use nonce::{Nonce, NonceGenerator, RandomNonceGenerator};
#[doc(inline)]
pub use unspecified::Unspecified;
