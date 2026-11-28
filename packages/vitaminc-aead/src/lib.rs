// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//! [`AsyncCipher`]: crate::AsyncCipher
//! [`CipherText`]: crate::CipherText
//! [`Cipher`]: crate::Cipher
//! [`ContextTag`]: crate::ContextTag
//! [`Decrypt`]: trait@crate::Decrypt
//! [`Encrypt`]: trait@crate::Encrypt
//! [`FrameWriter`]: crate::FrameWriter
//! [`Frame`]: crate::Frame
//! [`IntoAad`]: crate::IntoAad
//! [`LeafTypeAad`]: crate::LeafTypeAad
//! [`PassthroughFrame`]: crate::PassthroughFrame
//! [`Scalar`]: trait@crate::Scalar
//! [`Sink::passthrough`]: crate::Sink::passthrough
//! [`Sink`]: crate::Sink
//! [`Tee`]: crate::Tee
//! [`Unspecified`]: crate::Unspecified
//! [`decrypt_async`]: crate::decrypt_async
//! [`decrypt_into`]: crate::decrypt_into
//! [`decrypt`]: crate::decrypt
//! [`encrypt_async`]: crate::encrypt_async
//! [`encrypt`]: crate::encrypt
//! [`to_frame`]: crate::to_frame
//!
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
mod aad;
mod ciphertext;
mod container;
mod context;
#[cfg(feature = "jiff")]
mod date_value;
#[cfg(feature = "rust_decimal")]
mod decimal_value;
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
#[cfg(feature = "jiff")]
#[cfg_attr(docsrs, doc(cfg(feature = "jiff")))]
mod timestamp;
pub mod typed;
mod unspecified;
#[cfg(feature = "uuid")]
mod uuid_value;
mod walk;

// The data model: sources, sinks and the scalar kinds.
#[doc(inline)]
pub use plaintext::{
    Bytes, Encrypt, EncryptRef, FixedType, Float, Int, Kind, KnownLogical, Lent, Logical, MapSink,
    ParseValueKindError, Physical, Raw, Scalar, SealedNull, SeqSink, Sink, SourceError, Tee,
    TimeUnit, UnknownLogical, UnknownLogicalId, ValueKind, Width,
};
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
pub use frame::{to_frame, Frame, FrameWriter, OwnedFrame, PassthroughFrame};
// Wipeable scalars: a UTC instant that always encrypts, and a date, a
// decimal and a uuid, each the leaf of the type it wraps.
#[cfg(feature = "jiff")]
pub use date_value::Date;
#[cfg(feature = "rust_decimal")]
pub use decimal_value::Decimal;
#[cfg(feature = "jiff")]
#[cfg_attr(docsrs, doc(cfg(feature = "jiff")))]
#[doc(inline)]
pub use timestamp::{OutOfRange, Timestamp};
#[cfg(feature = "uuid")]
pub use uuid_value::Uuid;

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

/// The items that the code of Stack Encrypt's `#[derive(Encrypt)]` and
/// `#[derive(Decrypt)]` names. Not an API: `stack_encrypt` re-exports this
/// module, and the generated code reaches it as `stack_encrypt::__derive`.
/// The module contains exactly what the generated code uses, so the derives
/// reach nothing else in this crate.
#[doc(hidden)]
pub mod __derive {
    pub use crate::plaintext::sources::discard_one;
    pub use crate::plaintext::{
        depth, Encrypt, EncryptRef, FixedType, Int, Logical, MapSink, Physical, Scalar, Sink, Width,
    };
    pub use crate::typed::{
        Clear, DecodeError, Decrypt, Either, Forward, FromScalar, Never, Nothing, Rewrap, Slot,
        Wrapped,
    };
}
