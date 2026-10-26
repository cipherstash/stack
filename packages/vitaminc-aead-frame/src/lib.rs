// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//! [`CodecError`]: crate::CodecError
//! [`FrameError`]: crate::FrameError
//! [`FrameWriter`]: crate::FrameWriter
//! [`Frame`]: crate::Frame
//! [`MAX_DEPTH`]: crate::MAX_DEPTH
//! [`PassthroughFrame`]: crate::PassthroughFrame
//! [`decode_ciphertext`]: crate::decode_ciphertext
//! [`encode_ciphertext`]: crate::encode_ciphertext
//! [`tags`]: crate::tags
//! [`to_frame`]: crate::to_frame
//!
// Workspace crates release together; keep cross-crate links on that version.
#![doc = concat!(
    "\n[`CipherText`]: https://docs.rs/vitaminc-aead/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_aead/enum.CipherText.html\n",
    "\n[`Encrypt`]: https://docs.rs/vitaminc-aead/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_aead/trait.Encrypt.html\n",
    "\n[`Sink`]: https://docs.rs/vitaminc-aead/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_aead/trait.Sink.html\n",
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
pub mod transport;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod serde;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod storage;

pub use transport::{decode_ciphertext, encode_ciphertext, CodecError};
/// The frame: a value as transport bytes, and back. These live in
/// `vitaminc-aead` next to the leaf codec they share, and are re-exported
/// here so a binding that depends on this crate has the whole transport.
pub use vitaminc_aead::frame::{
    FrameError, FrameWriteError, ARRAY, MAX_DEPTH, OBJECT, PASSTHROUGH,
};
/// The leaf tag table, which lives with the leaf codec in `vitaminc-aead`.
pub use vitaminc_aead::tags;
pub use vitaminc_aead::{to_frame, Frame, FrameWriter, PassthroughFrame};
