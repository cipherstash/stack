#![deny(clippy::unwrap_used, clippy::todo, unsafe_code, unused_imports)]
#![doc = include_str!("../README.md")]
pub mod transport;

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
