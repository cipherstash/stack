//! A value the engine seals as one leaf.

use stack_encrypt::dynamic::plaintext::{depth, Error as _, Scalar, Sink, SourceError};
use stack_encrypt::dynamic::{ValueFrame, ValueKind};
use stack_encrypt::Encrypt;
use vitaminc_protected::OpaqueDebug;

use crate::error::{ErrorKind, RecipherErrorFields};

/// A value checked to be one string, so the engine seals it through its
/// opaque scalar path, as Rust's `keyset.encrypt(value)` does.
///
/// The engine seals a value as one opaque leaf only when its type is one of
/// vitaminc's scalars (`Scalar`). A [`ValueFrame`] can hold any value of the
/// model, so it is not one; this type is the check that it holds one scalar,
/// made once, before the engine sees it. The engine's opaque path also
/// needs a value it can wipe (`Zeroize`): wiping drops the frame, whose
/// buffer wipes itself. `Debug` hides the value.
#[derive(OpaqueDebug)]
pub(crate) struct OneValue(Option<ValueFrame>);

impl OneValue {
    /// `value`, if it is one string.
    ///
    /// # Errors
    ///
    /// A failure of kind `value` for any other value.
    pub(crate) fn new(value: ValueFrame) -> Result<Self, RecipherErrorFields> {
        if value.kind() == Some(ValueKind::String) {
            Ok(Self(Some(value)))
        } else {
            Err(RecipherErrorFields::new(
                ErrorKind::Value,
                "recipher::not_a_string",
                "this build encrypts a string only",
            ))
        }
    }
}

impl zeroize::Zeroize for OneValue {
    fn zeroize(&mut self) {
        // The frame wipes its buffer when it is dropped.
        self.0 = None;
    }
}

impl Encrypt for &OneValue {
    const DEPTH: Option<usize> = depth::SCALAR;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(frame) => frame.visit(sink),
            None => Err(S::Error::source(SourceError::msg("a wiped value"))),
        }
    }
}

impl Scalar for &OneValue {}
