//! A value the engine seals as one leaf.

use stack_encrypt::dynamic::plaintext::{depth, Error as _, Scalar, Sink, SourceError};
use stack_encrypt::dynamic::{ValueFrame, ValueKind};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::Encrypt;
use vitaminc_protected::OpaqueDebug;

use crate::error::{Error, RecipherErrorFields};

/// A value checked to be one leaf: one scalar of the value model, or a JSON
/// document. The engine seals it through its opaque scalar path, as Rust's
/// `keyset.encrypt(value)` does, so each ciphertext is the one Rust and Go
/// write for the same value.
///
/// The engine seals a value as one opaque leaf only when its type is one of
/// vitaminc's scalars (`Scalar`). A [`ValueFrame`] can hold any value of the
/// model, an array or a map too, so it is not one; this type is the check
/// that it holds one scalar, made once, before the engine sees it. The
/// engine's opaque path also needs a value it can wipe (`Zeroize`): wiping
/// drops the value, which wipes its own buffer. `Debug` hides the value.
#[derive(OpaqueDebug)]
pub(crate) struct OneValue(Option<Leaf>);

/// What a [`OneValue`] holds.
#[derive(OpaqueDebug)]
enum Leaf {
    Scalar(ValueFrame),
    Json(JsonPlaintext),
}

impl OneValue {
    /// `value`, if it is one scalar.
    ///
    /// # Errors
    ///
    /// `recipher::not_a_scalar` for an array, `recipher::plain_object` for an
    /// object.
    pub(crate) fn scalar(value: ValueFrame) -> Result<Self, RecipherErrorFields> {
        match value.kind() {
            Some(ValueKind::Array) => Err(Error::NotAScalar.into()),
            Some(ValueKind::Object) => Err(Error::PlainObject.into()),
            _ => Ok(Self(Some(Leaf::Scalar(value)))),
        }
    }

    /// A JSON document, sealed as the engine's `JsonPlaintext` is: as its
    /// JSON text.
    pub(crate) fn json(document: JsonPlaintext) -> Self {
        Self(Some(Leaf::Json(document)))
    }
}

impl zeroize::Zeroize for OneValue {
    fn zeroize(&mut self) {
        // Each leaf wipes its buffer when it is dropped.
        self.0 = None;
    }
}

impl Encrypt for &OneValue {
    const DEPTH: Option<usize> = depth::SCALAR;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(Leaf::Scalar(frame)) => frame.visit(sink),
            Some(Leaf::Json(document)) => document.visit(sink),
            None => Err(S::Error::source(SourceError::msg("a wiped value"))),
        }
    }
}

impl Scalar for &OneValue {}

#[cfg(test)]
mod tests {
    use super::OneValue;
    use stack_encrypt::dynamic::ValueFrame;

    #[test]
    fn a_scalar_is_one_value_and_a_container_is_not() {
        assert!(OneValue::scalar(ValueFrame::of("text").unwrap()).is_ok());
        assert!(OneValue::scalar(ValueFrame::of(vec![1u8, 2]).unwrap()).is_ok());
        let refused = OneValue::scalar(ValueFrame::of(vec!["a", "b"]).unwrap()).unwrap_err();
        assert_eq!(refused.code, "recipher::not_a_scalar");
    }

    #[test]
    fn debug_hides_the_value() {
        let value = OneValue::scalar(ValueFrame::of("secret").unwrap()).unwrap();
        assert!(!format!("{value:?}").contains("secret"));
    }
}
