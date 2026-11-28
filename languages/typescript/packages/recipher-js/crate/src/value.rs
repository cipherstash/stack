//! A value that the engine encrypts as one leaf.
//!
//! The engine is the Stack Encrypt engine, the `stack-encrypt` crate. A
//! leaf is one value that the engine encrypts as a single ciphertext.

use stack_encrypt::dynamic::plaintext::{depth, Error as _, Scalar, Sink, SourceError};
use stack_encrypt::dynamic::{frame::OwnedFrame, ValueKind};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::Encrypt;
use vitaminc_protected::OpaqueDebug;

use crate::error::{Error, RecipherErrorFields};

/// A value checked to be one leaf: one scalar of the engine's value model,
/// or one JSON document.
///
/// The value model is the set of value types the engine reads. A scalar is
/// a value of the model that is not an array or a map, such as text, a
/// number, or bytes.
///
/// The engine encrypts the value through its opaque scalar path. That path
/// encrypts a whole value as one leaf. Rust's `keyset.encrypt(value)` uses
/// the same path. So each ciphertext has the form that Rust's
/// `keyset.encrypt` writes for the same value.
///
/// The engine encrypts a value as one opaque leaf only when its type
/// implements `Scalar`, a trait of the `vitaminc-aead` crate. An
/// [`OwnedFrame`] can contain any value of the model, including an array or
/// a map. So an [`OwnedFrame`] is not a `Scalar`. This type checks that the
/// frame contains one scalar. The check runs once, before the engine reads
/// the value.
///
/// The opaque path also needs a value it can wipe (`Zeroize`). Wiping drops
/// the value, and the value wipes its own buffer when it drops. `Debug`
/// hides the value.
#[derive(OpaqueDebug)]
pub(crate) struct OneValue(Option<Leaf>);

/// The value inside a [`OneValue`]: a scalar, or a JSON document.
#[derive(OpaqueDebug)]
enum Leaf {
    Scalar(OwnedFrame),
    Json(JsonPlaintext),
}

impl OneValue {
    /// Returns `value` as a [`OneValue`], if it is one scalar.
    ///
    /// # Errors
    ///
    /// Returns `recipher_js::not_a_scalar` for an array, and
    /// `recipher_js::plain_object` for an object.
    pub(crate) fn scalar(value: OwnedFrame) -> Result<Self, RecipherErrorFields> {
        match value.frame().kind() {
            Some(ValueKind::Array) => Err(Error::NotAScalar.into()),
            Some(ValueKind::Object) => Err(Error::PlainObject.into()),
            _ => Ok(Self(Some(Leaf::Scalar(value)))),
        }
    }

    /// Returns a JSON document as a [`OneValue`]. The engine encrypts it as
    /// it encrypts any `JsonPlaintext`: as its JSON text.
    pub(crate) fn json(document: JsonPlaintext) -> Self {
        Self(Some(Leaf::Json(document)))
    }
}

impl zeroize::Zeroize for OneValue {
    fn zeroize(&mut self) {
        // Dropping the leaf wipes its buffer.
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
    use stack_encrypt::dynamic::frame::OwnedFrame;

    #[test]
    fn a_scalar_is_one_value_and_a_container_is_not() {
        assert!(OneValue::scalar(OwnedFrame::of("text").unwrap()).is_ok());
        assert!(OneValue::scalar(OwnedFrame::of(vec![1u8, 2]).unwrap()).is_ok());
        let refused = OneValue::scalar(OwnedFrame::of(vec!["a", "b"]).unwrap()).unwrap_err();
        assert_eq!(refused.code, "recipher_js::not_a_scalar");
    }

    #[test]
    fn debug_hides_the_value() {
        let value = OneValue::scalar(OwnedFrame::of("secret").unwrap()).unwrap();
        assert!(!format!("{value:?}").contains("secret"));
    }
}
