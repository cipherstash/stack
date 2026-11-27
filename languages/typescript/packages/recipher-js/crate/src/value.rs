//! A value that the engine encrypts as one leaf.
//!
//! The engine is the Stack Encrypt engine, the `stack-encrypt` crate. A
//! leaf is one value that the engine encrypts as a single ciphertext.

use stack_encrypt::dynamic::plaintext::{depth, Error as _, Scalar, Sink, SourceError};
use stack_encrypt::dynamic::{frame::OwnedFrame, ValueKind};
use stack_encrypt::Encrypt;
use vitaminc_protected::OpaqueDebug;

use crate::error::{Error, RecipherErrorFields};

/// A value checked to be one string.
///
/// The engine encrypts the value through its opaque scalar path. That path
/// encrypts a whole value as one leaf. Rust's `keyset.encrypt(value)` uses
/// the same path. So each ciphertext has the form that Rust and Go write
/// for the same value.
///
/// The engine encrypts a value as one opaque leaf only when its type
/// implements `Scalar`, a trait of vitaminc, CipherStash's cryptography
/// library. An [`OwnedFrame`] can contain any value of the engine's value
/// model, the set of value types the engine reads. So an [`OwnedFrame`] is
/// not a `Scalar`. This type checks that the frame contains one string. The
/// check runs once, before the engine reads the value.
///
/// The opaque path also needs a value it can wipe (`Zeroize`). Wiping drops
/// the frame, and the frame wipes its own buffer when it drops. `Debug`
/// hides the value.
#[derive(OpaqueDebug)]
pub(crate) struct OneValue(Option<OwnedFrame>);

impl OneValue {
    /// Returns `value` as a [`OneValue`], if it is one string.
    ///
    /// # Errors
    ///
    /// Returns `recipher_js::not_a_string` for any other value.
    pub(crate) fn new(value: OwnedFrame) -> Result<Self, RecipherErrorFields> {
        if value.frame().kind() == Some(ValueKind::String) {
            Ok(Self(Some(value)))
        } else {
            Err(Error::NotAString.into())
        }
    }
}

impl zeroize::Zeroize for OneValue {
    fn zeroize(&mut self) {
        // Dropping the frame wipes its buffer.
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

#[cfg(test)]
mod tests {
    use super::OneValue;
    use stack_encrypt::dynamic::frame::OwnedFrame;

    #[test]
    fn a_string_is_one_value_and_another_value_is_not() {
        assert!(OneValue::new(OwnedFrame::of("text").unwrap()).is_ok());
        let refused = OneValue::new(OwnedFrame::of(5i64).unwrap()).unwrap_err();
        assert_eq!(refused.code, "recipher_js::not_a_string");
    }

    #[test]
    fn debug_hides_the_value() {
        let value = OneValue::new(OwnedFrame::of("secret").unwrap()).unwrap();
        assert!(!format!("{value:?}").contains("secret"));
    }
}
