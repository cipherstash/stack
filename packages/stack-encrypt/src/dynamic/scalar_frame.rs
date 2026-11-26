//! [`ScalarFrame`]: a [`ValueFrame`] checked to hold one scalar, so it seals
//! as one opaque [`Ciphertext`](crate::Ciphertext).

use std::fmt;

use vitaminc_aead::plaintext::{depth, Scalar, Sink};
use vitaminc_aead::Encrypt;
use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroize;

use super::{ValueFrame, ValueKind};

/// A [`ValueFrame`] that holds one scalar of the value model: what one
/// opaque [`Ciphertext`](crate::Ciphertext) seals.
///
/// `keyset.encrypt(value)` seals a value as one leaf when the value's borrow
/// implements vitaminc's [`Scalar`] marker. A [`ValueFrame`] can hold any
/// value of the [value model](ValueFrame#the-value-model), an array or a map
/// included, so it is not a `Scalar`. A `ScalarFrame` is one: its value was
/// checked, when it was built, to be one scalar (a null, an `undefined`, a
/// boolean, an integer, a float, text, bytes, a date, a timestamp or a
/// decimal).
///
/// ```
/// use stack_encrypt::dynamic::{ScalarFrame, ValueFrame, ValueKind};
/// use stack_encrypt::{Ciphertext, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// // The value as a binding hands it over: one value, as its frame.
/// let value = ScalarFrame::new(ValueFrame::of("alice")?)?;
/// let stored: Ciphertext = keyset.encrypt_with_context(value, "users/name").await?;
///
/// // It opens into a frame of the kind it was sealed as.
/// let opened: ValueFrame = keyset.decrypt_with_context(stored, "users/name").await?;
/// assert_eq!(opened.kind(), Some(ValueKind::String));
///
/// // An array is not one value.
/// assert!(ScalarFrame::new(ValueFrame::of(vec!["a", "b"])?).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// Every `ScalarFrame` holds a scalar: [`new`](Self::new) refuses an
/// array, a map and a passthrough, so the check runs once, before the value
/// is read.
///
/// A null and an `undefined` are scalars. A frame does not keep a null's
/// type, so a null seals as a plain null, unpadded: its ciphertext is
/// shorter than a present value's, and its length shows that the value is
/// absent. To store a field's absent values padded to a present value's
/// length, seal the field through a record plan with `"null": "sealed"`
/// ([`FieldPlan::with_null`](super::FieldPlan::with_null)).
///
/// Its borrow implements vitaminc's [`Scalar`], and the frame can be wiped
/// ([`Zeroize`]), so `keyset.encrypt(scalar_frame)` compiles and seals the
/// value as one leaf. The leaf is the one `keyset.encrypt` seals for the
/// same Rust value under the same context: the same tagged plaintext under
/// the same associated data, so a Rust caller opens it as that type and a
/// binding opens it as a [`ValueFrame`].
///
/// The frame's bytes are kept in the [`ValueFrame`]'s protected buffer.
/// `keyset.encrypt` wipes the value before its pending result is returned:
/// wiping replaces the frame with an empty one, and the buffer that held the
/// value is wiped as it is dropped. A wiped `ScalarFrame` seals nothing; a
/// walk of it fails. `Debug` ([`OpaqueDebug`]) names the type and masks the
/// value.
#[derive(OpaqueDebug)]
pub struct ScalarFrame(ValueFrame);

impl ScalarFrame {
    /// The frame, if it holds one scalar.
    ///
    /// The frame is moved in, not copied. A refused frame is dropped, which
    /// wipes it.
    ///
    /// # Errors
    ///
    /// [`ScalarFrameError`] for an array, a map or a passthrough. The error
    /// names what the value is ([`NonScalar`]), never the value.
    pub fn new(value: ValueFrame) -> Result<Self, ScalarFrameError> {
        let found = match value.kind() {
            Some(ValueKind::Array) => Some(NonScalar::Array),
            Some(ValueKind::Object) => Some(NonScalar::Object),
            // A passthrough has no kind, as a null has none.
            _ if value.has_passthrough() => Some(NonScalar::Passthrough),
            _ => None,
        };
        match found {
            Some(found) => Err(ScalarFrameError { found }),
            None => Ok(Self(value)),
        }
    }
}

impl TryFrom<ValueFrame> for ScalarFrame {
    type Error = ScalarFrameError;

    /// As [`ScalarFrame::new`].
    fn try_from(value: ValueFrame) -> Result<Self, ScalarFrameError> {
        Self::new(value)
    }
}

/// Replace the frame with an empty one. The protected buffer that held the
/// value wipes it as it is dropped.
impl Zeroize for ScalarFrame {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Walks the frame in place: the one scalar goes straight to the sink.
impl Encrypt for &ScalarFrame {
    const DEPTH: Option<usize> = depth::SCALAR;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self.0).visit(sink)
    }
}

/// One leaf: [`ScalarFrame::new`] refused every value that is not.
impl Scalar for &ScalarFrame {}

/// Walks the frame, then drops it, which wipes it.
impl Encrypt for ScalarFrame {
    const DEPTH: Option<usize> = depth::SCALAR;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

/// One leaf, as its borrow is.
impl Scalar for ScalarFrame {}

// A `Scalar` must be one leaf deep, so the marker cannot land on a
// container.
const _: () = assert!(depth::is_scalar(<&ScalarFrame as Encrypt>::DEPTH));
const _: () = assert!(depth::is_scalar(<ScalarFrame as Encrypt>::DEPTH));

/// What a value refused by [`ScalarFrame::new`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonScalar {
    /// A sequence: `"array"`.
    Array,
    /// A map: `"object"`.
    Object,
    /// A passthrough: `"passthrough"`. It is stored in the clear, not
    /// sealed.
    Passthrough,
}

impl NonScalar {
    /// The name: `"array"` and `"object"`, as their [`ValueKind`]s are
    /// named, or `"passthrough"`.
    pub fn name(self) -> &'static str {
        match self {
            NonScalar::Array => ValueKind::Array.name(),
            NonScalar::Object => ValueKind::Object.name(),
            NonScalar::Passthrough => "passthrough",
        }
    }
}

impl fmt::Display for NonScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why [`ScalarFrame::new`] refused a value: it is an array, a map or a
/// passthrough, not one scalar.
///
/// The error names what the value is, never the value. Its code is
/// `stack_encrypt::dynamic_not_a_scalar`, and its payload is
/// `{"found": "array"}`, `"object"` or `"passthrough"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[error("a value sealed as one ciphertext must be one scalar; found {found}")]
#[diagnostic(
    code(stack_encrypt::dynamic_not_a_scalar),
    help(
        "seal an array, an object or a passthrough through a record plan (`dynamic::record::Plan`)"
    )
)]
pub struct ScalarFrameError {
    found: NonScalar,
}

impl ScalarFrameError {
    /// What the value is.
    pub fn found(&self) -> NonScalar {
        self.found
    }
}

impl crate::ErrorPayload for ScalarFrameError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        crate::diagnostic::payload([("found", self.found.name().into())])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::Tree;
    use crate::ErrorPayload as _;
    use miette::Diagnostic as _;
    use vitaminc_aead::plaintext::{Logical, TimeUnit};

    fn frame(tree: Tree) -> ValueFrame {
        ValueFrame::of(&tree).unwrap()
    }

    /// One value of every scalar kind of the model, a null, a typed null
    /// and an `undefined` among them.
    fn every_scalar() -> Vec<Tree> {
        use Tree::*;
        vec![
            Null,
            Undefined,
            Bool(true),
            Int8(-8),
            Int16(-16),
            Int32(-32),
            Int64(-64),
            Int128(-128),
            UInt8(8),
            UInt16(16),
            UInt32(32),
            UInt64(64),
            UInt128(128),
            Float32(1.5),
            Float64(-2.5),
            String("alice".into()),
            Bytes(vec![0, 1, 2]),
            Typed(Logical::Date, Box::new(Int32(20_000))),
            Typed(
                Logical::Timestamp(TimeUnit::Micros),
                Box::new(Int64(1_700_000_000_000_000)),
            ),
            Typed(Logical::Decimal { scale: 2 }, Box::new(Int128(12_345))),
        ]
    }

    mod given_a_scalar {
        use super::*;

        #[test]
        fn it_is_admitted_with_its_frame_unchanged() {
            for tree in every_scalar() {
                let value = frame(tree.clone());
                let scalar = ScalarFrame::new(frame(tree.clone()))
                    .unwrap_or_else(|e| panic!("{tree:?} is a scalar: {e}"));
                assert!(
                    ValueFrame::of(&scalar).unwrap() == value,
                    "{tree:?} walks as the frame it was built from"
                );
            }
        }

        #[test]
        fn an_absent_option_is_admitted_as_a_null() {
            let null = ValueFrame::of(None::<i64>).unwrap();
            assert!(ScalarFrame::try_from(null).is_ok(), "a null is one leaf");
        }
    }

    mod given_a_value_that_is_not_one_scalar {
        use super::*;

        fn refused(tree: Tree) -> ScalarFrameError {
            ScalarFrame::new(frame(tree.clone()))
                .err()
                .unwrap_or_else(|| panic!("{tree:?} is not one scalar"))
        }

        #[test]
        fn an_array_is_refused_as_an_array() {
            for tree in [
                Tree::Array(vec![]),
                Tree::Array(vec![Tree::String("a".into())]),
            ] {
                assert_eq!(refused(tree).found(), NonScalar::Array, "an array");
            }
        }

        #[test]
        fn a_map_is_refused_as_an_object() {
            for tree in [
                Tree::Object(vec![]),
                Tree::Object(vec![("k".into(), Tree::UInt8(1))]),
            ] {
                assert_eq!(refused(tree).found(), NonScalar::Object, "a map");
            }
        }

        #[test]
        fn a_passthrough_is_refused_as_a_passthrough() {
            let tree = Tree::Passthrough(Box::new(Tree::String("p".into())));
            assert_eq!(refused(tree).found(), NonScalar::Passthrough);
        }

        #[test]
        fn try_from_refuses_as_new_does() {
            let error = ScalarFrame::try_from(frame(Tree::Array(vec![]))).err();
            assert_eq!(error.map(|e| e.found()), Some(NonScalar::Array));
        }

        #[test]
        fn the_error_names_the_kind_and_never_the_value() {
            let marker = "marker-plaintext";
            for (tree, name) in [
                (Tree::Array(vec![Tree::String(marker.into())]), "array"),
                (
                    Tree::Object(vec![("k".into(), Tree::String(marker.into()))]),
                    "object",
                ),
                (
                    Tree::Passthrough(Box::new(Tree::String(marker.into()))),
                    "passthrough",
                ),
            ] {
                let error = refused(tree);
                let shown = format!(
                    "{error} {error:?} {:?} {:?}",
                    error.help().map(|h| h.to_string()),
                    error.payload()
                );
                assert!(!shown.contains(marker), "no plaintext: {shown}");
                assert!(error.to_string().ends_with(name), "{error}");
                assert_eq!(error.payload()["found"], name, "the payload names it");
                assert_eq!(
                    error.code().map(|c| c.to_string()).as_deref(),
                    Some("stack_encrypt::dynamic_not_a_scalar"),
                    "{error}"
                );
            }
        }
    }

    mod given_a_wiped_frame {
        use super::*;

        #[test]
        fn it_walks_nothing() {
            let mut scalar = ScalarFrame::new(frame(Tree::String("alice".into()))).unwrap();
            scalar.zeroize();
            assert!(
                ValueFrame::of(&scalar).is_err(),
                "a wiped frame holds no value to seal"
            );
        }
    }

    #[test]
    fn debug_masks_the_value() {
        let scalar = ScalarFrame::new(frame(Tree::String("marker-plaintext".into()))).unwrap();
        let shown = format!("{scalar:?}");
        assert!(!shown.contains("marker-plaintext"), "{shown}");
        assert!(shown.contains("ScalarFrame"), "{shown}");
    }
}
