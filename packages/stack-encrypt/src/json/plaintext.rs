//! A JSON document as a plaintext: [`JsonPlaintext`].

use std::fmt;

use serde_json::Value;
use vitaminc_aead::plaintext::{depth, Error as _, Scalar, SourceError};
use vitaminc_aead::{FixedType, FromScalar, Logical, Physical, Sink};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::text::{parse_text, to_wiped_text};
use super::{plain, JsonTextError};
use crate::Encrypt;

/// A JSON document that is wiped when it is dropped.
///
/// `serde_json::Value` does not implement [`Zeroize`], and Rust's orphan
/// rule stops this crate adding it. `JsonPlaintext` holds a `Value` and
/// wipes it: every string, object keys included, is overwritten, every
/// number is set to zero and every boolean to `false`. Numbers and booleans
/// are overwritten best-effort, as [`wipe_value`](super::wipe_value) says.
///
/// Build one from a `Value` you already hold, or parse JSON text with
/// [`parse`](Self::parse). Read the document with [`value`](Self::value).
///
/// ```
/// use serde_json::json;
/// use stack_encrypt::json::JsonPlaintext;
///
/// let built = JsonPlaintext::from(json!({"name": "Ada", "age": 36}));
/// assert_eq!(built.value()["age"], 36);
///
/// let parsed = JsonPlaintext::parse(r#"{"name": "Ada", "age": 36}"#)?;
/// assert_eq!(parsed.value(), built.value());
/// # Ok::<(), stack_encrypt::json::JsonTextError>(())
/// ```
///
/// # One ciphertext
///
/// A `JsonPlaintext` encrypts as **one ciphertext**. It is a single value
/// to the cipher, as a `String` is, so [`KeysetCipher::encrypt`] takes one
/// and returns one [`Ciphertext`](crate::Ciphertext):
///
/// ```
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use serde_json::json;
/// use stack_encrypt::json::JsonPlaintext;
/// use stack_encrypt::StackCipher;
///
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// let profile = JsonPlaintext::from(json!({"name": "Ada", "tags": ["maths"]}));
/// let stored = keyset
///     .encrypt_with_context(profile, ("users", "profile"))
///     .await?;
///
/// let opened: JsonPlaintext = keyset
///     .decrypt_with_context(stored, ("users", "profile"))
///     .await?;
/// assert_eq!(opened.value()["tags"][0], "maths");
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
/// ```
///
/// Nothing inside the ciphertext can be searched, and all of it decrypts or
/// none of it does. To search inside a document, use the
/// [JSON index](super).
///
/// ## The stored format
///
/// The plaintext of the ciphertext is the document's **JSON text**, sealed
/// as one text leaf. It is the text `serde_json` writes: no whitespace
/// between tokens, each number in its shortest form that reads back as the
/// same number, and the members of an object in the order the `Value`
/// holds them. That is the same ciphertext as sealing a `String` that holds
/// the text.
///
/// The document is stored as values, not as the text it was parsed from.
/// So whitespace, the order of an object's members, and the spelling of a
/// number (`1.0` or `1e0`) are not kept.
///
/// ## Decryption
///
/// The ciphertext is checked before the text is parsed. The leaf is opened
/// and authenticated first. Then the text is parsed by the rules of
/// [`parse_text`]. These refusals are possible:
///
/// - [`Error::Aead`](crate::Error::Aead): the leaf did not open.
/// - [`Error::OpenedType`](crate::Error::OpenedType): the leaf opened, but
///   it does not hold a JSON document. It holds a value that is not text,
///   such as a number, or text that [`parse_text`] refuses. The ciphertext
///   is authentic. It was sealed as something else, not altered.
///
/// A leaf does not record that its text is JSON. So a `JsonPlaintext`
/// decrypted as a `String` gives the JSON text, and a `String` that holds
/// JSON text decrypts as a `JsonPlaintext`. The context is checked either
/// way, so neither lets a caller read data they could not read before.
///
/// ## What the ciphertext reveals
///
/// The ciphertext is as long as the JSON text, plus a constant. So it
/// shows the size of the document, as the ciphertext of a `String` shows
/// the length of the string. An `Option<JsonPlaintext>` that is `None`
/// seals as a null with no padding, so its length can show that the value
/// is absent.
///
/// # What wiping covers
///
/// The document is wiped when the `JsonPlaintext` is dropped
/// ([`ZeroizeOnDrop`]). A clone is wiped when it is dropped too. The JSON
/// text written to seal the document is built in a buffer of its final
/// size, and that buffer is wiped when the document has been sealed.
///
/// A `Value` read through [`value`](Self::value) and then cloned is an
/// ordinary value. The caller looks after it, with
/// [`wipe_value`](super::wipe_value).
///
/// `Debug` is redacted. There is no `PartialEq`, which would compare
/// plaintext in variable time: compare the documents that
/// [`value`](Self::value) returns.
///
/// [`KeysetCipher::encrypt`]: crate::KeysetCipher::encrypt
pub struct JsonPlaintext(Value);

impl JsonPlaintext {
    /// Parse a document from JSON text, by the rules of [`parse_text`].
    ///
    /// # Errors
    ///
    /// [`JsonTextError`]: the text is not JSON, an object repeats a member,
    /// or an integer is outside the 64-bit range. The error says what kind
    /// of mistake it was and where, and never includes any of the text.
    pub fn parse(text: &str) -> Result<Self, JsonTextError> {
        Self::parse_bytes(text.as_bytes())
    }

    /// [`parse`](Self::parse) for text held as bytes, which is refused if
    /// it is not UTF-8.
    pub(crate) fn parse_bytes(text: &[u8]) -> Result<Self, JsonTextError> {
        parse_text(text).map(Self)
    }

    /// The document.
    pub fn value(&self) -> &Value {
        &self.0
    }
}

impl From<Value> for JsonPlaintext {
    /// Take ownership of a document, so it is wiped when the
    /// `JsonPlaintext` is dropped.
    fn from(value: Value) -> Self {
        Self(value)
    }
}

impl Clone for JsonPlaintext {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Zeroize for JsonPlaintext {
    /// Wipe the document. What is left is a JSON `null`.
    fn zeroize(&mut self) {
        plain::wipe(&mut self.0);
        self.0 = Value::Null;
    }
}

impl Drop for JsonPlaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for JsonPlaintext {}

impl fmt::Debug for JsonPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsonPlaintext(<redacted>)")
    }
}

/// A document describes itself to Vitamin C as one text scalar: its JSON
/// text. The text is written into a buffer of its final size, read by the
/// sink in place, and wiped when the sink returns.
impl Encrypt for &JsonPlaintext {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = None;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let text = to_wiped_text(&self.0).map_err(|e| S::Error::source(SourceError::new(e)))?;
        // serde_json writes UTF-8. The check costs one pass and keeps the
        // text out of an unchecked conversion.
        let text = std::str::from_utf8(&text)
            .map_err(|_| S::Error::source(SourceError::msg("JSON text that is not UTF-8")))?;
        sink.scalar(None, Physical::Text(text))
    }
}

/// The owned form visits through the borrowed one, and is then dropped and
/// wiped.
impl Encrypt for JsonPlaintext {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = None;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

impl Scalar for &JsonPlaintext {}
impl Scalar for JsonPlaintext {}

/// A document reads exactly a text scalar that holds JSON text. The text
/// is parsed where the cipher opened it, so no second copy of it is made.
impl FromScalar for JsonPlaintext {
    const EXPECTED: &'static str = "JSON document";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        match (ty, value) {
            (None, Physical::Text(text)) => Self::parse(text).ok(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vitaminc_aead::plaintext::Raw;
    use vitaminc_aead::{Decrypt, Int};

    /// The text scalar a document describes itself as: what a `String`
    /// reads from the same sink.
    fn text(document: impl Encrypt) -> String {
        document.visit(String::sink()).unwrap()
    }

    #[test]
    fn a_document_is_one_text_scalar_holding_its_compact_json() {
        let document = JsonPlaintext::from(json!({"b": [1, 2.5, null], "a": "é"}));
        let sealed = text(&document);
        // serde_json's map is ordered by key, and writes no whitespace.
        assert_eq!(sealed, r#"{"a":"é","b":[1,2.5,null]}"#);
        assert_eq!(text(document), sealed, "the owned form");
        assert_eq!(<&JsonPlaintext as Encrypt>::DEPTH, depth::SCALAR);
        assert_eq!(<JsonPlaintext as Encrypt>::FIXED, None);
    }

    #[test]
    fn every_kind_of_document_reads_back_as_itself() {
        for value in [
            json!(null),
            json!(true),
            json!(-7),
            json!(18_446_744_073_709_551_615u64),
            json!(1.5),
            json!("text with \"quotes\" and \n"),
            json!([]),
            json!({}),
            json!({"nested": {"list": [1, {"k": null}]}}),
        ] {
            let sealed = text(JsonPlaintext::from(value.clone()));
            let read = sealed.as_str().visit(JsonPlaintext::sink()).unwrap();
            assert_eq!(read.value(), &value, "{sealed}");
        }
    }

    #[test]
    fn parse_applies_the_engines_rules() {
        let parsed = JsonPlaintext::parse(r#" {"a": 1} "#).unwrap();
        assert_eq!(parsed.value(), &json!({"a": 1}));
        assert!(matches!(
            JsonPlaintext::parse(r#"{"a": 1, "a": 2}"#),
            Err(JsonTextError::DuplicateKey { .. })
        ));
        assert!(matches!(
            JsonPlaintext::parse("18446744073709551616"),
            Err(JsonTextError::IntegerRange)
        ));
        assert!(matches!(
            JsonPlaintext::parse("{"),
            Err(JsonTextError::Syntax { .. })
        ));
    }

    #[test]
    fn only_json_text_reads_as_a_document() {
        let refused = |value: Raw<'_>| value.visit(JsonPlaintext::sink()).is_err();
        // Text that is not a document by the engine's rules.
        assert!(refused(Raw(None, Physical::Text("{"))));
        assert!(refused(Raw(None, Physical::Text(r#"{"a":1,"a":2}"#))));
        // The same text in a bytes leaf: a document is stored as text.
        assert!(refused(Raw(None, Physical::Bytes(b"{}"))));
        // A number is a JSON document as text, and not as an integer leaf.
        assert!(refused(Raw(None, Physical::Int(Int::I32(1)))));
        assert!(!refused(Raw(None, Physical::Text("1"))));
        // Text with a logical type is not plain text.
        assert!(refused(Raw(Some(Logical::Date), Physical::Text("1"))));
        assert!(None::<i32>.visit(JsonPlaintext::sink()).is_err(), "a null");
        assert_eq!(<JsonPlaintext as FromScalar>::EXPECTED, "JSON document");
    }

    #[test]
    fn an_absent_document_is_none_and_a_json_null_is_a_document() {
        let absent = None::<JsonPlaintext>
            .visit(Option::<JsonPlaintext>::sink())
            .unwrap();
        assert!(absent.is_none());
        let null = Some(JsonPlaintext::from(Value::Null))
            .visit(Option::<JsonPlaintext>::sink())
            .unwrap()
            .expect("a JSON null is present");
        assert_eq!(null.value(), &Value::Null);
    }

    #[test]
    fn zeroize_leaves_a_null_and_a_clone_is_its_own_copy() {
        let mut document = JsonPlaintext::from(json!({"secret": "hunter2", "pin": 1234}));
        let copy = document.clone();
        document.zeroize();
        assert_eq!(document.value(), &Value::Null);
        assert_eq!(copy.value(), &json!({"secret": "hunter2", "pin": 1234}));
    }

    #[test]
    fn debug_never_shows_the_document() {
        let document = JsonPlaintext::from(json!({"secret": "hunter2"}));
        assert_eq!(format!("{document:?}"), "JsonPlaintext(<redacted>)");
    }
}
