//! A JSON document as a binding hands one over and gets one back.
//!
//! A field of kind [`json`](ValueKind::Json) carries its document as UTF-8
//! JSON text, in a text leaf or a bytes leaf of the transport frame. The
//! engine parses it once, by [`parse_text`]'s rules, where it is sealed,
//! queried or compared, so every language seals the same document for the
//! same text. An opened document comes back as its text in a bytes leaf.
//!
//! A document's `null` is the text `null`, a present value. A field's
//! absent value is the frame's null, which a `json` field stores as SQL
//! `NULL` (`"null": "sql"`) and never as a document.

use serde_json::Value;
use vitaminc_aead::plaintext::{Logical, Physical};
use vitaminc_aead::Encrypt;
use vitaminc_protected::Protected;
use zeroize::Zeroizing;

use super::term::OneScalar;
use super::{ValueFrame, ValueKind};
use crate::json::{parse_text, to_text, wipe_value, JsonTextError};

/// Why a `json` field's value is not a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JsonValueError {
    /// The value is not a text or bytes leaf: a number, a container, a
    /// null or a passthrough.
    #[error("a JSON document crosses as text or bytes")]
    NotText,
    /// The text is not a document by the engine's rules.
    #[error(transparent)]
    Text(#[from] JsonTextError),
}

impl JsonValueError {
    /// The error's machine-readable code: `json_not_text`, or the text
    /// error's ([`JsonTextError::code`]).
    pub fn code(&self) -> &'static str {
        match self {
            JsonValueError::NotText => "json_not_text",
            JsonValueError::Text(error) => error.code(),
        }
    }
}

/// A JSON document a binding handed over, parsed. Wiped when it drops: the
/// caller holds the plaintext only as long as it reads it.
pub struct JsonPlaintext(Value);

impl JsonPlaintext {
    /// The document.
    pub fn value(&self) -> &Value {
        &self.0
    }
}

impl Drop for JsonPlaintext {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}

/// Parse a `json` field's value: the document its text or bytes leaf
/// holds.
///
/// # Errors
///
/// [`JsonValueError::NotText`] for a value that is not a text or bytes
/// leaf, and [`JsonValueError::Text`] for text that is not a document by
/// [`parse_text`]'s rules.
pub fn read_json(value: &ValueFrame) -> Result<JsonPlaintext, JsonValueError> {
    if !ValueKind::Json.holds(value.kind()) {
        return Err(JsonValueError::NotText);
    }
    value
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                (None, Physical::Text(text)) => Ok(parse_text(text.as_bytes())),
                (None, Physical::Bytes(bytes)) => Ok(parse_text(bytes)),
                _ => Err(None),
            },
        ))
        .map_err(|_| JsonValueError::NotText)?
        .map(JsonPlaintext)
        .map_err(JsonValueError::Text)
}

/// A document as the value a `json` field opens to: its JSON text
/// ([`to_text`]), in a bytes leaf. The text's buffer moves into the
/// frame's protected value, so no second copy of it is made.
///
/// # Errors
///
/// [`crate::Error::Other`] if the frame writer refuses the bytes, which a
/// document's text never is.
pub fn json_frame(value: &Value) -> Result<ValueFrame, crate::Error> {
    let mut text = Zeroizing::new(to_text(value).map_err(|e| crate::Error::Other(Box::new(e)))?);
    ValueFrame::of(Protected::new(std::mem::take(&mut *text)))
        .map_err(|e| crate::Error::Other(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::Tree;
    use serde_json::json;

    fn frame(tree: Tree) -> ValueFrame {
        ValueFrame::of(&tree).unwrap()
    }

    #[test]
    fn a_document_is_read_from_text_or_bytes() {
        let text = read_json(&frame(Tree::String(r#"{"a": [1, null]}"#.into()))).unwrap();
        assert_eq!(text.value(), &json!({"a": [1, null]}));
        let bytes = read_json(&frame(Tree::Bytes(b"null".to_vec()))).unwrap();
        assert_eq!(bytes.value(), &Value::Null, "a JSON null is a document");
    }

    #[test]
    fn anything_else_is_not_a_document() {
        for tree in [
            Tree::Null,
            Tree::UInt32(1),
            Tree::Array(vec![]),
            Tree::Bool(true),
        ] {
            assert_eq!(read_json(&frame(tree)).err(), Some(JsonValueError::NotText));
        }
        let error = read_json(&frame(Tree::String(r#"{"a":1,"a":2}"#.into())))
            .err()
            .unwrap();
        assert_eq!(error.code(), "json_duplicate_key");
    }

    #[test]
    fn an_opened_document_is_its_text_in_bytes() {
        let value = json!({"name": "Alice", "n": [1.5, -2]});
        let opened = json_frame(&value).unwrap();
        assert_eq!(opened.kind(), Some(ValueKind::Bytes));
        assert_eq!(read_json(&opened).unwrap().value(), &value);
    }
}
