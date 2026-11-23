//! Text encodings a wire field is written in.
//!
//! A payload field that carries bytes carries them as text, and the
//! encoding is part of the field's contract: SQL decodes base64 with
//! `decode(x, 'base64')`, and decodes no base85 at all. These newtypes name
//! the encoding in the type, so a field's type says how its text is to be
//! read. Each serializes as the string itself (`#[serde(transparent)]`), and
//! renders as `string` in TypeScript and JSON Schema.
//!
//! The type is also a guarantee. A [`Base64Text`] holds exactly the text
//! [`Base64Text::encode`] writes for some bytes, and a [`Base85Text`] the
//! text [`Base85Text::encode`] writes, so whoever holds one can rely on its
//! encoding without checking it again: [`decode`](Base64Text::decode) cannot
//! fail. The inner string is private, and there are two ways to make a
//! value, both of which uphold the guarantee:
//!
//! - `encode`, from the bytes, which writes the text itself;
//! - `Deserialize`, from a wire string, which decodes the text with the
//!   real decoder and refuses, with an error naming the encoding, text that
//!   is not in it. Base85 text whose last group is not the one its bytes
//!   encode to is refused as well, so that the text and the bytes determine
//!   each other and two equal values hold the same bytes.
//!
//! The cost is a decode per field on read. A field Stack Encrypt goes on to
//! use is decoded twice: once here, when the payload deserializes, and once
//! in the engine, which works from its own wire form.

use std::fmt;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize};
use ts_rs::TS;

/// Padded standard base64 (RFC 4648 §4), as PostgreSQL's
/// `encode(x, 'base64')` writes it and `decode(x, 'base64')` reads it.
///
/// Made only by [`encode`](Self::encode) or by deserializing text that
/// decodes as this encoding, so it always holds base64 (see the
/// [module docs](self)).
///
/// ```
/// use eql_bindings::encoding::Base64Text;
///
/// let text = Base64Text::encode([0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(text.as_str(), "3q2+7w==");
/// assert_eq!(text.decode(), [0xde, 0xad, 0xbe, 0xef]);
/// assert!(serde_json::from_str::<Base64Text>(r#""not base64""#).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, TS, JsonSchema)]
#[serde(transparent)]
pub struct Base64Text(String);

/// RFC 1924 base85, the alphabet `base85-simd` writes. No SQL function
/// decodes it, so a field in it is opaque to the database.
///
/// Made only by [`encode`](Self::encode) or by deserializing text that
/// decodes as this encoding, so it always holds base85 (see the
/// [module docs](self)).
///
/// ```
/// use eql_bindings::encoding::Base85Text;
///
/// let text = Base85Text::encode([0, 15, 255]);
/// assert_eq!(text.as_str(), "01y8");
/// assert_eq!(text.decode(), [0, 15, 255]);
/// assert!(serde_json::from_str::<Base85Text>(r#""z""#).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, TS, JsonSchema)]
#[serde(transparent)]
pub struct Base85Text(String);

impl Base64Text {
    /// Encodes `bytes` as padded standard base64.
    pub fn encode(bytes: impl AsRef<[u8]>) -> Self {
        Self(STANDARD.encode(bytes))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The bytes the text encodes.
    pub fn decode(&self) -> Vec<u8> {
        STANDARD
            .decode(&self.0)
            .expect("a Base64Text holds base64: encode and Deserialize are the only ways in")
    }

    /// The value for wire text, if it is padded standard base64. The
    /// standard engine is strict, so text it accepts is the text `encode`
    /// writes for the bytes it decodes to.
    fn from_wire(text: String) -> Result<Self, base64::DecodeError> {
        STANDARD.decode(&text)?;
        Ok(Self(text))
    }
}

impl Base85Text {
    /// Encodes `bytes` as RFC 1924 base85.
    pub fn encode(bytes: impl AsRef<[u8]>) -> Self {
        Self(base85_simd::encode(bytes.as_ref()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The bytes the text encodes.
    pub fn decode(&self) -> Vec<u8> {
        base85_simd::decode(&self.0)
            .expect("a Base85Text holds base85: encode and Deserialize are the only ways in")
    }

    /// The value for wire text, if it is RFC 1924 base85 and the text
    /// `encode` writes for the bytes it decodes to. The decoder alone
    /// accepts more than one final group for the same trailing bytes.
    fn from_wire(text: String) -> Result<Self, String> {
        let bytes = base85_simd::decode(&text).map_err(|err| err.to_string())?;
        if base85_simd::encode(&bytes) != text {
            return Err(
                "the final group is not the one its bytes encode to (non-canonical)".to_owned(),
            );
        }
        Ok(Self(text))
    }
}

impl<'de> Deserialize<'de> for Base64Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_wire(String::deserialize(deserializer)?).map_err(|err| {
            de::Error::custom(format_args!(
                "not padded standard base64 (RFC 4648 §4): {err}"
            ))
        })
    }
}

impl<'de> Deserialize<'de> for Base85Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_wire(String::deserialize(deserializer)?)
            .map_err(|err| de::Error::custom(format_args!("not RFC 1924 base85: {err}")))
    }
}

impl AsRef<str> for Base64Text {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Base85Text {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Base64Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Base85Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{json, Value};

    /// The serde error for deserializing `wire` as `T`, which must fail.
    fn refusal<T: for<'de> Deserialize<'de> + fmt::Debug>(wire: Value) -> String {
        let result = serde_json::from_value::<T>(wire.clone());
        assert!(result.is_err(), "{wire} should be refused, got {result:?}");
        result.unwrap_err().to_string()
    }

    mod base64_text {
        use super::*;

        proptest! {
            #[test]
            fn decode_returns_the_bytes_encode_was_given(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
                prop_assert_eq!(Base64Text::encode(&bytes).decode(), bytes, "encode then decode");
            }

            #[test]
            fn deserializing_the_text_encode_writes_yields_the_same_value(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
                let encoded = Base64Text::encode(&bytes);
                let read: Base64Text = serde_json::from_value(json!(encoded.as_str())).unwrap();
                prop_assert_eq!(&read, &encoded, "the wire text reads back as itself");
                prop_assert_eq!(read, Base64Text::encode(encoded.decode()), "and is encode of its bytes");
            }
        }

        #[test]
        fn empty_bytes_are_the_empty_string() {
            let empty = Base64Text::encode([]);
            assert_eq!(empty.as_str(), "", "empty bytes encode to empty text");
            assert!(empty.decode().is_empty(), "and decode back to nothing");
        }

        #[test]
        fn is_postgres_padded_standard_base64() {
            assert_eq!(
                Base64Text::encode([0xfb, 0xff]).as_str(),
                "+/8=",
                "the standard alphabet, padded, as encode(x, 'base64') writes it"
            );
        }

        mod given_text_that_is_not_padded_standard_base64 {
            use super::*;

            #[test]
            fn deserializing_fails_naming_the_encoding() {
                for wire in [
                    "QQ@=",  // `@` is not in the alphabet
                    "-_8=",  // the URL-safe alphabet
                    "QQ",    // padding missing
                    "QQ=",   // padding short
                    "QR==",  // trailing bits set: not the text encode writes
                    "QUJD=", // padding after a whole group
                    "Q",     // a length no encoding has
                    " QQ==",
                ] {
                    let message = refusal::<Base64Text>(json!(wire));
                    assert!(
                        message.contains("padded standard base64"),
                        "the error for {wire:?} should name the encoding, got: {message}"
                    );
                }
            }

            #[test]
            fn deserializing_a_non_string_fails() {
                let _ = refusal::<Base64Text>(json!(1));
            }
        }
    }

    mod base85_text {
        use super::*;

        proptest! {
            #[test]
            fn decode_returns_the_bytes_encode_was_given(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
                prop_assert_eq!(Base85Text::encode(&bytes).decode(), bytes, "encode then decode");
            }

            #[test]
            fn deserializing_the_text_encode_writes_yields_the_same_value(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
                let encoded = Base85Text::encode(&bytes);
                let read: Base85Text = serde_json::from_value(json!(encoded.as_str())).unwrap();
                prop_assert_eq!(&read, &encoded, "the wire text reads back as itself");
                prop_assert_eq!(read, Base85Text::encode(encoded.decode()), "and is encode of its bytes");
            }
        }

        #[test]
        fn empty_bytes_are_the_empty_string() {
            let empty = Base85Text::encode([]);
            assert_eq!(empty.as_str(), "", "empty bytes encode to empty text");
            assert!(empty.decode().is_empty(), "and decode back to nothing");
        }

        #[test]
        fn is_rfc_1924_base85() {
            assert_eq!(
                Base85Text::encode([0, 15, 255]).as_str(),
                "01y8",
                "the RFC 1924 alphabet, as Stack Encrypt writes `c`"
            );
        }

        mod given_text_that_is_not_rfc_1924_base85 {
            use super::*;

            #[test]
            fn deserializing_fails_naming_the_encoding() {
                for wire in [
                    "z",     // a length no encoding has
                    "\"",    // a quote is not in the alphabet
                    "01y\"", // nor inside the text
                    "0rr 1", // nor a space
                ] {
                    let message = refusal::<Base85Text>(json!(wire));
                    assert!(
                        message.contains("RFC 1924 base85"),
                        "the error for {wire:?} should name the encoding, got: {message}"
                    );
                }
            }

            #[test]
            fn deserializing_a_non_string_fails() {
                let _ = refusal::<Base85Text>(json!(1));
            }

            #[test]
            fn deserializing_a_final_group_encode_never_writes_fails() {
                // "01" decodes to [0], which encodes as "00".
                assert_eq!(
                    base85_simd::decode("01").unwrap(),
                    [0],
                    "the decoder takes it"
                );
                let message = refusal::<Base85Text>(json!("01"));
                assert!(
                    message.contains("RFC 1924 base85") && message.contains("non-canonical"),
                    "the error should name the encoding and the reason, got: {message}"
                );
            }
        }
    }

    mod on_the_wire {
        use super::*;

        #[test]
        fn both_encodings_are_the_bare_string() {
            let b64 = Base64Text::encode([0u8; 16]);
            let b85 = Base85Text::encode([0xde, 0xad, 0xbe, 0xef]);
            assert_eq!(
                serde_json::to_value(&b64).unwrap(),
                json!("AAAAAAAAAAAAAAAAAAAAAA=="),
                "base64 serializes as its text"
            );
            assert_eq!(
                serde_json::to_value(&b85).unwrap(),
                json!(b85.as_str()),
                "base85 serializes as its text"
            );
            assert_eq!(b64.to_string(), b64.as_str(), "Display writes the text");
            assert_eq!(b85.to_string(), b85.as_str(), "Display writes the text");
        }

        #[test]
        fn both_render_as_string_in_typescript_and_json_schema() {
            assert_eq!(Base64Text::name(), "Base64Text", "the TS name");
            assert_eq!(Base64Text::inline(), "string", "base64 is a TS string");
            assert_eq!(Base85Text::inline(), "string", "base85 is a TS string");
            for schema in [
                schemars::schema_for!(Base64Text),
                schemars::schema_for!(Base85Text),
            ] {
                assert_eq!(
                    serde_json::to_value(schema).unwrap()["type"],
                    "string",
                    "each is a JSON Schema string"
                );
            }
        }
    }
}
