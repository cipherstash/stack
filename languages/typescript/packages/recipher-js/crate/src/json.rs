//! JSON documents: the [`Json`] class that `json(..)` makes.
//!
//! The engine is the Stack Encrypt engine, the `stack-encrypt` crate. It
//! encrypts a JSON document as the document's JSON text, through its
//! [`JsonPlaintext`] type. Rust and Go encrypt a document the same way, so
//! each SDK decrypts the documents of the others.
//!
//! The value bridge, the `recipher-value-napi` crate, converts between a
//! JavaScript value and a JSON document. This module converts nothing. It
//! passes the document between the bridge and the engine:
//!
//! - Encrypting. `json(..)` asks the bridge for the document's JSON text,
//!   and keeps the text in a [`Json`]. `encrypt` gives the text to the
//!   engine's parser, which makes the [`JsonPlaintext`] that the engine
//!   encrypts.
//! - Decrypting. [`opened`] gives the decrypted text to the engine's
//!   parser. The bridge then builds the JavaScript value of the document.
//!
//! The text and the document are plaintext. Each is wiped when it is
//! dropped, and nothing prints either.

use napi::bindgen_prelude::{ClassInstance, FromNapiValue, JavaScriptClassExt, Unknown};
use napi::Env;
use napi_derive::napi;
use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::dynamic::read_json;
use stack_encrypt::json::JsonPlaintext;
use vitaminc_protected::{Buffer, Controlled, OpaqueDebug};

use crate::error::{Error, RecipherErrorFields};
use crate::js;

/// The deepest a document can nest. The engine's JSON parser reads 127
/// levels of arrays and objects, and `[1]` is one level.
///
/// The bridge checks this depth when `json(..)` reads the document, so the
/// refusal says the document is too deep. The engine's parser would refuse
/// the same text without a reason.
const MAX_DEPTH: usize = 127;

/// A JSON document to encrypt as one ciphertext, as its JSON text. Nothing
/// inside the document can be searched. Make one with `json(..)`.
///
/// `json(..)` reads the document when it makes the `Json`. So a later
/// change to the object does not change what is encrypted. If the document
/// cannot be encrypted, the `Json` keeps the failure, and `encrypt` returns
/// that failure. `toString()` and Node's `inspect` hide the document.
///
/// The class has no constructor.
#[napi]
#[derive(OpaqueDebug)]
pub struct Json {
    /// The document's JSON text, or the reason `json(..)` refused it.
    text: Result<Buffer, RecipherErrorFields>,
}

#[napi]
impl Json {
    /// Returns the type's name, and hides the document.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Json(***)"
    }
}

impl Json {
    /// Returns the document that `value` holds, when `value` is a `Json`.
    ///
    /// The result answers two questions, so it has three cases:
    ///
    /// - `None`: `value` is not a `Json`. That is not a failure. The caller
    ///   reads `value` as any other value.
    /// - `Some(Err(..))`: `value` is a `Json`, and `json(..)` refused its
    ///   document. `json(..)` never throws, so it kept the refusal for
    ///   `encrypt` to return.
    /// - `Some(Ok(..))`: `value` is a `Json`, and this is its document.
    ///
    /// The `Option` says whether `value` is a `Json`. The `Result` says
    /// whether that `Json`'s document can be encrypted. A single `Result`
    /// could not tell "not a `Json`" from "a `Json` that was refused".
    ///
    /// `encrypt` calls it to choose how to read each value:
    ///
    /// ```ignore
    /// let leaf = match Json::of(env, value) {
    ///     // `keyset.encrypt(json({ name: 'Ada' }))`: the document, or
    ///     // the refusal that `json(..)` kept.
    ///     Some(document) => OneValue::json(document?),
    ///     // `keyset.encrypt('Ada')`: any other value.
    ///     None => OneValue::scalar(js::read(env, value)?)?,
    /// };
    /// ```
    pub(crate) fn of(
        env: &Env,
        value: Unknown<'_>,
    ) -> Option<Result<JsonPlaintext, RecipherErrorFields>> {
        if !Self::instance_of(env, &value).unwrap_or(false) {
            return None;
        }
        ClassInstance::<Json>::from_unknown(value)
            .ok()
            .map(|json| json.document())
    }

    /// Returns the document as the engine's [`JsonPlaintext`], or the
    /// refusal that `json(..)` kept. Each call parses the text again, so
    /// each `encrypt` of one `Json` gets a document of its own to wipe.
    fn document(&self) -> Result<JsonPlaintext, RecipherErrorFields> {
        match &self.text {
            Ok(text) => plaintext(text.risky_ref()),
            Err(refusal) => Err(refusal.clone()),
        }
    }
}

/// Makes a JSON document to encrypt as one ciphertext.
///
/// ```ts
/// const profile = json({ name: 'Ada', visits: 3, id: 2n ** 64n - 1n })
/// const sealed = (await keyset.encrypt(profile)).unwrap()
/// const opened = (await cipher.decrypt(sealed)).unwrap()
/// // { id: 18446744073709551615n, name: 'Ada', visits: 3 }
/// ```
///
/// The document is a plain object, an array, text, a number, a `bigint`, a
/// boolean or `null`. It nests at most 127 levels of arrays and objects.
///
/// A number is stored by these rules:
///
/// - A whole `number` within 2^53 - 1 of zero is an integer, as
///   `JSON.stringify` writes it. `5000000000` is stored as `5000000000`.
/// - A whole `number` from 2^53 up to 2^64 is refused. Its digits may not
///   be the ones you wrote. Give it as a `bigint`.
/// - Any other `number` is a float. `NaN` and the infinities are refused.
/// - A `bigint` is its exact digits, from `-(2n ** 63n)` to
///   `2n ** 64n - 1n`. A `bigint` outside that range is refused.
///
/// Decrypting gives an integer back as a `number` when it is within
/// 2^53 - 1 of zero, and as a `bigint` otherwise. So `json({ a: 5n })`
/// decrypts as `{ a: 5 }`.
///
/// The engine stores an object's members sorted by key. A decrypted object
/// lists its members in that order, not in the order you wrote them.
///
/// `undefined`, bytes, a `Date` and the wrapper classes have no JSON form,
/// and are refused.
///
/// `json(..)` reads the document now. `json(..)` never throws: `encrypt`
/// returns an `Err` for a document that cannot be encrypted.
#[napi(js_name = "json", ts_args_type = "document: JsonValue")]
pub fn json_document(env: &Env, document: Unknown<'_>) -> Json {
    Json {
        text: js::read_json(env, document, MAX_DEPTH),
    }
}

/// Returns the document that `text` is the JSON text of, as the value the
/// engine encrypts.
///
/// # Errors
///
/// Returns `recipher_js::not_sealed` for text that the engine's parser
/// refuses. The bridge writes no such text.
pub(crate) fn plaintext(text: &[u8]) -> Result<JsonPlaintext, RecipherErrorFields> {
    std::str::from_utf8(text)
        .ok()
        .and_then(|text| JsonPlaintext::parse(text).ok())
        .ok_or_else(|| Error::NotSealed.into())
}

/// Returns the document in a decrypted value: the value is the document's
/// JSON text.
///
/// # Errors
///
/// Returns `recipher_js::not_a_document` for a value that is not the text
/// of a JSON document. The failure quotes none of the text.
pub(crate) fn opened(value: &OwnedFrame) -> Result<JsonPlaintext, RecipherErrorFields> {
    read_json(value.frame()).map_err(|_| Error::NotADocument.into())
}

#[cfg(test)]
mod tests {
    use super::{opened, plaintext, MAX_DEPTH};
    use serde_json::json;
    use stack_encrypt::dynamic::frame::OwnedFrame;

    /// The text of `levels` arrays, each inside the one before.
    fn nested(levels: usize) -> String {
        format!("{}{}", "[".repeat(levels), "]".repeat(levels))
    }

    #[test]
    fn the_text_of_a_document_is_the_document_the_engine_encrypts() {
        let document =
            plaintext(br#"{"n":5000000000,"big":18446744073709551615,"f":1.5}"#).unwrap();
        assert_eq!(
            document.value(),
            &json!({"n": 5_000_000_000u64, "big": u64::MAX, "f": 1.5})
        );
    }

    #[test]
    fn the_depth_limit_is_the_depth_the_engine_reads() {
        assert!(plaintext(nested(MAX_DEPTH).as_bytes()).is_ok());
        let refused = plaintext(nested(MAX_DEPTH + 1).as_bytes()).unwrap_err();
        assert_eq!(refused.code, "recipher_js::not_sealed");
    }

    #[test]
    fn text_the_engine_does_not_read_is_refused_without_the_text() {
        for text in [
            &b"{not json"[..],
            br#"{"a":1,"a":2}"#,
            b"18446744073709551616",
            b"\xff",
        ] {
            let refused = plaintext(text).unwrap_err();
            assert_eq!(refused.code, "recipher_js::not_sealed");
            assert!(!refused.message.contains("not json"));
        }
    }

    #[test]
    fn decrypted_text_opens_as_its_document() {
        let text =
            OwnedFrame::of(r#"{"small": 5, "big": 18446744073709551615, "f": 1e20}"#).unwrap();
        assert_eq!(
            opened(&text).unwrap().value(),
            &json!({"small": 5, "big": u64::MAX, "f": 1e20})
        );
    }

    #[test]
    fn text_that_is_not_a_document_does_not_open() {
        let error = opened(&OwnedFrame::of("{not json").unwrap()).unwrap_err();
        assert_eq!(error.code, "recipher_js::not_a_document");
        assert!(!error.message.contains("not json"));
        // A value that is not text is not a document.
        let error = opened(&OwnedFrame::of(5i64).unwrap()).unwrap_err();
        assert_eq!(error.code, "recipher_js::not_a_document");
    }
}
