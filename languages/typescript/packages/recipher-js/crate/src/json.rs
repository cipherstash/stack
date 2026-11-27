//! JSON documents: the [`Json`] class that `json(..)` makes, and the
//! conversion between a frame and the engine's [`JsonPlaintext`].
//!
//! The engine is the Stack Encrypt engine, the `stack-encrypt` crate. The
//! engine's value model is the set of value types it reads. A frame is a
//! byte buffer that contains one value of the model. A sink receives a
//! value from a frame one part at a time: one scalar, array or map.
//!
//! # Encrypting
//!
//! JavaScript has one number type, and a `number` cannot represent every
//! integer that a JSON document can. So a document's values become JSON
//! values by these rules:
//!
//! - An object, an array, text, a boolean and null stay as they are.
//! - A `number` that is a safe integer is written as that integer, as
//!   `JSON.stringify` writes it. A safe integer is at most 2^53 - 1 from
//!   zero.
//! - A whole `number` between 2^53 and 2^64 from zero is refused. The
//!   caller probably meant an integer, and the `number`'s digits are not the
//!   ones the caller wrote.
//! - Any other finite `number` is written as a float.
//! - A `bigint` is written as its digits. A `bigint` outside the 64-bit
//!   range that the engine's parser reads is refused.
//! - Any other value is refused, because it has no JSON form. Examples are
//!   bytes, a date, a timestamp, a decimal, a UUID and `undefined`.
//! - A document nested deeper than 127 levels is refused, because the
//!   engine's parser would refuse it when the document is decrypted.
//!
//! # Decrypting
//!
//! An integer in the safe range becomes a `number`, and an integer outside
//! it becomes a `bigint`, so no digit is lost. A float becomes a `number`.
//!
//! The engine encrypts the document as its JSON text, through
//! [`JsonPlaintext`], and reads it back with the engine's JSON parser.
//! Everything built along the way, including map keys, is wiped when it is
//! dropped.

use napi::bindgen_prelude::{ClassInstance, FromNapiValue, JavaScriptClassExt, Unknown};
use napi::Env;
use napi_derive::napi;
use serde_json::{Map, Number, Value};
use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::dynamic::plaintext::{
    Error as SinkError, FixedType, Float, Int, Logical, MapSink, Physical, SeqSink, Sink,
    SourceError,
};
use stack_encrypt::dynamic::read_json;
use stack_encrypt::json::{wipe_value, JsonPlaintext};
use stack_encrypt::{Encrypt, EncryptRef};
use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroizing;

use crate::error::{Error, RecipherErrorFields};
use crate::js;

/// The deepest a document can nest. The engine's JSON parser reads 127
/// levels of arrays and objects.
const MAX_DEPTH: usize = 127;

/// The largest integer that a JavaScript `number` represents exactly:
/// 2^53 - 1.
const MAX_SAFE: u64 = (1 << 53) - 1;

/// 2^64: the smallest magnitude larger than every 64-bit integer.
const TWO_TO_64: f64 = 18_446_744_073_709_551_616.0;

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
    document: Result<JsonPlaintext, RecipherErrorFields>,
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
    /// Returns the document of `value` as a value to encrypt, when `value`
    /// is a `Json`. Returns the failure instead when the document cannot be
    /// encrypted. Returns `None` when `value` is not a `Json`.
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

    /// Returns the document as a value to encrypt, or the failure that
    /// stops it being encrypted.
    pub(crate) fn document(&self) -> Result<JsonPlaintext, RecipherErrorFields> {
        match &self.document {
            // The copy is wiped when the `JsonPlaintext` that contains it
            // drops.
            Ok(document) => Ok(JsonPlaintext::from(document.value().clone())),
            Err(error) => Err(error.clone()),
        }
    }
}

/// Makes a JSON document to encrypt as one ciphertext. The document is a
/// plain object, an array, text, a number, a `bigint`, a boolean or `null`,
/// nested at most 127 levels.
///
/// Give an integer outside a `number`'s safe range as a `bigint`, within 64
/// bits. The safe range is at most 2^53 - 1 from zero. A whole `number`
/// between 2^53 and 2^64 from zero is refused, because the caller probably
/// meant an integer.
///
/// `json(..)` reads the document now. `json(..)` never throws: `encrypt`
/// returns an `Err` for a document that cannot be encrypted.
#[napi(js_name = "json", ts_args_type = "document: JsonValue")]
pub fn json_document(env: &Env, document: Unknown<'_>) -> Json {
    Json {
        document: js::read(env, document).and_then(|frame| self::document(&frame)),
    }
}

/// The JSON sink returns the SDK's own errors: [`Error::NotJson`] or
/// [`Error::JsonTooDeep`]. Each has fixed text that includes no part of the
/// value.
impl SinkError for Error {
    fn source(_: SourceError) -> Self {
        Self::NotJson {
            what: "it could not be read",
        }
    }
}

/// Returns the document in a frame, as the engine's [`JsonPlaintext`].
pub(crate) fn document(frame: &OwnedFrame) -> Result<JsonPlaintext, RecipherErrorFields> {
    frame
        .visit(ToJson {
            out: Root,
            depth: 0,
        })
        .map(JsonPlaintext::from)
        .map_err(RecipherErrorFields::from)
}

/// Returns the value of a decrypted document's text, as a frame. The
/// conversion follows the rules in the module docs.
pub(crate) fn opened(frame: &OwnedFrame) -> Result<OwnedFrame, RecipherErrorFields> {
    let document = read_json(frame.frame()).map_err(|_| Error::NotADocument)?;
    OwnedFrame::of(&FromJson(document.value())).map_err(|_| Error::BuildValue.into())
}

/// The place a built JSON value goes.
trait Out {
    type Ok;
    fn put(self, value: Value) -> Result<Self::Ok, Error>;
}

/// The built value is the result.
struct Root;

impl Out for Root {
    type Ok = Value;
    fn put(self, value: Value) -> Result<Value, Error> {
        Ok(value)
    }
}

/// The built value is the next element of an array.
struct Element<'s>(&'s mut Vec<Value>);

impl Out for Element<'_> {
    type Ok = ();
    fn put(self, value: Value) -> Result<(), Error> {
        self.0.push(value);
        Ok(())
    }
}

/// The built value is the member `key` of an object. Until the key is in
/// the object, it is kept in a buffer that is wiped when dropped. So a
/// member that is refused, or dropped unfinished, leaves no copy of its key.
struct Member<'s> {
    object: &'s mut Map<String, Value>,
    key: Zeroizing<String>,
}

impl Out for Member<'_> {
    type Ok = ();
    fn put(mut self, value: Value) -> Result<(), Error> {
        let key = std::mem::take(&mut *self.key);
        let _ = self.object.insert(key, value);
        Ok(())
    }
}

/// A sink that builds a JSON value at `depth` levels of nesting, and passes
/// it to `O`.
struct ToJson<O> {
    out: O,
    depth: usize,
}

/// Returns the JSON number for a float, by the rules in the module docs.
fn float(value: f64) -> Result<Value, Error> {
    if !value.is_finite() {
        return Err(Error::NotJson {
            what: "a number that is not finite",
        });
    }
    let magnitude = value.abs();
    if value.fract() == 0.0 && magnitude <= MAX_SAFE as f64 {
        // The value is a safe integer, so the conversion is exact.
        #[allow(clippy::cast_possible_truncation)]
        return Ok(Value::Number(Number::from(value as i64)));
    }
    if value.fract() == 0.0 && magnitude < TWO_TO_64 {
        return Err(Error::NotJson {
            what: "a whole number between 2^53 and 2^64 held as a number, whose digits may not be \
             the ones meant; use a bigint",
        });
    }
    Number::from_f64(value)
        .map(Value::Number)
        .ok_or(Error::NotJson {
            what: "a number that is not finite",
        })
}

/// Returns the JSON number for an integer. An integer outside the 64-bit
/// range is refused.
fn integer(value: Int) -> Result<Value, Error> {
    let wide = match value {
        Int::I8(n) => i128::from(n),
        Int::I16(n) => i128::from(n),
        Int::I32(n) => i128::from(n),
        Int::I64(n) => i128::from(n),
        Int::I128(n) => n,
        Int::U8(n) => i128::from(n),
        Int::U16(n) => i128::from(n),
        Int::U32(n) => i128::from(n),
        Int::U64(n) => i128::from(n),
        Int::U128(n) => i128::try_from(n).unwrap_or(i128::MAX),
    };
    if let Ok(n) = i64::try_from(wide) {
        return Ok(Value::Number(Number::from(n)));
    }
    if let Ok(n) = u64::try_from(wide) {
        return Ok(Value::Number(Number::from(n)));
    }
    Err(Error::NotJson {
        what: "a bigint outside the 64-bit range (below -2^63 or above 2^64 - 1)",
    })
}

impl<O: Out> ToJson<O> {
    /// Returns the depth of an array or object that starts here. A depth
    /// past the limit is refused.
    fn nested(&self) -> Result<usize, Error> {
        let depth = self.depth + 1;
        if depth > MAX_DEPTH {
            return Err(Error::JsonTooDeep);
        }
        Ok(depth)
    }
}

impl<O: Out> Sink for ToJson<O> {
    type Ok = O::Ok;
    type Error = Error;
    type Seq = JsonArray<O>;
    type Map = JsonObject<O>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<O::Ok, Error> {
        let value = match (ty, value) {
            (None, Physical::Null) => Value::Null,
            (None, Physical::Bool(b)) => Value::Bool(b),
            (None, Physical::Text(text)) => Value::String(text.to_owned()),
            (None, Physical::Float(Float::F64(n))) => float(n)?,
            (None, Physical::Float(Float::F32(n))) => float(f64::from(n))?,
            (None, Physical::Int(n)) => integer(n)?,
            (None, Physical::Bytes(_)) => return Err(Error::NotJson { what: "bytes" }),
            (Some(Logical::Undefined), _) => return Err(Error::NotJson { what: "undefined" }),
            (Some(_), _) => {
                return Err(Error::NotJson {
                    what: "a date, a timestamp, a decimal or a UUID; write it as text",
                })
            }
        };
        self.out.put(value)
    }

    fn typed_null(self, _: FixedType) -> Result<O::Ok, Error> {
        self.out.put(Value::Null)
    }

    fn seq(self, len: Option<usize>) -> Result<JsonArray<O>, Error> {
        let depth = self.nested()?;
        Ok(JsonArray {
            out: Some(self.out),
            depth,
            items: Vec::with_capacity(len.unwrap_or(0).min(1024)),
        })
    }

    fn map(self, _: Option<usize>) -> Result<JsonObject<O>, Error> {
        let depth = self.nested()?;
        Ok(JsonObject {
            out: Some(self.out),
            depth,
            members: Map::new(),
        })
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<O::Ok, Error> {
        Err(Error::NotJson {
            what: "a passthrough",
        })
    }
}

/// An array being built. Its items are wiped if it is dropped unfinished.
struct JsonArray<O> {
    out: Option<O>,
    depth: usize,
    items: Vec<Value>,
}

impl<O> Drop for JsonArray<O> {
    fn drop(&mut self) {
        for item in &mut self.items {
            wipe_value(item);
        }
    }
}

impl<O: Out> SeqSink for JsonArray<O> {
    type Ok = O::Ok;
    type Error = Error;
    type Element<'s>
        = ToJson<Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<ToJson<Element<'_>>, Error> {
        Ok(ToJson {
            out: Element(&mut self.items),
            depth: self.depth,
        })
    }

    fn end(mut self) -> Result<O::Ok, Error> {
        let items = std::mem::take(&mut self.items);
        match self.out.take() {
            Some(out) => out.put(Value::Array(items)),
            None => Err(Error::NotJson {
                what: "it could not be read",
            }),
        }
    }
}

/// An object being built. Its members are wiped if it is dropped
/// unfinished.
struct JsonObject<O> {
    out: Option<O>,
    depth: usize,
    members: Map<String, Value>,
}

impl<O> Drop for JsonObject<O> {
    fn drop(&mut self) {
        let mut members = Value::Object(std::mem::take(&mut self.members));
        wipe_value(&mut members);
    }
}

impl<O: Out> MapSink for JsonObject<O> {
    type Ok = O::Ok;
    type Error = Error;
    type Entry<'s>
        = ToJson<Member<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<ToJson<Member<'_>>, Error> {
        Ok(ToJson {
            out: Member {
                object: &mut self.members,
                key: Zeroizing::new(key.to_owned()),
            },
            depth: self.depth,
        })
    }

    fn end(mut self) -> Result<O::Ok, Error> {
        let members = std::mem::take(&mut self.members);
        match self.out.take() {
            Some(out) => out.put(Value::Object(members)),
            None => Err(Error::NotJson {
                what: "it could not be read",
            }),
        }
    }
}

/// A JSON value, written into a sink by the rules in the module docs.
struct FromJson<'v>(&'v Value);

impl Encrypt for &FromJson<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        walk(self.0, sink)
    }
}

fn walk<S: Sink>(value: &Value, sink: S) -> Result<S::Ok, S::Error> {
    match value {
        Value::Null => sink.scalar(None, Physical::Null),
        Value::Bool(b) => sink.scalar(None, Physical::Bool(*b)),
        Value::String(text) => sink.scalar(None, Physical::Text(text)),
        Value::Number(number) => sink.scalar(None, number_of(number)),
        Value::Array(items) => {
            let mut seq = sink.seq(Some(items.len()))?;
            for item in items {
                walk(item, seq.element()?)?;
            }
            seq.end()
        }
        Value::Object(members) => {
            let mut map = sink.map(Some(members.len()))?;
            for (key, member) in members {
                walk(member, map.entry(key)?)?;
            }
            map.end()
        }
    }
}

/// Returns a number in the form JavaScript reads it: a `number` for a float
/// or a safe integer, and a `bigint` for any other integer.
fn number_of(number: &Number) -> Physical<'static> {
    if let Some(n) = number.as_i64() {
        if n.unsigned_abs() <= MAX_SAFE {
            // The integer is in the safe range, so the conversion is exact.
            #[allow(clippy::cast_precision_loss)]
            return Physical::Float(Float::F64(n as f64));
        }
        return Physical::Int(Int::I64(n));
    }
    if let Some(n) = number.as_u64() {
        return Physical::Int(Int::U64(n));
    }
    Physical::Float(Float::F64(number.as_f64().unwrap_or(f64::NAN)))
}

#[cfg(test)]
mod tests {
    use super::{document, opened, MAX_DEPTH};
    use serde_json::json;
    use stack_encrypt::dynamic::frame::OwnedFrame;
    use stack_encrypt::json::JsonPlaintext;

    fn frame_of_text(text: &str) -> OwnedFrame {
        OwnedFrame::of(text).unwrap()
    }

    /// Arrays nested `.0` levels deep. The innermost array is empty.
    struct Nested(usize);

    impl stack_encrypt::Encrypt for &Nested {
        fn visit<S: stack_encrypt::dynamic::plaintext::Sink>(
            self,
            sink: S,
        ) -> Result<S::Ok, S::Error> {
            use stack_encrypt::dynamic::plaintext::SeqSink;
            let mut seq = sink.seq(Some(usize::from(self.0 > 1)))?;
            if self.0 > 1 {
                let _ = (&Nested(self.0 - 1)).visit(seq.element()?)?;
            }
            seq.end()
        }
    }

    /// Returns a frame of `depth` nested arrays, each inside the one before.
    fn nested(depth: usize) -> OwnedFrame {
        OwnedFrame::of(&Nested(depth)).unwrap()
    }

    #[test]
    fn a_safe_integer_float_is_written_as_an_integer() {
        let frame = OwnedFrame::of(vec![5.0f64, 1.5]).unwrap();
        assert_eq!(document(&frame).unwrap().value(), &json!([5, 1.5]));
    }

    #[test]
    fn a_whole_number_between_2_53_and_2_64_is_refused() {
        let frame = OwnedFrame::of(9_007_199_254_740_993.0f64).unwrap();
        let error = document(&frame).unwrap_err();
        assert_eq!(error.code, "recipher_js::not_json");
        assert!(error.message.contains("bigint"));
    }

    #[test]
    fn a_large_float_is_written_as_a_float_and_reads_back_the_same() {
        for value in [1e20f64, f64::MAX, -6.02e23] {
            let written = document(&OwnedFrame::of(value).unwrap()).unwrap();
            assert_eq!(written.value().as_f64(), Some(value));
            // The engine's parser reads the text back as the same float.
            let text = stack_encrypt::json::to_text(written.value()).unwrap();
            let read = JsonPlaintext::parse(std::str::from_utf8(&text).unwrap()).unwrap();
            assert_eq!(read.value().as_f64(), Some(value));
        }
    }

    #[test]
    fn a_bigint_is_written_as_its_digits_within_64_bits() {
        let frame = OwnedFrame::of(u64::MAX).unwrap();
        assert_eq!(
            document(&frame).unwrap().value(),
            &json!(18_446_744_073_709_551_615u64)
        );
        assert!(document(&OwnedFrame::of(u128::MAX).unwrap()).is_err());
        assert!(document(&OwnedFrame::of(i128::MIN).unwrap()).is_err());
    }

    #[test]
    fn bytes_have_no_json_form() {
        let frame = OwnedFrame::of(vec![1u8, 2, 3]).unwrap();
        assert_eq!(document(&frame).unwrap_err().code, "recipher_js::not_json");
    }

    #[test]
    fn a_document_nests_as_deep_as_the_engine_reads_and_no_deeper() {
        assert!(document(&nested(MAX_DEPTH)).is_ok());
        let refused = document(&nested(MAX_DEPTH + 1)).unwrap_err();
        assert_eq!(refused.code, "recipher_js::too_deep");
    }

    #[test]
    fn an_opened_integer_is_a_number_when_safe_and_an_integer_when_not() {
        let opened = opened(&frame_of_text(
            r#"{"small": 5, "big": 18446744073709551615, "f": 1.5}"#,
        ))
        .unwrap();
        // In the decrypted frame, the small integer is now a float, and the
        // big one is still an integer. The frame reads back as the same
        // document.
        let read = document(&opened).unwrap();
        assert_eq!(
            read.value(),
            &json!({"small": 5, "big": 18_446_744_073_709_551_615u64, "f": 1.5})
        );
    }

    #[test]
    fn a_document_another_sdk_wrote_with_a_large_float_encrypts_again() {
        let opened = opened(&frame_of_text(r#"{"x": 1e20}"#)).unwrap();
        assert_eq!(document(&opened).unwrap().value(), &json!({"x": 1e20}));
    }

    #[test]
    fn text_that_is_not_a_document_does_not_open() {
        let error = opened(&frame_of_text("{not json")).unwrap_err();
        assert_eq!(error.code, "recipher_js::not_a_document");
        assert!(!error.message.contains("not json"));
    }
}
