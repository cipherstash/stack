//! A JSON document: [`Json`], made by `json(..)`, and the conversion between
//! a frame and the engine's [`JsonPlaintext`].
//!
//! JavaScript has one number type, and a `number` cannot hold every integer
//! a JSON document can. So on the way in:
//!
//! - an object, an array, text, a boolean and null are themselves;
//! - a `number` that is a safe integer (at most 2^53 - 1 from zero) is
//!   written as that integer, as `JSON.stringify` writes it, and any other
//!   finite `number` as a float, except one that is a whole number between
//!   2^53 and 2^64 from zero: that is refused, because an integer was likely
//!   meant and its digits are not the number the caller wrote;
//! - a `bigint` is written as its digits, and is refused outside the 64-bit
//!   range the engine's parser reads;
//! - anything else (bytes, a date, a timestamp, a decimal, a UUID,
//!   `undefined`) is refused: it has no JSON form;
//! - a document nested deeper than 127 levels is refused, as the engine's
//!   parser would refuse it on the way out.
//!
//! On the way out, an integer in the safe range is a `number`, and one
//! outside it a `bigint`, so no digit is lost. A float is a `number`.
//!
//! The document is sealed by the engine's [`JsonPlaintext`], as its JSON
//! text, and read back by the engine's parser. Everything built on the way,
//! map keys included, is wiped when it is dropped.

use napi::bindgen_prelude::{ClassInstance, FromNapiValue, JavaScriptClassExt, Unknown};
use napi::Env;
use napi_derive::napi;
use serde_json::{Map, Number, Value};
use stack_encrypt::dynamic::plaintext::{
    Error as SinkError, FixedType, Float, Int, Logical, MapSink, Physical, SeqSink, Sink,
    SourceError,
};
use stack_encrypt::dynamic::{read_json, ValueFrame};
use stack_encrypt::json::{wipe_value, JsonPlaintext};
use stack_encrypt::{Encrypt, EncryptRef};
use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroizing;

use crate::error::{Error, RecipherErrorFields};
use crate::js;

/// The deepest a document nests: the engine's parser reads 127 levels of
/// arrays and objects.
const MAX_DEPTH: usize = 127;

/// The largest integer a JavaScript `number` holds exactly: 2^53 - 1.
const MAX_SAFE: u64 = (1 << 53) - 1;

/// 2^64, the first magnitude past every 64-bit integer.
const TWO_TO_64: f64 = 18_446_744_073_709_551_616.0;

/// A JSON document to encrypt as one ciphertext, as its JSON text. Nothing
/// inside it can be searched. Make one with `json(..)`.
///
/// The document is read when it is made, so a later change to the object
/// does not change what is encrypted. A document that cannot be encrypted
/// is held as its failure, which `encrypt` returns. `Debug`, `toString()`
/// and Node's `inspect` hide the document.
#[napi]
#[derive(OpaqueDebug)]
pub struct Json {
    document: Result<JsonPlaintext, RecipherErrorFields>,
}

#[napi]
impl Json {
    /// Names the type and hides the document.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Json(***)"
    }
}

impl Json {
    /// The document of `value` when it is a `Json`, as a value to seal, or
    /// why it cannot be one; `None` when `value` is not a `Json`.
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

    /// The document, as a value to seal, or why it cannot be one.
    pub(crate) fn document(&self) -> Result<JsonPlaintext, RecipherErrorFields> {
        match &self.document {
            // The copy is wiped when the `JsonPlaintext` holding it drops.
            Ok(document) => Ok(JsonPlaintext::from(document.value().clone())),
            Err(error) => Err(error.clone()),
        }
    }
}

/// A JSON document, to encrypt as one ciphertext: a plain object, an array,
/// text, a number, a `bigint`, a boolean or `null`, nested at most 127
/// levels. An integer outside a `number`'s safe range is a `bigint`, within
/// 64 bits; a whole `number` between 2^53 and 2^64 from zero is refused,
/// since an integer was likely meant. The document is read now. Never
/// throws: a document that cannot be encrypted is an `Err` from `encrypt`.
#[napi(js_name = "json")]
pub fn json_document(env: &Env, document: Unknown<'_>) -> Json {
    Json {
        document: js::read(env, document).and_then(|frame| self::document(&frame)),
    }
}

/// The JSON sink's error is the SDK's: [`Error::NotJson`] or
/// [`Error::JsonTooDeep`], each fixed text with no part of the value in it.
impl SinkError for Error {
    fn source(_: SourceError) -> Self {
        Self::NotJson {
            what: "it could not be read",
        }
    }
}

/// The document a frame holds, as the engine's [`JsonPlaintext`].
pub(crate) fn document(frame: &ValueFrame) -> Result<JsonPlaintext, RecipherErrorFields> {
    frame
        .visit(ToJson {
            out: Root,
            depth: 0,
        })
        .map(JsonPlaintext::from)
        .map_err(RecipherErrorFields::from)
}

/// The value of an opened document's text, as a frame, by the rules in the
/// module docs.
pub(crate) fn opened(frame: &ValueFrame) -> Result<ValueFrame, RecipherErrorFields> {
    let document = read_json(frame).map_err(|_| Error::NotADocument)?;
    ValueFrame::of(&FromJson(document.value())).map_err(|_| Error::BuildValue.into())
}

/// Where a built value goes.
trait Out {
    type Ok;
    fn put(self, value: Value) -> Result<Self::Ok, Error>;
}

/// The value is the result.
struct Root;

impl Out for Root {
    type Ok = Value;
    fn put(self, value: Value) -> Result<Value, Error> {
        Ok(value)
    }
}

/// The value is the next element of an array.
struct Element<'s>(&'s mut Vec<Value>);

impl Out for Element<'_> {
    type Ok = ();
    fn put(self, value: Value) -> Result<(), Error> {
        self.0.push(value);
        Ok(())
    }
}

/// The value is the member `key` of an object. The key is held wiped on
/// drop until it is in the object, so a member refused or dropped
/// unfinished leaves no copy of its key behind.
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

/// A sink that builds a JSON value at `depth` levels of nesting, and hands
/// it to `O`.
struct ToJson<O> {
    out: O,
    depth: usize,
}

/// A JSON number for a float, by the rules in the module docs.
fn float(value: f64) -> Result<Value, Error> {
    if !value.is_finite() {
        return Err(Error::NotJson {
            what: "a number that is not finite",
        });
    }
    let magnitude = value.abs();
    if value.fract() == 0.0 && magnitude <= MAX_SAFE as f64 {
        // A safe integer, so the conversion is exact.
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

/// A JSON number for an integer, refused outside the 64-bit range.
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
    /// The depth of a container opened here, refused past the limit.
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

/// An array being built. What it holds is wiped if it is dropped unfinished.
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

/// An object being built. What it holds is wiped if it is dropped
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

/// A JSON value walked into a sink, by the rules in the module docs.
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

/// A number as JavaScript reads it: a `number` for a float or a safe
/// integer, a `bigint` for any other integer.
fn number_of(number: &Number) -> Physical<'static> {
    if let Some(n) = number.as_i64() {
        if n.unsigned_abs() <= MAX_SAFE {
            // In range, so the conversion is exact.
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
    use stack_encrypt::dynamic::ValueFrame;
    use stack_encrypt::json::JsonPlaintext;

    fn frame_of_text(text: &str) -> ValueFrame {
        ValueFrame::of(text).unwrap()
    }

    /// Arrays nested `.0` deep, the innermost empty.
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

    /// `depth` arrays, each holding the next, as a frame.
    fn nested(depth: usize) -> ValueFrame {
        ValueFrame::of(&Nested(depth)).unwrap()
    }

    #[test]
    fn a_safe_integer_float_is_written_as_an_integer() {
        let frame = ValueFrame::of(vec![5.0f64, 1.5]).unwrap();
        assert_eq!(document(&frame).unwrap().value(), &json!([5, 1.5]));
    }

    #[test]
    fn a_whole_number_between_2_53_and_2_64_is_refused() {
        let frame = ValueFrame::of(9_007_199_254_740_993.0f64).unwrap();
        let error = document(&frame).unwrap_err();
        assert_eq!(error.code, "recipher::not_json");
        assert!(error.message.contains("bigint"));
    }

    #[test]
    fn a_large_float_is_written_as_a_float_and_reads_back_the_same() {
        for value in [1e20f64, f64::MAX, -6.02e23] {
            let written = document(&ValueFrame::of(value).unwrap()).unwrap();
            assert_eq!(written.value().as_f64(), Some(value));
            // The engine's parser reads the text back as the same float.
            let text = stack_encrypt::json::to_text(written.value()).unwrap();
            let read = JsonPlaintext::parse(std::str::from_utf8(&text).unwrap()).unwrap();
            assert_eq!(read.value().as_f64(), Some(value));
        }
    }

    #[test]
    fn a_bigint_is_written_as_its_digits_within_64_bits() {
        let frame = ValueFrame::of(u64::MAX).unwrap();
        assert_eq!(
            document(&frame).unwrap().value(),
            &json!(18_446_744_073_709_551_615u64)
        );
        assert!(document(&ValueFrame::of(u128::MAX).unwrap()).is_err());
        assert!(document(&ValueFrame::of(i128::MIN).unwrap()).is_err());
    }

    #[test]
    fn bytes_have_no_json_form() {
        let frame = ValueFrame::of(vec![1u8, 2, 3]).unwrap();
        assert_eq!(document(&frame).unwrap_err().code, "recipher::not_json");
    }

    #[test]
    fn a_document_nests_as_deep_as_the_engine_reads_and_no_deeper() {
        assert!(document(&nested(MAX_DEPTH)).is_ok());
        let refused = document(&nested(MAX_DEPTH + 1)).unwrap_err();
        assert_eq!(refused.code, "recipher::too_deep");
    }

    #[test]
    fn an_opened_integer_is_a_number_when_safe_and_an_integer_when_not() {
        let opened = opened(&frame_of_text(
            r#"{"small": 5, "big": 18446744073709551615, "f": 1.5}"#,
        ))
        .unwrap();
        // Read back as a document: the small integer is a float now, the
        // big one is still an integer.
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
        assert_eq!(error.code, "recipher::not_a_document");
        assert!(!error.message.contains("not json"));
    }
}
