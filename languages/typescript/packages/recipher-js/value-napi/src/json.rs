//! JSON documents: a JavaScript value as the text of one, and a document
//! as a JavaScript value.
//!
//! # Encrypting: a JavaScript value to JSON text
//!
//! [`JsRef::to_json`] reads a JavaScript value and writes the text of a
//! JSON document. The walk is the one every value goes through, so the
//! same safety rules apply: only plain objects are read, by their own
//! enumerable string keys, and a hole, a getter that throws, an unpaired
//! surrogate and a reserved property name are refused. The
//! [`js_ref`](crate::js_ref) module lists what a document holds.
//!
//! The text is written straight into a [`Buffer`], which wipes each
//! allocation it outgrows and wipes itself when it is dropped. No tree of
//! the document is built on the way, so no copy of it is left behind.
//!
//! # Decrypting: a document to a JavaScript value
//!
//! [`JsBuilder::build_json`] builds the JavaScript value of a
//! `serde_json::Value`. Each scalar is converted by napi-rs's own
//! conversion for its type. For a number that is:
//!
//! - an integer within 2^53 - 1 of zero: a `number`;
//! - any other integer: a `bigint`, so no digit is lost;
//! - a float: a `number`.
//!
//! An array and an object are written here, not by napi-rs. napi-rs assigns
//! each element and member (`object[key] = value`). An assignment runs a
//! setter that a polluted prototype defines, which would receive the
//! decrypted value. It also gives a member named `__proto__` to the object
//! as its prototype. So this module defines each element and member as an
//! own data property, and refuses the three reserved property names, as
//! [`JsBuilder`] does for every other value.

use std::io;

use napi::bindgen_prelude::{JsValue, Null, ToNapiValue, Unknown};
use napi::{Env, Status};
use serde_json::Value;
use vitaminc_aead::{EncryptRef, FixedType, Float, Logical, MapSink, Physical, SeqSink, Sink};
use vitaminc_protected::Buffer;

use crate::error::{JsFault, NoJsonForm};
use crate::js::{
    define_own_properties, depth_error, forbidden_key, forbidden_key_error, new_array,
    not_json_error, own_property, too_deep, MAX_DEPTH,
};
use crate::{JsBuilder, JsRef};

impl JsRef<'_> {
    /// Write the value as the text of a JSON document, on the JavaScript
    /// thread. The text is plaintext, and comes back in a buffer that is
    /// wiped when it is dropped.
    ///
    /// `max_depth` is the most levels of arrays and objects the document
    /// may nest: the limit of whatever will read the text. `[1]` is one
    /// level. The walk's own limit, [`MAX_DEPTH`], applies too.
    ///
    /// An object's members are written in the order JavaScript lists them.
    ///
    /// # Errors
    ///
    /// A [`JsFault`]: its [`refusal`](JsFault::refusal) names the rule a
    /// refused value broke. A value with no JSON form is
    /// [`Refusal::NotJson`], and a document nested past `max_depth` is
    /// [`Refusal::TooDeep`]. No error holds any part of the value.
    ///
    /// [`Refusal::NotJson`]: crate::Refusal::NotJson
    /// [`Refusal::TooDeep`]: crate::Refusal::TooDeep
    pub fn to_json(self, max_depth: usize) -> Result<Buffer, JsFault> {
        let mut text = Buffer::new();
        self.visit_json(JsonText::new(&mut text, max_depth))?;
        Ok(text)
    }
}

impl<'e> JsBuilder<'e> {
    /// The JavaScript value of a JSON document.
    ///
    /// An integer within 2^53 - 1 of zero is a `number`, any other integer
    /// is a `bigint`, and a float is a `number`. An array and an object are
    /// built from own data properties.
    ///
    /// This function copies nothing out of `document`: the caller still
    /// owns it, and wipes it.
    ///
    /// # Errors
    ///
    /// A [`JsFault`]. [`Refusal::ReservedKey`] is an object with a member
    /// named `__proto__`, `constructor` or `prototype`, and
    /// [`Refusal::TooDeep`] is a document nested past [`MAX_DEPTH`].
    ///
    /// [`Refusal::ReservedKey`]: crate::Refusal::ReservedKey
    /// [`Refusal::TooDeep`]: crate::Refusal::TooDeep
    pub fn build_json(env: &'e Env, document: &Value) -> Result<Unknown<'e>, JsFault> {
        json_to_js(env, document, 0)
    }
}

/// The JavaScript value of `value`, which sits `depth` levels down in its
/// document.
fn json_to_js<'e>(env: &'e Env, value: &Value, depth: usize) -> Result<Unknown<'e>, JsFault> {
    if depth > MAX_DEPTH {
        return Err(depth_error());
    }
    match value {
        Value::Null => Ok(Null.into_unknown(env)?),
        Value::Bool(flag) => Ok((*flag).into_unknown(env)?),
        // napi-rs's conversion of a `serde_json::Number`: see the module
        // docs for which numbers become a `bigint`.
        Value::Number(number) => Ok(number.into_unknown(env)?),
        Value::String(text) => Ok(text.as_str().into_unknown(env)?),
        Value::Array(items) => {
            let mut built = Vec::with_capacity(items.len());
            for item in items {
                built.push(json_to_js(env, item, depth + 1)?);
            }
            let mut array = new_array(env, built.len())?;
            let mut elements = Vec::with_capacity(built.len());
            for (index, item) in built.iter().enumerate() {
                elements.push(own_property(env, &index.to_string(), item)?);
            }
            define_own_properties(&mut array, &elements)?;
            Ok(array.to_unknown())
        }
        Value::Object(members) => {
            let mut built = Vec::with_capacity(members.len());
            for (key, member) in members {
                if forbidden_key(key) {
                    return Err(forbidden_key_error(key));
                }
                built.push((key, json_to_js(env, member, depth + 1)?));
            }
            let mut object = napi::bindgen_prelude::Object::new(env)?;
            let mut properties = Vec::with_capacity(built.len());
            for (key, member) in &built {
                properties.push(own_property(env, key, member)?);
            }
            define_own_properties(&mut object, &properties)?;
            Ok(object.to_unknown())
        }
    }
}

/// A sink that writes one value as JSON text.
///
/// It writes what a JSON document holds: a null, a boolean, an integer, a
/// finite float, text, a sequence and a map. It refuses anything else. An
/// integer is written with its digits at any width. The reader of the text
/// decides which integers it takes.
///
/// A walk that fails part way leaves the text written so far in the
/// buffer. The buffer is the caller's, and is wiped when it is dropped.
pub(crate) struct JsonText<'b> {
    out: &'b mut Buffer,
    /// How many more levels of sequences and maps may open here.
    levels: usize,
    /// The limit the document was given, for the refusal's message.
    limit: usize,
}

impl<'b> JsonText<'b> {
    /// A sink that writes one document into `out`, nested at most
    /// `max_depth` levels of sequences and maps.
    pub(crate) fn new(out: &'b mut Buffer, max_depth: usize) -> Self {
        Self {
            out,
            levels: max_depth,
            limit: max_depth,
        }
    }

    /// The levels left for the children of a sequence or map that opens
    /// here, or the refusal of one that opens past the limit.
    fn open(&self) -> Result<usize, JsFault> {
        self.levels
            .checked_sub(1)
            .ok_or_else(|| too_deep(self.limit))
    }
}

/// Appends to a [`Buffer`], so `serde_json` can write into one.
struct Append<'a>(&'a mut Buffer);

impl io::Write for Append<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes one scalar as `serde_json` writes it: text with its escapes, an
/// integer as its digits, and a float in the shortest form that reads back
/// as the same float. `serde_json` writes each straight into `out`.
fn write_scalar<T: serde::Serialize + ?Sized>(out: &mut Buffer, value: &T) -> Result<(), JsFault> {
    // The only failure is the writer's, and this writer does not fail. The
    // error's text is dropped, so nothing of the value can leave in it.
    serde_json::to_writer(Append(out), value)
        .map_err(|_| JsFault::new(Status::GenericFailure, "JSON text could not be written"))
}

impl<'b> Sink for JsonText<'b> {
    type Ok = ();
    type Error = JsFault;
    type Seq = JsonSeq<'b>;
    type Map = JsonMap<'b>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), JsFault> {
        match (ty, value) {
            (None, Physical::Null) => {
                self.out.extend_from_slice(b"null");
                Ok(())
            }
            (None, Physical::Bool(flag)) => write_scalar(self.out, &flag),
            (None, Physical::Int(int)) => match int.to_i128() {
                Some(signed) => write_scalar(self.out, &signed),
                // Only a `u128` above `i128::MAX` has no `i128`.
                None => write_scalar(self.out, &int.to_u128().unwrap_or(u128::MAX)),
            },
            (None, Physical::Float(float)) => {
                let float = match float {
                    Float::F32(narrow) => f64::from(narrow),
                    Float::F64(wide) => wide,
                };
                // `serde_json` writes a float that is not finite as `null`.
                if !float.is_finite() {
                    return Err(not_json_error(NoJsonForm::NonFinite));
                }
                write_scalar(self.out, &float)
            }
            (None, Physical::Text(text)) => write_scalar(self.out, text),
            (None, Physical::Bytes(_)) => Err(not_json_error(NoJsonForm::Bytes)),
            (Some(Logical::Undefined), _) => Err(not_json_error(NoJsonForm::Undefined)),
            (Some(_), _) => Err(not_json_error(NoJsonForm::Typed)),
        }
    }

    /// An absent value is JSON's `null`, whatever its type.
    fn typed_null(self, _: FixedType) -> Result<(), JsFault> {
        self.scalar(None, Physical::Null)
    }

    fn seq(self, _: Option<usize>) -> Result<JsonSeq<'b>, JsFault> {
        let levels = self.open()?;
        self.out.push(b'[');
        Ok(JsonSeq(Container {
            out: self.out,
            levels,
            limit: self.limit,
            empty: true,
        }))
    }

    fn map(self, _: Option<usize>) -> Result<JsonMap<'b>, JsFault> {
        let levels = self.open()?;
        self.out.push(b'{');
        Ok(JsonMap(Container {
            out: self.out,
            levels,
            limit: self.limit,
            empty: true,
        }))
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<(), JsFault> {
        Err(JsFault::new(
            Status::InvalidArg,
            "a passthrough has no JSON form",
        ))
    }
}

/// An array or an object that is being written.
struct Container<'b> {
    out: &'b mut Buffer,
    levels: usize,
    limit: usize,
    /// Whether no element or member has been written yet.
    empty: bool,
}

impl Container<'_> {
    /// The sink for the next element or member's value, after the comma
    /// that separates it from the one before.
    fn next(&mut self) -> JsonText<'_> {
        if !self.empty {
            self.out.push(b',');
        }
        self.empty = false;
        JsonText {
            out: self.out,
            levels: self.levels,
            limit: self.limit,
        }
    }
}

/// The sequence side of [`JsonText`]: a JSON array.
pub(crate) struct JsonSeq<'b>(Container<'b>);

impl SeqSink for JsonSeq<'_> {
    type Ok = ();
    type Error = JsFault;
    type Element<'s>
        = JsonText<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<JsonText<'_>, JsFault> {
        Ok(self.0.next())
    }

    fn end(self) -> Result<(), JsFault> {
        self.0.out.push(b']');
        Ok(())
    }
}

/// The map side of [`JsonText`]: a JSON object.
pub(crate) struct JsonMap<'b>(Container<'b>);

impl MapSink for JsonMap<'_> {
    type Ok = ();
    type Error = JsFault;
    type Entry<'s>
        = JsonText<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<JsonText<'_>, JsFault> {
        let value = self.0.next();
        write_scalar(value.out, key)?;
        value.out.push(b':');
        Ok(value)
    }

    fn end(self) -> Result<(), JsFault> {
        self.0.out.push(b'}');
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vitaminc_aead::{Encrypt, Int};
    use vitaminc_protected::Controlled;

    use super::*;
    use crate::Refusal;

    /// The JSON text of `value`, nested at most `max_depth` levels.
    fn text_within(value: impl Encrypt, max_depth: usize) -> Result<String, JsFault> {
        let mut out = Buffer::new();
        value.visit(JsonText::new(&mut out, max_depth))?;
        Ok(String::from_utf8(out.risky_ref().clone()).expect("JSON text is UTF-8"))
    }

    fn text(value: impl Encrypt) -> String {
        text_within(value, 127).expect("a JSON value")
    }

    fn refused(value: impl Encrypt) -> Refusal {
        text_within(value, 127)
            .expect_err("no JSON form")
            .refusal()
            .expect("a refusal")
    }

    /// One scalar, sent to the sink as it is.
    struct Scalar<'a>(Option<Logical>, Physical<'a>);

    impl Encrypt for Scalar<'_> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.scalar(self.0, self.1)
        }
    }

    /// `.0` arrays, each inside the one before. The innermost is empty.
    struct Nested(usize);

    impl Encrypt for Nested {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut seq = sink.seq(None)?;
            if self.0 > 1 {
                Nested(self.0 - 1).visit(seq.element()?)?;
            }
            seq.end()
        }
    }

    #[test]
    fn scalars_are_written_as_json() {
        assert_eq!(text(Scalar(None, Physical::Null)), "null");
        assert_eq!(text(true), "true");
        assert_eq!(text(false), "false");
        assert_eq!(text("plain"), r#""plain""#);
        assert_eq!(text(-7i64), "-7");
        assert_eq!(text(1.5f64), "1.5");
        assert_eq!(text(1.5f32), "1.5");
    }

    #[test]
    fn an_integer_is_written_with_its_digits_and_no_fraction() {
        // The number a Go or a Rust reader must read into an integer field.
        assert_eq!(text(5_000_000_000i64), "5000000000");
        assert_eq!(text(i64::MIN), "-9223372036854775808");
        assert_eq!(text(u64::MAX), "18446744073709551615");
        // The sink writes every width. The reader decides what it takes.
        assert_eq!(
            text(Scalar(None, Physical::Int(Int::U128(u128::MAX)))),
            u128::MAX.to_string()
        );
        assert_eq!(
            text(Scalar(None, Physical::Int(Int::I128(i128::MIN)))),
            i128::MIN.to_string()
        );
    }

    #[test]
    fn a_float_is_written_as_a_float_that_reads_back_the_same() {
        assert_eq!(text(5.0f64), "5.0");
        assert_eq!(text(0.1f64), "0.1");
        assert_eq!(text(-0.0f64), "-0.0");
        for float in [
            5.0f64,
            0.1,
            1e20,
            -6.02e23,
            f64::MAX,
            f64::MIN,
            5e-324,
            -0.0,
        ] {
            let written = text(float);
            // A fraction or an exponent: a reader takes it as a float, never
            // as an integer out of range.
            assert!(written.contains(['.', 'e']), "{written}");
            let read: f64 = serde_json::from_str(&written).unwrap();
            assert_eq!(read.to_bits(), float.to_bits(), "{written}");
        }
    }

    #[test]
    fn a_float_that_is_not_finite_is_refused_not_written_as_null() {
        for float in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(refused(float), Refusal::NotJson(NoJsonForm::NonFinite));
        }
        assert_eq!(refused(f32::NAN), Refusal::NotJson(NoJsonForm::NonFinite));
    }

    #[test]
    fn text_is_escaped_and_reads_back_as_itself() {
        for plain in [
            "",
            "quote \" and backslash \\",
            "line\nfeed, tab\t, nul\0, and \u{1f}",
            "José, 日本, 😀, \u{2028} and \u{10FFFF}",
        ] {
            let written = text(plain);
            let read: String = serde_json::from_str(&written).unwrap();
            assert_eq!(read, plain, "{written}");
        }
        assert_eq!(text("a\"b\n"), r#""a\"b\n""#);
    }

    #[test]
    fn arrays_and_objects_are_written_with_their_separators() {
        assert_eq!(text(Vec::<i64>::new()), "[]");
        assert_eq!(text(vec![1i64]), "[1]");
        assert_eq!(text(vec![vec![1i64, 2], vec![]]), "[[1,2],[]]");
        assert_eq!(text(BTreeMap::<String, i64>::new()), "{}");
        let object: BTreeMap<String, Vec<Option<bool>>> = [
            ("a \"key\"".to_owned(), vec![Some(true), None]),
            ("b".to_owned(), vec![]),
        ]
        .into();
        assert_eq!(text(object), r#"{"a \"key\"":[true,null],"b":[]}"#);
    }

    #[test]
    fn a_typed_null_is_null() {
        assert_eq!(text(None::<i64>), "null");
    }

    #[test]
    fn a_value_with_no_json_form_is_refused_by_what_it_is() {
        assert_eq!(
            refused(Scalar(None, Physical::Bytes(&[1, 2, 3]))),
            Refusal::NotJson(NoJsonForm::Bytes)
        );
        assert_eq!(
            refused(Scalar(Some(Logical::Undefined), Physical::Null)),
            Refusal::NotJson(NoJsonForm::Undefined)
        );
        assert_eq!(
            refused(Scalar(Some(Logical::Date), Physical::Int(Int::I32(1)))),
            Refusal::NotJson(NoJsonForm::Typed)
        );
        assert_eq!(
            refused(Scalar(Some(Logical::Uuid), Physical::Bytes(&[0; 16]))),
            Refusal::NotJson(NoJsonForm::Typed)
        );
    }

    #[test]
    fn a_refusal_names_the_kind_of_value_and_never_the_value() {
        let fault = text_within(vec!["a secret".to_owned()], 0).expect_err("too deep");
        assert_eq!(fault.refusal(), Some(Refusal::TooDeep { limit: 0 }));
        assert!(!fault.reason().contains("secret"));
        let fault = text_within(Scalar(None, Physical::Bytes(b"a secret")), 1).expect_err("bytes");
        assert_eq!(fault.reason(), "a JSON document cannot hold bytes");
        assert_eq!(fault.status(), Status::InvalidArg);
    }

    #[test]
    fn a_document_nests_as_deep_as_the_limit_and_no_deeper() {
        for limit in [1usize, 2, 127] {
            let deepest = text_within(Nested(limit), limit).expect("at the limit");
            assert_eq!(
                deepest,
                format!("{}{}", "[".repeat(limit), "]".repeat(limit))
            );
            let fault = text_within(Nested(limit + 1), limit).expect_err("past the limit");
            assert_eq!(fault.refusal(), Some(Refusal::TooDeep { limit }));
        }
        // A scalar is no level, so it is a document at any limit.
        assert_eq!(text_within(5i64, 0).unwrap(), "5");
        assert!(text_within(Nested(1), 0).is_err());
        // A map is a level, as an array is.
        let object: BTreeMap<String, Vec<i64>> = [("k".to_owned(), vec![])].into();
        assert_eq!(text_within(object.clone(), 2).unwrap(), r#"{"k":[]}"#);
        assert!(text_within(object, 1).is_err());
    }

    #[test]
    fn the_refusal_of_a_deep_document_states_the_limit_it_was_given() {
        let fault = text_within(Nested(128), 127).expect_err("past the limit");
        assert_eq!(
            fault.refusal().map(|refusal| refusal.to_string()),
            Some("the value is nested deeper than 127 levels".to_owned())
        );
    }

    #[test]
    fn a_passthrough_has_not_json_error() {
        struct Clear;
        impl Encrypt for Clear {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough("in the clear")
            }
        }
        let fault = text_within(Clear, 127).expect_err("a passthrough");
        assert_eq!(fault.refusal(), None);
        assert!(!fault.reason().contains("in the clear"));
    }

    #[test]
    fn the_text_of_a_document_parses_as_that_document() {
        let object: BTreeMap<String, Vec<Option<f64>>> = [
            ("floats".to_owned(), vec![Some(1.5), None, Some(-2.25e-7)]),
            ("none".to_owned(), vec![]),
        ]
        .into();
        let read: serde_json::Value = serde_json::from_str(&text(object)).unwrap();
        assert_eq!(
            read,
            serde_json::json!({"floats": [1.5, null, -2.25e-7], "none": []})
        );
    }
}
