//! [`JsRef`]: a live JavaScript value as an [`Encrypt`] source.
//!
//! The walk runs on the JavaScript thread, reading each value as it goes:
//! no tree is built, and a scalar leaves the engine only to go straight to
//! the sink. Values map to sink calls as follows:
//!
//! | JavaScript             | `Sink` call                                     |
//! | ---------------------- | ----------------------------------------------- |
//! | `null`                 | `scalar(None, Null)`                            |
//! | `undefined`            | `scalar(Some(Undefined), Null)`                 |
//! | `boolean`              | `scalar(None, Bool)`                            |
//! | `number`               | `scalar(None, Float(F64))`                      |
//! | `bigint`               | `scalar(None, Int(narrowest fitting width))`    |
//! | `string`               | `scalar(None, Text)`                            |
//! | `Buffer`, `Uint8Array` | `scalar(None, Bytes)`; any other view is refused |
//! | `Date`                 | `scalar(Some(Timestamp(Millis)), Int(I64(ms)))` |
//! | `Array`                | `seq`, then `element()` per index               |
//! | plain object           | `map`, then `entry(key)` per own property       |
//!
//! The wrapper classes carry the scalars JavaScript has no type for:
//! `VcDate` is `Date` over the day count, `VcTimestamp` is
//! `Timestamp(Nanos)` over the nanosecond count, `VcDecimal` is `Decimal`
//! over the mantissa and `VcUuid` is `Uuid` over sixteen bytes.
//!
//! A getter that throws, a string with an unpaired surrogate, a BigInt out
//! of range or a `Date` outside the wire's range stops the walk through
//! [`Error::source`](vitaminc_aead::plaintext::Error::source), and comes
//! back to JavaScript as that error: see [`JsFault`].

use napi::bindgen_prelude::{
    Array, BigInt, FromNapiValue, JsObjectValue, JsValue, Object, Uint8ArraySlice, Unknown,
};
use napi::{Env, Error, Status, ValueType};
use vitaminc_aead::frame::FrameWriteError;
use vitaminc_aead::plaintext::{Error as _, SourceError};
use vitaminc_aead::{
    to_frame, Encrypt, Float, Logical, MapSink, Physical, SeqSink, Sink, TimeUnit,
};
use vitaminc_protected::Buffer;

use crate::error::JsFault;
use crate::js::{
    depth_error, forbidden_key, forbidden_key_error, get_own, lossless_string, not_plain_error,
    own_enumerable_keys, MAX_DEPTH,
};
use crate::scalar::{self, ConversionError};
use crate::wrappers::{Wrapper, Wrappers};

/// A live JavaScript value, walked in place on the JavaScript thread.
pub struct JsRef<'e> {
    value: Unknown<'e>,
    depth: usize,
}

impl<'e> JsRef<'e> {
    /// The value to walk, as the root of the structure.
    pub fn new(value: Unknown<'e>) -> Self {
        Self { value, depth: 0 }
    }

    /// A value that sits `depth` levels down in a larger structure, so
    /// the nesting limit counts the whole structure.
    pub(crate) fn at_depth(value: Unknown<'e>, depth: usize) -> Self {
        Self { value, depth }
    }

    /// Snapshot the value as a frame, on the JavaScript thread, so it can be
    /// encrypted on a worker with no JavaScript access. The frame is
    /// plaintext and comes back wiped on drop.
    pub fn to_frame(self) -> napi::Result<Buffer> {
        to_frame(self).map_err(frame_error)
    }
}

impl Encrypt for JsRef<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        js_walk(self.value, self.depth, sink)
    }
}

/// A frame writer's refusal as the napi error to hand back.
pub(crate) fn frame_error(error: FrameWriteError) -> Error {
    match error {
        FrameWriteError::Source(source) => JsFault::from_source(&source),
        FrameWriteError::TooDeep => depth_error(),
        other => Error::new(Status::InvalidArg, other.to_string()),
    }
}

/// A JavaScript-side failure, as the sink's error.
fn js_fault<S: Sink>(error: Error) -> S::Error {
    S::Error::source(SourceError::new(JsFault::from(error)))
}

/// A scalar conversion failure: thrown into JavaScript as a `TypeError`
/// with the error's stable code, and carried as the pending exception.
fn js_conversion<S: Sink>(env: &Env, error: ConversionError) -> S::Error {
    let error = match env.throw_type_error(&error.to_string(), Some(error.code())) {
        Ok(()) => Error::new(Status::PendingException, error.to_string()),
        Err(error) => error,
    };
    js_fault::<S>(error)
}

fn js_walk<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    if depth > MAX_DEPTH {
        return Err(js_fault::<S>(depth_error()));
    }
    match value.get_type().map_err(js_fault::<S>)? {
        ValueType::Null => sink.scalar(None, Physical::Null),
        ValueType::Undefined => sink.scalar(Some(Logical::Undefined), Physical::Null),
        ValueType::Boolean => {
            let b = bool::from_unknown(value).map_err(js_fault::<S>)?;
            sink.scalar(None, Physical::Bool(b))
        }
        ValueType::Number => {
            let n = f64::from_unknown(value).map_err(js_fault::<S>)?;
            sink.scalar(None, Physical::Float(Float::F64(n)))
        }
        ValueType::BigInt => {
            let env = Env::from_raw(value.value().env);
            let big = BigInt::from_unknown(value).map_err(js_fault::<S>)?;
            let int = scalar::bigint(big.sign_bit, &big.words)
                .map_err(|e| js_conversion::<S>(&env, e))?;
            sink.scalar(None, Physical::Int(int))
        }
        ValueType::String => {
            // The text is copied out of the engine to check it and goes
            // straight to the sink; the V8 original cannot be wiped from here.
            let text = lossless_string(value, "string").map_err(js_fault::<S>)?;
            sink.scalar(None, Physical::Text(&text))
        }
        ValueType::Object => js_object(value, depth, sink),
        other => Err(js_fault::<S>(Error::new(
            Status::InvalidArg,
            format!("JS type cannot be encrypted: {other}"),
        ))),
    }
}

/// Dispatch an object. The scalar shapes are read in helpers whose frames
/// are gone before the containers recurse, so the stack a nested level
/// costs is the recursion's own and a document at the depth limit walks
/// in a debug build too.
fn js_object<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    // Typed arrays before anything else: `napi_is_buffer` is true for every
    // `ArrayBufferView`, so a `Buffer` check first would take a
    // `Float64Array` as raw bytes.
    if value.is_typedarray().map_err(js_fault::<S>)? {
        return js_bytes(value, sink);
    }
    if value.is_dataview().map_err(js_fault::<S>)? {
        return Err(js_fault::<S>(not_bytes_error("DataView")));
    }
    if value.is_array().map_err(js_fault::<S>)? {
        return js_array(value, depth, sink);
    }
    if value.is_date().map_err(js_fault::<S>)? {
        return js_date(value, sink);
    }
    match js_classify(value).map_err(js_fault::<S>)? {
        Some(wrapper) => js_wrapped(value, wrapper, sink),
        None => js_map(value, depth, sink),
    }
}

/// A `Buffer` or `Uint8Array` as bytes. Only byte views are meaningful
/// plaintext: a `Float64Array`, an `Int16Array`, a `BigInt64Array` or a
/// `Uint8ClampedArray` would seal as its raw bytes and silently decrypt
/// as a `Buffer`, so the cast, which checks the element type, refuses
/// them. A `Buffer` is a `Uint8Array` and passes.
///
/// The view is borrowed as a slice, which holds no reference. napi-rs's
/// `Uint8Array` takes a reference before it checks the element type and
/// never releases it when the check fails, so every refused array would
/// stay alive until the environment exits.
fn js_bytes<S: Sink>(value: Unknown<'_>, sink: S) -> Result<S::Ok, S::Error> {
    let arr = Uint8ArraySlice::from_unknown(value)
        .map_err(|_| js_fault::<S>(not_bytes_error("typed array")))?;
    sink.scalar(None, Physical::Bytes(&arr))
}

fn not_bytes_error(what: &str) -> Error {
    Error::new(
        Status::InvalidArg,
        format!("only a Buffer or a Uint8Array can be encrypted as bytes, not a {what}"),
    )
}

fn js_date<S: Sink>(value: Unknown<'_>, sink: S) -> Result<S::Ok, S::Error> {
    let env = Env::from_raw(value.value().env);
    let date = napi::JsDate::from_unknown(value).map_err(js_fault::<S>)?;
    let ms = date.value_of().map_err(js_fault::<S>)?;
    let count = scalar::date_millis(ms).map_err(|e| js_conversion::<S>(&env, e))?;
    sink.scalar(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(count),
    )
}

/// Which wrapper class an object is an instance of, or none for a plain
/// object. Anything else is refused.
fn js_classify(value: Unknown<'_>) -> napi::Result<Option<Wrapper>> {
    let env = Env::from_raw(value.value().env);
    let wrappers = Wrappers::get(&env)?;
    // Most objects are plain, and a plain object has no wrapper prototype
    // in its chain, so it is asked first and the class checks are skipped.
    if wrappers.is_plain(value)? {
        return Ok(None);
    }
    match wrappers.classify(&value)? {
        Some(wrapper) => Ok(Some(wrapper)),
        None => Err(not_plain_error()),
    }
}

fn js_map<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    let obj = Object::from_unknown(value).map_err(js_fault::<S>)?;
    let keys = own_enumerable_keys(&obj).map_err(js_fault::<S>)?;
    let mut map = sink.map(Some(keys.len()))?;
    for key in keys {
        if forbidden_key(&key.name) {
            return Err(js_fault::<S>(forbidden_key_error(&key.name)));
        }
        // Raw fetch so an explicit `undefined` value survives as
        // `Undefined` instead of reading as a missing property.
        let value = get_own(&obj, &key).map_err(js_fault::<S>)?;
        js_walk(value, depth + 1, map.entry(&key.name)?)?;
    }
    map.end()
}

fn js_array<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    let arr = Array::from_unknown(value).map_err(js_fault::<S>)?;
    // The same JS value seen as an object, for per-index own-property
    // checks: `Array::get` wraps every in-bounds hole in `Some(undefined)`,
    // so on its own it can neither reject sparseness nor resist a polluted
    // `Array.prototype` filling holes with inherited elements.
    let obj = Object::from_unknown(value).map_err(js_fault::<S>)?;
    let len = arr.len();
    let mut seq = sink.seq(Some(len as usize))?;
    for i in 0..len {
        // A hole has no own property; an explicit `undefined` element does.
        // `[undefined]` round-trips; `[, , "x"]` and `new Array(n)` are
        // rejected.
        let sparse = || Error::new(Status::InvalidArg, "sparse arrays are not supported");
        if !obj
            .has_own_property(&i.to_string())
            .map_err(js_fault::<S>)?
        {
            return Err(js_fault::<S>(sparse()));
        }
        let element: Unknown = arr
            .get(i)
            .map_err(js_fault::<S>)?
            .ok_or_else(|| js_fault::<S>(sparse()))?;
        js_walk(element, depth + 1, seq.element()?)?;
    }
    seq.end()
}

/// A wrapper instance as its scalar. The text is read as an own string
/// property and checked here, so an instance made without the constructor
/// is held to the same rule.
fn js_wrapped<S: Sink>(value: Unknown<'_>, wrapper: Wrapper, sink: S) -> Result<S::Ok, S::Error> {
    let env = &Env::from_raw(value.value().env);
    let wrappers = Wrappers::get(env).map_err(js_fault::<S>)?;
    let instance = &Object::from_unknown(value).map_err(js_fault::<S>)?;
    let invalid = match wrapper {
        Wrapper::Date => ConversionError::InvalidDate,
        Wrapper::Timestamp => ConversionError::InvalidTimestamp,
        Wrapper::Decimal => ConversionError::InvalidDecimal,
        Wrapper::Uuid => ConversionError::InvalidUuid,
    };
    let text = match wrappers.text(instance).map_err(js_fault::<S>)? {
        Some(text) => lossless_string(text, wrapper.class_name()).map_err(js_fault::<S>)?,
        None => return Err(js_conversion::<S>(env, invalid)),
    };
    let convert = |e| js_conversion::<S>(env, e);
    match wrapper {
        Wrapper::Date => {
            let days = scalar::date(&text).map_err(convert)?;
            sink.scalar(Some(Logical::Date), Physical::Int(days))
        }
        Wrapper::Timestamp => {
            let nanos = scalar::timestamp(&text).map_err(convert)?;
            sink.scalar(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(nanos),
            )
        }
        Wrapper::Decimal => {
            let (scale, mantissa) = scalar::decimal(&text).map_err(convert)?;
            sink.scalar(Some(Logical::Decimal { scale }), Physical::Int(mantissa))
        }
        Wrapper::Uuid => {
            let bytes = scalar::uuid(&text).map_err(convert)?;
            sink.scalar(Some(Logical::Uuid), Physical::Bytes(&bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_writers_refusal_becomes_the_napi_error_the_host_expects() {
        let too_deep = frame_error(FrameWriteError::TooDeep);
        assert_eq!(too_deep.status, Status::InvalidArg);
        assert!(too_deep.reason.contains("nested too deeply"), "{too_deep}");

        let too_long = frame_error(FrameWriteError::TooLong);
        assert_eq!(too_long.status, Status::InvalidArg);
        assert_eq!(too_long.reason, FrameWriteError::TooLong.to_string());

        // A getter that threw comes back as the error it threw.
        let thrown = Error::new(Status::PendingException, "the getter threw");
        let source = FrameWriteError::Source(SourceError::new(JsFault::from(thrown)));
        let back = frame_error(source);
        assert_eq!(back.status, Status::PendingException);
        assert_eq!(back.reason, "the getter threw");
    }
}
