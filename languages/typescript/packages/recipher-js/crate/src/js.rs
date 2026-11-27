//! Converts JavaScript values to and from the engine's values, through the
//! value bridge, the `recipher-value-napi` crate.
//!
//! The engine is the Stack Encrypt engine, the `stack-encrypt` crate. The
//! engine's value model is the set of value types it reads.
//!
//! `JsRef::to_frame` reads a JavaScript value, on the JavaScript thread,
//! into a buffer, which becomes the engine's [`OwnedFrame`] without a copy.
//! A frame is a byte buffer that contains one value. The buffer is wiped
//! when it drops. A worker thread then encrypts the frame, with no access to JavaScript. `JsBuilder::build`
//! builds a decrypted frame back into a JavaScript value. This module does
//! not convert any value itself.
//!
//! When the bridge refuses a value, it says which rule the value broke. A
//! scalar is a value that is not an array or an object. For a scalar, the
//! bridge also throws a JavaScript exception. [`read`] turns either into a
//! [`RecipherErrorFields`]. So a call that reads a value returns an `Err`
//! instead of throwing.
//!
//! When an application's getter throws, the addon catches the exception
//! and drops it without copying it. The exception's message may contain
//! the value.

use napi::bindgen_prelude::{FromNapiValue, JsObjectValue, JsValue, Object, Unknown};
use napi::{Env, Status, ValueType};
use napi::{Property, PropertyAttributes};
use recipher_value_napi::{JsBuilder, JsFault, JsRef, Refusal, Wrappers};
use stack_encrypt::dynamic::frame::OwnedFrame;

use crate::error::{Error, RecipherErrorFields};
use crate::outcome::not_made;

/// Reads a JavaScript value into a frame of the engine's value model.
///
/// # Errors
///
/// Returns one of these errors:
///
/// - `recipher_js::undefined` for `undefined`;
/// - `recipher_js::value` when the bridge's bytes are not one well-formed
///   frame the engine reads (`FrameError`);
/// - `recipher_js::threw` when reading the value threw;
/// - the bridge's code, for a value the bridge refused.
pub fn read(env: &Env, value: Unknown<'_>) -> Result<OwnedFrame, RecipherErrorFields> {
    if value.get_type().ok() == Some(ValueType::Undefined) {
        return Err(Error::Undefined.into());
    }
    let frame = JsRef::new(value)
        .to_frame()
        .map_err(|error| refused(env, &error))?;
    // The bridge's buffer becomes the frame: checked, and kept as written.
    OwnedFrame::from_buffer(frame).map_err(|_| Error::Value.into())
}

/// Returns the elements of `value` when it is an array, or `None` when it
/// is not.
///
/// # Errors
///
/// Returns the bridge's refusal, or `recipher_js::threw`, when an element
/// cannot be read. For example, an element behind a getter that throws
/// cannot be read.
pub fn elements<'e>(
    env: &Env,
    value: Unknown<'e>,
) -> Option<Result<Vec<Unknown<'e>>, RecipherErrorFields>> {
    if !value.is_array().unwrap_or(false) {
        return None;
    }
    let array = Object::from_unknown(value).ok()?;
    let read = || -> napi::Result<Vec<Unknown<'e>>> {
        let len = array.get_array_length()?;
        (0..len)
            .map(|at| array.get_element::<Unknown<'e>>(at))
            .collect()
    };
    Some(read().map_err(|error| refused(env, &error.into())))
}

/// Builds the JavaScript value of a decrypted frame.
///
/// # Errors
///
/// Returns `recipher_js::reserved_key` for a value that JavaScript cannot
/// represent in the form it was encrypted. That is a value with a map key
/// that vitaminc, CipherStash's cryptography library, does not build.
/// Returns `recipher_js::build_value` for any other failure.
pub fn build(env: &Env, value: OwnedFrame) -> Result<Unknown<'_>, RecipherErrorFields> {
    JsBuilder::build(env, value.frame()).map_err(|error| not_built(env, &error))
}

/// Returns the failure for a value that `JsBuilder` did not build.
fn not_built(env: &Env, fault: &JsFault) -> RecipherErrorFields {
    if fault.status() == Status::PendingException {
        clear_exception(env);
    }
    match fault.refusal() {
        Some(refusal @ Refusal::ReservedKey) => RecipherErrorFields::diagnostic(&refusal, None),
        _ => Error::BuildValue.into(),
    }
}

/// Returns the property `name` of `value`, when `value` is an object and
/// the property is not `undefined`.
///
/// # Errors
///
/// Returns `recipher_js::threw` when reading the property throws, as a getter
/// can. The addon drops what the getter threw.
pub(crate) fn property<'e>(
    env: &Env,
    value: Unknown<'e>,
    name: &str,
) -> Result<Option<Unknown<'e>>, RecipherErrorFields> {
    if value.get_type().ok() != Some(ValueType::Object) {
        return Ok(None);
    }
    let object = Object::from_unknown(value).map_err(|error| refused(env, &error.into()))?;
    let property = object
        .get_named_property::<Unknown<'e>>(name)
        .map_err(|error| refused(env, &error.into()))?;
    Ok((property.get_type().ok() != Some(ValueType::Undefined)).then_some(property))
}

/// Returns whether `value` is a record declaration, as `record(..)` makes
/// it. A record declaration lists a record's fields and how to store each
/// one. A declaration is an object whose `type` is `"record"`. The check
/// reads only that property, so it works for a declaration from any copy
/// of the package.
pub(crate) fn is_record(env: &Env, value: &Unknown<'_>) -> bool {
    if value.is_array().unwrap_or(true) {
        return false;
    }
    matches!(
        property(env, *value, "type").map(|tag| tag.and_then(string)),
        Ok(Some(tag)) if tag == "record"
    )
}

/// Returns the failure for a call that has a second argument, when the
/// first argument is a plain object but not a record declaration. Such a
/// call passes a row with a record argument that is not a record. Returns
/// `None` for any other call. For example, `Array.prototype.map` passes a
/// value with its index, and that call gets `None`.
pub(crate) fn second_without_record(
    env: &Env,
    first: &Unknown<'_>,
    second: Option<&Unknown<'_>>,
) -> Option<RecipherErrorFields> {
    let second = second?;
    if second.get_type().ok() == Some(ValueType::Undefined)
        || first.get_type().ok() != Some(ValueType::Object)
        || first.is_array().unwrap_or(true)
    {
        return None;
    }
    let plain = Wrappers::get(env)
        .and_then(|wrappers| wrappers.is_plain(*first))
        .unwrap_or(false);
    plain.then(|| Error::NotARecord.into())
}

/// Returns the text of a JavaScript string, or `None` for any other value.
pub(crate) fn string(value: Unknown<'_>) -> Option<String> {
    if value.get_type().ok() != Some(ValueType::String) {
        return None;
    }
    String::from_unknown(value).ok()
}

/// Returns `row`, a decrypted row of `record`, with an added `inspect`
/// method. The method names the row's fields and hides their values. So
/// Node's `util.inspect` and `console.log` print
/// `users { email: [hidden], .. }`. The method is a property keyed by
/// `Symbol.for('nodejs.util.inspect.custom')`. The property is not
/// enumerable, so the row's own fields do not change.
pub(crate) fn hidden<'e>(
    env: &'e Env,
    row: Unknown<'e>,
    record: &str,
    fields: &[String],
) -> Result<Unknown<'e>, RecipherErrorFields> {
    let shown = format!(
        "{record} {{ {} }}",
        fields
            .iter()
            .map(|field| format!("{field}: [hidden]"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut object = Object::from_unknown(row).map_err(not_made)?;
    let inspect = env
        .create_function_from_closure::<(), String, _>("inspect", move |_| Ok(shown.clone()))
        .map_err(not_made)?;
    let key = env
        .symbol_for("nodejs.util.inspect.custom")
        .map_err(not_made)?;
    let property = Property::new()
        .with_name(env, key)
        .map_err(not_made)?
        .with_value(&inspect)
        // The property is not enumerable, writable or configurable. So a
        // copy, spread or comparison of the row does not include it, and
        // nothing can replace it.
        .with_property_attributes(PropertyAttributes::Default);
    object.define_properties(&[property]).map_err(not_made)?;
    Ok(row)
}

/// Returns the failure for a value the bridge refused. The bridge says
/// which rule the value broke, and this function does not read the
/// bridge's text. An exception may still be pending in JavaScript, and this
/// function clears it. What the application threw is never kept, because
/// its message may contain the value.
fn refused(env: &Env, fault: &JsFault) -> RecipherErrorFields {
    if fault.status() == Status::PendingException {
        clear_exception(env);
    }
    match fault.refusal() {
        Some(refusal) => RecipherErrorFields::diagnostic(&refusal, None),
        None if fault.status() == Status::PendingException => Error::Threw.into(),
        None => Error::Value.into(),
    }
}

/// Clears the exception pending in `env`, if there is one, and drops it
/// without reading it.
#[allow(unsafe_code)]
fn clear_exception(env: &Env) {
    let mut raw = std::ptr::null_mut();
    // SAFETY: `env` is the environment of the call running on this
    // JavaScript thread, and `raw` is a valid out-pointer. Node-API sets it
    // to the pending exception, or to `undefined` when none is pending, and
    // clears it. The value is never read; the status needs no handling,
    // because a failure leaves nothing to clear.
    let _ = unsafe { napi::sys::napi_get_and_clear_last_exception(env.raw(), &mut raw) };
}
