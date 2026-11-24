//! JavaScript values in and out, through `recipher-value-napi`.
//!
//! A value is read with `JsRef::to_frame`, on the JavaScript thread, into
//! the engine's [`ValueFrame`]: a buffer wiped when it drops, which a worker
//! thread then seals with no access to JavaScript. An opened frame is built
//! back into a JavaScript value with `JsBuilder::build`. Nothing here
//! converts a value itself.
//!
//! When the bridge refuses a value it says which rule the value broke, and
//! for a scalar it also throws into JavaScript. [`read`] turns either into a [`RecipherErrorFields`] of kind `value`, so a
//! call that reads a value returns an outcome rather than throwing. What a
//! getter of the application's threw is caught and dropped, never copied:
//! its message may hold the value.

use napi::bindgen_prelude::{FromNapiValue, JsObjectValue, JsValue, Object, Unknown};
use napi::{Env, Status, ValueType};
use napi::{Property, PropertyAttributes};
use recipher_value_napi::{JsBuilder, JsFault, JsRef, Refusal, Wrapper, Wrappers};
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::AsProtectedRef;
use vitaminc_aead::Frame;
use vitaminc_protected::Controlled;

use crate::error::{ErrorKind, RecipherErrorFields};
use crate::outcome::not_made;

/// Read a JavaScript value into the engine's value model.
///
/// # Errors
///
/// A failure of kind `value`: `undefined`, a value vitaminc refused or that
/// threw while it was read, or one outside the engine's value model, such
/// as a `VcUuid`.
pub fn read(env: &Env, value: Unknown<'_>) -> Result<ValueFrame, RecipherErrorFields> {
    if value.get_type().ok() == Some(ValueType::Undefined) {
        return Err(RecipherErrorFields::new(
            ErrorKind::Value,
            "recipher::undefined",
            "`undefined` is not a value; use `null` for a value that is not there",
        ));
    }
    let uuid = is_uuid(env, &value);
    let frame = JsRef::new(value)
        .to_frame()
        .map_err(|error| refused(env, &error))?;
    ValueFrame::from_bytes(frame.as_protected_ref()).map_err(|error| {
        if uuid {
            return RecipherErrorFields::new(
                ErrorKind::Value,
                "recipher::uuid",
                "a UUID cannot be encrypted yet: the engine's value model does not hold \
                 one. Encrypt its text instead",
            );
        }
        RecipherErrorFields::new(
            ErrorKind::Value,
            "recipher::value",
            format!("the value cannot be encrypted: {error}"),
        )
    })
}

/// The elements of `value` when it is an array, or `None` when it is not.
///
/// # Errors
///
/// A failure of kind `value` when an element cannot be read, such as one
/// behind a getter that throws.
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

/// Build the JavaScript value of an opened frame.
///
/// # Errors
///
/// A failure of kind `open` for a value JavaScript cannot hold as it was
/// sealed (a map key vitaminc does not build), and of kind `internal` for
/// any other failure.
pub fn build(env: &Env, value: ValueFrame) -> Result<Unknown<'_>, RecipherErrorFields> {
    let bytes = value.into_inner();
    let frame = Frame::parse(bytes.risky_ref()).map_err(|_| {
        RecipherErrorFields::internal("recipher::build_value", "an opened value is not a frame")
    })?;
    JsBuilder::build(env, frame).map_err(|error| not_built(env, &error))
}

/// The failure for a value `JsBuilder` did not build.
fn not_built(env: &Env, fault: &JsFault) -> RecipherErrorFields {
    if fault.status() == Status::PendingException {
        let _ = take_exception(env);
    }
    if let Some(refusal @ Refusal::ReservedKey) = fault.refusal() {
        return RecipherErrorFields::diagnostic(ErrorKind::Open, &refusal, None);
    }
    RecipherErrorFields::internal(
        "recipher::build_value",
        format!(
            "the opened value could not be given to JavaScript ({}). Report this as a bug \
             in @cipherstash/recipher.",
            fault.status()
        ),
    )
}

/// Whether `value` is one of vitaminc's `VcUuid`s.
fn is_uuid(env: &Env, value: &Unknown<'_>) -> bool {
    Wrappers::get(env)
        .and_then(|wrappers| wrappers.classify(value))
        .is_ok_and(|wrapper| wrapper == Some(Wrapper::Uuid))
}

/// The property `name` of `value`, when `value` is an object and has it.
///
/// # Errors
///
/// A failure of kind `value` when reading it throws, as a getter may; what
/// it threw is dropped.
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

/// Whether `value` is a record's declaration, as `record(..)` makes it: an
/// object whose `type` is `"record"`. The check reads only that property,
/// so it holds for a declaration from any copy of the package.
pub(crate) fn is_record(env: &Env, value: &Unknown<'_>) -> bool {
    if value.is_array().unwrap_or(true) {
        return false;
    }
    matches!(
        property(env, *value, "type").map(|tag| tag.and_then(string)),
        Ok(Some(tag)) if tag == "record"
    )
}

/// The failure for a call given a second argument whose first is a plain
/// object that is not a declaration: a row with a record that is not one.
/// `None` for anything else, such as a value passed with an index by
/// `Array.prototype.map`.
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
    plain.then(|| {
        RecipherErrorFields::new(
            ErrorKind::Declaration,
            "recipher::not_a_record",
            "the first argument is not a record: a record is declared with record(..)",
        )
    })
}

/// The text of a JavaScript string, or `None` for any other value.
pub(crate) fn string(value: Unknown<'_>) -> Option<String> {
    if value.get_type().ok() != Some(ValueType::String) {
        return None;
    }
    String::from_unknown(value).ok()
}

/// `row`, an opened row of `record`, with an `inspect` that names its
/// fields and hides their values: Node's `util.inspect` and `console.log`
/// print `users { email: [hidden], .. }`. The method is a property keyed
/// by `Symbol.for('nodejs.util.inspect.custom')` that is not enumerable,
/// so the row's own fields are as they were.
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
        // Not enumerable, writable or configurable: no copy, spread or
        // comparison of the row sees it, and nothing replaces it.
        .with_property_attributes(PropertyAttributes::Default);
    object.define_properties(&[property]).map_err(not_made)?;
    Ok(row)
}

/// The failure for a value the bridge refused. The bridge says which rule
/// the value broke; nothing here reads its text. An exception may still be
/// pending in JavaScript, and is cleared: what the application threw is
/// never kept, because its message may hold the value.
fn refused(env: &Env, fault: &JsFault) -> RecipherErrorFields {
    if fault.status() == Status::PendingException {
        let _ = take_exception(env);
    }
    match fault.refusal() {
        Some(refusal) => RecipherErrorFields::diagnostic(ErrorKind::Value, &refusal, None),
        None if fault.status() == Status::PendingException => RecipherErrorFields::new(
            ErrorKind::Value,
            "recipher::threw",
            "reading the value threw. The thrown error is not kept, because its \
             message may hold the value",
        ),
        None => RecipherErrorFields::new(
            ErrorKind::Value,
            "recipher::value",
            "the value cannot be encrypted: it could not be read",
        ),
    }
}

/// The exception pending in `env`, cleared, if there is one.
#[allow(unsafe_code)]
fn take_exception(env: &Env) -> Option<Unknown<'_>> {
    let mut raw = std::ptr::null_mut();
    // SAFETY: `env` is the environment of the call running on this
    // JavaScript thread, and `raw` is a valid out-pointer. Node-API sets it
    // to the pending exception, or to `undefined` when none is pending, and
    // clears it. The status is checked before `raw` is read.
    let status = unsafe { napi::sys::napi_get_and_clear_last_exception(env.raw(), &mut raw) };
    if status != napi::sys::Status::napi_ok || raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is a live value in `env`, made by the call above, and
    // the `Unknown` borrows `env` for no longer than this call.
    Some(unsafe { Unknown::from_raw_unchecked(env.raw(), raw) })
}
