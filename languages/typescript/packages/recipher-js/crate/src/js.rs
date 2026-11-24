//! JavaScript values in and out, through vitaminc's `vitaminc-aead-napi`.
//!
//! A value is read with `JsRef::to_frame`, on the JavaScript thread, into
//! the engine's [`ValueFrame`]: a buffer wiped when it drops, which a worker
//! thread then seals with no access to JavaScript. An opened frame is built
//! back into a JavaScript value with `JsBuilder::build`. Nothing here
//! converts a value itself.
//!
//! When vitaminc refuses a value it throws into JavaScript, or reports why.
//! [`read`] turns either into a [`RecipherErrorFields`] of kind `value`, so a
//! call that reads a value returns an outcome rather than throwing. What a
//! getter of the application's threw is caught and dropped, never copied:
//! its message may hold the value.

use napi::bindgen_prelude::{FromNapiValue, JsObjectValue, JsValue, Object, Unknown};
use napi::{Env, Status, ValueType};
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::AsProtectedRef;
use vitaminc_aead::Frame;
use vitaminc_aead_napi::{JsBuilder, JsRef, Wrapper, Wrappers};
use vitaminc_protected::Controlled;

use crate::error::{ErrorKind, RecipherErrorFields};

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
    Some(read().map_err(|error| refused(env, &error)))
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
fn not_built(env: &Env, error: &napi::Error) -> RecipherErrorFields {
    if error.status == Status::PendingException {
        let _ = take_exception(env);
    }
    if error.reason.starts_with("property name is not allowed") {
        return RecipherErrorFields::new(
            ErrorKind::Open,
            "recipher::reserved_key",
            "the value opened, but it has a property named `__proto__`, `constructor` or \
             `prototype`, which vitaminc does not build in JavaScript",
        );
    }
    RecipherErrorFields::internal(
        "recipher::build_value",
        format!(
            "the opened value could not be given to JavaScript ({}). Report this as a bug \
             in @cipherstash/recipher.",
            error.status
        ),
    )
}

/// Whether `value` is one of vitaminc's `VcUuid`s.
fn is_uuid(env: &Env, value: &Unknown<'_>) -> bool {
    Wrappers::get(env)
        .and_then(|wrappers| wrappers.classify(value))
        .is_ok_and(|wrapper| wrapper == Some(Wrapper::Uuid))
}

/// The codes vitaminc throws a `TypeError` with for a scalar it cannot
/// hold, each with the SDK's own message: a thrown error is the
/// application's to shape, so only its code is read, and only these codes
/// are kept.
const VITAMINC_CODES: [(&str, &str); 6] = [
    (
        "ERR_INTEGER_RANGE",
        "a bigint is outside the signed and unsigned 128-bit range",
    ),
    ("ERR_INVALID_DATE", "a VcDate's text is not a date it holds"),
    (
        "ERR_INVALID_TIMESTAMP",
        "a Date or VcTimestamp is invalid or outside the years -9999 to 9999",
    ),
    ("ERR_INVALID_DECIMAL", "a VcDecimal's text is not a decimal"),
    (
        "ERR_NON_FINITE_DECIMAL",
        "a VcDecimal is not finite, or does not fit 96 bits",
    ),
    ("ERR_INVALID_UUID", "a VcUuid's text is not a UUID"),
];

/// The rules vitaminc's walk refuses a value by, each with the SDK's code
/// and message. vitaminc's own message is matched by its start and never
/// passed on, so no text from the walk reaches the caller.
const WALK_REFUSALS: [(&str, &str, &str); 7] = [
    (
        "only plain objects",
        "recipher::not_plain",
        "a Map, a Set, a class instance or another object that is not plain cannot be \
         encrypted; make it a plain object first",
    ),
    (
        "property name is not allowed",
        "recipher::reserved_key",
        "an object has a property named `__proto__`, `constructor` or `prototype`, \
         which vitaminc refuses in both directions",
    ),
    (
        "value is nested too deeply",
        "recipher::too_deep",
        "the value is nested deeper than 128 levels",
    ),
    (
        "sparse arrays",
        "recipher::sparse_array",
        "an array has a hole; write `undefined` or `null` where a value is missing",
    ),
    (
        "only a Buffer or a Uint8Array",
        "recipher::not_bytes",
        "only a Buffer or a Uint8Array is bytes; another typed array or a DataView is refused",
    ),
    (
        "JS type cannot be encrypted",
        "recipher::not_a_value",
        "a function, a symbol or another type JavaScript has no value of cannot be \
         encrypted",
    ),
    (
        "property was removed",
        "recipher::changed_while_read",
        "an object changed while it was read",
    ),
];

/// The failure for vitaminc's refusal of a value: `error` is what its walk
/// returned, and a JavaScript exception may still be pending.
fn refused(env: &Env, error: &napi::Error) -> RecipherErrorFields {
    let value_error = |code: &str, message: &str| {
        RecipherErrorFields::new(ErrorKind::Value, code, message.to_owned())
    };
    if error.status == Status::PendingException {
        let code = take_exception(env).and_then(|exception| vitaminc_code(env, exception));
        return match VITAMINC_CODES
            .iter()
            .find(|(known, _)| Some(*known) == code)
        {
            Some((code, message)) => value_error(code, message),
            None => value_error(
                "recipher::threw",
                "reading the value threw. The thrown error is not kept, because its \
                 message may hold the value",
            ),
        };
    }
    if error.reason.contains("unpaired surrogate") {
        return value_error(
            "recipher::unpaired_surrogate",
            "a string or a property name has an unpaired surrogate, so it has no exact \
             UTF-8 form",
        );
    }
    match WALK_REFUSALS
        .iter()
        .find(|(start, _, _)| error.reason.starts_with(start))
    {
        Some((_, code, message)) => value_error(code, message),
        None => value_error(
            "recipher::value",
            "the value cannot be encrypted: vitaminc refused it",
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

/// vitaminc's code on a thrown error, if it is one of vitaminc's. Only a
/// string `code` is read; nothing is converted, so no code of the
/// application's runs except a getter on `code` itself.
fn vitaminc_code(env: &Env, exception: Unknown<'_>) -> Option<&'static str> {
    if !exception.is_error().ok()? {
        return None;
    }
    let object = Object::from_unknown(exception).ok()?;
    let code = match object.get_named_property::<Unknown<'_>>("code") {
        Ok(code) => code,
        Err(_) => {
            // A getter on the thrown error threw in turn: clear that too,
            // so no exception is left pending when the call returns.
            let _ = take_exception(env);
            return None;
        }
    };
    if code.get_type().ok()? != napi::ValueType::String {
        return None;
    }
    let code = String::from_unknown(code).ok()?;
    VITAMINC_CODES
        .iter()
        .map(|(known, _)| *known)
        .find(|known| *known == code)
}
