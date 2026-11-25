//! Converts JavaScript values to and from the engine's values, through the
//! value bridge, the `recipher-value-napi` crate.
//!
//! The engine is the Stack Encrypt engine, the `stack-encrypt` crate. The
//! engine's value model is the set of value types it reads.
//!
//! `JsRef::to_frame` reads a JavaScript value, on the JavaScript thread,
//! into the engine's [`ValueFrame`]. A frame is a byte buffer that contains
//! one value. The buffer is wiped when it drops. A worker thread then
//! encrypts the frame, with no access to JavaScript. `JsBuilder::build`
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

use napi::bindgen_prelude::Unknown;
use napi::{Env, Status};
use recipher_value_napi::{JsBuilder, JsFault, JsRef};
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::AsProtectedRef;
use vitaminc_aead::Frame;
use vitaminc_protected::Controlled;

use crate::error::{Error, RecipherErrorFields};

/// Reads a JavaScript value into a frame of the engine's value model.
///
/// # Errors
///
/// Returns one of these errors:
///
/// - `recipher_js::value` for a value outside the engine's value model;
/// - `recipher_js::threw` when reading the value threw;
/// - the bridge's code, for a value the bridge refused.
pub fn read(env: &Env, value: Unknown<'_>) -> Result<ValueFrame, RecipherErrorFields> {
    let frame = JsRef::new(value)
        .to_frame()
        .map_err(|error| refused(env, &error))?;
    ValueFrame::from_bytes(frame.as_protected_ref()).map_err(|_| Error::Value.into())
}

/// Builds the JavaScript value of a decrypted frame.
///
/// # Errors
///
/// Returns `recipher_js::build_value` when the value cannot be built.
pub fn build(env: &Env, value: ValueFrame) -> Result<Unknown<'_>, RecipherErrorFields> {
    let bytes = value.into_inner();
    let frame = Frame::parse(bytes.risky_ref()).map_err(|_| Error::BuildValue)?;
    JsBuilder::build(env, frame).map_err(|error| not_built(env, &error))
}

/// Returns the failure for a value that `JsBuilder` did not build.
fn not_built(env: &Env, fault: &JsFault) -> RecipherErrorFields {
    if fault.status() == Status::PendingException {
        let _ = take_exception(env);
    }
    Error::BuildValue.into()
}

/// Returns the failure for a value the bridge refused. The bridge says
/// which rule the value broke, and this function does not read the
/// bridge's text. An exception may still be pending in JavaScript, and this
/// function clears it. What the application threw is never kept, because
/// its message may contain the value.
fn refused(env: &Env, fault: &JsFault) -> RecipherErrorFields {
    if fault.status() == Status::PendingException {
        let _ = take_exception(env);
    }
    match fault.refusal() {
        Some(refusal) => RecipherErrorFields::diagnostic(&refusal, None),
        None if fault.status() == Status::PendingException => Error::Threw.into(),
        None => Error::Value.into(),
    }
}

/// Clears and returns the exception pending in `env`, if there is one.
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
