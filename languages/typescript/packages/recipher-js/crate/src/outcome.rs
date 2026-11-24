//! Outcome objects: what every call that can fail returns to JavaScript.
//!
//! An outcome object is `{ ok: true, value }` on success, or
//! `{ ok: false, error }` on failure. A call returns one instead of
//! throwing.

use std::future::Future;

use napi::bindgen_prelude::{JsObjectValue, Object, PromiseRaw, ToNapiValue, Unknown};
use napi::Env;

use crate::error::{Error, RecipherErrorFields};

/// The result of a call's work, before the addon builds it into an outcome
/// object for JavaScript.
pub(crate) type Outcome<T> = Result<T, RecipherErrorFields>;

/// Builds the outcome object for `outcome`.
///
/// A success becomes `{ ok: true, value }`, and the `value` function builds
/// its JavaScript value. A failure becomes `{ ok: false, error }`. If the
/// `value` function fails, the outcome object is a failure too, so the call
/// still returns an outcome object. The returned `napi::Result` is an error
/// only when napi cannot make the object itself.
pub(crate) fn settle<'e, T>(
    env: &'e Env,
    outcome: Outcome<T>,
    value: impl FnOnce(&'e Env, T) -> Outcome<Unknown<'e>>,
) -> napi::Result<Object<'e>> {
    let built = outcome.and_then(|ok| value(env, ok));
    let mut object = Object::new(env)?;
    match built {
        Ok(value) => {
            object.set_named_property("ok", true)?;
            object.set_named_property("value", value)?;
        }
        Err(error) => {
            object.set_named_property("ok", false)?;
            object.set_named_property("error", error)?;
        }
    }
    Ok(object)
}

/// Returns the failure for a JavaScript value that napi could not make.
/// The caller did not cause this failure and cannot fix it.
pub(crate) fn not_made(_: napi::Error) -> RecipherErrorFields {
    Error::BuildValue.into()
}

/// Builds a failed outcome object for `error`.
pub(crate) fn failed(env: &Env, error: RecipherErrorFields) -> napi::Result<Object<'_>> {
    settle(env, Err::<(), _>(error), |env, ()| {
        ().into_unknown(env).map_err(not_made)
    })
}

/// Runs `work` on napi's asynchronous runtime, and returns a promise of its
/// outcome object. The `value` function builds the success's JavaScript
/// value on the JavaScript thread.
pub(crate) fn spawn<'e, T, F, V>(
    env: &'e Env,
    work: F,
    value: V,
) -> napi::Result<PromiseRaw<'e, Object<'e>>>
where
    T: Send + 'static,
    F: Future<Output = Outcome<T>> + Send + 'static,
    V: FnOnce(&'e Env, T) -> Outcome<Unknown<'e>> + 'static,
{
    env.spawn_future_with_callback(async move { Ok(work.await) }, move |env, outcome| {
        settle(env, outcome, value)
    })
}

/// Returns a promise of a failed outcome object for `error`. A call uses it
/// when it refuses its arguments before any work starts. The call then
/// still returns a promise, and does not throw.
pub(crate) fn refused(
    env: &Env,
    error: RecipherErrorFields,
) -> napi::Result<PromiseRaw<'_, Object<'_>>> {
    spawn(env, async move { Err::<(), _>(error) }, |env, ()| {
        ().into_unknown(env).map_err(not_made)
    })
}
