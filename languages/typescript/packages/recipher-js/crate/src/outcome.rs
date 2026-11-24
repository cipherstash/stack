//! The outcome object every call that can fail returns.

use std::future::Future;

use napi::bindgen_prelude::{JsObjectValue, Object, PromiseRaw, ToNapiValue, Unknown};
use napi::Env;

use crate::error::{Error, RecipherErrorFields};

/// What a call's work comes to before JavaScript sees it.
pub(crate) type Outcome<T> = Result<T, RecipherErrorFields>;

/// The outcome object for `outcome`: `{ ok: true, value }`, with `value`
/// building the success's JavaScript value, or `{ ok: false, error }`. A
/// failure to build the value is a failure too, so the call still returns
/// an outcome. The `napi::Result` is an error only when napi cannot make the
/// object itself.
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

/// The failure for a value napi could not make, which is never the
/// caller's to fix.
pub(crate) fn not_made(_: napi::Error) -> RecipherErrorFields {
    Error::BuildValue.into()
}

/// A failure, as an outcome object.
pub(crate) fn failed(env: &Env, error: RecipherErrorFields) -> napi::Result<Object<'_>> {
    settle(env, Err::<(), _>(error), |env, ()| {
        ().into_unknown(env).map_err(not_made)
    })
}

/// Run `work` on napi's runtime and resolve the promise to its outcome
/// object, built on the JavaScript thread by `value`.
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

/// A promise of `error`'s outcome, for a call refused before any work
/// starts, so the call still returns a promise and never throws.
pub(crate) fn refused(
    env: &Env,
    error: RecipherErrorFields,
) -> napi::Result<PromiseRaw<'_, Object<'_>>> {
    spawn(env, async move { Err::<(), _>(error) }, |env, ()| {
        ().into_unknown(env).map_err(not_made)
    })
}
