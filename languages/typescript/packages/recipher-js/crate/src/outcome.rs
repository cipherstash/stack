//! The `Result` that every call that can fail returns to JavaScript.
//!
//! `Result` is the package's TypeScript class pair, `Ok` and `Err`, and the
//! error in an `Err` is the TypeScript class `RecipherError`. Rust cannot
//! define those classes, because `isOk()` narrows a type only in TypeScript.
//! So the package's TypeScript gives the three classes to the addon once,
//! when it loads the addon ([`install_result`]). The addon keeps them in
//! the environment's instance data. A worker thread loads the addon in an
//! environment of its own, so it has its own set. Every call then builds
//! its `Result` itself, `new Ok(value)` or
//! `new Err(new RecipherError(fields))`, on the JavaScript thread.

use std::future::Future;

use napi::bindgen_prelude::{
    FromNapiValue, Function, FunctionRef, JsObjectValue, JsValue, Object, PromiseRaw, ToNapiValue,
    Unknown,
};
use napi::{Env, Status};
use napi_derive::napi;

use crate::error::{Error, RecipherErrorFields};

/// The result of a call's work, before the addon builds it into a
/// JavaScript `Result`.
pub(crate) type Outcome<T> = Result<T, RecipherErrorFields>;

/// The classes a `Result` is built from, for one environment.
struct ResultClasses {
    ok: FunctionRef<(), ()>,
    err: FunctionRef<(), ()>,
    error: FunctionRef<(), ()>,
}

/// Calls `class` with `new`, and one argument.
fn construct<'e>(
    env: &'e Env,
    class: &FunctionRef<(), ()>,
    argument: Unknown<'_>,
) -> napi::Result<Object<'e>> {
    // The reference is typed `()` only to store it. The call needs the
    // argument's type.
    let class = class.borrow_back(env)?.to_unknown();
    let class = Function::<Unknown<'_>, Unknown<'_>>::from_unknown(class)?;
    Object::from_unknown(class.new_instance(argument)?)
}

/// Gives the addon the classes that every call builds its `Result` from.
/// The package calls this once, when it loads the addon, so an
/// application never needs to.
///
/// Returns `true` when the classes were installed. Returns `false` when
/// this JavaScript environment already has them, and keeps the ones it has.
/// That happens when both the ESM and the CommonJS builds of the package
/// load, because the two builds share one addon.
#[napi(
    ts_args_type = "classes: { Ok: typeof Ok; Err: typeof Err; RecipherError: typeof RecipherError }"
)]
pub fn install_result(env: Env, classes: Object<'_>) -> napi::Result<bool> {
    if env.get_instance_data::<ResultClasses>()?.is_some() {
        return Ok(false);
    }
    let class = |name: &str| -> napi::Result<FunctionRef<(), ()>> {
        classes
            .get_named_property::<Function<'_, (), ()>>(name)?
            .create_ref()
    };
    let installed = ResultClasses {
        ok: class("Ok")?,
        err: class("Err")?,
        error: class("RecipherError")?,
    };
    env.set_instance_data(installed, (), |_| {})?;
    Ok(true)
}

/// Returns the classes of `env`. Without them, the addon was loaded without
/// the package, and napi throws this error.
fn classes(env: &Env) -> napi::Result<&'static ResultClasses> {
    env.get_instance_data::<ResultClasses>()?
        .map(|classes| &*classes)
        .ok_or_else(|| {
            napi::Error::new(
                Status::GenericFailure,
                "the addon was loaded without @cipherstash/recipher, which installs its Result classes",
            )
        })
}

/// Returns `new Ok(value)`.
fn ok<'e>(env: &'e Env, value: Unknown<'_>) -> napi::Result<Object<'e>> {
    construct(env, &classes(env)?.ok, value)
}

/// Returns `new Err(new RecipherError(error))`.
fn err<'e>(env: &'e Env, error: RecipherErrorFields) -> napi::Result<Object<'e>> {
    let classes = classes(env)?;
    let fields = error.into_unknown(env)?;
    let error = construct(env, &classes.error, fields)?;
    construct(env, &classes.err, error.to_unknown())
}

/// Builds the `Result` for `outcome`.
///
/// A success becomes an `Ok`, and the `value` function builds its
/// JavaScript value. A failure becomes an `Err`. If the `value` function
/// fails, the `Result` is an `Err` too, so the call still returns a
/// `Result`. The returned `napi::Result` is an error only when napi cannot
/// make the `Result` itself.
pub(crate) fn settle<'e, T>(
    env: &'e Env,
    outcome: Outcome<T>,
    value: impl FnOnce(&'e Env, T) -> Outcome<Unknown<'e>>,
) -> napi::Result<Object<'e>> {
    match outcome.and_then(|ok| value(env, ok)) {
        Ok(value) => ok(env, value),
        Err(error) => err(env, error),
    }
}

/// Returns the failure for a JavaScript value that napi could not make.
/// The caller did not cause this failure and cannot fix it.
pub(crate) fn not_made(_: napi::Error) -> RecipherErrorFields {
    Error::BuildValue.into()
}

/// Builds an `Err` for `error`.
pub(crate) fn failed(env: &Env, error: RecipherErrorFields) -> napi::Result<Object<'_>> {
    err(env, error)
}

/// Runs `work` on napi's asynchronous runtime, and returns a promise of its
/// `Result`. The `value` function builds the success's JavaScript value on
/// the JavaScript thread.
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

/// Returns a promise of an `Err` for `error`. A call uses it when it
/// refuses its arguments before any work starts. The call then still
/// returns a promise, and does not throw.
pub(crate) fn refused(
    env: &Env,
    error: RecipherErrorFields,
) -> napi::Result<PromiseRaw<'_, Object<'_>>> {
    spawn(env, async move { Err::<(), _>(error) }, |env, ()| {
        ().into_unknown(env).map_err(not_made)
    })
}
