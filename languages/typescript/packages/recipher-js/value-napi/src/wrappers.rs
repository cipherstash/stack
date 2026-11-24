//! The wrapper classes: `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid`.
//!
//! JavaScript has no type of its own for a calendar date, a timestamp finer
//! than a millisecond, a decimal or a UUID, so the binding represents each
//! as an instance of a small class holding its text. A class instance is
//! not a plain object, so it can never be confused with data another
//! language wrote as an ordinary one-key object (#382).
//!
//! The classes are defined by the JavaScript in `wrappers.js`, evaluated
//! once per environment. The object it returns (the classes and the
//! plain-object check, frozen) is kept in a registry keyed by the
//! environment and released by an environment cleanup hook, so the
//! addon's own instance data (`napi_set_instance_data`) is never touched.
//! An addon exports the classes with [`Wrappers::exports`] so applications
//! can construct them; the walk recognises instances with `instanceof`,
//! and the build constructs them.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use napi::bindgen_prelude::{Function, JsObjectValue, JsValue, Object, ObjectRef, Unknown};
use napi::{Env, Error, Result, Status};

/// Which wrapper class a value is an instance of.
///
/// A logical type JavaScript has no value for needs a new class, so more
/// variants may come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Wrapper {
    /// `VcDate`: a calendar date as `YYYY-MM-DD`.
    Date,
    /// `VcTimestamp`: an instant as RFC 3339 text, to the nanosecond.
    Timestamp,
    /// `VcDecimal`: a fixed-point decimal as text.
    Decimal,
    /// `VcUuid`: a UUID as hyphenated hexadecimal.
    Uuid,
}

impl Wrapper {
    /// Every wrapper class, in the order the walk asks them.
    pub const ALL: &'static [Wrapper] = &[
        Wrapper::Date,
        Wrapper::Timestamp,
        Wrapper::Decimal,
        Wrapper::Uuid,
    ];

    /// The class name, as JavaScript sees it.
    pub fn class_name(self) -> &'static str {
        match self {
            Wrapper::Date => "VcDate",
            Wrapper::Timestamp => "VcTimestamp",
            Wrapper::Decimal => "VcDecimal",
            Wrapper::Uuid => "VcUuid",
        }
    }
}

const SOURCE: &str = include_str!("wrappers.js");

/// The own property a wrapper instance holds its text in.
const VALUE: &str = "value";

/// The property of the script's result that answers the plain-object check.
const IS_PLAIN: &str = "isPlain";

/// One environment's evaluated `wrappers.js`, by the environment's raw
/// handle. An entry is added on first use and removed by the cleanup hook
/// registered then, so a handle a later environment reuses starts fresh.
/// The reference is dropped without the leak warning: it is released by
/// the hook while the environment is still live.
static REALMS: LazyLock<Mutex<HashMap<usize, ObjectRef<false>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn registry_poisoned() -> Error {
    Error::new(Status::GenericFailure, "wrapper class registry is poisoned")
}

/// The wrapper classes of one environment, for one call: a borrowed view
/// that cannot outlive the environment it was taken from.
pub struct Wrappers<'e> {
    classes: Object<'e>,
}

impl<'e> Wrappers<'e> {
    /// The wrapper classes of `env`, defined on first use.
    pub fn get(env: &'e Env) -> Result<Self> {
        let key = env.raw() as usize;
        let existing = REALMS
            .lock()
            .map_err(|_| registry_poisoned())?
            .get(&key)
            .map(|classes| classes.get_value(env))
            .transpose()?;
        let classes = match existing {
            Some(classes) => classes,
            // The script runs outside the lock: it is self-contained, but
            // nothing that runs JavaScript should hold a lock the
            // JavaScript thread may take again.
            None => {
                let classes: Object<'e> = env.run_script(SOURCE)?;
                let reference = classes.create_ref::<false>()?;
                REALMS
                    .lock()
                    .map_err(|_| registry_poisoned())?
                    .insert(key, reference);
                env.add_env_cleanup_hook(key, release_wrappers)?;
                classes
            }
        };
        Ok(Self { classes })
    }

    /// An object holding every class under its name, for an addon to
    /// re-export: `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid`.
    pub fn exports(env: &'e Env) -> Result<Object<'e>> {
        let wrappers = Self::get(env)?;
        let mut exports = Object::new(env)?;
        for &wrapper in Wrapper::ALL {
            exports.set_named_property(wrapper.class_name(), wrappers.constructor(wrapper)?)?;
        }
        Ok(exports)
    }

    fn constructor(&self, wrapper: Wrapper) -> Result<Function<'e, String, Unknown<'e>>> {
        self.classes.get_named_property(wrapper.class_name())
    }

    /// Which wrapper class `value` is an instance of, if any.
    pub fn classify(&self, value: &Unknown<'e>) -> Result<Option<Wrapper>> {
        for &wrapper in Wrapper::ALL {
            if value.instanceof(self.constructor(wrapper)?)? {
                return Ok(Some(wrapper));
            }
        }
        Ok(None)
    }

    /// Whether `value` is a plain object: prototype `Object.prototype` or
    /// `null` (`Object.create(null)`).
    ///
    /// Anything else stores its state in internal slots or carries class
    /// behaviour that key/value enumeration silently loses: a `Map`'s or
    /// `Set`'s contents enumerate as `{}`, a `RegExp` drops its pattern and
    /// flags, an `ArrayBuffer` or `DataView` its bytes. Encrypting such a
    /// value would destroy the payload with no error at either end, so the
    /// walk refuses it instead, unless it is an instance of a wrapper class.
    /// The question is put to the `Object.getPrototypeOf` captured when the
    /// script was evaluated, which runs a `Proxy`'s trap; `napi_get_prototype`
    /// reports `null` for every proxy, which would pass a proxied `Map` as
    /// `Object.create(null)`.
    ///
    /// A trap that throws leaves its exception pending, so the caller hands
    /// back the very value thrown, as it would for a getter that throws.
    pub fn is_plain(&self, value: Unknown<'e>) -> Result<bool> {
        let is_plain: Function<'e, Unknown<'e>, bool> =
            self.classes.get_named_property(IS_PLAIN)?;
        // napi-rs clears the exception a called function throws and keeps
        // it inside the error, which a `JsFault` cannot carry, so it is
        // thrown again here.
        is_plain.call(value).map_err(|error| {
            let reason = error.reason.clone();
            match Env::from_raw(self.classes.value().env).throw(error) {
                Ok(()) => Error::new(Status::PendingException, reason),
                Err(error) => error,
            }
        })
    }

    /// The text a wrapper instance holds. The class keeps `value` as an
    /// own, read-only string, but an instance can be made without the
    /// constructor (`Object.create`), so the property is read as an own
    /// property and its type checked.
    pub fn text(&self, instance: &Object<'e>) -> Result<Option<Unknown<'e>>> {
        if !instance.has_own_property(VALUE)? {
            return Ok(None);
        }
        let text = crate::js::get_property_unknown(instance, VALUE)?;
        Ok((text.get_type()? == napi::ValueType::String).then_some(text))
    }

    /// A new instance of `wrapper` holding `text`.
    pub fn construct(&self, wrapper: Wrapper, text: &str) -> Result<Unknown<'e>> {
        self.constructor(wrapper)?.new_instance(text.to_owned())
    }
}

/// The environment cleanup hook: delete the reference while the
/// environment can still do so, and forget the entry.
///
/// Only a live environment can run this, so no unit test reaches it; the
/// Worker teardown check in `tests/object-safety.cjs` does.
#[cfg_attr(test, mutants::skip)]
fn release_wrappers(key: usize) {
    let Ok(mut realms) = REALMS.lock() else {
        return;
    };
    if let Some(reference) = realms.remove(&key) {
        let env = Env::from_raw(key as napi::sys::napi_env);
        // A failure here leaves a reference the environment is about to
        // reclaim anyway; there is nobody to report it to.
        let _ = reference.unref(&env);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_wrapper_has_the_class_name_javascript_sees() {
        let names: Vec<&str> = Wrapper::ALL.iter().map(|w| w.class_name()).collect();
        assert_eq!(names, ["VcDate", "VcTimestamp", "VcDecimal", "VcUuid"]);
        for &wrapper in Wrapper::ALL {
            assert_eq!(wrapper.class_name(), format!("Vc{wrapper:?}"));
        }
    }
}
