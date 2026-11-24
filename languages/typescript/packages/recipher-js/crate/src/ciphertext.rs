//! [`Ciphertext`]: one sealed value, as JavaScript holds it.

use napi::bindgen_prelude::{
    ClassInstance, FromNapiValue, JavaScriptClassExt, JsValue, Object, Uint8Array, Uint8ArraySlice,
    Unknown,
};
use napi::Env;
use napi_derive::napi;
use vitaminc_protected::OpaqueDebug;

use crate::error::{ErrorKind, RecipherErrorFields};
use crate::outcome::{failed, settle};

/// One sealed value: the engine's opaque ciphertext, with its own data key.
///
/// Its bytes are the engine's sealed-value envelope, the bytes Rust's
/// `Ciphertext::to_bytes` and the Go SDK write. `Debug` hides them, and so
/// do `toString()` and Node's `inspect`: the class has no own properties.
///
/// It exists as a class, rather than as the bytes, so that `decrypt` can
/// tell a ciphertext from any other value without reading it.
#[napi]
#[derive(Clone, OpaqueDebug)]
pub struct Ciphertext {
    sealed: stack_encrypt::Ciphertext,
}

impl Ciphertext {
    pub(crate) fn new(sealed: stack_encrypt::Ciphertext) -> Self {
        Self { sealed }
    }

    /// The engine's ciphertext.
    pub(crate) fn sealed(&self) -> &stack_encrypt::Ciphertext {
        &self.sealed
    }

    /// The ciphertext `value` is, or `None` when it is not a `Ciphertext`.
    pub(crate) fn of(env: &Env, value: Unknown<'_>) -> Option<Self> {
        if !Self::instance_of(env, &value).unwrap_or(false) {
            return None;
        }
        ClassInstance::<Ciphertext>::from_unknown(value)
            .ok()
            .map(|instance| Ciphertext::clone(&instance))
    }
}

#[napi]
impl Ciphertext {
    /// Read a ciphertext from stored bytes, a `Uint8Array` or a `Buffer`.
    /// This checks the bytes' shape only; decrypting is what authenticates
    /// them. A failure does not quote the bytes.
    // Configurable, as an instance method is, so the package's TypeScript
    // can wrap it (`adapt`).
    #[napi(configurable = true, ts_return_type = "Outcome<Ciphertext>")]
    pub fn from_bytes<'e>(env: &'e Env, bytes: Unknown<'_>) -> napi::Result<Object<'e>> {
        let bytes = match bytes_of(bytes) {
            Some(bytes) => bytes,
            None => {
                return failed(
                    env,
                    RecipherErrorFields::new(
                        ErrorKind::Value,
                        "recipher::not_bytes",
                        "a ciphertext is read from a Uint8Array",
                    ),
                )
            }
        };
        let outcome = stack_encrypt::Ciphertext::from_bytes(&bytes)
            .map(Ciphertext::new)
            .map_err(|error| RecipherErrorFields::diagnostic(ErrorKind::Open, &error, None));
        settle(env, outcome, |env, ciphertext| {
            Ok(ciphertext.into_instance(env)?.to_unknown())
        })
    }

    /// The bytes to store: a copy, so changing it changes no ciphertext.
    #[napi]
    pub fn to_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.sealed.to_bytes())
    }

    /// Names the type and hides the bytes.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Ciphertext(***)"
    }
}

/// The bytes of a `Uint8Array` (a `Buffer` is one), copied, or `None` for
/// any other value. Read as a borrowed slice, as vitaminc reads bytes:
/// napi's owned `Uint8Array` keeps a reference to a typed array of another
/// element type it refuses.
pub(crate) fn bytes_of(value: Unknown<'_>) -> Option<Vec<u8>> {
    if !value.is_typedarray().unwrap_or(false) {
        return None;
    }
    Uint8ArraySlice::from_unknown(value)
        .ok()
        .map(|bytes| bytes.to_vec())
}
