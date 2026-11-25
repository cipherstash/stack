//! The [`Ciphertext`] class: one encrypted value, as a JavaScript object.
//!
//! The engine that encrypts it is the Stack Encrypt engine, the
//! `stack-encrypt` crate.

use napi::bindgen_prelude::{
    ClassInstance, FromNapiValue, JavaScriptClassExt, JsValue, Object, Uint8Array, Uint8ArraySlice,
    Unknown,
};
use napi::Env;
use napi_derive::napi;
use vitaminc_protected::OpaqueDebug;

use crate::error::{Error, RecipherErrorFields};
use crate::outcome::{failed, not_made, settle};

/// One encrypted value: the engine's opaque ciphertext of the whole value,
/// with its own data key. A data key is the key that encrypts one value.
///
/// The ciphertext's bytes are the engine's format for an encrypted value.
/// The Rust and Go SDKs write the same bytes. `toString()` and Node's
/// `inspect` hide the bytes, because the object has no own properties.
///
/// The SDK uses a class rather than plain bytes so that `decrypt` can tell a
/// ciphertext from any other value.
#[napi]
#[derive(Clone, OpaqueDebug)]
pub struct Ciphertext {
    sealed: stack_encrypt::Ciphertext,
}

impl Ciphertext {
    /// Wraps `sealed`.
    pub(crate) fn new(sealed: stack_encrypt::Ciphertext) -> Self {
        Self { sealed }
    }

    /// Returns the engine's ciphertext.
    pub(crate) fn sealed(&self) -> &stack_encrypt::Ciphertext {
        &self.sealed
    }

    /// Returns a copy of `value` when it is a `Ciphertext`, or `None` when
    /// it is not.
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
    /// Reads a ciphertext from stored bytes, a `Uint8Array` or a `Buffer`.
    /// This method checks only the shape of the bytes. Decrypting is what
    /// checks that they are authentic. A failure does not quote the bytes.
    ///
    /// Returns an `Err` with the code `recipher_js::not_bytes` when the
    /// argument is not a `Uint8Array`. Does not throw.
    #[napi(
        ts_args_type = "bytes: Uint8Array",
        ts_return_type = "Result<Ciphertext, RecipherError>"
    )]
    pub fn from_bytes<'e>(env: &'e Env, bytes: Unknown<'_>) -> napi::Result<Object<'e>> {
        let Some(bytes) = bytes_of(bytes) else {
            return failed(env, Error::NotBytes.into());
        };
        let outcome = stack_encrypt::Ciphertext::from_bytes(&bytes)
            .map(Ciphertext::new)
            .map_err(|error| RecipherErrorFields::engine(&error));
        settle(env, outcome, |env, ciphertext| {
            Ok(ciphertext
                .into_instance(env)
                .map_err(not_made)?
                .to_unknown())
        })
    }

    /// Returns the bytes to store. They are a copy, so changing them does
    /// not change any ciphertext.
    #[napi]
    pub fn to_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.sealed.to_bytes())
    }

    /// Returns the type's name, and hides the bytes.
    #[napi(js_name = "toString")]
    pub fn describe(&self) -> &'static str {
        "Ciphertext(***)"
    }
}

/// Returns a copy of the bytes of a `Uint8Array`, or `None` for any other
/// value. A `Buffer` is a `Uint8Array`.
///
/// The function reads the bytes as a borrowed slice. That is how vitaminc,
/// CipherStash's cryptography library, reads bytes. napi's owned
/// `Uint8Array` is not used. When it refuses a typed array of another
/// element type, it still keeps a reference to that array.
pub(crate) fn bytes_of(value: Unknown<'_>) -> Option<Vec<u8>> {
    if !value.is_typedarray().unwrap_or(false) {
        return None;
    }
    Uint8ArraySlice::from_unknown(value)
        .ok()
        .map(|bytes| bytes.to_vec())
}
