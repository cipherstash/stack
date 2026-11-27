//! The [`Ciphertext`] class: one encrypted value, as a JavaScript object.
//!
//! The engine that encrypts it is the Stack Encrypt engine, the
//! `stack-encrypt` crate.

use napi::bindgen_prelude::{
    ClassInstance, FromNapiValue, JavaScriptClassExt, JsValue, Object, Uint8Array, Uint8ArraySlice,
    Unknown,
};
use napi::{Env, ValueType};
use napi_derive::napi;
use serde::Deserialize;
use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::dynamic::{read, ValueKind};
use vitaminc_protected::OpaqueDebug;

use crate::error::{Error, RecipherErrorFields};
use crate::js;
use crate::outcome::{failed, not_made, settle, Outcome};

/// One encrypted value: the engine's opaque ciphertext of the whole value,
/// with its own data key. A data key is the key that encrypts one value.
///
/// The ciphertext's bytes are the engine's format for an encrypted value.
/// The Rust and Go SDKs write the same bytes. `toString()` and Node's
/// `inspect` hide the bytes, because the object has no own properties.
///
/// The SDK uses a class rather than plain bytes for two reasons. First,
/// `decrypt` can tell a ciphertext from any other value. Second, the class
/// records the type the value decrypts as. A JSON document is encrypted as
/// its JSON text, and nothing in the bytes says that it is JSON.
#[napi]
#[derive(Clone, OpaqueDebug)]
pub struct Ciphertext {
    sealed: stack_encrypt::Ciphertext,
    opens_as: Option<ValueKind>,
}

impl Ciphertext {
    /// Wraps `sealed`. When `opens_as` is `None`, the ciphertext decrypts as
    /// the type it was encrypted as. Otherwise it decrypts as that kind.
    pub(crate) fn new(sealed: stack_encrypt::Ciphertext, opens_as: Option<ValueKind>) -> Self {
        Self { sealed, opens_as }
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

    /// Returns a decrypted value as the kind this ciphertext decrypts as.
    ///
    /// # Errors
    ///
    /// Returns `recipher_js::opened_type` for a value encrypted as another
    /// type. Returns `recipher_js::not_a_document` when the kind is JSON but
    /// the value is not a JSON document.
    pub(crate) fn opened(&self, value: OwnedFrame) -> Outcome<OwnedFrame> {
        match self.opens_as {
            None => Ok(value),
            Some(ValueKind::Json) => crate::json::opened(&value),
            Some(kind) => as_kind(kind, value),
        }
    }
}

#[napi]
impl Ciphertext {
    /// Reads a ciphertext from stored bytes, a `Uint8Array` or a `Buffer`.
    /// This method checks only the shape of the bytes. Decrypting is what
    /// checks that they are authentic. A failure does not quote the bytes.
    ///
    /// Give a kind, such as `kinds.string`, to decrypt the value as that
    /// kind. Decrypting then refuses a value encrypted as another type.
    /// `kinds.json` decrypts a JSON document.
    ///
    /// With no kind, the value decrypts as the type it was encrypted as. A
    /// JSON document then decrypts as its JSON text. `JSON.parse` of that
    /// text loses the digits of an integer outside a `number`'s safe range.
    ///
    /// Returns an `Err` with the code `recipher_js::not_bytes` when the
    /// bytes are not a `Uint8Array`, and `recipher_js::not_a_kind` when the
    /// kind is not one of `kinds`. Does not throw.
    #[napi(
        ts_type = "<K extends Kind>(bytes: Uint8Array, kind: K): Result<Ciphertext<ValueOf<K>>, RecipherError>
static fromBytes(bytes: Uint8Array): Result<Ciphertext, RecipherError>"
    )]
    pub fn from_bytes<'e>(
        env: &'e Env,
        bytes: Unknown<'_>,
        kind: Option<Unknown<'_>>,
    ) -> napi::Result<Object<'e>> {
        let Some(bytes) = bytes_of(bytes) else {
            return failed(env, Error::NotBytes.into());
        };
        let outcome = kind_of(env, kind).and_then(|opens_as| {
            stack_encrypt::Ciphertext::from_bytes(&bytes)
                .map(|sealed| Ciphertext::new(sealed, opens_as))
                .map_err(|error| RecipherErrorFields::engine(&error))
        });
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

/// A kind, in the form the package's `kinds` object writes it:
/// `{ name: "string" }`.
#[derive(Deserialize)]
struct KindArgument {
    name: String,
}

/// Returns the kind that `value` names, or `None` when `value` is absent or
/// `undefined`.
fn kind_of(env: &Env, value: Option<Unknown<'_>>) -> Outcome<Option<ValueKind>> {
    let Some(value) = value.filter(|value| value.get_type().ok() != Some(ValueType::Undefined))
    else {
        return Ok(None);
    };
    let frame = js::read(env, value).map_err(|_| Error::NotAKind)?;
    let argument: KindArgument =
        stack_encrypt::dynamic::frame::serde::from_slice(frame.frame().as_bytes())
            .map_err(|_| Error::NotAKind)?;
    let kind = argument
        .name
        .parse::<ValueKind>()
        .ok()
        .filter(|kind| !matches!(kind, ValueKind::Array | ValueKind::Object))
        .ok_or(Error::NotAKind)?;
    Ok(Some(kind))
}

/// Returns whether `kind` is an integer kind.
fn integer(kind: ValueKind) -> bool {
    matches!(
        kind,
        ValueKind::Int8
            | ValueKind::Int16
            | ValueKind::Int32
            | ValueKind::Int64
            | ValueKind::Int128
            | ValueKind::UInt8
            | ValueKind::UInt16
            | ValueKind::UInt32
            | ValueKind::UInt64
            | ValueKind::UInt128
    )
}

/// Returns `value` as `kind`.
///
/// A value of that kind is returned unchanged. The engine's `read` converts
/// an integer to another integer width, or a float to another float width,
/// when the conversion is exact. Any other value is refused.
fn as_kind(kind: ValueKind, value: OwnedFrame) -> Outcome<OwnedFrame> {
    let refused = || RecipherErrorFields::from(Error::OpenedType { kind });
    let opened = value.frame().kind();
    if opened == Some(kind) {
        return Ok(value);
    }
    let float = |kind| matches!(kind, ValueKind::Float32 | ValueKind::Float64);
    let same_family = opened
        .is_some_and(|opened| (integer(opened) && integer(kind)) || (float(opened) && float(kind)));
    if !same_family {
        return Err(refused());
    }
    read(kind, &value).map_err(|_| refused())
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

#[cfg(test)]
mod tests {
    use super::as_kind;
    use stack_encrypt::dynamic::frame::OwnedFrame;
    use stack_encrypt::dynamic::ValueKind;

    #[test]
    fn an_integer_opens_at_any_width_that_holds_it() {
        let opened = as_kind(ValueKind::Int64, OwnedFrame::of(5i8).unwrap()).unwrap();
        assert_eq!(opened.frame(), OwnedFrame::of(5i64).unwrap().frame());
        assert!(as_kind(ValueKind::UInt8, OwnedFrame::of(300i16).unwrap()).is_err());
    }

    #[test]
    fn a_value_of_another_type_is_refused_as_not_opened() {
        let refused = as_kind(ValueKind::Int64, OwnedFrame::of(5.0f64).unwrap()).unwrap_err();
        assert_eq!(refused.code, "recipher_js::opened_type");
        assert!(as_kind(ValueKind::String, OwnedFrame::of(true).unwrap()).is_err());
        assert!(as_kind(ValueKind::String, OwnedFrame::of("x").unwrap()).is_ok());
    }
}
