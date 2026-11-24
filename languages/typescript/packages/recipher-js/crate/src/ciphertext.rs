//! [`Ciphertext`]: one sealed value, as JavaScript holds it.

use napi::bindgen_prelude::{
    ClassInstance, FromNapiValue, JavaScriptClassExt, JsValue, Object, Uint8Array, Uint8ArraySlice,
    Unknown,
};
use napi::{Env, ValueType};
use napi_derive::napi;
use serde::Deserialize;
use stack_encrypt::dynamic::{read, ValueFrame, ValueKind};
use stack_encrypt::AsProtectedRef;
use vitaminc_protected::OpaqueDebug;

use crate::error::{ErrorKind, RecipherErrorFields};
use crate::js;
use crate::outcome::{failed, not_made, settle, Outcome};

/// One sealed value: the engine's opaque ciphertext, with its own data key.
///
/// Its bytes are the engine's sealed-value envelope, the bytes Rust's
/// `Ciphertext::to_bytes` and the Go SDK write. `Debug` hides them, and so
/// do `toString()` and Node's `inspect`: the class has no own properties.
///
/// It exists as a class, rather than as the bytes, so that `decrypt` can
/// tell a ciphertext from any other value, and so that it carries the type
/// it opens as: a JSON document is sealed as its JSON text, and nothing in
/// the bytes says it is JSON.
#[napi]
#[derive(Clone, OpaqueDebug)]
pub struct Ciphertext {
    sealed: stack_encrypt::Ciphertext,
    opens_as: Option<ValueKind>,
}

impl Ciphertext {
    /// `sealed`, opening as what it was sealed as (`None`), or as `kind`.
    pub(crate) fn new(sealed: stack_encrypt::Ciphertext, opens_as: Option<ValueKind>) -> Self {
        Self { sealed, opens_as }
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

    /// An opened value, as the kind this ciphertext opens as.
    ///
    /// # Errors
    ///
    /// A failure of kind `open` for a value sealed as another type, or for
    /// one named JSON that is not a JSON document.
    pub(crate) fn opened(&self, value: ValueFrame) -> Outcome<ValueFrame> {
        match self.opens_as {
            None => Ok(value),
            Some(ValueKind::Json) => crate::json::opened(&value),
            Some(kind) => as_kind(kind, value),
        }
    }
}

#[napi]
impl Ciphertext {
    /// Read a ciphertext from stored bytes, a `Uint8Array` or a `Buffer`.
    /// This checks the bytes' shape only; decrypting is what authenticates
    /// them. A failure does not quote the bytes.
    ///
    /// With a kind, such as `kinds.string`, it opens as that kind, and
    /// decrypting refuses a value sealed as another type. `kinds.json` opens
    /// a JSON document. With none, it opens as whatever it was sealed as,
    /// and a JSON document opens as its JSON text.
    // Configurable, as an instance method is, so the package's TypeScript
    // can wrap it (`adapt`).
    #[napi(configurable = true, ts_return_type = "Outcome<Ciphertext>")]
    pub fn from_bytes<'e>(
        env: &'e Env,
        bytes: Unknown<'_>,
        kind: Option<Unknown<'_>>,
    ) -> napi::Result<Object<'e>> {
        let Some(bytes) = bytes_of(bytes) else {
            return failed(
                env,
                RecipherErrorFields::new(
                    ErrorKind::Value,
                    "recipher::not_bytes",
                    "a ciphertext is read from a Uint8Array",
                ),
            );
        };
        let outcome = kind_of(env, kind).and_then(|opens_as| {
            stack_encrypt::Ciphertext::from_bytes(&bytes)
                .map(|sealed| Ciphertext::new(sealed, opens_as))
                .map_err(|error| RecipherErrorFields::diagnostic(ErrorKind::Open, &error, None))
        });
        settle(env, outcome, |env, ciphertext| {
            Ok(ciphertext
                .into_instance(env)
                .map_err(not_made)?
                .to_unknown())
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

/// A kind, as the package's `kinds` spells it: `{ name: "string" }`.
#[derive(Deserialize)]
struct KindArgument {
    name: String,
}

/// The kind `value` names, or `None` for `undefined`.
fn kind_of(env: &Env, value: Option<Unknown<'_>>) -> Outcome<Option<ValueKind>> {
    let Some(value) = value.filter(|value| value.get_type().ok() != Some(ValueType::Undefined))
    else {
        return Ok(None);
    };
    let not_a_kind = || {
        RecipherErrorFields::new(
            ErrorKind::Value,
            "recipher::not_a_kind",
            "a ciphertext opens as one of `kinds`, such as `kinds.string`",
        )
    };
    let frame = js::read(env, value).map_err(|_| not_a_kind())?;
    let argument: KindArgument =
        stack_encrypt::dynamic::frame::serde::from_slice(frame.as_protected_ref().risky_ref())
            .map_err(|_| not_a_kind())?;
    argument
        .name
        .parse::<ValueKind>()
        .ok()
        .filter(|kind| !matches!(kind, ValueKind::Array | ValueKind::Object))
        .map(Some)
        .ok_or_else(not_a_kind)
}

/// Whether `kind` is an integer kind.
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

/// `value` as `kind`: itself when it is of that kind; an integer of another
/// width, or a float of another width, converted by the engine's `read`
/// when the conversion is exact; anything else refused.
fn as_kind(kind: ValueKind, value: ValueFrame) -> Outcome<ValueFrame> {
    let refused = || {
        RecipherErrorFields::new(
            ErrorKind::Open,
            "recipher::opened_type",
            format!("the value opened, but it was not sealed as the kind named, {kind}"),
        )
    };
    let opened = value.kind();
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

#[cfg(test)]
mod tests {
    use super::as_kind;
    use stack_encrypt::dynamic::{ValueFrame, ValueKind};

    #[test]
    fn an_integer_opens_at_any_width_that_holds_it() {
        let opened = as_kind(ValueKind::Int64, ValueFrame::of(5i8).unwrap()).unwrap();
        assert_eq!(opened, ValueFrame::of(5i64).unwrap());
        assert!(as_kind(ValueKind::UInt8, ValueFrame::of(300i16).unwrap()).is_err());
    }

    #[test]
    fn a_value_of_another_type_is_refused_as_not_opened() {
        let refused = as_kind(ValueKind::Int64, ValueFrame::of(5.0f64).unwrap()).unwrap_err();
        assert_eq!(refused.code, "recipher::opened_type");
        assert!(as_kind(ValueKind::String, ValueFrame::of(true).unwrap()).is_err());
        assert!(as_kind(ValueKind::String, ValueFrame::of("x").unwrap()).is_ok());
    }
}
