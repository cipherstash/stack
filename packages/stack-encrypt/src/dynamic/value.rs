//! An [`FfiValue`] as a plan field. See [`Value`].

use std::fmt;

use vitaminc_aead::{Cipher, Decipher, Decrypt, Encrypt, IntoAad};
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::{Controlled, Protected};

/// A runtime value as the plaintext of a plan field: what every field
/// lowered from data holds, whatever its declared type, and what a Rust
/// chain's field holds when its rows must open from a binding.
///
/// The engine hands a borrowed field to every operation that consumes it
/// and clones it on the way in, as it does a `String` field of a derived
/// record, so a field's plaintext type is `Clone`. [`FfiValue`] is not:
/// vitaminc keeps its leaves in [`Protected`] and gives no copy out
/// implicitly. This wrapper is the copy made explicit, once, here: its
/// `Clone` rebuilds the tree leaf by leaf into fresh `Protected` payloads,
/// which wipe on drop as the originals do, so a clone is under the same
/// custody as the value it was made from. A record of a few fields clones
/// each once per operation that consumes it, as the derive's does.
///
/// It seals and opens as the [`FfiValue`] it wraps, in vitaminc's
/// self-describing tagged leaf encoding — a different leaf from a bare
/// `u32`'s or `String`'s, and one the other reader cannot tell apart by
/// inspection; [`dynamic::record`](super::record) says what follows from
/// that. Its `Debug` names the type and nothing else: the value is
/// plaintext.
pub struct Value(FfiValue);

impl Value {
    /// Wrap a value.
    pub fn new(value: FfiValue) -> Self {
        Self(value)
    }

    /// The value.
    pub fn get(&self) -> &FfiValue {
        &self.0
    }

    /// Unwrap the value.
    pub fn into_inner(self) -> FfiValue {
        self.0
    }
}

impl From<FfiValue> for Value {
    fn from(value: FfiValue) -> Self {
        Self(value)
    }
}

impl From<Value> for FfiValue {
    fn from(value: Value) -> Self {
        value.0
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value")
    }
}

impl Clone for Value {
    fn clone(&self) -> Self {
        Self(duplicate(&self.0))
    }
}

/// A deep copy of a value, each byte-bearing leaf into a fresh
/// [`Protected`]. Exhaustive, so a variant added to [`FfiValue`] has to say
/// how it is copied.
fn duplicate(value: &FfiValue) -> FfiValue {
    match value {
        FfiValue::Null => FfiValue::Null,
        FfiValue::Undefined => FfiValue::Undefined,
        FfiValue::Bool(v) => FfiValue::Bool(*v),
        FfiValue::Int32(v) => FfiValue::Int32(*v),
        FfiValue::Int64(v) => FfiValue::Int64(*v),
        FfiValue::UInt32(v) => FfiValue::UInt32(*v),
        FfiValue::UInt64(v) => FfiValue::UInt64(*v),
        FfiValue::Float32(v) => FfiValue::Float32(*v),
        FfiValue::Float64(v) => FfiValue::Float64(*v),
        // Valid UTF-8 by `Utf8String`'s construction invariant. Were it not,
        // the copy is a bytes leaf: a different type the plan then refuses,
        // never a string that reads differently from its original.
        FfiValue::String(s) => match std::str::from_utf8(s.risky_ref()) {
            Ok(text) => FfiValue::String(text.into()),
            Err(_) => FfiValue::Bytes(Protected::new(s.risky_ref().to_vec())),
        },
        FfiValue::Bytes(b) => FfiValue::Bytes(Protected::new(b.risky_ref().to_vec())),
        FfiValue::Array(items) => FfiValue::Array(items.iter().map(duplicate).collect()),
        FfiValue::Object(entries) => FfiValue::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), duplicate(value)))
                .collect(),
        ),
        FfiValue::Passthrough(inner) => FfiValue::Passthrough(Box::new(duplicate(inner))),
    }
}

impl Encrypt for Value {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.0.encrypt_with_aad(cipher, aad)
    }
}

impl<'c> Decrypt<'c> for Value {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        D::map_ok(FfiValue::decrypt_with_aad(decipher, aad), Value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    /// Structural equality, which `FfiValue` offers only inside vitaminc's
    /// own tests.
    fn same(a: &FfiValue, b: &FfiValue) -> bool {
        match (a, b) {
            (FfiValue::Null, FfiValue::Null) | (FfiValue::Undefined, FfiValue::Undefined) => true,
            (FfiValue::Bool(x), FfiValue::Bool(y)) => x == y,
            (FfiValue::Int32(x), FfiValue::Int32(y)) => x == y,
            (FfiValue::Int64(x), FfiValue::Int64(y)) => x == y,
            (FfiValue::UInt32(x), FfiValue::UInt32(y)) => x == y,
            (FfiValue::UInt64(x), FfiValue::UInt64(y)) => x == y,
            (FfiValue::Float32(x), FfiValue::Float32(y)) => x.to_bits() == y.to_bits(),
            (FfiValue::Float64(x), FfiValue::Float64(y)) => x.to_bits() == y.to_bits(),
            (FfiValue::String(x), FfiValue::String(y)) => x.risky_ref() == y.risky_ref(),
            (FfiValue::Bytes(x), FfiValue::Bytes(y)) => x.risky_ref() == y.risky_ref(),
            (FfiValue::Array(x), FfiValue::Array(y)) => {
                x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b))
            }
            (FfiValue::Object(x), FfiValue::Object(y)) => {
                x.len() == y.len()
                    && x.iter()
                        .zip(y)
                        .all(|((ka, va), (kb, vb))| ka == kb && same(va, vb))
            }
            (FfiValue::Passthrough(x), FfiValue::Passthrough(y)) => same(x, y),
            _ => false,
        }
    }

    /// A clone is the same value, leaf for leaf, at every depth and for
    /// every variant, and shares no payload with its original.
    #[test]
    fn a_clone_is_the_same_value_in_fresh_payloads() {
        let original = Value::new(FfiValue::Object(vec![
            ("n".to_string(), FfiValue::Null),
            ("u".to_string(), FfiValue::Undefined),
            ("b".to_string(), FfiValue::Bool(true)),
            ("i32".to_string(), FfiValue::Int32(-3)),
            ("i64".to_string(), FfiValue::Int64(-4)),
            ("u32".to_string(), FfiValue::UInt32(34)),
            ("u64".to_string(), FfiValue::UInt64(35)),
            ("f32".to_string(), FfiValue::Float32(1.5)),
            ("f64".to_string(), FfiValue::Float64(2.5)),
            ("s".to_string(), s("alice")),
            (
                "bytes".to_string(),
                FfiValue::Bytes(Protected::new(vec![1, 2, 3])),
            ),
            (
                "list".to_string(),
                FfiValue::Array(vec![s("a"), FfiValue::Passthrough(Box::new(s("p")))]),
            ),
        ]));
        let copy = original.clone();
        assert!(same(copy.get(), original.get()), "the same value");
        let (FfiValue::Object(a), FfiValue::Object(b)) = (original.get(), copy.get()) else {
            panic!("objects");
        };
        let (FfiValue::String(x), FfiValue::String(y)) = (&a[9].1, &b[9].1) else {
            panic!("strings");
        };
        assert_ne!(
            x.risky_ref().as_ptr(),
            y.risky_ref().as_ptr(),
            "the text was copied, not shared"
        );
        assert_eq!(format!("{copy:?}"), "Value", "debug shows no plaintext");
        assert!(matches!(copy.into_inner(), FfiValue::Object(_)));
    }
}
