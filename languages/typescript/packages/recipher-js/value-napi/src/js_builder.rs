//! [`JsBuilder`]: a [`Sink`] that builds JavaScript values.
//!
//! The build runs on the JavaScript thread. Each scalar becomes the
//! JavaScript value of its kind, the inverse of the mapping in
//! [`js_ref`](crate::js_ref): a null, a boolean, a `number` for a float, a
//! `BigInt` for any int width, a string, a `Buffer`, a `Date` for a
//! timestamp that is whole milliseconds inside `Date`'s range, and a
//! wrapper class instance for a calendar date, a finer timestamp, a decimal
//! or a UUID. A sequence becomes an array and a map a plain object, both
//! written as own data properties so a polluted prototype never sees the
//! plaintext. A passthrough subtree is built like the rest.
//!
//! A logical type this build does not know cannot be shown to JavaScript
//! and is refused.

use napi::bindgen_prelude::{BigInt, Buffer, JsValue, Null, Object, ToNapiValue, Unknown};
use napi::{Env, Error, Status};
use vitaminc_aead::{
    Encrypt, EncryptRef, FixedType, Float, Frame, Int, Logical, MapSink, Physical, SeqSink, Sink,
};

use crate::error::JsFault;
use crate::js::{
    define_own_properties, depth_error, eager_capacity, forbidden_key, forbidden_key_error,
    new_array, own_property, MAX_DEPTH,
};
use crate::scalar;
use crate::wrappers::{Wrapper, Wrappers};

/// Where a built value goes: the root hands it back, a child writes it into
/// its parent.
mod out {
    use napi::bindgen_prelude::Unknown;

    pub trait Out<'e> {
        type Ok;
        fn put(self, value: Unknown<'e>) -> Self::Ok;
    }

    /// The root of the build: the value is the result.
    pub struct Root;

    impl<'e> Out<'e> for Root {
        type Ok = Unknown<'e>;
        fn put(self, value: Unknown<'e>) -> Unknown<'e> {
            value
        }
    }

    /// An element slot in a parent sequence.
    pub struct Slot<'s, 'e>(pub(super) &'s mut Vec<Unknown<'e>>);

    impl<'e> Out<'e> for Slot<'_, 'e> {
        type Ok = ();
        fn put(self, value: Unknown<'e>) {
            self.0.push(value);
        }
    }

    /// An entry in a parent map.
    pub struct Entry<'s, 'e> {
        pub(super) entries: &'s mut Vec<(String, Unknown<'e>)>,
        pub(super) key: String,
    }

    impl<'e> Out<'e> for Entry<'_, 'e> {
        type Ok = ();
        fn put(self, value: Unknown<'e>) {
            self.entries.push((self.key, value));
        }
    }
}

use out::{Entry, Out, Root, Slot};

/// A sink that builds a JavaScript value, on the JavaScript thread.
///
/// `O` is where the value goes; a caller only meets the root form, whose
/// `Ok` is the built value.
pub struct JsBuilder<'e, O = Root> {
    env: &'e Env,
    depth: usize,
    out: O,
}

impl<'e> JsBuilder<'e> {
    /// A build of a root value in `env`.
    pub fn new(env: &'e Env) -> Self {
        Self::at_depth(env, 0)
    }

    /// A build whose root sits `depth` levels down in a larger structure,
    /// so the nesting limit counts the whole structure.
    pub(crate) fn at_depth(env: &'e Env, depth: usize) -> Self {
        Self {
            env,
            depth,
            out: Root,
        }
    }

    /// The JavaScript value of a frame.
    pub fn build(env: &'e Env, frame: Frame<'_>) -> napi::Result<Unknown<'e>> {
        frame.visit(Self::new(env)).map_err(Error::from)
    }
}

impl<O> JsBuilder<'_, O> {
    fn check_depth(&self) -> napi::Result<()> {
        if self.depth > MAX_DEPTH {
            return Err(depth_error());
        }
        Ok(())
    }
}

impl<'e, O: Out<'e>> Sink for JsBuilder<'e, O> {
    type Ok = O::Ok;
    type Error = JsFault;
    type Seq = JsSeq<'e, O>;
    type Map = JsMap<'e, O>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<O::Ok, JsFault> {
        self.check_depth()?;
        let built = scalar_to_js(self.env, ty, value)?;
        Ok(self.out.put(built))
    }

    /// An absent value is JavaScript's `null`, whatever its type.
    fn typed_null(self, _: FixedType) -> Result<O::Ok, JsFault> {
        self.scalar(None, Physical::Null)
    }

    fn seq(self, len: Option<usize>) -> Result<JsSeq<'e, O>, JsFault> {
        self.check_depth()?;
        Ok(JsSeq {
            env: self.env,
            depth: self.depth,
            out: self.out,
            items: Vec::with_capacity(capacity(len)),
        })
    }

    fn map(self, len: Option<usize>) -> Result<JsMap<'e, O>, JsFault> {
        self.check_depth()?;
        Ok(JsMap {
            env: self.env,
            depth: self.depth,
            out: self.out,
            entries: Vec::with_capacity(capacity(len)),
        })
    }

    /// A passthrough subtree is plaintext to the application, so it is
    /// built like anything else, one level down as the frame counts it.
    fn passthrough<P: ?Sized + EncryptRef>(self, value: &P) -> Result<O::Ok, JsFault> {
        self.check_depth()?;
        let built = value.visit_ref(JsBuilder::at_depth(self.env, self.depth + 1))?;
        Ok(self.out.put(built))
    }
}

/// A length hint is only a hint, and a hostile one costs the source
/// nothing, so it buys at most a bounded reservation.
fn capacity(len: Option<usize>) -> usize {
    eager_capacity(u32::try_from(len.unwrap_or(0)).unwrap_or(u32::MAX))
}

/// The sequence side of [`JsBuilder`]: an array, written once its
/// elements are built.
pub struct JsSeq<'e, O> {
    env: &'e Env,
    depth: usize,
    out: O,
    items: Vec<Unknown<'e>>,
}

impl<'e, O: Out<'e>> SeqSink for JsSeq<'e, O> {
    type Ok = O::Ok;
    type Error = JsFault;
    type Element<'s>
        = JsBuilder<'e, Slot<'s, 'e>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, JsFault> {
        Ok(JsBuilder {
            env: self.env,
            depth: self.depth + 1,
            out: Slot(&mut self.items),
        })
    }

    fn end(self) -> Result<O::Ok, JsFault> {
        let env = self.env;
        let mut array = new_array(env, self.items.len())?;
        let mut elements = Vec::with_capacity(self.items.len());
        for (i, item) in self.items.iter().enumerate() {
            elements.push(own_property(env, &i.to_string(), item)?);
        }
        define_own_properties(&mut array, &elements)?;
        Ok(self.out.put(array.to_unknown()))
    }
}

/// The map side of [`JsBuilder`]: a plain object, written once its
/// entries are built.
pub struct JsMap<'e, O> {
    env: &'e Env,
    depth: usize,
    out: O,
    entries: Vec<(String, Unknown<'e>)>,
}

impl<'e, O: Out<'e>> MapSink for JsMap<'e, O> {
    type Ok = O::Ok;
    type Error = JsFault;
    type Entry<'s>
        = JsBuilder<'e, Entry<'s, 'e>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, JsFault> {
        // Keys decrypted from a ciphertext are attacker-influenced in
        // principle; never assign prototype-polluting names.
        if forbidden_key(key) {
            return Err(forbidden_key_error(key).into());
        }
        Ok(JsBuilder {
            env: self.env,
            depth: self.depth + 1,
            out: Entry {
                entries: &mut self.entries,
                key: key.to_owned(),
            },
        })
    }

    fn end(self) -> Result<O::Ok, JsFault> {
        let env = self.env;
        let mut object = Object::new(env)?;
        let mut properties = Vec::with_capacity(self.entries.len());
        for (key, value) in &self.entries {
            properties.push(own_property(env, key, value)?);
        }
        define_own_properties(&mut object, &properties)?;
        Ok(self.out.put(object.to_unknown()))
    }
}

fn malformed(what: &str) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("{what} is not a value this binding can build"),
    )
}

/// One scalar as its JavaScript value.
fn scalar_to_js<'e>(
    env: &'e Env,
    ty: Option<Logical>,
    value: Physical<'_>,
) -> napi::Result<Unknown<'e>> {
    let Some(ty) = ty else {
        return match value {
            Physical::Null => Null.into_unknown(env),
            Physical::Bool(b) => b.into_unknown(env),
            Physical::Int(int) => bigint(int).into_unknown(env),
            // Both float widths surface as a JS `number`; `f32` widens exactly.
            Physical::Float(Float::F32(f)) => f64::from(f).into_unknown(env),
            Physical::Float(Float::F64(f)) => f.into_unknown(env),
            Physical::Text(s) => s.into_unknown(env),
            Physical::Bytes(b) => Buffer::from(b.to_vec()).into_unknown(env),
        };
    };
    let wrap = |wrapper: Wrapper, text: Option<String>| -> napi::Result<Unknown<'e>> {
        let text = text.ok_or_else(|| malformed(wrapper.class_name()))?;
        Wrappers::get(env)?.construct(wrapper, &text)
    };
    match (ty, value) {
        (Logical::Undefined, Physical::Null) => ().into_unknown(env),
        (Logical::Date, Physical::Int(days)) => wrap(Wrapper::Date, scalar::date_text(days)),
        (Logical::Timestamp(unit), Physical::Int(count)) => {
            match scalar::timestamp_js_millis(unit, count) {
                Some(ms) => Ok(env.create_date(ms)?.to_unknown()),
                None => wrap(Wrapper::Timestamp, scalar::timestamp_text(unit, count)),
            }
        }
        (Logical::Decimal { scale }, Physical::Int(mantissa)) => {
            wrap(Wrapper::Decimal, scalar::decimal_text(scale, mantissa))
        }
        (Logical::Uuid, Physical::Bytes(bytes)) => wrap(Wrapper::Uuid, scalar::uuid_text(bytes)),
        (Logical::Unknown(unknown), _) => Err(Error::new(
            Status::GenericFailure,
            format!(
                "logical type {} is not known to this binding and has no JavaScript value",
                unknown.id()
            ),
        )),
        (ty, _) => Err(malformed(&ty.to_string())),
    }
}

fn bigint(int: Int) -> BigInt {
    match int.to_i128() {
        Some(v) => BigInt::from(v),
        // Only a u128 above i128::MAX has no i128.
        None => BigInt::from(int.to_u128().unwrap_or(u128::MAX)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::MAX_DEPTH;

    #[test]
    fn a_length_hint_buys_a_bounded_reservation() {
        assert_eq!(capacity(None), 0);
        assert_eq!(capacity(Some(0)), 0);
        assert_eq!(capacity(Some(37)), 37);
        assert_eq!(capacity(Some(usize::MAX)), eager_capacity(u32::MAX));
        assert_eq!(capacity(Some(1 << 40)), eager_capacity(u32::MAX));
    }

    #[test]
    fn every_int_width_becomes_a_bigint_of_its_sign_and_magnitude() {
        // Every width goes through i128 when it fits, so two words always.
        let big = bigint(Int::I8(-1));
        assert!(big.sign_bit, "negative");
        assert_eq!(big.words, [1, 0]);
        let big = bigint(Int::U64(u64::MAX));
        assert!(!big.sign_bit);
        assert_eq!(big.words, [u64::MAX, 0]);
        let big = bigint(Int::I128(i128::MIN));
        assert!(big.sign_bit);
        assert_eq!(big.words, [0, 1 << 63]);
        // Above i128::MAX there is no i128, so the u128 path carries it.
        let big = bigint(Int::U128(u128::MAX));
        assert!(!big.sign_bit);
        assert_eq!(big.words, [u64::MAX, u64::MAX]);
    }

    #[test]
    fn the_depth_check_refuses_one_past_the_limit() {
        let env = Env::from_raw(std::ptr::null_mut());
        assert!(JsBuilder::at_depth(&env, MAX_DEPTH).check_depth().is_ok());
        let error = JsBuilder::at_depth(&env, MAX_DEPTH + 1)
            .check_depth()
            .expect_err("past the limit");
        assert_eq!(error.status, Status::InvalidArg);
        assert!(error.reason.contains("nested too deeply"), "{error}");
    }

    // A container at the limit may itself be built, but each of its
    // children sits one level deeper and must be refused. The builders
    // below never reach the environment: the depth check comes first.

    #[test]
    fn a_sequence_at_the_limit_refuses_its_elements() {
        let env = Env::from_raw(std::ptr::null_mut());
        let mut seq = JsSeq {
            env: &env,
            depth: MAX_DEPTH,
            out: Root,
            items: Vec::new(),
        };
        let element = seq.element().expect("the element slot itself");
        assert_eq!(element.depth, MAX_DEPTH + 1);
        element.check_depth().expect_err("one level deeper");
    }

    #[test]
    fn a_map_at_the_limit_refuses_its_entries() {
        let env = Env::from_raw(std::ptr::null_mut());
        let mut map = JsMap {
            env: &env,
            depth: MAX_DEPTH,
            out: Root,
            entries: Vec::new(),
        };
        let entry = map.entry("k").expect("the entry slot itself");
        assert_eq!(entry.depth, MAX_DEPTH + 1);
        entry.check_depth().expect_err("one level deeper");
    }

    #[test]
    fn a_passthrough_at_the_limit_builds_its_value_one_level_deeper() {
        /// A value that opens a sequence and reports whether the sink let it.
        struct Probe;
        impl Encrypt for &Probe {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                match sink.seq(Some(0)) {
                    Ok(_) => panic!("a sequence one level past the limit was accepted"),
                    Err(error) => Err(error),
                }
            }
        }
        let env = Env::from_raw(std::ptr::null_mut());
        let error = JsBuilder::at_depth(&env, MAX_DEPTH)
            .passthrough(&Probe)
            .err()
            .expect("the passthrough's value sits one level deeper");
        assert!(error.reason().contains("nested too deeply"), "{error:?}");
    }
}
