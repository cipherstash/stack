//! Statically typed decryption as sinks.
//!
//! A type that can be decrypted names the [`Sink`] that builds it
//! ([`Decrypt`]). A scalar target is one function from a scalar, logical
//! plus physical, to the type, or `None` to refuse it ([`FromScalar`]);
//! every such type gets its sink for free. Containers push each child into
//! the parent through the child's own sink. A `#[derive(Decrypt)]` will
//! generate the struct case: a map sink that routes each entry to the
//! field's sink.
//!
//! Integer targets read the value, not the width: a `u32` accepts an `i8`
//! leaf holding 34 and refuses one holding -1. The width is a host-fidelity
//! hint. `Option<T>` reads null and `undefined` as `None` and defers
//! anything else to `T`. `HashMap<String, T>` and `BTreeMap<String, T>`
//! read a map, each value through `T`'s sink. Any scalar target that can
//! be wiped can also be read straight into `Protected`.
//!
//! Nothing here knows whether the cipher was sync or async: the opened tree
//! is walked after every await has completed.
//!
//! This trait will replace [`Decrypt`](crate::Decrypt). Until that is
//! removed it is reached through this module rather than the crate root.

use core::fmt;
use core::marker::PhantomData;
use std::collections::{BTreeMap, HashMap};

use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

use crate::plaintext::{
    Error, Float, Logical, MapSink, Physical, Plaintext, SeqSink, Sink, SourceError,
};
use crate::seal::{AsyncCipher, Cipher, Node};
use crate::walk::{decrypt_into, decrypt_into_async, DecryptError};
use crate::IntoAad;

/// Why a typed target refused what it was given.
///
/// Non-exhaustive, so a derived struct target can add refusals (an
/// unknown key, a missing field) without a breaking change.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// The ciphertext holds something other than the named kind.
    Expected(&'static str),
    /// The source stopped the walk (only reachable through a passthrough).
    Source(SourceError),
}

impl Error for DecodeError {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expected(what) => write!(f, "expected {what}"),
            Self::Source(e) => write!(f, "source failed: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Expected(_) => None,
            Self::Source(e) => Some(e),
        }
    }
}

/// A type that can be decrypted: it names the sink that builds it.
pub trait Decrypt: Sized {
    type Sink: Sink<Ok = Self, Error = DecodeError>;
    fn sink() -> Self::Sink;
}

/// Decrypt into `T`.
pub fn decrypt<'a, T, C, A>(
    cipher: &C,
    node: Node<C::Leaf>,
    aad: A,
) -> Result<T, DecryptError<DecodeError, C::Error>>
where
    T: Decrypt,
    C: Cipher,
    A: IntoAad<'a>,
{
    decrypt_into(cipher, node, aad, T::sink())
}

/// Decrypt into `T` through an async cipher. Gives the same result as
/// [`decrypt`] for the same ciphertext.
pub async fn decrypt_async<'a, T, C, A>(
    cipher: &C,
    node: Node<C::Leaf>,
    aad: A,
) -> Result<T, DecryptError<DecodeError, C::Error>>
where
    T: Decrypt,
    C: AsyncCipher,
    A: IntoAad<'a>,
{
    decrypt_into_async(cipher, node, aad, T::sink()).await
}

/// A type that decodes from one scalar.
pub trait FromScalar: Sized {
    /// What the type is called in a refusal.
    const EXPECTED: &'static str;
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self>;

    /// Decode straight into `Protected`: the seam `Protected<T>`'s target
    /// goes through. The default decodes, then wraps, which leaves no bare
    /// copy for a type that moves by pointer (`String`, `Vec<u8>`) and only
    /// a stack copy of a small scalar. A type that would otherwise pass
    /// through a bare temporary (`[u8; N]`) overrides it to build in place.
    fn from_scalar_protected(ty: Option<Logical>, value: Physical<'_>) -> Option<Protected<Self>>
    where
        Self: Zeroize,
    {
        Self::from_scalar(ty, value).map(Protected::new)
    }
}

/// The sink for any [`FromScalar`] type. Refuses containers and passthrough.
pub struct ScalarSink<T>(PhantomData<T>);

impl<T: FromScalar> Sink for ScalarSink<T> {
    type Ok = T;
    type Error = DecodeError;
    type Seq = Never<T>;
    type Map = Never<T>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<T, DecodeError> {
        T::from_scalar(ty, v).ok_or(DecodeError::Expected(T::EXPECTED))
    }

    fn seq(self, _: Option<usize>) -> Result<Never<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn map(self, _: Option<usize>) -> Result<Never<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<T, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }
}

impl<T: FromScalar> Decrypt for T {
    type Sink = ScalarSink<T>;
    fn sink() -> ScalarSink<T> {
        ScalarSink(PhantomData)
    }
}

/// Container sinks for a target that has none. Never built.
pub enum Never<T> {
    #[doc(hidden)]
    _Never(core::convert::Infallible, PhantomData<T>),
}

impl<T> Never<T> {
    fn absurd<R>(&self) -> R {
        match *self {
            Never::_Never(never, _) => match never {},
        }
    }
}

impl<T> SeqSink for Never<T> {
    type Ok = T;
    type Error = DecodeError;
    type Element<'s>
        = ScalarSink<i32>
    where
        Self: 's;

    fn element(&mut self) -> Result<ScalarSink<i32>, DecodeError> {
        self.absurd()
    }

    fn end(self) -> Result<T, DecodeError> {
        self.absurd()
    }
}

impl<T> MapSink for Never<T> {
    type Ok = T;
    type Error = DecodeError;
    type Entry<'s>
        = ScalarSink<i32>
    where
        Self: 's;

    fn entry(&mut self, _: &str) -> Result<ScalarSink<i32>, DecodeError> {
        self.absurd()
    }

    fn end(self) -> Result<T, DecodeError> {
        self.absurd()
    }
}

macro_rules! int_target {
    ($($ty:ty),* $(,)?) => {
        $(
            impl FromScalar for $ty {
                const EXPECTED: &'static str = stringify!($ty);
                fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
                    match (ty, v) {
                        (None, Physical::Int(i)) => i
                            .to_i128()
                            .and_then(|v| Self::try_from(v).ok())
                            .or_else(|| i.to_u128().and_then(|v| Self::try_from(v).ok())),
                        _ => None,
                    }
                }
            }
        )*
    };
}

// `u8` is not a target for the same reason it is not a source: `Vec<u8>` is
// a byte leaf, and the generic `Vec<T>` sequence target must not overlap it.
int_target!(i8, i16, i32, i64, i128, u16, u32, u64, u128);

impl FromScalar for bool {
    const EXPECTED: &'static str = "bool";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Bool(b)) => Some(b),
            _ => None,
        }
    }
}

impl FromScalar for f32 {
    const EXPECTED: &'static str = "f32";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Float(Float::F32(f))) => Some(f),
            _ => None,
        }
    }
}

/// Widening from `f32` is exact, so an `f64` target accepts both widths.
impl FromScalar for f64 {
    const EXPECTED: &'static str = "f64";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Float(Float::F64(f))) => Some(f),
            (None, Physical::Float(Float::F32(f))) => Some(f.into()),
            _ => None,
        }
    }
}

impl FromScalar for String {
    const EXPECTED: &'static str = "string";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Text(s)) => Some(s.to_owned()),
            _ => None,
        }
    }
}

/// `Vec<u8>` is a byte leaf, as it is on the source side.
impl FromScalar for Vec<u8> {
    const EXPECTED: &'static str = "bytes";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Bytes(b)) => Some(b.to_vec()),
            _ => None,
        }
    }
}

impl<const N: usize> FromScalar for [u8; N] {
    const EXPECTED: &'static str = "byte array";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Bytes(b)) => b.try_into().ok(),
            _ => None,
        }
    }

    /// Filled inside the wrapper, so no bare copy of the array sits on the
    /// stack, as today's `Decrypt` for `Protected<[u8; N]>` does.
    fn from_scalar_protected(ty: Option<Logical>, v: Physical<'_>) -> Option<Protected<Self>> {
        match (ty, v) {
            (None, Physical::Bytes(b)) if b.len() == N => {
                let mut out = Protected::new([0u8; N]);
                out.risky_inner_mut().copy_from_slice(b);
                Some(out)
            }
            _ => None,
        }
    }
}

/// Any scalar target that can be wiped, read into `Protected`. The only
/// copy is the one inside the wrapper, from the borrow the opened leaf
/// handed over, and the leaf's own buffer is wiped when it drops.
impl<T: FromScalar + Zeroize> FromScalar for Protected<T> {
    const EXPECTED: &'static str = T::EXPECTED;
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        T::from_scalar_protected(ty, v)
    }
}

#[cfg(feature = "chrono")]
mod chrono_targets {
    use super::*;
    use crate::plaintext::kinds::chrono as conv;
    use ::chrono::{DateTime, NaiveDate, Utc};

    impl FromScalar for NaiveDate {
        const EXPECTED: &'static str = "date";
        fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
            match (ty, v) {
                (Some(Logical::Date), Physical::Int(days)) => conv::date(days),
                _ => None,
            }
        }
    }

    /// Any unit: a JavaScript `Date` in milliseconds decodes as well as a
    /// Rust timestamp in nanoseconds.
    impl FromScalar for DateTime<Utc> {
        const EXPECTED: &'static str = "timestamp";
        fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
            match (ty, v) {
                (Some(Logical::Timestamp(unit)), Physical::Int(count)) => {
                    conv::timestamp(unit, count)
                }
                _ => None,
            }
        }
    }
}

#[cfg(feature = "rust_decimal")]
impl FromScalar for rust_decimal::Decimal {
    const EXPECTED: &'static str = "decimal";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (Some(Logical::Decimal { scale }), Physical::Int(mantissa)) => {
                crate::plaintext::kinds::decimal::decimal(scale, mantissa)
            }
            _ => None,
        }
    }
}

#[cfg(feature = "uuid")]
impl FromScalar for uuid::Uuid {
    const EXPECTED: &'static str = "uuid";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (Some(Logical::Uuid), Physical::Bytes(b)) => uuid::Uuid::from_slice(b).ok(),
            _ => None,
        }
    }
}

/// Somewhere a finished child goes.
pub trait Put<T> {
    fn put(self, value: T);
}

/// The next slot of a sequence.
pub struct Push<'s, T>(pub &'s mut Vec<T>);

impl<T> Put<T> for Push<'_, T> {
    fn put(self, value: T) {
        self.0.push(value);
    }
}

/// A map entry: the key it arrived under.
pub struct Insert<'s, M>(pub &'s mut M, pub String);

impl<T> Put<T> for Insert<'_, HashMap<String, T>> {
    fn put(self, value: T) {
        self.0.insert(self.1, value);
    }
}

impl<T> Put<T> for Insert<'_, BTreeMap<String, T>> {
    fn put(self, value: T) {
        self.0.insert(self.1, value);
    }
}

/// A single slot, such as a struct field.
pub struct Slot<'s, T>(pub &'s mut Option<T>);

impl<T> Put<T> for Slot<'_, T> {
    fn put(self, value: T) {
        *self.0 = Some(value);
    }
}

/// `T`'s own sink, with its result handed to `O` instead of returned.
/// This is how every container decodes a child: `Forward(T::sink(), slot)`.
pub struct Forward<T: Decrypt, O>(pub T::Sink, pub O);

impl<T: Decrypt, O: Put<T>> Sink for Forward<T, O> {
    type Ok = ();
    type Error = DecodeError;
    type Seq = ForwardEnd<T, <T::Sink as Sink>::Seq, O>;
    type Map = ForwardEnd<T, <T::Sink as Sink>::Map, O>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<(), DecodeError> {
        self.1.put(self.0.scalar(ty, v)?);
        Ok(())
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(ForwardEnd(self.0.seq(len)?, self.1, PhantomData))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(ForwardEnd(self.0.map(len)?, self.1, PhantomData))
    }

    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<(), DecodeError> {
        self.1.put(self.0.passthrough(value)?);
        Ok(())
    }
}

/// A container sink whose `end` hands its result to `O`.
pub struct ForwardEnd<T, Q, O>(Q, O, PhantomData<T>);

impl<T, Q: SeqSink<Ok = T, Error = DecodeError>, O: Put<T>> SeqSink for ForwardEnd<T, Q, O> {
    type Ok = ();
    type Error = DecodeError;
    type Element<'e>
        = Q::Element<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        self.0.element()
    }

    fn end(self) -> Result<(), DecodeError> {
        self.1.put(self.0.end()?);
        Ok(())
    }
}

impl<T, Q: MapSink<Ok = T, Error = DecodeError>, O: Put<T>> MapSink for ForwardEnd<T, Q, O> {
    type Ok = ();
    type Error = DecodeError;
    type Entry<'e>
        = Q::Entry<'e>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
        self.0.entry(key)
    }

    fn end(self) -> Result<(), DecodeError> {
        self.1.put(self.0.end()?);
        Ok(())
    }
}

/// `Vec<T>`: a sequence, each element decoded by `T`'s sink.
pub struct List<T>(PhantomData<T>);

impl<T: Decrypt> Sink for List<T> {
    type Ok = Vec<T>;
    type Error = DecodeError;
    type Seq = ListSeq<T>;
    type Map = Never<Vec<T>>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<Vec<T>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn seq(self, len: Option<usize>) -> Result<ListSeq<T>, DecodeError> {
        Ok(ListSeq(Vec::with_capacity(len.unwrap_or(0).min(1024))))
    }

    fn map(self, _: Option<usize>) -> Result<Never<Vec<T>>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<Vec<T>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }
}

pub struct ListSeq<T>(Vec<T>);

impl<T: Decrypt> SeqSink for ListSeq<T> {
    type Ok = Vec<T>;
    type Error = DecodeError;
    type Element<'s>
        = Forward<T, Push<'s, T>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        Ok(Forward(T::sink(), Push(&mut self.0)))
    }

    fn end(self) -> Result<Vec<T>, DecodeError> {
        Ok(self.0)
    }
}

impl<T: Decrypt> Decrypt for Vec<T> {
    type Sink = List<T>;
    fn sink() -> List<T> {
        List(PhantomData)
    }
}

/// `HashMap<String, T>` and `BTreeMap<String, T>`: a map, each value
/// decoded by `T`'s sink. The walk has already refused repeated keys.
pub struct Dict<M>(PhantomData<M>);

/// The entries of a [`Dict`].
pub struct DictEntries<M>(M);

macro_rules! dict_target {
    ($($map:ident),*) => {
        $(
            impl<T: Decrypt> Sink for Dict<$map<String, T>> {
                type Ok = $map<String, T>;
                type Error = DecodeError;
                type Seq = Never<$map<String, T>>;
                type Map = DictEntries<$map<String, T>>;

                fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<Self::Ok, DecodeError> {
                    Err(DecodeError::Expected("map"))
                }

                fn seq(self, _: Option<usize>) -> Result<Self::Seq, DecodeError> {
                    Err(DecodeError::Expected("map"))
                }

                fn map(self, _: Option<usize>) -> Result<Self::Map, DecodeError> {
                    Ok(DictEntries($map::new()))
                }

                fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<Self::Ok, DecodeError> {
                    Err(DecodeError::Expected("map"))
                }
            }

            impl<T: Decrypt> MapSink for DictEntries<$map<String, T>> {
                type Ok = $map<String, T>;
                type Error = DecodeError;
                type Entry<'s>
                    = Forward<T, Insert<'s, $map<String, T>>>
                where
                    Self: 's;

                fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
                    Ok(Forward(T::sink(), Insert(&mut self.0, key.to_owned())))
                }

                fn end(self) -> Result<Self::Ok, DecodeError> {
                    Ok(self.0)
                }
            }

            impl<T: Decrypt> Decrypt for $map<String, T> {
                type Sink = Dict<$map<String, T>>;
                fn sink() -> Self::Sink {
                    Dict(PhantomData)
                }
            }
        )*
    };
}

dict_target!(HashMap, BTreeMap);

/// `Option<T>`: null and `undefined` are `None`; anything else is `T`.
///
/// Since `None` is written as null, `Option<Option<T>>` cannot tell
/// `Some(None)` from `None`: both read back as `None`.
pub struct Optional<T: Decrypt>(T::Sink);

impl<T: Decrypt> Sink for Optional<T> {
    type Ok = Option<T>;
    type Error = DecodeError;
    type Seq = Some_<T, <T::Sink as Sink>::Seq>;
    type Map = Some_<T, <T::Sink as Sink>::Map>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Option<T>, DecodeError> {
        match (ty, v) {
            (None | Some(Logical::Undefined), Physical::Null) => Ok(None),
            _ => self.0.scalar(ty, v).map(Some),
        }
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(Some_(self.0.seq(len)?, PhantomData))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(Some_(self.0.map(len)?, PhantomData))
    }

    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<Option<T>, DecodeError> {
        self.0.passthrough(value).map(Some)
    }
}

/// A container sink whose result is wrapped in `Some`.
pub struct Some_<T, Q>(Q, PhantomData<T>);

impl<T, Q: SeqSink<Ok = T, Error = DecodeError>> SeqSink for Some_<T, Q> {
    type Ok = Option<T>;
    type Error = DecodeError;
    type Element<'e>
        = Q::Element<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        self.0.element()
    }

    fn end(self) -> Result<Option<T>, DecodeError> {
        self.0.end().map(Some)
    }
}

impl<T, Q: MapSink<Ok = T, Error = DecodeError>> MapSink for Some_<T, Q> {
    type Ok = Option<T>;
    type Error = DecodeError;
    type Entry<'e>
        = Q::Entry<'e>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
        self.0.entry(key)
    }

    fn end(self) -> Result<Option<T>, DecodeError> {
        self.0.end().map(Some)
    }
}

impl<T: Decrypt> Decrypt for Option<T> {
    type Sink = Optional<T>;
    fn sink() -> Optional<T> {
        Optional(T::sink())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::{Int, Raw};
    use crate::seal::mock::{Mock, Remote};
    use crate::{encrypt, encrypt_async};
    use futures_executor::block_on;

    fn round_trip<T: Decrypt>(
        p: impl Plaintext,
    ) -> Result<T, DecryptError<DecodeError, crate::seal::mock::Refused>> {
        decrypt(&Mock, encrypt(p, &Mock, "ctx").expect("encrypts"), "ctx")
    }

    fn expected<T>(
        r: Result<T, DecryptError<DecodeError, crate::seal::mock::Refused>>,
    ) -> &'static str {
        match r {
            Err(DecryptError::Sink(DecodeError::Expected(what))) => what,
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("decoded"),
        }
    }

    #[test]
    fn scalars_round_trip() {
        assert_eq!(round_trip::<u32>(34u32).expect("u32"), 34);
        assert_eq!(round_trip::<i128>(-5i64).expect("i128"), -5);
        assert!(round_trip::<bool>(true).expect("bool"));
        assert_eq!(round_trip::<f64>(2.5f64).expect("f64"), 2.5);
        assert_eq!(round_trip::<f64>(2.5f32).expect("f64 from f32"), 2.5);
        assert_eq!(round_trip::<String>("Ada").expect("string"), "Ada");
        assert_eq!(round_trip::<Vec<u8>>(vec![1u8, 2]).expect("bytes"), [1, 2]);
        assert_eq!(round_trip::<[u8; 2]>(vec![1u8, 2]).expect("array"), [1, 2]);
        assert_eq!(
            round_trip::<Protected<String>>(Protected::new(String::from("pw")))
                .expect("protected")
                .risky_ref(),
            "pw"
        );
        assert_eq!(
            round_trip::<Protected<Vec<u8>>>(vec![9u8])
                .expect("protected")
                .risky_ref(),
            &[9]
        );
    }

    #[test]
    fn integer_targets_read_the_value_not_the_width() {
        assert_eq!(round_trip::<u32>(34i8).expect("widens"), 34);
        assert_eq!(round_trip::<i8>(34u64).expect("narrows"), 34);
        assert_eq!(
            round_trip::<u128>(Raw(None, Physical::Int(Int::U128(u128::MAX)))).expect("u128"),
            u128::MAX
        );
        assert_eq!(expected(round_trip::<u32>(-1i8)), "u32");
        assert_eq!(expected(round_trip::<i8>(300u16)), "i8");
        assert_eq!(
            expected(round_trip::<i128>(Raw(
                None,
                Physical::Int(Int::U128(u128::MAX))
            ))),
            "i128"
        );
    }

    #[test]
    fn the_wrong_kind_is_refused_by_name() {
        assert_eq!(expected(round_trip::<String>(34u32)), "string");
        assert_eq!(expected(round_trip::<u32>("34")), "u32");
        assert_eq!(expected(round_trip::<f32>(2.5f64)), "f32");
        assert_eq!(expected(round_trip::<bool>(vec![true])), "bool");
        assert_eq!(expected(round_trip::<Vec<u32>>(34u32)), "sequence");
        assert_eq!(expected(round_trip::<[u8; 4]>(vec![1u8, 2])), "byte array");
        // A logical type is not its physical value.
        assert_eq!(
            expected(round_trip::<i32>(Raw(
                Some(Logical::Date),
                Physical::Int(Int::I32(0))
            ))),
            "i32"
        );
    }

    #[test]
    fn containers_round_trip() {
        assert_eq!(
            round_trip::<Vec<String>>(vec!["Ada", "Grace"]).expect("strings"),
            ["Ada", "Grace"]
        );
        assert_eq!(
            round_trip::<Vec<Vec<u32>>>(vec![vec![1u32, 2], vec![], vec![3]]).expect("nested"),
            [vec![1, 2], vec![], vec![3]]
        );
        assert_eq!(
            round_trip::<Vec<u32>>(Vec::<u32>::new()).expect("empty"),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn option_reads_null_and_undefined_as_none() {
        assert_eq!(round_trip::<Option<u32>>(None::<u32>).expect("none"), None);
        assert_eq!(
            round_trip::<Option<u32>>(Some(7u32)).expect("some"),
            Some(7)
        );
        assert_eq!(
            round_trip::<Option<u32>>(Raw(Some(Logical::Undefined), Physical::Null))
                .expect("undefined"),
            None
        );
        assert_eq!(
            round_trip::<Option<Vec<u32>>>(Some(vec![1u32])).expect("some seq"),
            Some(vec![1])
        );
        assert_eq!(
            round_trip::<Vec<Option<u32>>>(vec![Some(1u32), None]).expect("options"),
            [Some(1), None]
        );
        assert_eq!(expected(round_trip::<Option<u32>>("x")), "u32");
    }

    #[test]
    fn a_typed_target_works_through_an_async_cipher() {
        let remote = Remote::new(true);
        let sealed = block_on(encrypt_async(vec![1u32, 2], &remote, ())).expect("encrypts");
        let out: Vec<u32> = block_on(decrypt_async(&remote, sealed, ())).expect("decrypts");
        assert_eq!(out, [1, 2]);
        assert_eq!(remote.calls(), 2);
    }

    #[test]
    fn sync_and_async_decrypt_agree() {
        let mut value = BTreeMap::new();
        value.insert(String::from("a"), vec![Some(1u32), None]);
        value.insert(String::from("b"), vec![]);
        // The mock is deterministic, so both are the same ciphertext.
        let sealed = || encrypt(value.clone(), &Mock, "ctx").expect("encrypts");
        let sync: BTreeMap<String, Vec<Option<u32>>> =
            decrypt(&Mock, sealed(), "ctx").expect("sync");
        let remote = Remote::new(true);
        let async_: BTreeMap<String, Vec<Option<u32>>> =
            block_on(decrypt_async(&remote, sealed(), "ctx")).expect("async");
        assert_eq!(sync, async_);
        assert_eq!(sync, value);
    }

    #[test]
    fn maps_round_trip() {
        let mut hash = HashMap::new();
        hash.insert(String::from("a"), 1u32);
        hash.insert(String::from("b"), 2u32);
        assert_eq!(
            round_trip::<HashMap<String, u32>>(hash.clone()).expect("hash"),
            hash
        );
        let mut tree = BTreeMap::new();
        tree.insert("xs", vec![String::from("Ada")]);
        tree.insert("ys", vec![]);
        let back = round_trip::<BTreeMap<String, Vec<String>>>(tree).expect("tree");
        assert_eq!(back["xs"], ["Ada"]);
        assert!(back["ys"].is_empty());
        assert!(
            round_trip::<HashMap<String, u32>>(HashMap::<String, u32>::new())
                .expect("empty")
                .is_empty()
        );
        assert_eq!(
            expected(round_trip::<HashMap<String, u32>>(vec![1u32])),
            "map"
        );
        assert_eq!(expected(round_trip::<BTreeMap<String, u32>>(1u32)), "map");
        // A map's value of the wrong kind is refused by the value's name.
        let mut bad = BTreeMap::new();
        bad.insert("a", "x");
        assert_eq!(expected(round_trip::<BTreeMap<String, u32>>(bad)), "u32");
    }

    #[test]
    fn any_wipeable_scalar_reads_into_protected() {
        assert_eq!(
            *round_trip::<Protected<u64>>(34u64)
                .expect("u64")
                .risky_ref(),
            34
        );
        assert_eq!(
            round_trip::<Protected<[u8; 32]>>([7u8; 32])
                .expect("array")
                .risky_ref(),
            &[7; 32]
        );
        assert_eq!(
            expected(round_trip::<Protected<[u8; 4]>>(vec![1u8, 2])),
            "byte array"
        );
        assert_eq!(expected(round_trip::<Protected<u64>>("x")), "u64");
    }

    #[test]
    fn a_scalar_target_refuses_a_map_and_a_passthrough() {
        let mut map = BTreeMap::new();
        map.insert("a", 1u32);
        assert_eq!(expected(round_trip::<u32>(map)), "u32");

        // A passthrough is unauthenticated, so it must never stand in for a
        // sealed leaf.
        #[derive(Clone)]
        struct Clear;
        impl Plaintext for Clear {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(Some(2))?;
                seq.element()?.passthrough(7u16)?;
                8u16.visit(seq.element()?)?;
                seq.end()
            }
        }
        assert_eq!(expected(round_trip::<Vec<u16>>(Clear)), "u16");
        assert_eq!(expected(round_trip::<Vec<Option<u16>>>(Clear)), "u16");
    }

    #[test]
    fn nested_maps_are_handed_up_to_their_container() {
        let mut row = BTreeMap::new();
        row.insert(String::from("a"), 1u32);
        let rows = vec![row.clone(), row.clone()];
        assert_eq!(
            round_trip::<Vec<BTreeMap<String, u32>>>(rows.clone()).expect("decodes"),
            rows
        );
        assert_eq!(
            round_trip::<Option<BTreeMap<String, u32>>>(Some(row.clone())).expect("decodes"),
            Some(row)
        );
    }

    #[test]
    fn a_list_target_refuses_a_passthrough() {
        struct Clear;
        impl Plaintext for Clear {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough(vec![1u16])
            }
        }
        assert_eq!(expected(round_trip::<Vec<u16>>(Clear)), "sequence");
    }

    #[test]
    fn f32_reads_only_an_f32() {
        assert_eq!(round_trip::<f32>(1.5f32).expect("decodes"), 1.5);
        assert_eq!(expected(round_trip::<f32>(1.5f64)), "f32");
    }

    #[test]
    fn a_slot_holds_what_is_put() {
        let mut held = None;
        Slot(&mut held).put(3u8);
        assert_eq!(held, Some(3));
    }

    #[test]
    fn some_none_reads_back_as_none() {
        assert_eq!(
            round_trip::<Option<Option<u32>>>(Some(None::<u32>)).expect("decodes"),
            None
        );
        assert_eq!(
            round_trip::<Option<Option<u32>>>(Some(Some(1u32))).expect("decodes"),
            Some(Some(1))
        );
    }

    #[test]
    fn decode_errors_are_std_errors() {
        let e: Box<dyn std::error::Error> = Box::new(DecodeError::Expected("u32"));
        assert_eq!(e.to_string(), "expected u32");
        assert!(std::error::Error::source(&DecodeError::Expected("u32")).is_none());
        let source = DecodeError::Source(SourceError::new(fmt::Error));
        assert!(std::error::Error::source(&source).is_some());
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_targets_accept_any_unit() {
        use crate::plaintext::TimeUnit;
        use ::chrono::{DateTime, NaiveDate};
        let date = NaiveDate::from_ymd_opt(2024, 2, 29).expect("date");
        assert_eq!(round_trip::<NaiveDate>(date).expect("date"), date);
        let ts = DateTime::from_timestamp(1_700_000_000, 123_456_789).expect("ts");
        assert_eq!(round_trip::<DateTime<_>>(ts).expect("ts"), ts);
        // A JavaScript `Date` is milliseconds.
        let js = Raw(
            Some(Logical::Timestamp(TimeUnit::Millis)),
            Physical::Int(Int::I64(1_700_000_000_123)),
        );
        assert_eq!(
            round_trip::<DateTime<_>>(js).expect("ms"),
            DateTime::from_timestamp(1_700_000_000, 123_000_000).expect("ts")
        );
        assert_eq!(expected(round_trip::<NaiveDate>(0i32)), "date");
    }

    #[cfg(feature = "rust_decimal")]
    #[test]
    fn decimal_round_trips_with_its_scale() {
        let d: rust_decimal::Decimal = "1.50".parse().expect("decimal");
        let back = round_trip::<rust_decimal::Decimal>(d).expect("decimal");
        assert_eq!(back, d);
        assert_eq!(back.scale(), 2);
        assert_eq!(
            expected(round_trip::<rust_decimal::Decimal>(150u32)),
            "decimal"
        );
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn uuid_round_trips() {
        let id = uuid::Uuid::from_bytes([5; 16]);
        assert_eq!(round_trip::<uuid::Uuid>(id).expect("uuid"), id);
        assert_eq!(expected(round_trip::<uuid::Uuid>(vec![5u8; 16])), "uuid");
    }
}
