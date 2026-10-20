//! Statically typed decryption as sinks.
//!
//! A type that can be decrypted names the [`Sink`] that builds it
//! ([`Decrypt`]). A scalar target is one function from a scalar, logical
//! plus physical, to the type, or `None` to refuse it ([`FromScalar`]);
//! every such type gets its sink for free. Containers push each child into
//! the parent through the child's own sink.
//!
//! Integer targets read the value, not the width: a `u32` accepts an `i8`
//! leaf holding 34 and refuses one holding -1. The width is a host-fidelity
//! hint. `Option<T>` reads null and `undefined` as `None` and defers
//! anything else to `T`. A typed null (see [`Sink::typed_null`]) is `None`
//! only for an `Option<T>` whose `T` has that same
//! [`FIXED`](Decrypt::FIXED) type, the one its own `None` seals as; any
//! other target refuses it as the wrong kind, never reads it as a zero. `HashMap<String, T>` and `BTreeMap<String, T>`
//! read a map, each value through `T`'s sink.
//!
//! `Protected<T>` is a target for every `T` that implements
//! [`DecryptProtected`]: any scalar target that can be wiped, and a
//! `Vec<T>` or `Option<T>` of such targets, nested to any depth. A
//! protected target is built inside its wrapper from the start, so a walk
//! that fails part way wipes whatever it had already decoded.
//!
//! A struct's sink is what `#[derive(Decrypt)]` generates, out of the
//! pieces here: a map sink with one slot per field, whose `entry` hands
//! back [`Either`] of the fields' own sinks ([`Forward`] for a sealed
//! field, [`Clear`] for a passthrough one). A newtype's sink is its inner
//! type's, [`Wrapped`] so the result is rewrapped. A field decoded before
//! a later entry is refused is dropped as an ordinary value, so a secret
//! field should be a `Protected<T>`, which wipes itself, whatever the
//! struct around it does.
//!
//! Nothing here knows whether the cipher was sync or async: the opened tree
//! is walked after every await has completed.
//!
//! [`Decrypt`] is re-exported from the crate root.

use core::marker::PhantomData;
use std::collections::{BTreeMap, HashMap};

use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

use crate::plaintext::{
    Encrypt, Error, FixedType, Float, Logical, MapSink, Physical, SeqSink, Sink, SourceError, Width,
};
use crate::seal::{AsyncCipher, Cipher, Node};
use crate::walk::{decrypt_into, decrypt_into_async, DecryptError};
use crate::IntoAad;

/// Derive [`Decrypt`] for a struct or a fieldless enum: the sink that builds
/// it. A struct reads a map keyed by field name; a fieldless enum reads an
/// int leaf holding the variant's discriminant. Takes the same
/// `#[aead(...)]` attributes as [`Encrypt`](macro@crate::Encrypt).
#[doc(inline)]
pub use vitaminc_aead_derive::Decrypt;

/// Why a typed target refused what it was given.
///
/// Non-exhaustive, so a target can add refusals without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The ciphertext holds something other than the named kind.
    #[error("expected {0}")]
    Expected(&'static str),
    /// A map holds a key the target has no field for.
    #[error("unknown key {0:?}")]
    UnknownKey(String),
    /// A map holds the same key twice.
    #[error("duplicate key {0:?}")]
    DuplicateKey(String),
    /// A map is missing the named field.
    #[error("missing field {0:?}")]
    MissingField(&'static str),
    /// The source stopped the walk (only reachable through a passthrough).
    #[error("source failed: {0}")]
    Source(#[source] SourceError),
}

impl DecodeError {
    /// A map holds `key`, which the target has no field for.
    pub fn unknown_key(key: &str) -> Self {
        Self::UnknownKey(key.to_owned())
    }

    /// A map holds `key` twice.
    pub fn duplicate_key(key: &str) -> Self {
        Self::DuplicateKey(key.to_owned())
    }
}

impl Error for DecodeError {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

/// A type that can be decrypted: it names the sink that builds it.
pub trait Decrypt: Sized {
    type Sink: Sink<Ok = Self, Error = DecodeError>;

    /// The fixed-width type whose typed null an `Option<Self>` reads as
    /// `None`: the [`Encrypt::FIXED`] of the same type, so a `None` reads
    /// back as it was sealed. `None`, the default, for a type with none,
    /// whose `Option` then refuses every typed null.
    const FIXED: Option<FixedType> = None;

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
    /// The type's [`Decrypt::FIXED`].
    const FIXED: Option<FixedType> = None;
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

    /// An absent value is not a value, whatever its type.
    fn typed_null(self, _: FixedType) -> Result<T, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn seq(self, _: Option<usize>) -> Result<Never<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn map(self, _: Option<usize>) -> Result<Never<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<T, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }
}

impl<T: FromScalar> Decrypt for T {
    type Sink = ScalarSink<T>;
    const FIXED: Option<FixedType> = T::FIXED;
    fn sink() -> ScalarSink<T> {
        ScalarSink(PhantomData)
    }
}

/// A sink nothing is ever walked into: the element and entry type of a
/// container sink that hands out none, such as [`Never`] and the map sink
/// of a derived struct with no fields. Uninhabited, so it cannot be built.
pub enum Nothing {}

impl Sink for Nothing {
    type Ok = ();
    type Error = DecodeError;
    type Seq = Never<()>;
    type Map = Never<()>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), DecodeError> {
        match self {}
    }

    fn typed_null(self, _: FixedType) -> Result<(), DecodeError> {
        match self {}
    }

    fn seq(self, _: Option<usize>) -> Result<Never<()>, DecodeError> {
        match self {}
    }

    fn map(self, _: Option<usize>) -> Result<Never<()>, DecodeError> {
        match self {}
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<(), DecodeError> {
        match self {}
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
        = Nothing
    where
        Self: 's;

    fn element(&mut self) -> Result<Nothing, DecodeError> {
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
        = Nothing
    where
        Self: 's;

    fn entry(&mut self, _: &str) -> Result<Nothing, DecodeError> {
        self.absurd()
    }

    fn end(self) -> Result<T, DecodeError> {
        self.absurd()
    }
}

macro_rules! int_target {
    ($($ty:ty => $width:ident),* $(,)?) => {
        $(
            impl FromScalar for $ty {
                const EXPECTED: &'static str = stringify!($ty);
                const FIXED: Option<FixedType> = Some(FixedType::plain(Width::$width));
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
int_target! {
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
    u16 => U16, u32 => U32, u64 => U64, u128 => U128,
}

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
    const FIXED: Option<FixedType> = Some(FixedType::plain(Width::F32));
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
    const FIXED: Option<FixedType> = Some(FixedType::plain(Width::F64));
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

    /// Built in place inside the wrapper, so the array never passes through a bare temporary.
    /// The wrapper holds the bytes inline, so a later move can still leave an unwiped copy on the stack.
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

#[cfg(feature = "chrono")]
mod chrono_targets {
    use super::*;
    use crate::plaintext::kinds::chrono as conv;
    use ::chrono::{DateTime, NaiveDate, Utc};

    impl FromScalar for NaiveDate {
        const EXPECTED: &'static str = "date";
        const FIXED: Option<FixedType> = <NaiveDate as Encrypt>::FIXED;
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
        const FIXED: Option<FixedType> = <DateTime<Utc> as Encrypt>::FIXED;
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
    const FIXED: Option<FixedType> = <rust_decimal::Decimal as Encrypt>::FIXED;
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

    fn typed_null(self, ty: FixedType) -> Result<(), DecodeError> {
        self.1.put(self.0.typed_null(ty)?);
        Ok(())
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(ForwardEnd(self.0.seq(len)?, self.1, PhantomData))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(ForwardEnd(self.0.map(len)?, self.1, PhantomData))
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), DecodeError> {
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

/// One of two sinks. The sink a derived struct hands out for an entry is
/// one of its fields' sinks, which have different types, so `entry`
/// returns them as a chain of `Either`s. The two sides share an error;
/// the result is whichever side ran, which nobody reads, since an entry
/// sink writes into its parent. The chain composes through containers:
/// the `Seq` of an `Either` is an `Either` of the two `Seq`s, and so on
/// down.
pub enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L: Sink, R: Sink<Error = L::Error>> Sink for Either<L, R> {
    type Ok = Either<L::Ok, R::Ok>;
    type Error = L::Error;
    type Seq = Either<L::Seq, R::Seq>;
    type Map = Either<L::Map, R::Map>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Self::Ok, Self::Error> {
        match self {
            Either::Left(l) => l.scalar(ty, v).map(Either::Left),
            Either::Right(r) => r.scalar(ty, v).map(Either::Right),
        }
    }

    fn typed_null(self, ty: FixedType) -> Result<Self::Ok, Self::Error> {
        match self {
            Either::Left(l) => l.typed_null(ty).map(Either::Left),
            Either::Right(r) => r.typed_null(ty).map(Either::Right),
        }
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error> {
        match self {
            Either::Left(l) => l.seq(len).map(Either::Left),
            Either::Right(r) => r.seq(len).map(Either::Right),
        }
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, Self::Error> {
        match self {
            Either::Left(l) => l.map(len).map(Either::Left),
            Either::Right(r) => r.map(len).map(Either::Right),
        }
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<Self::Ok, Self::Error> {
        match self {
            Either::Left(l) => l.passthrough(value).map(Either::Left),
            Either::Right(r) => r.passthrough(value).map(Either::Right),
        }
    }
}

impl<L: SeqSink, R: SeqSink<Error = L::Error>> SeqSink for Either<L, R> {
    type Ok = Either<L::Ok, R::Ok>;
    type Error = L::Error;
    type Element<'s>
        = Either<L::Element<'s>, R::Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error> {
        match self {
            Either::Left(l) => l.element().map(Either::Left),
            Either::Right(r) => r.element().map(Either::Right),
        }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        match self {
            Either::Left(l) => l.end().map(Either::Left),
            Either::Right(r) => r.end().map(Either::Right),
        }
    }
}

impl<L: MapSink, R: MapSink<Error = L::Error>> MapSink for Either<L, R> {
    type Ok = Either<L::Ok, R::Ok>;
    type Error = L::Error;
    type Entry<'s>
        = Either<L::Entry<'s>, R::Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error> {
        match self {
            Either::Left(l) => l.entry(key).map(Either::Left),
            Either::Right(r) => r.entry(key).map(Either::Right),
        }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        match self {
            Either::Left(l) => l.end().map(Either::Left),
            Either::Right(r) => r.end().map(Either::Right),
        }
    }
}

/// A passthrough target: `T` built from a subtree that travelled in the
/// clear, with the result handed to `O`. A derived struct uses it for a
/// `#[aead(passthrough)]` field. The subtree is walked into `T`'s own sink,
/// so it decodes exactly as a sealed `T` would; what it refuses is a
/// sealed value where a passthrough was expected, since the two are not
/// interchangeable. Nothing here is authenticated.
pub struct Clear<T: Decrypt, O>(O, PhantomData<T>);

impl<T: Decrypt, O: Put<T>> Clear<T, O> {
    pub fn new(out: O) -> Self {
        Self(out, PhantomData)
    }
}

impl<T: Decrypt, O: Put<T>> Sink for Clear<T, O> {
    type Ok = ();
    type Error = DecodeError;
    type Seq = Never<()>;
    type Map = Never<()>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), DecodeError> {
        Err(DecodeError::Expected("passthrough"))
    }

    fn typed_null(self, _: FixedType) -> Result<(), DecodeError> {
        Err(DecodeError::Expected("passthrough"))
    }

    fn seq(self, _: Option<usize>) -> Result<Never<()>, DecodeError> {
        Err(DecodeError::Expected("passthrough"))
    }

    fn map(self, _: Option<usize>) -> Result<Never<()>, DecodeError> {
        Err(DecodeError::Expected("passthrough"))
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), DecodeError> {
        self.0.put(value.visit(T::sink())?);
        Ok(())
    }
}

/// A conversion applied to a sink's result: what a newtype's sink does to
/// its inner type's result. Fallible, so a newtype whose conversion can
/// refuse a value (a length-checked string, say) is one `Rewrap` impl, with
/// the refusal reported as a [`DecodeError`].
pub trait Rewrap<T> {
    type Output;
    fn rewrap(value: T) -> Result<Self::Output, DecodeError>;
}

/// `S` with its result passed through `W`. A derived newtype's sink is
/// `Wrapped<Inner::Sink, W>` for a `W` that rewraps the inner value.
pub struct Wrapped<S, W>(S, PhantomData<W>);

impl<S, W> Wrapped<S, W> {
    pub fn new(sink: S) -> Self {
        Self(sink, PhantomData)
    }
}

impl<S: Sink<Error = DecodeError>, W: Rewrap<S::Ok>> Sink for Wrapped<S, W> {
    type Ok = W::Output;
    type Error = DecodeError;
    type Seq = WrappedEnd<S::Seq, W>;
    type Map = WrappedEnd<S::Map, W>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<W::Output, DecodeError> {
        self.0.scalar(ty, v).and_then(W::rewrap)
    }

    fn typed_null(self, ty: FixedType) -> Result<W::Output, DecodeError> {
        self.0.typed_null(ty).and_then(W::rewrap)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(WrappedEnd(self.0.seq(len)?, PhantomData))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(WrappedEnd(self.0.map(len)?, PhantomData))
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<W::Output, DecodeError> {
        self.0.passthrough(value).and_then(W::rewrap)
    }
}

/// A container sink whose `end` passes its result through `W`.
pub struct WrappedEnd<Q, W>(Q, PhantomData<W>);

impl<Q: SeqSink<Error = DecodeError>, W: Rewrap<Q::Ok>> SeqSink for WrappedEnd<Q, W> {
    type Ok = W::Output;
    type Error = DecodeError;
    type Element<'e>
        = Q::Element<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        self.0.element()
    }

    fn end(self) -> Result<W::Output, DecodeError> {
        self.0.end().and_then(W::rewrap)
    }
}

impl<Q: MapSink<Error = DecodeError>, W: Rewrap<Q::Ok>> MapSink for WrappedEnd<Q, W> {
    type Ok = W::Output;
    type Error = DecodeError;
    type Entry<'e>
        = Q::Entry<'e>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
        self.0.entry(key)
    }

    fn end(self) -> Result<W::Output, DecodeError> {
        self.0.end().and_then(W::rewrap)
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

    fn typed_null(self, _: FixedType) -> Result<Vec<T>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn seq(self, len: Option<usize>) -> Result<ListSeq<T>, DecodeError> {
        Ok(ListSeq(Vec::with_capacity(len.unwrap_or(0).min(1024))))
    }

    fn map(self, _: Option<usize>) -> Result<Never<Vec<T>>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Vec<T>, DecodeError> {
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

                fn typed_null(self, _: FixedType) -> Result<Self::Ok, DecodeError> {
                    Err(DecodeError::Expected("map"))
                }

                fn seq(self, _: Option<usize>) -> Result<Self::Seq, DecodeError> {
                    Err(DecodeError::Expected("map"))
                }

                fn map(self, _: Option<usize>) -> Result<Self::Map, DecodeError> {
                    Ok(DictEntries($map::new()))
                }

                fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Self::Ok, DecodeError> {
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
/// A typed null is `None` if it is of `T`'s [`FIXED`](Decrypt::FIXED)
/// type, and otherwise refused by `T`'s sink as the wrong kind.
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

    fn typed_null(self, ty: FixedType) -> Result<Option<T>, DecodeError> {
        if T::FIXED == Some(ty) {
            return Ok(None);
        }
        self.0.typed_null(ty).map(Some)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(Some_(self.0.seq(len)?, PhantomData))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(Some_(self.0.map(len)?, PhantomData))
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<Option<T>, DecodeError> {
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
    const FIXED: Option<FixedType> = T::FIXED;
    fn sink() -> Optional<T> {
        Optional(T::sink())
    }
}

/// A type that can be decrypted straight into `Protected<Self>`: it names
/// the sink that builds the wrapped value.
///
/// This is what makes `Protected<T>` a target. Scalars build in place
/// through [`FromScalar::from_scalar_protected`]; `Vec<T>` and `Option<T>`
/// build inside the wrapper from the first element, so a failure part way
/// wipes what was already decoded. A struct target opts in with its own
/// impl (the orphan rule lets the crate that defines the struct write it).
pub trait DecryptProtected: Decrypt + Zeroize {
    type ProtectedSink: Sink<Ok = Protected<Self>, Error = DecodeError>;
    fn protected_sink() -> Self::ProtectedSink;
}

impl<T: DecryptProtected> Decrypt for Protected<T> {
    type Sink = T::ProtectedSink;
    const FIXED: Option<FixedType> = T::FIXED;
    fn sink() -> T::ProtectedSink {
        T::protected_sink()
    }
}

/// Any scalar target that can be wiped, read into `Protected`. A heap
/// type (`String`, `Vec<u8>`) is copied once, into the wrapper's buffer.
/// An inline type (an integer, `[u8; N]`) moves by value, so a move can
/// leave an unwiped copy on the stack. The opened leaf's buffer is wiped
/// when it drops.
impl<T: FromScalar + Zeroize> DecryptProtected for T {
    type ProtectedSink = ScalarProtected<T>;
    fn protected_sink() -> ScalarProtected<T> {
        ScalarProtected(PhantomData)
    }
}

/// The sink for `Protected<T>` of a [`FromScalar`] type. Refuses
/// containers and passthrough, as [`ScalarSink`] does.
pub struct ScalarProtected<T>(PhantomData<T>);

impl<T: FromScalar + Zeroize> Sink for ScalarProtected<T> {
    type Ok = Protected<T>;
    type Error = DecodeError;
    type Seq = Never<Protected<T>>;
    type Map = Never<Protected<T>>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Protected<T>, DecodeError> {
        T::from_scalar_protected(ty, v).ok_or(DecodeError::Expected(T::EXPECTED))
    }

    fn typed_null(self, _: FixedType) -> Result<Protected<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn seq(self, _: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn map(self, _: Option<usize>) -> Result<Self::Map, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Protected<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }
}

/// `Protected<Vec<T>>`: a sequence built inside the wrapper, each element
/// decoded by `Protected<T>`'s sink, so nested containers are protected
/// too.
///
/// `T` needs [`DecryptProtected`], as `Vec<T>` needs [`Decrypt`]; neither
/// covers `u8`, so this does not overlap `Vec<u8>`, the byte leaf.
impl<T: DecryptProtected> DecryptProtected for Vec<T> {
    type ProtectedSink = ProtectedList<T>;
    fn protected_sink() -> ProtectedList<T> {
        ProtectedList(PhantomData)
    }
}

/// The sink for `Protected<Vec<T>>`.
pub struct ProtectedList<T>(PhantomData<T>);

impl<T: DecryptProtected> Sink for ProtectedList<T> {
    type Ok = Protected<Vec<T>>;
    type Error = DecodeError;
    type Seq = ProtectedListSeq<T>;
    type Map = Never<Protected<Vec<T>>>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<Self::Ok, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn typed_null(self, _: FixedType) -> Result<Self::Ok, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn seq(self, len: Option<usize>) -> Result<ProtectedListSeq<T>, DecodeError> {
        let items = Vec::with_capacity(len.unwrap_or(0).min(1024));
        Ok(ProtectedListSeq(Protected::new(items)))
    }

    fn map(self, _: Option<usize>) -> Result<Self::Map, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Self::Ok, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }
}

/// The elements of a [`ProtectedList`], kept inside the wrapper. Dropped
/// part way, it zeroizes every element decoded so far.
pub struct ProtectedListSeq<T: Zeroize>(Protected<Vec<T>>);

impl<T: DecryptProtected> SeqSink for ProtectedListSeq<T> {
    type Ok = Protected<Vec<T>>;
    type Error = DecodeError;
    type Element<'s>
        = Forward<Protected<T>, ProtectedPush<'s, T>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        Ok(Forward(
            T::protected_sink(),
            ProtectedPush(self.0.risky_inner_mut()),
        ))
    }

    fn end(self) -> Result<Protected<Vec<T>>, DecodeError> {
        Ok(self.0)
    }
}

/// The next slot of a protected sequence. A full vector grows into a new
/// buffer and wipes the old one, since a `Vec` that regrows by itself
/// frees its old buffer with the elements' bytes still in it.
pub struct ProtectedPush<'s, T: Zeroize>(&'s mut Vec<T>);

impl<T: Zeroize> Put<Protected<T>> for ProtectedPush<'_, T> {
    fn put(self, value: Protected<T>) {
        if self.0.len() == self.0.capacity() {
            let mut grown = Vec::with_capacity(self.0.capacity().max(4) * 2);
            grown.append(self.0);
            // `append` moved the elements out; wipe the bytes they left.
            self.0.zeroize();
            *self.0 = grown;
        }
        self.0.push(value.risky_unwrap());
    }
}

/// `Protected<Option<T>>`: null and `undefined` are `None`; anything else
/// is built by `Protected<T>`'s sink and moved into the wrapper's `Some`.
impl<T: DecryptProtected> DecryptProtected for Option<T> {
    type ProtectedSink = ProtectedOptional<T>;
    fn protected_sink() -> ProtectedOptional<T> {
        ProtectedOptional(T::protected_sink())
    }
}

/// The sink for `Protected<Option<T>>`.
pub struct ProtectedOptional<T: DecryptProtected>(T::ProtectedSink);

impl<T: DecryptProtected> Sink for ProtectedOptional<T> {
    type Ok = Protected<Option<T>>;
    type Error = DecodeError;
    type Seq = SomeProtected<T, <T::ProtectedSink as Sink>::Seq>;
    type Map = SomeProtected<T, <T::ProtectedSink as Sink>::Map>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Self::Ok, DecodeError> {
        match (ty, v) {
            (None | Some(Logical::Undefined), Physical::Null) => Ok(Protected::new(None)),
            _ => self.0.scalar(ty, v).map(some),
        }
    }

    fn typed_null(self, ty: FixedType) -> Result<Self::Ok, DecodeError> {
        if T::FIXED == Some(ty) {
            return Ok(Protected::new(None));
        }
        self.0.typed_null(ty).map(some)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(SomeProtected(self.0.seq(len)?, PhantomData))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(SomeProtected(self.0.map(len)?, PhantomData))
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<Self::Ok, DecodeError> {
        self.0.passthrough(value).map(some)
    }
}

/// Move a protected value into a protected `Some`.
fn some<T: Zeroize>(value: Protected<T>) -> Protected<Option<T>> {
    value.map(Some)
}

/// Any sink, with its result moved into `Protected` when it is done: the
/// simplest [`DecryptProtected`] sink for a struct target, as
/// `Wrap(MyStruct::sink())`.
///
/// The value is built bare and wrapped at the end, so a walk that fails
/// part way drops what it had built without wiping it. A target that holds
/// secrets in its own fields can do better by building each field inside
/// its own wrapper, as [`ProtectedList`] does.
pub struct Wrap<S>(pub S);

impl<S> Sink for Wrap<S>
where
    S: Sink<Error = DecodeError>,
    S::Ok: Zeroize,
{
    type Ok = Protected<S::Ok>;
    type Error = DecodeError;
    type Seq = WrapEnd<S::Seq>;
    type Map = WrapEnd<S::Map>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Self::Ok, DecodeError> {
        self.0.scalar(ty, v).map(Protected::new)
    }

    fn typed_null(self, ty: FixedType) -> Result<Self::Ok, DecodeError> {
        self.0.typed_null(ty).map(Protected::new)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(WrapEnd(self.0.seq(len)?))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(WrapEnd(self.0.map(len)?))
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<Self::Ok, DecodeError> {
        self.0.passthrough(value).map(Protected::new)
    }
}

/// A container sink whose result is moved into `Protected` at its end.
pub struct WrapEnd<Q>(Q);

impl<Q> SeqSink for WrapEnd<Q>
where
    Q: SeqSink<Error = DecodeError>,
    Q::Ok: Zeroize,
{
    type Ok = Protected<Q::Ok>;
    type Error = DecodeError;
    type Element<'e>
        = Q::Element<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        self.0.element()
    }

    fn end(self) -> Result<Self::Ok, DecodeError> {
        self.0.end().map(Protected::new)
    }
}

impl<Q> MapSink for WrapEnd<Q>
where
    Q: MapSink<Error = DecodeError>,
    Q::Ok: Zeroize,
{
    type Ok = Protected<Q::Ok>;
    type Error = DecodeError;
    type Entry<'e>
        = Q::Entry<'e>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
        self.0.entry(key)
    }

    fn end(self) -> Result<Self::Ok, DecodeError> {
        self.0.end().map(Protected::new)
    }
}

/// A container sink whose protected result is moved into a protected
/// `Some`.
pub struct SomeProtected<T, Q>(Q, PhantomData<T>);

impl<T, Q> SeqSink for SomeProtected<T, Q>
where
    T: Zeroize,
    Q: SeqSink<Ok = Protected<T>, Error = DecodeError>,
{
    type Ok = Protected<Option<T>>;
    type Error = DecodeError;
    type Element<'e>
        = Q::Element<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        self.0.element()
    }

    fn end(self) -> Result<Protected<Option<T>>, DecodeError> {
        self.0.end().map(some)
    }
}

impl<T, Q> MapSink for SomeProtected<T, Q>
where
    T: Zeroize,
    Q: MapSink<Ok = Protected<T>, Error = DecodeError>,
{
    type Ok = Protected<Option<T>>;
    type Error = DecodeError;
    type Entry<'e>
        = Q::Entry<'e>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
        self.0.entry(key)
    }

    fn end(self) -> Result<Protected<Option<T>>, DecodeError> {
        self.0.end().map(some)
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
        p: impl Encrypt,
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

    /// A typed null as a host would describe it.
    struct Null(FixedType);

    impl Encrypt for Null {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.typed_null(self.0)
        }
    }

    #[test]
    fn a_typed_null_reads_as_none_only_for_an_option_of_its_type() {
        // Sealed by `Option<T>`'s own `None`, and read back by it.
        assert_eq!(round_trip::<Option<u32>>(None::<u32>).expect("u32"), None);
        assert_eq!(round_trip::<Option<i8>>(None::<i8>).expect("i8"), None);
        assert_eq!(round_trip::<Option<f32>>(None::<f32>).expect("f32"), None);
        assert_eq!(
            round_trip::<Option<Option<i64>>>(None::<i64>).expect("nested"),
            None
        );
        assert_eq!(
            round_trip::<Vec<Option<u16>>>(vec![None, Some(3u16)]).expect("elements"),
            [None, Some(3)]
        );
        // Any other type's typed null is the wrong kind, never a `None`:
        // not another width (even one whose values the target reads), not
        // a float for an int, not a logical type over the same int.
        let u32_null = || Null(FixedType::plain(Width::U32));
        assert_eq!(expected(round_trip::<Option<u64>>(u32_null())), "u64");
        assert_eq!(expected(round_trip::<Option<f32>>(u32_null())), "f32");
        assert_eq!(expected(round_trip::<Option<String>>(u32_null())), "string");
        assert_eq!(
            expected(round_trip::<Option<f64>>(Null(FixedType::plain(
                Width::F32
            )))),
            "f64"
        );
        let date = FixedType::new(Some(Logical::Date), Width::I32).expect("fixed");
        assert_eq!(expected(round_trip::<Option<i32>>(Null(date))), "i32");
        assert_eq!(
            expected(round_trip::<Option<Vec<u32>>>(u32_null())),
            "sequence"
        );
    }

    #[test]
    fn a_typed_null_is_not_a_value() {
        assert_eq!(expected(round_trip::<u32>(None::<u32>)), "u32");
        assert_eq!(expected(round_trip::<f64>(None::<f64>)), "f64");
        assert_eq!(expected(round_trip::<Vec<u32>>(None::<u32>)), "sequence");
        assert_eq!(
            expected(round_trip::<HashMap<String, u32>>(None::<u32>)),
            "map"
        );
        assert_eq!(expected(round_trip::<Protected<u32>>(None::<u32>)), "u32");
    }

    #[test]
    fn the_plain_null_still_reads_as_none_for_any_option() {
        // What every writer sealed before typed nulls, and still seals for
        // a type with no fixed width.
        assert_eq!(
            round_trip::<Option<u32>>(Raw(None, Physical::Null)).expect("u32"),
            None
        );
        assert_eq!(
            round_trip::<Protected<Option<u32>>>(Raw(None, Physical::Null))
                .expect("protected")
                .risky_ref(),
            &None
        );
    }

    #[test]
    fn a_protected_option_reads_its_typed_null() {
        assert_eq!(
            round_trip::<Protected<Option<u32>>>(None::<u32>)
                .expect("none")
                .risky_ref(),
            &None
        );
        assert_eq!(
            expected(round_trip::<Protected<Option<u64>>>(None::<u32>)),
            "u64"
        );
    }

    #[test]
    fn decrypt_and_encrypt_agree_on_every_fixed_type() {
        fn same<T: Encrypt + Decrypt>() {
            assert_eq!(<T as Encrypt>::FIXED, <T as Decrypt>::FIXED);
        }
        same::<i8>();
        same::<i16>();
        same::<i32>();
        same::<i64>();
        same::<i128>();
        same::<u16>();
        same::<u32>();
        same::<u64>();
        same::<u128>();
        same::<f32>();
        same::<f64>();
        same::<bool>();
        same::<String>();
        same::<Option<u32>>();
        same::<Vec<u32>>();
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
        impl Encrypt for Clear {
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
        impl Encrypt for Clear {
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

    /// `Clear` only accepts a passthrough, and decodes it through the
    /// target's own sink.
    #[test]
    fn clear_decodes_a_passthrough_and_nothing_else() {
        let mut held = None;
        Clear::<Vec<u16>, _>::new(Slot(&mut held))
            .passthrough(vec![1u16, 2])
            .expect("decodes");
        assert_eq!(held, Some(vec![1, 2]));
        let refused = |r: Result<(), DecodeError>| {
            assert!(matches!(r, Err(DecodeError::Expected("passthrough"))))
        };
        let mut held: Option<u16> = None;
        refused(Clear::<u16, _>::new(Slot(&mut held)).scalar(None, Physical::Null));
        refused(Clear::<u16, _>::new(Slot(&mut held)).seq(None).map(|_| ()));
        refused(Clear::<u16, _>::new(Slot(&mut held)).map(None).map(|_| ()));
        assert!(matches!(
            Clear::<u16, _>::new(Slot(&mut held)).passthrough("x"),
            Err(DecodeError::Expected("u16"))
        ));
    }

    /// A newtype's conversion can refuse a value, and the refusal comes
    /// out as the sink's error wherever it happens: on a scalar, or at the
    /// end of a container.
    #[test]
    fn a_wrap_can_refuse_what_it_is_handed() {
        struct AtMostTwo;
        impl Rewrap<Vec<u16>> for AtMostTwo {
            type Output = Vec<u16>;
            fn rewrap(v: Vec<u16>) -> Result<Vec<u16>, DecodeError> {
                (v.len() <= 2)
                    .then_some(v)
                    .ok_or(DecodeError::Expected("at most two"))
            }
        }
        struct Even;
        impl Rewrap<u16> for Even {
            type Output = u16;
            fn rewrap(v: u16) -> Result<u16, DecodeError> {
                v.is_multiple_of(2)
                    .then_some(v)
                    .ok_or(DecodeError::Expected("even"))
            }
        }
        let short = vec![1u16, 2].visit(Wrapped::<_, AtMostTwo>::new(Vec::<u16>::sink()));
        assert_eq!(short.expect("two"), [1, 2]);
        let long = vec![1u16, 2, 3].visit(Wrapped::<_, AtMostTwo>::new(Vec::<u16>::sink()));
        assert!(matches!(long, Err(DecodeError::Expected("at most two"))));
        assert_eq!(
            4u16.visit(Wrapped::<_, Even>::new(u16::sink()))
                .expect("even"),
            4
        );
        assert!(matches!(
            5u16.visit(Wrapped::<_, Even>::new(u16::sink())),
            Err(DecodeError::Expected("even"))
        ));
        assert!(matches!(
            DecodeError::unknown_key("k"),
            DecodeError::UnknownKey(k) if k == "k"
        ));
        assert!(matches!(
            DecodeError::duplicate_key("k"),
            DecodeError::DuplicateKey(k) if k == "k"
        ));
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
        let e: Box<dyn core::error::Error> = Box::new(DecodeError::Expected("u32"));
        assert_eq!(e.to_string(), "expected u32");
        assert!(core::error::Error::source(&DecodeError::Expected("u32")).is_none());
        let source = DecodeError::Source(SourceError::new(core::fmt::Error));
        assert!(core::error::Error::source(&source).is_some());
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

    #[test]
    fn a_map_target_refuses_a_passthrough() {
        struct Clear;
        impl Encrypt for Clear {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = BTreeMap::new();
                map.insert("a", 1u16);
                sink.passthrough(map)
            }
        }
        assert_eq!(expected(round_trip::<HashMap<String, u16>>(Clear)), "map");
        assert_eq!(expected(round_trip::<BTreeMap<String, u16>>(Clear)), "map");
    }

    #[test]
    fn byte_targets_refuse_a_uuid_leaf() {
        let uuid = || Raw(Some(Logical::Uuid), Physical::Bytes(&[5; 16]));
        assert_eq!(expected(round_trip::<Vec<u8>>(uuid())), "bytes");
        assert_eq!(expected(round_trip::<[u8; 16]>(uuid())), "byte array");
        assert_eq!(
            expected(round_trip::<Protected<[u8; 16]>>(uuid())),
            "byte array"
        );
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_targets_refuse_the_other_logical_types() {
        use crate::plaintext::TimeUnit;
        use ::chrono::{DateTime, NaiveDate, Utc};
        let date = NaiveDate::from_ymd_opt(2024, 2, 29).expect("date");
        let ts = DateTime::from_timestamp(1_700_000_000, 0).expect("ts");
        assert_eq!(expected(round_trip::<DateTime<Utc>>(date)), "timestamp");
        assert_eq!(
            expected(round_trip::<DateTime<Utc>>(1_700_000_000i64)),
            "timestamp"
        );
        assert_eq!(expected(round_trip::<NaiveDate>(ts)), "date");

        let instant = DateTime::from_timestamp(2, 0).expect("timestamp");
        for (unit, count) in [
            (TimeUnit::Seconds, 2),
            (TimeUnit::Millis, 2_000),
            (TimeUnit::Micros, 2_000_000),
            (TimeUnit::Nanos, 2_000_000_000),
        ] {
            let raw = Raw(
                Some(Logical::Timestamp(unit)),
                Physical::Int(Int::I64(count)),
            );
            assert_eq!(round_trip::<DateTime<Utc>>(raw).expect("unit"), instant);
        }
    }

    #[test]
    fn a_wrong_aad_fails_before_the_target_is_checked() {
        let sealed = || encrypt(34u32, &Mock, "ctx").expect("encrypts");
        assert!(matches!(
            decrypt::<String, _, _>(&Mock, sealed(), "other"),
            Err(DecryptError::Cipher(_))
        ));
        assert!(matches!(
            decrypt::<Vec<u32>, _, _>(&Mock, sealed(), "other"),
            Err(DecryptError::Cipher(_))
        ));
        let remote = Remote::new(true);
        // With the right AAD the async path decrypts, so the next
        // assertion is about the AAD and nothing else.
        assert_eq!(
            block_on(decrypt_async::<u32, _, _>(&remote, sealed(), "ctx")).expect("decrypts"),
            34
        );
        assert!(matches!(
            block_on(decrypt_async::<String, _, _>(&remote, sealed(), "other")),
            Err(DecryptError::Cipher(_))
        ));
    }

    #[test]
    fn a_null_is_refused_where_no_option_is_expected() {
        assert_eq!(expected(round_trip::<u32>(None::<u32>)), "u32");
        assert_eq!(expected(round_trip::<String>(None::<String>)), "string");
        assert_eq!(
            expected(round_trip::<Vec<u32>>(None::<Vec<u32>>)),
            "sequence"
        );
        assert_eq!(
            expected(round_trip::<Vec<u32>>(vec![Some(1u32), None])),
            "u32"
        );
        assert_eq!(
            expected(round_trip::<u32>(Raw(
                Some(Logical::Undefined),
                Physical::Null
            ))),
            "u32"
        );
    }

    #[test]
    fn a_list_target_refuses_a_map() {
        let mut map = BTreeMap::new();
        map.insert("a", 1u32);
        assert_eq!(expected(round_trip::<Vec<u32>>(map)), "sequence");
    }

    #[test]
    fn number_targets_refuse_the_other_number_kinds() {
        assert_eq!(expected(round_trip::<u32>(true)), "u32");
        assert_eq!(expected(round_trip::<i64>(1.0f64)), "i64");
        assert_eq!(expected(round_trip::<i64>(1.0f32)), "i64");
        assert_eq!(expected(round_trip::<f64>(1i64)), "f64");
        assert_eq!(expected(round_trip::<f32>(1u32)), "f32");
    }

    #[test]
    fn integer_targets_accept_their_limits_and_nothing_past_them() {
        assert_eq!(round_trip::<i8>(i8::MIN).expect("i8"), i8::MIN);
        assert_eq!(round_trip::<i8>(127i32).expect("i8"), i8::MAX);
        assert_eq!(expected(round_trip::<i8>(-129i32)), "i8");
        assert_eq!(expected(round_trip::<i8>(128i32)), "i8");
        assert_eq!(round_trip::<u64>(u64::MAX).expect("u64"), u64::MAX);
        assert_eq!(expected(round_trip::<u64>(u128::from(u64::MAX) + 1)), "u64");
        assert_eq!(round_trip::<u128>(u128::MAX).expect("u128"), u128::MAX);
        assert_eq!(expected(round_trip::<u128>(-1i8)), "u128");
        assert_eq!(round_trip::<i128>(i128::MIN).expect("i128"), i128::MIN);
        assert_eq!(expected(round_trip::<i128>(u128::MAX)), "i128");
    }

    #[test]
    fn a_source_error_displays_its_message() {
        assert_eq!(
            DecodeError::Source(SourceError::msg("getter threw")).to_string(),
            "source failed: getter threw"
        );
        assert_eq!(DecodeError::Expected("u32").to_string(), "expected u32");
    }

    #[test]
    fn protected_containers_round_trip() {
        let ints = round_trip::<Protected<Vec<u32>>>(vec![1u32, 2, 3]).expect("decrypts");
        assert_eq!(ints.risky_ref(), &[1, 2, 3]);
        let some = round_trip::<Protected<Option<String>>>(Some("pw")).expect("decrypts");
        assert_eq!(some.risky_ref().as_deref(), Some("pw"));
        let none = round_trip::<Protected<Option<String>>>(None::<&str>).expect("decrypts");
        assert_eq!(none.risky_ref(), &None);
        let undefined =
            round_trip::<Protected<Option<u32>>>(Raw(Some(Logical::Undefined), Physical::Null))
                .expect("decrypts");
        assert_eq!(undefined.risky_ref(), &None);
        // Nested to any depth, containers inside options and the reverse.
        let nested = round_trip::<Protected<Vec<Vec<String>>>>(vec![vec!["a", "b"], vec![]])
            .expect("decrypts");
        assert_eq!(
            nested.risky_ref(),
            &[vec![String::from("a"), String::from("b")], vec![]]
        );
        let list = round_trip::<Protected<Option<Vec<u32>>>>(Some(vec![7u32])).expect("decrypts");
        assert_eq!(list.risky_ref(), &Some(vec![7]));
        let arrays = round_trip::<Protected<Vec<Option<[u8; 2]>>>>(vec![Some([1u8, 2]), None])
            .expect("decrypts");
        assert_eq!(arrays.risky_ref(), &[Some([1, 2]), None]);
        // `Vec<u8>` is still the byte leaf, not a sequence of `u8`.
        let bytes = round_trip::<Protected<Vec<u8>>>(vec![9u8, 8]).expect("decrypts");
        assert_eq!(bytes.risky_ref(), &[9, 8]);
    }

    #[test]
    fn protected_containers_refuse_what_their_bare_forms_refuse() {
        let mut map = BTreeMap::new();
        map.insert("a", 1u32);
        assert_eq!(expected(round_trip::<Protected<Vec<u32>>>(map)), "sequence");
        assert_eq!(
            expected(round_trip::<Protected<Vec<u32>>>(1u32)),
            "sequence"
        );
        assert_eq!(
            expected(round_trip::<Protected<Vec<u32>>>(vec!["x"])),
            "u32"
        );
        assert_eq!(expected(round_trip::<Protected<Option<u32>>>("x")), "u32");
        assert_eq!(
            expected(round_trip::<Protected<Option<Vec<u32>>>>(1u32)),
            "sequence"
        );
        struct Clear;
        impl Encrypt for Clear {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough(vec![1u32])
            }
        }
        assert_eq!(
            expected(round_trip::<Protected<Vec<u32>>>(Clear)),
            "sequence"
        );
        assert_eq!(expected(round_trip::<Protected<Option<u32>>>(Clear)), "u32");
        assert_eq!(expected(round_trip::<Protected<u32>>(Clear)), "u32");
        assert_eq!(expected(round_trip::<Protected<u32>>(vec![1u32])), "u32");
        let mut map = BTreeMap::new();
        map.insert("a", 1u32);
        assert_eq!(expected(round_trip::<Protected<u32>>(map)), "u32");
    }

    std::thread_local! {
        static WIPES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    /// A scalar target that counts its wipes.
    struct Wiped(u32);

    impl Zeroize for Wiped {
        fn zeroize(&mut self) {
            self.0 = 0;
            WIPES.with(|w| w.set(w.get() + 1));
        }
    }

    impl FromScalar for Wiped {
        const EXPECTED: &'static str = "wiped";
        fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
            u32::from_scalar(ty, v).map(Wiped)
        }
    }

    #[test]
    fn a_protected_list_that_fails_part_way_wipes_what_it_decoded() {
        let source = vec![
            Raw(None, Physical::Int(Int::U32(1))),
            Raw(None, Physical::Int(Int::U32(2))),
            Raw(None, Physical::Text("x")),
        ];
        WIPES.with(|w| w.set(0));
        let result = round_trip::<Protected<Vec<Wiped>>>(source);
        assert_eq!(expected(result), "wiped");
        assert_eq!(WIPES.with(|w| w.get()), 2);
    }

    /// A sequence that does not say how long it is.
    struct Unsized(u32);

    impl Encrypt for Unsized {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut seq = sink.seq(None)?;
            for i in 0..self.0 {
                i.visit(seq.element()?)?;
            }
            seq.end()
        }
    }

    #[test]
    fn a_protected_list_grows_by_doubling_into_a_fresh_buffer() {
        let decode = |n| {
            Unsized(n)
                .visit(<Protected<Vec<u32>> as Decrypt>::sink())
                .expect("decodes")
        };
        let five = decode(5);
        assert_eq!(five.risky_ref(), &[0, 1, 2, 3, 4]);
        assert_eq!(five.risky_ref().capacity(), 8);
        let nine = decode(9);
        assert_eq!(nine.risky_ref(), &(0..9).collect::<Vec<_>>());
        assert_eq!(nine.risky_ref().capacity(), 16);
    }

    /// A struct target written by hand, as `#[derive(Decrypt)]` will write
    /// one: a map with one field, opted into `Protected` through `Wrap`.
    #[derive(Debug, PartialEq)]
    struct Point {
        x: u32,
    }

    impl Zeroize for Point {
        fn zeroize(&mut self) {
            self.x.zeroize();
        }
    }

    struct PointSink;
    struct PointFields(Option<u32>);

    impl Sink for PointSink {
        type Ok = Point;
        type Error = DecodeError;
        type Seq = Never<Point>;
        type Map = PointFields;

        fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<Point, DecodeError> {
            Err(DecodeError::Expected("point"))
        }

        fn typed_null(self, _: FixedType) -> Result<Point, DecodeError> {
            Err(DecodeError::Expected("point"))
        }

        fn seq(self, _: Option<usize>) -> Result<Never<Point>, DecodeError> {
            Err(DecodeError::Expected("point"))
        }

        fn map(self, _: Option<usize>) -> Result<PointFields, DecodeError> {
            Ok(PointFields(None))
        }

        fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Point, DecodeError> {
            Err(DecodeError::Expected("point"))
        }
    }

    impl MapSink for PointFields {
        type Ok = Point;
        type Error = DecodeError;
        type Entry<'s> = Forward<u32, Slot<'s, u32>>;

        fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
            match key {
                "x" => Ok(Forward(u32::sink(), Slot(&mut self.0))),
                _ => Err(DecodeError::Expected("point")),
            }
        }

        fn end(self) -> Result<Point, DecodeError> {
            self.0
                .map(|x| Point { x })
                .ok_or(DecodeError::Expected("point"))
        }
    }

    impl Decrypt for Point {
        type Sink = PointSink;
        fn sink() -> PointSink {
            PointSink
        }
    }

    impl DecryptProtected for Point {
        type ProtectedSink = Wrap<PointSink>;
        fn protected_sink() -> Wrap<PointSink> {
            Wrap(PointSink)
        }
    }

    #[test]
    fn a_struct_target_opts_into_protected_through_wrap() {
        let point = || {
            let mut map = BTreeMap::new();
            map.insert("x", 3u32);
            map
        };
        let p = round_trip::<Protected<Point>>(point()).expect("decrypts");
        assert_eq!(p.risky_ref(), &Point { x: 3 });
        let some = round_trip::<Protected<Option<Point>>>(Some(point())).expect("decrypts");
        assert_eq!(some.risky_ref(), &Some(Point { x: 3 }));
        let list = round_trip::<Protected<Vec<Point>>>(vec![point()]).expect("decrypts");
        assert_eq!(list.risky_ref(), &[Point { x: 3 }]);
        assert_eq!(expected(round_trip::<Protected<Point>>(1u32)), "point");
        assert_eq!(
            expected(round_trip::<Protected<Point>>(vec![1u32])),
            "point"
        );
        let mut extra = point();
        extra.insert("y", 4u32);
        assert_eq!(expected(round_trip::<Protected<Point>>(extra)), "point");
    }

    #[test]
    fn wrap_moves_any_sink_result_into_protected() {
        let n = Wrap(u32::sink())
            .scalar(None, Physical::Int(Int::U32(5)))
            .expect("decodes");
        assert_eq!(n.risky_ref(), &5);
        assert!(matches!(
            Wrap(u32::sink()).passthrough(5u32),
            Err(DecodeError::Expected("u32"))
        ));
        let list = vec![1u32, 2]
            .visit(Wrap(<Vec<u32>>::sink()))
            .expect("decodes");
        assert_eq!(list.risky_ref(), &[1, 2]);
    }
}
