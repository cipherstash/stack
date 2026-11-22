//! What [`predicate!`](crate::predicate) expands to so that the compiler
//! checks a predicate against the paths its field declares. For generated
//! code only. [`document`] is what an expansion calls when the program
//! runs; everything else here is type-checked and never run.
//!
//! The macro sees the predicate's text and the field reference's
//! expression, never the field's declaration. So it names each path the
//! text uses as a type, [`Char`] by [`Char`], and asks for the derive's
//! lookup of that path. `#[derive(EncryptTarget)]` implements
//! [`PathLookup`] once for each path the field's `#[stash(json(..))]`
//! declares, under `ordered = {..}` or under `paths = {..}`, and
//! [`ArrayLookup`] and [`MemberLookup`] once for each array and member
//! under `ordered = {..}` alone, since an element condition compares by an
//! ordering term. Each lookup calls the accessor the derive generated. The
//! lookup is keyed by the path's text, not the accessor's name, so a
//! `names = {..}` override, which the macro cannot see, changes nothing
//! here.
//!
//! The macro's own trait, generated at each use, refuses a path the field
//! does not declare with a message that names it. The finders below then
//! fetch the accessor and the path's type when there is one, and
//! [`Unknown`], which takes anything, when there is not, so that one
//! mistake is reported once.
use std::marker::PhantomData;

pub use stack_encrypt_derive::predicate_with_crate;

use super::{
    ArrayElements, DocumentPaths, ElementArray, JsonFieldQuery, JsonScalarType, PathValue,
    Predicate,
};
use crate::field_reference::{FieldReference, Place, ScopeInput};
use crate::json::JsonQueries;

/// `reference.predicate(text)`, with the paths the field declares and the
/// field reference's type, for the checks. One call takes the field
/// reference, so a field that stores no document is refused once for it,
/// with [`JsonQueries`]'s message. (Each path is refused too: such a field
/// declares none.)
#[allow(clippy::type_complexity)]
pub fn document<W: Place, T: JsonQueries, C: ScopeInput, P, D>(
    reference: FieldReference<W, T, C, P, D>,
    text: &str,
) -> (
    JsonFieldQuery<T, Predicate, C::Start>,
    PhantomData<D>,
    PhantomData<FieldReference<W, T, C, P, D>>,
) {
    (reference.predicate(text), PhantomData, PhantomData)
}

/// One character of a path's text, as a type. A path is the tuple of its
/// characters, as `JsonPath`'s `Display` writes it: `$.age` is
/// `(Char<'$'>, Char<'.'>, Char<'a'>, Char<'g'>, Char<'e'>)`.
pub struct Char<const C: char>;

/// A path the field declares, keyed by its text: what `at()` gives for it.
/// Implemented by the derive on the field's paths type.
pub trait PathLookup<Key>: DocumentPaths {
    /// The type the path holds.
    type Value;
    /// What the path's accessor under `at()` returns.
    type Accessor<W, T, C, P>;
    /// The path's accessor under `at()`.
    fn path<W: Place, T: JsonQueries, C: ScopeInput, P>(
        reference: FieldReference<W, T, C, P, Self>,
    ) -> Self::Accessor<W, T, C, P>;
}

/// What an array's accessor under `elements()` returns: the array `A`'s
/// members, adding to the array's first condition.
pub type ArrayMembers<A, W, T, C, P> = <A as ElementArray>::Members<ArrayElements<W, T, C, P, A>>;

/// An array the field declares, keyed by its text (`$.visits[*]`): what
/// `elements()` gives for it. Implemented by the derive on the field's paths
/// type.
pub trait ArrayLookup<Key>: DocumentPaths {
    /// The array's type, whose methods are its members.
    type Array: ElementArray;
    /// The array's accessor under `elements()`.
    fn array<W: Place, T: JsonQueries, C: ScopeInput, P>(
        reference: FieldReference<W, T, C, P, Self>,
    ) -> ArrayMembers<Self::Array, W, T, C, P>;
}

/// A member of an array's elements, keyed by its text below the element,
/// written from `$` (`$.place`). Implemented by the derive on the array's
/// type.
pub trait MemberLookup<Key>: ElementArray {
    /// The type the member holds.
    type Value;
    /// What the member's accessor returns.
    type Accessor<Q>;
    /// The member's accessor, adding to the predicate `Q`.
    fn member<Q>(members: Self::Members<Q>) -> Self::Accessor<Q>;
}

/// What a finder gives for a path, an array or a member the field does not
/// declare: a type whose methods take anything, so that the code that uses
/// it compiles and the one refusal is the missing path's. No value of it
/// exists.
pub enum Unknown {}

macro_rules! takes_anything {
    ($($method:ident),+) => {
        impl Unknown {
            $(
                #[doc(hidden)]
                pub fn $method<X>(self, _: X) {}
            )+
        }
    };
}
takes_anything!(eq, lt, lte, gt, gte);

impl Unknown {
    #[doc(hidden)]
    pub fn is_null(self) {}
    #[doc(hidden)]
    pub fn selector(self) {}
}

/// A value `V` may be compared with: what a path of type `V` takes
/// ([`PathValue`]), or anything at all for an [`Unknown`] path.
pub trait ValueFits<V> {}
impl<V: JsonScalarType, X: PathValue<V>> ValueFits<V> for X {}
impl<X> ValueFits<Unknown> for X {}

/// A number literal that is an integer of zero or more, named by the
/// narrowest of the integer types that holds it: `UpTo<u8>` is 128 to 255.
pub struct UpTo<N>(PhantomData<N>);
/// A number literal that is an integer below zero, named by the narrowest
/// of the signed types that holds it: `DownTo<i16>` is -32768 to -129.
pub struct DownTo<N>(PhantomData<N>);
/// A number literal with a fraction or an exponent.
pub enum Fraction {}

/// A type the number literal `L` fits: an integer type that holds the
/// literal, `f64` for any number, and [`Unknown`]. The macro names `L`
/// from the literal's text, so `$.age > 1.5`, `$.age >= -1` and
/// `$.age == 99999999999` are refused for a `u32`, as the typed accessor
/// refuses those values.
pub trait NumberFits<L> {}
/// A type a string literal fits: `String`, and [`Unknown`].
pub trait StringFits {}
/// A type `true` or `false` fits: `bool`, which a path under `paths` can
/// hold, and [`Unknown`].
pub trait BooleanFits {}

macro_rules! number_fits {
    ($($literal:ty => $($ty:ty),+;)+) => {
        $($(impl NumberFits<$literal> for $ty {})+)+
    };
}
number_fits! {
    UpTo<i8> => i8, u8, i16, u16, i32, u32, i64, u64, f64;
    UpTo<u8> => u8, i16, u16, i32, u32, i64, u64, f64;
    UpTo<i16> => i16, u16, i32, u32, i64, u64, f64;
    UpTo<u16> => u16, i32, u32, i64, u64, f64;
    UpTo<i32> => i32, u32, i64, u64, f64;
    UpTo<u32> => u32, i64, u64, f64;
    UpTo<i64> => i64, u64, f64;
    UpTo<u64> => u64, f64;
    DownTo<i8> => i8, i16, i32, i64, f64;
    DownTo<i16> => i16, i32, i64, f64;
    DownTo<i32> => i32, i64, f64;
    DownTo<i64> => i64, f64;
    Fraction => f64;
}
impl<L> NumberFits<L> for Unknown {}
impl StringFits for String {}
impl StringFits for Unknown {}
impl BooleanFits for bool {}
impl BooleanFits for Unknown {}

/// A value of the type `V`, for code that is type-checked and never run.
pub fn placeholder_of<V>(_: PhantomData<V>) -> V {
    unreachable!("predicate! checks types and never runs this")
}

/// Finds the path keyed `K` among the paths `D`.
pub struct PathFind<D, K>(PhantomData<fn() -> (D, K)>);

impl<D, K> PathFind<D, K> {
    /// The finder for the paths `D`.
    pub fn new(_: PhantomData<D>) -> Self {
        Self(PhantomData)
    }
}

/// The path, when the field declares it.
pub trait FoundPath<D> {
    /// The type the path holds.
    type Value;
    /// What the path's accessor returns.
    type Accessor<W, T, C, P>;
    /// The type the path holds.
    fn value(&self) -> PhantomData<Self::Value>;
    /// The path's accessor.
    fn accessor<W: Place, T: JsonQueries, C: ScopeInput, P>(
        &self,
        reference: FieldReference<W, T, C, P, D>,
    ) -> Self::Accessor<W, T, C, P>;
}

impl<D: PathLookup<K>, K> FoundPath<D> for PathFind<D, K> {
    type Value = D::Value;
    type Accessor<W, T, C, P> = D::Accessor<W, T, C, P>;
    fn value(&self) -> PhantomData<D::Value> {
        PhantomData
    }
    fn accessor<W: Place, T: JsonQueries, C: ScopeInput, P>(
        &self,
        reference: FieldReference<W, T, C, P, D>,
    ) -> D::Accessor<W, T, C, P> {
        D::path(reference)
    }
}

/// The path, when the field does not declare it: [`Unknown`]. Found only
/// when [`FoundPath`] is not.
pub trait MissingPath {
    /// [`Unknown`].
    fn value(&self) -> PhantomData<Unknown> {
        PhantomData
    }
    /// [`Unknown`].
    fn accessor<R>(&self, _: R) -> Unknown {
        unreachable!("predicate! checks types and never runs this")
    }
}

impl<D, K> MissingPath for &PathFind<D, K> {}

/// Finds the array keyed `K` among the paths `D`.
pub struct ArrayFind<D, K>(PhantomData<fn() -> (D, K)>);

impl<D, K> ArrayFind<D, K> {
    /// The finder for the paths `D`.
    pub fn new(_: PhantomData<D>) -> Self {
        Self(PhantomData)
    }
}

/// The array, when the field declares it.
pub trait FoundArray<D> {
    /// The array's type.
    type Array;
    /// What the array's accessor returns.
    type Members<W, T, C, P>;
    /// The array's type.
    fn array(&self) -> PhantomData<Self::Array>;
    /// The array's accessor.
    fn members<W: Place, T: JsonQueries, C: ScopeInput, P>(
        &self,
        reference: FieldReference<W, T, C, P, D>,
    ) -> Self::Members<W, T, C, P>;
}

impl<D: ArrayLookup<K>, K> FoundArray<D> for ArrayFind<D, K> {
    type Array = D::Array;
    type Members<W, T, C, P> = ArrayMembers<D::Array, W, T, C, P>;
    fn array(&self) -> PhantomData<D::Array> {
        PhantomData
    }
    fn members<W: Place, T: JsonQueries, C: ScopeInput, P>(
        &self,
        reference: FieldReference<W, T, C, P, D>,
    ) -> Self::Members<W, T, C, P> {
        D::array(reference)
    }
}

/// The array, when the field does not declare it: [`Unknown`]. Found only
/// when [`FoundArray`] is not.
pub trait MissingArray {
    /// [`Unknown`].
    fn array(&self) -> PhantomData<Unknown> {
        PhantomData
    }
    /// [`Unknown`].
    fn members<R>(&self, _: R) -> Unknown {
        unreachable!("predicate! checks types and never runs this")
    }
}

impl<D, K> MissingArray for &ArrayFind<D, K> {}

/// Finds the member keyed `K` of the array `A`.
pub struct MemberFind<A, K>(PhantomData<fn() -> (A, K)>);

impl<A, K> MemberFind<A, K> {
    /// The finder for the array `A`.
    pub fn new(_: PhantomData<A>) -> Self {
        Self(PhantomData)
    }
}

/// The member, when the array has it.
pub trait FoundMember<A: ElementArray> {
    /// The type the member holds.
    type Value;
    /// What the member's accessor returns.
    type Accessor<Q>;
    /// The type the member holds.
    fn value(&self) -> PhantomData<Self::Value>;
    /// The member's accessor.
    fn accessor<Q>(&self, members: A::Members<Q>) -> Self::Accessor<Q>;
}

impl<A: MemberLookup<K>, K> FoundMember<A> for MemberFind<A, K> {
    type Value = A::Value;
    type Accessor<Q> = A::Accessor<Q>;
    fn value(&self) -> PhantomData<A::Value> {
        PhantomData
    }
    fn accessor<Q>(&self, members: A::Members<Q>) -> A::Accessor<Q> {
        A::member(members)
    }
}

/// The member, when the array does not have it, or is not declared:
/// [`Unknown`]. Found only when [`FoundMember`] is not.
pub trait MissingMember {
    /// [`Unknown`].
    fn value(&self) -> PhantomData<Unknown> {
        PhantomData
    }
    /// [`Unknown`].
    fn accessor<R>(&self, _: R) -> Unknown {
        unreachable!("predicate! checks types and never runs this")
    }
}

impl<A, K> MissingMember for &MemberFind<A, K> {}
