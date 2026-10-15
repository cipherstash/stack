//! Physical kinds and logical types.
//!
//! A scalar is a [`Physical`] value, optionally annotated with the
//! [`Logical`] type it represents. The split is Arrow's and Parquet's:
//!
//! - **Physical kinds are a small closed set**: null, bool, int, float, text,
//!   bytes. `Physical` is an exhaustive enum, so adding one is a breaking
//!   change that fails to compile in every sink. That is deliberate: a new
//!   physical kind changes what every consumer has to handle.
//! - **Logical types are open.** A timestamp is an int with a unit, a date
//!   is an int, a uuid is sixteen bytes. `Logical` is `#[non_exhaustive]`,
//!   so a sink outside this crate has to say what it does with a logical
//!   type it does not know. Structural sinks (encryption, frames, host
//!   builders) carry the annotation through. Index sinks refuse it.
//!
//! The int's width ([`Int`]'s variant) is a host-fidelity hint, not a kind:
//! every width shares one equality domain, and only the leaf, the frame and
//! the host builders look at it.
//!
//! The validity rules here ([`Logical::admits`]) are self-contained, so the
//! core model has no dependency on chrono or `rust_decimal`. The conversions
//! to and from those crates' types sit behind their features.
//!
//! # Adding a logical type
//!
//! A logical type is a meaning layered on a physical kind that already
//! exists. Never add a physical kind for one. The steps, in this module
//! unless said otherwise:
//!
//! 1. **Choose the physical kind** it rides on (an int, sixteen bytes, a
//!    string) and its parameter, if it has one. The parameter is a single
//!    byte carried with every value, like a decimal's scale. A type that
//!    needs more than a byte needs a different design; the `0xF4` tag is
//!    reserved for a length-prefixed envelope for that day.
//! 2. **Add the variant** to [`Logical`] and a constant to [`id`], the next
//!    value after [`id::LAST_KNOWN`], then move `LAST_KNOWN` up to it. Ids
//!    are a cross-language commitment: never renumber or reuse one.
//! 3. **Name it without its parameter**: add the matching variant to
//!    [`KnownLogical`], with its id and the one kind it is stored as in
//!    [`KnownLogical::id`], [`KnownLogical::kind`] and
//!    [`KnownLogical::from_id`]. This is what a schema binds for a column
//!    (see [`LeafTypeAad`](crate::LeafTypeAad)), so the kind is part of the
//!    cross-language commitment too.
//! 4. **Map it on the wire** in [`Logical::to_wire`] and
//!    [`Logical::from_wire`]. `from_wire` must return `None` for a
//!    parameter the type cannot take, so a malformed envelope is refused
//!    rather than read as some other value.
//! 5. **State its validity rule** in [`Logical::admits`]: which physical
//!    kind it accepts, and the range. Keep the rule self-contained, as the
//!    date and timestamp ranges are (constants pinned by a test, not a
//!    dependency), so the core model stays dependency-free.
//! 6. **Name it** in the `Display` impl.
//! 7. **Add a source**: a `Plaintext` impl for the Rust type that calls
//!    `sink.scalar(Some(Logical::YourType), Physical::...)`. If the type
//!    comes from another crate, put the impl behind a feature named after
//!    that crate, as the chrono, `rust_decimal` and uuid sources are.
//! 8. **Extend the tests here**: the variant goes into
//!    `every_known_logical_type_round_trips_through_the_wire`, its pairing
//!    with the [`KnownLogical`] variant into the `known` helper, a parameter
//!    it refuses into `a_known_id_with_a_bad_parameter_is_refused`, and its
//!    range edges into `admits_checks_the_range`.
//!
//! Outside this module, each consumer that interprets logical types opts
//! in on its own: a typed decode target for the Rust type, an equality
//! domain and normalization in the index layer, and a conversion in each
//! host binding. Structural sinks need nothing. Encryption, the frame and
//! the leaf codec carry any logical type through the generic envelope, so
//! a new type gets no tag of its own, and a sink built before the type
//! existed still passes it through as [`Logical::Unknown`].
//!
//! The compiler finds most of a missed step: `to_wire`, `Display` and the
//! tests' `known` helper match exhaustively, so a new variant fails to
//! build until they are updated, and `KnownLogical::id` and
//! `KnownLogical::kind` do the same for a new `KnownLogical` variant.
//! `from_wire`, `KnownLogical::from_id` and `admits` have fallbacks, so a
//! type missed there is refused rather than reported; the round-trip tests
//! are what catch it.

use core::fmt;

use vitaminc_protected::{Choice, OpaqueDebug, TimingSafeEq};
use zeroize::Zeroize;

/// One scalar value, as stored. Borrowed, so a source can hand over text
/// and bytes without copying.
///
/// A scalar is plaintext, so `Debug` redacts the value and `==` compares
/// in constant time (see [`TimingSafeEq`]). Equality is structural: an
/// int's width and a float's bit pattern both count. It is for tests and
/// sinks that compare what a source said, not for comparing values across
/// widths (see [`Int::sign_and_word`]).
///
/// `Physical` is a view: the text and bytes it borrows are owned, and
/// wiped, by the source. It therefore does not implement `Zeroize`
/// itself; [`Int`] and [`Float`], which are owned, do.
#[derive(Clone, Copy, OpaqueDebug, TimingSafeEq)]
pub enum Physical<'a> {
    Null,
    Bool(bool),
    Int(Int),
    Float(Float),
    Text(&'a str),
    Bytes(&'a [u8]),
}

/// A physical kind, named without a value: what a schema expects a column
/// to hold. Closed, like [`Physical`], and with a wire byte of its own for
/// the places a kind is bound rather than carried, such as
/// [`LeafTypeAad`](crate::LeafTypeAad).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Null,
    Bool,
    Int,
    Float,
    Text,
    Bytes,
}

impl Kind {
    /// The kind's wire byte. A cross-language commitment: never renumber.
    pub const fn to_wire(self) -> u8 {
        match self {
            Kind::Null => 0,
            Kind::Bool => 1,
            Kind::Int => 2,
            Kind::Float => 3,
            Kind::Text => 4,
            Kind::Bytes => 5,
        }
    }
}

impl Physical<'_> {
    /// The kind of this value.
    pub fn kind(&self) -> Kind {
        match self {
            Physical::Null => Kind::Null,
            Physical::Bool(_) => Kind::Bool,
            Physical::Int(_) => Kind::Int,
            Physical::Float(_) => Kind::Float,
            Physical::Text(_) => Kind::Text,
            Physical::Bytes(_) => Kind::Bytes,
        }
    }
}

/// An integer, with the width it came from.
///
/// `==` compares the width as well as the value, so `I8(34) != U64(34)`.
/// Code that compares values across widths goes through [`to_i128`],
/// [`to_u128`] or [`sign_and_word`].
///
/// [`to_i128`]: Int::to_i128
/// [`to_u128`]: Int::to_u128
/// [`sign_and_word`]: Int::sign_and_word
#[derive(Clone, Copy, OpaqueDebug, Eq, Zeroize)]
pub enum Int {
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}

impl Int {
    /// The value as an `i128`, unless it is a `u128` above `i128::MAX`.
    pub fn to_i128(self) -> Option<i128> {
        match self {
            Int::I8(v) => Some(v.into()),
            Int::I16(v) => Some(v.into()),
            Int::I32(v) => Some(v.into()),
            Int::I64(v) => Some(v.into()),
            Int::I128(v) => Some(v),
            Int::U8(v) => Some(v.into()),
            Int::U16(v) => Some(v.into()),
            Int::U32(v) => Some(v.into()),
            Int::U64(v) => Some(v.into()),
            Int::U128(v) => i128::try_from(v).ok(),
        }
    }

    /// The value as a `u128`, unless it is negative.
    pub fn to_u128(self) -> Option<u128> {
        match self {
            Int::U128(v) => Some(v),
            other => other.to_i128().and_then(|v| u128::try_from(v).ok()),
        }
    }

    /// The value as a sign and a two's-complement 128-bit word: one layout
    /// covering `i128::MIN` to `u128::MAX`, for equality encodings.
    pub fn sign_and_word(self) -> (bool, u128) {
        let (sign, word) = self.sign_bit_and_word();
        (sign == 1, word)
    }

    /// [`sign_and_word`](Int::sign_and_word) with the sign as a bit, for
    /// constant-time equality.
    ///
    /// Only the width is branched on. The word is the value sign-extended
    /// (or zero-extended) to 128 bits, and a signed value's sign is that
    /// word's top bit, taken by shift rather than by comparing the value
    /// with zero, so no branch depends on the value. This also covers a
    /// `u128` above `i128::MAX` without a second path.
    fn sign_bit_and_word(self) -> (u8, u128) {
        let (word, signed) = match self {
            Int::I8(v) => (i128::from(v) as u128, 1),
            Int::I16(v) => (i128::from(v) as u128, 1),
            Int::I32(v) => (i128::from(v) as u128, 1),
            Int::I64(v) => (i128::from(v) as u128, 1),
            Int::I128(v) => (v as u128, 1),
            Int::U8(v) => (u128::from(v), 0),
            Int::U16(v) => (u128::from(v), 0),
            Int::U32(v) => (u128::from(v), 0),
            Int::U64(v) => (u128::from(v), 0),
            Int::U128(v) => (v, 0),
        };
        (((word >> 127) as u8) & signed, word)
    }
}

macro_rules! int_from {
    ($($ty:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$ty> for Int {
                fn from(v: $ty) -> Self {
                    Int::$variant(v)
                }
            }
        )*
    };
}

int_from! {
    i8 => I8, i16 => I16, i32 => I32, i64 => I64, i128 => I128,
    u8 => U8, u16 => U16, u32 => U32, u64 => U64, u128 => U128,
}

/// A float, with the width it came from. Compared and carried by bit
/// pattern, so `NaN` payloads and `-0.0` survive, and `-0.0 != 0.0`.
#[derive(Clone, Copy, OpaqueDebug, TimingSafeEq, Zeroize)]
pub enum Float {
    F32(f32),
    F64(f64),
}

// `Physical` and `Float` derive their constant-time equality: the derive
// compares same-variant payloads with `ts_eq` and treats different
// variants as unequal, which is the structural equality wanted here. The
// float impls in `vitaminc_protected` compare by bit pattern.
//
// `Int` is written by hand so its equality is one comparison over the
// sign and the 128-bit word rather than a ten-arm match. The width (the
// variant) is a host-fidelity hint, not a secret, so it may be compared
// by branch; the sign and the word are derived without branching on the
// value (see `Int::sign_bit_and_word`).

impl TimingSafeEq for Int {
    fn ts_eq(&self, other: &Self) -> Choice {
        let (sign_a, word_a) = self.sign_bit_and_word();
        let (sign_b, word_b) = other.sign_bit_and_word();
        let same_width = core::mem::discriminant(self) == core::mem::discriminant(other);
        Choice::from(u8::from(same_width)) & sign_a.ts_eq(&sign_b) & word_a.ts_eq(&word_b)
    }
}

impl PartialEq for Int {
    fn eq(&self, other: &Self) -> bool {
        self.ts_eq(other).into()
    }
}

/// What a physical value means. Carried per value, so a parameter such as
/// a decimal's scale can differ from one value to the next.
///
/// Each variant says which physical kind it rides on. A value that does not
/// fit is refused by [`admits`](Logical::admits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Logical {
    /// JavaScript's `undefined`. Over null.
    Undefined,
    /// Days since 1970-01-01, within chrono's date range. Over int.
    Date,
    /// A count of `TimeUnit`s since the Unix epoch, UTC, with no leap
    /// seconds, within chrono's range. Over int.
    ///
    /// chrono's range (years -262143 to 262142) is narrower than a
    /// JavaScript `Date`'s (about ±275,000 years). It stays the bound
    /// because today's `TIMESTAMP` decoder is chrono-bound, so a wider
    /// timestamp could be sealed but not read back there. A host refuses
    /// a `Date` outside it.
    Timestamp(TimeUnit),
    /// `int × 10^-scale`, scale at most 28 and `|int| < 2^96`. Over int.
    Decimal { scale: u8 },
    /// Sixteen bytes. Over bytes.
    Uuid,
    /// A logical type this build does not know. Structural sinks carry it
    /// through unchanged; index sinks refuse it.
    Unknown(UnknownLogical),
}

/// The unit of a [`Logical::Timestamp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeUnit {
    Seconds,
    Millis,
    Micros,
    Nanos,
}

impl TimeUnit {
    /// Nanoseconds per unit.
    pub fn nanos(self) -> i128 {
        match self {
            TimeUnit::Seconds => 1_000_000_000,
            TimeUnit::Millis => 1_000_000,
            TimeUnit::Micros => 1_000,
            TimeUnit::Nanos => 1,
        }
    }

    fn from_wire(param: u8) -> Option<Self> {
        [
            TimeUnit::Seconds,
            TimeUnit::Millis,
            TimeUnit::Micros,
            TimeUnit::Nanos,
        ]
        .get(usize::from(param))
        .copied()
    }
}

/// An id and parameter from the wire that this build has no meaning for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownLogical {
    id: u8,
    param: u8,
}

impl UnknownLogical {
    pub fn id(self) -> u8 {
        self.id
    }

    pub fn param(self) -> u8 {
        self.param
    }
}

/// The largest decimal scale `rust_decimal` represents.
pub const MAX_DECIMAL_SCALE: u8 = 28;

/// Decimal mantissas are 96-bit: `|mantissa| < 2^96`.
const DECIMAL_MANTISSA_LIMIT: i128 = 1 << 96;

/// chrono's `NaiveDate::MIN` (year -262143) and `NaiveDate::MAX` (year
/// 262142) as days since 1970-01-01. Pinned against chrono in a test.
pub const MIN_DATE_DAYS: i32 = -96_465_292;
pub const MAX_DATE_DAYS: i32 = 95_026_236;

/// chrono's `NaiveDateTime::MIN` and `NaiveDateTime::MAX` as nanoseconds
/// since the Unix epoch. Pinned against chrono in a test.
pub const MIN_TIMESTAMP_NANOS: i128 = MIN_DATE_DAYS as i128 * NANOS_PER_DAY;
pub const MAX_TIMESTAMP_NANOS: i128 = (MAX_DATE_DAYS as i128 + 1) * NANOS_PER_DAY - 1;

const NANOS_PER_DAY: i128 = 86_400 * 1_000_000_000;

/// The wire ids of the logical types. These are the cross-language
/// commitment for the logical envelope and must never change; a new type
/// takes the next free id.
pub mod id {
    /// No logical type.
    pub const NONE: u8 = 0;
    pub const UNDEFINED: u8 = 1;
    pub const DATE: u8 = 2;
    pub const TIMESTAMP: u8 = 3;
    pub const DECIMAL: u8 = 4;
    pub const UUID: u8 = 5;
    /// The highest id this build knows. Any id above it is
    /// [`Logical::Unknown`](super::Logical::Unknown).
    pub const LAST_KNOWN: u8 = UUID;
}

/// A logical type this build knows, named without its parameter: what a
/// schema says a column holds. A [`Logical`] says "a decimal of scale 2"
/// about one value; a `KnownLogical` says "decimals" about a column, whose
/// values may each have a scale of their own.
///
/// Each one is stored as exactly one [`Kind`], named by
/// [`kind`](KnownLogical::kind), so
/// [`LeafTypeAad::logical`](crate::LeafTypeAad::logical) derives the kind
/// from it and a column with a logical type has one binding. A logical
/// type this build does not know is an [`UnknownLogicalId`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownLogical {
    /// [`Logical::Undefined`]. Over null.
    Undefined,
    /// [`Logical::Date`]. Over int.
    Date,
    /// [`Logical::Timestamp`], of any unit. Over int.
    Timestamp,
    /// [`Logical::Decimal`], of any scale. Over int.
    Decimal,
    /// [`Logical::Uuid`]. Over bytes.
    Uuid,
}

impl KnownLogical {
    /// The logical type's wire id, one of the constants in [`id`].
    pub const fn id(self) -> u8 {
        match self {
            KnownLogical::Undefined => id::UNDEFINED,
            KnownLogical::Date => id::DATE,
            KnownLogical::Timestamp => id::TIMESTAMP,
            KnownLogical::Decimal => id::DECIMAL,
            KnownLogical::Uuid => id::UUID,
        }
    }

    /// The physical kind the logical type is stored as, the one kind
    /// [`Logical::admits`] accepts it over. A cross-language commitment,
    /// since a schema binds it: never change one.
    pub const fn kind(self) -> Kind {
        match self {
            KnownLogical::Undefined => Kind::Null,
            KnownLogical::Date | KnownLogical::Timestamp | KnownLogical::Decimal => Kind::Int,
            KnownLogical::Uuid => Kind::Bytes,
        }
    }

    /// The known logical type with wire id `id`, or `None` for
    /// [`id::NONE`] and for an id above [`id::LAST_KNOWN`]. For a schema
    /// that stores a column's logical type as its id.
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            id::UNDEFINED => Some(KnownLogical::Undefined),
            id::DATE => Some(KnownLogical::Date),
            id::TIMESTAMP => Some(KnownLogical::Timestamp),
            id::DECIMAL => Some(KnownLogical::Decimal),
            id::UUID => Some(KnownLogical::Uuid),
            _ => None,
        }
    }
}

/// A logical id above [`id::LAST_KNOWN`]: a logical type from a newer
/// build, which this one has no meaning for and so cannot say what kind it
/// is stored as. See [`LeafTypeAad::unknown`](crate::LeafTypeAad::unknown).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownLogicalId(u8);

impl UnknownLogicalId {
    /// `id` as an unknown logical id, or `None` for [`id::NONE`] and for an
    /// id this build knows, which is a [`KnownLogical`].
    pub const fn new(id: u8) -> Option<Self> {
        if id > id::LAST_KNOWN {
            Some(Self(id))
        } else {
            None
        }
    }

    /// The wire id.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Logical {
    /// The wire id and parameter, for the generic logical envelope.
    pub fn to_wire(self) -> (u8, u8) {
        match self {
            Logical::Undefined => (id::UNDEFINED, 0),
            Logical::Date => (id::DATE, 0),
            Logical::Timestamp(unit) => (id::TIMESTAMP, unit as u8),
            Logical::Decimal { scale } => (id::DECIMAL, scale),
            Logical::Uuid => (id::UUID, 0),
            Logical::Unknown(u) => (u.id, u.param),
        }
    }

    /// The logical type for a wire id and parameter. `None` for
    /// [`id::NONE`], which means "no logical type", and for a known id with
    /// a parameter it cannot take.
    pub fn from_wire(id: u8, param: u8) -> Option<Self> {
        match (id, param) {
            (id::NONE, _) => None,
            (id::UNDEFINED, 0) => Some(Logical::Undefined),
            (id::DATE, 0) => Some(Logical::Date),
            (id::TIMESTAMP, p) => TimeUnit::from_wire(p).map(Logical::Timestamp),
            (id::DECIMAL, scale) => {
                (scale <= MAX_DECIMAL_SCALE).then_some(Logical::Decimal { scale })
            }
            (id::UUID, 0) => Some(Logical::Uuid),
            (id::UNDEFINED..=id::LAST_KNOWN, _) => None,
            (id, param) => Some(Logical::Unknown(UnknownLogical { id, param })),
        }
    }

    /// Whether `v` is a valid value of this logical type: the right physical
    /// kind, and in range.
    pub fn admits(self, v: &Physical<'_>) -> bool {
        match (self, *v) {
            (Logical::Undefined, Physical::Null) => true,
            (Logical::Date, Physical::Int(i)) => date_in_range(i),
            (Logical::Timestamp(unit), Physical::Int(i)) => timestamp_nanos(unit, i).is_some(),
            (Logical::Decimal { scale }, Physical::Int(i)) => decimal_in_range(scale, i),
            (Logical::Uuid, Physical::Bytes(b)) => b.len() == 16,
            (Logical::Unknown(_), _) => true,
            _ => false,
        }
    }
}

fn date_in_range(days: Int) -> bool {
    days.to_i128()
        .and_then(|d| i32::try_from(d).ok())
        .is_some_and(|d| (MIN_DATE_DAYS..=MAX_DATE_DAYS).contains(&d))
}

/// A timestamp's count of `unit`s as nanoseconds since the epoch, if it is
/// in range.
pub fn timestamp_nanos(unit: TimeUnit, count: Int) -> Option<i128> {
    let nanos = count.to_i128()?.checked_mul(unit.nanos())?;
    (MIN_TIMESTAMP_NANOS..=MAX_TIMESTAMP_NANOS)
        .contains(&nanos)
        .then_some(nanos)
}

fn decimal_in_range(scale: u8, mantissa: Int) -> bool {
    scale <= MAX_DECIMAL_SCALE
        && mantissa
            .to_i128()
            .is_some_and(|m| m > -DECIMAL_MANTISSA_LIMIT && m < DECIMAL_MANTISSA_LIMIT)
}

/// Conversions between the chrono types and the ints they are stored as.
#[cfg(feature = "chrono")]
pub mod chrono {
    use super::{Int, TimeUnit};
    use ::chrono::{DateTime, Datelike, NaiveDate, Utc};

    const EPOCH_DAYS_FROM_CE: i32 = 719_163;

    /// The date for a day count, if it is one chrono can represent.
    pub fn date(days: Int) -> Option<NaiveDate> {
        let days = i32::try_from(days.to_i128()?).ok()?;
        NaiveDate::from_num_days_from_ce_opt(days.checked_add(EPOCH_DAYS_FROM_CE)?)
    }

    /// A date's day count since 1970-01-01.
    pub fn date_days(date: NaiveDate) -> i32 {
        date.num_days_from_ce() - EPOCH_DAYS_FROM_CE
    }

    /// The instant for a count of `unit`s, if it is one chrono can
    /// represent.
    pub fn timestamp(unit: TimeUnit, count: Int) -> Option<DateTime<Utc>> {
        let nanos = super::timestamp_nanos(unit, count)?;
        let seconds = i64::try_from(nanos.div_euclid(1_000_000_000)).ok()?;
        DateTime::from_timestamp(seconds, nanos.rem_euclid(1_000_000_000) as u32)
    }

    /// An instant as nanoseconds since the epoch. `None` for a leap second,
    /// which has no count.
    pub fn timestamp_nanos(ts: DateTime<Utc>) -> Option<i128> {
        let sub = ts.timestamp_subsec_nanos();
        (sub < 1_000_000_000).then(|| i128::from(ts.timestamp()) * 1_000_000_000 + i128::from(sub))
    }

    /// Reduce a nanosecond count to `unit`, if it is exact.
    pub fn timestamp_count(unit: TimeUnit, nanos: i128) -> Option<i128> {
        (nanos % unit.nanos() == 0).then(|| nanos / unit.nanos())
    }

    #[cfg(test)]
    mod tests {
        use super::super::{
            MAX_DATE_DAYS, MAX_TIMESTAMP_NANOS, MIN_DATE_DAYS, MIN_TIMESTAMP_NANOS,
        };
        use super::*;

        #[test]
        fn range_constants_match_chrono() {
            assert_eq!(date_days(NaiveDate::MIN), MIN_DATE_DAYS);
            assert_eq!(date_days(NaiveDate::MAX), MAX_DATE_DAYS);
            assert_eq!(
                timestamp_nanos(::chrono::NaiveDateTime::MIN.and_utc()),
                Some(MIN_TIMESTAMP_NANOS)
            );
            assert_eq!(
                timestamp_nanos(::chrono::NaiveDateTime::MAX.and_utc()),
                Some(MAX_TIMESTAMP_NANOS)
            );
            assert_eq!(
                date_days(NaiveDate::from_ymd_opt(1970, 1, 1).expect("date")),
                0
            );
            assert_eq!(date(Int::I32(0)), NaiveDate::from_ymd_opt(1970, 1, 1));
        }

        #[test]
        fn out_of_range_counts_have_no_chrono_value() {
            assert!(date(Int::I32(MIN_DATE_DAYS - 1)).is_none());
            assert!(date(Int::I32(MAX_DATE_DAYS + 1)).is_none());
            assert!(date(Int::I64(i64::MAX)).is_none());
            assert!(timestamp(TimeUnit::Nanos, Int::I128(MAX_TIMESTAMP_NANOS + 1)).is_none());
            assert!(timestamp(TimeUnit::Seconds, Int::I64(i64::MAX)).is_none());
            assert!(timestamp(TimeUnit::Nanos, Int::I128(MAX_TIMESTAMP_NANOS)).is_some());
        }

        #[test]
        fn leap_second_has_no_count() {
            let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
                .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 1_500_000_000))
                .expect("leap second")
                .and_utc();
            assert!(timestamp_nanos(leap).is_none());

            let first_leap_nano = NaiveDate::from_ymd_opt(2016, 12, 31)
                .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 1_000_000_000))
                .expect("leap second")
                .and_utc();
            assert!(timestamp_nanos(first_leap_nano).is_none());

            let last_ordinary_nano = NaiveDate::from_ymd_opt(2016, 12, 31)
                .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 999_999_999))
                .expect("instant")
                .and_utc();
            assert_eq!(
                timestamp_nanos(last_ordinary_nano),
                Some(1_483_228_799_999_999_999)
            );
        }

        #[test]
        fn a_count_before_the_epoch_is_the_right_instant() {
            let one_ns_before = timestamp(TimeUnit::Nanos, Int::I128(-1)).expect("instant");
            assert_eq!(
                one_ns_before,
                DateTime::from_timestamp(-1, 999_999_999).expect("instant")
            );
            assert_eq!(timestamp_nanos(one_ns_before), Some(-1));

            let ms = timestamp(TimeUnit::Millis, Int::I64(-1_500)).expect("instant");
            assert_eq!(
                ms,
                DateTime::from_timestamp(-2, 500_000_000).expect("instant")
            );
            assert_eq!(timestamp_nanos(ms), Some(-1_500_000_000));
        }

        #[test]
        fn a_count_is_reduced_only_when_exact() {
            assert_eq!(timestamp_count(TimeUnit::Nanos, 7), Some(7));
            assert_eq!(timestamp_count(TimeUnit::Millis, 3_000_000), Some(3));
            assert_eq!(timestamp_count(TimeUnit::Millis, -3_000_000), Some(-3));
            assert_eq!(timestamp_count(TimeUnit::Seconds, 2_000_000_000), Some(2));
            assert_eq!(timestamp_count(TimeUnit::Millis, 3_000_001), None);
            assert_eq!(timestamp_count(TimeUnit::Seconds, 1_500_000_000), None);
        }
    }
}

/// Conversions between `rust_decimal::Decimal` and its scale and mantissa.
#[cfg(feature = "rust_decimal")]
pub mod decimal {
    use super::Int;
    use rust_decimal::Decimal;

    /// The decimal for a scale and mantissa, if `rust_decimal` can hold it.
    pub fn decimal(scale: u8, mantissa: Int) -> Option<Decimal> {
        Decimal::try_from_i128_with_scale(mantissa.to_i128()?, scale.into()).ok()
    }

    /// A decimal's scale and mantissa. A negative zero comes out as zero,
    /// with its scale kept.
    pub fn parts(d: Decimal) -> (u8, i128) {
        (d.scale() as u8, d.mantissa())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use core::str::FromStr;

        #[test]
        fn negative_zero_normalizes_to_zero_with_its_scale() {
            let mut neg = Decimal::new(0, 2);
            neg.set_sign_negative(true);
            assert!(neg.is_sign_negative());
            assert_eq!(parts(neg), (2, 0));
            let back = decimal(2, Int::I128(0)).expect("decimal");
            assert!(!back.is_sign_negative());
            assert_eq!(back.to_string(), "0.00");
        }

        #[test]
        fn scale_and_mantissa_round_trip() {
            let d = Decimal::from_str("-1234.5678").expect("decimal");
            let (scale, mantissa) = parts(d);
            assert_eq!((scale, mantissa), (4, -12_345_678));
            assert_eq!(decimal(scale, Int::I128(mantissa)), Some(d));
        }

        #[test]
        fn what_rust_decimal_cannot_hold_has_no_decimal() {
            assert_eq!(decimal(28, Int::I128(1)).map(|d| d.scale()), Some(28));
            assert_eq!(decimal(29, Int::I128(1)), None);
            assert_eq!(decimal(0, Int::I128(1 << 96)), None);
            assert_eq!(decimal(0, Int::I128(-(1 << 96))), None);
            assert_eq!(decimal(0, Int::U128(u128::MAX)), None);
        }
    }
}

impl fmt::Display for Logical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Logical::Undefined => f.write_str("undefined"),
            Logical::Date => f.write_str("date"),
            Logical::Timestamp(unit) => {
                let unit = match unit {
                    TimeUnit::Seconds => "s",
                    TimeUnit::Millis => "ms",
                    TimeUnit::Micros => "us",
                    TimeUnit::Nanos => "ns",
                };
                write!(f, "timestamp({unit})")
            }
            Logical::Decimal { scale } => write!(f, "decimal({scale})"),
            Logical::Uuid => f.write_str("uuid"),
            Logical::Unknown(u) => write!(f, "logical({}, {})", u.id, u.param),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_logical_type_round_trips_through_the_wire() {
        let known = [
            Logical::Undefined,
            Logical::Date,
            Logical::Timestamp(TimeUnit::Seconds),
            Logical::Timestamp(TimeUnit::Millis),
            Logical::Timestamp(TimeUnit::Micros),
            Logical::Timestamp(TimeUnit::Nanos),
            Logical::Decimal { scale: 0 },
            Logical::Decimal { scale: 28 },
            Logical::Uuid,
        ];
        for ty in known {
            let (id, param) = ty.to_wire();
            assert_eq!(Logical::from_wire(id, param), Some(ty), "{ty}");
        }
    }

    #[test]
    fn id_zero_is_no_logical_type() {
        assert_eq!(Logical::from_wire(0, 0), None);
        assert_eq!(Logical::from_wire(0, 7), None);
    }

    #[test]
    fn a_known_id_with_a_bad_parameter_is_refused() {
        assert_eq!(Logical::from_wire(1, 1), None);
        assert_eq!(Logical::from_wire(2, 1), None);
        assert_eq!(Logical::from_wire(3, 4), None);
        assert_eq!(Logical::from_wire(4, 29), None);
        assert_eq!(Logical::from_wire(5, 1), None);
    }

    #[test]
    fn an_unknown_id_is_carried_through() {
        let ty = Logical::from_wire(200, 9).expect("unknown");
        assert!(matches!(ty, Logical::Unknown(u) if u.id() == 200 && u.param() == 9));
        assert_eq!(ty.to_wire(), (200, 9));
        assert!(ty.admits(&Physical::Text("anything")));
    }

    /// The `KnownLogical` a logical type is named by. Matches exhaustively,
    /// so a new `Logical` variant fails to build until it is paired here.
    fn known(logical: Logical) -> Option<KnownLogical> {
        match logical {
            Logical::Undefined => Some(KnownLogical::Undefined),
            Logical::Date => Some(KnownLogical::Date),
            Logical::Timestamp(_) => Some(KnownLogical::Timestamp),
            Logical::Decimal { .. } => Some(KnownLogical::Decimal),
            Logical::Uuid => Some(KnownLogical::Uuid),
            Logical::Unknown(_) => None,
        }
    }

    /// `KnownLogical` and `Logical` name the same types by the same ids,
    /// and every id this build knows is a `KnownLogical`, so the two cannot
    /// drift apart.
    #[test]
    fn known_logical_agrees_with_logical_on_every_id() {
        for id in 0..=u8::MAX {
            let known_id = KnownLogical::from_id(id);
            assert_eq!(
                known_id.is_some(),
                (id::UNDEFINED..=id::LAST_KNOWN).contains(&id),
                "id {id}"
            );
            assert_eq!(known_id.map(KnownLogical::id), known_id.map(|_| id));
            // Every logical type with this id, whatever its parameter, is
            // named by the same `KnownLogical`.
            for param in 0..=u8::MAX {
                if let Some(logical) = Logical::from_wire(id, param) {
                    assert_eq!(known(logical), known_id, "{logical:?}");
                }
            }
            let unknown = UnknownLogicalId::new(id);
            assert_eq!(unknown.is_some(), id > id::LAST_KNOWN, "id {id}");
            assert_eq!(unknown.map(UnknownLogicalId::get), unknown.map(|_| id));
        }
        assert_eq!(known(Logical::from_wire(200, 0).expect("unknown")), None);
    }

    /// `kind` names the one kind `admits` accepts a known logical type
    /// over, so a binding built from it agrees with what opens.
    #[test]
    fn kind_is_the_kind_admits_accepts() {
        let samples = [
            Physical::Null,
            Physical::Bool(true),
            Physical::Int(Int::I64(0)),
            Physical::Float(Float::F64(0.0)),
            Physical::Text(""),
            Physical::Bytes(&[0; 16]),
        ];
        let logicals = [
            Logical::Undefined,
            Logical::Date,
            Logical::Timestamp(TimeUnit::Millis),
            Logical::Decimal { scale: 2 },
            Logical::Uuid,
        ];
        for logical in logicals {
            for sample in &samples {
                let kind = known(logical).expect("known").kind();
                assert_eq!(
                    logical.admits(sample),
                    kind == sample.kind(),
                    "{logical:?} over {:?}",
                    sample.kind()
                );
            }
        }
    }

    #[test]
    fn admits_checks_the_physical_kind() {
        assert!(Logical::Undefined.admits(&Physical::Null));
        assert!(!Logical::Undefined.admits(&Physical::Bool(false)));
        assert!(Logical::Date.admits(&Physical::Int(Int::I32(0))));
        assert!(!Logical::Date.admits(&Physical::Text("2024-01-01")));
        assert!(Logical::Uuid.admits(&Physical::Bytes(&[0; 16])));
        assert!(!Logical::Uuid.admits(&Physical::Bytes(&[0; 15])));
        assert!(!Logical::Uuid.admits(&Physical::Text("")));
    }

    #[test]
    fn admits_checks_the_range() {
        assert!(Logical::Date.admits(&Physical::Int(Int::I64(MIN_DATE_DAYS.into()))));
        assert!(!Logical::Date.admits(&Physical::Int(Int::I64(i64::from(MIN_DATE_DAYS) - 1))));
        assert!(!Logical::Date.admits(&Physical::Int(Int::U128(u128::MAX))));
        let ns = Logical::Timestamp(TimeUnit::Nanos);
        assert!(ns.admits(&Physical::Int(Int::I128(MAX_TIMESTAMP_NANOS))));
        assert!(!ns.admits(&Physical::Int(Int::I128(MAX_TIMESTAMP_NANOS + 1))));
        assert!(!Logical::Timestamp(TimeUnit::Seconds).admits(&Physical::Int(Int::I128(i128::MAX))));
        assert!(Logical::Decimal { scale: 28 }.admits(&Physical::Int(Int::I128((1 << 96) - 1))));
        assert!(!Logical::Decimal { scale: 28 }.admits(&Physical::Int(Int::I128(1 << 96))));
        assert!(!Logical::Decimal { scale: 29 }.admits(&Physical::Int(Int::I8(1))));
        // The other two edges of the chrono ranges.
        assert!(Logical::Date.admits(&Physical::Int(Int::I32(MAX_DATE_DAYS))));
        assert!(!Logical::Date.admits(&Physical::Int(Int::I64(i64::from(MAX_DATE_DAYS) + 1))));
        assert!(ns.admits(&Physical::Int(Int::I128(MIN_TIMESTAMP_NANOS))));
        assert!(!ns.admits(&Physical::Int(Int::I128(MIN_TIMESTAMP_NANOS - 1))));
    }

    #[test]
    fn floats_compare_by_bit_pattern() {
        assert_ne!(Float::F64(-0.0), Float::F64(0.0));
        assert_eq!(Float::F64(f64::NAN), Float::F64(f64::NAN));
        assert_eq!(Float::F32(1.5), Float::F32(1.5));
        assert_ne!(Float::F32(-0.0), Float::F32(0.0));
        assert_ne!(Float::F32(1.0), Float::F64(1.0));
        assert_ne!(Physical::Int(Int::I8(34)), Physical::Int(Int::U64(34)));
    }

    #[test]
    fn ints_compare_by_width_sign_and_value() {
        assert_eq!(Int::I8(-1), Int::I8(-1));
        assert_ne!(Int::I8(-1), Int::I8(1));
        assert_ne!(Int::I8(-1), Int::I128(-1));
        assert_ne!(Int::I8(-1), Int::U8(255));
        assert_eq!(Int::U128(u128::MAX), Int::U128(u128::MAX));
        assert_ne!(Int::U128(u128::MAX), Int::I128(-1));
    }

    #[test]
    fn every_physical_kind_compares_to_itself_and_nothing_else() {
        let kinds = [
            Physical::Null,
            Physical::Bool(true),
            Physical::Int(Int::I32(1)),
            Physical::Float(Float::F64(1.0)),
            Physical::Text("a"),
            Physical::Bytes(b"a"),
        ];
        for (i, a) in kinds.iter().enumerate() {
            for (j, b) in kinds.iter().enumerate() {
                assert_eq!(a == b, i == j, "{a:?} {b:?}");
            }
        }
        assert_ne!(Physical::Bool(true), Physical::Bool(false));
        assert_ne!(Physical::Text("a"), Physical::Text("b"));
        assert_ne!(Physical::Text("a"), Physical::Text("ab"));
        assert_ne!(Physical::Bytes(b"a"), Physical::Bytes(b"b"));
        assert_ne!(Physical::Bytes(b"a"), Physical::Bytes(b"ab"));
    }

    #[test]
    fn debug_output_is_redacted() {
        for v in [
            format!("{:?}", Physical::Text("secret")),
            format!("{:?}", Physical::Bytes(b"secret")),
            format!("{:?}", Physical::Int(Int::I64(1_234_567))),
            format!("{:?}", Physical::Float(Float::F64(1_234_567.0))),
            format!("{:?}", Physical::Bool(true)),
            format!("{:?}", Int::U8(123)),
        ] {
            assert!(
                !v.contains("secret")
                    && !v.contains("1234567")
                    && !v.contains("true")
                    && !v.contains("123"),
                "{v}"
            );
            assert!(v.contains("***"), "{v}");
        }
        assert!(format!("{:?}", crate::plaintext::Bytes(b"secret")).contains("***"));
        assert!(!format!("{:?}", crate::plaintext::Bytes(b"secret")).contains("secret"));
        let raw = format!(
            "{:?}",
            crate::plaintext::Raw(None, Physical::Text("secret"))
        );
        assert!(raw.contains("***") && !raw.contains("secret"), "{raw}");
        // Only the variant name is the derive's; the type path `type_name`
        // prints before it differs between compiler versions.
        let null = format!("{:?}", Physical::Null);
        assert!(null.ends_with("::Null"), "{null}");
    }

    #[test]
    fn ints_and_floats_zeroize_in_place() {
        let mut i = Int::I64(7);
        i.zeroize();
        assert_eq!(i, Int::I64(0));
        let mut f = Float::F32(1.5);
        f.zeroize();
        assert_eq!(f, Float::F32(0.0));
    }

    #[test]
    fn a_javascript_date_beyond_chrono_is_refused() {
        // `new Date(8.64e15)`: valid in JavaScript, past chrono's range.
        let millis = Logical::Timestamp(TimeUnit::Millis);
        assert!(!millis.admits(&Physical::Int(Int::I64(8_640_000_000_000_000))));
        assert!(millis.admits(&Physical::Int(Int::I64(8_000_000_000_000_000))));
    }

    #[test]
    fn int_conversions() {
        assert_eq!(Int::U128(u128::MAX).to_i128(), None);
        assert_eq!(Int::I8(-1).to_u128(), None);
        assert_eq!(Int::U128(u128::MAX).to_u128(), Some(u128::MAX));
        assert_eq!(Int::I8(5).to_u128(), Some(5));
        assert_eq!(Int::I8(-1).sign_and_word(), (true, u128::MAX));
        assert_eq!(Int::U128(u128::MAX).sign_and_word(), (false, u128::MAX));
        assert_eq!(Int::U64(34).sign_and_word(), (false, 34));
        assert_eq!(Int::I8(0).sign_and_word(), (false, 0));
    }

    #[test]
    fn every_width_has_one_sign_and_word() {
        // A signed -1 sign-extends to every bit set; an unsigned maximum
        // zero-extends. Either way only a signed value can be negative.
        for v in [
            Int::I8(-1),
            Int::I16(-1),
            Int::I32(-1),
            Int::I64(-1),
            Int::I128(-1),
        ] {
            assert_eq!(v.sign_and_word(), (true, u128::MAX));
        }
        let unsigned = [
            (Int::U8(u8::MAX), u128::from(u8::MAX)),
            (Int::U16(u16::MAX), u128::from(u16::MAX)),
            (Int::U32(u32::MAX), u128::from(u32::MAX)),
            (Int::U64(u64::MAX), u128::from(u64::MAX)),
            (Int::U128(u128::MAX), u128::MAX),
        ];
        for (v, word) in unsigned {
            assert_eq!(v.sign_and_word(), (false, word));
        }
        // The top bit is the sign only for a signed value.
        assert_eq!(Int::I128(i128::MIN).sign_and_word(), (true, 1 << 127));
        assert_eq!(Int::U128(1 << 127).sign_and_word(), (false, 1 << 127));
        assert_eq!(
            Int::I64(i64::MAX).sign_and_word(),
            (false, i64::MAX as u128)
        );
        // Same word, different sign: never equal.
        assert_ne!(Int::I128(i128::MIN), Int::I128(i128::MAX));
    }

    #[test]
    fn a_decimal_mantissa_is_bounded_on_both_sides() {
        let ty = Logical::Decimal { scale: 0 };
        assert!(ty.admits(&Physical::Int(Int::I128(1 - (1 << 96)))));
        assert!(!ty.admits(&Physical::Int(Int::I128(-(1 << 96)))));
    }

    #[test]
    fn logical_displays_its_type() {
        let logical = [
            (Logical::Undefined, "undefined"),
            (Logical::Date, "date"),
            (Logical::Timestamp(TimeUnit::Seconds), "timestamp(s)"),
            (Logical::Timestamp(TimeUnit::Millis), "timestamp(ms)"),
            (Logical::Timestamp(TimeUnit::Micros), "timestamp(us)"),
            (Logical::Timestamp(TimeUnit::Nanos), "timestamp(ns)"),
            (Logical::Decimal { scale: 4 }, "decimal(4)"),
            (Logical::Uuid, "uuid"),
            (
                Logical::from_wire(200, 9).expect("unknown"),
                "logical(200, 9)",
            ),
        ];
        for (v, s) in logical {
            assert_eq!(v.to_string(), s);
        }
    }

    #[test]
    fn every_physical_value_names_its_kind_and_kinds_have_fixed_wire_bytes() {
        let pairs = [
            (Physical::Null, Kind::Null, 0),
            (Physical::Bool(true), Kind::Bool, 1),
            (Physical::Int(Int::I8(1)), Kind::Int, 2),
            (Physical::Float(Float::F32(1.0)), Kind::Float, 3),
            (Physical::Text("a"), Kind::Text, 4),
            (Physical::Bytes(&[1]), Kind::Bytes, 5),
        ];
        for (value, kind, wire) in pairs {
            assert_eq!(value.kind(), kind);
            assert_eq!(kind.to_wire(), wire, "{kind:?}");
        }
    }
}
