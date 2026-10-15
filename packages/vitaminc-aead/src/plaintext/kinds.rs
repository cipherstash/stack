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
//! 3. **Map it on the wire** in [`Logical::to_wire`] and
//!    [`Logical::from_wire`]. `from_wire` must return `None` for a
//!    parameter the type cannot take, so a malformed envelope is refused
//!    rather than read as some other value.
//! 4. **State its validity rule** in [`Logical::admits`]: which physical
//!    kind it accepts, and the range. Keep the rule self-contained, as the
//!    date and timestamp ranges are (constants pinned by a test, not a
//!    dependency), so the core model stays dependency-free.
//! 5. **Name it** in the `Display` impl.
//! 6. **Add a source**: a `Plaintext` impl for the Rust type that calls
//!    `sink.scalar(Some(Logical::YourType), Physical::...)`. If the type
//!    comes from another crate, put the impl behind a feature named after
//!    that crate, as the chrono, `rust_decimal` and uuid sources are.
//! 7. **Extend the tests here**: the variant goes into
//!    `every_known_logical_type_round_trips_through_the_wire`, a parameter
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
//! The compiler finds most of a missed step: `to_wire` and `Display` match
//! exhaustively, so a new variant fails to build until they are updated.
//! `from_wire` and `admits` have fallbacks, so a type missed there is
//! refused rather than reported; the round-trip test is what catches it.

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
        match self.to_i128() {
            Some(v) => (v < 0, v as u128),
            None => (false, self.to_u128().unwrap_or_default()),
        }
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
// by branch.

impl TimingSafeEq for Int {
    fn ts_eq(&self, other: &Self) -> Choice {
        let (sign_a, word_a) = self.sign_and_word();
        let (sign_b, word_b) = other.sign_and_word();
        let same_width = core::mem::discriminant(self) == core::mem::discriminant(other);
        Choice::from(u8::from(same_width))
            & u8::from(sign_a).ts_eq(&u8::from(sign_b))
            & word_a.ts_eq(&word_b)
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
        assert!(format!("{:?}", Physical::Null).ends_with("Physical<'_>::Null"));
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
        assert_eq!(Int::I8(-1).sign_and_word(), (true, u128::MAX));
        assert_eq!(Int::U128(u128::MAX).sign_and_word(), (false, u128::MAX));
        assert_eq!(Int::U64(34).sign_and_word(), (false, 34));
        assert_eq!(Int::I8(0).sign_and_word(), (false, 0));
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
}
