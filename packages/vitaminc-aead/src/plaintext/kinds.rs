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

use core::fmt;

/// One scalar value, as stored. Borrowed, so a source can hand over text
/// and bytes without copying.
///
/// Equality is structural: an int's width and a float's bit pattern both
/// count. It is for tests and sinks that compare what a source said, not
/// for comparing values across widths (see [`Int::sign_and_word`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug)]
pub enum Float {
    F32(f32),
    F64(f64),
}

impl PartialEq for Float {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Float::F32(a), Float::F32(b)) => a.to_bits() == b.to_bits(),
            (Float::F64(a), Float::F64(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
}

impl Eq for Float {}

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

impl Logical {
    /// The wire id and parameter, for the generic logical envelope.
    pub fn to_wire(self) -> (u8, u8) {
        match self {
            Logical::Undefined => (1, 0),
            Logical::Date => (2, 0),
            Logical::Timestamp(unit) => (3, unit as u8),
            Logical::Decimal { scale } => (4, scale),
            Logical::Uuid => (5, 0),
            Logical::Unknown(u) => (u.id, u.param),
        }
    }

    /// The logical type for a wire id and parameter. `None` for id 0, which
    /// means "no logical type", and for a known id with a parameter it
    /// cannot take.
    pub fn from_wire(id: u8, param: u8) -> Option<Self> {
        match (id, param) {
            (0, _) => None,
            (1, 0) => Some(Logical::Undefined),
            (2, 0) => Some(Logical::Date),
            (3, p) => TimeUnit::from_wire(p).map(Logical::Timestamp),
            (4, scale) => (scale <= MAX_DECIMAL_SCALE).then_some(Logical::Decimal { scale }),
            (5, 0) => Some(Logical::Uuid),
            (1..=5, _) => None,
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

impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Int::I8(v) => write!(f, "i8 {v}"),
            Int::I16(v) => write!(f, "i16 {v}"),
            Int::I32(v) => write!(f, "i32 {v}"),
            Int::I64(v) => write!(f, "i64 {v}"),
            Int::I128(v) => write!(f, "i128 {v}"),
            Int::U8(v) => write!(f, "u8 {v}"),
            Int::U16(v) => write!(f, "u16 {v}"),
            Int::U32(v) => write!(f, "u32 {v}"),
            Int::U64(v) => write!(f, "u64 {v}"),
            Int::U128(v) => write!(f, "u128 {v}"),
        }
    }
}

impl fmt::Display for Physical<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Physical::Null => f.write_str("null"),
            Physical::Bool(v) => write!(f, "{v}"),
            Physical::Int(v) => write!(f, "{v}"),
            Physical::Float(Float::F32(v)) => write!(f, "f32 {v}"),
            Physical::Float(Float::F64(v)) => write!(f, "f64 {v}"),
            Physical::Text(v) => write!(f, "{v:?}"),
            Physical::Bytes(v) => {
                f.write_str("0x")?;
                v.iter().try_for_each(|b| write!(f, "{b:02x}"))
            }
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
    fn display_names_the_width_and_the_type() {
        let ints = [
            (Int::I8(-1), "i8 -1"),
            (Int::I16(2), "i16 2"),
            (Int::I32(3), "i32 3"),
            (Int::I64(4), "i64 4"),
            (Int::I128(5), "i128 5"),
            (Int::U8(6), "u8 6"),
            (Int::U16(7), "u16 7"),
            (Int::U32(8), "u32 8"),
            (Int::U64(9), "u64 9"),
            (Int::U128(10), "u128 10"),
        ];
        for (v, s) in ints {
            assert_eq!(v.to_string(), s);
        }

        let physical = [
            (Physical::Null, "null"),
            (Physical::Bool(true), "true"),
            (Physical::Int(Int::U8(1)), "u8 1"),
            (Physical::Float(Float::F32(1.5)), "f32 1.5"),
            (Physical::Float(Float::F64(-2.5)), "f64 -2.5"),
            (Physical::Text("a\"b"), "\"a\\\"b\""),
            (Physical::Bytes(&[0x0f, 0xa0]), "0x0fa0"),
            (Physical::Bytes(&[]), "0x"),
        ];
        for (v, s) in physical {
            assert_eq!(v.to_string(), s);
        }

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
