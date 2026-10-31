//! Plaintexts with no Rust standard type: a calendar date, a UTC instant
//! and a decimal number, each held as the integers vitaminc's value model
//! stores it as (ADR-0002).
//!
//! The types the ecosystem offers (chrono's `NaiveDate` and
//! `DateTime<Utc>`, rust_decimal's `Decimal`) keep their fields private,
//! so their bytes cannot be wiped. A plaintext this crate copies, to seal
//! it or to derive a term from it, must be wiped when it is dropped, so
//! these types stand in for them. With the `chrono` and `rust_decimal`
//! features each converts to and from its ecosystem type.
//!
//! vitaminc-aead has a wipeable `Timestamp` of its own, and it is not
//! reused: this crate hands each term of a type its own copy of the
//! plaintext, so a target with several terms needs a `Clone` plaintext,
//! and vitaminc's type is deliberately not `Clone`. It is also built only
//! from a `DateTime<Utc>`, which would make chrono a dependency of every
//! build. The types here are `Clone`, and a clone is wiped too.
//!
//! | Type | Holds | Range |
//! |---|---|---|
//! | [`Date`] | an `i32` count of days since 1970-01-01, in the proleptic Gregorian calendar | years -262143 to 262142 |
//! | [`Timestamp`] | an `i64` count of seconds since the Unix epoch and a `u32` of nanoseconds below one second, UTC, with no leap seconds | years -262143 to 262142 |
//! | [`Decimal`] | an `i128` mantissa and a `u8` scale: the value is `mantissa × 10^-scale` | scale at most 28, mantissa below 2^96 in magnitude |
//!
//! The ranges are vitaminc's, which are chrono's and rust_decimal's: a
//! value outside them has no encoding and is refused when the type is
//! built, so a value of one of these types always encrypts. A refusal
//! ([`RangeError`]) names what was out of range, never the value.
//!
//! # What wiping covers
//!
//! Each type implements [`Zeroize`] and wipes its integers when it is
//! dropped ([`ZeroizeOnDrop`]). That covers every owned copy this crate
//! makes. The integer a value describes itself to vitaminc's sink with is a
//! `Copy` stack temporary, as it is for the primitive, chrono and
//! rust_decimal sources, and is not wiped. Nor is a value the caller builds
//! the type from, or converts it to: a `NaiveDate`, `DateTime<Utc>` or
//! rust_decimal `Decimal` (with the `chrono` and `rust_decimal` features),
//! or the integers read through an accessor, are ordinary values the caller
//! looks after.
//!
//! None of the types is `Copy`, so a copy is never made without a trace.
//! Each is `Clone`, because each term of a type takes its own copy of the
//! plaintext; a clone is wiped when it is dropped too. `Debug` is redacted,
//! and there is no `PartialEq`, `Ord` or `Hash`, which would compare
//! plaintext in variable time: compare the accessors' integers.
//!
//! # Equality and order
//!
//! The ciphertext keeps the value exactly as given. An equality term and an
//! order term (ORE, OPE or block ORE) are derived from vitaminc's encodings
//! of it, which agree:
//!
//! - a decimal's scale is normalised, so `1.5` and `1.50` have one equality
//!   term and order as equal, while each opens as it was stored;
//! - a timestamp is truncated to the microsecond: the nanoseconds below
//!   it are dropped, never rounded, so two instants in the same microsecond
//!   match under `=` and order as equal, while each opens with its own
//!   nanoseconds. Truncation is floor on the count since the epoch, so it
//!   moves an instant before 1970 earlier too. It does not depend on any one
//!   store's rounding;
//! - a date is its day.

use std::fmt;

use crate::Encrypt;
use vitaminc_aead::plaintext::depth;
use vitaminc_aead::plaintext::kinds::{timestamp_nanos, MAX_DECIMAL_SCALE};
use vitaminc_aead::{FixedType, FromScalar, Int, Logical, Physical, Sink, TimeUnit, Width};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Why a value could not be built as one of this module's plaintexts.
///
/// The message names the range, never the value: the value is plaintext,
/// and an error is what a program logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RangeError {
    /// A day count outside chrono's date range, years -262143 to 262142.
    #[error("the date is outside the representable range, years -262143 to 262142")]
    Date,
    /// An instant outside chrono's range, years -262143 to 262142.
    #[error("the timestamp is outside the representable range, years -262143 to 262142")]
    Timestamp,
    /// Nanoseconds of one second or more: not a nanosecond field, and
    /// chrono's representation of a leap second, which has no count of
    /// seconds since the epoch.
    #[error(
        "the timestamp's nanoseconds must be below one second (chrono holds a leap second \
         this way, and it has no encoding)"
    )]
    LeapSecond,
    /// A decimal scale above 28.
    #[error("the decimal's scale is above 28")]
    DecimalScale,
    /// A decimal mantissa of 2^96 or more in magnitude.
    #[error("the decimal's mantissa does not fit 96 bits")]
    DecimalMantissa,
}

/// A calendar date with no time of day and no time zone: a count of days
/// since 1970-01-01 in the proleptic Gregorian calendar.
///
/// 1970-01-01 is day 0 and 1969-12-31 is day -1: the day count vitaminc's
/// value model stores a date as, and the one a `NaiveDate` converts to with
/// the `chrono` feature. See the [module documentation](self) for what
/// wiping covers.
///
/// ```
/// use stack_encrypt::value::Date;
///
/// let day = Date::from_days_since_epoch(19_782)?; // 2024-02-29
/// assert_eq!(day.days_since_epoch(), 19_782);
/// # Ok::<(), stack_encrypt::value::RangeError>(())
/// ```
#[derive(Clone)]
pub struct Date {
    days: i32,
}

impl Date {
    /// The date `days` after 1970-01-01, or before it for a negative count.
    ///
    /// # Errors
    ///
    /// [`RangeError::Date`] outside years -262143 to 262142.
    pub fn from_days_since_epoch(days: i32) -> Result<Self, RangeError> {
        Logical::Date
            .admits(&Physical::Int(Int::I32(days)))
            .then_some(Self { days })
            .ok_or(RangeError::Date)
    }

    /// The count of days since 1970-01-01. The integer is the caller's to
    /// look after: it is a copy, and is not wiped.
    pub fn days_since_epoch(&self) -> i32 {
        self.days
    }
}

/// A UTC instant with nanosecond precision and no leap seconds: whole
/// seconds since the Unix epoch, and nanoseconds past them.
///
/// The ciphertext keeps the nanoseconds; an equality or order term keeps
/// the microseconds, truncated rather than rounded (see the [module
/// documentation](self#equality-and-order), which also says what wiping
/// covers).
///
/// ```
/// use stack_encrypt::value::{RangeError, Timestamp};
///
/// let instant = Timestamp::new(1_700_000_000, 500)?;
/// assert_eq!((instant.seconds(), instant.nanoseconds()), (1_700_000_000, 500));
/// assert_eq!(Timestamp::new(0, 1_000_000_000).unwrap_err(), RangeError::LeapSecond);
/// # Ok::<(), RangeError>(())
/// ```
#[derive(Clone)]
pub struct Timestamp {
    seconds: i64,
    nanos: u32,
}

impl Timestamp {
    /// The instant `seconds` after the Unix epoch, plus `nanoseconds`.
    /// A negative `seconds` is before 1970; the nanoseconds still count
    /// forward from it, so -0.5 seconds is `new(-1, 500_000_000)`.
    ///
    /// # Errors
    ///
    /// [`RangeError::LeapSecond`] for nanoseconds of one second or more,
    /// and [`RangeError::Timestamp`] outside years -262143 to 262142.
    pub fn new(seconds: i64, nanoseconds: u32) -> Result<Self, RangeError> {
        if nanoseconds >= NANOS_PER_SECOND {
            return Err(RangeError::LeapSecond);
        }
        let instant = Self {
            seconds,
            nanos: nanoseconds,
        };
        timestamp_nanos(TimeUnit::Nanos, Int::I128(instant.count()))
            .map(|_| instant)
            .ok_or(RangeError::Timestamp)
    }

    /// Whole seconds since the Unix epoch, negative before 1970. A copy,
    /// not wiped.
    pub fn seconds(&self) -> i64 {
        self.seconds
    }

    /// Nanoseconds past [`seconds`](Self::seconds), below one second. A
    /// copy, not wiped.
    pub fn nanoseconds(&self) -> u32 {
        self.nanos
    }

    /// Nanoseconds since the epoch: the count vitaminc stores a timestamp
    /// as, and the one a `DateTime<Utc>` encrypts to, so the two seal the
    /// same leaf. Cannot overflow: an `i64` of seconds times 10^9 is far
    /// inside an `i128`.
    fn count(&self) -> i128 {
        i128::from(self.seconds) * i128::from(NANOS_PER_SECOND) + i128::from(self.nanos)
    }

    /// The instant for a count of nanoseconds already checked to be in
    /// range.
    fn from_nanos(nanos: i128) -> Option<Self> {
        let per_second = i128::from(NANOS_PER_SECOND);
        Some(Self {
            seconds: i64::try_from(nanos.div_euclid(per_second)).ok()?,
            nanos: u32::try_from(nanos.rem_euclid(per_second)).ok()?,
        })
    }
}

/// A finite decimal number with its scale: `mantissa × 10^-scale`.
///
/// The scale is kept: `1.50` (mantissa 150, scale 2) opens as `1.50`, not
/// `1.5`. An equality or order term normalises it, so `1.5` and `1.50`
/// match under `=` and order as equal. There is no NaN and no infinity, and a negative zero is zero. See
/// the [module documentation](self) for what wiping covers.
///
/// PostgreSQL's `numeric` holds values this type cannot (more than 28
/// digits after the point, or a mantissa past 96 bits); such a value is
/// refused, never rounded.
///
/// ```
/// use stack_encrypt::value::{Decimal, RangeError};
///
/// let price = Decimal::new(-123_450, 2)?; // -1234.50
/// assert_eq!((price.mantissa(), price.scale()), (-123_450, 2));
/// assert_eq!(Decimal::new(1, 29).unwrap_err(), RangeError::DecimalScale);
/// # Ok::<(), RangeError>(())
/// ```
#[derive(Clone)]
pub struct Decimal {
    mantissa: i128,
    scale: u8,
}

impl Decimal {
    /// `mantissa × 10^-scale`.
    ///
    /// # Errors
    ///
    /// [`RangeError::DecimalScale`] for a scale above 28, and
    /// [`RangeError::DecimalMantissa`] for a mantissa of 2^96 or more in
    /// magnitude.
    pub fn new(mantissa: i128, scale: u8) -> Result<Self, RangeError> {
        if scale > MAX_DECIMAL_SCALE {
            return Err(RangeError::DecimalScale);
        }
        Logical::Decimal { scale }
            .admits(&Physical::Int(Int::I128(mantissa)))
            .then_some(Self { mantissa, scale })
            .ok_or(RangeError::DecimalMantissa)
    }

    /// The mantissa: the value is `mantissa × 10^-scale`. A copy, not
    /// wiped.
    pub fn mantissa(&self) -> i128 {
        self.mantissa
    }

    /// The number of digits after the point, at most 28. A copy, not
    /// wiped.
    pub fn scale(&self) -> u8 {
        self.scale
    }
}

/// `Zeroize`, `ZeroizeOnDrop` and a redacted `Debug` for each type: wiping
/// sets every integer to zero.
macro_rules! wiped {
    ($($ty:ident { $($field:ident),+ }),+ $(,)?) => {$(
        impl Zeroize for $ty {
            fn zeroize(&mut self) {
                $(self.$field.zeroize();)+
            }
        }

        impl Drop for $ty {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl ZeroizeOnDrop for $ty {}

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+};
}
wiped!(
    Date { days },
    Timestamp { seconds, nanos },
    Decimal { mantissa, scale },
);

/// Each type describes itself to vitaminc as the logical type over an int
/// it is, the same scalar the chrono and rust_decimal types describe, so a
/// value converted from one of those seals the same leaf. The owned form
/// visits through the borrowed one and is then dropped, and wiped.
///
/// Each is fixed width, so `None` of one seals as a typed null as long as a
/// value, and an `Option` of one reads it back: the type's
/// own zero (the epoch, a zero decimal) is a value it reads, which is what
/// `Decrypt::reads_null` asks of it.
macro_rules! source {
    ($($ty:ident ($fixed:expr) => |$value:ident| $scalar:expr),+ $(,)?) => {$(
        impl Encrypt for &$ty {
            const DEPTH: Option<usize> = depth::SCALAR;
            const FIXED: Option<FixedType> = $fixed;
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let $value = self;
                let (logical, int) = $scalar;
                sink.scalar(Some(logical), Physical::Int(int))
            }
        }

        impl Encrypt for $ty {
            const DEPTH: Option<usize> = depth::SCALAR;
            const FIXED: Option<FixedType> = $fixed;
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                (&self).visit(sink)
            }
        }
    )+};
}
source!(
    Date (FixedType::new(Some(Logical::Date), Width::I32))
        => |date| (Logical::Date, Int::I32(date.days)),
    Timestamp (FixedType::new(Some(Logical::Timestamp(TimeUnit::Nanos)), Width::I128))
        => |instant| (Logical::Timestamp(TimeUnit::Nanos), Int::I128(instant.count())),
    Decimal (FixedType::new(Some(Logical::Decimal { scale: 0 }), Width::I128))
        => |decimal| (Logical::Decimal { scale: decimal.scale }, Int::I128(decimal.mantissa)),
);

/// A date reads exactly a date scalar, at any integer width, in range.
impl FromScalar for Date {
    const EXPECTED: &'static str = "date";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        match (ty, value) {
            (Some(Logical::Date), Physical::Int(days)) => {
                Date::from_days_since_epoch(i32::try_from(days.to_i128()?).ok()?).ok()
            }
            _ => None,
        }
    }
}

/// A timestamp reads a timestamp scalar in any unit (a JavaScript `Date`
/// is in milliseconds, a Rust or Go instant in nanoseconds), in range.
impl FromScalar for Timestamp {
    const EXPECTED: &'static str = "timestamp";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        match (ty, value) {
            (Some(Logical::Timestamp(unit)), Physical::Int(count)) => {
                Timestamp::from_nanos(timestamp_nanos(unit, count)?)
            }
            _ => None,
        }
    }
}

/// A decimal reads a decimal scalar, keeping its scale, in range.
impl FromScalar for Decimal {
    const EXPECTED: &'static str = "decimal";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        match (ty, value) {
            (Some(Logical::Decimal { scale }), Physical::Int(mantissa)) => {
                Decimal::new(mantissa.to_i128()?, scale).ok()
            }
            _ => None,
        }
    }
}

/// Conversions to and from chrono's `NaiveDate` and `DateTime<Utc>`. The
/// ranges are the same (vitaminc pins them to chrono's), so only a leap
/// second, which a `DateTime<Utc>` can hold and a [`Timestamp`] cannot, is
/// refused. The chrono value is outside this crate's care: it is not wiped.
#[cfg(feature = "chrono")]
mod chrono_conversions {
    use super::{Date, RangeError, Timestamp};
    use chrono::{DateTime, NaiveDate, Utc};
    use vitaminc_aead::plaintext::kinds::chrono as conv;
    use vitaminc_aead::{Int, TimeUnit};

    impl From<NaiveDate> for Date {
        /// Every `NaiveDate` is in range: chrono's range is the one a
        /// `Date` checks.
        fn from(date: NaiveDate) -> Self {
            Date {
                days: conv::date_days(date),
            }
        }
    }

    impl From<&Date> for NaiveDate {
        #[allow(
            clippy::expect_used,
            reason = "a Date is only built in chrono's NaiveDate range (from_days_since_epoch checks it, and From<NaiveDate> starts inside it), and chrono has no unchecked constructor"
        )]
        fn from(date: &Date) -> Self {
            // A `Date` is only built in chrono's range, so the conversion
            // always succeeds. If the two ranges ever drifted apart, this
            // fails loudly rather than returning a wrong date.
            conv::date(Int::I32(date.days)).expect("a Date is built in chrono's NaiveDate range")
        }
    }

    impl TryFrom<DateTime<Utc>> for Timestamp {
        type Error = RangeError;

        /// # Errors
        ///
        /// [`RangeError::LeapSecond`] for a leap second, which chrono holds
        /// as nanoseconds of one second or more.
        fn try_from(instant: DateTime<Utc>) -> Result<Self, RangeError> {
            Timestamp::new(instant.timestamp(), instant.timestamp_subsec_nanos())
        }
    }

    impl From<&Timestamp> for DateTime<Utc> {
        #[allow(
            clippy::expect_used,
            reason = "a Timestamp is only built in chrono's DateTime<Utc> range (Timestamp::new checks it), and chrono has no unchecked constructor"
        )]
        fn from(instant: &Timestamp) -> Self {
            // A `Timestamp` is only built in chrono's range. If the two
            // ranges ever drifted apart, this fails loudly rather than
            // returning a wrong instant.
            conv::timestamp(TimeUnit::Nanos, Int::I128(instant.count()))
                .expect("a Timestamp is built in chrono's DateTime<Utc> range")
        }
    }
}

/// Conversions to and from rust_decimal's `Decimal`, whose range (scale at
/// most 28, a 96-bit mantissa) is the one a [`Decimal`] checks, so neither
/// direction can fail. A rust_decimal negative zero converts to zero at its
/// scale. The rust_decimal value is outside this crate's care: it is not
/// wiped.
#[cfg(feature = "rust_decimal")]
mod rust_decimal_conversions {
    use super::Decimal;
    use vitaminc_aead::plaintext::kinds::decimal as conv;
    use vitaminc_aead::Int;

    impl From<rust_decimal::Decimal> for Decimal {
        fn from(decimal: rust_decimal::Decimal) -> Self {
            let (scale, mantissa) = conv::parts(decimal);
            Decimal { mantissa, scale }
        }
    }

    impl From<&Decimal> for rust_decimal::Decimal {
        #[allow(
            clippy::expect_used,
            reason = "a Decimal is only built in rust_decimal's range (Decimal::new checks the scale and mantissa, and From<rust_decimal::Decimal> starts inside it)"
        )]
        fn from(decimal: &Decimal) -> Self {
            // A `Decimal` is only built in rust_decimal's range. If the two
            // ranges ever drifted apart, this fails loudly rather than
            // returning a wrong number.
            conv::decimal(decimal.scale, Int::I128(decimal.mantissa))
                .expect("a Decimal is built in rust_decimal's range")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decrypt;
    use vitaminc_aead::plaintext::kinds::{
        MAX_DATE_DAYS, MAX_TIMESTAMP_NANOS, MIN_DATE_DAYS, MIN_TIMESTAMP_NANOS,
    };

    /// The scalar a value describes itself as.
    struct Scalar;
    impl Sink for Scalar {
        type Ok = (Option<Logical>, Option<i128>);
        type Error = vitaminc_aead::DecodeError;
        type Seq = vitaminc_aead::typed::Never<Self::Ok>;
        type Map = vitaminc_aead::typed::Never<Self::Ok>;
        fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Self::Ok, Self::Error> {
            Ok((
                ty,
                match v {
                    Physical::Int(i) => i.to_i128(),
                    _ => None,
                },
            ))
        }
        fn typed_null(self, ty: vitaminc_aead::FixedType) -> Result<Self::Ok, Self::Error> {
            Ok((ty.logical(), None))
        }
        fn seq(self, _: Option<usize>) -> Result<Self::Seq, Self::Error> {
            unreachable!("a plaintext here is a scalar")
        }
        fn map(self, _: Option<usize>) -> Result<Self::Map, Self::Error> {
            unreachable!("a plaintext here is a scalar")
        }
        fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Self::Ok, Self::Error> {
            unreachable!("a plaintext here is a scalar")
        }
    }

    fn scalar(value: impl Encrypt) -> (Option<Logical>, Option<i128>) {
        value.visit(Scalar).unwrap()
    }

    /// What the type's own decrypt sink builds from one scalar: the path
    /// an opened leaf takes.
    fn read<T: FromScalar>(ty: Logical, int: Int) -> Option<T> {
        T::sink().scalar(Some(ty), Physical::Int(int)).ok()
    }

    #[test]
    fn a_date_is_its_day_count_and_refuses_one_outside_the_range() {
        for days in [0, -1, 19_782, MIN_DATE_DAYS, MAX_DATE_DAYS] {
            let date = Date::from_days_since_epoch(days).unwrap();
            assert_eq!(date.days_since_epoch(), days);
            assert_eq!(scalar(&date), (Some(Logical::Date), Some(days.into())));
            let back: Date = read(Logical::Date, Int::I32(days)).unwrap();
            assert_eq!(back.days_since_epoch(), days);
        }
        for days in [MIN_DATE_DAYS - 1, MAX_DATE_DAYS + 1, i32::MIN, i32::MAX] {
            assert_eq!(
                Date::from_days_since_epoch(days).unwrap_err(),
                RangeError::Date
            );
            assert!(read::<Date>(Logical::Date, Int::I32(days)).is_none());
        }
        // Another width reads too; another logical type does not.
        let wide: Date = read(Logical::Date, Int::I64(-3)).unwrap();
        assert_eq!(wide.days_since_epoch(), -3);
        assert!(read::<Date>(Logical::Date, Int::I64(i64::MAX)).is_none());
        assert!(read::<Date>(Logical::Timestamp(TimeUnit::Nanos), Int::I32(0)).is_none());
        assert!(<Date as FromScalar>::from_scalar(None, Physical::Int(Int::I32(0))).is_none());
    }

    #[test]
    fn a_timestamp_is_its_nanosecond_count_and_refuses_a_leap_second() {
        for (seconds, nanos) in [
            (0, 0),
            (1_700_000_000, 123_456_789),
            (-1, 999_999_999),
            (-1, 500_000_000),
        ] {
            let instant = Timestamp::new(seconds, nanos).unwrap();
            assert_eq!((instant.seconds(), instant.nanoseconds()), (seconds, nanos));
            let count = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
            assert_eq!(
                scalar(&instant),
                (Some(Logical::Timestamp(TimeUnit::Nanos)), Some(count))
            );
            let back: Timestamp =
                read(Logical::Timestamp(TimeUnit::Nanos), Int::I128(count)).unwrap();
            assert_eq!((back.seconds(), back.nanoseconds()), (seconds, nanos));
        }
        // Any unit reads: a millisecond count is a JavaScript `Date`'s.
        let millis: Timestamp =
            read(Logical::Timestamp(TimeUnit::Millis), Int::I64(-1_500)).unwrap();
        assert_eq!((millis.seconds(), millis.nanoseconds()), (-2, 500_000_000));

        assert_eq!(
            Timestamp::new(0, 1_000_000_000).unwrap_err(),
            RangeError::LeapSecond
        );
        assert_eq!(
            Timestamp::new(0, u32::MAX).unwrap_err(),
            RangeError::LeapSecond
        );
        // The range's two edges, and one nanosecond past each.
        let edge = |nanos: i128| {
            let n = i128::from(NANOS_PER_SECOND);
            Timestamp::new(
                i64::try_from(nanos.div_euclid(n)).unwrap(),
                u32::try_from(nanos.rem_euclid(n)).unwrap(),
            )
        };
        assert!(edge(MIN_TIMESTAMP_NANOS).is_ok());
        assert!(edge(MAX_TIMESTAMP_NANOS).is_ok());
        assert_eq!(
            edge(MIN_TIMESTAMP_NANOS - 1).unwrap_err(),
            RangeError::Timestamp
        );
        assert_eq!(
            edge(MAX_TIMESTAMP_NANOS + 1).unwrap_err(),
            RangeError::Timestamp
        );
        for seconds in [i64::MIN, i64::MAX] {
            assert_eq!(
                Timestamp::new(seconds, 0).unwrap_err(),
                RangeError::Timestamp
            );
        }
        assert!(read::<Timestamp>(
            Logical::Timestamp(TimeUnit::Nanos),
            Int::I128(MAX_TIMESTAMP_NANOS + 1)
        )
        .is_none());
        assert!(read::<Timestamp>(Logical::Date, Int::I128(0)).is_none());
    }

    #[test]
    fn a_decimal_keeps_its_scale_and_refuses_what_rust_decimal_cannot_hold() {
        let limit = 1i128 << 96;
        for (mantissa, scale) in [(150, 2), (-1, 0), (0, 28), (limit - 1, 28), (1 - limit, 0)] {
            let decimal = Decimal::new(mantissa, scale).unwrap();
            assert_eq!((decimal.mantissa(), decimal.scale()), (mantissa, scale));
            assert_eq!(
                scalar(&decimal),
                (Some(Logical::Decimal { scale }), Some(mantissa))
            );
            let back: Decimal = read(Logical::Decimal { scale }, Int::I128(mantissa)).unwrap();
            assert_eq!((back.mantissa(), back.scale()), (mantissa, scale));
        }
        assert_eq!(Decimal::new(1, 29).unwrap_err(), RangeError::DecimalScale);
        assert_eq!(
            Decimal::new(1, u8::MAX).unwrap_err(),
            RangeError::DecimalScale
        );
        for mantissa in [limit, -limit, i128::MAX, i128::MIN] {
            assert_eq!(
                Decimal::new(mantissa, 0).unwrap_err(),
                RangeError::DecimalMantissa
            );
            assert!(read::<Decimal>(Logical::Decimal { scale: 0 }, Int::I128(mantissa)).is_none());
        }
        assert!(read::<Decimal>(Logical::Date, Int::I128(1)).is_none());
    }

    #[test]
    fn an_owned_value_seals_the_scalar_its_borrow_does() {
        let date = Date::from_days_since_epoch(5).unwrap();
        assert_eq!(scalar(date.clone()), scalar(&date));
        let instant = Timestamp::new(5, 6).unwrap();
        assert_eq!(scalar(instant.clone()), scalar(&instant));
        let decimal = Decimal::new(5, 6).unwrap();
        assert_eq!(scalar(decimal.clone()), scalar(&decimal));
    }

    #[test]
    fn zeroize_clears_every_field() {
        let mut date = Date::from_days_since_epoch(-42).unwrap();
        date.zeroize();
        assert_eq!(date.days_since_epoch(), 0);
        let mut instant = Timestamp::new(-7, 999).unwrap();
        instant.zeroize();
        assert_eq!((instant.seconds(), instant.nanoseconds()), (0, 0));
        let mut decimal = Decimal::new(-123, 4).unwrap();
        decimal.zeroize();
        assert_eq!((decimal.mantissa(), decimal.scale()), (0, 0));
    }

    /// Dropping wipes the value where it lies. Read through a
    /// `ManuallyDrop` so the memory is still the test's after the drop
    /// glue has run: `drop_in_place` runs `Drop` without freeing. The one
    /// `unsafe` in this crate, in a test: nothing else observes memory
    /// after a drop, and without it a `Drop` that wiped nothing would pass.
    #[test]
    #[allow(unsafe_code)]
    fn dropping_wipes_the_value_in_place() {
        use std::mem::ManuallyDrop;
        let mut date = ManuallyDrop::new(Date::from_days_since_epoch(-42).unwrap());
        let mut instant = ManuallyDrop::new(Timestamp::new(-7, 999).unwrap());
        let mut decimal = ManuallyDrop::new(Decimal::new(-123, 4).unwrap());
        // SAFETY: each value is dropped once and only its integers, which
        // need no drop of their own, are read afterwards.
        unsafe {
            ManuallyDrop::drop(&mut date);
            ManuallyDrop::drop(&mut instant);
            ManuallyDrop::drop(&mut decimal);
        }
        assert_eq!(date.days, 0);
        assert_eq!((instant.seconds, instant.nanos), (0, 0));
        assert_eq!((decimal.mantissa, decimal.scale), (0, 0));
    }

    #[test]
    fn debug_and_errors_never_show_the_value() {
        let date = Date::from_days_since_epoch(19_782).unwrap();
        let instant = Timestamp::new(1_700_000_000, 0).unwrap();
        let decimal = Decimal::new(123_450, 2).unwrap();
        for shown in [
            format!("{date:?}"),
            format!("{instant:?}"),
            format!("{decimal:?}"),
        ] {
            assert!(shown.ends_with("(<redacted>)"), "{shown}");
            assert!(!shown.chars().any(|c| c.is_ascii_digit()), "{shown}");
        }
        for error in [
            Date::from_days_since_epoch(i32::MAX).unwrap_err(),
            Timestamp::new(i64::MAX, 0).unwrap_err(),
            Timestamp::new(0, 1_234_567_890).unwrap_err(),
            Decimal::new(i128::MAX, 0).unwrap_err(),
            Decimal::new(1, 200).unwrap_err(),
        ] {
            let message = error.to_string();
            for value in ["2147483647", "9223372036854775807", "1234567890", "200"] {
                assert!(!message.contains(value), "{message}");
            }
        }
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_values_convert_both_ways() {
        use chrono::{DateTime, NaiveDate, Utc};

        for date in [
            NaiveDate::from_ymd_opt(2024, 2, 29).unwrap(),
            NaiveDate::from_ymd_opt(1969, 12, 31).unwrap(),
            NaiveDate::from_ymd_opt(1, 1, 1).unwrap(),
            NaiveDate::MIN,
            NaiveDate::MAX,
        ] {
            let ours = Date::from(date);
            assert_eq!(NaiveDate::from(&ours), date);
            // The same scalar chrono's own source describes.
            assert_eq!(scalar(&ours), scalar(date));
        }
        assert_eq!(
            Date::from(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()).days_since_epoch(),
            0
        );
        // The ends of the range a `Date` checks are chrono's ends: if the
        // two drift apart, the `expect` in the conversion fires here.
        for (days, date) in [
            (MIN_DATE_DAYS, NaiveDate::MIN),
            (MAX_DATE_DAYS, NaiveDate::MAX),
        ] {
            let ours = Date::from_days_since_epoch(days).unwrap();
            assert_eq!(NaiveDate::from(&ours), date);
        }

        for instant in [
            DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap(),
            DateTime::from_timestamp(-1, 1).unwrap(),
            chrono::NaiveDateTime::MIN.and_utc(),
            chrono::NaiveDateTime::MAX.and_utc(),
        ] {
            let ours = Timestamp::try_from(instant).unwrap();
            assert_eq!(DateTime::<Utc>::from(&ours), instant);
            assert_eq!(scalar(&ours), scalar(instant));
        }
        // The same for a `Timestamp`'s range.
        for (nanos, instant) in [
            (MIN_TIMESTAMP_NANOS, chrono::NaiveDateTime::MIN.and_utc()),
            (MAX_TIMESTAMP_NANOS, chrono::NaiveDateTime::MAX.and_utc()),
        ] {
            let ours =
                read::<Timestamp>(Logical::Timestamp(TimeUnit::Nanos), Int::I128(nanos)).unwrap();
            assert_eq!(DateTime::<Utc>::from(&ours), instant);
        }
        let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
            .and_then(|d| d.and_hms_nano_opt(23, 59, 59, 1_500_000_000))
            .unwrap()
            .and_utc();
        assert_eq!(
            Timestamp::try_from(leap).unwrap_err(),
            RangeError::LeapSecond
        );
    }

    #[cfg(feature = "rust_decimal")]
    #[test]
    fn rust_decimal_values_convert_both_ways() {
        use std::str::FromStr;

        for text in [
            "1.50",
            "-1234.5678",
            "0",
            "79228162514264337593543950335",
            "-0.0000000000000000000000000001",
        ] {
            let theirs = rust_decimal::Decimal::from_str(text).unwrap();
            let ours = Decimal::from(theirs);
            let back = rust_decimal::Decimal::from(&ours);
            assert_eq!(back.to_string(), theirs.to_string(), "{text}");
            assert_eq!(scalar(&ours), scalar(theirs), "{text}");
        }
        // The ends of rust_decimal's range, at the smallest and the largest
        // scale: if the ranges drift apart, the `expect` in the conversion
        // fires here.
        let limit = 79_228_162_514_264_337_593_543_950_335_i128;
        for theirs in [rust_decimal::Decimal::MIN, rust_decimal::Decimal::MAX] {
            let ours = Decimal::from(theirs);
            assert_eq!(rust_decimal::Decimal::from(&ours), theirs);
        }
        for mantissa in [limit, -limit] {
            let ours = Decimal::new(mantissa, MAX_DECIMAL_SCALE).unwrap();
            let back = rust_decimal::Decimal::from(&ours);
            assert_eq!((back.mantissa(), back.scale()), (mantissa, 28));
        }
        let ours = Decimal::from(rust_decimal::Decimal::from_str("1.50").unwrap());
        assert_eq!((ours.mantissa(), ours.scale()), (150, 2));
        // A negative zero is zero, at its scale.
        let mut negative_zero = rust_decimal::Decimal::new(0, 2);
        negative_zero.set_sign_negative(true);
        let ours = Decimal::from(negative_zero);
        assert_eq!((ours.mantissa(), ours.scale()), (0, 2));
        assert_eq!(rust_decimal::Decimal::from(&ours).to_string(), "0.00");
    }
}
