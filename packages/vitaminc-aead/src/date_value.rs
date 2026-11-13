//! [`Date`]: a calendar date that is wiped when dropped.

use ::jiff::civil;
use vitaminc_protected::{OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::plaintext::kinds::jiff as conv;
use crate::plaintext::{depth, Encrypt, FixedType, Int, Logical, Physical, Scalar, Sink, Width};
use crate::typed::FromScalar;

/// A calendar date, held as its count of days since 1970-01-01 and wiped
/// when it is dropped.
///
/// It encrypts to the same leaf as [`jiff::civil::Date`], owned or
/// borrowed, so a `jiff::civil::Date` field can become a `Date` without
/// changing its ciphertext. Every `jiff::civil::Date` is one, so building
/// it cannot fail.
///
/// ```
/// use vitaminc_aead::Date;
///
/// let day = jiff::civil::date(2026, 11, 14);
/// assert_eq!(Date::new(day).to_jiff(), day);
/// ```
///
/// A `Date` is plaintext, so it is handled as the data model's other
/// scalars are: a `jiff::civil::Date` cannot be wiped, because it is `Copy`
/// and its fields are private. Equality is constant time (see
/// [`TimingSafeEq`]). It is not `Copy` or `Clone`, so it is not copied
/// without a trace, and it has no ordering or hash, which would compare
/// plaintext in variable time. `Debug` is redacted. `Default` is
/// 1970-01-01, the epoch, not jiff's default of 0000-01-01.
#[derive(Default, OpaqueDebug, TimingSafeEq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(docsrs, doc(cfg(feature = "jiff")))]
pub struct Date {
    /// Days since 1970-01-01.
    days: i32,
}

impl Date {
    /// The date.
    pub fn new(date: civil::Date) -> Self {
        Self {
            days: conv::date_days(date),
        }
    }

    /// The date, as a `jiff::civil::Date`. The copy is the caller's to look
    /// after: it cannot be wiped.
    pub fn to_jiff(&self) -> civil::Date {
        // A `Date` is only built from a `jiff::civil::Date`, whose day count
        // always makes one again, so the fallback is never taken. It is
        // there so this cannot panic.
        conv::date(Int::I32(self.days)).unwrap_or_default()
    }
}

impl From<civil::Date> for Date {
    fn from(date: civil::Date) -> Self {
        Self::new(date)
    }
}

impl From<Date> for civil::Date {
    fn from(date: Date) -> Self {
        date.to_jiff()
    }
}

/// The same leaf as `jiff::civil::Date`: a date over its day count.
impl Encrypt for Date {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = <&Date as Encrypt>::FIXED;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

impl Encrypt for &Date {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = FixedType::new(Some(Logical::Date), Width::I32);
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(Some(Logical::Date), Physical::Int(Int::I32(self.days)))
    }
}

impl Scalar for Date {}
impl Scalar for &Date {}
const _: () = assert!(depth::is_scalar(<Date as Encrypt>::DEPTH));

impl FromScalar for Date {
    const EXPECTED: &'static str = "date";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        civil::Date::from_scalar(ty, value).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_frame;
    use vitaminc_protected::Controlled;

    fn frame<P: Encrypt>(value: P) -> Vec<u8> {
        to_frame(value).expect("frames").risky_ref().to_vec()
    }

    fn day(y: i16, m: i8, d: i8) -> civil::Date {
        civil::Date::new(y, m, d).expect("a date")
    }

    /// Every date comes back as it went in, and walks as the
    /// `jiff::civil::Date`.
    #[test]
    fn it_walks_as_the_jiff_date_it_holds() {
        for date in [
            civil::Date::MIN,
            civil::Date::MAX,
            day(1970, 1, 1),
            day(1969, 12, 31),
            day(2026, 11, 14),
        ] {
            let held = Date::new(date);
            assert_eq!(held.to_jiff(), date, "{date}");
            assert_eq!(frame(&held), frame(date), "{date}");
            assert_eq!(frame(Date::new(date)), frame(date), "{date}");
            assert_eq!(civil::Date::from(Date::from(date)), date);
        }
        assert_eq!(<Date as Encrypt>::FIXED, <civil::Date as Encrypt>::FIXED);
        assert_eq!(<&Date as Encrypt>::FIXED, <civil::Date as Encrypt>::FIXED);
        assert_eq!(Date::default().to_jiff(), day(1970, 1, 1));
        let decoded =
            Date::from_scalar(Some(Logical::Date), Physical::Int(Int::I32(1))).expect("a date");
        assert_eq!(decoded.to_jiff(), day(1970, 1, 2));
        assert!(Date::from_scalar(None, Physical::Int(Int::I32(1))).is_none());
    }

    /// Constant-time equality, wiped by `zeroize`, a redacted `Debug`.
    #[test]
    fn it_compares_in_constant_time_wipes_and_redacts() {
        let date = |d| Date::new(day(2026, 11, d));
        assert!(bool::from(date(14).ts_eq(&date(14))));
        assert!(date(14) != date(15));
        let mut held = date(14);
        held.zeroize();
        assert!(held == Date::default());
        assert!(!format!("{:?}", date(14)).contains("2026"));
    }
}
